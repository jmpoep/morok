// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionCallObfuscate.cpp
//
// Each eligible direct call/invoke to an external function `f(args)` becomes
//   buf = <inline, per-site decryption of the encrypted symbol name>
//   p   = dlsym(RTLD_DEFAULT, buf); p(args)
// so the static import/call edge to `f` disappears.  Crucially the symbol name
// is NEVER stored as a readable string and is NEVER recovered by a single shared
// routine: every call site carries its own ciphertext and its own unrolled
// keystream arithmetic, keyed on a runtime-opaque module seed (a volatile load
// of a mutable global, so the optimizer cannot fold the cipher back to text).
// Per-site key material differs, so cracking one site does not crack the rest.
// Only declared (external) symbols are redirected — locally-defined functions
// stay direct, since dlsym would not resolve them.

#include "morok/passes/FunctionCallObfuscate.hpp"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kMaxCallsPerModule = 256;

// MurmurHash3 64-bit finalizer constants — used to spread the per-site key into
// a keystream byte.  The SAME computation runs at pass time (to produce the
// ciphertext) and in the emitted IR (to recover the plaintext), so they must
// stay byte-for-byte identical.
constexpr std::uint64_t kMix1 = 0xFF51AFD7ED558CCDULL;
constexpr std::uint64_t kMix2 = 0xC4CEB9FE1A85EC53ULL;

// keystream byte for position `j`, given the per-site runtime key `k0` and the
// per-site odd multiplier `mul`.  Pure 64-bit wraparound arithmetic, so it has
// an exact i64 IR analogue.
std::uint8_t keystreamByte(std::uint64_t k0, std::uint32_t j,
                           std::uint64_t mul) {
    std::uint64_t t = k0 + static_cast<std::uint64_t>(j + 1) * mul;
    t ^= t >> 33;
    t *= kMix1;
    t ^= t >> 33;
    t *= kMix2;
    t ^= t >> 33;
    return static_cast<std::uint8_t>(t & 0xFFu);
}

// Emit the i64 keystream value for position `j` from the runtime key value
// `K0` (an i64 Value) — the exact IR mirror of keystreamByte before the final
// truncation.
Value *emitKeystream(IRBuilder<> &B, Value *K0, std::uint32_t j,
                     std::uint64_t mul) {
    auto *I64 = B.getInt64Ty();
    Value *T = B.CreateAdd(
        K0,
        ConstantInt::get(I64, static_cast<std::uint64_t>(j + 1) * mul),
        "morok.fco.k.t");
    T = B.CreateXor(T, B.CreateLShr(T, ConstantInt::get(I64, 33)),
                    "morok.fco.k.x1");
    T = B.CreateMul(T, ConstantInt::get(I64, kMix1), "morok.fco.k.m1");
    T = B.CreateXor(T, B.CreateLShr(T, ConstantInt::get(I64, 33)),
                    "morok.fco.k.x2");
    T = B.CreateMul(T, ConstantInt::get(I64, kMix2), "morok.fco.k.m2");
    T = B.CreateXor(T, B.CreateLShr(T, ConstantInt::get(I64, 33)),
                    "morok.fco.k.x3");
    return T;
}

bool eligible(CallBase *cb) {
    if (!isa<CallInst>(cb) && !isa<InvokeInst>(cb))
        return false;
    if (cb->isInlineAsm() || cb->hasOperandBundles())
        return false;
    if (auto *ci = dyn_cast<CallInst>(cb))
        if (ci->isMustTailCall())
            return false;
    Function *callee = cb->getCalledFunction();
    if (!callee || !callee->isDeclaration() || callee->isIntrinsic())
        return false;
    if (callee->getName().starts_with("llvm.") ||
        callee->getName().starts_with("morok.") || callee->getName() == "dlsym")
        return false;
    return true;
}

std::vector<Value *> argsOf(CallBase &cb) {
    std::vector<Value *> args;
    args.reserve(cb.arg_size());
    for (Use &arg : cb.args())
        args.push_back(arg.get());
    return args;
}

// Lazily materialise the per-module runtime key: a private *mutable* global
// holding a random value, always read with a volatile load.  Mutable + volatile
// is the established anti-fold pattern (see ConstantEncryption) — the optimizer
// must treat the loaded value as unknown, so the keystream (and therefore the
// symbol) never constant-folds back to readable text.
GlobalVariable *getSeed(Module &M, GlobalVariable *&Cache, ir::IRRandom &rng) {
    if (Cache)
        return Cache;
    auto *I64 = Type::getInt64Ty(M.getContext());
    Cache = new GlobalVariable(M, I64, /*isConstant=*/false,
                               GlobalValue::PrivateLinkage,
                               ConstantInt::get(I64, rng.next()), "morok.fco.s");
    Cache->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    return Cache;
}

// Build the encrypted symbol bytes (name + NUL) for `Name`, keyed by the
// pass-time seed `SeedVal`, site key `SiteKey`, and multiplier `Mul`.
std::vector<std::uint8_t> encryptSymbol(StringRef Name, std::uint64_t SeedVal,
                                        std::uint64_t SiteKey,
                                        std::uint64_t Mul) {
    const std::uint64_t K0 = SeedVal ^ SiteKey;
    std::vector<std::uint8_t> Cipher;
    Cipher.reserve(Name.size() + 1);
    for (std::uint32_t j = 0; j <= Name.size(); ++j) {
        const std::uint8_t Plain =
            j < Name.size() ? static_cast<std::uint8_t>(Name[j]) : 0u;
        Cipher.push_back(
            static_cast<std::uint8_t>(Plain ^ keystreamByte(K0, j, Mul)));
    }
    return Cipher;
}

// Emit, at `cb`, the inline per-site decryption of `callee`'s name into a fresh
// stack buffer and return a pointer to it.
Value *emitSymbolBuffer(IRBuilder<> &B, Module &M, Function *callee,
                        GlobalVariable *Seed, ir::IRRandom &rng) {
    LLVMContext &ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(ctx);
    auto *I64 = Type::getInt64Ty(ctx);

    const std::string Name = callee->getName().str();
    const std::uint64_t SiteKey = rng.next();
    const std::uint64_t Mul = rng.next() | 1ull;
    const std::uint64_t SeedVal =
        cast<ConstantInt>(Seed->getInitializer())->getZExtValue();

    const std::vector<std::uint8_t> Cipher =
        encryptSymbol(Name, SeedVal, SiteKey, Mul);
    const std::size_t Len = Cipher.size();

    // Ciphertext lives in a private constant global — just opaque-looking bytes.
    auto *ArrTy = ArrayType::get(I8, Len);
    SmallVector<Constant *, 32> Bytes;
    Bytes.reserve(Len);
    for (std::uint8_t Byte : Cipher)
        Bytes.push_back(ConstantInt::get(I8, Byte));
    auto *CipherGV = new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantArray::get(ArrTy, Bytes), "morok.fco.c");
    CipherGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    // Stack buffer for the recovered name.
    AllocaInst *Buf = B.CreateAlloca(ArrTy, nullptr, "morok.fco.buf");

    // Runtime key: volatile-load the module seed, xor the per-site constant.
    LoadInst *SeedLoad = B.CreateLoad(I64, Seed, /*isVolatile=*/true,
                                      "morok.fco.seed");
    Value *K0 = B.CreateXor(SeedLoad, ConstantInt::get(I64, SiteKey),
                            "morok.fco.k0");

    for (std::uint32_t j = 0; j < Len; ++j) {
        Value *Ks = emitKeystream(B, K0, j, Mul);
        Value *KsByte = B.CreateTrunc(Ks, I8, "morok.fco.ksb");
        Value *CipherPtr = B.CreateInBoundsGEP(
            ArrTy, CipherGV, {ConstantInt::get(I64, 0), ConstantInt::get(I64, j)},
            "morok.fco.cp");
        Value *CipherByte = B.CreateLoad(I8, CipherPtr, "morok.fco.cb");
        Value *Plain = B.CreateXor(CipherByte, KsByte, "morok.fco.pb");
        Value *BufPtr = B.CreateInBoundsGEP(
            ArrTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, j)},
            "morok.fco.bp");
        B.CreateStore(Plain, BufPtr);
    }
    return B.CreateInBoundsGEP(
        ArrTy, Buf, {ConstantInt::get(I64, 0), ConstantInt::get(I64, 0)},
        "morok.fco.name");
}

} // namespace

bool functionCallObfuscateModule(Module &M, const FcoParams &params,
                                 ir::IRRandom &rng) {
    if (params.probability == 0 || params.max_calls == 0)
        return false;

    const std::uint32_t Limit = std::min(params.max_calls, kMaxCallsPerModule);

    std::vector<CallBase *> targets;
    targets.reserve(Limit);
    for (Function &F : M) {
        if (targets.size() >= Limit)
            break;
        if (F.isDeclaration() || F.getName().starts_with("morok."))
            continue;
        for (Instruction &inst : instructions(F)) {
            if (targets.size() >= Limit)
                break;
            if (auto *cb = dyn_cast<CallBase>(&inst))
                if (eligible(cb))
                    if (rng.chance(params.probability))
                        targets.push_back(cb);
        }
    }
    if (targets.empty())
        return false;

    LLVMContext &ctx = M.getContext();
    auto *i64 = Type::getInt64Ty(ctx);
    auto *ptr = PointerType::getUnqual(ctx);
    const Triple tt(M.getTargetTriple());
    const int rtldDefaultVal = tt.isOSDarwin() ? -2 : 0; // RTLD_DEFAULT

    FunctionCallee dlsym = M.getOrInsertFunction(
        "dlsym", FunctionType::get(ptr, {ptr, ptr}, false));

    GlobalVariable *Seed = nullptr;
    bool changed = false;
    for (CallBase *cb : targets) {
        Function *callee = cb->getCalledFunction();

        IRBuilder<> B(cb);
        Value *name = emitSymbolBuffer(B, M, callee, getSeed(M, Seed, rng), rng);
        Value *rtld =
            B.CreateIntToPtr(ConstantInt::getSigned(i64, rtldDefaultVal), ptr);
        Value *resolved = B.CreateCall(dlsym, {rtld, name});

        std::vector<Value *> args = argsOf(*cb);
        CallBase *indirect = nullptr;
        if (auto *ci = dyn_cast<CallInst>(cb)) {
            auto *call = B.CreateCall(callee->getFunctionType(), resolved, args);
            call->setTailCallKind(ci->getTailCallKind());
            indirect = call;
        } else {
            auto *ii = cast<InvokeInst>(cb);
            indirect = B.CreateInvoke(callee->getFunctionType(), resolved,
                                      ii->getNormalDest(), ii->getUnwindDest(),
                                      args);
        }
        indirect->setCallingConv(cb->getCallingConv());
        indirect->setAttributes(cb->getAttributes());
        indirect->setDebugLoc(cb->getDebugLoc());
        indirect->copyMetadata(*cb);

        cb->replaceAllUsesWith(indirect);
        cb->eraseFromParent();
        changed = true;
    }
    return changed;
}

PreservedAnalyses FunctionCallObfuscatePass::run(Module &M,
                                                 ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return functionCallObfuscateModule(M, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
