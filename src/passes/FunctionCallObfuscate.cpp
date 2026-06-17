// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/FunctionCallObfuscate.cpp
//
// Each eligible direct call/invoke to an external function `f(args)` becomes
//   buf = <inline, per-site decryption of the encrypted symbol name>
//   p   = dlsym(RTLD_DEFAULT, buf); p(args)
// so the static import/call edge to `f` disappears.  The symbol name is never a
// readable string and is never recovered by a single shared routine: each site
// gets its own cloaked symbol (ir::emitCloakedSymbol), so cracking one site does
// not crack the rest.  Only declared (external) symbols are redirected —
// locally-defined functions stay direct, since dlsym would not resolve them.

#include "morok/passes/FunctionCallObfuscate.hpp"

#include "morok/core/KnuthHash.hpp"
#include "morok/ir/SymbolCloak.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr std::uint32_t kMaxCallsPerModule = 256;

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

Value *rotl64(IRBuilder<> &B, Value *V, unsigned Amount) {
    auto *I64 = Type::getInt64Ty(B.getContext());
    return B.CreateOr(B.CreateShl(V, ConstantInt::get(I64, Amount)),
                      B.CreateLShr(V, ConstantInt::get(I64, 64 - Amount)),
                      "morok.fco.ptr.rot");
}

Value *pointerKey(IRBuilder<> &B, Module &M, ir::IRRandom &rng,
                  std::uint64_t SiteKey, unsigned Variant,
                  std::uint64_t Mul, std::uint64_t Mask) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    GlobalVariable *Seed = ir::cloakSeed(M, rng);
    LoadInst *SeedLoad =
        B.CreateLoad(I64, Seed, /*isVolatile=*/true, "morok.fco.ptr.seed");
    Value *K0 = B.CreateXor(SeedLoad, ConstantInt::get(I64, SiteKey),
                            "morok.fco.ptr.k0");
    Value *K = ir::emitKeystream(B, Variant, K0, 0, Mul);
    return B.CreateXor(K, ConstantInt::get(I64, Mask), "morok.fco.ptr.key");
}

AllocaInst *entryAlloca(Function &F, Type *Ty, StringRef Name) {
    IRBuilder<> EntryB(&*F.getEntryBlock().getFirstInsertionPt());
    return EntryB.CreateAlloca(Ty, nullptr, Name);
}

Value *encodeResolvedPointer(IRBuilder<> &B, Module &M, Value *Resolved,
                             ir::IRRandom &rng) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    const unsigned Variant = rng.range(ir::kKeystreamVariants);
    const unsigned Mode = rng.range(3);
    const std::uint64_t SiteKey = rng.next();
    const std::uint64_t Mul = rng.next() | 1ull;
    const std::uint64_t Mask = rng.next();
    const std::uint64_t PtrMul = rng.next() | 1ull;
    const std::uint64_t PtrMulInv = core::modInverse64(PtrMul);

    Value *Raw = B.CreatePtrToInt(Resolved, I64, "morok.fco.ptr.raw");
    Value *EncKey = pointerKey(B, M, rng, SiteKey, Variant, Mul, Mask);
    Value *Encoded = nullptr;
    switch (Mode) {
    case 1:
        Encoded = B.CreateXor(B.CreateAdd(Raw, EncKey, "morok.fco.ptr.add"),
                              rotl64(B, EncKey, 29), "morok.fco.ptr.enc");
        break;
    case 2:
        Encoded = B.CreateXor(
            B.CreateMul(B.CreateAdd(Raw, EncKey, "morok.fco.ptr.add"),
                        ConstantInt::get(I64, PtrMul), "morok.fco.ptr.mul"),
            EncKey, "morok.fco.ptr.enc");
        break;
    default:
        Encoded = B.CreateAdd(B.CreateXor(Raw, EncKey, "morok.fco.ptr.xor"),
                              rotl64(B, EncKey, 17), "morok.fco.ptr.enc");
        break;
    }

    AllocaInst *Slot =
        entryAlloca(*B.GetInsertBlock()->getParent(), I64, "morok.fco.ptr.slot");
    B.CreateStore(Encoded, Slot, /*isVolatile=*/true);
    LoadInst *EncodedLoad =
        B.CreateLoad(I64, Slot, /*isVolatile=*/true, "morok.fco.ptr.reload");
    Value *DecKey = pointerKey(B, M, rng, SiteKey, Variant, Mul, Mask);
    Value *DecodedInt = nullptr;
    switch (Mode) {
    case 1:
        DecodedInt = B.CreateSub(B.CreateXor(EncodedLoad, rotl64(B, DecKey, 29),
                                             "morok.fco.ptr.unxor"),
                                 DecKey, "morok.fco.ptr.dec.i");
        break;
    case 2:
        DecodedInt = B.CreateSub(
            B.CreateMul(B.CreateXor(EncodedLoad, DecKey, "morok.fco.ptr.unxor"),
                        ConstantInt::get(I64, PtrMulInv),
                        "morok.fco.ptr.unmul"),
            DecKey, "morok.fco.ptr.dec.i");
        break;
    default:
        DecodedInt = B.CreateXor(
            B.CreateSub(EncodedLoad, rotl64(B, DecKey, 17),
                        "morok.fco.ptr.unadd"),
            DecKey, "morok.fco.ptr.dec.i");
        break;
    }
    return B.CreateIntToPtr(DecodedInt, PointerType::getUnqual(M.getContext()),
                            "morok.fco.ptr.dec");
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

    bool changed = false;
    for (CallBase *cb : targets) {
        Function *callee = cb->getCalledFunction();

        IRBuilder<> B(cb);
        // dlsym needs the plain C symbol name.  LLVM may carry a `\01`-escaped
        // asm name (e.g. macOS libc's `\01_fwrite`); strip the escape and the
        // platform underscore, otherwise dlsym returns null and the redirected
        // call jumps to address 0.
        StringRef dlName = callee->getName();
        if (dlName.consume_front(StringRef("\x01", 1)) && tt.isOSDarwin())
            dlName.consume_front("_");
        Value *name = ir::emitCloakedSymbol(B, M, dlName, rng);
        Value *rtld =
            B.CreateIntToPtr(ConstantInt::getSigned(i64, rtldDefaultVal), ptr);
        Value *resolved = B.CreateCall(dlsym, {rtld, name});
        Value *decoded = encodeResolvedPointer(B, M, resolved, rng);

        std::vector<Value *> args = argsOf(*cb);
        CallBase *indirect = nullptr;
        if (auto *ci = dyn_cast<CallInst>(cb)) {
            auto *call = B.CreateCall(callee->getFunctionType(), decoded, args);
            call->setTailCallKind(ci->getTailCallKind());
            indirect = call;
        } else {
            auto *ii = cast<InvokeInst>(cb);
            indirect = B.CreateInvoke(callee->getFunctionType(), decoded,
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
