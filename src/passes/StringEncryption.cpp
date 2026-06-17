// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/StringEncryption.cpp
//
// Every eligible private byte-array string is encrypted with its OWN cipher:
// a per-string keystream generator (one of several), XOR- or ADD-combined, with
// per-string key material.  Each string also gets its OWN decryptor — a separate
// global constructor that recovers exactly that string in place, with the
// keystream inlined (no shared multiply/decrypt helper).  So there is no single
// place that decrypts every string, no two strings share an encryption, and a
// decompiler sees N unrelated startup routines rather than one tell-all loop.

#include "morok/passes/StringEncryption.hpp"

#include "morok/ir/SymbolCloak.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

// Encrypt *every* eligible string — readable strings are toxic — so the caps
// are sized only to keep pathological inputs in check, not to leave strings in
// the clear.  Strings longer than the unroll threshold get a compact loop
// decryptor instead of a fully unrolled one, so total code size stays bounded
// regardless of how much string data a module carries.
constexpr std::uint64_t kMaxEncryptedStrings = 8192;
constexpr std::uint64_t kMaxEncryptedStringBytes = 1u << 20; // 1 MiB / string
constexpr std::uint64_t kMaxEncryptedTotalBytes = 8u << 20;  // 8 MiB / module
constexpr std::uint64_t kUnrollThreshold = 64; // ≤ this ⇒ unrolled, else loop

bool eligible(const GlobalVariable &gv) {
    if (!gv.hasInitializer() || !gv.hasLocalLinkage())
        return false;
    // A single global constructor only decrypts the init-time TLS instance;
    // other threads would observe ciphertext.  Leave thread-locals alone.
    if (gv.isThreadLocal())
        return false;
    if (gv.getName().starts_with("llvm.") || gv.getName().starts_with("morok."))
        return false;
    if (gv.getSection() == "llvm.metadata")
        return false;
    const auto *cda = dyn_cast<ConstantDataArray>(gv.getInitializer());
    return cda && cda->getElementType()->isIntegerTy(8) &&
           cda->getNumElements() > 0;
}

// The per-string cipher recipe; chosen independently for every string.
struct Cipher {
    unsigned variant = 0;   // keystream generator
    bool add = false;       // ADD vs XOR combine
    std::uint64_t key = 0;  // per-string xor into the module seed
    std::uint64_t mul = 1;  // per-string odd multiplier
};

} // namespace

bool stringEncryptModule(Module &M, const StrEncParams &params,
                         ir::IRRandom &rng) {
    if (params.probability == 0)
        return false;

    LLVMContext &ctx = M.getContext();
    auto *i8 = Type::getInt8Ty(ctx);
    auto *i64 = Type::getInt64Ty(ctx);
    auto *voidTy = Type::getVoidTy(ctx);

    std::vector<GlobalVariable *> targets;
    targets.reserve(kMaxEncryptedStrings);
    std::uint64_t selectedBytes = 0;
    for (GlobalVariable &gv : M.globals()) {
        if (targets.size() >= kMaxEncryptedStrings ||
            selectedBytes >= kMaxEncryptedTotalBytes)
            break;
        if (!eligible(gv))
            continue;
        const auto *cda = cast<ConstantDataArray>(gv.getInitializer());
        const std::uint64_t n = cda->getNumElements();
        if (n > kMaxEncryptedStringBytes ||
            selectedBytes + n > kMaxEncryptedTotalBytes)
            continue;
        if (rng.chance(params.probability)) {
            targets.push_back(&gv);
            selectedBytes += n;
        }
    }
    if (targets.empty())
        return false;

    // One runtime-opaque module seed underlies every per-string key; reading it
    // with a volatile load keeps the optimizer from folding ciphertext to text.
    GlobalVariable *seed = ir::cloakSeed(M, rng);
    const std::uint64_t seedVal =
        cast<ConstantInt>(seed->getInitializer())->getZExtValue();

    bool changed = false;
    for (GlobalVariable *gv : targets) {
        const auto *cda = cast<ConstantDataArray>(gv->getInitializer());
        StringRef raw = cda->getRawDataValues();
        const std::uint64_t n = cda->getNumElements();

        Cipher c;
        c.variant = rng.range(ir::kKeystreamVariants);
        c.add = rng.range(2) == 0;
        c.key = rng.next();
        c.mul = rng.next() | 1ull;
        const std::uint64_t k0 = seedVal ^ c.key;

        std::vector<std::uint8_t> ct(n);
        for (std::uint64_t i = 0; i < n; ++i) {
            const auto ks = static_cast<std::uint8_t>(
                ir::keystreamValue(c.variant, k0,
                                   static_cast<std::uint32_t>(i), c.mul) &
                0xFFu);
            const auto p = static_cast<std::uint8_t>(raw[i]);
            ct[i] = c.add ? static_cast<std::uint8_t>(p + ks)
                          : static_cast<std::uint8_t>(p ^ ks);
        }
        gv->setInitializer(
            ConstantDataArray::get(ctx, ArrayRef<std::uint8_t>(ct)));
        gv->setConstant(false); // mutated in place by this string's decryptor

        // A decryptor unique to this string: recover its bytes in place with the
        // keystream inlined, then return.  Each gets its own constructor.  Short
        // strings are fully unrolled (maximally tangled); long strings use a
        // compact loop so module code size stays bounded.
        auto *decFn = Function::Create(FunctionType::get(voidTy, false),
                                       GlobalValue::InternalLinkage,
                                       "morok.strdec", &M);
        auto combine = [&](IRBuilder<> &B, Value *cipher, Value *ksByte) {
            return c.add ? B.CreateSub(cipher, ksByte)
                         : B.CreateXor(cipher, ksByte);
        };
        if (n <= kUnrollThreshold) {
            IRBuilder<> B(BasicBlock::Create(ctx, "entry", decFn));
            Value *rtKey = B.CreateXor(
                B.CreateLoad(i64, seed, /*isVolatile=*/true),
                ConstantInt::get(i64, c.key));
            for (std::uint64_t i = 0; i < n; ++i) {
                Value *ks = ir::emitKeystream(
                    B, c.variant, rtKey, static_cast<std::uint32_t>(i), c.mul);
                Value *ptr = B.CreateConstInBoundsGEP2_64(gv->getValueType(), gv,
                                                          0, i);
                B.CreateStore(combine(B, B.CreateLoad(i8, ptr),
                                      B.CreateTrunc(ks, i8)),
                              ptr);
            }
            B.CreateRetVoid();
        } else {
            auto *entry = BasicBlock::Create(ctx, "entry", decFn);
            auto *loop = BasicBlock::Create(ctx, "loop", decFn);
            auto *exit = BasicBlock::Create(ctx, "exit", decFn);
            IRBuilder<> B(entry);
            Value *rtKey = B.CreateXor(
                B.CreateLoad(i64, seed, /*isVolatile=*/true),
                ConstantInt::get(i64, c.key));
            B.CreateBr(loop);

            B.SetInsertPoint(loop);
            PHINode *iv = B.CreatePHI(i64, 2);
            iv->addIncoming(ConstantInt::get(i64, 0), entry);
            Value *ks = ir::emitKeystreamDynamic(B, c.variant, rtKey, iv, c.mul);
            Value *ptr = B.CreateInBoundsGEP(
                gv->getValueType(), gv, {ConstantInt::get(i64, 0), iv});
            B.CreateStore(combine(B, B.CreateLoad(i8, ptr),
                                  B.CreateTrunc(ks, i8)),
                          ptr);
            Value *next = B.CreateAdd(iv, ConstantInt::get(i64, 1));
            iv->addIncoming(next, loop);
            B.CreateCondBr(B.CreateICmpULT(next, ConstantInt::get(i64, n)), loop,
                           exit);

            B.SetInsertPoint(exit);
            B.CreateRetVoid();
        }

        // Vary the constructor priority so the decryptors do not appear as one
        // contiguous block running back-to-back.
        appendToGlobalCtors(M, decFn,
                            static_cast<int>(rng.range(40000)) + 1);
        changed = true;
    }
    return changed;
}

PreservedAnalyses StringEncryptionPass::run(Module &M,
                                            ModuleAnalysisManager &) {
    ir::IRRandom rng(engine_);
    return stringEncryptModule(M, params_, rng) ? PreservedAnalyses::none()
                                                : PreservedAnalyses::all();
}

} // namespace morok::passes
