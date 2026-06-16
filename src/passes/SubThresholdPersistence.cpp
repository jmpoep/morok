// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/SubThresholdPersistence.cpp
//
// The pass preserves semantics by adding opaque-zero terms: two adjacent
// volatile loads from a private stack seed are equal at runtime, but remain
// distinct side-effecting SSA values for simple canonicalizers.

#include "morok/passes/SubThresholdPersistence.hpp"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

constexpr StringRef kSeedPrefix = "morok.threshold.seed";

bool supportedFloatType(Type *Ty) {
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

bool eligibleIntegerOp(BinaryOperator *bo, IntegerType *Ty) {
    if (Ty->getBitWidth() == 0)
        return false;
    if (bo->getName().starts_with("morok.threshold"))
        return false;
    // Poison-generating flags (nsw/nuw/exact/disjoint) are accepted: cloneBaseOp
    // re-emits the operation WITHOUT flags and the original is replaced, so the
    // wrapped value is a sound refinement of the flagged op.  This matters
    // because -O2 stamps these flags onto essentially all integer arithmetic.

    switch (bo->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
        return true;
    default:
        return false;
    }
}

bool eligibleFloatOp(BinaryOperator *bo) {
    if (!supportedFloatType(bo->getType()))
        return false;
    if (bo->getName().starts_with("morok.threshold"))
        return false;
    if (bo->getFastMathFlags().any())
        return false;

    switch (bo->getOpcode()) {
    case Instruction::FAdd:
    case Instruction::FSub:
    case Instruction::FMul:
    case Instruction::FDiv:
    case Instruction::FRem:
        return true;
    default:
        return false;
    }
}

bool eligible(BinaryOperator *bo) {
    if (auto *Ty = dyn_cast<IntegerType>(bo->getType()))
        return eligibleIntegerOp(bo, Ty);
    return eligibleFloatOp(bo);
}

IntegerType *integerCarrierFor(Type *Ty) {
    const unsigned Bits = static_cast<unsigned>(Ty->getPrimitiveSizeInBits());
    return IntegerType::get(Ty->getContext(), Bits);
}

AllocaInst *findSeed(Function &F) {
    for (Instruction &I : F.getEntryBlock())
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with(kSeedPrefix))
                return AI;
    return nullptr;
}

AllocaInst *ensureSeed(Function &F, ir::IRRandom &rng) {
    if (AllocaInst *Existing = findSeed(F))
        return Existing;

    LLVMContext &Ctx = F.getContext();
    Builder B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I64 = Type::getInt64Ty(Ctx);
    AllocaInst *Seed = B.CreateAlloca(I64, nullptr, kSeedPrefix);
    Seed->setAlignment(Align(8));
    StoreInst *Store =
        B.CreateStore(ConstantInt::get(I64, rng.next()), Seed);
    Store->setAlignment(Align(8));
    return Seed;
}

Value *loadSeedAs(Builder &B, AllocaInst *Seed, IntegerType *Ty,
                  const Twine &Name) {
    auto *I64 = Type::getInt64Ty(Ty->getContext());
    LoadInst *Load = B.CreateLoad(I64, Seed, /*isVolatile=*/true, Name);
    Load->setAlignment(Align(8));
    if (Ty == I64)
        return Load;
    return B.CreateZExtOrTrunc(Load, Ty, Name + ".cast");
}

Value *opaqueZero(Builder &B, AllocaInst *Seed, IntegerType *Ty) {
    Value *A = loadSeedAs(B, Seed, Ty, "morok.threshold.load.a");
    Value *Bv = loadSeedAs(B, Seed, Ty, "morok.threshold.load.b");
    return B.CreateXor(A, Bv, "morok.threshold.zero");
}

Value *cloneBaseOp(Builder &B, BinaryOperator *bo) {
    return B.CreateBinOp(bo->getOpcode(), bo->getOperand(0),
                         bo->getOperand(1), "morok.threshold.base");
}

Value *wrap(BinaryOperator *bo, AllocaInst *Seed,
            const SubThresholdParams &params, ir::IRRandom &rng) {
    Type *ResultTy = bo->getType();
    auto *Ty = ResultTy->isIntegerTy() ? cast<IntegerType>(ResultTy)
                                       : integerCarrierFor(ResultTy);
    Builder B(bo);
    Value *Result = cloneBaseOp(B, bo);
    const std::uint32_t Terms =
        std::clamp<std::uint32_t>(params.max_terms, 1, 6);

    for (std::uint32_t I = 0; I < Terms; ++I) {
        Value *Zero = opaqueZero(B, Seed, Ty);
        Value *Bits = Result;
        if (!ResultTy->isIntegerTy())
            Bits = B.CreateBitCast(Result, Ty, "morok.threshold.bits");
        switch (rng.range(3)) {
        case 0:
            Bits = B.CreateAdd(Bits, Zero,
                               ResultTy->isIntegerTy()
                                   ? "morok.threshold.keep"
                                   : "morok.threshold.keep.bits");
            break;
        case 1:
            Bits = B.CreateSub(Bits, Zero,
                               ResultTy->isIntegerTy()
                                   ? "morok.threshold.keep"
                                   : "morok.threshold.keep.bits");
            break;
        default:
            Bits = B.CreateXor(Bits, Zero,
                               ResultTy->isIntegerTy()
                                   ? "morok.threshold.keep"
                                   : "morok.threshold.keep.bits");
            break;
        }
        if (ResultTy->isIntegerTy())
            Result = Bits;
        else
            Result = B.CreateBitCast(Bits, ResultTy, "morok.threshold.keep");
    }
    return Result;
}

} // namespace

bool subThresholdPersistFunction(Function &F, const SubThresholdParams &params,
                                 ir::IRRandom &rng) {
    if (F.isDeclaration() || params.probability == 0 || params.max_terms == 0)
        return false;

    std::vector<BinaryOperator *> targets;
    for (BasicBlock &BB : F)
        for (Instruction &I : BB)
            if (auto *BO = dyn_cast<BinaryOperator>(&I))
                if (eligible(BO))
                    targets.push_back(BO);

    AllocaInst *Seed = nullptr;
    bool changed = false;
    for (BinaryOperator *BO : targets) {
        if (!rng.chance(params.probability))
            continue;
        if (!Seed)
            Seed = ensureSeed(F, rng);
        Value *Replacement = wrap(BO, Seed, params, rng);
        BO->replaceAllUsesWith(Replacement);
        BO->eraseFromParent();
        changed = true;
    }
    return changed;
}

PreservedAnalyses
SubThresholdPersistencePass::run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return subThresholdPersistFunction(F, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
