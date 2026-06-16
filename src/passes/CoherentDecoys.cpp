// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/CoherentDecoys.cpp
//
// Coherent decoy dead paths.  Each selected integer return is split into a
// guard block, the real return block, and a dead alternate return block.  The
// guard uses two volatile loads from a private global, so the predicate is true
// at runtime but not foldable.  The decoy return computes a type-correct value
// from real inputs and live values rather than emitting arbitrary junk.

#include "morok/passes/CoherentDecoys.hpp"

#include "morok/ir/InstUtil.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kOpaqueGlobal[] = "morok.decoy.opaque";
constexpr char kAltBlock[] = "morok.decoy.alt";

GlobalVariable *opaqueGlobal(Module &M, ir::IRRandom &rng) {
    if (auto *GV = M.getGlobalVariable(kOpaqueGlobal, /*AllowInternal=*/true))
        return GV;
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32, static_cast<std::uint32_t>(rng.next())),
        kOpaqueGlobal);
    GV->setAlignment(Align(4));
    return GV;
}

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.decoy");
}

bool eligibleReturn(ReturnInst &RI) {
    if (ir::isMustTailReturn(RI))
        return false;
    Value *Ret = RI.getReturnValue();
    if (!Ret)
        return false;
    auto *IT = dyn_cast<IntegerType>(Ret->getType());
    return IT && IT->getBitWidth() > 0;
}

std::vector<ReturnInst *> collectReturns(Function &F) {
    std::vector<ReturnInst *> Returns;
    for (Instruction &I : instructions(F)) {
        auto *RI = dyn_cast<ReturnInst>(&I);
        if (!RI || isGeneratedBlock(*RI->getParent()) || !eligibleReturn(*RI))
            continue;
        Returns.push_back(RI);
    }
    return Returns;
}

void shuffleReturns(std::vector<ReturnInst *> &Returns, ir::IRRandom &rng) {
    for (std::size_t I = Returns.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Returns[I - 1], Returns[J]);
    }
}

Value *asReturnType(IRBuilder<NoFolder> &B, Value *V, IntegerType *RetTy) {
    if (!V || !V->getType()->isIntegerTy())
        return nullptr;
    if (V->getType() == RetTy)
        return V;
    auto *IT = cast<IntegerType>(V->getType());
    const unsigned SrcBits = IT->getBitWidth();
    const unsigned DstBits = RetTy->getBitWidth();
    if (SrcBits < DstBits)
        return B.CreateZExt(V, RetTy, "morok.decoy.alt.zext");
    if (SrcBits > DstBits)
        return B.CreateTrunc(V, RetTy, "morok.decoy.alt.trunc");
    return B.CreateIntCast(V, RetTy, false, "morok.decoy.alt.cast");
}

void addTerm(Value *V, SmallPtrSetImpl<Value *> &Seen,
             std::vector<Value *> &Terms) {
    if (!V || !V->getType()->isIntegerTy())
        return;
    if (Seen.insert(V).second)
        Terms.push_back(V);
}

std::vector<Value *> collectTerms(ReturnInst &RI) {
    std::vector<Value *> Terms;
    SmallPtrSet<Value *, 32> Seen;
    Function *F = RI.getFunction();
    for (Argument &Arg : F->args())
        addTerm(&Arg, Seen, Terms);

    for (Instruction &I : *RI.getParent()) {
        if (&I == &RI)
            break;
        if (isa<AllocaInst>(&I))
            continue;
        addTerm(&I, Seen, Terms);
    }
    return Terms;
}

void shuffleTerms(std::vector<Value *> &Terms, ir::IRRandom &rng) {
    for (std::size_t I = Terms.size(); I > 1; --I) {
        const std::size_t J = rng.range(static_cast<std::uint32_t>(I));
        std::swap(Terms[I - 1], Terms[J]);
    }
}

Value *buildAlternateValue(IRBuilder<NoFolder> &B, ReturnInst &RI,
                           const CoherentDecoyParams &Params,
                           ir::IRRandom &rng) {
    auto *RetTy = cast<IntegerType>(RI.getReturnValue()->getType());
    Value *Alt = RI.getReturnValue();
    Alt = B.CreateXor(Alt,
                      ConstantInt::get(RetTy,
                                       static_cast<std::uint64_t>(rng.next())),
                      "morok.decoy.alt.seed");

    std::vector<Value *> Terms = collectTerms(RI);
    shuffleTerms(Terms, rng);
    const std::uint32_t Limit = std::min<std::uint32_t>(
        Params.depth, static_cast<std::uint32_t>(Terms.size()));

    for (std::uint32_t I = 0; I < Limit; ++I) {
        Value *Term = asReturnType(B, Terms[I], RetTy);
        if (!Term)
            continue;
        Value *Salt =
            ConstantInt::get(RetTy, static_cast<std::uint64_t>(rng.next()));
        Value *Odd = ConstantInt::get(
            RetTy, static_cast<std::uint64_t>(rng.next()) | 1ull);
        Alt = B.CreateAdd(Alt, B.CreateXor(Term, Salt, "morok.decoy.alt.term"),
                          "morok.decoy.alt.add");
        Alt = B.CreateMul(Alt, Odd, "morok.decoy.alt.mul");
        Alt = B.CreateXor(Alt, Term, "morok.decoy.alt.mix");
    }

    return Alt;
}

Value *opaqueTrue(IRBuilder<NoFolder> &B, GlobalVariable *GV) {
    auto *I32 = B.getInt32Ty();
    auto *A = B.CreateLoad(I32, GV, "morok.decoy.a");
    A->setVolatile(true);
    A->setAlignment(Align(4));
    auto *Bv = B.CreateLoad(I32, GV, "morok.decoy.b");
    Bv->setVolatile(true);
    Bv->setAlignment(Align(4));
    return B.CreateICmpEQ(A, Bv, "morok.decoy.pred");
}

bool rewriteReturn(ReturnInst *RI, GlobalVariable *GV,
                   const CoherentDecoyParams &Params, ir::IRRandom &rng) {
    BasicBlock *Head = RI->getParent();
    Function *F = Head->getParent();
    BasicBlock *Real = SplitBlock(Head, RI);
    Instruction *HeadTerm = Head->getTerminator();

    auto *AltBB = BasicBlock::Create(F->getContext(), kAltBlock, F, Real);
    IRBuilder<NoFolder> AltB(AltBB);
    Value *Alt = buildAlternateValue(AltB, *RI, Params, rng);
    AltB.CreateRet(Alt);

    IRBuilder<NoFolder> GuardB(HeadTerm);
    Value *Pred = opaqueTrue(GuardB, GV);
    GuardB.CreateCondBr(Pred, Real, AltBB);
    HeadTerm->eraseFromParent();
    return true;
}

} // namespace

bool coherentDecoysFunction(Function &F, const CoherentDecoyParams &params,
                            ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        params.probability == 0 || params.max_blocks == 0)
        return false;

    std::vector<ReturnInst *> Returns = collectReturns(F);
    shuffleReturns(Returns, rng);
    if (Returns.empty())
        return false;

    GlobalVariable *GV = nullptr;
    bool Changed = false;
    std::uint32_t Count = 0;
    for (ReturnInst *RI : Returns) {
        if (Count >= params.max_blocks)
            break;
        if (!rng.chance(params.probability))
            continue;
        if (!GV)
            GV = opaqueGlobal(*F.getParent(), rng);
        Changed |= rewriteReturn(RI, GV, params, rng);
        ++Count;
    }
    return Changed;
}

PreservedAnalyses CoherentDecoysPass::run(Function &F,
                                          FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return coherentDecoysFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                   : PreservedAnalyses::all();
}

} // namespace morok::passes
