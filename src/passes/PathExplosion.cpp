// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/PathExplosion.cpp
//
// Anti-DSE path explosion.  Selected blocks are guarded by an opaque-true
// volatile predicate.  The false edge is never taken in normal execution, but
// it contains a bounded, input-derived loop with volatile memory stores and an
// input-derived indirectbr over several decoy blocks.  Symbolic engines that
// cannot prove the guard must explore a small computed-control-flow region.

#include "morok/passes/PathExplosion.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

constexpr char kOpaqueGlobal[] = "morok.path.opaque";
constexpr char kScratchPrefix[] = "morok.path.scratch";

bool isGeneratedBlock(const BasicBlock &BB) {
    return BB.getName().starts_with("morok.path");
}

Instruction *guardSplitPoint(BasicBlock &BB) {
    for (Instruction &I : BB) {
        if (isa<PHINode>(&I) || isa<AllocaInst>(&I))
            continue;
        if (I.isTerminator())
            return nullptr;
        return &I;
    }
    return nullptr;
}

GlobalVariable *opaqueGlobal(Module &M, ir::IRRandom &rng) {
    if (auto *GV = M.getGlobalVariable(kOpaqueGlobal, /*AllowInternal=*/true))
        return GV;
    auto *I32 = Type::getInt32Ty(M.getContext());
    return new GlobalVariable(
        M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32, static_cast<std::uint32_t>(rng.next())),
        kOpaqueGlobal);
}

AllocaInst *findScratch(Function &F) {
    for (Instruction &I : F.getEntryBlock())
        if (auto *AI = dyn_cast<AllocaInst>(&I))
            if (AI->getName().starts_with(kScratchPrefix))
                return AI;
    return nullptr;
}

AllocaInst *ensureScratch(Function &F) {
    if (AllocaInst *Existing = findScratch(F))
        return Existing;

    LLVMContext &Ctx = F.getContext();
    IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *ScratchTy = ArrayType::get(I64, 8);
    auto *Scratch = B.CreateAlloca(ScratchTy, nullptr, kScratchPrefix);
    Scratch->setAlignment(Align(8));
    return Scratch;
}

Value *asI64(IRBuilder<NoFolder> &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    if (V->getType() == I64)
        return V;
    if (auto *IT = dyn_cast<IntegerType>(V->getType())) {
        if (IT->getBitWidth() < 64)
            return B.CreateZExt(V, I64, "morok.path.seed.zext");
        return B.CreateTrunc(V, I64, "morok.path.seed.trunc");
    }
    if (V->getType()->isPointerTy())
        return B.CreatePtrToInt(V, I64, "morok.path.seed.ptr");
    return nullptr;
}

Value *buildInputSeed(IRBuilder<NoFolder> &B, Function &F, ir::IRRandom &rng) {
    auto *I64 = B.getInt64Ty();
    Value *Seed = ConstantInt::get(I64, rng.next());
    for (Argument &Arg : F.args()) {
        // A swifterror pointer may only be loaded/stored or used in select/phi;
        // ptrtoint on it (via asI64) fails the verifier.
        if (Arg.hasSwiftErrorAttr())
            continue;
        Value *Term = asI64(B, &Arg);
        if (!Term)
            continue;
        Value *Salt = ConstantInt::get(I64, rng.next());
        Value *Mixed = B.CreateXor(Term, Salt, "morok.path.seed.term");
        Seed = B.CreateXor(Seed, Mixed, "morok.path.seed.mix");
        Seed = B.CreateMul(Seed, ConstantInt::get(I64, rng.next() | 1ull),
                           "morok.path.seed");
    }
    return Seed;
}

Value *buildOpaqueTrue(IRBuilder<NoFolder> &B, GlobalVariable *GV) {
    auto *I32 = Type::getInt32Ty(B.getContext());
    auto *A = B.CreateLoad(I32, GV, /*isVolatile=*/true);
    auto *Bv = B.CreateLoad(I32, GV, /*isVolatile=*/true);
    return B.CreateICmpEQ(A, Bv, "morok.path.guard");
}

Value *scratchSlot(IRBuilder<NoFolder> &B, AllocaInst *Scratch, Value *Acc) {
    auto *I32 = B.getInt32Ty();
    Value *Low = B.CreateTrunc(Acc, I32, "morok.path.slot.raw");
    Value *Idx = B.CreateAnd(Low, ConstantInt::get(I32, 7), "morok.path.slot");
    return B.CreateInBoundsGEP(Scratch->getAllocatedType(), Scratch,
                               {ConstantInt::get(I32, 0), Idx},
                               "morok.path.scratch.ptr");
}

Value *boundFromSeed(IRBuilder<NoFolder> &B, Value *Seed,
                     std::uint32_t maxIterations) {
    auto *I32 = B.getInt32Ty();
    const std::uint32_t Cap = std::clamp<std::uint32_t>(maxIterations, 1, 64);
    Value *Seed32 = B.CreateTrunc(Seed, I32, "morok.path.bound.seed");
    Value *Masked = B.CreateURem(Seed32, ConstantInt::get(I32, Cap),
                                 "morok.path.bound.mod");
    return B.CreateAdd(Masked, ConstantInt::get(I32, 1), "morok.path.bound");
}

void buildCaseBody(BasicBlock *CaseBB, BasicBlock *LoopBB, BasicBlock *ExitBB,
                   PHINode *I, PHINode *Acc, Value *Bound, std::uint64_t Salt,
                   unsigned Variant) {
    IRBuilder<NoFolder> B(CaseBB);
    auto *I32 = B.getInt32Ty();
    auto *I64 = B.getInt64Ty();
    Value *NextI = B.CreateAdd(I, ConstantInt::get(I32, 1), "morok.path.nexti");
    Value *Mix = nullptr;
    switch (Variant) {
    case 0:
        Mix = B.CreateXor(Acc, ConstantInt::get(I64, Salt),
                          "morok.path.case.mix");
        break;
    case 1:
        Mix = B.CreateAdd(Acc, ConstantInt::get(I64, Salt),
                          "morok.path.case.mix");
        break;
    default:
        Mix = B.CreateMul(B.CreateXor(Acc, ConstantInt::get(I64, Salt)),
                          ConstantInt::get(I64, Salt | 1ull),
                          "morok.path.case.mix");
        break;
    }
    Value *Done = B.CreateICmpUGE(NextI, Bound, "morok.path.done");
    B.CreateCondBr(Done, ExitBB, LoopBB);
    I->addIncoming(NextI, CaseBB);
    Acc->addIncoming(Mix, CaseBB);
}

void buildDecoy(Function &F, BasicBlock *DecoyEntry, BasicBlock *Body,
                AllocaInst *Scratch, const PathExplosionParams &Params,
                ir::IRRandom &rng) {
    LLVMContext &Ctx = F.getContext();
    BasicBlock *LoopBB = BasicBlock::Create(Ctx, "morok.path.loop", &F, Body);
    BasicBlock *Case0 = BasicBlock::Create(Ctx, "morok.path.case0", &F, Body);
    BasicBlock *Case1 = BasicBlock::Create(Ctx, "morok.path.case1", &F, Body);
    BasicBlock *Case2 = BasicBlock::Create(Ctx, "morok.path.case2", &F, Body);
    BasicBlock *ExitBB = BasicBlock::Create(Ctx, "morok.path.exit", &F, Body);

    IRBuilder<NoFolder> EB(DecoyEntry);
    Value *Seed = buildInputSeed(EB, F, rng);
    Value *Bound = boundFromSeed(EB, Seed, Params.max_iterations);
    EB.CreateBr(LoopBB);

    IRBuilder<NoFolder> LB(LoopBB);
    auto *I32 = LB.getInt32Ty();
    auto *I64 = LB.getInt64Ty();
    PHINode *I = LB.CreatePHI(I32, 4, "morok.path.i");
    PHINode *Acc = LB.CreatePHI(I64, 4, "morok.path.acc");
    I->addIncoming(ConstantInt::get(I32, 0), DecoyEntry);
    Acc->addIncoming(Seed, DecoyEntry);

    auto *Store = LB.CreateStore(Acc, scratchSlot(LB, Scratch, Acc));
    Store->setVolatile(true);
    Store->setAlignment(Align(8));

    Value *TagBase =
        LB.CreateXor(Acc, LB.CreateZExt(Bound, I64), "morok.path.tagbase");
    Value *Tag = LB.CreateAnd(LB.CreateTrunc(TagBase, I32),
                              ConstantInt::get(I32, 3), "morok.path.tag");
    Value *Is0 = LB.CreateICmpEQ(Tag, ConstantInt::get(I32, 0));
    Value *Is1 = LB.CreateICmpEQ(Tag, ConstantInt::get(I32, 1));
    Constant *Addr0 = BlockAddress::get(Case0);
    Constant *Addr1 = BlockAddress::get(Case1);
    Constant *Addr2 = BlockAddress::get(Case2);
    Value *Target = LB.CreateSelect(Is1, Addr1, Addr2, "morok.path.target.1");
    Target = LB.CreateSelect(Is0, Addr0, Target, "morok.path.target");
    IndirectBrInst *IB = LB.CreateIndirectBr(Target, 3);
    IB->addDestination(Case0);
    IB->addDestination(Case1);
    IB->addDestination(Case2);

    buildCaseBody(Case0, LoopBB, ExitBB, I, Acc, Bound, rng.next(), 0);
    buildCaseBody(Case1, LoopBB, ExitBB, I, Acc, Bound, rng.next(), 1);
    buildCaseBody(Case2, LoopBB, ExitBB, I, Acc, Bound, rng.next(), 2);

    IRBuilder<NoFolder> XB(ExitBB);
    auto *Load =
        XB.CreateLoad(I64, scratchSlot(XB, Scratch, Acc), "morok.path.sink");
    Load->setVolatile(true);
    Load->setAlignment(Align(8));
    XB.CreateBr(Body);
}

} // namespace

bool pathExplosionFunction(Function &F, const PathExplosionParams &params,
                           ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        params.probability == 0 || params.max_blocks == 0 ||
        params.max_iterations == 0)
        return false;

    std::vector<BasicBlock *> blocks;
    for (BasicBlock &BB : F)
        blocks.push_back(&BB);

    Module &M = *F.getParent();
    AllocaInst *Scratch = nullptr;
    bool changed = false;
    std::uint32_t transformed = 0;

    for (BasicBlock *Head : blocks) {
        if (transformed >= params.max_blocks)
            break;
        if (Head->isEHPad() || Head->isLandingPad() || isGeneratedBlock(*Head))
            continue;
        if (!rng.chance(params.probability))
            continue;

        Instruction *SplitPt = guardSplitPoint(*Head);
        if (!SplitPt)
            continue;

        if (!Scratch)
            Scratch = ensureScratch(F);

        BasicBlock *Body = SplitBlock(Head, SplitPt);
        BasicBlock *DecoyEntry =
            BasicBlock::Create(F.getContext(), "morok.path.entry", &F, Body);
        buildDecoy(F, DecoyEntry, Body, Scratch, params, rng);

        Instruction *HeadTerm = Head->getTerminator();
        IRBuilder<NoFolder> B(HeadTerm);
        Value *Guard = buildOpaqueTrue(B, opaqueGlobal(M, rng));
        B.CreateCondBr(Guard, Body, DecoyEntry);
        HeadTerm->eraseFromParent();

        changed = true;
        ++transformed;
    }

    return changed;
}

PreservedAnalyses PathExplosionPass::run(Function &F,
                                         FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return pathExplosionFunction(F, params_, rng) ? PreservedAnalyses::none()
                                                  : PreservedAnalyses::all();
}

} // namespace morok::passes
