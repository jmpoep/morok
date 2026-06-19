// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/MutualGuardGraph.cpp
//
// IR-stage mutual guard graph.  Final native code-region checksums need
// post-link sizing, so this pass emits private IR-owned checksum regions plus
// mutable native-code window descriptors that a post-link sealer can fill. Each
// checker validates its own region, peer expected hashes, and sealed native
// bytes; the graph's combined diff is fused into return values as data, not a
// trap or branch.

#include "morok/passes/MutualGuardGraph.hpp"

#include "morok/ir/InstUtil.hpp"
#include "morok/passes/CodeRegionKdf.hpp"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

using Builder = IRBuilder<NoFolder>;

// Fixed post-link manifest sentinel. Keep this non-printable: readable product
// markers in emitted binaries become cheap static-analysis anchors.
constexpr std::uint64_t kPostlinkMagic = 0x8E21B7C4005AF10DULL;

struct NodeRuntime {
    GlobalVariable *region = nullptr;
    GlobalVariable *expected = nullptr;
    GlobalVariable *code_size = nullptr;
    GlobalVariable *native_expected = nullptr;
    Function *checker = nullptr;
    std::uint64_t expected_hash = 0;
    std::uint64_t seed = 0;
};

struct GraphRuntime {
    Function *diff = nullptr;
    std::vector<NodeRuntime> nodes;
};

bool generatedFunction(const Function &F) {
    return F.getName().starts_with("morok.");
}

bool directlyRecursive(Function &F) {
    for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (CB && CB->getCalledFunction() == &F)
            return true;
    }
    return false;
}

std::string suffixFor(Function &F) { return F.getName().str(); }

bool eligibleReturn(ReturnInst *RI) {
    if (!RI || RI->getNumOperands() == 0)
        return false;
    if (ir::isMustTailReturn(*RI))
        return false;
    Type *Ty = RI->getOperand(0)->getType();
    if (auto *IntTy = dyn_cast<IntegerType>(Ty))
        return IntTy->getBitWidth() <= 64;
    return Ty->isHalfTy() || Ty->isBFloatTy() || Ty->isFloatTy() ||
           Ty->isDoubleTy();
}

IntegerType *integerCarrierFor(Type *Ty) {
    if (auto *IntTy = dyn_cast<IntegerType>(Ty))
        return IntTy;
    const unsigned Bits = static_cast<unsigned>(Ty->getPrimitiveSizeInBits());
    return IntegerType::get(Ty->getContext(), Bits);
}

Value *rotl64(Builder &B, Value *V, unsigned Amount, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    const unsigned Sh = (Amount % 63u) + 1u;
    Value *L = B.CreateShl(V, ConstantInt::get(I64, Sh), Name + ".lo");
    Value *R = B.CreateLShr(V, ConstantInt::get(I64, 64u - Sh), Name + ".hi");
    return B.CreateOr(L, R, Name);
}

std::uint32_t coverageDepth(std::uint32_t Count) {
    return std::min<std::uint32_t>(Count, 3);
}

std::vector<std::uint32_t> coveredRegionIndices(std::uint32_t Index,
                                                std::uint32_t Count) {
    std::vector<std::uint32_t> Indices;
    Indices.reserve(coverageDepth(Count));
    auto addUnique = [&](std::uint32_t I) {
        if (std::find(Indices.begin(), Indices.end(), I) == Indices.end())
            Indices.push_back(I);
    };
    addUnique(Index);
    addUnique((Index + Count - 1u) % Count);
    addUnique((Index + 1u) % Count);
    return Indices;
}

std::vector<std::uint8_t> randomRegion(std::uint32_t Size, ir::IRRandom &Rng) {
    std::vector<std::uint8_t> Bytes;
    Bytes.reserve(Size);
    for (std::uint32_t I = 0; I < Size; ++I)
        Bytes.push_back(static_cast<std::uint8_t>(Rng.next()));
    return Bytes;
}

void addRuntimeAttrs(Function *F) {
    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr(Attribute::OptimizeNone);
    F->setMemoryEffects(MemoryEffects::unknown());
}

void relaxMemoryAttrs(Function &F) {
    F.setMemoryEffects(MemoryEffects::unknown());
    F.removeFnAttr(Attribute::NoSync);
}

void invalidateCallerEffects(Function &F) {
    SmallVector<Function *, 8> Worklist;
    SmallPtrSet<Function *, 16> Seen;
    Worklist.push_back(&F);
    Seen.insert(&F);

    while (!Worklist.empty()) {
        Function *Current = Worklist.pop_back_val();
        for (User *U : Current->users()) {
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB)
                continue;
            CB->setMemoryEffects(MemoryEffects::unknown());
            CB->removeFnAttr(Attribute::NoSync);

            Function *Caller = CB->getFunction();
            if (!Caller || !Seen.insert(Caller).second)
                continue;
            relaxMemoryAttrs(*Caller);
            Worklist.push_back(Caller);
        }
    }
}

void shuffleReturns(std::vector<ReturnInst *> &Returns, ir::IRRandom &Rng) {
    for (std::size_t I = Returns.size(); I > 1; --I) {
        const std::size_t J = Rng.range(static_cast<std::uint32_t>(I));
        std::swap(Returns[I - 1], Returns[J]);
    }
}

GlobalVariable *createRegion(Module &M, StringRef Suffix, std::uint32_t Index,
                             ArrayRef<std::uint8_t> Bytes) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *ArrTy = ArrayType::get(I8, Bytes.size());
    auto *Region = new GlobalVariable(
        M, ArrTy, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantDataArray::get(Ctx, Bytes),
        (Twine("morok.mg.region.") + Suffix + "." + Twine(Index)).str());
    Region->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Region->setAlignment(Align(1));
    return Region;
}

GlobalVariable *createExpected(Module &M, StringRef Suffix, std::uint32_t Index,
                               std::uint64_t ExpectedHash) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *Expected = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, ExpectedHash),
        (Twine("morok.mg.expected.") + Suffix + "." + Twine(Index)).str());
    Expected->setAlignment(Align(8));
    return Expected;
}

GlobalVariable *createCodeSize(Module &M, StringRef Suffix,
                               std::uint32_t Index) {
    auto *I32 = Type::getInt32Ty(M.getContext());
    auto *CodeSize = new GlobalVariable(
        M, I32, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32, code_region_kdf::kUnsealedCodeSize),
        (Twine("morok.mg.code.size.") + Suffix + "." + Twine(Index)).str());
    CodeSize->setAlignment(Align(4));
    return CodeSize;
}

GlobalVariable *createNativeExpected(Module &M, StringRef Suffix,
                                     std::uint32_t Index,
                                     std::uint64_t Initial) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *Expected = new GlobalVariable(
        M, I64, /*isConstant=*/false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64, Initial ? Initial : 1),
        (Twine("morok.mg.native.expected.") + Suffix + "." + Twine(Index))
            .str());
    Expected->setAlignment(Align(8));
    return Expected;
}

Value *regionPtr(Builder &B, GlobalVariable *Region, Value *Idx) {
    auto *I32 = B.getInt32Ty();
    auto *ArrTy = cast<ArrayType>(Region->getValueType());
    return B.CreateInBoundsGEP(ArrTy, Region, {ConstantInt::get(I32, 0), Idx},
                               "morok.mg.region.ptr");
}

Value *nativeHashSeed(Builder &B, Value *RegionHash,
                      std::uint32_t RegionIndex) {
    auto *I64 = B.getInt64Ty();
    Value *Rot = rotl64(B, RegionHash, 17u + RegionIndex * 11u,
                        "morok.mg.code.seed.rot");
    Value *Salt = ConstantInt::get(I64, 0xd6e8feb86659fd93ULL +
                                            RegionIndex * 0x100000001b3ULL);
    Value *Mul = B.CreateMul(
        B.CreateXor(RegionHash, Salt, "morok.mg.code.seed.xor"),
        ConstantInt::get(I64, 0x94d049bb133111ebULL + RegionIndex * 0x9e37ULL),
        "morok.mg.code.seed.mul");
    return B.CreateXor(Rot, Mul, "morok.mg.code.seed");
}

LoadInst *volatileExpectedLoad(Builder &B, GlobalVariable *Expected,
                               const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    auto *Load = B.CreateLoad(I64, Expected, Name);
    Load->setVolatile(true);
    Load->setAlignment(Align(8));
    return Load;
}

Value *emitCoveredRegionCheck(Module &M, Function *Fn, Function *Target,
                              Builder &B, const NodeRuntime &Covered,
                              std::uint32_t RegionIndex, bool Peer,
                              Value *Acc) {
    LLVMContext &Ctx = M.getContext();
    auto *I8 = Type::getInt8Ty(Ctx);
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    const auto *ArrTy = cast<ArrayType>(Covered.region->getValueType());
    const std::uint32_t Size =
        static_cast<std::uint32_t>(ArrTy->getNumElements());

    BasicBlock *Pred = B.GetInsertBlock();
    BasicBlock *Loop =
        BasicBlock::Create(Ctx, Peer ? "peer.hash" : "self.hash", Fn);
    BasicBlock *CodeCheck = BasicBlock::Create(
        Ctx, Peer ? "peer.code.check" : "self.code.check", Fn);
    BasicBlock *CodeLoop =
        BasicBlock::Create(Ctx, Peer ? "peer.code.hash" : "self.code.hash", Fn);
    BasicBlock *Exit =
        BasicBlock::Create(Ctx, Peer ? "peer.exit" : "self.exit", Fn);
    B.CreateBr(Loop);

    Builder LB(Loop);
    PHINode *I = LB.CreatePHI(I32, 2, "morok.mg.hash.i");
    PHINode *H = LB.CreatePHI(I64, 2, "morok.mg.hash");
    I->addIncoming(ConstantInt::get(I32, 0), Pred);
    H->addIncoming(ConstantInt::get(I64, Covered.seed), Pred);
    auto *Byte = LB.CreateLoad(I8, regionPtr(LB, Covered.region, I),
                               "morok.mg.region.byte");
    Byte->setVolatile(true);
    Byte->setAlignment(Align(1));
    Value *NextH = code_region_kdf::emitHashStep(LB, H, Byte,
                                                 "morok.mg.hash");
    Value *NextI =
        LB.CreateAdd(I, ConstantInt::get(I32, 1), "morok.mg.hash.next");
    I->addIncoming(NextI, Loop);
    H->addIncoming(NextH, Loop);
    Value *Done = LB.CreateICmpEQ(NextI, ConstantInt::get(I32, Size),
                                  "morok.mg.hash.done");
    LB.CreateCondBr(Done, CodeCheck, Loop);

    Builder CB(CodeCheck);
    Value *CodeSeed = nativeHashSeed(CB, NextH, RegionIndex);
    code_region_kdf::SealedCodeHash CodeHash =
        code_region_kdf::emitSealedCodeHash(
            CB, CodeCheck, CodeLoop, Exit, Target, Covered.code_size, CodeSeed,
            ConstantInt::get(I64, 0), "morok.mg", "morok.mg.code.final");

    Builder XB(Exit);
    PHINode *NativeH = CodeHash.final_hash;
    Value *HasCode = CodeHash.has_code;
    Value *OwnLoaded = volatileExpectedLoad(XB, Covered.expected,
                                            Peer ? "morok.mg.peer.expected.load"
                                                 : "morok.mg.expected.load");
    Value *RegionDiff = XB.CreateXor(NextH, OwnLoaded,
                                     Peer ? "morok.mg.peer.region.diff"
                                          : "morok.mg.node.region.diff");
    Value *ExpectedDiff = XB.CreateXor(
        OwnLoaded, ConstantInt::get(I64, Covered.expected_hash),
        Peer ? "morok.mg.peer.expected.diff" : "morok.mg.expected.diff");
    Value *ExpectedRot = rotl64(XB, ExpectedDiff, 23u + RegionIndex * 5u,
                                Peer ? "morok.mg.peer.expected.diff.rot"
                                     : "morok.mg.expected.diff.rot");
    Value *ExpectedMix = XB.CreateMul(
        XB.CreateXor(ExpectedDiff, ExpectedRot, "morok.mg.expected.diff.mix"),
        ConstantInt::get(I64, 0xd6e8feb86659fd93ULL + RegionIndex * 0x401u),
        Peer ? "morok.mg.peer.expected.diff.mul"
             : "morok.mg.expected.diff.mul");
    auto *NativeExpected =
        XB.CreateLoad(I64, Covered.native_expected,
                      Peer ? "morok.mg.peer.native.expected.load"
                           : "morok.mg.native.expected.load");
    NativeExpected->setVolatile(true);
    NativeExpected->setAlignment(Align(8));
    Value *NativeDiff = XB.CreateXor(NativeH, NativeExpected,
                                     Peer ? "morok.mg.peer.native.diff"
                                          : "morok.mg.native.diff");
    Value *NativeRot = rotl64(XB, NativeDiff, 19u + RegionIndex * 13u,
                              Peer ? "morok.mg.peer.native.diff.rot"
                                   : "morok.mg.native.diff.rot");
    Value *NativeMix = XB.CreateMul(
        XB.CreateXor(NativeDiff, NativeRot, "morok.mg.native.diff.mix"),
        ConstantInt::get(I64, 0xbf58476d1ce4e5b9ULL + RegionIndex * 0x211u),
        Peer ? "morok.mg.peer.native.diff.mul" : "morok.mg.native.diff.mul");
    NativeMix = XB.CreateSelect(HasCode, NativeMix, ConstantInt::get(I64, 0),
                                "morok.mg.native.diff");
    Value *CoverDiff =
        XB.CreateXor(RegionDiff, ExpectedMix, "morok.mg.node.diff");
    CoverDiff = XB.CreateXor(CoverDiff, NativeMix, "morok.mg.node.diff");
    Value *Rot =
        rotl64(XB, CoverDiff, 11u + RegionIndex * 7u, "morok.mg.node.diff.rot");
    Value *Mix = XB.CreateMul(
        XB.CreateXor(CoverDiff, Rot, "morok.mg.node.diff"),
        ConstantInt::get(I64, 0x9e3779b97f4a7c15ULL + RegionIndex * 0x101u),
        "morok.mg.node.diff.mul");
    Value *NextAcc = XB.CreateXor(Acc, Mix, "morok.mg.node.diff");
    B.SetInsertPoint(Exit);
    return NextAcc;
}

Function *createNodeFunction(Module &M, Function &Target, StringRef Suffix,
                             std::uint32_t Index, ArrayRef<NodeRuntime> Nodes) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    const std::uint32_t Count = static_cast<std::uint32_t>(Nodes.size());

    auto *Fn = Function::Create(
        FunctionType::get(I64, false), GlobalValue::InternalLinkage,
        (Twine("morok.mg.node.") + Suffix + "." + Twine(Index)).str(), &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    Builder B(Entry);
    Value *Acc = ConstantInt::get(I64, 0);
    for (std::uint32_t RegionIndex : coveredRegionIndices(Index, Count)) {
        Acc = emitCoveredRegionCheck(M, Fn, &Target, B, Nodes[RegionIndex],
                                     RegionIndex, RegionIndex != Index, Acc);
    }
    Value *Rot = rotl64(B, Acc, 9u + Index * 7u, "morok.mg.node.diff.rot");
    Value *Mul = B.CreateMul(
        Acc, ConstantInt::get(I64, 0x9e3779b97f4a7c15ULL + Index * 0x101u),
        "morok.mg.node.diff.mul");
    B.CreateRet(B.CreateXor(Mul, Rot, "morok.mg.node.diff"));
    return Fn;
}

Function *createDiffFunction(Module &M, StringRef Suffix,
                             ArrayRef<NodeRuntime> Nodes) {
    LLVMContext &Ctx = M.getContext();
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *Fn = Function::Create(FunctionType::get(I64, false),
                                GlobalValue::InternalLinkage,
                                (Twine("morok.mg.diff.") + Suffix).str(), &M);
    addRuntimeAttrs(Fn);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
    Builder B(Entry);
    Value *Acc = ConstantInt::get(I64, 0);
    for (std::uint32_t I = 0, E = static_cast<std::uint32_t>(Nodes.size());
         I != E; ++I) {
        Function *Node = Nodes[I].checker;
        Value *D = B.CreateCall(Node->getFunctionType(), Node, {},
                                "morok.mg.node.call");
        Value *Rot = rotl64(B, D, 13u + I * 5u, "morok.mg.diff.rot");
        Value *Mix = B.CreateXor(D, Rot, "morok.mg.diff");
        Mix = B.CreateMul(
            Mix, ConstantInt::get(I64, 0xbf58476d1ce4e5b9ULL + I * 0x211u),
            "morok.mg.diff");
        Acc = B.CreateXor(Acc, Mix, "morok.mg.diff");
    }
    B.CreateRet(Acc);
    return Fn;
}

GlobalVariable *createPostlinkManifest(Module &M, Function &Target,
                                       StringRef Suffix,
                                       ArrayRef<NodeRuntime> Nodes,
                                       std::uint32_t RegionSize,
                                       std::uint32_t CoverageDepth) {
    LLVMContext &Ctx = M.getContext();
    auto *I32 = Type::getInt32Ty(Ctx);
    auto *I64 = Type::getInt64Ty(Ctx);
    auto *PtrTy = PointerType::getUnqual(Ctx);
    auto *NodeTy =
        StructType::get(Ctx, {PtrTy, PtrTy, PtrTy, PtrTy, PtrTy, I64, I64});
    SmallVector<Constant *, 16> NodeRecords;
    NodeRecords.reserve(Nodes.size());
    auto *Scrubbed = ConstantInt::get(I64, 0);
    for (const NodeRuntime &Node : Nodes) {
        // The retained manifest is a layout contract, not a recompute oracle.
        // Keep live seeds and baked hashes only in the checker code/globals.
        NodeRecords.push_back(ConstantStruct::get(
            NodeTy, {Node.region, Node.expected, &Target, Node.code_size,
                     Node.native_expected, Scrubbed, Scrubbed}));
    }
    auto *NodesTy = ArrayType::get(NodeTy, NodeRecords.size());
    auto *ManifestTy = StructType::get(Ctx, {I64, I32, I32, I32, I32, NodesTy});
    auto *Init = ConstantStruct::get(
        ManifestTy,
        {ConstantInt::get(I64, kPostlinkMagic), ConstantInt::get(I32, 3),
         ConstantInt::get(I32, Nodes.size()), ConstantInt::get(I32, RegionSize),
         ConstantInt::get(I32, CoverageDepth),
         ConstantArray::get(NodesTy, NodeRecords)});
    auto *Manifest = new GlobalVariable(
        M, ManifestTy, /*isConstant=*/true, GlobalValue::PrivateLinkage, Init,
        (Twine("morok.postlink.mg.") + Suffix).str());
    Manifest->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
    Manifest->setAlignment(Align(8));
    appendToCompilerUsed(M, {Manifest});
    return Manifest;
}

GraphRuntime createGraph(Function &F, const MutualGuardGraphParams &Params,
                         ir::IRRandom &Rng) {
    Module &M = *F.getParent();
    const std::string Suffix = suffixFor(F);
    const std::uint32_t Count = std::clamp<std::uint32_t>(Params.nodes, 2, 16);
    const std::uint32_t RegionSize =
        std::clamp<std::uint32_t>(Params.region_bytes, 8, 1024);

    GraphRuntime G;
    G.nodes.reserve(Count);
    for (std::uint32_t I = 0; I != Count; ++I) {
        NodeRuntime Node;
        Node.seed = Rng.next();
        std::vector<std::uint8_t> Bytes = randomRegion(RegionSize, Rng);
        Node.expected_hash = code_region_kdf::hashBytes(
            ArrayRef<std::uint8_t>(Bytes.data(), Bytes.size()), Node.seed);
        Node.region = createRegion(
            M, Suffix, I, ArrayRef<std::uint8_t>(Bytes.data(), Bytes.size()));
        Node.expected = createExpected(M, Suffix, I, Node.expected_hash);
        Node.code_size = createCodeSize(M, Suffix, I);
        Node.native_expected =
            createNativeExpected(M, Suffix, I, Rng.next() | 1ULL);
        G.nodes.push_back(Node);
    }

    for (std::uint32_t I = 0; I != Count; ++I)
        G.nodes[I].checker =
            createNodeFunction(M, F, Suffix, I, ArrayRef<NodeRuntime>(G.nodes));
    createPostlinkManifest(M, F, Suffix, ArrayRef<NodeRuntime>(G.nodes),
                           RegionSize, coverageDepth(Count));
    G.diff = createDiffFunction(M, Suffix, ArrayRef<NodeRuntime>(G.nodes));
    return G;
}

Value *emitPoisonedReturn(ReturnInst *RI, Function *Diff) {
    Value *RetVal = RI->getOperand(0);
    Type *ReturnTy = RetVal->getType();
    IntegerType *CarrierTy = integerCarrierFor(ReturnTy);
    Builder B(RI);
    Value *GraphDiff =
        B.CreateCall(Diff->getFunctionType(), Diff, {}, "morok.mg.diff.call");
    Value *Narrow = GraphDiff;
    if (CarrierTy->getBitWidth() < 64)
        Narrow = B.CreateTrunc(GraphDiff, CarrierTy, "morok.mg.diff.trunc");

    Value *RetBits = RetVal;
    if (!ReturnTy->isIntegerTy())
        RetBits = B.CreateBitCast(RetBits, CarrierTy, "morok.mg.bits");

    Value *PoisonedBits = B.CreateXor(
        RetBits, Narrow,
        ReturnTy->isIntegerTy() ? "morok.mg.value" : "morok.mg.bits.value");
    if (ReturnTy->isIntegerTy())
        return PoisonedBits;
    return B.CreateBitCast(PoisonedBits, ReturnTy, "morok.mg.value");
}

} // namespace

bool mutualGuardGraphFunction(Function &F, const MutualGuardGraphParams &Params,
                              ir::IRRandom &Rng) {
    if (F.isDeclaration() || generatedFunction(F) || Params.probability == 0 ||
        Params.nodes < 2 || Params.region_bytes == 0 || Params.max_returns == 0)
        return false;
    if (directlyRecursive(F))
        return false;

    const std::string DiffName = "morok.mg.diff." + suffixFor(F);
    if (F.getParent()->getFunction(DiffName))
        return false;

    std::vector<ReturnInst *> Returns;
    for (BasicBlock &BB : F)
        if (eligibleReturn(dyn_cast<ReturnInst>(BB.getTerminator())))
            Returns.push_back(cast<ReturnInst>(BB.getTerminator()));
    if (Returns.empty())
        return false;
    shuffleReturns(Returns, Rng);

    SmallVector<ReturnInst *, 8> Selected;
    for (ReturnInst *RI : Returns) {
        if (Selected.size() >= Params.max_returns)
            break;
        if (!Rng.chance(Params.probability))
            continue;
        Selected.push_back(RI);
    }
    if (Selected.empty())
        return false;

    GraphRuntime G = createGraph(F, Params, Rng);
    for (ReturnInst *RI : Selected)
        RI->setOperand(0, emitPoisonedReturn(RI, G.diff));

    relaxMemoryAttrs(F);
    invalidateCallerEffects(F);
    return true;
}

PreservedAnalyses MutualGuardGraphPass::run(Function &F,
                                            FunctionAnalysisManager &) {
    ir::IRRandom Rng(engine_);
    return mutualGuardGraphFunction(F, params_, Rng) ? PreservedAnalyses::none()
                                                     : PreservedAnalyses::all();
}

} // namespace morok::passes
