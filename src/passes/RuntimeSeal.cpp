// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Shared runtime seal / KDF support for dataflow-bound detector consumers.

#include "morok/passes/RuntimeSeal.hpp"

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cctype>

using namespace llvm;

namespace morok::passes::runtime_seal {
namespace {

std::string rootName(StringRef Channel) {
    SmallString<64> Name("morok.seal.root.");
    for (char C : Channel) {
        const auto UC = static_cast<unsigned char>(C);
        Name.push_back((std::isalnum(UC) || C == '_' || C == '.') ? C : '_');
    }
    return std::string(Name);
}

std::string scoreName(StringRef Channel, StringRef Slot) {
    SmallString<64> Name("morok.seal.score.");
    for (char C : Channel) {
        const auto UC = static_cast<unsigned char>(C);
        Name.push_back((std::isalnum(UC) || C == '_' || C == '.') ? C : '_');
    }
    Name.push_back('.');
    Name.append(Slot);
    return std::string(Name);
}

Value *toI64(IRBuilderBase &B, Value *V) {
    auto *I64 = B.getInt64Ty();
    if (V->getType()->isIntegerTy(64))
        return V;
    if (V->getType()->isIntegerTy())
        return B.CreateZExtOrTrunc(V, I64);
    return B.CreatePtrToInt(V, I64);
}

Value *mix64(IRBuilderBase &B, Value *X, std::uint64_t Salt,
             const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    X = B.CreateAdd(X, ConstantInt::get(I64, Salt), Name + ".add");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 33)),
                    Name + ".fold33");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    Name + ".mul0");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                    Name + ".fold29");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    Name + ".mul1");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                       Name + ".fold32");
}

GlobalVariable *getScoreSlot(Module &M, StringRef Channel, StringRef Slot,
                             Type *Ty, Constant *Init, Align Alignment) {
    const std::string Name = scoreName(Channel, Slot);
    if (auto *Existing = M.getGlobalVariable(Name, /*AllowInternal=*/true))
        return Existing;
    auto *GV = new GlobalVariable(M, Ty, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage, Init, Name);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Alignment);
    return GV;
}

} // namespace

GlobalVariable *findChannel(Module &M, StringRef Channel) {
    return M.getGlobalVariable(rootName(Channel), /*AllowInternal=*/true);
}

GlobalVariable *getChannel(Module &M, StringRef Channel, ir::IRRandom &Rng) {
    if (auto *Existing = findChannel(M, Channel))
        return Existing;
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(M, I64, /*isConstant=*/false,
                                  GlobalValue::PrivateLinkage,
                                  ConstantInt::get(I64, Rng.next()),
                                  rootName(Channel));
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return GV;
}

std::uint64_t initialValue(const GlobalVariable *Seal) {
    if (!Seal || !Seal->hasInitializer())
        return 0;
    if (auto *CI = dyn_cast<ConstantInt>(Seal->getInitializer()))
        return CI->getZExtValue();
    return 0;
}

Value *emitDelta(IRBuilderBase &B, GlobalVariable *Seal,
                 std::uint64_t Initial, const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    if (!Seal)
        return ConstantInt::get(I64, 0);
    auto *Loaded = B.CreateLoad(I64, Seal, Name + ".load");
    Loaded->setVolatile(true);
    Loaded->setAlignment(Align(8));
    return B.CreateXor(Loaded, ConstantInt::get(I64, Initial),
                       Name + ".delta");
}

Value *emitChannelDelta(IRBuilderBase &B, StringRef Channel,
                        const Twine &Name) {
    Module *M = B.GetInsertBlock() ? B.GetInsertBlock()->getModule() : nullptr;
    if (!M)
        return ConstantInt::get(B.getInt64Ty(), 0);
    GlobalVariable *Seal = findChannel(*M, Channel);
    return emitDelta(B, Seal, initialValue(Seal), Name);
}

Value *emitKdf64(IRBuilderBase &B, Value *Delta, std::uint64_t Domain,
                 const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Delta = toI64(B, Delta);
    Value *Dirty = B.CreateICmpNE(Delta, ConstantInt::get(I64, 0),
                                  Name + ".dirty");
    Value *Seed =
        B.CreateXor(Delta, ConstantInt::get(I64, Domain),
                    Name + ".domain");
    Value *Mixed = mix64(B, Seed, Domain ^ 0x9E3779B97F4A7C15ULL, Name);
    return B.CreateSelect(Dirty, Mixed, ConstantInt::get(I64, 0),
                          Name + ".key");
}

void foldFlag(IRBuilderBase &B, StringRef Channel, Value *Flag,
              std::uint64_t Salt, const Twine &Name) {
    Module *M = B.GetInsertBlock() ? B.GetInsertBlock()->getModule() : nullptr;
    if (!M)
        return;
    GlobalVariable *Seal = findChannel(*M, Channel);
    if (!Seal)
        return;

    auto *I64 = B.getInt64Ty();
    Value *Tripped = B.CreateICmpNE(toI64(B, Flag), ConstantInt::get(I64, 0),
                                    Name + ".trip");
    auto *Cur = B.CreateLoad(I64, Seal, Name + ".cur");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Rot = B.CreateOr(B.CreateShl(Cur, ConstantInt::get(I64, 17)),
                            B.CreateLShr(Cur, ConstantInt::get(I64, 47)),
                            Name + ".rot");
    Value *Mixed =
        B.CreateXor(Rot, ConstantInt::get(I64, Salt ^ 0xD6E8FEB86659FD93ULL),
                    Name + ".salt");
    Mixed = B.CreateMul(
        Mixed, ConstantInt::get(I64, (Salt ^ 0x9E3779B97F4A7C15ULL) | 1ULL),
        Name + ".mul");
    Mixed = B.CreateAdd(
        Mixed, ConstantInt::get(I64, (Salt + 0xA0761D6478BD642FULL) | 1ULL),
        Name + ".mix");
    Value *Next = B.CreateSelect(Tripped, Mixed, Cur, Name + ".next");
    auto *Store = B.CreateStore(Next, Seal);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
}

void foldWord(IRBuilderBase &B, StringRef Channel, Value *Word,
              std::uint64_t Salt, const Twine &Name) {
    Module *M = B.GetInsertBlock() ? B.GetInsertBlock()->getModule() : nullptr;
    if (!M)
        return;
    GlobalVariable *Seal = findChannel(*M, Channel);
    if (!Seal)
        return;

    auto *I64 = B.getInt64Ty();
    Value *Word64 = toI64(B, Word);
    Value *Active = B.CreateICmpNE(Word64, ConstantInt::get(I64, 0),
                                   Name + ".active");
    auto *Cur = B.CreateLoad(I64, Seal, Name + ".cur");
    Cur->setVolatile(true);
    Cur->setAlignment(Align(8));
    Value *Input = B.CreateXor(Cur, Word64, Name + ".word");
    Value *Mixed = mix64(B, Input, Salt ^ 0xA0761D6478BD642FULL, Name);
    Value *Next = B.CreateSelect(Active, Mixed, Cur, Name + ".next");
    auto *Store = B.CreateStore(Next, Seal);
    Store->setVolatile(true);
    Store->setAlignment(Align(8));
}

void foldWeightedFlag(IRBuilderBase &B, StringRef Channel, Value *Flag,
                      std::uint32_t Weight, std::uint64_t EvidenceMask,
                      std::uint32_t Threshold, std::uint64_t Salt,
                      const Twine &Name) {
    Module *M = B.GetInsertBlock() ? B.GetInsertBlock()->getModule() : nullptr;
    if (!M || !findChannel(*M, Channel) || Weight == 0 || Threshold == 0)
        return;

    auto *I1 = B.getInt1Ty();
    auto *I32 = B.getInt32Ty();
    auto *I64 = B.getInt64Ty();
    GlobalVariable *Score =
        getScoreSlot(*M, Channel, "weight", I32, ConstantInt::get(I32, 0),
                     Align(4));
    GlobalVariable *Evidence =
        getScoreSlot(*M, Channel, "evidence", I64, ConstantInt::get(I64, 0),
                     Align(8));
    GlobalVariable *Committed = getScoreSlot(
        *M, Channel, "committed", I1, ConstantInt::getFalse(M->getContext()),
        Align(1));

    Value *Tripped = B.CreateICmpNE(toI64(B, Flag), ConstantInt::get(I64, 0),
                                    Name + ".trip");
    auto *OldScore = B.CreateLoad(I32, Score, Name + ".score.old");
    OldScore->setVolatile(true);
    OldScore->setAlignment(Align(4));
    auto *OldEvidence = B.CreateLoad(I64, Evidence, Name + ".evidence.old");
    OldEvidence->setVolatile(true);
    OldEvidence->setAlignment(Align(8));
    auto *OldCommitted =
        B.CreateLoad(I1, Committed, Name + ".committed.old");
    OldCommitted->setVolatile(true);
    OldCommitted->setAlignment(Align(1));

    Value *Bump = B.CreateSelect(Tripped, ConstantInt::get(I32, Weight),
                                 ConstantInt::get(I32, 0),
                                 Name + ".weight");
    Value *NextScore = B.CreateAdd(OldScore, Bump, Name + ".score.next");
    Value *NextEvidence = B.CreateSelect(
        Tripped,
        B.CreateOr(OldEvidence,
                   ConstantInt::get(I64, EvidenceMask ? EvidenceMask : 1),
                   Name + ".evidence.add"),
        OldEvidence, Name + ".evidence.next");

    auto *ScoreStore = B.CreateStore(NextScore, Score);
    ScoreStore->setVolatile(true);
    ScoreStore->setAlignment(Align(4));
    auto *EvidenceStore = B.CreateStore(NextEvidence, Evidence);
    EvidenceStore->setVolatile(true);
    EvidenceStore->setAlignment(Align(8));

    Value *EnoughWeight =
        B.CreateICmpUGE(NextScore, ConstantInt::get(I32, Threshold),
                        Name + ".enough");
    Value *EvidenceMinusOne =
        B.CreateSub(NextEvidence, ConstantInt::get(I64, 1),
                    Name + ".evidence.prev");
    Value *MultipleEvidence = B.CreateICmpNE(
        B.CreateAnd(NextEvidence, EvidenceMinusOne, Name + ".evidence.multi"),
        ConstantInt::get(I64, 0), Name + ".coherent");
    Value *ShouldCommit =
        B.CreateAnd(Tripped, EnoughWeight, Name + ".commit.weighted");
    ShouldCommit =
        B.CreateAnd(ShouldCommit, MultipleEvidence, Name + ".commit.coherent");
    ShouldCommit =
        B.CreateAnd(ShouldCommit, B.CreateNot(OldCommitted, Name + ".fresh"),
                    Name + ".commit");

    Value *ScoreWord = B.CreateXor(B.CreateZExt(NextScore, I64),
                                   NextEvidence, Name + ".word");
    ScoreWord = B.CreateSelect(ShouldCommit, ScoreWord,
                               ConstantInt::get(I64, 0), Name + ".active");
    foldWord(B, Channel, ScoreWord, Salt ^ 0x5A17C0DEF00D5A17ULL,
             Name + ".seal");

    Value *NextCommitted =
        B.CreateOr(OldCommitted, ShouldCommit, Name + ".committed.next");
    auto *CommitStore = B.CreateStore(NextCommitted, Committed);
    CommitStore->setVolatile(true);
    CommitStore->setAlignment(Align(1));
}

} // namespace morok::passes::runtime_seal
