// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// Shared post-link code-region hash provider for dataflow-bound consumers.

#include "morok/passes/CodeRegionKdf.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace morok::passes::code_region_kdf {
namespace {

Value *codePtr(IRBuilderBase &B, Function *Target, Value *Idx,
               const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Value *Base = B.CreatePtrToInt(Target, I64, Name + ".base");
    Value *Offset = B.CreateZExt(Idx, I64, Name + ".offset");
    Value *Addr = B.CreateAdd(Base, Offset, Name + ".addr");
    return B.CreateIntToPtr(Addr, PointerType::getUnqual(B.getContext()),
                            Name + ".ptr");
}

} // namespace

std::uint64_t hashStep(std::uint64_t H, std::uint8_t Byte) {
    H ^= Byte;
    H *= 0xff51afd7ed558ccdULL;
    H ^= H >> 32;
    H *= 0xc4ceb9fe1a85ec53ULL;
    return H ^ (H >> 29);
}

std::uint64_t hashBytes(ArrayRef<std::uint8_t> Bytes, std::uint64_t Seed) {
    std::uint64_t H = Seed;
    for (std::uint8_t B : Bytes)
        H = hashStep(H, B);
    return H;
}

Value *emitHashStep(IRBuilderBase &B, Value *H, Value *Byte,
                    const Twine &Name) {
    auto *I64 = B.getInt64Ty();
    Value *Wide = B.CreateZExt(Byte, I64, Name + ".byte");
    Value *X = B.CreateXor(H, Wide, Name + ".mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xff51afd7ed558ccdULL),
                    Name + ".mix");
    X = B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 32)),
                    Name + ".mix");
    X = B.CreateMul(X, ConstantInt::get(I64, 0xc4ceb9fe1a85ec53ULL),
                    Name + ".mix");
    return B.CreateXor(X, B.CreateLShr(X, ConstantInt::get(I64, 29)),
                       Name + ".mix");
}

SealedCodeHash emitSealedCodeHash(IRBuilderBase &CheckB,
                                  BasicBlock *CodeCheck,
                                  BasicBlock *CodeLoop,
                                  BasicBlock *Exit,
                                  Function *Target,
                                  GlobalVariable *CodeSize,
                                  Value *Seed,
                                  Value *UnsealedValue,
                                  StringRef Prefix,
                                  StringRef FinalName) {
    auto *I32 = CheckB.getInt32Ty();
    auto *I64 = CheckB.getInt64Ty();
    auto *I8 = CheckB.getInt8Ty();

    auto *CodeSizeLoad =
        CheckB.CreateLoad(I32, CodeSize, Prefix + ".code.size.load");
    CodeSizeLoad->setVolatile(true);
    CodeSizeLoad->setAlignment(Align(4));
    Value *NonZero = CheckB.CreateICmpNE(CodeSizeLoad, ConstantInt::get(I32, 0),
                                         Prefix + ".code.nz");
    Value *Sealed = CheckB.CreateICmpNE(
        CodeSizeLoad, ConstantInt::get(I32, kUnsealedCodeSize),
        Prefix + ".code.sealed");
    Value *HasCode = CheckB.CreateAnd(NonZero, Sealed, Prefix + ".code.has");
    CheckB.CreateCondBr(HasCode, CodeLoop, Exit);

    IRBuilderBase::InsertPointGuard Guard(CheckB);
    CheckB.SetInsertPoint(CodeLoop);
    auto *CI = CheckB.CreatePHI(I32, 2, Prefix + ".code.i");
    auto *CH = CheckB.CreatePHI(I64, 2, Prefix + ".code.hash");
    CI->addIncoming(ConstantInt::get(I32, 0), CodeCheck);
    CH->addIncoming(Seed, CodeCheck);
    auto *CodeByte = CheckB.CreateLoad(
        I8, codePtr(CheckB, Target, CI, Prefix + ".code"),
        Prefix + ".code.byte");
    CodeByte->setVolatile(true);
    CodeByte->setAlignment(Align(1));
    Value *NextCH = emitHashStep(CheckB, CH, CodeByte, Prefix + ".hash");
    Value *NextCI =
        CheckB.CreateAdd(CI, ConstantInt::get(I32, 1), Prefix + ".code.next");
    CI->addIncoming(NextCI, CodeLoop);
    CH->addIncoming(NextCH, CodeLoop);
    Value *CodeDone =
        CheckB.CreateICmpEQ(NextCI, CodeSizeLoad, Prefix + ".code.done");
    CheckB.CreateCondBr(CodeDone, Exit, CodeLoop);

    CheckB.SetInsertPoint(Exit);
    auto *FinalH = CheckB.CreatePHI(I64, 2, FinalName);
    FinalH->addIncoming(UnsealedValue, CodeCheck);
    FinalH->addIncoming(NextCH, CodeLoop);
    return {HasCode, FinalH};
}

} // namespace morok::passes::code_region_kdf
