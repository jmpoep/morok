// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/passes/ReturnlessDispatch.cpp
//
// Tail-position returns are rewritten into indirect tail branches.  A function
// whose body ends in `%r = call g(args) ; ret %r` (or `call g(args) ; ret void`
// for a void callee) leaves through a computed branch instead of a `ret`: the
// callee address is read from a volatile slot, the call is made indirect, and
// the tail-call kind forces the backend to emit `br x16` / `jmp *rax` with the
// frame torn down correctly.
//
// Only genuine tail-position returns are touched.  A function rewritten to end
// in a bare branch with no epilogue would skip the callee-saved restore and
// corrupt its caller; a tail call is the only IR form the backend lowers to an
// indirect branch *with* a correct epilogue.  Returns of computed values keep a
// real ABI return — eliminating those needs a uniform-signature continuation
// transform or a post-link rewriter, which this pass deliberately does not do.
//
// Perfect-forwarding sites (the call forwards F's own arguments with a matching
// prototype, calling convention, and ABI attributes) are marked `musttail`,
// which the verifier and backend guarantee lowers with no `ret`.  Any other
// eligible site is marked `tail`, a best-effort hint the backend honors when it
// can prove the call does not reference the local frame.

#include "morok/passes/ReturnlessDispatch.hpp"

#include "morok/ir/Annotations.hpp"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <vector>

using namespace llvm;

namespace morok::passes {

namespace {

struct Site {
    CallInst *call = nullptr;
    bool must_tail = false;
};

// ABI attributes that make a tail call unsafe or that the backend cannot tail
// through: the callee touches the caller's frame (byval/inalloca/preallocated)
// or carries a hidden ABI slot (sret/swifterror) we must not disturb.
bool hasBlockingAbiAttrs(CallInst &CI) {
    if (CI.hasStructRetAttr())
        return true;
    for (unsigned I = 0, E = CI.arg_size(); I != E; ++I) {
        if (CI.paramHasAttr(I, Attribute::ByVal) ||
            CI.paramHasAttr(I, Attribute::InAlloca) ||
            CI.paramHasAttr(I, Attribute::Preallocated) ||
            CI.paramHasAttr(I, Attribute::SwiftError) ||
            CI.paramHasAttr(I, Attribute::Nest))
            return true;
    }
    return false;
}

// The call's `%r = call ... ; ret %r` (or void) tail-position shape, plus the
// safety filters that keep the rewrite semantics-preserving.
bool eligibleSite(Function &F, ReturnInst &RI, CallInst &CI) {
    if (CI.getNextNode() != &RI)
        return false; // the call must be immediately before the return
    if (F.getReturnType()->isVoidTy()) {
        if (RI.getReturnValue() != nullptr || !CI.getType()->isVoidTy())
            return false;
    } else if (RI.getReturnValue() != &CI) {
        return false;
    }
    if (CI.isInlineAsm() || CI.hasOperandBundles())
        return false;
    if (CI.getFunctionType()->isVarArg())
        return false;
    const CallInst::TailCallKind TCK = CI.getTailCallKind();
    if (TCK == CallInst::TCK_MustTail || TCK == CallInst::TCK_NoTail)
        return false;
    if (CI.hasFnAttr(Attribute::ReturnsTwice))
        return false;
    if (hasBlockingAbiAttrs(CI))
        return false;

    Function *Callee = CI.getCalledFunction();
    if (!Callee || Callee->isDeclaration() || Callee->isIntrinsic())
        return false; // need a defined internal target to take the address of
    if (Callee->isVarArg() || Callee->hasFnAttribute(Attribute::ReturnsTwice))
        return false;
    if (Callee->getName().starts_with("morok."))
        return false;
    return true;
}

// True when `CI` perfectly forwards F's own arguments with a matching prototype
// and ABI attributes, so `musttail` is verifier-valid and guarantees no `ret`.
bool qualifiesForMustTail(Function &F, CallInst &CI) {
    if (F.isVarArg())
        return false;
    if (CI.getFunctionType() != F.getFunctionType())
        return false;
    if (CI.getCallingConv() != F.getCallingConv())
        return false;
    if (CI.arg_size() != F.arg_size())
        return false;
    for (unsigned I = 0, E = CI.arg_size(); I != E; ++I)
        if (CI.getArgOperand(I) != F.getArg(I))
            return false;

    const AttributeList FA = F.getAttributes();
    const AttributeList CA = CI.getAttributes();
    const Attribute::AttrKind AbiKinds[] = {Attribute::SExt, Attribute::ZExt,
                                            Attribute::InReg};
    for (Attribute::AttrKind K : AbiKinds)
        if (FA.hasRetAttr(K) != CA.hasRetAttr(K))
            return false;
    for (unsigned I = 0, E = CI.arg_size(); I != E; ++I)
        for (Attribute::AttrKind K : AbiKinds)
            if (FA.hasParamAttr(I, K) != CA.hasParamAttr(I, K))
                return false;
    return true;
}

GlobalVariable *makeTargetSlot(Module &M, Function *Callee) {
    auto *I64 = Type::getInt64Ty(M.getContext());
    auto *GV = new GlobalVariable(
        M, I64, /*isConstant=*/true, GlobalValue::PrivateLinkage,
        ConstantExpr::getPtrToInt(Callee, I64), "morok.retless.slot");
    GV->setAlignment(Align(8));
    appendToCompilerUsed(M, {GV});
    return GV;
}

void rewriteSite(Module &M, const Site &S) {
    CallInst *CI = S.call;
    IRBuilder<> B(CI);
    auto *I64 = B.getInt64Ty();
    auto *PtrTy = PointerType::getUnqual(M.getContext());

    GlobalVariable *Slot = makeTargetSlot(M, CI->getCalledFunction());
    LoadInst *Enc = B.CreateLoad(I64, Slot, /*isVolatile=*/true,
                                 "morok.retless.enc");
    Enc->setAlignment(Align(8));
    Value *Target = B.CreateIntToPtr(Enc, PtrTy, "morok.retless.target");

    CI->setCalledOperand(Target);
    CI->setTailCallKind(S.must_tail ? CallInst::TCK_MustTail
                                    : CallInst::TCK_Tail);
}

} // namespace

bool returnlessDispatchFunction(Function &F, const ReturnlessParams &params,
                                ir::IRRandom &rng) {
    if (F.isDeclaration() || F.getName().starts_with("morok.") ||
        F.hasFnAttribute(Attribute::Naked) || F.hasPersonalityFn() ||
        F.isVarArg() || params.probability == 0 || params.max_sites == 0)
        return false;
    // Honor explicit opt-out and keep hot/perf-annotated functions on a normal
    // return path (the indirect branch defeats the CPU return-address-stack
    // predictor and is not worth the slowdown on hot code).
    if (!ir::shouldObfuscate(F, "returnless", true) ||
        ir::hasAnnotation(F, "perf_critical") || ir::hasAnnotation(F, "hot"))
        return false;

    std::vector<Site> Sites;
    for (BasicBlock &BB : F) {
        if (Sites.size() >= params.max_sites)
            break;
        auto *RI = dyn_cast<ReturnInst>(BB.getTerminator());
        if (!RI)
            continue;
        auto *CI = dyn_cast_or_null<CallInst>(RI->getPrevNode());
        if (!CI || !eligibleSite(F, *RI, *CI))
            continue;
        if (!rng.chance(params.probability))
            continue;
        Sites.push_back({CI, qualifiesForMustTail(F, *CI)});
    }
    if (Sites.empty())
        return false;

    Module &M = *F.getParent();
    for (const Site &S : Sites)
        rewriteSite(M, S);
    return true;
}

bool returnlessDispatchModule(Module &M, const ReturnlessParams &params,
                              ir::IRRandom &rng) {
    if (params.probability == 0 || params.max_sites == 0)
        return false;
    bool Changed = false;
    for (Function &F : M)
        Changed |= returnlessDispatchFunction(F, params, rng);
    return Changed;
}

PreservedAnalyses ReturnlessDispatchPass::run(Function &F,
                                              FunctionAnalysisManager &) {
    if (F.isDeclaration())
        return PreservedAnalyses::all();
    ir::IRRandom rng(engine_);
    return returnlessDispatchFunction(F, params_, rng)
               ? PreservedAnalyses::none()
               : PreservedAnalyses::all();
}

} // namespace morok::passes
