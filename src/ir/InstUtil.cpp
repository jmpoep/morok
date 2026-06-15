// SPDX-License-Identifier: MIT
//
// Morok — modular LLVM IR obfuscator.
//
// morok/ir/InstUtil.cpp

#include "morok/ir/InstUtil.hpp"

#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace morok::ir {

bool isMustTailReturn(const ReturnInst &RI) {
    // `ret %c` / `ret bitcast(%c)` where %c is a musttail call.
    if (const Value *RV = RI.getReturnValue()) {
        if (const auto *BC = dyn_cast<BitCastInst>(RV))
            RV = BC->getOperand(0);
        if (const auto *CI = dyn_cast<CallInst>(RV))
            if (CI->isMustTailCall())
                return true;
    }

    // `ret void` (or any ret) immediately preceded by a musttail call,
    // peeling a trailing bitcast of the returned value.
    const Instruction *Prev = RI.getPrevNode();
    if (Prev && isa<BitCastInst>(Prev))
        Prev = Prev->getPrevNode();
    if (const auto *CI = dyn_cast_or_null<CallInst>(Prev))
        if (CI->isMustTailCall())
            return true;

    return false;
}

} // namespace morok::ir
