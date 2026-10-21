// SPDX-License-Identifier: MIT

#ifndef CTRACE_COMPILER_HOOKS_H
#define CTRACE_COMPILER_HOOKS_H

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include <dr_api.h>

#include "analysis.hh"

enum class ct_compiler_hook_kind { None, Enter, Exit };

struct ct_compiler_hooks {
  std::map<app_pc, ct_compiler_hook_kind> symbols;
  std::map<app_pc, ct_compiler_hook_kind> slots;
  std::vector<std::pair<app_pc, app_pc>> linkage;
};

// Borrow the module's stable ELF descriptor. An empty catalog is valid;
// malformed or unsupported ELF leaves the catalog empty and returns false.
// Defined hook aliases that share one address are deliberately ambiguous.
bool ct_compiler_hooks_read(int descriptor, app_pc module_base,
                            ct_compiler_hooks &catalog);

// Classify an actual CALL or unconditional JMP, never symbol presence alone.
// Direct definitions, PLT/CET stubs and RIP-relative GOT operands preserve the
// linkage name even when the loader resolves enter and exit to one address.
// The caller supplies decoded original instruction bytes and owns module/code
// lifetime validation. This does not prove which function the hook describes.
ct_compiler_hook_kind ct_compiler_hook_at(void *context,
                                          const ct_compiler_hooks &catalog,
                                          instr_t *instruction);

struct ct_compiler_hook_function {
  app_pc entry = nullptr;
  // RSP immediately before the enter CALL, relative to the function's entry.
  int64_t entry_stack_delta = 0;
  std::vector<app_pc> exits;
};

// The caller supplies its complete, bounded, reachable original graph. Prove
// a straight prologue leading to an enter CALL whose first argument is this
// physical function. Before it, only fixed stack operations, stack spills and
// register preparation are accepted. Exit CALLs require a certified straight
// epilogue suffix to RET with no further call, branch or store; exit JMPs are
// tail transfers. Inner inline exits, including recursive inlining with the
// same this_fn, do not qualify merely by calling an exit hook. This is not
// proof that every return path calls one. The caller must check each exit's
// runtime this_fn and retain RET/return-PC/unwind handling. Hook registers are
// not the function's original arguments or its return value.
bool ct_compiler_hooks_function(
    void *context, const ct_compiler_hooks &catalog, app_pc module_base,
    app_pc function, const std::vector<ct_flow_instruction> &instructions,
    ct_compiler_hook_function &proof);

#endif
