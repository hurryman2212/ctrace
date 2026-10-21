// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_GATE_H
#define CTRACE_KERNEL_GATE_H

#include <array>
#include <cstdint>
#include <vector>

struct ct_kernel_gate_relocation {
  uint8_t instruction_offset;
  uint8_t displacement_offset;
  uint8_t displacement_size;
  uint8_t next_pc;
};

struct ct_kernel_gate_stack {
  uint8_t instruction_offset;
  int8_t rsp_delta;
};

struct ct_kernel_gate_template {
  std::vector<unsigned char> bytes;
  ct_kernel_gate_relocation selector;
  // Continuations are indexed by level: arm=0, perfetto=1, full=2.
  std::array<ct_kernel_gate_relocation, 3> continuations;
  // RSP delta from gate entry before each instruction, including all arms.
  std::vector<ct_kernel_gate_stack> stack;
};

// The caller binds each zero-filled signed rel32 field to target - next_pc,
// accounting for the gate's final address and checking the signed 32-bit range.
// For ELF PC-relative relocations, the field-to-next-PC addend is -4.
// Canonical-entry ENDBR and original-PC/unwind mappings belong to the rewriter.
//
// Private selector ABI: return arm=0, perfetto=1 or full=2 in EAX and preserve
// every other GPR. All other EAX values also take the full continuation. At
// selector entry [RSP] is the CALL return PC, [RSP+8] is the original RAX,
// [RSP+16] is the original flags, and RSP+24 is the original RSP. This is one
// extra saved word compared with the ordinary kctrace_probe call boundary.
// The selector must return normally without changing any of these words.
//
// PUSHFQ precedes CALL so call/return thunks cannot corrupt the saved flags.
// Every direct-JMP continuation receives the original GPRs, flags and RSP.
// Function entries and equivalent mid-function boundaries use the same ABI.
// Only ordinary kernel stack/flag contexts (DF=0, AC=0, no live red zone) are
// supported; the rewriter must retain its unsupported-context exclusions.
const ct_kernel_gate_template &ct_kernel_gate(unsigned minimum_level = 0);

#endif
