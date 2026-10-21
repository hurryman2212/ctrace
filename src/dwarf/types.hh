// SPDX-License-Identifier: MIT

#ifndef CTRACE_DWARF_TYPES_H
#define CTRACE_DWARF_TYPES_H

#include <cstddef>
#include <cstdint>
#include <string>

/* AMD64 DWARF register order, NOT the Linux ptrace or DR struct order. */
typedef struct {
  uint64_t gpr[17]; /* rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp,r8..r15,rip */
  unsigned char xmm[32][64];
  size_t simd_bytes;
  uint64_t opmask[8];
  bool have_opmask;
  bool have_gpr, have_xmm;
  /* Registers whose live bytes no longer belong to the current DWARF frame,
   * e.g. restored RBP during an epilogue. Raw instruction operands may still
   * display those bytes, but variable locations must not use them. */
  uint64_t unavailable_gpr;
  uint64_t flags;
} ct_registers;
/* Stable DWARF identity and the type of the resolved object/member. Formatting
 * does not mark this symbol as displayed; the output owner decides that only
 * when the corresponding input value is actually emitted. */
typedef struct {
  // Lifetime-unique instance identity; allocation reuse must not merge names.
  uint64_t module_id;
  uint64_t die_offset;
  std::string name;
  std::string type;
} ct_variable_description;
/* Original DWARF line-row identity resolved by the external analysis helper.
 * Compare numeric file indices within the same CU, without parsing native
 * libdw line tables on DynamoRIO's bounded instrumentation stack. */
typedef struct {
  uint64_t cu_die_offset, file_index;
  uint32_t line;
  bool valid;
} ct_initializer_source;

#endif
