// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_INTERRUPT_H
#define CTRACE_KERNEL_INTERRUPT_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

enum class ct_kernel_interrupt_kind {
  hrtimer,
  hard_irq,
  threaded_irq,
  timer_list,
  tasklet
};
enum class ct_kernel_interrupt_target {
  saved_register,
  saved_register_word,
  tasklet_token
};
enum class ct_kernel_interrupt_register { rbx, r13, rbp, rdx, r12 };

// These offsets must come from a layout record compiled by the selected
// kernel's Kbuild, whose image has the expected build ID. They are not inferred
// from instruction displacements or supplied as runtime memory-read recipes.
struct ct_kernel_interrupt_layout {
  uint32_t irq_desc_action = 0;
  uint32_t irqaction_handler = 0;
  uint32_t irqaction_next = 0;
  uint32_t irqaction_thread_fn = 0;
  uint32_t hrtimer_function = 0;
  uint32_t tasklet_function = 0;
  uint32_t tasklet_data = 0;
};

struct ct_kernel_interrupt_dispatch {
  ct_kernel_interrupt_kind kind;
  ct_kernel_interrupt_target target;
  ct_kernel_interrupt_register reg;
  uint32_t word_offset = 0;
  uint64_t call_pc = 0, return_pc = 0;
  // Link-time witness bytes, beginning at witness_pc. Binding must separately
  // validate supported live alternatives and apply the verified KASLR slide.
  uint64_t witness_pc = 0;
  std::vector<unsigned char> witness;
};

struct ct_kernel_interrupt_code {
  uint64_t address = 0;
  std::vector<unsigned char> bytes;
};

struct ct_kernel_interrupt_jump {
  uint64_t pc = 0, target = 0;
  uint8_t size = 0;
};

enum class ct_kernel_interrupt_window_kind {
  indirect_call,
  return_thunk,
  endbr_seal,
  tracepoint_call,
  warning_call,
  jump_label,
  relocate32,
  relocate64
};

// A live-code binding may differ from the image only inside these typed
// windows. This is not a byte mask: each kind has an exact encoding contract.
// Tracepoint CALLs retain the normal C call-clobber transfer already used by
// the provenance analysis; their legal later static-call updates need no
// dispatcher rescan. A warning trap has its own encoding, never CALL freedom.
struct ct_kernel_interrupt_window {
  ct_kernel_interrupt_window_kind kind;
  uint64_t pc = 0, target = 0, key = 0;
  uint8_t size = 0, reg = 0;
};

struct ct_kernel_interrupt_proof {
  std::string build_id, image_digest, relocation_digest;
  uint64_t text_address = 0, anchor_address = 0;
  std::vector<ct_kernel_interrupt_dispatch> dispatches;
  // Complete hot/cold dispatcher code used for provenance, retained once.
  std::vector<ct_kernel_interrupt_code> code;
  // Supported live static-branch alternatives are NOP or JMP to this target.
  std::vector<ct_kernel_interrupt_jump> jumps;
  std::vector<ct_kernel_interrupt_window> windows;
};

// Offline x86-64 ELF executable analysis only: no kernel reads or hooks.
// expected_build_id is the lowercase GNU build-ID hex from the running kernel.
// Requires proved hrtimer, timer_list, generic hard-IRQ and threaded-IRQ
// dispatch forms; failure clears proof and explains unsupported/malformed
// evidence. Timer proofs retain the actual callback in a callee-saved register,
// never reread a mutable or possibly freed timer's callback field.
// Nonzero tasklet offsets additionally require the tasklet dispatcher and
// matching entry/exit tracepoint argument provenance. Its volatile target is
// qualified using an invocation token, never the register alone.
// irq_work, NMI and arbitrary IRQ roots are deliberately not proofs.
//
// Optional boot_relocations is the exact selected Kbuild's vmlinux.relocs,
// whose x86-64 format is zero/u64-sites/zero/u32-sites (signed 32-bit site
// addresses). Its provenance must be bound to that build separately from the
// ELF build ID. Without it extraction proves provenance only: relocation_digest
// remains empty and the result must not authorize a live-code binding.
//
// At an eligible canonical ENTER, compare the original saved return word to
// return_pc + slide, then compare the proved target to the canonical function
// symbol address INCLUDING ENDBR. The first gate event PC is not that address.
// saved_register_word uses one nofault u64 at the saved register + word_offset;
// irqaction lifetime/stability follows the selected IRQ core's registration
// and synchronized free contract. Never apply it at an unmatched return PC.
bool ct_kernel_interrupt_extract(
    const std::vector<unsigned char> &vmlinux,
    const std::string &expected_build_id,
    const ct_kernel_interrupt_layout &layout, ct_kernel_interrupt_proof &proof,
    std::string &error,
    const std::vector<unsigned char> &boot_relocations = {});

// Reuse an exact-image proof through the common disk cache. A miss first calls
// verify_relocations, which must regenerate and compare the selected Kbuild's
// boot relocation list, then runs the full offline CFG/provenance analysis.
// A hit checks the bounded restored proof against these immutable inputs; it
// reuses the prior analysis rather than claiming to re-prove its CFG. Runtime
// slide and live-code validation remain mandatory and unchanged.
bool ct_kernel_interrupt_prepare(
    const std::vector<unsigned char> &vmlinux,
    const std::string &expected_build_id,
    const ct_kernel_interrupt_layout &layout,
    const std::vector<unsigned char> &boot_relocations,
    const std::string &relocator_identity,
    const std::function<bool(std::string &)> &verify_relocations,
    ct_kernel_interrupt_proof &proof, std::string &error,
    bool *reused = nullptr);

#endif
