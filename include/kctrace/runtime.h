/* SPDX-License-Identifier: MIT */
#ifndef KCTRACE_RUNTIME_H
#define KCTRACE_RUNTIME_H

#include "linux/kctrace.h"

/* Internal compiled-module/runtime contract shared by preparation tools and
 * kernel builds. These descriptors are embedded in generated modules, not
 * exposed through the /dev/kctrace ioctl or read interface.
 */
#define KCTRACE_LEVEL_MASK_FULL 0x4U
#define KCTRACE_LEVEL_MASK_ALL 7U

/* SINGLE_FULL adapter metadata only; normalized before event publication. */
#define KCTRACE_GATE_INDIRECT_REG_BASE 16
#define KCTRACE_GATE_UNKNOWN_CONTROL 32

#define KCTRACE_PROGRAM_TERMINAL 0x1U
#define KCTRACE_PROGRAM_PERFETTO 0x2U
/* At least one explicit within criterion; absent means unrestricted within. */
#define KCTRACE_PROGRAM_WITHIN_FILTER 0x4U
/* One physical FULL body; logical policy still controls collected output. */
#define KCTRACE_PROGRAM_SINGLE_FULL 0x8U
#define KCTRACE_PROGRAM_WITHIN_INTR 0x10U
/* At least one function uses a fixed FULL body and saved-flags gates. */
#define KCTRACE_PROGRAM_FIXED_FULL 0x20U

#define KCTRACE_INTERRUPT_HRTIMER 0
#define KCTRACE_INTERRUPT_HARD_IRQ 1
#define KCTRACE_INTERRUPT_THREADED_IRQ 2
#define KCTRACE_INTERRUPT_TIMER_LIST 3
#define KCTRACE_INTERRUPT_TASKLET 4

#define KCTRACE_INTERRUPT_SAVED_REGISTER 0
#define KCTRACE_INTERRUPT_SAVED_WORD 1
#define KCTRACE_INTERRUPT_TASKLET_TOKEN 2

#define KCTRACE_INTERRUPT_PATCH_INDIRECT_CALL 0
#define KCTRACE_INTERRUPT_PATCH_RETURN_THUNK 1
#define KCTRACE_INTERRUPT_PATCH_ENDBR_SEAL 2
#define KCTRACE_INTERRUPT_PATCH_TRACEPOINT_CALL 3
#define KCTRACE_INTERRUPT_PATCH_WARNING_CALL 4
#define KCTRACE_INTERRUPT_PATCH_JUMP_LABEL 5
#define KCTRACE_INTERRUPT_PATCH_RELOCATE32 6
#define KCTRACE_INTERRUPT_PATCH_RELOCATE64 7

#define KCTRACE_CAPTURE_NONE 0
#define KCTRACE_CAPTURE_STACK 1
#define KCTRACE_CAPTURE_OBJECT 2
#define KCTRACE_CAPTURE_GPR 3
#define KCTRACE_CAPTURE_SLOT 4
#define KCTRACE_CAPTURE_XSTATE 5
#define KCTRACE_XSTATE_FPU 0xe7U
#define KCTRACE_XSTATE_AMX 0x60000U
#define KCTRACE_XSTATE_USER_SCALAR 0x200U
/* Passive scalar MSRs: PASID, CET_U/S, HDC and HWP. */
#define KCTRACE_XSTATE_SUPERVISOR 0x13c00U
#define KCTRACE_XSTATE_SCALAR                                                  \
  (KCTRACE_XSTATE_USER_SCALAR | KCTRACE_XSTATE_SUPERVISOR)
#define KCTRACE_XSTATE_SUPPORTED                                               \
  (KCTRACE_XSTATE_FPU | KCTRACE_XSTATE_AMX | KCTRACE_XSTATE_SCALAR)
#define KCTRACE_CAPTURE_ADDRESS (1U << 0)

/* Relocated addresses in the immutable, offline-generated probe table. */
struct kctrace_probe_site {
  __u64 return_pc;
  __u64 site_id;
  __u64 pc;
  __u16 type;
  __u16 reserved;
  /* One-based index in the immutable capture plan array; zero means none. */
  __u32 capture_plan;
};

/* Multiple physical probes can share an original site ID across code copies.
 * return_pc is unique among body probes. A SINGLE_FULL ordinary boundary may
 * share its CALL with the immediately following point at the same site.
 * ARM has gates only; PERFETTO body probes never reference capture plans.
 */
struct kctrace_copy_probe {
  struct kctrace_probe_site probe;
  __u32 function;
  __u32 path;
  __u32 level;
  __u32 reserved;
};

struct kctrace_gate_site {
  __u64 return_pc;
  __u64 site_id;
  /* Actual gate address; site_id identifies the original instruction. */
  __u64 pc;
  __u64 related_site_id;
  __u64 call_returns[3];
  __u64 continuations[3];
  __u32 function;
  __u32 path;
  __u32 kind;
  /* ENTRY/EXIT snapshots; SINGLE_FULL guards may use the original point plan.
   */
  __u32 capture_plan;
};

/* Encoded state: flags in bits 0..2, mode in bits 3..4. Zero element is unused.
 * These are precomputed decisions, not runtime pattern strings.
 */
struct kctrace_function_decisions {
  __u8 states[8];
  __u8 minimum_level;
};

struct kctrace_policy_decisions {
  __u8 states[8];
};

/* Immutable target-owned data, copied and validated before init. Counts for
 * functions/paths include their zero sentinel; others exclude sentinels.
 * Its original_site_count equals PREPARE.site_count. Physical counts differ.
 */
struct kctrace_program {
  __u32 size;
  __u8 contract_sha256[KCTRACE_HASH_SIZE];
  __u32 flags;
  __u32 minimum_level;
  __u64 original_site_count;
  __u64 probes;
  __u64 probe_count;
  __u64 gates;
  __u64 gate_count;
  __u64 functions;
  __u64 function_count;
  __u64 paths;
  __u64 path_count;
  /* Zero without WITHIN_INTR; otherwise a target-owned immutable proof. */
  __u64 interrupt_proof;
};

/* Original kernel link addresses are normalized by one checked public-export
 * slide. Module function entries below instead use normal ELF relocations.
 * Byte ranges and window records are validated once before registration.
 */
struct kctrace_interrupt_range {
  __u64 address;
  __u64 bytes;
  __u64 size;
};

struct kctrace_interrupt_window {
  __u64 pc;
  __u64 target;
  __u64 key;
  __u8 kind;
  __u8 size;
  /* x86 instruction register encoding (RAX=0, RBP=5, R13=13). */
  __u8 reg;
  __u8 reserved;
  __u32 reserved2;
};

struct kctrace_interrupt_dispatch {
  __u64 return_pc;
  __u32 kind;
  /* Snapshot register index: KCTRACE_REG_*. */
  __u32 reg;
  __u32 word_offset;
  __u32 target;
};

struct kctrace_interrupt_proof {
  __u32 size;
  __u32 reserved;
  /* hrtimer_start_range_ns and optional __static_call_return0 link PCs. */
  __u64 anchor;
  __u64 return_zero;
  __u64 ranges;
  __u64 range_count;
  __u64 windows;
  __u64 window_count;
  __u64 dispatches;
  __u64 dispatch_count;
  /* One-based canonical module function entries, including original ENDBR. */
  __u64 entries;
  __u64 entry_count;
};

/* Offline-proven scalar storage only. STACK uses original RSP/RBP + offset;
 * OBJECT uses a relocated owned data object + nonnegative in-object offset.
 * GPR uses a captured register; SLOT uses an earlier eight-byte slot in this
 * same chunk. Each explicit pointer hop has its own immutable descriptor.
 * ADDRESS outputs the computed address without reading the destination.
 * XSTATE uses reg as a component number and offset as its byte offset.
 * Components 0/1 retain legacy FXSAVE offsets: 0 owns bytes 0..23 and
 * 32..159; 1 owns MXCSR at 24..31 and XMM at 160..415. Other components
 * use offsets relative to their CPUID-enumerated standard XSAVE area.
 * NONE slots are entirely zero. No runtime DWARF, type or source analysis.
 */
struct kctrace_capture {
  __u64 object;
  __u64 object_size;
  __s64 offset;
  __u8 kind;
  __u8 reg;
  __u8 size;
  __u8 reserved;   /* KCTRACE_CAPTURE_ADDRESS, or zero for a memory read. */
  __u32 reserved2; /* SLOT: one-based source slot; zero for all other kinds. */
};

struct kctrace_capture_plan {
  struct kctrace_capture slots[KCTRACE_VALUE_SLOTS];
  /* One-based next chunk; zero terminates this immutable capture chain. */
  __u32 next;
  /* Required xstate components, derived from this chunk's XSTATE slots. */
  __u32 xstate_mask;
};

/* Embedded in the prepared target, then covered by its final signature. */
struct kctrace_manifest {
  __u32 size;
  __u8 contract_sha256[KCTRACE_HASH_SIZE];
  __u32 levels;
  __u32 flags;
  __u64 site_count;
  char module_name[KCTRACE_MODULE_NAME_SIZE];
  /* PREPARE's input/template digests, not the final signed-file digest.
   */
  __u8 original_sha256[KCTRACE_HASH_SIZE];
  __u8 artifact_sha256[KCTRACE_HASH_SIZE];
  __u8 session_nonce[KCTRACE_NONCE_SIZE];
};

/* Immutable relocated target descriptor, discovered at MODULE_STATE_COMING.
 * Count addresses refer to immutable u64 objects. The binding output slot is
 * zeroed writable non-init module data; no userspace address is accepted.
 */
struct kctrace_bootstrap {
  __u32 size;
  __u8 contract_sha256[KCTRACE_HASH_SIZE];
  __u64 flags;
  __u64 manifest;
  __u64 sites;
  __u64 site_count_address;
  __u64 capture_plans;
  __u64 capture_plan_count_address;
  __u64 binding_slot;
  /* Zero for the legacy full table; otherwise points to kctrace_program. */
  __u64 program;
};

#ifdef __KERNEL__

struct module;
struct kctrace_binding;

/* Explicit probes supply bytes; automatic probes reference validated plans. */
struct kctrace_snapshot {
  __u64 valid_registers;
  __u64 registers[KCTRACE_REGISTER_COUNT];
  union {
    __u64 memory_address;
    __u64 capture_plan;
  };
  union {
    __u32 memory_size;
    __u32 capture_valid;
  };
  union {
    __u32 reserved;
    __u32 flags;
  };
  union {
    __u8 memory[KCTRACE_MEMORY_SIZE];
    __u8 capture_values[KCTRACE_VALUE_SLOTS][8];
  };
  __u32 level;
  __u32 reserved2;
  struct kctrace_execution_record execution;
  /* Registered automatic probes only; never copied to the UAPI event. */
  const struct kctrace_capture_plan *capture_plans;
  /* Live only under the recorder guard; never part of a wire event. */
  const void *xstate;
  __u64 xstate_mask;
};

#ifdef __cplusplus
extern "C" {
#endif

struct kctrace_binding *kctrace_bind(struct module *target,
                                     const struct kctrace_manifest *manifest);
int kctrace_register_sites(struct kctrace_binding *binding,
                           const struct kctrace_probe_site *sites, __u64 count,
                           const struct kctrace_capture_plan *plans,
                           __u64 plan_count);
int kctrace_register_program(struct kctrace_binding *binding,
                             const struct kctrace_program *program,
                             const struct kctrace_capture_plan *plans,
                             __u64 plan_count);
/* Explicit callers supply legacy raw memory only; snapshot flags stay zero.
 * Automatic registered probes alone produce the plan-indexed values payload.
 */
void kctrace_record(struct kctrace_binding *binding, __u16 type, __u64 site_id,
                    __u64 pc, const struct kctrace_snapshot *snapshot);
void kctrace_initialized(struct kctrace_binding *binding, int result);
/* Call after target exit has quiesced all callbacks; never from a probe. */
void kctrace_unbind(struct kctrace_binding *binding);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* KCTRACE_RUNTIME_H */
