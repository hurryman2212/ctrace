// SPDX-License-Identifier: MIT

#ifndef CTRACE_USERSPACE_PATCH_H
#define CTRACE_USERSPACE_PATCH_H

#include <cstddef>
#include <cstdint>

#include <dr_api.h>

enum ct_userspace_gate_kind : unsigned {
  CT_USERSPACE_GATE_ENTRY = 1,
  CT_USERSPACE_GATE_SYSCALL = 2,
  CT_USERSPACE_GATE_RETURN = 4,
  CT_USERSPACE_GATE_BRANCH = 8,
  // Logical observation sites may share a window replayed entirely under DR.
  CT_USERSPACE_GATE_TRACE = 16,
};

struct ct_userspace_patch_request {
  app_pc pc;
  unsigned kind;
};

struct ct_userspace_patch_info {
  app_pc pc;
  app_pc redirect_pc;
  byte original[15];
  size_t available;
  size_t length;
  unsigned kind;
};

struct ct_userspace_patch_instruction {
  app_pc pc;
  size_t length;
};

struct ct_userspace_patch_plan;

// Preparation-only counters. Reasons describe the attempted search, not proof
// that a mapping remains available after another thread changes it.
enum class ct_userspace_preparation {
  CallSelected,
  Jump32Selected,
  Jump8Selected,
  CallStackUnproven,
  CallOriginalReplayIneligible,
  CallRegistryFailed,
  CallOutOfReach,
  ProbeReused,
  ProbeCreated,
  ProbeDirect,
  ProbeIndirect,
  ProbeAddressInvalid,
  ProbeHelpersUnavailable,
  ProbeEmptyIntersection,
  ProbeQueryFailed,
  ProbeAddressSpaceOccupied,
  ProbeAllocationFailed,
  ProbeEncodingFailed,
  ProbeProtectionFailed,
  JumpSlotReused,
  JumpPageCreated,
  JumpDirect,
  JumpIndirect,
  JumpHelpersUnavailable,
  JumpEmptyIntersection,
  JumpQueryFailed,
  JumpAddressSpaceOccupied,
  JumpAllocationFailed,
  JumpEncodingFailed,
  JumpNoSlot,
  PatchWindowRejected,
  PatchFiveByteWindowRejected,
  PatchTwoByteWindowRejected,
  PatchRelayUnavailable,
  PatchCachedRejection,
  SharedGatesDirect,
  SharedDirect,
  SharedIndirect,
  SharedHelpersUnavailable,
  SharedEmptyIntersection,
  SharedQueryFailed,
  SharedAddressSpaceOccupied,
  SharedAllocationFailed,
  Count
};
void ct_userspace_prepare_note(ct_userspace_preparation event,
                               uint64_t count = 1);
bool ct_userspace_prepare_stat(size_t index, const char **name,
                               uint64_t *count);

bool ct_userspace_patch_init();
void ct_userspace_patch_fork_prepare();
void ct_userspace_patch_fork_parent();
void ct_userspace_patch_fork_child();
// Plan every required gate before changing application text. The instruction
// map includes all reachable instruction starts, plus any verified trailing NOP
// padding. Protected targets may start a patch but never lie inside one.
// Preparation reserves 64-byte slots in shared gateway pages and stages their
// code without writing live executable pages. It may run with application
// threads live; publication installs the staged bytes while peers are stopped.
// identity fingerprints the module and debug inputs; module_base rebases disk
// recipes. Empty identity disables recipe caching for this preparation.
ct_userspace_patch_plan *ct_userspace_patch_prepare(
    void *context, const char *identity, app_pc module_base, app_pc begin,
    app_pc end, const ct_userspace_patch_request *requests, size_t count,
    const ct_userspace_patch_instruction *instructions,
    size_t instruction_count, const app_pc *protected_targets,
    size_t target_count);
// The caller must stop other application threads and prevent new userspace
// entries. Publication validates all preserved bytes before the first write.
// Publish an entire direct-call closure atomically; any failure restores every
// changed window before threads resume. A failed plan must not be used for
// userspace execution.
bool ct_userspace_patch_publish_all(ct_userspace_patch_plan *const *plans,
                                    size_t count);
const unsigned char *
ct_userspace_patch_backend_path(const ct_userspace_patch_plan *plan);
// Always discard after publication or cancellation. Published records remain
// alive until patch teardown; gateway pages have a separate quiescent lifetime.
void ct_userspace_patch_discard(ct_userspace_patch_plan *plan);

// Reads are lock-free and do not allocate, including from a signal callback.
// Lookup covers every overwritten instruction, including its interior bytes.
bool ct_userspace_patch_lookup(app_pc pc, ct_userspace_patch_info *information);
// A short gate can pause at the embedded E9 inside an application NOP relay.
// Resolve only that intermediate PC to the original gate's replay PC. Ordinary
// fallthrough through the relay's leading short jump must keep its own PC.
app_pc ct_userspace_patch_target(app_pc pc);
// Stable storage for DynamoRIO's decoder. Unregister the decoder callback
// before exit releases it. No allocation, DR API calls, or blocking occur.
const byte *ct_userspace_patch_original(app_pc pc, size_t *length);
bool ct_userspace_patch_read_original(app_pc pc, size_t size,
                                      void *destination);

// The caller must prevent execution/unmapping of this region during removal.
// Restore only bytes that are still owned CALL/JMP gates. For an already
// unmapped module, mapped=false invalidates records without touching
// application memory. Any overlap with the preserved instruction or its ENDBR
// entry prefix retires the gate, including instructions straddling the edge of
// the removed region. Retired records remain allocated until exit so concurrent
// readers are safe.
bool ct_userspace_patch_remove_range(app_pc begin, size_t size, bool mapped);
// Recycle retired slots, and reclaim pages with no published or reserved slots.
// The caller must hold the address-space suspension and prevent new entries,
// after dr_cancel_suspended_userspace_execution succeeds for every peer. The
// calling thread must be in DR and have abandoned its own userspace redirect.
// Decoder registry records remain allocated for lock-free readers.
void ct_userspace_patch_reclaim();
// Call only once application threads no longer execute or consult the gates.
void ct_userspace_patch_exit();

#endif
