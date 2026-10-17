#ifndef CTRACE_USERSPACE_VERSION_H
#define CTRACE_USERSPACE_VERSION_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <dr_api.h>

#include "instrumentation.h"
#include "shared_objects.h"

struct ct_userspace_version_instruction {
  app_pc pc = nullptr;
  size_t length = 0;
  byte bytes[15]{};
  // A required observation or policy boundary for this particular level.
  // Full versions additionally observe every instruction.
  bool boundary = false;
};

struct ct_userspace_version;

struct ct_userspace_version_cache {
  // Borrowed only during prepare(). The module/debug identity and policy are
  // stable across ASLR; module_base is used only to form relative proof
  // offsets.
  const char *identity = nullptr;
  app_pc module_base = nullptr;
  size_t module_size = 0;
  const char *policy = nullptr;
  // Exact generator + DR build/ABI identity, required for shared artifacts.
  const char *runtime_identity = nullptr;
};

// Build an immutable RX body and register its original-PC mappings. Inputs must
// be sorted, non-overlapping original instructions. No original code is
// changed. The caller must validate the original bytes/generation before
// publishing this object, and keep it alive while any thread can execute or
// resume in the body. A failure returns nullptr with a reason for using the DR
// path instead.
// A cache context enables persistent common instruction templates and per-level
// layouts through the analysis helper's configured cache root. Empty cache-dir
// still disables all disk access. Validated hits bind addresses/gates without
// decoding or regenerating layout; an invalid record is regenerated normally.
ct_userspace_version *ct_userspace_version_prepare(
    void *context, ct_instrument_level level, uint64_t generation,
    const ct_userspace_version_instruction *instructions, size_t count,
    std::string &error, const ct_userspace_version_cache *cache = nullptr,
    bool shared_layout = false);

// A shared layout keeps gateway addresses in a separate private read-only
// binding region. The returned page-aligned RX image excludes those bindings.
// RIP-relative memory operations use private islands with their original
// operands; only relative jumps to those islands remain in shared RX. Compare
// the complete image before sharing; selecting this layout alone does not
// publish or share any physical pages.
const byte *ct_userspace_version_image(const ct_userspace_version *version,
                                       size_t *size);
// Before publishing any entry (or after cancelling every execution/redirect),
// replace the RX image with an identical immutable shared file range. The FD is
// borrowed, its offset must be page aligned, and its contents/size must be
// sealed. Private address bindings keep their original allocation and values.
// The caller retains catalog ownership. An OS replacement failure disables
// entry/image lookup; discard the version instead of publishing or retrying it.
bool ct_userspace_version_map_shared(ct_userspace_version *version, int fd,
                                     uint64_t offset);
bool ct_userspace_version_shared(const ct_userspace_version *version);

// Compute before cache lookup or emission. No decoding, disk access, or code
// generation occurs. runtime_identity and module/debug identity are mandatory.
bool ct_userspace_version_shared_key(
    const ct_userspace_version_cache *cache, ct_instrument_level level,
    const ct_userspace_version_instruction *instructions, size_t count,
    ct_shared_key &key, std::string &error);
// Export pointer-free proof/layout/private relocation records followed by a
// page-aligned canonical RX image. After publication a producer may map its
// existing version with map_shared(fd, payload_offset + rx_offset).
bool ct_userspace_version_export(const ct_userspace_version *version,
                                 const ct_shared_key &key,
                                 std::vector<byte> &payload, size_t &rx_offset,
                                 std::string &error);
// Before publishing a producer's version, replace its private node/proof vector
// with the sealed artifact's equivalent read-only metadata view. The code and
// private bindings stay intact; failure preserves the private metadata.
bool ct_userspace_version_adopt_metadata(ct_userspace_version *version,
                                         const ct_shared_key &expected_key,
                                         int fd, uint64_t payload_offset,
                                         uint64_t payload_size,
                                         std::string &error);

// READY path: validate sealed artifact, current original proof, level and key;
// keep immutable metadata mapped read-only, map shared RX directly, and create
// only private bindings/islands and local PC registrations. No decode,
// classify, layout generation, disk-cache access, or shared-body emission
// occurs.
ct_userspace_version *ct_userspace_version_restore(
    void *context, ct_instrument_level level, uint64_t generation,
    const ct_userspace_version_instruction *instructions, size_t count,
    const ct_shared_key &expected_key, int fd, uint64_t payload_offset,
    uint64_t payload_size, std::string &error);
bool ct_userspace_version_shared_restored(const ct_userspace_version *version);
// Initialize the registry once before application threads can fork.
void ct_userspace_version_init();
// After all producers have stopped and every published version is discarded.
// Preserve the registry and return false if any version is still alive.
bool ct_userspace_version_exit();
// Mark before exposing an entry in a process-owned published version table.
// A regular fork child retains published objects and the surviving creator's
// work, and releases unpublished objects owned by vanished creator contexts.
void ct_userspace_version_mark_published(ct_userspace_version *version);
// Call only in the regular-fork child after DR has removed vanished threads.
// Never call from vfork/CLONE_VM children. This resets private registry
// locking; it does not wait for the parent's threads or change catalog
// references.
void ct_userspace_version_fork_child(void *surviving_context);

// Call only from the terminal thread-exit callback, after the creator cannot
// resume, to dispose of unfinished versions. Published versions remain owned by
// their caller. Never use this for a temporarily suspended peer.
void ct_userspace_version_thread_exit(void *context);

// Enter after this original instruction has already been observed. This skips
// its prefix gate, but branches and fallthrough within the body enter
// subsequent prefix gates. Returns nullptr for instructions that must execute
// under DR (CALL, RET, syscall, or an external/indirect control transfer), or
// unknown PCs.
app_pc ct_userspace_version_entry(const ct_userspace_version *version,
                                  app_pc original_pc);
// Enumerate original PCs targeted by immutable exit gates, including an exit
// beyond the supplied cover. Uses relocation metadata without decoding code.
// The owner must keep the version alive through every callback. Duplicates are
// allowed; the caller chooses which exits need a prepared DR continuation.
void ct_userspace_version_exits(const ct_userspace_version *version,
                                void (*callback)(app_pc, void *),
                                void *context);
// Direct-branch destination before observation. This is the compact linear
// body, not an indirect CET landing; external dispatch uses entry() instead.
app_pc ct_userspace_version_ingress(const ct_userspace_version *version,
                                    app_pc original_pc);
ct_instrument_level
ct_userspace_version_level(const ct_userspace_version *version);
uint64_t ct_userspace_version_generation(const ct_userspace_version *version);
size_t ct_userspace_version_size(const ct_userspace_version *version);
// Preparation evidence: common reuse can avoid decoding even when this level's
// layout is new. restored() additionally confirms the level layout was reused.
bool ct_userspace_version_restored(const ct_userspace_version *version);
bool ct_userspace_version_common_restored(const ct_userspace_version *version);
size_t ct_userspace_version_decoded_count(const ct_userspace_version *version);

// Consult the retained byte proof without decoding or reading application text.
bool ct_userspace_version_original(const ct_userspace_version *version,
                                   app_pc original_pc, byte *bytes,
                                   size_t *length);
// read_original must return the unpatched application bytes. Call while code
// mutation is excluded, before exposing new entries or accepting a generation.
bool ct_userspace_version_validate(const ct_userspace_version *version,
                                   bool (*read_original)(app_pc pc, size_t size,
                                                         void *destination));

// All execution, pending redirects, and saved signal/return references must be
// quiescent before disposal. This retires mappings before releasing RX memory.
bool ct_userspace_version_discard(ct_userspace_version *version);

#endif
