// SPDX-License-Identifier: MIT

#ifndef CTRACE_SHARED_DR_BATCH_H
#define CTRACE_SHARED_DR_BATCH_H

#include <cstddef>
#include <cstdint>

#include "shared_objects.hh"

enum { CT_SHARED_DR_COMPACT_LIMIT = 65536 };

typedef struct ct_shared_dr_relocation {
  uint32_t field_offset, kind, target_offset, reserved;
} ct_shared_dr_relocation;

typedef struct ct_shared_dr_compact_header {
  char magic[8];
  unsigned char contract[32];
  uint32_t isa_mode, count, relocation_count, reserved;
  uint64_t code_size, private_size;
} ct_shared_dr_compact_header;

typedef struct ct_shared_dr_compact_member {
  unsigned char identity[32];
  uint32_t offset, size, private_offset, private_size;
  uint32_t prototype_private_offset, relocation_index, relocation_count,
      reserved;
} ct_shared_dr_compact_member;

typedef struct ct_shared_dr_member_result {
  ct_shared_result result;
  uint64_t member_offset;
  uint64_t member_size;
} ct_shared_dr_member_result;

/* ABSENT never creates a lease or waits for an unfinished producer. READY owns
 * one ordinary catalog reference to the batch and borrows its sealed FD.
 */
bool ct_shared_dr_member_acquire(ct_shared_channel *channel,
                                 const ct_shared_key *member,
                                 ct_shared_dr_member_result *result);

/* Bind a validated source/policy/level proof to an already READY canonical
 * body. The broker recomputes the association key and never substitutes a
 * different body or modifies an existing association. Missing bodies return
 * ABSENT without a producer wait; source eligibility remains mandatory.
 */
bool ct_shared_dr_member_bind(ct_shared_channel *channel,
                              const ct_shared_key *member,
                              const unsigned char provenance[32],
                              const unsigned char body[32],
                              ct_shared_dr_member_result *result);

/* Deferred advertisement for an actual emission. The expected backing must
 * still be pinned by this image and contain this exact body. ABSENT means the
 * executed view retired before the advertisement could be completed. */
bool ct_shared_dr_member_bind_to(ct_shared_channel *channel,
                                 const ct_shared_key *member,
                                 const unsigned char provenance[32],
                                 const unsigned char body[32],
                                 uint64_t expected_object,
                                 ct_shared_dr_member_result *result);

/* Acquire a currently advertised object with an exact source/body proof.
 * Unlike bind_to(), no preexisting image reference is required. The broker
 * checks availability and grants a reference atomically; a vanished object
 * returns ABSENT instead of substituting another placement. */
bool ct_shared_dr_member_bind_available(ct_shared_channel *channel,
                                        const ct_shared_key *member,
                                        const unsigned char provenance[32],
                                        const unsigned char body[32],
                                        uint64_t expected_object,
                                        ct_shared_dr_member_result *result);

/* Forward-only eligibility advertisements, bounded by a captured alias ID.
 * Entries carry the full source key, backing object ID, absolute member file
 * offset/length and canonical body digest. Acquire before mapping: listings
 * do not pin a backing and may become stale while paging.
 */
bool ct_shared_dr_member_scan(ct_shared_channel *channel, uint64_t upper_bound,
                              uint64_t cursor, ct_shared_scan_page *page);

/* Hash the normalized template while validating every placement-dependent
 * word. code points at the member, not the beginning of the bundle. */
bool ct_shared_dr_compact_digest(uint32_t isa_mode,
                                 const ct_shared_dr_compact_member *member,
                                 const void *relocations, const void *code,
                                 size_t code_size, size_t private_size,
                                 unsigned char digest[32]);
bool ct_shared_dr_compact_member_key(uint32_t level,
                                     const unsigned char provenance[32],
                                     const unsigned char body[32],
                                     ct_shared_key *key);
bool ct_shared_dr_compact_validate(const void *index, size_t index_size,
                                   const void *code, size_t size);
bool ct_shared_dr_compact_create(const void *index, size_t index_size,
                                 const void *code, size_t size,
                                 ct_shared_key *key, ct_shared_file *file);

#endif
