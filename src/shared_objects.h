#ifndef CTRACE_SHARED_OBJECTS_H
#define CTRACE_SHARED_OBJECTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ct_shared_channel ct_shared_channel;

enum ct_shared_kind {
  CT_SHARED_USERSPACE_CODE = 1,
  CT_SHARED_DR_CODE = 2,
  CT_SHARED_DECOMPILE = 3
};

/* identity covers original content/ranges, policy, generator/runtime/ISA/ABI,
 * binding format and any required layout. The broker does not infer it from
 * function names, process addresses, or process-local generation counters. */
typedef struct ct_shared_key {
  uint32_t kind;
  uint32_t schema;
  uint32_t level;
  uint32_t reserved;
  unsigned char identity[32];
} ct_shared_key;

typedef struct ct_shared_descriptor {
  ct_shared_key key;
  uint64_t object_id;
  uint64_t sequence;
  uint64_t payload_offset;
  uint64_t payload_size;
  unsigned char digest[32];
} ct_shared_descriptor;

enum ct_shared_status {
  CT_SHARED_ERROR,
  CT_SHARED_READY,
  CT_SHARED_CREATE,
  CT_SHARED_WAIT,
  CT_SHARED_ABSENT,
  CT_SHARED_OK,
  CT_SHARED_RESYNC
};

typedef struct ct_shared_result {
  uint32_t status;
  uint32_t error;
  uint64_t token; /* CREATE lease or WAIT ticket; never interchangeable. */
  uint64_t sequence;
  ct_shared_descriptor object;
  int fd; /* READY: borrowed for mapping; close only with result_close. */
  uint64_t owner_process;
  uint64_t owner_session;
} ct_shared_result;

typedef struct ct_shared_file {
  int fd; /* Producer-owned sealed file; publish borrows it. */
  uint64_t owner_process;
  uint64_t owner_session;
} ct_shared_file;

typedef struct ct_shared_fork_reservation {
  uint64_t token;
  uint64_t owner_process;
  uint64_t owner_session;
  int fd;
} ct_shared_fork_reservation;

enum { CT_SHARED_SNAPSHOT_CAPACITY = 16 };
typedef struct ct_shared_snapshot {
  uint64_t sequence;
  uint64_t cursor;
  uint32_t count;
  bool more;
  bool resync;
  ct_shared_descriptor entries[CT_SHARED_SNAPSHOT_CAPACITY];
} ct_shared_snapshot;

typedef struct ct_shared_scan_page {
  uint64_t upper_bound;
  uint64_t cursor;
  uint64_t sequence;
  uint32_t count;
  bool more;
  ct_shared_descriptor entries[CT_SHARED_SNAPSHOT_CAPACITY];
} ct_shared_scan_page;

/* One channel belongs to one process/thread and must be closed at thread exit.
 * Never call acquire/wait/publish while holding an analysis lock or stopping
 * peers: a producer may be one of those peers. Fork children open new channels;
 * vfork/CLONE_VM children must not use or close their parent's channel. These
 * operations do not enable tracing or change a thread's instrumentation level.
 */
ct_shared_channel *ct_shared_open(void);
bool ct_shared_close(ct_shared_channel *channel);
/* Same-image teardown only: caller guarantees the owning peer is stopped or
 * terminated and can never touch this wrapper again (e.g. DR thread_exit).
 * Closes the channel and frees its wrapper without a thread-ownership check.
 * This does not release process-image READY references. Never use after fork.
 */
bool ct_shared_close_quiescent(ct_shared_channel *channel);
/* Final address-space teardown from another descriptor-table owner. All
 * producers must be stopped. Frees only the wrapper, without interpreting its
 * descriptor number or changing catalog references owned by another image. */
void ct_shared_abandon_channel(ct_shared_channel *channel);
/* Only in a regular fork child, after connecting its new analysis session:
 * free an inherited local wrapper without touching its old FD or broker state.
 * DR has already closed that FD and may have reused its number. Rejects the
 * current image's wrappers. Never call this from vfork/CLONE_VM children. */
bool ct_shared_fork_forget_channel(ct_shared_channel *channel);
bool ct_shared_acquire(ct_shared_channel *channel, const ct_shared_key *key,
                       ct_shared_result *result);
/* A timeout returns WAIT and preserves the ticket. Cancel tickets that will
 * not be waited on. The broker never blocks its event loop for this wait. */
bool ct_shared_wait(ct_shared_channel *channel, uint64_t ticket, int timeout_ms,
                    ct_shared_result *result);
bool ct_shared_cancel_wait(ct_shared_channel *channel, uint64_t ticket);
bool ct_shared_publish(ct_shared_channel *channel, uint64_t lease,
                       const ct_shared_file *file, ct_shared_result *result);
bool ct_shared_fail(ct_shared_channel *channel, uint64_t lease);
/* Each READY acquire/publish/wait result owns one process-image catalog
 * reference, releasable through any channel in that same image. Thread exit
 * closes leases/tickets, but does not release process-shared execution views.
 * Release after local execution/mapping readers are gone; closing its FD is
 * separate. The last reference evicts the object unless an explicit waiter
 * still owns interest in it. Publication is not a permanent catalog reference.
 */
bool ct_shared_release(ct_shared_channel *channel, uint64_t object_id);
bool ct_shared_result_close(ct_shared_result *result);
/* Code kinds use MFD_EXEC; decompile data uses MFD_NOEXEC_SEAL and must be
 * mapped read-only by its reader. F_SEAL_EXEC freezes the executable mode.
 * Linux's noexec memfd mode is not an mmap(PROT_EXEC) access-control boundary.
 */
bool ct_shared_file_create(const ct_shared_key *key, const void *payload,
                           size_t size, ct_shared_file *file);
bool ct_shared_file_close(ct_shared_file *file);
/* Reserve before a regular fork. The protected liveness FD survives fork but
 * closes on exec. Parent completion (success or failure) closes only its local
 * FD; pins remain while an unclaimed child holds its copy, even after parent
 * death. Close unused reservations at thread exit too. The child opens a fresh
 * analysis session/channel and claims once using its inherited FD. Claim
 * consumes that local FD; repeated claims are rejected. A surviving mmap alone
 * is not a catalog reference. Reserve never waits for another producer and may
 * run from the existing quiescent fork-preparation hook. Do not use these hooks
 * for vfork/CLONE_VM: those children must not alter the parent's ownership. */
bool ct_shared_fork_reserve(ct_shared_channel *channel,
                            ct_shared_fork_reservation *reservation);
/* Reserve only locally published inherited views, excluding temporary READY
 * acquisitions in other threads. Each repeated ID owns one additional ref;
 * unknown/foreign IDs or counts exceeding this image's holdings are rejected.
 * An empty list reserves nothing. The complete sealed list is sent by FD, so
 * its capacity is independent of the small catalog snapshot packet. */
bool ct_shared_fork_reserve_selected(ct_shared_channel *channel,
                                     const uint64_t *object_ids, size_t count,
                                     ct_shared_fork_reservation *reservation);
bool ct_shared_fork_parent_done(ct_shared_fork_reservation *reservation);
bool ct_shared_fork_claim(ct_shared_channel *channel,
                          ct_shared_fork_reservation *reservation);
/* Start with sequence=cursor=0. Continue with the returned sequence/cursor;
 * RESYNC means the catalog changed while paging: restart from zero. Entries
 * advertise availability only: listing does not acquire or map any body. */
bool ct_shared_list(ct_shared_channel *channel, uint64_t sequence,
                    uint64_t cursor, ct_shared_snapshot *snapshot);
/* Forward-only enumeration: start with upper_bound=cursor=0, then retain the
 * returned upper_bound and cursor until more=false. kind=0 includes all kinds.
 * Capturing the current allocation ID bounds the work despite continuous
 * publication/eviction; each page examines a bounded number of catalog entries.
 * Live objects already READY at capture are visited. Objects that disappear or
 * become READY after their cursor position may be absent. A later acquire or
 * publication must still check for an equivalent object; absence in this scan
 * is not an exclusive producer lease.
 * This advertises availability only and never acquires/maps any object body.
 * sequence reports current availability; changes never restart this scan. */
bool ct_shared_scan(ct_shared_channel *channel, uint32_t kind,
                    uint64_t upper_bound, uint64_t cursor,
                    ct_shared_scan_page *page);
/* Consume coalesced availability hints without acquiring any body. A zero
 * timeout only checks already queued hints; use list to resynchronize. */
bool ct_shared_poll(ct_shared_channel *channel, int timeout_ms,
                    uint64_t *sequence);
uint64_t ct_shared_sequence(const ct_shared_channel *channel);

#ifdef __cplusplus
}
#endif

#endif
