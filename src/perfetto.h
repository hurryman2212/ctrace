#ifndef CTRACE_PERFETTO_H
#define CTRACE_PERFETTO_H

#include <cstdint>

#include "instrumentation.h"

struct ct_perfetto_timestamp {
  uint64_t ticks = 0;
  uint64_t wall_nanoseconds = 0;
};

// Initialize once before registering application callbacks. The analysis
// broker owns the destination and serializes events from every descendant.
// Call exit only after callbacks have stopped using the writer.
// tsc_hz must be nonzero. Event positions share the broker's
// CLOCK_MONOTONIC_RAW origin after time-namespace normalization; adjusted
// per-thread application ticks describe cost separately.
bool ct_perfetto_init(uint64_t tsc_hz, ct_instrument_level initial_level,
                      const char *program = nullptr);
void ct_perfetto_exit();
bool ct_perfetto_enabled();

// Capture at the application boundary before callback work. Failure stops
// recording; another clock cannot replace the shared timeline.
ct_perfetto_timestamp ct_perfetto_now(uint64_t ticks);

// Freeze local writer state across an ordinary fork. The parent unlocks it;
// the child resets the copied lock and state after reconnecting its analysis
// session. Shared-address-space children must not use these reset functions.
void ct_perfetto_fork_prepare();
void ct_perfetto_fork_parent();
bool ct_perfetto_fork_child(void *context, bool recording);

// Count an observed return from actual userspace execution, not an attempted
// transition. gate=true identifies an owned interception gate; other userspace
// interruptions also complete a span. This only updates atomic counters: no
// trace event, allocation, locking or I/O. The next event or exit publishes
// userspace_spans/userspace_gate_hits in otherData.
// detailed=true counts a completed original instruction whose before/after
// snapshots belong to the detailed terminal trace.
void ct_perfetto_userspace_span(bool gate, bool detailed = false);

// Open the thread's execution lifetime at the current wall time, even when no
// trace scopes are selected. Repeated calls are harmless after thread end too.
void ct_perfetto_thread_begin(void *context);

// A value-owned identifier for this DR context's lifetime. Allocation uses only
// its TLS field and an atomic counter: no trace lock, event publication or IPC.
// A foreign context can only be queried, never assigned a new identity here.
uint64_t ct_perfetto_track_token(void *context);

// Returns zero when disabled or on failure. The token identifies a dynamic
// slice, including its original thread, and may safely be ended more than once.
// Optional details are escaped into args.details (begin) and args.end_details
// (end), so importing a complete slice preserves both pieces of information.
uint64_t ct_perfetto_begin(ct_perfetto_timestamp timestamp,
                           const char *category, const char *name,
                           const char *module, const char *file, unsigned line,
                           uint64_t pc, const char *origin,
                           const char *details = nullptr);
// Ending an ancestor also closes still-open descendants as incomplete.
void ct_perfetto_end(uint64_t token, ct_perfetto_timestamp timestamp,
                     const char *status, const char *details = nullptr);
void ct_perfetto_instant(ct_perfetto_timestamp timestamp, const char *name,
                         const char *details, uint64_t pc);
// Pass the exiting thread's callback context: teardown can run on another
// thread.
void ct_perfetto_thread_end(void *context, ct_perfetto_timestamp timestamp,
                            const char *status);

#endif
