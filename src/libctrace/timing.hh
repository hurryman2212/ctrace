// SPDX-License-Identifier: MIT

#ifndef CTRACE_TIMING_H
#define CTRACE_TIMING_H

#include <cstdint>
#include <vector>

#include <dr_api.h>

// Initialize only for an explicitly requested timing trace. The frequency is
// invariant TSC ticks per second, not the processor's variable core frequency.
bool ct_timing_init();
void ct_timing_exit();
uint64_t ct_timing_frequency();
// Reset the surviving thread's clock after an ordinary fork. The calibrated
// frequency remains valid; no parent samples or running intervals are copied.
void ct_timing_after_fork(void *context);

struct ct_timing_thread_snapshot {
  thread_id_t tid;
  // Capture the value while the registered context is live; snapshots must
  // never dereference a context after releasing the timing registry lock.
  uint64_t track_token;
  uint64_t nanoseconds;
};

// Register only threads selected for recording. Snapshot published clocks
// without suspending or sampling other threads, including their ongoing quiet
// application/kernel intervals. Detailed instruction intervals contribute when
// their normal observer samples them. A snapshot never advances the live clock.
void ct_timing_register_thread(void *context);
// Call after the final timing sample, while the owner is no longer executing
// application/client timing work. Teardown may unregister another DR context.
void ct_timing_unregister_thread(void *context);
std::vector<ct_timing_thread_snapshot> ct_timing_snapshot_process();

// Insert stop before all callbacks and start after their restored application
// state. The probes preserve application GPRs and flags through drreg.
void ct_timing_stop(void *context, instrlist_t *block, instr_t *where);
void ct_timing_start(void *context, instrlist_t *block, instr_t *where);

// Consume a completed pair or quiet span once and return cumulative ticks.
// Ordinary pairs contribute no duration after migration, reversed timestamps
// or interruption. Quiet spans use the monotonic fallback described below.
uint64_t ct_timing_sample(void *context);
// Preserve accumulated duration, but invalidate a gap crossing unmeasured
// runtime work, code generation or signal delivery.
void ct_timing_discard(void *context);

// Measure application spans without per-instruction probes. End at the start
// of every client callback, then begin after its work if execution is still
// quiet. Code generation, module events and signal callbacks must also stop
// the span before analysis or output. An ordinary sample defensively ends it.
// Repeated begins or ends are idempotent. Begin preserves a completed ordinary
// probe pair; end invalidates pairs crossing the quiet span. Kernel and quiet
// intervals never overlap: kernel begin ends a quiet span, and quiet begin is
// ignored while a kernel interval is armed. Both use monotonic elapsed time
// converted to ticks if the thread migrates between their boundaries.
bool ct_timing_quiet_active(void *context);
void ct_timing_quiet_begin(void *context);
uint64_t ct_timing_quiet_end(void *context);

// Arm at the end of an application pre-syscall callback; consume at the start
// of its post-syscall or signal callback. A signal handler's own system calls
// use a new pair after the interrupted interval has been consumed. This adds
// kernel execution and waiting time, excluding client callback work. If the
// thread migrates, use monotonic elapsed time converted to the same tick axis.
// These calls invalidate ordinary probe pairs crossing the kernel interval.
// Repeated begin/end calls are idempotent until the opposite operation occurs.
void ct_timing_kernel_begin(void *context);
uint64_t ct_timing_kernel_end(void *context);

#endif
