#ifndef CTRACE_DR_SHARED_PROVIDER_H
#define CTRACE_DR_SHARED_PROVIDER_H

#include <cstdint>
#include <vector>

#include <dr_api.h>

#include "instrumentation.h"

// Register after drmgr_init and before application execution. A failed or
// unsupported registration leaves ordinary DR execution unchanged.
using ct_dr_shared_current = bool (*)(app_pc tag, uint64_t incarnation,
                                      uint64_t generation);
enum class ct_dr_shared_generation { current, busy, stale };
using ct_dr_shared_current_try = ct_dr_shared_generation (*)(
    app_pc tag, uint64_t incarnation, uint64_t generation);
// current_try must not block or allocate: replay can run with peers stopped.
// Pending mapping changes remain busy until their syscall completes. A known
// stale generation ends this promotion without retrying an impossible proof.
bool ct_dr_shared_init(ct_dr_shared_current current,
                       ct_dr_shared_current_try current_try);

// Stamp an emission-owned meta label. The digest must prove module content,
// original code generation, module-relative range, runtime/generator/ABI,
// policy and the complete compiled case set, not merely the current TLS case.
// Labels carry their own digest through ilist cloning and nested emissions.
bool ct_dr_shared_stamp(void *drcontext, instrlist_t *ilist,
                        const unsigned char provenance[32],
                        ct_instrument_level level, uint64_t incarnation,
                        uint64_t generation);

// Drain deferred catalog work and READY promotion at an existing safe client
// callback, outside analysis locks and peer suspension. Does not enable trace
// or create a higher instrumentation level. drain_pending is used on exit.
// An executed_tag is an exact original BB tag from an existing execution
// callback. Record its bounded demand before the ordinary service throttle.
void ct_dr_shared_service(void *drcontext, bool drain_pending = false,
                          app_pc executed_tag = nullptr);
// After tracing and producers stop, before analysis disconnect and drmgr_exit.
// A foreign final CLONE_VM task frees local wrappers without closing the
// producer's descriptor numbers. Returns false if service work is still active.
bool ct_dr_shared_exit(void *drcontext);

// The regular-fork preparation hook runs with peers quiescent. Include each
// returned ID per live token (including duplicate IDs) in the
// selected-reference reservation. vfork and CLONE_VM callers must not invoke
// these hooks or mutate parent ownership.
void ct_dr_shared_fork_prepare(void *drcontext,
                               std::vector<uint64_t> &published_objects);
void ct_dr_shared_fork_parent_done(void *drcontext);
// Call after the child has connected its new image session and claimed the
// selected catalog references. Early vanished-thread retirements are retained
// until this claim; inherited unpublished channels/FDs are only forgotten.
void ct_dr_shared_fork_child(void *drcontext);

#endif
