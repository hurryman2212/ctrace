#ifndef CTRACE_KERNEL_LOAD_H
#define CTRACE_KERNEL_LOAD_H

#include <functional>
#include <string>
#include <vector>

#include "kernel_lifetime.h"

// The caller has already completed preparation, verification and any required
// signing. All descriptors are borrowed. Start before loading, from a single
// controller thread with no competing SIGCHLD reaper. Parameters become literal
// insmod argv entries. Only its temporary /proc FD path is replaced in stderr
// with original_path; kernel error text and wait status are preserved.
// Fatal controller errors leave the independent guardian armed: the caller must
// close its collector lease and terminate, rather than continue unmanaged work.
ct_kernel_lifetime_result
ct_kernel_load(int collector, const kctrace_prepare &prepared, int module,
               const std::string &original_path,
               const std::vector<std::string> &parameters,
               const std::function<bool(const kctrace_event &)> &event,
               const std::function<void(const std::string &)> &notice);

#endif
