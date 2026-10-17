#ifndef CTRACE_KERNEL_GUARDIAN_H
#define CTRACE_KERNEL_GUARDIAN_H

#include <string>

#include <sys/types.h>

#include <uapi/kctrace.h>

struct ct_kernel_guardian {
  pid_t process = -1;
  int control = -1;
};

// Start in the controller's single-threaded initialization, after PREPARE and
// before loading the target. The ready handshake proves that the child closed
// every inherited collector lease and can observe the session independently.
// The child retains stderr for notices, and closes inherited stdin, stdout,
// and unrelated FDs. The caller must cancel on a normal finish and not reap
// this child elsewhere. Module removal remains a best-effort normal name-based
// delete_module, without atomic protection against external unload/reload.
bool ct_kernel_guardian_start(int collector, const kctrace_prepare &prepared,
                              ct_kernel_guardian &guardian, std::string &error);
// An explicit cancellation message is required: closing the control channel
// alone does not cancel protection against an owner's subsequent death.
bool ct_kernel_guardian_cancel(ct_kernel_guardian &guardian,
                               std::string &error);

#endif
