// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_LIFETIME_H
#define CTRACE_KERNEL_LIFETIME_H

#include <functional>
#include <string>

#include <sys/types.h>

#include "linux/kctrace.h"

enum class ct_kernel_finish {
  unloaded,
  external_exit,
  init_failed,
  error,
  load_failed
};

struct ct_kernel_lifetime_result {
  ct_kernel_finish reason = ct_kernel_finish::error;
  int error = 0;
  int load_status = 0; // Raw wait status; not a guessed kernel errno.
  int exec_error = 0;
  bool output_failed = false;
};

// Internal handoff from the asynchronous insmod launcher. The follower reaps
// process and closes its channels on completion; the launcher owns cleanup on
// fatal errors. A successful exec closes exec_errors without writing a value.
struct ct_kernel_loading {
  pid_t process = -1;
  int process_fd = -1, exec_errors = -1, diagnostics = -1;
  int wait_status = 0, exec_error = 0;
  bool finished = false;
  std::string original_path;
};

void ct_kernel_termination_signals(sigset_t &mask);
// Consume the SIGPIPE already handled as output failure while it is blocked.
void ct_kernel_consume_sigpipe();

// The caller owns the prepared/bound session descriptor and immutable metadata.
// A successful owned delete_module proves removal; external_exit only means the
// bound instance's exit and disappearance were observed. No conditional-delete
// kernel API or claim of atomicity against external unload/reload is involved.
ct_kernel_lifetime_result
ct_kernel_follow(int descriptor, const kctrace_prepare &prepared,
                 const std::function<bool(const kctrace_event &)> &event,
                 const std::function<void(const std::string &)> &notice,
                 ct_kernel_loading *loading = nullptr);

#endif
