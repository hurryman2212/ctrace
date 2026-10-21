// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_PERFETTO_H
#define CTRACE_KERNEL_PERFETTO_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "trace.hh"

// A common wall-time axis and separately measured probe-excluded elapsed cost.
// This is not CPU time: scheduling/IRQ delays and unmeasured probe tails
// remain.
// Explicit IRQ tracks are CPU/depth lanes across interrupted tasks. Scope
// arguments retain the current-task attribution captured at each entry.
class ct_kernel_perfetto {
  struct Data;
  std::unique_ptr<Data> data;

public:
  ct_kernel_perfetto();
  ~ct_kernel_perfetto();
  ct_kernel_perfetto(const ct_kernel_perfetto &) = delete;
  ct_kernel_perfetto &operator=(const ct_kernel_perfetto &) = delete;

  // directory is a borrowed FD captured in the invoking shell's cwd before
  // preparation. prefix supplies its original path/name for display only.
  bool open(const std::string &prefix, int directory, uint32_t controller_tid,
            const std::string &module, const std::string &input,
            std::string &error);
  bool observe(const kctrace_event &event,
               const std::vector<ct_kernel_trace_transition> &transitions,
               std::string &error);
  // Close remaining scopes at the latest observed boundary, then the module
  // lifetime at the controller's normalized kernel-clock observation.
  bool finish(const std::vector<ct_kernel_trace_transition> &transitions,
              const char *status, std::string &error);
  const std::string &path() const;
};

#endif
