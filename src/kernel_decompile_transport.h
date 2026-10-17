#ifndef CTRACE_KERNEL_DECOMPILE_TRANSPORT_H
#define CTRACE_KERNEL_DECOMPILE_TRANSPORT_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "analysis.h"
#include "decompile_view.h"

// Offline preparation only. The child owns the Ghidra worker; received views
// are sealed read-only objects and contain no live producer handles.
class ct_kernel_decompile_client {
  struct State;
  std::unique_ptr<State> state;

public:
  ct_kernel_decompile_client();
  ~ct_kernel_decompile_client();
  ct_kernel_decompile_client(const ct_kernel_decompile_client &) = delete;
  ct_kernel_decompile_client &
  operator=(const ct_kernel_decompile_client &) = delete;

  bool open(const std::string &helper, const std::string &module,
            const std::string &identity,
            const std::vector<unsigned char> &analysis_image,
            const std::function<void(const ct_analysis_progress &)> &progress,
            std::string &manifest, std::string &error);
  // True with an empty view is a recoverable per-function failure (reason in
  // error). False means the protocol/producer failed; do not load the target.
  bool function(uint64_t address, uint32_t level, ct_decompile_view &view,
                std::string &error);
  std::string identity() const;
  // Requires the cleanup acknowledgement AND successful producer exit.
  bool finish(std::string &error);
};

#endif
