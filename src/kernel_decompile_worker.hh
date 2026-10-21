// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_DECOMPILE_WORKER_H
#define CTRACE_KERNEL_DECOMPILE_WORKER_H

#include <cstdint>

#include "ctrace_contract.h"

// Private same-build stream protocol. The parent owns a sealed analysis image
// FD and invokes ctrace_analyze --kernel-decompile-worker CONTROL_FD IMAGE_FD.
// OPEN: JSON {module, analysis_identity}; FUNCTION: ct_kernel_decompile_query.
// MANIFEST: JSON; RESULT: JSON {address, identity, common_bytes, full_bytes},
// then COMMON and FULL binary view frames. PROGRESS is ct_analysis_progress.
// ERROR is JSON {scope,error}. FINISH/FINISHED have no payload. FINISHED and
// successful child exit are both required before loading the target module.
enum class ct_kernel_decompile_kind : uint32_t {
  open = 1,
  function = 2,
  finish = 3,
  manifest = 4,
  result = 5,
  common = 6,
  full = 7,
  progress = 8,
  error = 9,
  finished = 10
};

struct ct_kernel_decompile_packet {
  unsigned char contract_hash[32] = CTRACE_CONTRACT_BYTES;
  ct_kernel_decompile_kind kind = ct_kernel_decompile_kind::error;
  uint32_t reserved = 0;
  uint64_t bytes = 0;
};

struct ct_kernel_decompile_query {
  uint64_t address = 0;
  uint32_t level = 0, reserved = 0;
};

int ct_kernel_decompile_worker(int control, int image);

#endif
