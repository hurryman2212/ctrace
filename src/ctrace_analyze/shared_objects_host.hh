// SPDX-License-Identifier: MIT

#ifndef CTRACE_SHARED_OBJECTS_HOST_H
#define CTRACE_SHARED_OBJECTS_HOST_H

#include <cstdint>

#include "ctrace_contract.h"

/* A private broker-created helper channel. Its cookie is distinct from the
 * application image's tracing session; helper participation never arms trace.
 */
enum ct_shared_host_operation : uint32_t {
  CT_SHARED_HOST_OBJECT_CONNECT = 1,
  CT_SHARED_HOST_DECOMPILE_CONNECT
};

struct ct_shared_host_request {
  uint32_t operation = 0;
  uint32_t reserved = 0;
  uint64_t session = 0;
  unsigned char contract[32] = CTRACE_CONTRACT_BYTES;
};

void ct_shared_host_init(int control, uint64_t session);
bool ct_shared_host_available();
bool ct_shared_host_connect(ct_shared_host_operation operation, int descriptor);

#endif
