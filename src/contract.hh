// SPDX-License-Identifier: MIT

#ifndef CTRACE_CONTRACT_H
#define CTRACE_CONTRACT_H

#include <cstring>

#include "ctrace_contract.h"

/* Generated from the implementation and its private interface definitions. */
static const unsigned char ct_contract_digest[32] = CTRACE_CONTRACT_BYTES;

static inline bool ct_contract_matches(const unsigned char digest[32]) {
  return memcmp(digest, ct_contract_digest, sizeof(ct_contract_digest)) == 0;
}

#endif
