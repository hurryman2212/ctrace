/* SPDX-License-Identifier: MIT */
#ifndef KCTRACE_CONTRACT_H
#define KCTRACE_CONTRACT_H

/* Build systems provide only the digest values generated from the shared
 * contract and runtime sources. This declaration is shared by kernel C and
 * userspace C++ consumers.
 */
#if !defined(KCTRACE_CONTRACT_HEX) || !defined(KCTRACE_CONTRACT_BYTES)
#error "KCTRACE contract digest must be supplied by the build"
#endif

#ifdef __cplusplus
inline constexpr unsigned char kctrace_contract_hash[32] =
    KCTRACE_CONTRACT_BYTES;
#else
static const unsigned char kctrace_contract_hash[32] = KCTRACE_CONTRACT_BYTES;
#endif

#endif
