// SPDX-License-Identifier: MIT

#ifndef CTRACE_SHARED_OBJECTS_PLATFORM_H
#define CTRACE_SHARED_OBJECTS_PLATFORM_H

#include <cstddef>
#include <cstdint>

#include "shared_digest.hh"

/* The catalog protocol is identical in a DR client and an external helper.
 * Only descriptor protection, image ownership and SHA implementation differ. */
bool ct_shared_platform_adopt(int descriptor, bool inherit_fork);
void ct_shared_platform_close(int descriptor);
uint64_t ct_shared_platform_session(void);
bool ct_shared_platform_connect(int descriptor);
bool ct_shared_platform_digest(const void *data, size_t size,
                               unsigned char digest[32]);
bool ct_shared_platform_digest_parts(const ct_digest_part *parts, size_t count,
                                     unsigned char digest[32]);

#endif
