// SPDX-License-Identifier: MIT

#include <dr_api.h>

#include "analysis.hh"
#include "shared_digest.hh"
#include "shared_objects_platform.hh"

bool ct_shared_platform_adopt(int descriptor, bool inherit_fork) {
  return dr_adopt_file_descriptor_ex(descriptor, false, !inherit_fork);
}

void ct_shared_platform_close(int descriptor) { dr_close_file(descriptor); }

uint64_t ct_shared_platform_session(void) { return ct_analysis_object_owner(); }

bool ct_shared_platform_connect(int descriptor) {
  return ct_analysis_object_connect(descriptor);
}

bool ct_shared_platform_digest(const void *data, size_t size,
                               unsigned char digest[32]) {
  const ct_digest_part part = {data, size};
  return ct_shared_digest_parts(&part, 1, digest);
}

bool ct_shared_platform_digest_parts(const ct_digest_part *parts, size_t count,
                                     unsigned char digest[32]) {
  return ct_shared_digest_parts(parts, count, digest);
}
