// SPDX-License-Identifier: MIT

#include <sha256.h>

#include "shared_digest.hh"

bool ct_shared_digest_parts(const ct_digest_part *parts, size_t count,
                            unsigned char digest[32]) {
  if (!digest || (count && !parts))
    return false;
  SHA256_CTX context;
  SHA256_Init(&context);
  for (size_t index = 0; index < count; ++index) {
    if (parts[index].size && !parts[index].data)
      return false;
    if (parts[index].size)
      SHA256_Update(&context, static_cast<const uint8_t *>(parts[index].data),
                    parts[index].size);
  }
  SHA256_Final(digest, &context);
  return true;
}
