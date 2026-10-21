// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstring>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/SHA256.h>

#include "shared_objects_platform.hh"

bool ct_shared_platform_digest(const void *data, size_t size,
                               unsigned char digest[32]) {
  const ct_digest_part part{data, size};
  return ct_shared_platform_digest_parts(&part, 1, digest);
}

bool ct_shared_platform_digest_parts(const ct_digest_part *parts, size_t count,
                                     unsigned char digest[32]) {
  if (!digest || (count && !parts))
    return false;
  llvm::SHA256 context;
  size_t total = 0;
  for (size_t index = 0; index < count; ++index) {
    if ((!parts[index].data && parts[index].size) ||
        parts[index].size > SIZE_MAX - total)
      return false;
    total += parts[index].size;
    if (parts[index].size)
      context.update(llvm::ArrayRef<uint8_t>(
          static_cast<const uint8_t *>(parts[index].data), parts[index].size));
  }
  const auto hash = context.final();
  std::memcpy(digest, hash.data(), hash.size());
  return true;
}
