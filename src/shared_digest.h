#ifndef CTRACE_SHARED_DIGEST_H
#define CTRACE_SHARED_DIGEST_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ct_digest_part {
  const void *data;
  size_t size;
} ct_digest_part;

/* Local streaming SHA-256: no helper RPC, allocation, or process address
 * material is added implicitly. Empty parts produce the standard empty hash.
 */
bool ct_shared_digest_parts(const ct_digest_part *parts, size_t count,
                            unsigned char digest[32]);

#ifdef __cplusplus
}
#endif

#endif
