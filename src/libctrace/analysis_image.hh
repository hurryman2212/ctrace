// SPDX-License-Identifier: MIT

#ifndef CTRACE_ANALYSIS_IMAGE_H
#define CTRACE_ANALYSIS_IMAGE_H

#include <cstddef>
#include <cstdint>

/* One bounded x86-64 code window, matching the flow decoder's byte budget.
 * A larger executable mapping must be discovered in separate windows. */
enum { CT_ANALYSIS_IMAGE_LIMIT = 65536 };

/* Wrap stable original bytes in a deterministic ELF64LE analysis container.
 * Its executable section starts at virtual address zero; ENTRY_OFFSET is an
 * observed entry hint, not a fabricated function extent. There are no symbols
 * or DWARF records. The caller validates the live mapping and generation.
 *
 * Return a protected, close-on-exec, fork-inherited sealed data descriptor, or
 * -1 with IDENTITY empty. IDENTITY receives a 64-digit content SHA-256
 * including the format contract hash and entry hint, never process addresses or
 * descriptor IDs. The caller closes the result with ct_shared_platform_close()
 * after analysis has borrowed/duplicated it. This API does not map or execute
 * the container. */
int ct_analysis_image_create(const unsigned char *bytes, size_t size,
                             uint64_t entry_offset, char identity[65]);

/* Compare an original instruction with its sealed snapshot without copying
 * the surrounding data window. This is a preparation-time read, not a check
 * on every entry into an already prepared executable copy. */
bool ct_analysis_image_matches(int descriptor, uint64_t offset,
                               const unsigned char *bytes, size_t size);

#endif
