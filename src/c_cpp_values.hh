// SPDX-License-Identifier: MIT

#ifndef CTRACE_C_CPP_VALUES_H
#define CTRACE_C_CPP_VALUES_H

#include <cstddef>
#include <cstdint>
#include <string>

typedef bool (*ct_read_memory)(void *, uint64_t, void *, size_t);

typedef enum {
  CT_VALUE_UNKNOWN,
  CT_VALUE_SIGNED,
  CT_VALUE_UNSIGNED,
  CT_VALUE_FLOAT,
  CT_VALUE_BOOLEAN,
  CT_VALUE_POINTER
} ct_value_kind;
typedef struct {
  ct_value_kind kind;
  size_t bytes;
} ct_value_type;
/* Portable, bounded type graph shared by DWARF and decompiler values.
 * Type IDs are one-based; zero means unavailable. Member ranges are zero-based.
 * Pointer targets may be followed only when they describe declared aggregates.
 */
typedef enum {
  CT_LAYOUT_UNKNOWN,
  CT_LAYOUT_SCALAR,
  CT_LAYOUT_STRUCT,
  CT_LAYOUT_ARRAY,
  CT_LAYOUT_POINTER,
  // Every declared member is a view of shared bytes, not an active-member
  // claim.
  CT_LAYOUT_UNION
} ct_value_layout_kind;
typedef struct {
  ct_value_layout_kind kind;
  ct_value_type scalar;
  size_t bytes;
  uint32_t element_type;
  size_t element_count, element_stride;
  uint32_t first_member;
  size_t member_count;
  bool complete, guarded;
} ct_value_layout_node;
typedef struct {
  std::string name;
  uint32_t type;
  size_t offset;
  bool available;
} ct_value_layout_member;
typedef struct {
  const ct_value_layout_node *types;
  size_t type_count;
  const ct_value_layout_member *members;
  size_t member_count;
} ct_value_layout;
/* Format a whole object as name=value. raw, when non-NULL, supplies the entire
 * captured object (bytes bounds it); otherwise memory/address identify its
 * storage, read only through the callback. Missing children are '?'; exhausted
 * traversal/output budgets are marked '...'. No application expression runs.
 */
bool ct_values_format_layout(const char *name, const ct_value_layout *layout,
                             uint32_t type_id, const unsigned char *raw,
                             size_t bytes, uint64_t address, bool memory,
                             ct_read_memory read, void *arg, char *out,
                             size_t size, bool *truncated = nullptr);
/* Internal lazy metadata adapter. Only providers interpret these type handles;
 * identity and dimension distinguish active aggregate paths for cycle checks.
 * Member cursors start zeroed and advance once per member request. */
typedef struct {
  const void *identity, *context;
  uint32_t id;
  unsigned dimension;
} ct_value_format_ref;
typedef struct {
  const unsigned char *raw;
  size_t size;
  uint64_t address;
  bool memory;
} ct_value_view;
typedef struct {
  char *p;
  size_t size, used;
  bool truncated;
} ct_value_buffer;
typedef struct {
  ct_value_format_ref type;
  const char *name;
  size_t offset;
  bool available;
} ct_value_format_member;
typedef enum {
  CT_VALUE_MEMBER_END,
  CT_VALUE_MEMBER_ITEM,
  CT_VALUE_MEMBER_SKIP,
  CT_VALUE_MEMBER_INVALID
} ct_value_member_status;
typedef struct {
  const void *arg;
  bool (*shape)(const void *, ct_value_format_ref *, ct_value_layout_node *,
                ct_value_format_ref *);
  ct_value_member_status (*member)(const void *, ct_value_format_ref, size_t,
                                   ct_value_format_ref *,
                                   ct_value_format_member *);
} ct_value_provider;
/* Append one unnamed value with the same bounded walker used by layout values.
 * False rolls back this value; truncated distinguishes output exhaustion from
 * unavailable storage/type information. No metadata ownership is transferred.
 */
bool ct_values_format_object(const ct_value_provider *provider,
                             ct_value_format_ref type, ct_value_view value,
                             ct_read_memory read, void *arg,
                             ct_value_buffer *out, bool *truncated = nullptr);
/* Captured scalar bytes only; no metadata lookup or target memory access.
 * Like snprintf, returns the required character count excluding NUL; a result
 * >= size means truncation. NULL out with size zero is a valid count query.
 * Invalid type/width/raw/output arguments return -1 without touching output.
 * Integer widths 1..8 are supported; pointers require 8 and floats 4 or 8.
 */
int ct_values_format_scalar(const ct_value_type *type, const unsigned char *raw,
                            size_t bytes, char *out, size_t size);
/* name=value; invalid arguments or truncation return false and empty output. */
bool ct_values_format_typed(const char *name, const ct_value_type *type,
                            const unsigned char *raw, size_t bytes, char *out,
                            size_t size);

#endif
