#ifndef CTRACE_VALUES_H
#define CTRACE_VALUES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/* AMD64 DWARF register order, NOT the Linux ptrace or DR struct order. */
typedef struct {
  uint64_t gpr[17]; /* rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp,r8..r15,rip */
  unsigned char xmm[32][64];
  size_t simd_bytes;
  uint64_t opmask[8];
  bool have_opmask;
  bool have_gpr, have_xmm;
  /* Registers whose live bytes no longer belong to the current DWARF frame,
   * e.g. restored RBP during an epilogue. Raw instruction operands may still
   * display those bytes, but variable locations must not use them. */
  uint64_t unavailable_gpr;
  uint64_t flags;
} ct_registers;
typedef bool (*ct_read_memory)(void *, uint64_t, void *, size_t);
typedef struct ct_values_module ct_values_module;
typedef struct ct_values_site ct_values_site;
typedef struct ct_function ct_function;
/* Serialize all operations per module. Objects outlive emitted code. */
/* debug_path is the matching debug file resolved by the external analysis
 * helper. NULL/empty disables external lookup inside the instrumented process.
 */
ct_values_module *ct_values_open(const char *path, uint64_t mapped_base,
                                 const char *debug_path);
/* Borrow main/debug ELF snapshots without reopening their paths or transferring
 * descriptor ownership to libdwfl. Descriptors may close after this call;
 * read-only file pages remain shared, with private copy-on-write ELF metadata
 * pages for libelf's decompression bookkeeping. DEBUG_FD may be -1 for embedded
 * DWARF. The helper computes the signed difference
 * between libdwfl's DWARF and ELF biases for this exact main/debug pair. */
ct_values_module *ct_values_open_fd(const char *path, uint64_t mapped_base,
                                    int module_fd, int debug_fd,
                                    int64_t dwarf_bias_correction);
/* Attach a helper-validated supplementary DWARF snapshot before preparing any
 * sites/functions. The caller verifies the .gnu_debugaltlink build ID or
 * .debug_sup identity. FD remains borrowed and may close after this call. */
bool ct_values_set_supplement_fd(ct_values_module *m, int fd);
/* Content identity includes the executable and its resolved debug object.
 * Disk recipes are optional; prepared plans remain cached in this module. */
void ct_values_set_cache_identity(ct_values_module *m, const char *identity);
void ct_values_close(ct_values_module *m);
ct_values_site *ct_values_prepare(ct_values_module *m, uint64_t pc);
bool ct_values_has_scope(const ct_values_site *s);
void ct_values_site_free(ct_values_site *s);
/* Visible variables use the same recursive aggregate formatter as operand and
 * decompiler values. Unavailable values are '?'; empty scopes stay empty. */
void ct_values_format(ct_values_site *s, const ct_registers *regs,
                      ct_read_memory read, void *arg, char *out, size_t size);
/* Format only the requested visible variables, in the order of the bounded
 * NUL-separated name list. Duplicate/unknown names are omitted; an empty or
 * unterminated list produces empty output. No C expressions are evaluated. */
void ct_values_format_selected(ct_values_site *s, const ct_registers *regs,
                               ct_read_memory read, void *arg,
                               const char *names, size_t names_size, char *out,
                               size_t size);
/* Match a complete variable or a statically located member/array element,
 * never a coincidentally equal scalar value. If no direct variable matches,
 * one pointer/reference level may identify its pointee without reading it.
 * For memory, location is an application address; otherwise it is a DWARF
 * register number. Nonzero byte_offset, ambiguous aliases, pieces, and partial
 * variables do not match. */
bool ct_values_find_name(ct_values_site *s, const ct_registers *regs,
                         ct_read_memory read, void *arg, bool memory,
                         uint64_t location, size_t byte_offset, size_t bytes,
                         char *out, size_t size);
/* Format name=value using supplied captured operand bytes and a proven DWARF
 * location/type match. The operand storage is not reread by this function. */
bool ct_values_format_operand(ct_values_site *s, const ct_registers *regs,
                              ct_read_memory read, void *arg, bool memory,
                              uint64_t location, size_t byte_offset,
                              const unsigned char *raw, size_t bytes, char *out,
                              size_t size);
/* Stable DWARF identity and the type of the resolved object/member. Formatting
 * does not mark this symbol as displayed; the output owner decides that only
 * when the corresponding input value is actually emitted. */
typedef struct {
  // Lifetime-unique instance identity; allocation reuse must not merge names.
  uint64_t module_id;
  uint64_t die_offset;
  char name[256];
  char type[512];
} ct_variable_description;
/* Resolve a visible lexical name without evaluating its storage or consuming
 * any first-use state. Unknown types still carry a stable symbol identity. */
bool ct_values_describe_name(ct_values_site *s, const char *name,
                             ct_variable_description *description);
bool ct_values_describe_operand(ct_values_site *s, const ct_registers *regs,
                                ct_read_memory read, void *arg, bool memory,
                                uint64_t location, size_t byte_offset,
                                size_t bytes,
                                ct_variable_description *description);
/* Assembly snapshots produce plain name=value. A partial memory operand of a
 * declared aggregate expands that whole object, using captured operand bytes
 * plus safe reads of its siblings. raw may be NULL after a failed capture:
 * overlapping members then stay '?'. description identifies the displayed
 * object and may be NULL. First-use bookkeeping is owned by the caller. */
bool ct_values_format_assembly_operand(
    ct_values_site *s, const ct_registers *regs, ct_read_memory read, void *arg,
    bool memory, uint64_t location, size_t byte_offset,
    const unsigned char *raw, size_t bytes, char *out, size_t size,
    ct_variable_description *description);
/* Sample only storage whose current DWARF location and non-volatile type are
 * proven. This is a storage snapshot, not proof of an exact concurrent write.
 */
bool ct_values_read_operand(ct_values_site *s, const ct_registers *regs,
                            ct_read_memory read, void *arg, bool memory,
                            uint64_t location, size_t byte_offset, size_t bytes,
                            char *out, size_t size);
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
  CT_LAYOUT_POINTER
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
  char name[128];
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
                             size_t size);
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
                             ct_value_buffer *out);
/* Original DWARF line-row identity resolved by the external analysis helper.
 * Compare numeric file indices within the same CU, without parsing native
 * libdw line tables on DynamoRIO's bounded instrumentation stack. */
typedef struct {
  uint64_t cu_die_offset, file_index;
  uint32_t line;
  bool valid;
} ct_initializer_source;
/* Preserve scalar formatting for an instruction-proven register copy without
 * evaluating a stale source location or rereading the original storage. */
bool ct_values_operand_type(ct_values_site *s, const ct_registers *regs,
                            ct_read_memory read, void *arg, bool memory,
                            uint64_t location, size_t byte_offset, size_t bytes,
                            ct_value_type *type);
/* Return a whole local integer declaration such as "int i" only when the
 * exact current storage matches and its DWARF declaration file/line agrees
 * with source. Globals, parameters, members and unproven declarations
 * return false. No source files or application values are evaluated. */
bool ct_values_initializer_declaration(
    ct_values_site *s, const ct_registers *regs, ct_read_memory read, void *arg,
    bool memory, uint64_t location, size_t byte_offset, size_t bytes,
    const ct_initializer_source *source, char *out, size_t size);
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
/* SysV AMD64 scalar ABI only. Capture arguments at the actual callee entry,
 * before its prologue, and the return value after a normal return. Module
 * operations, including these calls, require the same external serialization.
 * Arguments format as name=value for observed named parameters only.
 * Return formatting produces an observed value; void and unavailable values
 * produce an empty string. */
ct_function *ct_function_prepare(ct_values_module *m, uint64_t runtime_pc);
void ct_function_free(ct_function *fn);
typedef struct {
  ct_value_type type;
  unsigned reg;
  uint64_t stack_offset;
  bool on_stack;
  char name[128];
  char type_name[256];
} ct_function_parameter;
/* Read fixed scalar argument locations without evaluating application state.
 * reg uses AMD64 DWARF numbering, and type.bytes is the storage width.
 * stack_offset is relative to callee entry RSP (first stack argument is +8).
 * NULL out with zero capacity is a validated count query. A known empty list
 * succeeds; unsupported/incomplete ABI metadata or insufficient capacity
 * fails with count=0 and variadic=false, leaving out untouched. */
bool ct_function_parameters(ct_function *fn, ct_function_parameter *out,
                            size_t capacity, size_t *count, bool *variadic);
/* Format the DWARF function-pointer type, including parameter names when
 * available, for a first-use cast in the trace. */
bool ct_function_pointer_type(ct_function *fn, char *out, size_t size);
/* Reconstruct the DWARF declaration around the supplied display name, without
 * a body or semicolon. Failure leaves empty output, never a guessed type. */
bool ct_function_declaration(ct_function *fn, const char *display_name,
                             char *out, size_t size);
/* A known void return or a scalar returned in RAX/XMM0 by the SysV ABI.
 * Aggregate and unsupported return locations fail without guessing a width.
 * spelling is the DWARF type, or '?' if its spelling is unavailable. */
bool ct_function_return_type(ct_function *fn, ct_value_type *type,
                             bool *is_void, char *spelling, size_t capacity);
/* A real DWARF return type with an unsupported ABI must not be reinterpreted
 * as a scalar by a less authoritative decompiler or caller-width guess. */
bool ct_function_return_unsupported(ct_function *fn);
/* Declared parameter names only, comma-space separated; unnamed parameters
 * are omitted. Failure leaves an empty output, never a partial/truncated name.
 */
bool ct_function_argument_names(ct_function *fn, char *out, size_t size);
/* Parameter identity agrees with ct_values_describe_name/describe_operand at
 * later instructions, including abstract-origin DWARF parameter DIEs. */
bool ct_function_describe_parameter(ct_function *fn, const char *name,
                                    ct_variable_description *description);
void ct_function_arguments(ct_function *fn, const ct_registers *regs,
                           ct_read_memory read, void *arg, char *out,
                           size_t size);
/* Capture positional entry values, including unnamed parameters. Unknown
 * fixed slots are '?'; the unspecified variadic tail is represented by '...'.
 * A known empty parameter list succeeds with empty output. */
bool ct_function_argument_values(ct_function *fn, const ct_registers *regs,
                                 ct_read_memory read, void *arg, char *out,
                                 size_t size);
/* The same entry snapshot with name=value fields and no type casts. Unnamed
 * fixed parameters use argN; the unspecified variadic tail is omitted. */
bool ct_function_entry_arguments(ct_function *fn, const ct_registers *regs,
                                 ct_read_memory read, void *arg, char *out,
                                 size_t size);
/* Select entry arguments with the same bounded ordered-name contract as
 * ct_values_format_selected; capture before the callee prologue. */
void ct_function_arguments_selected(ct_function *fn, const ct_registers *regs,
                                    ct_read_memory read, void *arg,
                                    const char *names, size_t names_size,
                                    char *out, size_t size);
void ct_function_return(ct_function *fn, const ct_registers *regs,
                        ct_read_memory read, void *arg, char *out, size_t size);
#ifdef __cplusplus
}
#endif
#endif
