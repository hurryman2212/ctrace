// SPDX-License-Identifier: MIT

#ifndef CTRACE_DWARF_VALUES_H
#define CTRACE_DWARF_VALUES_H
#include <cstddef>
#include <cstdint>

#include "c_cpp_values.hh"
#include "dwarf/types.hh"

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
/* Exact visible-variable/location equivalence at two PCs. On success, the
 * mask contains every DWARF register used by those locations and their frame
 * bases. Unsupported/ambiguous recipes forbid coalescing observations. */
bool ct_values_observation_equivalent(ct_values_site *before,
                                      ct_values_site *after,
                                      uint64_t *registers);
void ct_values_site_free(ct_values_site *s);
/* Visible variables use the same recursive aggregate formatter as operand and
 * decompiler values. Unavailable values are '?'; empty scopes stay empty. */
void ct_values_format(ct_values_site *s, const ct_registers *regs,
                      ct_read_memory read, void *arg, char *out, size_t size,
                      bool *truncated = nullptr);
/* Format requested variables and bounded source access paths in the order of
 * the NUL-separated list. Accesses retain base addresses and the selected leaf;
 * unsupported paths stay '?'. No calls or arbitrary C expressions execute. */
void ct_values_format_selected(ct_values_site *s, const ct_registers *regs,
                               ct_read_memory read, void *arg,
                               const char *names, size_t names_size, char *out,
                               size_t size, bool *truncated = nullptr);
/* Match a complete variable or a statically located member/array element,
 * never a coincidentally equal scalar value. If no direct variable matches,
 * one pointer/reference level may identify its pointee without reading it.
 * For memory, location is an application address; otherwise it is a DWARF
 * register number. Nonzero byte_offset, ambiguous aliases, pieces, and partial
 * variables do not match. */
bool ct_values_find_name(ct_values_site *s, const ct_registers *regs,
                         ct_read_memory read, void *arg, bool memory,
                         uint64_t location, size_t byte_offset, size_t bytes,
                         char *out, size_t size, bool *truncated = nullptr);
/* Format name=value using supplied captured operand bytes and a proven DWARF
 * location/type match. The operand storage is not reread by this function. */
bool ct_values_format_operand(ct_values_site *s, const ct_registers *regs,
                              ct_read_memory read, void *arg, bool memory,
                              uint64_t location, size_t byte_offset,
                              const unsigned char *raw, size_t bytes, char *out,
                              size_t size, bool *truncated = nullptr);
/* Resolve a visible lexical name without evaluating its storage or consuming
 * any first-use state. Unknown types still carry a stable symbol identity. */
bool ct_values_describe_name(ct_values_site *s, const char *name,
                             ct_variable_description *description);
// Resolve an explicitly selected lvalue path without reading its storage.
// Synthetic aggregate-base addresses deliberately claim no aggregate type.
bool ct_values_describe_access(ct_values_site *s, const char *name,
                               bool storage_address,
                               ct_variable_description *description);
bool ct_values_describe_operand(ct_values_site *s, const ct_registers *regs,
                                ct_read_memory read, void *arg, bool memory,
                                uint64_t location, size_t byte_offset,
                                size_t bytes,
                                ct_variable_description *description);
/* Assembly snapshots select only an exact, unambiguous DWARF storage extent.
 * Member paths retain their base addresses and captured leaf bytes; unrelated
 * sibling values are not read. raw may be NULL after a failed capture, leaving
 * the leaf '?'. description identifies the leaf; first-use state is external.
 */
bool ct_values_format_assembly_operand(
    ct_values_site *s, const ct_registers *regs, ct_read_memory read, void *arg,
    bool memory, uint64_t location, size_t byte_offset,
    const unsigned char *raw, size_t bytes, char *out, size_t size,
    ct_variable_description *description, bool *truncated = nullptr);
/* Sample only storage whose current DWARF location and non-volatile type are
 * proven. This is a storage snapshot, not proof of an exact concurrent write.
 */
bool ct_values_read_operand(ct_values_site *s, const ct_registers *regs,
                            ct_read_memory read, void *arg, bool memory,
                            uint64_t location, size_t byte_offset, size_t bytes,
                            char *out, size_t size, bool *truncated = nullptr);
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
    const ct_initializer_source *source, char *out, size_t size,
    bool *truncated = nullptr);
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
  std::string name;
  std::string type_name;
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
bool ct_function_pointer_type(ct_function *fn, char *out, size_t size,
                              bool *truncated = nullptr);
/* Reconstruct the DWARF declaration around the supplied display name, without
 * a body or semicolon. Failure leaves empty output, never a guessed type. */
bool ct_function_declaration(ct_function *fn, const char *display_name,
                             char *out, size_t size, bool *truncated = nullptr);
/* A known void return or a scalar returned in RAX/XMM0 by the SysV ABI.
 * Aggregate and unsupported return locations fail without guessing a width.
 * spelling is the DWARF type, or '?' if its spelling is unavailable. */
bool ct_function_return_type(ct_function *fn, ct_value_type *type,
                             bool *is_void, char *spelling, size_t capacity,
                             bool *truncated = nullptr);
/* A real DWARF return type with an unsupported ABI must not be reinterpreted
 * as a scalar by a less authoritative decompiler or caller-width guess. */
bool ct_function_return_unsupported(ct_function *fn);
/* Declared parameter names only, comma-space separated; unnamed parameters
 * are omitted. Failure leaves an empty output, never a partial/truncated name.
 */
bool ct_function_argument_names(ct_function *fn, char *out, size_t size,
                                bool *truncated = nullptr);
/* Parameter identity agrees with ct_values_describe_name/describe_operand at
 * later instructions, including abstract-origin DWARF parameter DIEs. */
bool ct_function_describe_parameter(ct_function *fn, const char *name,
                                    ct_variable_description *description);
void ct_function_arguments(ct_function *fn, const ct_registers *regs,
                           ct_read_memory read, void *arg, char *out,
                           size_t size, bool *truncated = nullptr);
/* Capture positional entry values, including unnamed parameters. Unknown
 * fixed slots are '?'; the unspecified variadic tail is represented by '...'.
 * A known empty parameter list succeeds with empty output. */
bool ct_function_argument_values(ct_function *fn, const ct_registers *regs,
                                 ct_read_memory read, void *arg, char *out,
                                 size_t size, bool *truncated = nullptr);
/* The same entry snapshot with name=value fields and no type casts. Unnamed
 * fixed parameters use argN; the unspecified variadic tail is omitted. */
bool ct_function_entry_arguments(ct_function *fn, const ct_registers *regs,
                                 ct_read_memory read, void *arg, char *out,
                                 size_t size, bool *truncated = nullptr);
/* Select entry arguments with the same bounded ordered-name contract as
 * ct_values_format_selected; capture before the callee prologue. */
void ct_function_arguments_selected(ct_function *fn, const ct_registers *regs,
                                    ct_read_memory read, void *arg,
                                    const char *names, size_t names_size,
                                    char *out, size_t size,
                                    bool *truncated = nullptr);
void ct_function_return(ct_function *fn, const ct_registers *regs,
                        ct_read_memory read, void *arg, char *out, size_t size,
                        bool *truncated = nullptr);
#endif
