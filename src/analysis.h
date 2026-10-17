#ifndef CTRACE_ANALYSIS_H
#define CTRACE_ANALYSIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "values.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ct_analysis ct_analysis;

/* Uncached bulk work, reported before it starts. Offsets are module-relative;
 * callbacks run while an analysis request is pending and must not query it. */
typedef struct ct_analysis_progress {
  char stage[32];
  char module[4096];
  char detail[1024];
  char file[4096];
  /* Selected source mapping as old=new; empty when no source is identified. */
  char source_prefix[8192];
  char function[512];
  uint64_t line;
  uint64_t begin_offset;
  uint64_t end_offset;
  bool has_range;
} ct_analysis_progress;
void ct_analysis_set_progress_callback(
    void (*callback)(const ct_analysis_progress *progress, void *context),
    void *context);
/* Helper-side producers; notification delivery is synchronous. */
void ct_analysis_report_progress(const ct_analysis_progress *progress);

/* SHA-256 of the helper's length-framed key, encoded as 64 lowercase hex
 * characters plus NUL. Computing an identity never accesses the disk cache. */
bool ct_analysis_cache_digest(const char *key, char digest[65]);
/* SHA-256 over raw bytes, without framing or disk access. */
bool ct_analysis_content_digest(const void *data, size_t size,
                                unsigned char digest[32]);
/* Exact selected client/runtime/helper build fingerprint. Call before target
 * code runs, then before preparing each shared artifact. Full file hashes are
 * computed once; later calls revalidate file metadata. Actual loaded client/DR
 * inode and GNU build-id must match the hashed files. Missing evidence, file
 * replacement/deletion or modification fails closed and clears digest. This
 * does not depend on --cache-dir and excludes runtime instrumentation policy.
 */
bool ct_analysis_runtime_identity(char digest[65]);
/* Internal connection handoff for the session shared-object client. */
bool ct_analysis_object_connect(int descriptor);
/* Broker image-session identity, only when this process owns the private
 * worker socket (kernel peer credentials, not a cached namespace-local PID). */
uint64_t ct_analysis_object_owner(void);

/* Opaque, pointer-free client analysis recipes. Successful reads allocate
 * with malloc; the caller frees the bytes and validates its own schema. */
bool ct_analysis_cache_read(const char *kind, const char *key,
                            unsigned char **data, size_t *size);
bool ct_analysis_cache_write(const char *kind, const char *key,
                             const void *data, size_t size);

/* The client connects to the launcher-owned native analysis helper once. */
bool ct_analysis_connect(int socket_fd);
// The broker preserves the executing task's participation across exec without
// relying on the application's environment or PID namespace.
bool ct_analysis_recording_allowed(void);
/* Shared broker origin in nanoseconds on the namespace-normalized raw clock.
 * The origin remains unchanged across worker connections, forks and execs.
 */
uint64_t ct_analysis_trace_origin_ns(void);
uint64_t ct_analysis_wall_nanoseconds(void);
/* Refresh after entering another time namespace and before sampling wall time.
 * Fork and exec connections refresh their inherited clock offsets themselves.
 */
bool ct_analysis_refresh_clock(void);
/* Per-thread adjusted application time since the current image's thread
 * origin, paired with namespace-normalized raw wall time. Only the successful
 * exec's snapshots close the replaced image's Perfetto tracks. track_token is
 * a context-lifetime identifier, not a namespace-local kernel TID.
 */
typedef struct ct_exec_timestamp {
  uint64_t track_token;
  uint64_t nanoseconds;
  uint64_t wall_nanoseconds;
} ct_exec_timestamp;
uint64_t ct_analysis_prepare_exec(bool recording,
                                  const ct_exec_timestamp *timestamps,
                                  size_t count);
bool ct_analysis_cancel_exec(uint64_t nonce);
void ct_analysis_disconnect(void);
/* Hold the proxy catalog stable across fork. Parent releases the guard; child
 * establishes a private worker and rebinds inherited analysis objects in place.
 */
void ct_analysis_fork_prepare(void);
void ct_analysis_fork_parent(void);
bool ct_analysis_fork_child(void);
bool ct_analysis_trace_event(const char *data, size_t size);
bool ct_analysis_trace_footer(const char *data, size_t size);
bool ct_analysis_trace_flush(void);
/* -1 keeps source asm unchanged; 0 selects AT&T, 1 selects Intel. */
void ct_analysis_set_syntax(int syntax);
/* Opt in before opening modules; unreadable sources remain unavailable. */
void ct_analysis_set_source_bypass(bool enabled);
/* Canonical instruction text; LLVM lives in the helper, outside DR's loader.
 * bytes must contain exactly one x86-64 instruction (at most 15 bytes). */
bool ct_analysis_disassemble(uint64_t pc, const unsigned char *bytes,
                             size_t size, char *att, size_t att_capacity,
                             char *intel, size_t intel_capacity);

#define CT_DECOMPILED_INSTRUCTION_LIMIT 64
#define CT_DECOMPILED_VARIABLE_LIMIT 128
#define CT_DECOMPILED_PARAMETER_LIMIT 32
#define CT_DECOMPILED_TYPE_LIMIT 512
#define CT_DECOMPILED_MEMBER_LIMIT 1024

typedef struct ct_decompiled_instruction {
  uint64_t offset;
  uint8_t size;
  uint8_t bytes[15];
} ct_decompiled_instruction;

/* Candidate decompiler text, not proof that the statement executed. Each PC
 * must match the original bytes and execute in the listed order before the
 * client may replace its assembly rows. Offsets are relative to module start.
 * Synthetic labels use @Lhex@ module-offset placeholders for runtime rebasing.
 */
typedef struct ct_decompiled_statement {
  uint64_t id;
  uint64_t function_offset;
  uint32_t instruction_count;
  uint32_t instruction_index;
  char text[4096];
  /* Optional scalar assignment target type. This describes the C symbol,
   * independently of whether its runtime storage can be observed here. */
  uint64_t declaration_id;
  char declaration_name[128];
  char declaration_type[256];
  ct_decompiled_instruction instructions[CT_DECOMPILED_INSTRUCTION_LIMIT];
} ct_decompiled_statement;

typedef enum {
  CT_DECOMPILED_STACK,
  CT_DECOMPILED_GLOBAL,
  CT_DECOMPILED_REGISTER
} ct_decompiled_storage;

enum { CT_DECOMPILED_READ = 1, CT_DECOMPILED_WRITE = 2 };

/* Storage evidence for the requested instruction. Stack offsets are relative
 * to the physical function's entry stack pointer; global offsets are relative
 * to the loaded module. Register evidence never extends to another PC.
 * These names are inferred by the decompiler, not recovered source names. */
typedef struct ct_decompiled_variable {
  uint64_t id;
  uint64_t offset;
  int64_t stack_offset;
  uint32_t size;
  ct_decompiled_storage kind;
  uint32_t access;
  /* An exact, read-only original input-register name at this instruction.
   * The client may share its first-use identity with that physical register. */
  bool register_alias;
  char name[128];
  char type_name[256];
  char register_name[32];
  ct_value_type type;
  /* One-based root in ct_decompiled_variables.types; zero is unavailable. */
  uint32_t type_id;
} ct_decompiled_variable;

/* Fixed scalar parameters in declaration order. Registers and stack offsets
 * describe storage at physical function entry, before its prologue executes.
 * A known empty parameter list is distinct from an unavailable signature. */
typedef struct ct_decompiled_parameter {
  int64_t stack_offset;
  uint32_t size;
  ct_decompiled_storage kind;
  char name[128];
  char type_name[256];
  char register_name[32];
  ct_value_type type;
} ct_decompiled_parameter;

typedef struct ct_decompiled_variables {
  uint64_t function_offset;
  ct_decompiled_instruction instruction;
  /* Scalar return storage belongs to this function, including instructions
   * with no named variables. Unknown kinds may carry a proven register width;
   * aggregates, multiple registers and unproven inferred void are excluded. */
  bool return_known;
  bool return_void;
  bool return_unsupported;
  ct_value_type return_type;
  char return_type_name[256];
  char return_register[32];
  bool parameters_known;
  bool variadic;
  uint32_t parameter_count;
  ct_decompiled_parameter parameters[CT_DECOMPILED_PARAMETER_LIMIT];
  uint32_t count;
  ct_decompiled_variable entries[CT_DECOMPILED_VARIABLE_LIMIT];
  /* Shared recursive layouts avoid copying a complete type tree per symbol.
   * Storage is self-contained because this record crosses the helper IPC. */
  uint32_t type_count;
  ct_value_layout_node types[CT_DECOMPILED_TYPE_LIMIT];
  uint32_t member_count;
  ct_value_layout_member members[CT_DECOMPILED_MEMBER_LIMIT];
} ct_decompiled_variables;

enum { CT_DECOMPILE_PERFETTO = 1, CT_DECOMPILE_FULL = 2 };

/* Display information is shared by both levels; no value evaluation or
 * recursive aggregate layouts are required to obtain it. */
typedef struct ct_decompiled_display {
  uint64_t function_offset;
  uint32_t loaded_level;
  char function_name[256];
  char prototype[2048];
  ct_decompiled_instruction instruction;
  char control_text[4096];
  char control_kind[16];
  char control_initializer[2048];
  char control_update[2048];
  bool control_conditional;
  bool control_has_target;
  uint64_t control_target;
} ct_decompiled_display;

/* One allocation per function validation, never one proof copy per Site.
 * The payload is a header, range_count ranges, then instruction_count records.
 * Offsets are module-relative; release the returned allocation with free(). */
#define CT_DECOMPILED_PROOF_LIMIT 65536

typedef struct ct_decompiled_proof_header {
  uint64_t function_offset;
  /* Zero denotes an ELF/DWARF byte proof with no decompiler information. */
  uint32_t loaded_level;
  uint32_t range_count;
  uint32_t instruction_count;
  char code_identity[65];
} ct_decompiled_proof_header;

typedef struct ct_decompiled_range {
  uint64_t begin, end;
} ct_decompiled_range;

bool ct_analysis_code_proof(ct_analysis *analysis, uint64_t module_offset,
                            unsigned char **data, size_t *size);
bool ct_analysis_decompile_proof(ct_analysis *analysis, uint64_t module_offset,
                                 uint32_t level, unsigned char **data,
                                 size_t *size);
bool ct_analysis_decompile_display(ct_analysis *analysis,
                                   uint64_t module_offset, uint32_t level,
                                   ct_decompiled_display *display);
bool ct_analysis_decompile(ct_analysis *analysis, uint64_t module_offset,
                           uint32_t level, ct_decompiled_statement *statement);
bool ct_analysis_decompile_variables(ct_analysis *analysis,
                                     uint64_t module_offset, uint32_t level,
                                     ct_decompiled_variables *variables);
const char *ct_analysis_decompile_error(ct_analysis *analysis);

typedef enum {
  CT_EXPRESSION_NONE,
  CT_EXPRESSION_ASSIGNMENT,
  CT_EXPRESSION_CALL,
  CT_EXPRESSION_RETURN,
  CT_EXPRESSION_UPDATE
} ct_expression_kind;

typedef enum {
  CT_SOURCE_BLOCK_COMPOUND,
  CT_SOURCE_BLOCK_STATEMENT_EXPRESSION,
  CT_SOURCE_BLOCK_CONTROL
} ct_source_block_kind;

/* Lexical boundaries, never evidence on their own that an instruction ran.
 * Brace coordinates are one-based positions in the original source. Text and
 * highlighting offsets use the same leading-space-stripped spelling as
 * ct_location.text. Variable names are NUL-separated, in source order. */
typedef struct ct_source_block {
  uint64_t id;
  uint64_t start_line;
  uint64_t opening_line;
  uint64_t opening_column;
  uint64_t first_body_line;
  uint64_t closing_line;
  uint64_t closing_column;
  /* Loop statement extent includes its header and trailing do/while condition.
   * The end is exclusive; a zero end line identifies a non-loop block. */
  uint64_t loop_start_column;
  uint64_t loop_end_line;
  uint64_t loop_end_column;
  /* Retention-only envelope for reordered instructions, relative to module
   * start. It must never be used to infer that a block was entered. */
  uint64_t begin_offset;
  uint64_t end_offset;
  bool has_address_range;
  ct_source_block_kind kind;
  bool has_for_initializer;
  bool opening_standalone;
  bool closing_standalone;
  uint32_t opening_highlight_begin;
  uint32_t opening_highlight_end;
  uint32_t closing_highlight_begin;
  uint32_t closing_highlight_end;
  char opening[512];
  /* Complete normalized header through the opening brace, including an
   * Allman-style control header or statement-expression assignment. */
  char opening_context[2048];
  char closing[256];
  char assignment[256];
  char variables[512];
  uint32_t variables_size;
} ct_source_block;

/* Verified lexical blocks whose closing braces occur in this source row,
 * ordered by closing-token position. Function bodies are included. */
typedef struct ct_source_closure {
  uint64_t id;
  char opening[2048];
  bool function_body;
} ct_source_closure;

typedef struct ct_source_highlight {
  uint32_t begin;
  uint32_t end;
} ct_source_highlight;

/* Verified source labels associated with the current instruction's lexical
 * case group. Stacked labels share group_id. A zero group_id marks a proven
 * switch dispatch position and starts a new dynamic selection. */
typedef struct ct_source_case {
  uint64_t switch_id;
  uint64_t group_id;
  uint64_t id;
  uint64_t line;
  char text[512];
} ct_source_case;

typedef struct ct_macro_call {
  uint32_t callee_offset;
  /* Optional function-address value span in the original expansion text.
   * An empty span means no identity annotation is present. */
  uint32_t address_begin;
  uint32_t address_end;
  /* Only a direct function identity authorizes runtime resolution.
   * Non-static member pointers are not plain code addresses. */
  bool runtime_address;
} ct_macro_call;

typedef struct ct_source_macro {
  /* SHA-256 of the definition name, file, offset and replacement spelling.
   * Repeated invocations across source locations/modules share this identity.
   */
  char identity[65];
  char text[8192];
  /* Every source call occurrence remains in text, including builtins and
   * inlined functions without a callable runtime address. Symbol names are
   * NUL-separated; value spans refer to the original text even after other
   * addresses have been rendered. */
  char callees[4096];
  uint32_t callees_size;
  ct_macro_call calls[16];
  uint32_t call_count;
} ct_source_macro;

/* A verified source declaration may type a callee that has no DWARF. Fixed
 * scalar parameters are kept in ABI order, including unnamed slots. These
 * contracts never describe variadic arguments or authorize guessing types. */
typedef struct ct_call_parameter {
  char name[64];
  char type_name[192];
  ct_value_type type;
} ct_call_parameter;

typedef struct ct_source_call {
  char callee[1024];
  /* Verified ordinary declaration, without a body or trailing semicolon. */
  char declaration[2048];
  uint32_t parameter_begin;
  uint32_t parameter_count;
  bool variadic;
} ct_source_call;

/* Original call expressions for a single verified source row. Columns are
 * one-based byte columns in the untrimmed source, with an exclusive end.
 * Repeated calls retain separate identities; AST order is not runtime order.
 */
typedef struct ct_source_call_result {
  uint64_t id;
  char callee[1024];
  /* Source-visible name in the callee's current scope, without qualifiers. */
  char display_name[512];
  char text[2048];
  ct_value_type return_type;
  uint32_t begin_column;
  uint32_t end_column;
} ct_source_call_result;

typedef struct ct_location {
  char file[4096];
  char function[512];
  char symbol[1024];
  char qualified_function[1024];
  /* Complete NUL-terminated raw ELF alias names; no enclosing inline aliases.
   */
  char aliases[4096];
  uint32_t aliases_size;
  /* Raw linkage names from the physical function to the innermost inline
   * scope, NUL-separated. An unnamed scope contributes an empty entry. */
  char scope_chain[4096];
  uint32_t scope_chain_size;
  /* ELF aliases of the enclosing physical function, also at inline PCs. */
  char physical_aliases[4096];
  uint32_t physical_aliases_size;
  char text[4096];
  /* Whole function signature on a source-only prologue line. The client uses
   * its first line for entry display; statement lines retain their own text. */
  char declaration[4096];
  uint64_t declaration_line;
  /* An optimized entry instruction may map directly to a body statement.
   * Preserve that instruction's normal text while exposing its signature. */
  char entry_declaration[4096];
  uint64_t entry_declaration_line;
  char conversion_error[256];
  /* Verified source spelling only; values always come from runtime events.
   * UPDATE includes compound assignment/postfix operations, whose expression
   * value must not be confused with the destination's post-write value. */
  ct_expression_kind expression_kind;
  char expression[2048];
  char assignment[512];
  char expression_callee[1024];
  bool expression_is_call;
  /* Available only for a proven direct source call using the SysV x86-64
   * scalar ABI. Unknown types never authorize guessing a return register. */
  ct_value_type expression_return_type;
  /* NUL-separated variable names in first-occurrence order on this source
   * line, including declaration identifiers; no guessed or macro names. */
  char source_variables[4096];
  uint32_t source_variables_size;
  /* NUL-separated names explicitly declared in the displayed source row.
   * These are AST declarations, not uses or names hidden in a macro. */
  char source_declarations[4096];
  uint32_t source_declarations_size;
  uint64_t line;
  /* Outermost to innermost, scoped to the current physical/inline function.
   * An over-capacity chain is omitted in full rather than truncated. */
  ct_source_block source_blocks[8];
  uint32_t source_block_count;
  ct_source_closure source_closures[8];
  uint32_t source_closure_count;
  ct_source_highlight source_highlights[32];
  uint32_t source_highlight_count;
  ct_source_case source_cases[16];
  uint32_t source_case_count;
  bool source_case_label_only;
  /* Source macro function identities, independent of return eligibility. */
  ct_source_macro source_macros[4];
  uint32_t source_macro_count;
  /* Unique, consistent source call declarations in the displayed scope.
   * Only validated SysV x86-64 scalar contracts are included. */
  ct_source_call source_calls[16];
  uint32_t source_call_count;
  ct_call_parameter call_parameters[64];
  uint32_t call_parameter_count;
  ct_source_call_result source_call_results[16];
  uint32_t source_call_result_count;
  uint64_t source_id;
  uint64_t function_id;
  uint32_t column;
  uint32_t discriminator;
  bool has_line;
  bool source_verified;
  bool source_usable;
  bool structural;
  bool inlined;
  /* Executable ELF linkage section, identified independently of DWARF. */
  bool is_plt;
  /* Relocation symbol at this PLT entry, without the display-only @plt suffix.
   * Kept separate from function symbols so linkage stubs do not match filters.
   */
  char plt_symbol[1024];
} ct_location;

/* maps is the already validated comma-separated OLD=NEW option. */
ct_analysis *ct_analysis_open(const char *path, const char *maps);
/* Read the borrowed module descriptor; PATH remains its display/source lookup
 * identity. A missing descriptor never falls back to a different namespace's
 * file with the same pathname. The helper retains its own descriptor. */
ct_analysis *ct_analysis_open_fd(const char *path, const char *maps,
                                 int descriptor);
/* A previously captured selection, including companions that were absent.
 * All descriptors are borrowed sealed snapshots. Paths retain their original
 * display/cache identity and must never be used to rediscover these files. */
typedef struct ct_analysis_file_bundle {
  int module_file;
  int debug_file;
  int supplement_file;
  const char *debug_path;
  const char *supplement_path;
  const char *identity;
  int64_t debug_bias_correction;
} ct_analysis_file_bundle;
ct_analysis *ct_analysis_open_bundle(const char *path, const char *maps,
                                     const ct_analysis_file_bundle *bundle);
/* Borrowed descriptors remain valid until analysis_close. They identify the
 * exact module and verified debug companion, even after mount/path changes. */
int ct_analysis_module_file(ct_analysis *analysis);
int ct_analysis_debug_file_descriptor(ct_analysis *analysis);
/* Verified GNU supplementary DWARF, or -1 when it is not present/available. */
int ct_analysis_supplement_file_descriptor(ct_analysis *analysis);
const char *ct_analysis_supplement_file(ct_analysis *analysis);
/* Difference between DWARF and main-ELF load biases, including prelink undo.
 * Add this to the main ELF bias when evaluating the shared debug snapshot. */
int64_t ct_analysis_debug_bias_correction(ct_analysis *analysis);
/* module_offset is PC minus DynamoRIO's module.start, also for non-PIE ELF. */
void ct_analysis_lookup(ct_analysis *analysis, uint64_t module_offset,
                        ct_location *location);
/* Symbol, aliases, scopes and source position for entry gates and diagnostics.
 * Does not parse source bodies or populate detailed source/value fields. */
void ct_analysis_lookup_arming(ct_analysis *analysis, uint64_t module_offset,
                               ct_location *location);
/* Bounded initial-preparation lookup. OFFSETS are ordered and unique. The
 * validated packed response covers a nonempty prefix and belongs to the caller
 * (free()). No partially received or invalid response is exposed. Dynamic
 * single-PC lookups retain the interfaces above. */
bool ct_analysis_lookup_batch(ct_analysis *analysis, const uint64_t *offsets,
                              size_t count, bool arming, unsigned char **data,
                              size_t *size);
bool ct_analysis_has_dwarf(ct_analysis *analysis);
/* Helper-verified debug object path, or an empty string when absent. */
const char *ct_analysis_debug_file(ct_analysis *analysis);
/* ELF SONAME, falling back to the module basename. */
const char *ct_analysis_soname(ct_analysis *analysis);
/* Content identity of the module and any resolved external debug object. */
const char *ct_analysis_identity(ct_analysis *analysis);
/* Recheck cached locations after another module quarantines a shared prefix. */
bool ct_analysis_source_allowed(ct_analysis *analysis, uint64_t source_id);
/* NULL means all known referenced source files passed verification. */
const char *ct_analysis_source_error(ct_analysis *analysis);
void ct_analysis_functions(ct_analysis *analysis,
                           void (*callback)(uint64_t module_offset,
                                            const char *name, void *context),
                           void *context);
/* Actual half-open ranges of named inline scopes, without source analysis.
 * Each range is reported separately; gaps between ranges stay excluded. */
void ct_analysis_inline_scopes(ct_analysis *analysis,
                               void (*callback)(uint64_t begin_offset,
                                                uint64_t end_offset,
                                                const char *linkage_name,
                                                void *context),
                               void *context);
/* Conservative observation points: readable-source line-row transitions and
 * every named inline-scope endpoint. Uses the module's cached line/inline
 * catalogs, without preparing per-instruction source or variable metadata.
 * Returns false when the catalog cannot be supplied completely. */
bool ct_analysis_observation_boundaries(ct_analysis *analysis,
                                        void (*callback)(uint64_t module_offset,
                                                         void *context),
                                        void *context);
enum { CT_FLOW_ENTRY = 1, CT_FLOW_EXIT = 2 };
enum { CT_FLOW_IF = 1, CT_FLOW_LOOP = 2 };
typedef struct ct_flow_region {
  uint64_t branch_offset;
  uint64_t taken_offset;
  uint64_t fallthrough_offset;
  uint64_t join_offset;
  uint64_t loop_header_offset;
  uint32_t kind;
  bool taken_is_body;
  uint64_t update_offset;
  bool has_update;
  uint64_t initializer_offset;
  bool has_initializer;
  ct_initializer_source initializer_source;
} ct_flow_region;
enum { CT_FLOW_SWITCH_CASE_LIMIT = 256 };
typedef struct ct_flow_case {
  int64_t value;
  uint64_t target_offset;
} ct_flow_case;
typedef struct ct_flow_switch {
  uint64_t guard_offset;
  uint64_t dispatch_offset;
  uint64_t selector_offset;
  uint64_t join_offset;
  uint64_t default_offset;
  char selector_register[16];
  uint32_t case_count;
  ct_flow_case cases[CT_FLOW_SWITCH_CASE_LIMIT];
} ct_flow_switch;
typedef struct ct_flow_range {
  uint64_t begin_offset;
  uint64_t end_offset;
  bool complete;
  bool bounded;
} ct_flow_range;
enum {
  CT_FLOW_GRAPH_INSTRUCTION_LIMIT = 4096,
  CT_FLOW_GRAPH_EDGE_LIMIT =
      CT_FLOW_GRAPH_INSTRUCTION_LIMIT * CT_FLOW_SWITCH_CASE_LIMIT
};
enum {
  CT_FLOW_CALL = 1,
  CT_FLOW_RETURN = 2,
  CT_FLOW_BRANCH = 4,
  CT_FLOW_CONDITIONAL = 8,
  CT_FLOW_SYSCALL = 16,
  CT_FLOW_INDIRECT = 32,
  CT_FLOW_FRONTIER = 64
};
typedef struct ct_flow_instruction {
  uint64_t offset;
  uint32_t flags;
  uint8_t size;
  unsigned char bytes[15];
} ct_flow_instruction;
typedef struct ct_flow_edge {
  uint64_t from_offset;
  uint64_t to_offset;
} ct_flow_edge;
/* Reachable instructions of the containing machine function, ordered by PC.
 * Edges preserve known destinations even outside this response's instruction
 * set; only an unknown destination is UINT64_MAX. CALL has only its fallthrough
 * edge: callees are never traversed. Known in-function frontiers can be
 * supplied as module_offset in another request to continue beyond the per-reply
 * limit. RETURN has no successor. Flags identify boundaries at branches, calls,
 * returns and syscalls; ordinary fallthrough edges remain available too.
 * Offsets are module-relative. Unknown/undecoded successors set FRONTIER and
 * clear range.complete. range.bounded has the same meaning as ct_analysis_flow;
 * complete describes this reply's reachable graph, not all function entries.
 * All records are validated before any callback. Pointers are callback-local.
 * A valid partial graph can be returned; callers must not call its frontier
 * prepared, and must revalidate the current code generation and original bytes.
 */
bool ct_analysis_code_graph(
    ct_analysis *analysis, uint64_t module_offset, ct_flow_range *range,
    void (*instruction_callback)(const ct_flow_instruction *, void *),
    void (*edge_callback)(const ct_flow_edge *, void *), void *context);
/* Analyze a containing machine function, or use the observed entry when its
 * bounds are unavailable. Roles describe destination PCs, never source lines.
 * Boundaries in the same control region share a representative group offset.
 * Structured regions require a complete graph and a real postdominating join.
 * LOOP describes a proven pretest guard, not an original source-language loop.
 * has_update identifies an unconditional iteration-tail update of a guard
 * operand; update_offset is valid only when this proof succeeds.
 * has_initializer identifies an immediate store to that same storage on the
 * unique preheader path. Only no-ops, jumps and independent immediate GPR
 * moves may precede the first guard. initializer_source carries helper-side
 * DWARF line coordinates; a split or unidentified CU leaves it invalid.
 * initializer_offset is valid only when this proof succeeds.
 * All callbacks are optional; region offsets are relative to the module.
 * Switches require a proven unsigned bound, immutable jump table and real
 * common join. Case values address the compared, possibly normalized index.
 */
bool ct_analysis_flow(
    ct_analysis *analysis, uint64_t module_offset, ct_flow_range *range,
    void (*callback)(uint64_t module_offset, uint32_t roles,
                     uint64_t group_offset, void *context),
    void (*region_callback)(const ct_flow_region *region, void *context),
    void (*switch_callback)(const ct_flow_switch *region, void *context),
    void *context);
void ct_analysis_close(ct_analysis *analysis);

#ifdef __cplusplus
}
#endif

#endif
