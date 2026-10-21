// SPDX-License-Identifier: MIT

#ifndef CTRACE_C_CPP_SOURCE_HH
#define CTRACE_C_CPP_SOURCE_HH

#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "analysis.hh"

enum ct_source_comparison_kind {
  CT_SOURCE_COMPARE_NONE,
  CT_SOURCE_COMPARE_EQ,
  CT_SOURCE_COMPARE_NE,
  CT_SOURCE_COMPARE_LT,
  CT_SOURCE_COMPARE_LE,
  CT_SOURCE_COMPARE_GT,
  CT_SOURCE_COMPARE_GE,
};

struct ct_source_comparison {
  ct_source_comparison_kind kind = CT_SOURCE_COMPARE_NONE;
  std::string variable;
  // The variable's original type, followed by casts in evaluation order.
  // The last type is the common type of both comparison operands.
  std::vector<ct_value_type> types;
  uint64_t constant = 0;
};

struct ct_source_expression {
  ct_expression_kind kind = CT_EXPRESSION_NONE;
  std::string text, assignment, callee, function;
  // File-scope constant-array destination, when the AST proves direct indexing.
  std::string assignment_object;
  ct_value_type assignment_type = {};
  bool is_call = false;
  bool macro_result = false;
  bool constant = false;
  uint64_t constant_value = 0;
  ct_value_type constant_type = {};
  // Exact scalar lvalue read, with no casts, indexing or pointer chasing.
  std::string read_path;
  ct_value_type value_type = {};
  ct_value_type return_type = {};
  // Every built-in scalar conversion of a returned direct call, in evaluation
  // order. The call's ABI return_type remains its original declared type.
  std::vector<ct_value_type> result_casts;
  ct_source_comparison comparison;
  size_t begin = 0, end = 0;
};

struct ct_source_variable {
  size_t offset;
  std::string name, function;
  bool declaration = false;
  // Verified access rooted at name; empty for a plain identifier/declaration.
  // Only built-in member, dereference, address and constant-index operations
  // are retained. The original spelling is never evaluated as arbitrary C.
  std::string access = {};
};

struct ct_source_declaration {
  std::string text, function;
  unsigned line = 0;
  std::vector<ct_source_variable> variables;
};

struct ct_source_block_info {
  ct_source_block block = {};
  std::string function;
  bool complete = true;
};

struct ct_source_macro_info {
  ct_source_macro macro = {};
  std::string function;
};

struct ct_source_call_info {
  std::string function, callee, declaration;
  std::vector<ct_call_parameter> parameters;
  bool variadic = false;
};

struct ct_source_call_result_info {
  ct_source_call_result result = {};
  std::string function;
  size_t begin = 0, end = 0;
  // This call's scalar value reaches the owning function's return without
  // intervening execution or a lossy conversion.
  bool return_forwarded = false;
  // Source-local variables passed directly to fixed arguments. Empty entries
  // denote other expressions; no bindings are supplied for side-effectful
  // argument lists whose evaluation could change an earlier input value.
  std::vector<std::string> argument_variables;
  // Direct nested-call results consumed as fixed arguments. Explicit casts,
  // compound expressions and indirect callees do not establish a binding.
  std::vector<std::string> argument_calls;
  // Direct addresses of non-TLS file-scope objects; empty for other operands.
  std::vector<std::string> argument_addresses;
};

struct ct_source_case_info {
  ct_source_case label = {};
  std::string function;
  unsigned begin_column = 0, end_column = 0;
  bool column_required = false;
  size_t begin = 0, end = 0;
  size_t display_begin = 0, display_end = 0;
};

struct ct_source_closure_info {
  ct_source_closure closure = {};
  std::string function;
  size_t offset = 0;
  size_t display_offset = 0;
};

struct ct_source_statement {
  std::string function, text;
  unsigned end_line = 0;
  size_t begin = 0, end = 0;
};

struct ct_source_asm_line {
  std::string text;
  std::string error;
  bool structural = false;
  ct_source_expression expression;
  std::vector<ct_source_variable> variables;
  ct_source_declaration declaration;
  std::vector<ct_source_block_info> blocks;
  std::vector<ct_source_highlight> highlights;
  std::vector<ct_source_macro_info> macros;
  std::vector<ct_source_case_info> cases;
  std::vector<ct_source_closure_info> closures;
  std::vector<ct_source_call_info> calls;
  std::vector<ct_source_call_result_info> call_results;
  // One complete AST statement, isolated from other statements on its rows.
  // Continuation rows retain their original coordinates in the source map.
  ct_source_statement statement;
};

struct ct_source_compile_context {
  std::string producer, directory, source;
  uint64_t language = 0;
  // Explicit semantic compiler flags, excluding executable/input/output.
  // An exact compilation-database command takes precedence; an inferred
  // command for a different file does not override these arguments.
  std::vector<std::string> arguments;
};

/* Source use has already passed the checksum policy, including explicit skip.
 * Expression descriptors require an unambiguous standalone source operation. */
std::map<unsigned, ct_source_asm_line>
ct_analyze_source(std::string_view source, const char *path, int syntax,
                  const char *module = nullptr,
                  std::string *cache_identity = nullptr,
                  const char *source_prefix = nullptr,
                  const ct_source_compile_context *compile_context = nullptr);

#endif
