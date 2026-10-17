#ifndef CTRACE_SOURCE_ASM_H
#define CTRACE_SOURCE_ASM_H

#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "analysis.h"

struct ct_source_expression {
  ct_expression_kind kind = CT_EXPRESSION_NONE;
  std::string text, assignment, callee, function;
  bool is_call = false;
  bool macro_result = false;
  ct_value_type return_type = {};
  size_t begin = 0, end = 0;
};

struct ct_source_variable {
  size_t offset;
  std::string name, function;
  bool declaration = false;
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
