// SPDX-License-Identifier: MIT

#ifndef CTRACE_DECOMPILE_RECORD_H
#define CTRACE_DECOMPILE_RECORD_H

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "analysis.hh"

struct ct_decompile_exception {
  ct_decompiled_exception scope{};
  std::vector<ct_decompiled_range> ranges;
};

// Temporary producer representation. Published consumers use immutable views.
struct ct_decompile_record {
  uint64_t begin, end;
  uint64_t entry = 0;
  uint32_t level = 0;
  std::string name, prototype, identity;
  std::map<uint64_t, ct_decompiled_display> controls;
  std::vector<ct_decompile_exception> exceptions;
  std::vector<unsigned char> proof;
  bool return_known = false, return_void = false, return_unsupported = false;
  ct_value_type return_type{};
  std::string return_type_name;
  std::string return_register;
  bool parameters_known = false, variadic = false;
  std::vector<ct_decompiled_parameter> parameters;
  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  std::vector<ct_decompiled_statement> statements;
  std::map<uint64_t, std::pair<size_t, uint32_t>> instructions;
  std::map<uint64_t, ct_decompiled_instruction> original_instructions;
  std::vector<ct_decompiled_variable> variables;
  std::map<uint64_t, std::vector<ct_decompiled_variable>> scoped_variables;
  std::vector<ct_value_layout_node> types;
  std::vector<ct_value_layout_member> members;
};

/* Validate instruction coverage, consistent nesting, catch entry guards and
 * text; require outer-before-inner order, allowing exclusive catch
 * alternatives. Shared by JSON producers and immutable view readers. */
bool ct_decompile_exceptions_valid(
    const std::vector<ct_decompile_exception> &exceptions,
    const std::vector<ct_decompiled_instruction> &instructions);

#endif
