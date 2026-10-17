#ifndef CTRACE_DECOMPILED_RECORD_H
#define CTRACE_DECOMPILED_RECORD_H

#include <vector>

#include "analysis.h"
#include "location_record.h"

// Protocol buffers are borrowed only for synchronous reads. Published client
// records own their active fields; no maximum-capacity IPC arrays stay
// resident.
struct ct_decompiled_statement_view {
  uint64_t id{};
  uint64_t function_offset{};
  uint32_t instruction_count{};
  uint32_t instruction_index{};
  const char *text = "";
  uint64_t declaration_id{};
  const char *declaration_name = "";
  const char *declaration_type = "";
  ct_location_array<ct_decompiled_instruction> instructions;
  ct_decompiled_statement_view() = default;
  ct_decompiled_statement_view(const ct_decompiled_statement &source)
      : id(source.id), function_offset(source.function_offset),
        instruction_count(
            ct_location_count(source.instructions, source.instruction_count)),
        instruction_index(source.instruction_index),
        text(ct_location_text(source.text)),
        declaration_id(source.declaration_id),
        declaration_name(ct_location_text(source.declaration_name)),
        declaration_type(ct_location_text(source.declaration_type)),
        instructions(source.instructions, instruction_count) {}
};

class ct_decompiled_statement_record final
    : public ct_decompiled_statement_view {
  std::vector<char> strings_;
  std::vector<ct_decompiled_instruction> instructions_;

public:
  explicit ct_decompiled_statement_record(
      const ct_decompiled_statement &source);
  ct_decompiled_statement_record(const ct_decompiled_statement_record &) =
      delete;
  ct_decompiled_statement_record &
  operator=(const ct_decompiled_statement_record &) = delete;
};

struct ct_decompiled_display_view {
  uint64_t function_offset{};
  uint32_t loaded_level{};
  const char *function_name = "";
  const char *prototype = "";
  ct_decompiled_instruction instruction{};
  const char *control_text = "";
  const char *control_kind = "";
  const char *control_initializer = "";
  const char *control_update = "";
  bool control_conditional{};
  bool control_has_target{};
  uint64_t control_target{};
  ct_decompiled_display_view() = default;
  ct_decompiled_display_view(const ct_decompiled_display &source)
      : function_offset(source.function_offset),
        loaded_level(source.loaded_level),
        function_name(ct_location_text(source.function_name)),
        prototype(ct_location_text(source.prototype)),
        instruction(source.instruction),
        control_text(ct_location_text(source.control_text)),
        control_kind(ct_location_text(source.control_kind)),
        control_initializer(ct_location_text(source.control_initializer)),
        control_update(ct_location_text(source.control_update)),
        control_conditional(source.control_conditional),
        control_has_target(source.control_has_target),
        control_target(source.control_target) {}
};

class ct_decompiled_display_record final : public ct_decompiled_display_view {
  std::vector<char> strings_;

public:
  explicit ct_decompiled_display_record(const ct_decompiled_display &source);
  ct_decompiled_display_record(const ct_decompiled_display_record &) = delete;
  ct_decompiled_display_record &
  operator=(const ct_decompiled_display_record &) = delete;
};

struct ct_decompiled_variables_view {
  uint64_t function_offset{};
  ct_decompiled_instruction instruction{};
  bool return_known{};
  bool return_void{};
  bool return_unsupported{};
  ct_value_type return_type{};
  const char *return_type_name = "";
  const char *return_register = "";
  bool parameters_known{};
  bool variadic{};
  uint32_t parameter_count{};
  ct_location_array<ct_decompiled_parameter> parameters;
  uint32_t count{};
  ct_location_array<ct_decompiled_variable> entries;
  uint32_t type_count{};
  ct_location_array<ct_value_layout_node> types;
  uint32_t member_count{};
  ct_location_array<ct_value_layout_member> members;
  ct_decompiled_variables_view() = default;
  ct_decompiled_variables_view(const ct_decompiled_variables &source)
      : function_offset(source.function_offset),
        instruction(source.instruction), return_known(source.return_known),
        return_void(source.return_void),
        return_unsupported(source.return_unsupported),
        return_type(source.return_type),
        return_type_name(ct_location_text(source.return_type_name)),
        return_register(ct_location_text(source.return_register)),
        parameters_known(source.parameters_known), variadic(source.variadic),
        parameter_count(
            ct_location_count(source.parameters, source.parameter_count)),
        parameters(source.parameters, parameter_count),
        count(ct_location_count(source.entries, source.count)),
        entries(source.entries, count),
        type_count(ct_location_count(source.types, source.type_count)),
        types(source.types, type_count),
        member_count(ct_location_count(source.members, source.member_count)),
        members(source.members, member_count) {}
};

class ct_decompiled_variables_record final
    : public ct_decompiled_variables_view {
  std::vector<char> strings_;
  std::vector<ct_decompiled_parameter> parameters_;
  std::vector<ct_decompiled_variable> entries_;
  std::vector<ct_value_layout_node> types_;
  std::vector<ct_value_layout_member> members_;

public:
  explicit ct_decompiled_variables_record(
      const ct_decompiled_variables &source);
  ct_decompiled_variables_record(const ct_decompiled_variables_record &) =
      delete;
  ct_decompiled_variables_record &
  operator=(const ct_decompiled_variables_record &) = delete;
};

#endif
