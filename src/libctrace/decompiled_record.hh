// SPDX-License-Identifier: MIT

#ifndef CTRACE_DECOMPILED_RECORD_H
#define CTRACE_DECOMPILED_RECORD_H

#include <algorithm>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "analysis.hh"
#include "location_record.hh"

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
        instruction_count(uint32_t(std::min(source.instructions.size(),
                                            size_t(source.instruction_count)))),
        instruction_index(source.instruction_index), text(source.text.c_str()),
        declaration_id(source.declaration_id),
        declaration_name(source.declaration_name.c_str()),
        declaration_type(source.declaration_type.c_str()),
        instructions(source.instructions.data(), instruction_count) {}
};

struct ct_decompiled_statement_data;

// Each Site owns only its instruction index and a view of immutable statement
// data. The module cache and live Sites jointly retain that data; replacing a
// cache entry never changes an observation already in progress.
class ct_decompiled_statement_record final
    : public ct_decompiled_statement_view {
  std::shared_ptr<const ct_decompiled_statement_data> owner_;

  ct_decompiled_statement_record(
      std::shared_ptr<const ct_decompiled_statement_data> owner,
      uint32_t instruction_index);
  friend class ct_decompiled_statement_cache;

public:
  ct_decompiled_statement_record(const ct_decompiled_statement_record &) =
      delete;
  ct_decompiled_statement_record &
  operator=(const ct_decompiled_statement_record &) = delete;
};

// Accessed during preparation under the module's analysis lock, never during
// event collection. Generation changes discard only the preparation index.
class ct_decompiled_statement_cache final {
  uint64_t generation_ = 0;
  std::map<std::pair<uint64_t, uint64_t>,
           std::shared_ptr<const ct_decompiled_statement_data>>
      statements_;

public:
  std::unique_ptr<const ct_decompiled_statement_record>
  publish(const ct_decompiled_statement &source, uint64_t generation);
  void clear();
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
  bool exception_boundary{};
  uint32_t exception_count{};
  ct_location_array<ct_decompiled_exception> exceptions;
  ct_decompiled_display_view() = default;
  ct_decompiled_display_view(const ct_decompiled_display &source)
      : function_offset(source.function_offset),
        loaded_level(source.loaded_level),
        function_name(source.function_name.c_str()),
        prototype(source.prototype.c_str()), instruction(source.instruction),
        control_text(source.control_text.c_str()),
        control_kind(source.control_kind.c_str()),
        control_initializer(source.control_initializer.c_str()),
        control_update(source.control_update.c_str()),
        control_conditional(source.control_conditional),
        control_has_target(source.control_has_target),
        control_target(source.control_target),
        exception_boundary(source.exception_boundary),
        exception_count(uint32_t(std::min(source.exceptions.size(),
                                          size_t(source.exception_count)))),
        exceptions(source.exceptions.data(), exception_count) {}
};

class ct_decompiled_display_record final : public ct_decompiled_display_view {
  std::vector<char> strings_;
  std::vector<ct_decompiled_exception> exceptions_;

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
        return_type_name(source.return_type_name.c_str()),
        return_register(source.return_register.c_str()),
        parameters_known(source.parameters_known), variadic(source.variadic),
        parameter_count(uint32_t(std::min(source.parameters.size(),
                                          size_t(source.parameter_count)))),
        parameters(source.parameters.data(), parameter_count),
        count(uint32_t(std::min(source.entries.size(), size_t(source.count)))),
        entries(source.entries.data(), count),
        type_count(
            uint32_t(std::min(source.types.size(), size_t(source.type_count)))),
        types(source.types.data(), type_count),
        member_count(uint32_t(
            std::min(source.members.size(), size_t(source.member_count)))),
        members(source.members.data(), member_count) {}
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
