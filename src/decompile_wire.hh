// SPDX-License-Identifier: MIT

#ifndef CTRACE_DECOMPILE_WIRE_HH
#define CTRACE_DECOMPILE_WIRE_HH

#include <cstring>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "analysis.hh"

// Private same-build IPC: pointers and container internals never cross it.
// Variable-length fields are bounded by their actual packet, not a work quota.
class ct_decompile_wire {
  std::vector<unsigned char> *output = nullptr;
  std::span<const unsigned char> input;
  size_t position = 0;
  bool valid = true;

public:
  explicit ct_decompile_wire(std::vector<unsigned char> &bytes)
      : output(&bytes) {
    bytes.clear();
  }
  explicit ct_decompile_wire(std::span<const unsigned char> bytes)
      : input(bytes) {}

  template <typename T> void field(T &value) {
    static_assert(std::is_trivially_copyable_v<T>);
    if (!valid)
      return;
    if constexpr (std::is_enum_v<T>) {
      using Integer = std::underlying_type_t<T>;
      Integer number = output ? static_cast<Integer>(value) : 0;
      field(number);
      if constexpr (std::is_same_v<T, ct_value_kind>)
        valid =
            valid && number >= CT_VALUE_UNKNOWN && number <= CT_VALUE_POINTER;
      else if constexpr (std::is_same_v<T, ct_value_layout_kind>)
        valid =
            valid && number >= CT_LAYOUT_UNKNOWN && number <= CT_LAYOUT_UNION;
      else if constexpr (std::is_same_v<T, ct_decompiled_storage>)
        valid = valid && number >= CT_DECOMPILED_STACK &&
                number <= CT_DECOMPILED_REGISTER;
      if (valid && !output)
        value = static_cast<T>(number);
      return;
    }
    if (output) {
      if (sizeof(value) > output->max_size() - output->size()) {
        valid = false;
        return;
      }
      const auto *bytes = reinterpret_cast<const unsigned char *>(&value);
      output->insert(output->end(), bytes, bytes + sizeof(value));
    } else if (sizeof(value) <= input.size() - position) {
      std::memcpy(&value, input.data() + position, sizeof(value));
      position += sizeof(value);
    } else {
      valid = false;
    }
  }

  void field(bool &value) {
    uint8_t number = output ? uint8_t(value) : 0;
    field(number);
    valid = valid && number <= 1;
    if (valid && !output)
      value = number != 0;
  }

  void field(ct_value_type &v) {
    field(v.kind);
    field(v.bytes);
  }
  void field(ct_value_layout_node &v) {
    field(v.kind);
    field(v.scalar);
    field(v.bytes);
    field(v.element_type);
    field(v.element_count);
    field(v.element_stride);
    field(v.first_member);
    field(v.member_count);
    field(v.complete);
    field(v.guarded);
  }
  void field(ct_value_layout_member &v) {
    field(v.name);
    field(v.type);
    field(v.offset);
    field(v.available);
  }
  void field(ct_decompiled_instruction &v) {
    field(v.offset);
    field(v.size);
    field(v.bytes);
  }

  void field(std::string &value) {
    uint64_t length = value.size();
    field(length);
    if (!valid)
      return;
    if (output) {
      if (value.find('\0') != std::string::npos ||
          length > output->max_size() - output->size()) {
        valid = false;
        return;
      }
      output->insert(output->end(), value.begin(), value.end());
    } else if (length <= input.size() - position &&
               length <= value.max_size()) {
      value.assign(reinterpret_cast<const char *>(input.data() + position),
                   size_t(length));
      position += size_t(length);
      valid = value.find('\0') == std::string::npos;
    } else {
      valid = false;
    }
  }

  template <typename T> void field(std::vector<T> &values) {
    uint64_t count = values.size();
    field(count);
    if (!valid)
      return;
    if (!output) {
      // Every encoded element below occupies at least one byte. Build only
      // elements actually decoded, never reserve an untrusted count first.
      values.clear();
      if (count > input.size() - position || count > values.max_size()) {
        valid = false;
        return;
      }
      for (uint64_t index = 0; valid && index < count; ++index) {
        T value{};
        field(value);
        if (valid)
          values.push_back(std::move(value));
      }
    } else {
      for (auto &value : values)
        field(value);
    }
  }

  void field(ct_decompiled_variable &v) {
    field(v.id);
    field(v.offset);
    field(v.stack_offset);
    field(v.size);
    field(v.kind);
    field(v.access);
    field(v.register_alias);
    field(v.name);
    field(v.type_name);
    field(v.register_name);
    field(v.type);
    field(v.type_id);
  }
  void field(ct_decompiled_parameter &v) {
    field(v.stack_offset);
    field(v.size);
    field(v.kind);
    field(v.name);
    field(v.type_name);
    field(v.register_name);
    field(v.type);
  }
  void field(ct_decompiled_exception &v) {
    field(v.id);
    field(v.entry);
    field(v.selector_value);
    field(v.kind);
    field(v.selector_register);
    field(v.selector_bytes);
    field(v.text);
  }
  void field(ct_decompiled_statement &v) {
    field(v.id);
    field(v.function_offset);
    field(v.instruction_count);
    field(v.instruction_index);
    field(v.text);
    field(v.declaration_id);
    field(v.declaration_name);
    field(v.declaration_type);
    field(v.instructions);
    valid = valid && v.instruction_count == v.instructions.size();
  }
  void field(ct_decompiled_variables &v) {
    field(v.function_offset);
    field(v.instruction);
    field(v.return_known);
    field(v.return_void);
    field(v.return_unsupported);
    field(v.return_type);
    field(v.return_type_name);
    field(v.return_register);
    field(v.parameters_known);
    field(v.variadic);
    field(v.parameter_count);
    field(v.parameters);
    field(v.count);
    field(v.entries);
    field(v.type_count);
    field(v.types);
    field(v.member_count);
    field(v.members);
    valid = valid && v.parameter_count == v.parameters.size() &&
            v.count == v.entries.size() && v.type_count == v.types.size() &&
            v.member_count == v.members.size();
  }
  void field(ct_decompiled_display &v) {
    field(v.function_offset);
    field(v.loaded_level);
    field(v.function_name);
    field(v.prototype);
    field(v.instruction);
    field(v.control_text);
    field(v.control_kind);
    field(v.control_initializer);
    field(v.control_update);
    field(v.control_conditional);
    field(v.control_has_target);
    field(v.control_target);
    field(v.exception_boundary);
    field(v.exception_count);
    field(v.exceptions);
    valid = valid && v.exception_count == v.exceptions.size();
  }

  bool complete() const {
    return valid && (output || position == input.size());
  }
};

#endif
