#include <cstring>
#include <vector>

#include "decompiled_record.h"

ct_decompiled_statement_record::ct_decompiled_statement_record(
    const ct_decompiled_statement &source)
    : ct_decompiled_statement_view(source) {
  const size_t sizes[] = {
      std::strlen(text),
      std::strlen(declaration_name),
      std::strlen(declaration_type),
  };
  size_t total = 0;
  for (size_t size : sizes)
    total += size + 1;
  strings_.resize(total);
  char *next = strings_.data();
  size_t index = 0;
  const auto copy = [&](const char *value) {
    const size_t size = sizes[index++];
    char *result = next;
    std::memcpy(next, value, size);
    next[size] = 0;
    next += size + 1;
    return result;
  };
  text = copy(text);
  declaration_name = copy(declaration_name);
  declaration_type = copy(declaration_type);
  instructions_.assign(source.instructions,
                       source.instructions + instruction_count);
  instructions = {instructions_.data(), instructions_.size()};
}

ct_decompiled_display_record::ct_decompiled_display_record(
    const ct_decompiled_display &source)
    : ct_decompiled_display_view(source) {
  const size_t sizes[] = {
      std::strlen(function_name),       std::strlen(prototype),
      std::strlen(control_text),        std::strlen(control_kind),
      std::strlen(control_initializer), std::strlen(control_update),
  };
  size_t total = 0;
  for (size_t size : sizes)
    total += size + 1;
  strings_.resize(total);
  char *next = strings_.data();
  size_t index = 0;
  const auto copy = [&](const char *value) {
    const size_t size = sizes[index++];
    char *result = next;
    std::memcpy(next, value, size);
    next[size] = 0;
    next += size + 1;
    return result;
  };
  function_name = copy(function_name);
  prototype = copy(prototype);
  control_text = copy(control_text);
  control_kind = copy(control_kind);
  control_initializer = copy(control_initializer);
  control_update = copy(control_update);
}

ct_decompiled_variables_record::ct_decompiled_variables_record(
    const ct_decompiled_variables &source)
    : ct_decompiled_variables_view(source) {
  const size_t sizes[] = {
      std::strlen(return_type_name),
      std::strlen(return_register),
  };
  size_t total = 0;
  for (size_t size : sizes)
    total += size + 1;
  strings_.resize(total);
  char *next = strings_.data();
  size_t index = 0;
  const auto copy = [&](const char *value) {
    const size_t size = sizes[index++];
    char *result = next;
    std::memcpy(next, value, size);
    next[size] = 0;
    next += size + 1;
    return result;
  };
  return_type_name = copy(return_type_name);
  return_register = copy(return_register);
  parameters_.assign(source.parameters, source.parameters + parameter_count);
  parameters = {parameters_.data(), parameters_.size()};
  entries_.assign(source.entries, source.entries + count);
  entries = {entries_.data(), entries_.size()};
  types_.assign(source.types, source.types + type_count);
  types = {types_.data(), types_.size()};
  members_.assign(source.members, source.members + member_count);
  members = {members_.data(), members_.size()};
}
