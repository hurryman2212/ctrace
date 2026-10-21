// SPDX-License-Identifier: MIT

#include <cstring>
#include <vector>

#include "decompiled_record.hh"

struct ct_decompiled_statement_data final : ct_decompiled_statement_view {
  std::vector<char> strings;
  std::vector<ct_decompiled_instruction> code;

  explicit ct_decompiled_statement_data(const ct_decompiled_statement &source)
      : ct_decompiled_statement_view(source), code(source.instructions) {
    // The position belongs to a Site, not to the shared logical statement.
    instruction_index = 0;
    strings.reserve(source.text.size() + source.declaration_name.size() +
                    source.declaration_type.size() + 3);
    for (const auto *value :
         {&source.text, &source.declaration_name, &source.declaration_type}) {
      strings.insert(strings.end(), value->begin(), value->end());
      strings.push_back(0);
    }
    text = strings.data();
    declaration_name = text + source.text.size() + 1;
    declaration_type = declaration_name + source.declaration_name.size() + 1;
    instructions = {code.data(), code.size()};
  }
};

ct_decompiled_statement_record::ct_decompiled_statement_record(
    std::shared_ptr<const ct_decompiled_statement_data> owner, uint32_t index)
    : ct_decompiled_statement_view(*owner), owner_(std::move(owner)) {
  instruction_index = index;
}

std::unique_ptr<const ct_decompiled_statement_record>
ct_decompiled_statement_cache::publish(const ct_decompiled_statement &source,
                                       uint64_t generation) {
  if (generation_ != generation) {
    clear();
    generation_ = generation;
  }
  if (!source.instruction_count ||
      source.instruction_count != source.instructions.size() ||
      source.instruction_index >= source.instruction_count)
    return nullptr;
  const auto key = std::make_pair(source.function_offset, source.id);
  // A single-instruction statement cannot be shared by different instruction
  // Sites. Keep its immutable owner only in the Site, without a cache node.
  if (source.instruction_count == 1) {
    statements_.erase(key);
    return std::unique_ptr<const ct_decompiled_statement_record>(
        new ct_decompiled_statement_record(
            std::make_shared<ct_decompiled_statement_data>(source), 0));
  }
  auto &known = statements_[key];
  const bool same =
      known && known->text == source.text &&
      known->declaration_id == source.declaration_id &&
      known->declaration_name == source.declaration_name &&
      known->declaration_type == source.declaration_type &&
      known->instructions.size() == source.instructions.size() &&
      std::equal(
          known->instructions.begin(), known->instructions.end(),
          source.instructions.begin(), [](const auto &left, const auto &right) {
            return left.offset == right.offset && left.size == right.size &&
                   !std::memcmp(left.bytes, right.bytes, sizeof(left.bytes));
          });
  if (!same)
    known = std::make_shared<ct_decompiled_statement_data>(source);
  return std::unique_ptr<const ct_decompiled_statement_record>(
      new ct_decompiled_statement_record(known, source.instruction_index));
}

void ct_decompiled_statement_cache::clear() {
  statements_.clear();
  generation_ = 0;
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
  exceptions_.assign(source.exceptions.begin(),
                     source.exceptions.begin() + exception_count);
  exceptions = {exceptions_.data(), exceptions_.size()};
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
  parameters_.assign(source.parameters.begin(),
                     source.parameters.begin() + parameter_count);
  parameters = {parameters_.data(), parameters_.size()};
  entries_.assign(source.entries.begin(), source.entries.begin() + count);
  entries = {entries_.data(), entries_.size()};
  types_.assign(source.types.begin(), source.types.begin() + type_count);
  types = {types_.data(), types_.size()};
  members_.assign(source.members.begin(),
                  source.members.begin() + member_count);
  members = {members_.data(), members_.size()};
}
