// SPDX-License-Identifier: MIT

#include <cstring>
#include <vector>

#include "location_record.hh"

ct_location_record::ct_location_record(const ct_location &source)
    : view(source) {
  // Compute the complete pool before exposing any pointers into it.
  const size_t sizes[] = {
      std::strlen(view.file),
      std::strlen(view.function),
      std::strlen(view.symbol),
      std::strlen(view.qualified_function),
      view.aliases_size,
      view.scope_chain_size,
      view.inline_files_size,
      view.physical_aliases_size,
      std::strlen(view.text),
      std::strlen(view.declaration),
      std::strlen(view.entry_declaration),
      std::strlen(view.conversion_error),
      std::strlen(view.expression),
      std::strlen(view.assignment),
      std::strlen(view.expression_callee),
      view.source_variables_size,
      view.source_declarations_size,
      std::strlen(view.plt_symbol),
  };
  size_t total = 0;
  for (size_t size : sizes)
    total += size + 1;
  strings_.resize(total);
  char *next = strings_.data();
  size_t index = 0;
  const auto copy = [&](const char *text) {
    const size_t size = sizes[index++];
    char *result = next;
    std::memcpy(next, text, size);
    next[size] = '\0';
    next += size + 1;
    return result;
  };
  view.file = copy(view.file);
  view.function = copy(view.function);
  view.symbol = copy(view.symbol);
  view.qualified_function = copy(view.qualified_function);
  view.aliases = copy(source.aliases);
  view.scope_chain = copy(source.scope_chain);
  view.inline_files = copy(source.inline_files);
  view.physical_aliases = copy(source.physical_aliases);
  view.text = copy(view.text);
  view.declaration = copy(view.declaration);
  view.entry_declaration = copy(view.entry_declaration);
  view.conversion_error = copy(view.conversion_error);
  view.expression = copy(view.expression);
  view.assignment = copy(view.assignment);
  view.expression_callee = copy(view.expression_callee);
  view.source_variables = copy(source.source_variables);
  view.source_declarations = copy(source.source_declarations);
  view.plt_symbol = copy(view.plt_symbol);
  inline_calls_.assign(source.inline_calls,
                       source.inline_calls + view.inline_calls.size());
  view.inline_calls = {inline_calls_.data(), inline_calls_.size()};
  source_blocks_.assign(source.source_blocks,
                        source.source_blocks + view.source_block_count);
  view.source_blocks = {source_blocks_.data(), source_blocks_.size()};
  source_closures_.assign(source.source_closures,
                          source.source_closures + view.source_closure_count);
  view.source_closures = {source_closures_.data(), source_closures_.size()};
  source_highlights_.assign(source.source_highlights,
                            source.source_highlights +
                                view.source_highlight_count);
  view.source_highlights = {source_highlights_.data(),
                            source_highlights_.size()};
  source_cases_.assign(source.source_cases,
                       source.source_cases + view.source_case_count);
  view.source_cases = {source_cases_.data(), source_cases_.size()};
  source_macros_.assign(source.source_macros,
                        source.source_macros + view.source_macro_count);
  view.source_macros = {source_macros_.data(), source_macros_.size()};
  source_calls_.assign(source.source_calls,
                       source.source_calls + view.source_call_count);
  view.source_calls = {source_calls_.data(), source_calls_.size()};
  call_parameters_.assign(source.call_parameters,
                          source.call_parameters + view.call_parameter_count);
  view.call_parameters = {call_parameters_.data(), call_parameters_.size()};
  source_call_results_.assign(source.source_call_results,
                              source.source_call_results +
                                  view.source_call_result_count);
  view.source_call_results = {source_call_results_.data(),
                              source_call_results_.size()};
}

bool ct_location_record::matches(const ct_location &source) const {
  const ct_location_view other(source);
  return std::strcmp(view.file, other.file) == 0 &&
         std::strcmp(view.function, other.function) == 0 &&
         std::strcmp(view.symbol, other.symbol) == 0 &&
         std::strcmp(view.qualified_function, other.qualified_function) == 0 &&
         view.aliases_size == other.aliases_size &&
         std::memcmp(view.aliases, other.aliases, view.aliases_size) == 0 &&

         view.scope_chain_size == other.scope_chain_size &&
         std::memcmp(view.scope_chain, other.scope_chain,
                     view.scope_chain_size) == 0 &&
         view.inline_calls == other.inline_calls &&
         view.inline_files_size == other.inline_files_size &&
         std::memcmp(view.inline_files, other.inline_files,
                     view.inline_files_size) == 0 &&

         view.physical_aliases_size == other.physical_aliases_size &&
         std::memcmp(view.physical_aliases, other.physical_aliases,
                     view.physical_aliases_size) == 0 &&

         std::strcmp(view.text, other.text) == 0 &&
         std::strcmp(view.declaration, other.declaration) == 0 &&
         view.declaration_line == other.declaration_line &&
         std::strcmp(view.entry_declaration, other.entry_declaration) == 0 &&
         view.entry_declaration_line == other.entry_declaration_line &&
         std::strcmp(view.conversion_error, other.conversion_error) == 0 &&
         view.expression_kind == other.expression_kind &&
         std::strcmp(view.expression, other.expression) == 0 &&
         std::strcmp(view.assignment, other.assignment) == 0 &&
         std::strcmp(view.expression_callee, other.expression_callee) == 0 &&
         view.expression_is_call == other.expression_is_call &&
         view.expression_return_type.kind ==
             other.expression_return_type.kind &&
         view.expression_return_type.bytes ==
             other.expression_return_type.bytes &&
         view.source_variables_size == other.source_variables_size &&
         std::memcmp(view.source_variables, other.source_variables,
                     view.source_variables_size) == 0 &&

         view.source_declarations_size == other.source_declarations_size &&
         std::memcmp(view.source_declarations, other.source_declarations,
                     view.source_declarations_size) == 0 &&

         view.line == other.line && view.source_blocks == other.source_blocks &&
         view.source_block_count == other.source_block_count &&
         view.source_closures == other.source_closures &&
         view.source_closure_count == other.source_closure_count &&
         view.source_highlights == other.source_highlights &&
         view.source_highlight_count == other.source_highlight_count &&
         view.source_cases == other.source_cases &&
         view.source_case_count == other.source_case_count &&
         view.source_case_label_only == other.source_case_label_only &&
         view.source_macros == other.source_macros &&
         view.source_macro_count == other.source_macro_count &&
         view.source_calls == other.source_calls &&
         view.source_call_count == other.source_call_count &&
         view.call_parameters == other.call_parameters &&
         view.call_parameter_count == other.call_parameter_count &&
         view.source_call_results == other.source_call_results &&
         view.source_call_result_count == other.source_call_result_count &&
         view.source_id == other.source_id &&
         view.function_id == other.function_id && view.column == other.column &&
         view.discriminator == other.discriminator &&
         view.has_line == other.has_line &&
         view.source_verified == other.source_verified &&
         view.source_usable == other.source_usable &&
         view.structural == other.structural && view.inlined == other.inlined &&
         view.is_plt == other.is_plt &&
         std::strcmp(view.plt_symbol, other.plt_symbol) == 0;
}
