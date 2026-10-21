// SPDX-License-Identifier: MIT

#ifndef CTRACE_LOCATION_RECORD_H
#define CTRACE_LOCATION_RECORD_H

#include <cstddef>
#include <cstring>
#include <vector>

#include "analysis.hh"

// Invalid protocol lengths omit the whole field rather than exposing an
// unterminated list or a partial over-capacity array.
template <size_t N> inline const char *ct_location_text(const char (&text)[N]) {
  return std::memchr(text, 0, N) ? text : "";
}
template <size_t N>
inline uint32_t ct_location_list_size(const char (&text)[N], uint32_t size) {
  return size <= N && (!size || text[size - 1] == 0) ? size : 0;
}
template <class T, size_t N>
inline uint32_t ct_location_count(const T (&)[N], uint32_t count) {
  return count <= N ? count : 0;
}

// A borrowed, immutable active portion of a fixed-capacity protocol array.
template <class T> class ct_location_array {
  const T *data_ = nullptr;
  size_t size_ = 0;

public:
  ct_location_array() = default;
  ct_location_array(const T *data, size_t size) : data_(data), size_(size) {}
  const T &operator[](size_t index) const { return data_[index]; }
  const T *begin() const { return data_; }
  const T *data() const { return data_; }
  const T *end() const { return size_ ? data_ + size_ : data_; }
  size_t size() const { return size_; }
  bool operator==(const ct_location_array &other) const {
    return size_ == other.size_ &&
           (!size_ || std::memcmp(data_, other.data_, size_ * sizeof(T)) == 0);
  }
};

// RPC records are temporary; this view either borrows one for a synchronous
// query or points into a Site-owned record whose storage never moves.
struct ct_location_view {
  const char *file = "";
  const char *function = "";
  const char *symbol = "";
  const char *qualified_function = "";
  const char *aliases = "";
  uint32_t aliases_size{};
  const char *scope_chain = "";
  uint32_t scope_chain_size{};
  ct_location_array<ct_inline_callsite> inline_calls;
  const char *inline_files = "";
  uint32_t inline_files_size{};
  const char *physical_aliases = "";
  uint32_t physical_aliases_size{};
  const char *text = "";
  const char *declaration = "";
  uint64_t declaration_line{};
  const char *entry_declaration = "";
  uint64_t entry_declaration_line{};
  const char *conversion_error = "";
  ct_expression_kind expression_kind{};
  const char *expression = "";
  const char *assignment = "";
  const char *expression_callee = "";
  bool expression_is_call{};
  ct_value_type expression_return_type{};
  const char *source_variables = "";
  uint32_t source_variables_size{};
  const char *source_declarations = "";
  uint32_t source_declarations_size{};
  uint64_t line{};
  ct_location_array<ct_source_block> source_blocks;
  uint32_t source_block_count{};
  ct_location_array<ct_source_closure> source_closures;
  uint32_t source_closure_count{};
  ct_location_array<ct_source_highlight> source_highlights;
  uint32_t source_highlight_count{};
  ct_location_array<ct_source_case> source_cases;
  uint32_t source_case_count{};
  bool source_case_label_only{};
  ct_location_array<ct_source_macro> source_macros;
  uint32_t source_macro_count{};
  ct_location_array<ct_source_call> source_calls;
  uint32_t source_call_count{};
  ct_location_array<ct_call_parameter> call_parameters;
  uint32_t call_parameter_count{};
  ct_location_array<ct_source_call_result> source_call_results;
  uint32_t source_call_result_count{};
  uint64_t source_id{};
  uint64_t function_id{};
  uint32_t column{};
  uint32_t discriminator{};
  bool has_line{};
  bool source_verified{};
  bool source_usable{};
  bool structural{};
  bool inlined{};
  bool is_plt{};
  const char *plt_symbol = "";

  ct_location_view() = default;
  ct_location_view(const ct_location &source)
      : file(ct_location_text(source.file)),
        function(ct_location_text(source.function)),
        symbol(ct_location_text(source.symbol)),
        qualified_function(ct_location_text(source.qualified_function)),
        aliases(ct_location_list_size(source.aliases, source.aliases_size)
                    ? source.aliases
                    : ""),
        aliases_size(
            ct_location_list_size(source.aliases, source.aliases_size)),
        scope_chain(
            ct_location_list_size(source.scope_chain, source.scope_chain_size)
                ? source.scope_chain
                : ""),
        scope_chain_size(
            ct_location_list_size(source.scope_chain, source.scope_chain_size)),
        inline_calls(
            source.inline_calls,
            ct_location_count(source.inline_calls, source.inline_call_count)),
        inline_files(
            ct_location_list_size(source.inline_files, source.inline_files_size)
                ? source.inline_files
                : ""),
        inline_files_size(ct_location_list_size(source.inline_files,
                                                source.inline_files_size)),
        physical_aliases(ct_location_list_size(source.physical_aliases,
                                               source.physical_aliases_size)
                             ? source.physical_aliases
                             : ""),
        physical_aliases_size(ct_location_list_size(
            source.physical_aliases, source.physical_aliases_size)),
        text(ct_location_text(source.text)),
        declaration(ct_location_text(source.declaration)),
        declaration_line(source.declaration_line),
        entry_declaration(ct_location_text(source.entry_declaration)),
        entry_declaration_line(source.entry_declaration_line),
        conversion_error(ct_location_text(source.conversion_error)),
        expression_kind(source.expression_kind),
        expression(ct_location_text(source.expression)),
        assignment(ct_location_text(source.assignment)),
        expression_callee(ct_location_text(source.expression_callee)),
        expression_is_call(source.expression_is_call),
        expression_return_type(source.expression_return_type),
        source_variables(ct_location_list_size(source.source_variables,
                                               source.source_variables_size)
                             ? source.source_variables
                             : ""),
        source_variables_size(ct_location_list_size(
            source.source_variables, source.source_variables_size)),
        source_declarations(
            ct_location_list_size(source.source_declarations,
                                  source.source_declarations_size)
                ? source.source_declarations
                : ""),
        source_declarations_size(ct_location_list_size(
            source.source_declarations, source.source_declarations_size)),
        line(source.line),
        source_blocks(
            source.source_blocks,
            ct_location_count(source.source_blocks, source.source_block_count)),
        source_block_count(source_blocks.size()),
        source_closures(source.source_closures,
                        ct_location_count(source.source_closures,
                                          source.source_closure_count)),
        source_closure_count(source_closures.size()),
        source_highlights(source.source_highlights,
                          ct_location_count(source.source_highlights,
                                            source.source_highlight_count)),
        source_highlight_count(source_highlights.size()),
        source_cases(
            source.source_cases,
            ct_location_count(source.source_cases, source.source_case_count)),
        source_case_count(source_cases.size()),
        source_case_label_only(source.source_case_label_only),
        source_macros(
            source.source_macros,
            ct_location_count(source.source_macros, source.source_macro_count)),
        source_macro_count(source_macros.size()),
        source_calls(
            source.source_calls,
            ct_location_count(source.source_calls, source.source_call_count)),
        source_call_count(source_calls.size()),
        call_parameters(source.call_parameters,
                        ct_location_count(source.call_parameters,
                                          source.call_parameter_count)),
        call_parameter_count(call_parameters.size()),
        source_call_results(source.source_call_results,
                            ct_location_count(source.source_call_results,
                                              source.source_call_result_count)),
        source_call_result_count(source_call_results.size()),
        source_id(source.source_id), function_id(source.function_id),
        column(source.column), discriminator(source.discriminator),
        has_line(source.has_line), source_verified(source.source_verified),
        source_usable(source.source_usable), structural(source.structural),
        inlined(source.inlined), is_plt(source.is_plt),
        plt_symbol(ct_location_text(source.plt_symbol)) {}
};

// Only active strings and array elements are retained. A record is immutable
// once published; pointers borrowed by pending calls/blocks remain valid for
// the owning Site's lifetime.
class ct_location_record {
  std::vector<char> strings_;
  std::vector<ct_inline_callsite> inline_calls_;
  std::vector<ct_source_block> source_blocks_;
  std::vector<ct_source_closure> source_closures_;
  std::vector<ct_source_highlight> source_highlights_;
  std::vector<ct_source_case> source_cases_;
  std::vector<ct_source_macro> source_macros_;
  std::vector<ct_source_call> source_calls_;
  std::vector<ct_call_parameter> call_parameters_;
  std::vector<ct_source_call_result> source_call_results_;

public:
  ct_location_view view;

  explicit ct_location_record(const ct_location &source);
  ct_location_record(const ct_location_record &) = delete;
  ct_location_record &operator=(const ct_location_record &) = delete;
  bool matches(const ct_location &source) const;
};

#endif
