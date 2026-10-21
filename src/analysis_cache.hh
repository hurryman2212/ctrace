// SPDX-License-Identifier: MIT

#ifndef CTRACE_ANALYSIS_CACHE_H
#define CTRACE_ANALYSIS_CACHE_H

#include <cstring>
#include <map>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "c_cpp_source.hh"

/* Analysis payloads contain no process pointers. POD fields use the native
 * ABI, guarded by cache.cc's exact analysis-helper executable identity. Each
 * variable-length field is bounded by the validated payload before allocation.
 */
struct ct_analysis_archive {
  std::vector<unsigned char> &bytes;
  bool reading;
  bool valid = true;
  size_t offset = 0;

  template <class T> void field(T &value) {
    if constexpr (!std::is_trivially_copyable_v<T>) {
      value.archive(*this);
    } else {
      static_assert(std::is_trivially_copyable_v<T>);
      if (!valid)
        return;
      if (reading) {
        if (sizeof(value) > bytes.size() - offset) {
          valid = false;
          return;
        }
        std::memcpy(&value, bytes.data() + offset, sizeof(value));
        offset += sizeof(value);
      } else {
        const auto *data = reinterpret_cast<const unsigned char *>(&value);
        bytes.insert(bytes.end(), data, data + sizeof(value));
      }
    }
  }

  void field(std::string &value) {
    uint64_t size = value.size();
    field(size);
    if (!valid)
      return;
    if (reading) {
      if (size > bytes.size() - offset) {
        valid = false;
        return;
      }
      value.assign(reinterpret_cast<const char *>(bytes.data() + offset), size);
      offset += size;
    } else {
      bytes.insert(bytes.end(), value.begin(), value.end());
    }
  }

  template <class A, class B> void field(std::pair<A, B> &value) {
    fields(value.first, value.second);
  }

  template <class T> void field(std::vector<T> &values) {
    uint64_t size = values.size();
    field(size);
    if (!valid)
      return;
    if (reading) {
      // No encoded element is empty. Never trust a count beyond this payload.
      if (size > bytes.size() - offset || size > values.max_size()) {
        valid = false;
        return;
      }
      values.clear();
      for (uint64_t index = 0; valid && index < size; ++index) {
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

  template <class K, class V> void field(std::map<K, V> &values) {
    uint64_t size = values.size();
    field(size);
    if (!valid)
      return;
    if (reading) {
      if (size > bytes.size() - offset || size > values.max_size()) {
        valid = false;
        return;
      }
      values.clear();
      for (uint64_t index = 0; valid && index < size; ++index) {
        K key{};
        V value{};
        fields(key, value);
        if (valid && !values.emplace(std::move(key), std::move(value)).second)
          valid = false;
      }
    } else {
      for (auto &[key, value] : values) {
        K copy = key;
        fields(copy, value);
      }
    }
  }

  void field(ct_value_layout_member &value) {
    fields(value.name, value.type, value.offset, value.available);
  }
  void field(ct_flow_switch &value) {
    fields(value.guard_offset, value.dispatch_offset, value.selector_offset,
           value.join_offset, value.default_offset, value.selector_register,
           value.cases);
  }
  void field(ct_source_comparison &value) {
    fields(value.kind, value.variable, value.types, value.constant);
  }
  void field(ct_source_expression &value) {
    fields(value.kind, value.text, value.assignment, value.callee,
           value.assignment_object, value.assignment_type, value.function,
           value.is_call, value.macro_result, value.constant,
           value.constant_value, value.constant_type, value.read_path,
           value.value_type, value.return_type, value.result_casts,
           value.comparison, value.begin, value.end);
  }
  void field(ct_source_variable &value) {
    fields(value.offset, value.name, value.function, value.declaration,
           value.access);
  }
  void field(ct_source_declaration &value) {
    fields(value.text, value.function, value.line, value.variables);
  }
  void field(ct_source_block_info &value) {
    fields(value.block, value.function, value.complete);
  }
  void field(ct_source_macro_info &value) {
    fields(value.macro, value.function);
  }
  void field(ct_source_call_info &value) {
    fields(value.function, value.callee, value.declaration, value.parameters,
           value.variadic);
  }
  void field(ct_source_call_result_info &value) {
    fields(value.result, value.function, value.begin, value.end,
           value.return_forwarded, value.argument_variables,
           value.argument_calls, value.argument_addresses);
  }
  void field(ct_source_case_info &value) {
    fields(value.label, value.function, value.begin_column, value.end_column,
           value.column_required, value.begin, value.end, value.display_begin,
           value.display_end);
  }
  void field(ct_source_closure_info &value) {
    fields(value.closure, value.function, value.offset, value.display_offset);
  }
  void field(ct_source_statement &value) {
    fields(value.function, value.text, value.end_line, value.begin, value.end);
  }
  void field(ct_source_asm_line &value) {
    fields(value.text, value.error, value.structural, value.expression,
           value.variables, value.declaration, value.blocks, value.highlights,
           value.macros, value.cases, value.closures, value.calls,
           value.call_results, value.statement);
  }

  template <class... T> void fields(T &...values) { (field(values), ...); }
  bool complete() const {
    return valid && (!reading || offset == bytes.size());
  }
};

#endif
