#ifndef CTRACE_ANALYSIS_CACHE_H
#define CTRACE_ANALYSIS_CACHE_H

#include <cstring>
#include <map>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "source_asm.h"

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
      // No encoded element is empty; also cap collection overhead on corrupt
      // inputs rather than trusting an attacker-supplied allocation count.
      if (size > bytes.size() - offset || size > 1000000) {
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
      if (size > bytes.size() - offset || size > 1000000) {
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

  void field(ct_source_expression &value) {
    fields(value.kind, value.text, value.assignment, value.callee,
           value.function, value.is_call, value.macro_result, value.return_type,
           value.begin, value.end);
  }
  void field(ct_source_variable &value) {
    fields(value.offset, value.name, value.function, value.declaration);
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
    fields(value.result, value.function, value.begin, value.end);
  }
  void field(ct_source_case_info &value) {
    fields(value.label, value.function, value.begin_column, value.end_column,
           value.column_required, value.begin, value.end, value.display_begin,
           value.display_end);
  }
  void field(ct_source_closure_info &value) {
    fields(value.closure, value.function, value.offset, value.display_offset);
  }
  void field(ct_source_asm_line &value) {
    fields(value.text, value.error, value.structural, value.expression,
           value.variables, value.declaration, value.blocks, value.highlights,
           value.macros, value.cases, value.closures, value.calls,
           value.call_results);
  }

  template <class... T> void fields(T &...values) { (field(values), ...); }
  bool complete() const {
    return valid && (!reading || offset == bytes.size());
  }
};

#endif
