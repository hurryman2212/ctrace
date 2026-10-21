// SPDX-License-Identifier: MIT

#ifndef CTRACE_SOURCE_COMPARE_H
#define CTRACE_SOURCE_COMPARE_H

#include <optional>

#include "c_cpp_source.hh"

// Apply the AST-proved scalar conversions before comparing an observed value
// with its constant operand. This evaluates no source expressions or memory.
inline std::optional<bool>
ct_source_compare_value(const ct_source_comparison &comparison,
                        ct_value_type input, uint64_t value) {
  if (comparison.types.empty() || comparison.types.size() > 16 ||
      !input.bytes || input.bytes > 8 ||
      input.kind != comparison.types.front().kind ||
      input.bytes != comparison.types.front().bytes)
    return {};
  const auto mask = [](unsigned bytes) {
    return bytes == 8 ? UINT64_MAX : (UINT64_C(1) << (bytes * 8)) - 1;
  };
  value &= mask(input.bytes);
  auto previous = input;
  for (const auto &current : comparison.types) {
    if (!current.bytes || current.bytes > 8 ||
        (current.kind != CT_VALUE_SIGNED && current.kind != CT_VALUE_UNSIGNED &&
         current.kind != CT_VALUE_BOOLEAN && current.kind != CT_VALUE_POINTER))
      return {};
    if (previous.kind == CT_VALUE_SIGNED && previous.bytes < current.bytes &&
        (value & (UINT64_C(1) << (previous.bytes * 8 - 1))))
      value |= ~mask(previous.bytes);
    value = current.kind == CT_VALUE_BOOLEAN ? value != 0
                                             : value & mask(current.bytes);
    previous = current;
  }
  uint64_t other = comparison.constant & mask(previous.bytes);
  if (previous.kind == CT_VALUE_SIGNED) {
    const auto sign = UINT64_C(1) << (previous.bytes * 8 - 1);
    value ^= sign;
    other ^= sign;
  }
  switch (comparison.kind) {
  case CT_SOURCE_COMPARE_EQ:
    return value == other;
  case CT_SOURCE_COMPARE_NE:
    return value != other;
  case CT_SOURCE_COMPARE_LT:
    return value < other;
  case CT_SOURCE_COMPARE_LE:
    return value <= other;
  case CT_SOURCE_COMPARE_GT:
    return value > other;
  case CT_SOURCE_COMPARE_GE:
    return value >= other;
  default:
    return {};
  }
}

#endif
