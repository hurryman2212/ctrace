// SPDX-License-Identifier: MIT

#ifndef CTRACE_FORMAT_BUFFER_HH
#define CTRACE_FORMAT_BUFFER_HH

#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>

#include "c_cpp_values.hh"

// Normal observations use the caller's original stack capacity. Retry only an
// explicitly truncated format; missing metadata remains an ordinary failure.
template <size_t Capacity = 16384, class Formatter>
bool ct_format_buffer(std::string &output, Formatter format) {
  char local[Capacity];
  local[0] = 0;
  bool truncated = false;
  bool valid = format(local, sizeof(local), &truncated);
  if (!truncated) {
    output = valid ? local : "";
    return valid;
  }
  size_t size = sizeof(local);
  for (;;) {
    if (size == output.max_size())
      throw std::length_error("trace value exceeds string representation");
    size = size > output.max_size() / 2 ? output.max_size() : size * 2;
    output.resize(size);
    output[0] = 0;
    truncated = false;
    valid = format(output.data(), output.size(), &truncated);
    if (!truncated) {
      output.resize(valid ? std::strlen(output.c_str()) : 0);
      return valid;
    }
  }
}

inline bool ct_format_typed(std::string &output, const char *name,
                            const ct_value_type *type, const unsigned char *raw,
                            size_t bytes) {
  output.clear();
  if (!name || !*name)
    return false;
  char scalar[64]; // Scalar types cover at most 64-bit integers and doubles.
  const int size =
      ct_values_format_scalar(type, raw, bytes, scalar, sizeof(scalar));
  if (size < 0 || size_t(size) >= sizeof(scalar))
    return false;
  const size_t name_size = std::strlen(name);
  if (name_size >= output.max_size() ||
      size_t(size) > output.max_size() - name_size - 1)
    throw std::length_error("trace value exceeds string representation");
  output.reserve(name_size + 1 + size_t(size));
  output = name;
  output += '=';
  output.append(scalar, size_t(size));
  return true;
}

#endif
