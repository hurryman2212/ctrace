// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstdio>

#include "perfetto_json.hh"

std::string ct_perfetto_json_string(const char *text) {
  std::string result = "\"";
  if (text) {
    for (const unsigned char *cursor =
             reinterpret_cast<const unsigned char *>(text);
         *cursor; ++cursor) {
      switch (*cursor) {
      case '"':
        result += "\\\"";
        break;
      case '\\':
        result += "\\\\";
        break;
      case '\b':
        result += "\\b";
        break;
      case '\f':
        result += "\\f";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      default:
        if (*cursor >= 0x80) {
          const unsigned length = *cursor >= 0xc2 && *cursor <= 0xdf   ? 2
                                  : *cursor >= 0xe0 && *cursor <= 0xef ? 3
                                  : *cursor >= 0xf0 && *cursor <= 0xf4 ? 4
                                                                       : 0;
          uint32_t codepoint = length ? *cursor & (0x7f >> length) : 0;
          bool valid = length != 0;
          for (unsigned index = 1; valid && index < length; ++index) {
            valid = (cursor[index] & 0xc0) == 0x80;
            codepoint = (codepoint << 6) | (cursor[index] & 0x3f);
          }
          valid = valid && (length != 3 || codepoint >= 0x800) &&
                  (length != 4 || codepoint >= 0x10000) &&
                  !(codepoint >= 0xd800 && codepoint <= 0xdfff) &&
                  codepoint <= 0x10ffff;
          if (valid) {
            result.append(reinterpret_cast<const char *>(cursor), length);
            cursor += length - 1;
            break;
          }
          // Linux paths may contain arbitrary bytes; keep the JSON valid even
          // when a symbol or source path is not UTF-8.
        }
        if (*cursor < 0x20 || *cursor >= 0x80) {
          char escaped[7];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", *cursor);
          result += escaped;
        } else {
          result += static_cast<char>(*cursor);
        }
      }
    }
  }
  result += '"';
  return result;
}
