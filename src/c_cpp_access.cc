// SPDX-License-Identifier: MIT

#include <cctype>
#include <charconv>
#include <functional>
#include <utility>

#include "c_cpp_access.hh"

bool ct_parse_source_access(std::string_view text, ct_source_access &access) {
  access = {};
  if (text.empty())
    return false;
  size_t cursor = 0;
  const auto whitespace = [&] {
    while (cursor < text.size() &&
           std::isspace(static_cast<unsigned char>(text[cursor])))
      ++cursor;
  };
  const auto identifier = [&]() {
    const size_t begin = cursor;
    if (cursor < text.size() &&
        (std::isalpha(static_cast<unsigned char>(text[cursor])) ||
         text[cursor] == '_')) {
      ++cursor;
      while (cursor < text.size() &&
             (std::isalnum(static_cast<unsigned char>(text[cursor])) ||
              text[cursor] == '_'))
        ++cursor;
    }
    return std::string(text.substr(begin, cursor - begin));
  };
  const auto append = [&](ct_source_access_kind kind, std::string member,
                          uint64_t index, std::string base, std::string value) {
    if (kind == ct_source_access_kind::dereference && !access.steps.empty() &&
        access.steps.back().kind == ct_source_access_kind::address) {
      access.steps.pop_back();
      return true;
    }
    access.steps.push_back(
        {kind, std::move(member), index, std::move(base), std::move(value)});
    return true;
  };
  std::function<bool(std::string &)> expression;
  expression = [&](std::string &value) {
    whitespace();
    if (cursor == text.size())
      return false;
    if (text[cursor] == '*' || text[cursor] == '&') {
      const char operation = text[cursor++];
      std::string operand;
      if (!expression(operand))
        return false;
      value = operation + std::string("(") + operand + ')';
      return append(operation == '*' ? ct_source_access_kind::dereference
                                     : ct_source_access_kind::address,
                    {}, 0, operand, value);
    }
    if (text[cursor] == '(') {
      ++cursor;
      if (!expression(value))
        return false;
      whitespace();
      if (cursor == text.size() || text[cursor++] != ')')
        return false;
    } else {
      value = identifier();
      if (value.empty() || !access.root.empty())
        return false;
      access.root = value;
    }
    while (true) {
      whitespace();
      if (cursor == text.size())
        return true;
      const bool arrow = text.substr(cursor, 2) == "->";
      if (arrow || text[cursor] == '.') {
        cursor += arrow ? 2 : 1;
        whitespace();
        auto member = identifier();
        if (member.empty())
          return false;
        const std::string base = value.front() == '*' || value.front() == '&'
                                     ? '(' + value + ')'
                                     : value;
        const std::string next = base + (arrow ? "->" : ".") + member;
        if (arrow && !append(ct_source_access_kind::dereference, {}, 0, value,
                             "*(" + value + ')'))
          return false;
        if (!append(ct_source_access_kind::member, std::move(member), 0,
                    arrow ? "*(" + value + ')' : value, next))
          return false;
        value = next;
      } else if (text[cursor] == '[') {
        ++cursor;
        whitespace();
        if (cursor == text.size())
          return false;
        const size_t begin = cursor;
        int base = 10;
        if (text.substr(cursor, 2) == "0x" || text.substr(cursor, 2) == "0X") {
          base = 16;
          cursor += 2;
        } else if (text[cursor] == '0') {
          base = 8;
        }
        const size_t digits = cursor;
        while (cursor < text.size() &&
               (base == 16
                    ? std::isxdigit(static_cast<unsigned char>(text[cursor]))
                    : std::isdigit(static_cast<unsigned char>(text[cursor]))))
          ++cursor;
        uint64_t index = 0;
        const auto parsed = std::from_chars(text.data() + digits,
                                            text.data() + cursor, index, base);
        if (digits == cursor || parsed.ec != std::errc() ||
            parsed.ptr != text.data() + cursor)
          return false;
        const std::string number(text.substr(begin, cursor - begin));
        whitespace();
        if (cursor == text.size() || text[cursor++] != ']')
          return false;
        const std::string base_label =
            value.front() == '*' || value.front() == '&' ? '(' + value + ')'
                                                         : value;
        const std::string next = base_label + '[' + number + ']';
        if (!append(ct_source_access_kind::index, {}, index, value, next))
          return false;
        value = next;
      } else {
        return true;
      }
    }
  };
  std::string value;
  if (!expression(value)) {
    access = {};
    return false;
  }
  whitespace();
  if (cursor != text.size()) {
    access = {};
    return false;
  }
  access.text = std::string(text);
  return true;
}
