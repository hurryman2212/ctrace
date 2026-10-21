// SPDX-License-Identifier: MIT

#ifndef CTRACE_C_CPP_ACCESS_HH
#define CTRACE_C_CPP_ACCESS_HH

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

enum class ct_source_access_kind { dereference, member, index, address };

struct ct_source_access_step {
  ct_source_access_kind kind;
  std::string member;
  uint64_t index = 0;
  // Exact display labels before and after this access operation.
  std::string base, text;
};

struct ct_source_access {
  std::string root, text;
  std::vector<ct_source_access_step> steps;
};

// Parse lvalue paths with constant indices, never calls, arithmetic or
// assignments. Parentheses preserve operator precedence; -> is dereference then
// member.
bool ct_parse_source_access(std::string_view text, ct_source_access &access);

#endif
