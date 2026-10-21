// SPDX-License-Identifier: MIT

#include <tuple>

#include <llvm/BinaryFormat/Dwarf.h>

#include "dwarf/language.hh"

void ct_dwarf_source_language(uint64_t code, std::string &language,
                              std::string &standard) {
  using namespace llvm::dwarf;
  for (const auto &[candidate, name, dialect] :
       {std::tuple<uint64_t, const char *, const char *>{DW_LANG_C, "c", ""},
        {DW_LANG_C89, "c", "gnu89"},
        {DW_LANG_C99, "c", "gnu99"},
        {DW_LANG_C11, "c", "gnu11"},
        {DW_LANG_C17, "c", "gnu17"},
        {DW_LANG_C_plus_plus, "c++", ""},
        {DW_LANG_C_plus_plus_03, "c++", "gnu++03"},
        {DW_LANG_C_plus_plus_11, "c++", "gnu++11"},
        {DW_LANG_C_plus_plus_14, "c++", "gnu++14"},
        {DW_LANG_C_plus_plus_17, "c++", "gnu++17"},
        {DW_LANG_C_plus_plus_20, "c++", "gnu++20"}}) {
    if (code != candidate)
      continue;
    if (language.empty())
      language = name;
    standard = dialect;
    return;
  }
}
