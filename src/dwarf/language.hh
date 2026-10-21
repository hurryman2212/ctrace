// SPDX-License-Identifier: MIT

#ifndef CTRACE_DWARF_LANGUAGE_H
#define CTRACE_DWARF_LANGUAGE_H

#include <cstdint>
#include <string>

// Interpret the compilation unit language, independent of a header's suffix.
// Keep an explicit compiler language; a known DWARF dialect updates standard.
// Unknown language codes leave both outputs unchanged.
void ct_dwarf_source_language(uint64_t code, std::string &language,
                              std::string &standard);

#endif
