// SPDX-License-Identifier: MIT

#ifndef CTRACE_C_SOURCE_HH
#define CTRACE_C_SOURCE_HH

#include <string>
#include <string_view>

#include <clang/AST/Decl.h>

// GNU producers name the source dialect independently of its DWARF language.
std::string ct_c_source_standard(std::string_view dialect);

// C distinguishes a zero-parameter prototype from an unspecified parameter
// list. The shared formatter has already printed any named/variadic arguments.
void ct_c_complete_parameters(const clang::FunctionDecl &function,
                              std::string &declarator);

#endif
