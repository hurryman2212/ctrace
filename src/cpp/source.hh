// SPDX-License-Identifier: MIT

#ifndef CTRACE_CPP_SOURCE_HH
#define CTRACE_CPP_SOURCE_HH

#include <string>
#include <string_view>

#include <clang/AST/Decl.h>

std::string ct_cpp_source_standard(std::string_view dialect);

struct ct_cpp_declarator {
  std::string member_scope, qualifiers;
};

// Member pointers and cv/ref/noexcept qualifiers surround the shared argument
// list; argument and return-type spelling remain in the common formatter.
ct_cpp_declarator ct_cpp_source_declarator(const clang::FunctionDecl &function);

struct ct_cpp_definition {
  bool body_starts_execution = true;
  bool declaration = true;
};

ct_cpp_definition ct_cpp_source_definition(const clang::FunctionDecl &function);

#endif
