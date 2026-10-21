// SPDX-License-Identifier: MIT

#include <string>
#include <string_view>

#include <clang/AST/Decl.h>
#include <clang/AST/Type.h>

#include "source.hh"

std::string ct_c_source_standard(std::string_view dialect) {
  for (const auto standard : {"C89", "C99", "C11", "C17", "C23"})
    if (dialect == standard)
      return "gnu" + std::string(dialect.substr(1));
  return {};
}

void ct_c_complete_parameters(const clang::FunctionDecl &function,
                              std::string &declarator) {
  if (function.getType()->getAs<clang::FunctionProtoType>() &&
      !function.getNumParams() && !function.isVariadic())
    declarator += "void";
}
