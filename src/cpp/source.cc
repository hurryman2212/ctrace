// SPDX-License-Identifier: MIT

#include <string>
#include <string_view>

#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Type.h>

#include "source.hh"

std::string ct_cpp_source_standard(std::string_view dialect) {
  for (const auto standard :
       {"C++98", "C++03", "C++11", "C++14", "C++17", "C++20", "C++23"})
    if (dialect == standard)
      return "gnu++" + std::string(dialect.substr(3));
  return {};
}

ct_cpp_declarator
ct_cpp_source_declarator(const clang::FunctionDecl &function) {
  ct_cpp_declarator result;
  if (const auto *method = llvm::dyn_cast<clang::CXXMethodDecl>(&function);
      method && !method->isStatic()) {
    result.member_scope =
        method->getParent()->getQualifiedNameAsString() + "::";
    const auto qualifiers = method->getMethodQualifiers().getAsString();
    if (!qualifiers.empty())
      result.qualifiers += ' ' + qualifiers;
    if (method->getRefQualifier() == clang::RQ_LValue)
      result.qualifiers += " &";
    else if (method->getRefQualifier() == clang::RQ_RValue)
      result.qualifiers += " &&";
  }
  if (const auto *prototype =
          function.getType()->getAs<clang::FunctionProtoType>();
      prototype && prototype->isNothrow())
    result.qualifiers += " noexcept";
  return result;
}

ct_cpp_definition
ct_cpp_source_definition(const clang::FunctionDecl &function) {
  ct_cpp_definition result;
  // Constructor initializer lists execute before their compound body.
  if (const auto *constructor =
          llvm::dyn_cast<clang::CXXConstructorDecl>(&function))
    result.body_starts_execution = !constructor->getNumCtorInitializers();
  result.declaration = !function.isDependentContext();
  if (const auto *method = llvm::dyn_cast<clang::CXXMethodDecl>(&function))
    result.declaration &= !method->getParent()->isLambda();
  return result;
}
