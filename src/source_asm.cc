#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <clang/AST/Attr.h>
#include <clang/AST/Mangle.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/Builtins.h>
#include <clang/Basic/Diagnostic.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Config/config.h>
#include <clang/Driver/Options.h>
#include <clang/Driver/Types.h>
#include <clang/Frontend/ASTUnit.h>
#include <clang/Lex/Lexer.h>
#include <clang/Lex/PreprocessingRecord.h>
#include <clang/Lex/Preprocessor.h>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/BinaryFormat/Dwarf.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCParser/MCAsmParser.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Option/ArgList.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/StringSaver.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/VirtualFileSystem.h>

#include "analysis_cache.h"
#include "analysis_files.h"
#include "cache.h"
#include "source_asm.h"

class AsmInstructions : public llvm::MCStreamer {
public:
  std::vector<llvm::MCInst> instructions;
  bool unsupported = false;
  explicit AsmInstructions(llvm::MCContext &context) : MCStreamer(context) {}
  void emitInstruction(const llvm::MCInst &instruction,
                       const llvm::MCSubtargetInfo &) override {
    instructions.push_back(instruction);
  }
  bool emitSymbolAttribute(llvm::MCSymbol *, llvm::MCSymbolAttr) override {
    unsupported = true;
    return false;
  }
  void emitCommonSymbol(llvm::MCSymbol *, uint64_t, llvm::Align) override {
    unsupported = true;
  }
};

struct PrintedAssembly {
  std::string text;
  std::string identity;
};

/* Parsing and instruction semantics are entirely LLVM MC's responsibility. */
static std::optional<PrintedAssembly>
print_assembly(const std::string &assembly, int input_syntax,
               int output_syntax) {
  static const bool initialized = [] {
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmParser();
    llvm::InitializeNativeTargetAsmPrinter();
    return true;
  }();
  (void)initialized;
  const llvm::Triple triple("x86_64-pc-linux-gnu");
  std::string error;
  const auto *target = llvm::TargetRegistry::lookupTarget(triple.str(), error);
  if (!target)
    return std::nullopt;
  llvm::MCTargetOptions options;
  std::unique_ptr<llvm::MCRegisterInfo> registers(
      target->createMCRegInfo(triple.str()));
  std::unique_ptr<llvm::MCAsmInfo> info(
      target->createMCAsmInfo(*registers, triple.str(), options));
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget(
      target->createMCSubtargetInfo(triple.str(), "generic", ""));
  std::unique_ptr<llvm::MCInstrInfo> instructions(target->createMCInstrInfo());
  llvm::SourceMgr sources;
  bool diagnosed = false;
  sources.setDiagHandler(
      [](const llvm::SMDiagnostic &, void *context) {
        *static_cast<bool *>(context) = true;
      },
      &diagnosed);
  sources.AddNewSourceBuffer(llvm::MemoryBuffer::getMemBufferCopy(assembly),
                             llvm::SMLoc());
  llvm::MCContext context(triple, info.get(), registers.get(), subtarget.get(),
                          &sources);
  std::unique_ptr<llvm::MCObjectFileInfo> object_info(
      target->createMCObjectFileInfo(context, false));
  context.setObjectFileInfo(object_info.get());
  AsmInstructions streamer(context);
  std::unique_ptr<llvm::MCAsmParser> parser(
      llvm::createMCAsmParser(sources, context, streamer, *info));
  std::unique_ptr<llvm::MCTargetAsmParser> machine_parser(
      target->createMCAsmParser(*subtarget, *parser, *instructions, options));
  if (!machine_parser)
    return std::nullopt;
  parser->setTargetParser(*machine_parser);
  parser->setAssemblerDialect(input_syntax);
  if (parser->Run(false) || diagnosed || streamer.unsupported ||
      streamer.instructions.empty())
    return std::nullopt;
  std::unique_ptr<llvm::MCInstPrinter> printer(target->createMCInstPrinter(
      triple, output_syntax, *info, *instructions, *registers));
  printer->setUseMarkup(true);
  PrintedAssembly result;
  llvm::raw_string_ostream text(result.text);
  llvm::raw_string_ostream identity(result.identity);
  for (const auto &instruction : streamer.instructions) {
    identity << instruction.getOpcode() << ':' << instruction.getFlags() << ':';
    for (const auto &operand : instruction) {
      if (operand.isReg())
        identity << 'r' << operand.getReg().id() << ',';
      else if (operand.isImm())
        identity << 'i' << operand.getImm() << ',';
      else
        return std::nullopt; // Symbols/labels need relocation and build
                             // context.
    }
    identity << ';';
    if (!result.text.empty())
      text << '\n';
    printer->printInst(&instruction, 0, "", *subtarget, text);
  }
  return result;
}

static std::string literal_template(llvm::StringRef text) {
  std::string result;
  for (char byte : text) {
    if (byte == '%' || byte == '{' || byte == '}' || byte == '|')
      result += '%';
    result += byte;
  }
  return result;
}

struct TemplatePiece {
  std::string text;
  unsigned operand = 0;
  char modifier = 0;
  bool reference = false;
};

/* Clang has parsed GNU placeholders/escapes. Select its LLVM IR dialect
 * markers here; this is template binding, not an assembly-language parser. */
static bool select_template(const clang::GCCAsmStmt &statement,
                            const clang::ASTContext &context, int syntax,
                            std::vector<TemplatePiece> &selected,
                            bool &has_variants) {
  llvm::SmallVector<clang::GCCAsmStmt::AsmStringPiece> pieces;
  unsigned offset = 0;
  if (statement.AnalyzeAsmString(pieces, context, offset))
    return false;
  int branch = -1;
  for (const auto &piece : pieces) {
    if (piece.isOperand()) {
      if (branch == -1 || branch == syntax)
        selected.push_back({"%" + piece.getString(), piece.getOperandNo(),
                            piece.getModifier(), true});
      continue;
    }
    std::string literal;
    llvm::StringRef text = piece.getString();
    for (size_t index = 0; index < text.size(); ++index) {
      char byte = text[index];
      if (byte == '$') {
        if (++index == text.size())
          return false;
        byte = text[index];
        if (byte == '(') {
          if (branch != -1)
            return false;
          branch = 0;
          has_variants = true;
          continue;
        }
        if (byte == '|') {
          if (branch != 0)
            return false;
          branch = 1;
          continue;
        }
        if (byte == ')') {
          if (branch < 0)
            return false;
          branch = -1;
          continue;
        }
        if (byte != '$')
          return false; // %= and other special expansions remain original.
      }
      if (branch == -1 || branch == syntax)
        literal += byte;
    }
    if (!literal.empty())
      selected.push_back({literal});
  }
  return branch == -1;
}

static std::optional<std::string>
convert_template(const clang::GCCAsmStmt &statement,
                 const clang::ASTContext &context, int syntax,
                 std::optional<int> configured_syntax, std::string &error) {
  if (statement.isSimple()) {
    error = "basic asm has no GNU operand contract";
    return std::nullopt;
  }
  std::vector<TemplatePiece> pieces;
  bool variants = false;
  if (!select_template(statement, context, syntax, pieces, variants)) {
    error = "unsupported GNU template expansion";
    return std::nullopt;
  }
  if (variants) {
    std::string result;
    for (const auto &piece : pieces)
      result += piece.reference ? piece.text : literal_template(piece.text);
    return result;
  }
  if (statement.isAsmGoto()) {
    error = "asm goto requires label-aware conversion";
    return std::nullopt;
  }
  std::map<std::string, std::string> bindings;
  std::map<std::string, std::string> placeholders;
  std::string assembly[2];
  for (const auto &piece : pieces) {
    if (!piece.reference) {
      // Directives, labels and assembler comments can affect subsequent code.
      if (piece.text.find_first_of(".:#") != std::string::npos) {
        error =
            "assembler directives, labels or comments require build context";
        return std::nullopt;
      }
      assembly[0] += piece.text;
      assembly[1] += piece.text;
      continue;
    }
    unsigned outputs = statement.getNumOutputs();
    if (piece.operand >= outputs + statement.getNumInputs()) {
      error = "unsupported implicit or label operand";
      return std::nullopt;
    }
    const clang::Expr *expression =
        piece.operand < outputs
            ? statement.getOutputExpr(piece.operand)
            : statement.getInputExpr(piece.operand - outputs);
    std::string constraint =
        piece.operand < outputs
            ? statement.getOutputConstraint(piece.operand)
            : statement.getInputConstraint(piece.operand - outputs);
    llvm::StringRef kind = llvm::StringRef(constraint).ltrim("=+&%");
    if (kind != "r" || (!expression->getType()->isIntegerType() &&
                        !expression->getType()->isPointerType())) {
      error = "operand constraint/type has no safe display binding";
      return std::nullopt;
    }
    uint64_t width = context.getTypeSize(expression->getType());
    switch (piece.modifier) {
    case 0:
      break;
    case 'b':
      width = 8;
      break;
    case 'w':
      width = 16;
      break;
    case 'k':
      width = 32;
      break;
    case 'q':
      width = 64;
      break;
    default:
      error = "unsupported operand modifier";
      return std::nullopt;
    }
    if (width != 8 && width != 16 && width != 32 && width != 64) {
      error = "unsupported register operand width";
      return std::nullopt;
    }
    auto binding = bindings.find(piece.text);
    if (binding == bindings.end()) {
      if (bindings.size() >= 8) {
        error = "too many distinct register operands for display binding";
        return std::nullopt;
      }
      std::string base = "r" + std::to_string(8 + bindings.size());
      if (llvm::StringRef(statement.getAsmString())
              .contains_insensitive(base)) {
        error = "literal register overlaps display binding";
        return std::nullopt;
      }
      std::string reg = base + (width == 8    ? "b"
                                : width == 16 ? "w"
                                : width == 32 ? "d"
                                              : "");
      binding = bindings.emplace(piece.text, reg).first;
      placeholders[reg] = piece.text;
    }
    assembly[0] += "%" + binding->second;
    assembly[1] += binding->second;
  }
  auto att = configured_syntax == 1 ? std::nullopt
                                    : print_assembly(assembly[0], 0, syntax);
  auto intel = configured_syntax == 0 ? std::nullopt
                                      : print_assembly(assembly[1], 1, syntax);
  if ((!att && !intel) || (att && intel && att->identity != intel->identity)) {
    error = att && intel ? "input assembler dialect is ambiguous"
                         : "LLVM cannot safely convert this template";
    return std::nullopt;
  }
  std::string rendered = att ? att->text : intel->text;
  // MC printer markup identifies registers; never search opcode/operand text
  // to infer an instruction's meaning or reverse operands ourselves.
  std::string result;
  unsigned markup_depth = 0;
  for (size_t index = 0; index < rendered.size();) {
    llvm::StringRef rest(rendered.data() + index, rendered.size() - index);
    if (rest.starts_with("<reg:")) {
      size_t end = rendered.find('>', index);
      if (end == std::string::npos)
        return std::nullopt;
      std::string reg =
          llvm::StringRef(rendered).slice(index + 5, end).ltrim("%").str();
      auto placeholder = placeholders.find(reg);
      if (placeholder != placeholders.end()) {
        result += placeholder->second;
        index = end + 1;
        continue;
      }
    }
    if (rest.starts_with("<reg:") || rest.starts_with("<imm:") ||
        rest.starts_with("<mem:")) {
      ++markup_depth;
      index += 5;
      continue;
    }
    if (rendered[index] == '>' && markup_depth) {
      --markup_depth;
      ++index;
      continue;
    }
    char byte = rendered[index++];
    if (byte == '\t')
      byte = ' ';
    result += literal_template(llvm::StringRef(&byte, 1));
  }
  return llvm::StringRef(result).trim().str();
}

class SourceAsmVisitor : public clang::RecursiveASTVisitor<SourceAsmVisitor> {
public:
  struct Edit {
    size_t begin, end;
    std::string replacement;
  };
  clang::ASTContext &context;
  llvm::StringRef source;
  int syntax;
  std::optional<int> configured_syntax;
  bool parse_failed;
  std::vector<Edit> edits;
  std::map<unsigned, std::string> errors;
  std::set<unsigned> structural_lines;
  std::map<unsigned, ct_source_expression> expressions;
  std::set<unsigned> ambiguous_lines;
  std::map<unsigned, std::vector<ct_source_variable>> variables;
  std::map<unsigned, ct_source_declaration> declarations;
  struct Macro {
    size_t end;
    unsigned line;
    std::string identity, invocation, function;
    std::vector<const clang::CallExpr *> calls;
  };
  std::map<size_t, Macro> macros;
  std::map<std::tuple<unsigned, std::string, std::string>, unsigned> line_calls;
  std::map<std::tuple<unsigned, std::string, std::string>,
           std::optional<ct_source_call_info>>
      call_contracts;
  std::map<unsigned, std::vector<ct_source_call_result_info>> call_results;
  struct Block {
    ct_source_block_info info;
    size_t opening_begin, opening_end, closing_begin, closing_end;
    bool complete = true;
    bool has_braces = true;
  };
  std::vector<Block> blocks;
  std::map<unsigned, std::vector<ct_source_closure_info>> closures;
  struct CaseGroup {
    uint64_t switch_id;
    std::string function;
    std::vector<ct_source_case> labels;
    size_t begin, body_begin, end;
  };
  std::vector<CaseGroup> case_groups;

  SourceAsmVisitor(clang::ASTContext &context, llvm::StringRef source,
                   int syntax, std::optional<int> configured_syntax,
                   bool failed)
      : context(context), source(source), syntax(syntax),
        configured_syntax(configured_syntax), parse_failed(failed) {}

  void collect_macros(clang::PreprocessingRecord *record) {
    if (parse_failed || !record)
      return;
    auto &manager = context.getSourceManager();
    for (const auto *entity : *record) {
      const auto *expansion = llvm::dyn_cast<clang::MacroExpansion>(entity);
      if (!expansion || !expansion->getDefinition())
        continue;
      const auto range = expansion->getSourceRange();
      if (range.getBegin().isMacroID() || range.getEnd().isMacroID() ||
          !manager.isWrittenInMainFile(range.getBegin()) ||
          !manager.isWrittenInMainFile(range.getEnd()) ||
          manager.getSpellingLineNumber(range.getBegin()) !=
              manager.getSpellingLineNumber(range.getEnd()))
        continue;
      bool invalid = false;
      const auto invocation = clang::Lexer::getSourceText(
          clang::CharSourceRange::getTokenRange(range), manager,
          context.getLangOpts(), &invalid);
      const auto name = expansion->getName()->getName();
      if (invalid || !invocation.starts_with(name) ||
          !invocation.drop_front(name.size()).ltrim().starts_with("("))
        continue;
      const auto *definition = expansion->getDefinition();
      const auto spelling = clang::Lexer::getSourceText(
          clang::CharSourceRange::getTokenRange(definition->getSourceRange()),
          manager, context.getLangOpts(), &invalid);
      if (invalid || spelling.empty())
        continue;
      const auto location = manager.getSpellingLoc(definition->getLocation());
      auto definition_path = manager.getFilename(location);
      if (const auto file =
              manager.getFileEntryRefForID(manager.getFileID(location));
          file && !file->getFileEntry().tryGetRealPathName().empty())
        definition_path = file->getFileEntry().tryGetRealPathName();
      std::string key = name.str() + "\n" + definition_path.str() + "\n" +
                        std::to_string(manager.getFileOffset(location)) + "\n" +
                        spelling.str();
      const auto digest = llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(
          reinterpret_cast<const uint8_t *>(key.data()), key.size()));
      const size_t begin = manager.getFileOffset(range.getBegin());
      macros.emplace(begin,
                     Macro{begin + invocation.size(),
                           manager.getSpellingLineNumber(range.getBegin()),
                           llvm::toHex(digest, true),
                           invocation.str(),
                           {},
                           {}});
    }
  }

  std::string owning_function(clang::DynTypedNode node) {
    const clang::FunctionDecl *function = nullptr;
    while (!function) {
      auto parents = context.getParents(node);
      if (parents.size() != 1)
        return {};
      node = parents[0];
      if (node.get<clang::LambdaExpr>())
        return {};
      function = node.get<clang::FunctionDecl>();
    }
    if (function->isDependentContext())
      return {};
    if (const auto *method = llvm::dyn_cast<clang::CXXMethodDecl>(function))
      if (method->getParent()->isLambda())
        return {};
    return clang::ASTNameGenerator(context).getName(function);
  }

  void collect_variable(clang::SourceLocation location, std::string name,
                        const clang::DynTypedNode &node,
                        bool declaration = false) {
    auto &manager = context.getSourceManager();
    if (parse_failed || name.empty() || location.isInvalid() ||
        location.isMacroID() || !manager.isWrittenInMainFile(location))
      return;
    std::string function = owning_function(node);
    if (function.empty())
      return;
    variables[manager.getSpellingLineNumber(location)].push_back(
        {manager.getFileOffset(location), std::move(name), std::move(function),
         declaration});
  }

  bool VisitDeclRefExpr(clang::DeclRefExpr *expression) {
    if (llvm::isa<clang::VarDecl>(expression->getDecl()))
      collect_variable(expression->getLocation(),
                       expression->getDecl()->getNameAsString(),
                       clang::DynTypedNode::create(*expression));
    return true;
  }

  bool VisitVarDecl(clang::VarDecl *variable) {
    if (variable->isLocalVarDeclOrParm())
      collect_variable(variable->getLocation(), variable->getNameAsString(),
                       clang::DynTypedNode::create(*variable), true);
    return true;
  }

  bool VisitCXXThisExpr(clang::CXXThisExpr *expression) {
    if (!expression->isImplicit())
      collect_variable(expression->getBeginLoc(), "this",
                       clang::DynTypedNode::create(*expression));
    return true;
  }

  ct_value_type scalar_type(clang::QualType original) {
    const auto type = original.getCanonicalType();
    if (type->isVoidType() || type->isIncompleteType() ||
        type->isDependentType())
      return {};
    const auto bits = context.getTypeSize(type);
    if (!bits || bits > 64 || bits % 8)
      return {};
    ct_value_type result = {CT_VALUE_UNKNOWN, size_t(bits / 8)};
    if (type->isBooleanType())
      result.kind = CT_VALUE_BOOLEAN;
    else if (type->isIntegerType() || type->isEnumeralType())
      result.kind = type->isSignedIntegerOrEnumerationType()
                        ? CT_VALUE_SIGNED
                        : CT_VALUE_UNSIGNED;
    else if (type->isPointerType())
      result.kind = CT_VALUE_POINTER;
    else if (type->isRealFloatingType() && (bits == 32 || bits == 64))
      result.kind = CT_VALUE_FLOAT;
    return result.kind == CT_VALUE_UNKNOWN ? ct_value_type{} : result;
  }

  ct_value_type scalar_return_type(const clang::FunctionDecl *function) {
    const auto &target = context.getTargetInfo();
    if (!function || target.getTriple().getArch() != llvm::Triple::x86_64 ||
        !target.getTriple().isOSLinux())
      return {};
    const auto *prototype = function->getType()->getAs<clang::FunctionType>();
    if (!prototype || (prototype->getCallConv() != clang::CC_C &&
                       prototype->getCallConv() != clang::CC_X86_64SysV))
      return {};
    return scalar_type(function->getReturnType());
  }

  std::string function_spelling(const clang::FunctionDecl &function,
                                bool pointer) {
    const auto *prototype =
        function.getType()->getAs<clang::FunctionProtoType>();
    const auto *method = llvm::dyn_cast<clang::CXXMethodDecl>(&function);
    clang::PrintingPolicy policy(context.getLangOpts());
    policy.Restrict = true;
    std::string declarator = pointer ? "(" : "";
    if (prototype && prototype->getCallConv() != clang::CC_C)
      declarator +=
          "__attribute__((" +
          clang::FunctionType::getNameForCallConv(prototype->getCallConv())
              .str() +
          ")) ";
    if (pointer) {
      if (method && !method->isStatic())
        declarator += method->getParent()->getQualifiedNameAsString() + "::";
      declarator += "*)";
    } else
      declarator += function.getQualifiedNameAsString();
    declarator += '(';
    for (unsigned index = 0; index < function.getNumParams(); ++index) {
      if (index)
        declarator += ", ";
      const auto *parameter = function.getParamDecl(index);
      llvm::raw_string_ostream output(declarator);
      // Print the type around its name to preserve qualifiers and nested
      // declarators such as callback and array parameters.
      parameter->getOriginalType().print(output, policy,
                                         parameter->getNameAsString());
    }
    if (function.isVariadic()) {
      if (function.getNumParams())
        declarator += ", ";
      declarator += "...";
    } else if (prototype && !function.getNumParams() &&
               !context.getLangOpts().CPlusPlus)
      declarator += "void";
    declarator += ')';
    if (method && !method->isStatic()) {
      const auto qualifiers = method->getMethodQualifiers().getAsString();
      if (!qualifiers.empty())
        declarator += ' ' + qualifiers;
      if (method->getRefQualifier() == clang::RQ_LValue)
        declarator += " &";
      else if (method->getRefQualifier() == clang::RQ_RValue)
        declarator += " &&";
    }
    if (prototype && context.getLangOpts().CPlusPlus && prototype->isNothrow())
      declarator += " noexcept";
    std::string result;
    llvm::raw_string_ostream output(result);
    // The return type may itself be a function pointer. Clang places this
    // declarator inside that type instead of concatenating invalid syntax.
    function.getReturnType().print(output, policy, declarator);
    return result;
  }

  void collect_call_contract(const clang::FunctionDecl &callee,
                             clang::SourceLocation location,
                             const std::string &caller) {
    const auto &target = context.getTargetInfo();
    const auto *prototype = callee.getType()->getAs<clang::FunctionProtoType>();
    const auto *method = llvm::dyn_cast<clang::CXXMethodDecl>(&callee);
    const auto linkage = clang::ASTNameGenerator(context).getName(&callee);
    const auto key = std::make_tuple(
        context.getSourceManager().getSpellingLineNumber(location), caller,
        linkage);
    ct_source_call_info candidate;
    candidate.function = caller;
    candidate.callee = linkage;
    candidate.variadic = callee.isVariadic();
    bool valid =
        prototype && !linkage.empty() && linkage.size() < 1024 &&
        (!callee.getBuiltinID() ||
         context.BuiltinInfo.isPredefinedLibFunction(callee.getBuiltinID())) &&
        (!method || method->isStatic()) &&
        target.getTriple().getArch() == llvm::Triple::x86_64 &&
        target.getTriple().isOSLinux() &&
        (prototype->getCallConv() == clang::CC_C ||
         prototype->getCallConv() == clang::CC_X86_64SysV) &&
        !prototype->getRegParmType() &&
        (callee.getReturnType()->isVoidType() ||
         scalar_return_type(&callee).kind != CT_VALUE_UNKNOWN);
    clang::PrintingPolicy policy(context.getLangOpts());
    policy.Restrict = true;
    if (valid) {
      for (const auto *parameter : callee.parameters()) {
        ct_call_parameter description{};
        description.type = scalar_type(parameter->getType());
        const auto name = parameter->getNameAsString();
        const auto type_name = parameter->getOriginalType().getAsString(policy);
        if (description.type.kind == CT_VALUE_UNKNOWN ||
            parameter->hasAttr<clang::PassObjectSizeAttr>() ||
            name.size() >= sizeof(description.name) ||
            type_name.size() >= sizeof(description.type_name)) {
          valid = false;
          break;
        }
        std::memcpy(description.name, name.c_str(), name.size() + 1);
        std::memcpy(description.type_name, type_name.c_str(),
                    type_name.size() + 1);
        candidate.parameters.push_back(description);
      }
    }
    if (valid)
      candidate.declaration = function_spelling(callee, false);
    const auto previous = call_contracts.find(key);
    if (previous == call_contracts.end()) {
      call_contracts.emplace(key, valid ? std::optional(std::move(candidate))
                                        : std::nullopt);
      return;
    }
    if (valid && previous->second &&
        previous->second->declaration == candidate.declaration &&
        previous->second->variadic == candidate.variadic &&
        previous->second->parameters.size() == candidate.parameters.size()) {
      for (size_t index = 0; index < candidate.parameters.size(); ++index) {
        const auto &left = previous->second->parameters[index];
        const auto &right = candidate.parameters[index];
        if (std::strcmp(left.name, right.name) ||
            std::strcmp(left.type_name, right.type_name) ||
            left.type.kind != right.type.kind ||
            left.type.bytes != right.type.bytes) {
          valid = false;
          break;
        }
      }
    } else
      valid = false;
    if (!valid)
      previous->second.reset();
  }

  void collect_call_result(const clang::CallExpr &call,
                           const clang::FunctionDecl &callee,
                           const std::string &caller) {
    auto &manager = context.getSourceManager();
    const auto begin = call.getBeginLoc(), end = call.getEndLoc();
    if (begin.isInvalid() || end.isInvalid() || begin.isMacroID() ||
        end.isMacroID() || !manager.isWrittenInMainFile(begin) ||
        !manager.isWrittenInMainFile(end) ||
        manager.getSpellingLineNumber(begin) !=
            manager.getSpellingLineNumber(end))
      return;
    bool invalid = false;
    const auto text = clang::Lexer::getSourceText(
        clang::CharSourceRange::getTokenRange(begin, end), manager,
        context.getLangOpts(), &invalid);
    const auto finish = clang::Lexer::getLocForEndOfToken(
        end, 0, manager, context.getLangOpts());
    const auto linkage = clang::ASTNameGenerator(context).getName(&callee);
    ct_source_call_result_info candidate;
    if (invalid || finish.isInvalid() || text.empty() || linkage.empty() ||
        text.size() >= sizeof(candidate.result.text) ||
        linkage.size() >= sizeof(candidate.result.callee) ||
        text.find_first_of("\r\n") != llvm::StringRef::npos)
      return;
    candidate.function = caller;
    candidate.begin = manager.getFileOffset(begin);
    candidate.end = manager.getFileOffset(finish);
    candidate.result.id = candidate.begin + 1;
    candidate.result.begin_column = manager.getSpellingColumnNumber(begin);
    candidate.result.end_column = manager.getSpellingColumnNumber(finish);
    candidate.result.return_type = scalar_return_type(&callee);
    std::memcpy(candidate.result.text, text.data(), text.size());
    std::memcpy(candidate.result.callee, linkage.c_str(), linkage.size() + 1);
    const auto display_name = callee.getNameAsString();
    if (display_name.size() < sizeof(candidate.result.display_name))
      std::memcpy(candidate.result.display_name, display_name.c_str(),
                  display_name.size() + 1);
    call_results[manager.getSpellingLineNumber(begin)].push_back(
        std::move(candidate));
  }

  bool macro_functions(const Macro &macro, ct_source_macro &result) {
    if (macro.calls.empty())
      return false;
    clang::PrintingPolicy policy(context.getLangOpts());
    policy.Restrict = true;
    std::string text = macro.invocation + "=";
    if (macro.calls.size() > 1)
      text += '{';
    for (size_t call_index = 0; call_index < macro.calls.size(); ++call_index) {
      const auto *call = macro.calls[call_index];
      if (call_index)
        text += "; ";
      const auto *callee = call->getDirectCallee();
      std::string name;
      std::string linkage;
      if (callee) {
        name = callee->getQualifiedNameAsString();
        linkage = clang::ASTNameGenerator(context).getName(callee);
      } else {
        llvm::raw_string_ostream output(name);
        call->getCallee()->IgnoreParenImpCasts()->printPretty(output, nullptr,
                                                              policy);
      }
      const auto *method = llvm::dyn_cast_or_null<clang::CXXMethodDecl>(callee);
      std::string pointer_type;
      if (callee)
        pointer_type = function_spelling(*callee, true);
      else {
        llvm::raw_string_ostream output(pointer_type);
        call->getCallee()->getType().print(output, policy);
      }
      text += '(' + pointer_type + ')' + name + '=';
      const uint32_t address_begin = text.size();
      text += '?';
      const uint32_t address_end = text.size();
      const bool runtime = callee && !callee->getBuiltinID() &&
                           !linkage.empty() && (!method || method->isStatic());
      if (text.size() >= sizeof(result.text))
        return false;
      // Capacity limits disable runtime enrichment without deleting any
      // source call from the complete fallback expansion.
      if (macro.calls.size() <= std::size(result.calls)) {
        auto &descriptor = result.calls[result.call_count++];
        descriptor.address_begin = address_begin;
        descriptor.address_end = address_end;
        if (linkage.size() + 1 <=
            sizeof(result.callees) - result.callees_size) {
          descriptor.callee_offset = result.callees_size;
          std::memcpy(result.callees + result.callees_size, linkage.c_str(),
                      linkage.size() + 1);
          result.callees_size += linkage.size() + 1;
          descriptor.runtime_address = runtime;
        }
      }
    }
    if (macro.calls.size() > 1)
      text += '}';
    if (text.size() >= sizeof(result.text))
      return false;
    std::memcpy(result.text, text.c_str(), text.size() + 1);
    return true;
  }

  void record_expression(unsigned line, ct_source_expression candidate) {
    const auto previous = expressions.find(line);
    if (previous == expressions.end())
      expressions.emplace(line, std::move(candidate));
    else if (previous->second.function == candidate.function &&
             previous->second.begin <= candidate.begin &&
             previous->second.end >= candidate.end) {
      // A GNU statement expression may contain another standalone operation
      // on the same physical line. Its outer assignment owns the result.
      return;
    } else if (previous->second.function == candidate.function &&
               candidate.begin <= previous->second.begin &&
               candidate.end >= previous->second.end)
      previous->second = std::move(candidate);
    else
      ambiguous_lines.insert(line);
  }

  void collect_expression(clang::Stmt *statement, clang::Expr *expression,
                          clang::Expr *assignment, clang::VarDecl *variable,
                          ct_expression_kind kind) {
    if (parse_failed || !statement || !expression)
      return;
    auto &manager = context.getSourceManager();
    auto begin = statement->getBeginLoc(), end = statement->getEndLoc();
    if (begin.isInvalid() || end.isInvalid() || begin.isMacroID() ||
        end.isMacroID() || !manager.isWrittenInMainFile(begin))
      return;
    const unsigned line = manager.getSpellingLineNumber(begin);
    if (manager.getSpellingLineNumber(end) != line)
      return;
    std::vector<const clang::Stmt *> pending{statement};
    while (!pending.empty()) {
      const auto *node = pending.back();
      pending.pop_back();
      if (!node)
        continue;
      if (node->getBeginLoc().isMacroID() || node->getEndLoc().isMacroID() ||
          llvm::isa<clang::LambdaExpr>(node))
        return;
      for (const auto *child : node->children())
        pending.push_back(child);
    }
    auto parents = context.getParents(*statement);
    if (parents.size() != 1 || (kind != CT_EXPRESSION_RETURN &&
                                !parents[0].get<clang::CompoundStmt>()))
      return;
    clang::ASTNameGenerator names(context);
    ct_source_expression candidate;
    candidate.kind = kind;
    candidate.function =
        owning_function(clang::DynTypedNode::create(*statement));
    if (candidate.function.empty())
      return;
    bool invalid = false;
    candidate.text =
        clang::Lexer::getSourceText(
            clang::CharSourceRange::getTokenRange(expression->getSourceRange()),
            manager, context.getLangOpts(), &invalid)
            .str();
    if (invalid || candidate.text.empty() ||
        candidate.text.find_first_of("\r\n") != std::string::npos)
      return;
    if (assignment) {
      if (assignment->HasSideEffects(context))
        return;
      candidate.assignment =
          clang::Lexer::getSourceText(clang::CharSourceRange::getTokenRange(
                                          assignment->getSourceRange()),
                                      manager, context.getLangOpts(), &invalid)
              .str();
      if (invalid || candidate.assignment.empty())
        return;
    } else if (variable) {
      candidate.assignment = variable->getNameAsString();
      if (candidate.assignment.empty())
        return;
    }
    if (auto *call = llvm::dyn_cast<clang::CallExpr>(
            expression->IgnoreParenImpCasts())) {
      candidate.is_call = true;
      if (auto *callee = call->getDirectCallee()) {
        candidate.callee = names.getName(callee);
        candidate.return_type = scalar_return_type(callee);
      }
    }
    candidate.begin = manager.getFileOffset(begin);
    if (kind == CT_EXPRESSION_RETURN) {
      // A whole function on one line is unambiguous when its body consists
      // solely of this return. Include its declaration in the isolation span.
      if (const auto *body = parents[0].get<clang::CompoundStmt>();
          body && body->size() == 1 && *body->body_begin() == statement) {
        auto owners = context.getParents(*body);
        const auto *function =
            owners.size() == 1 ? owners[0].get<clang::FunctionDecl>() : nullptr;
        if (function && !function->getBeginLoc().isMacroID() &&
            manager.getSpellingLineNumber(function->getBeginLoc()) == line)
          candidate.begin = manager.getFileOffset(function->getBeginLoc());
      }
    }
    auto finish = clang::Lexer::getLocForEndOfToken(end, 0, manager,
                                                    context.getLangOpts());
    if (finish.isInvalid())
      return;
    candidate.end = manager.getFileOffset(finish);
    record_expression(line, std::move(candidate));
  }

  bool VisitReturnStmt(clang::ReturnStmt *statement) {
    collect_expression(statement, statement->getRetValue(), nullptr, nullptr,
                       CT_EXPRESSION_RETURN);
    return true;
  }

  bool VisitDeclStmt(clang::DeclStmt *statement) {
    if (!statement->isSingleDecl())
      return true;
    auto *variable = llvm::dyn_cast<clang::VarDecl>(statement->getSingleDecl());
    if (variable && variable->isLocalVarDecl() && variable->hasInit() &&
        !variable->isStaticLocal())
      collect_expression(statement, variable->getInit(), nullptr, variable,
                         CT_EXPRESSION_ASSIGNMENT);
    return true;
  }

  bool VisitBinaryOperator(clang::BinaryOperator *operation) {
    if (operation->isAssignmentOp())
      collect_expression(
          operation,
          operation->isCompoundAssignmentOp() ? operation : operation->getRHS(),
          operation->getLHS(), nullptr,
          operation->isCompoundAssignmentOp() ? CT_EXPRESSION_UPDATE
                                              : CT_EXPRESSION_ASSIGNMENT);
    return true;
  }

  bool VisitUnaryOperator(clang::UnaryOperator *operation) {
    if (operation->isIncrementDecrementOp())
      collect_expression(operation, operation, operation->getSubExpr(), nullptr,
                         CT_EXPRESSION_UPDATE);
    return true;
  }

  bool VisitCallExpr(clang::CallExpr *call) {
    collect_expression(call, call, nullptr, nullptr, CT_EXPRESSION_CALL);
    const auto *callee = call->getDirectCallee();
    if (parse_failed)
      return true;
    // Only a macro that supplies the callee is an expansion annotation.
    // ordinary_function(CONSTANT_MACRO) is still an ordinary function call.
    auto &manager = context.getSourceManager();
    const auto callee_location = call->getCallee()->getBeginLoc();
    const auto caller_location = manager.getExpansionLoc(callee_location);
    const auto caller = owning_function(clang::DynTypedNode::create(*call));
    if (callee && caller_location.isValid() &&
        manager.isWrittenInMainFile(caller_location) && !caller.empty()) {
      ++line_calls[{manager.getSpellingLineNumber(caller_location), caller,
                    clang::ASTNameGenerator(context).getName(callee)}];
      collect_call_contract(*callee, caller_location, caller);
      if (!callee_location.isMacroID())
        collect_call_result(*call, *callee, caller);
    }
    if (callee_location.isMacroID()) {
      const auto expansion = manager.getExpansionLoc(callee_location);
      if (manager.isWrittenInMainFile(expansion)) {
        const size_t offset = manager.getFileOffset(expansion);
        auto entry = macros.upper_bound(offset);
        if (entry != macros.begin()) {
          --entry;
          auto &macro = entry->second;
          const auto function =
              owning_function(clang::DynTypedNode::create(*call));
          if (offset < macro.end && !function.empty() &&
              (macro.function.empty() || macro.function == function)) {
            macro.function = function;
            macro.calls.push_back(call);
          }
        }
      }
    }
    if (!callee)
      return true;
    bool has_macro = false;
    std::vector<const clang::Stmt *> pending{call};
    while (!pending.empty()) {
      const auto *node = pending.back();
      pending.pop_back();
      if (!node)
        continue;
      has_macro |=
          node->getBeginLoc().isMacroID() || node->getEndLoc().isMacroID();
      for (const auto *child : node->children())
        pending.push_back(child);
    }
    if (!has_macro)
      return true;
    const clang::Expr *whole = call;
    while (true) {
      const auto parents = context.getParents(*whole);
      if (parents.size() != 1)
        return true;
      if (const auto *parent = parents[0].get<clang::ParenExpr>()) {
        whole = parent;
        continue;
      }
      if (const auto *parent = parents[0].get<clang::CastExpr>();
          parent && parent->getCastKind() == clang::CK_NoOp &&
          context.hasSameType(parent->getType(), whole->getType())) {
        whole = parent;
        continue;
      }
      if (const auto *parent = parents[0].get<clang::ConditionalOperator>();
          parent &&
          (parent->getTrueExpr() == whole || parent->getFalseExpr() == whole) &&
          context.hasSameType(parent->getType(), whole->getType())) {
        whole = parent;
        continue;
      }
      if (const auto *parent = parents[0].get<clang::BinaryOperator>();
          parent && parent->getOpcode() == clang::BO_Comma &&
          parent->getRHS() == whole &&
          context.hasSameType(parent->getType(), whole->getType())) {
        whole = parent;
        continue;
      }
      const auto *body = parents[0].get<clang::CompoundStmt>();
      if (!body)
        return true;
      const auto owners = context.getParents(*body);
      if (owners.size() != 1)
        return true;
      if (const auto *expression = owners[0].get<clang::StmtExpr>()) {
        // Only the final expression supplies a GNU statement-expression's
        // value. Calls in declarations, guards and discarded statements must
        // never be attributed to the surrounding macro's result.
        if (body->body_empty() || body->body_back() != whole ||
            !context.hasSameType(expression->getType(), whole->getType()))
          return true;
        whole = expression;
        continue;
      }
      // A macro-generated do/if block is a statement, not a value expression.
      if (body->getLBracLoc().isMacroID())
        return true;
      break;
    }
    const auto range = clang::Lexer::makeFileCharRange(
        clang::CharSourceRange::getTokenRange(whole->getSourceRange()), manager,
        context.getLangOpts());
    if (range.isInvalid() || !manager.isWrittenInMainFile(range.getBegin()) ||
        !manager.isWrittenInMainFile(range.getEnd()) ||
        manager.getSpellingLineNumber(range.getBegin()) !=
            manager.getSpellingLineNumber(range.getEnd()))
      return true;
    ct_source_expression candidate;
    candidate.function = owning_function(clang::DynTypedNode::create(*whole));
    if (candidate.function.empty())
      return true;
    candidate.kind = CT_EXPRESSION_CALL;
    candidate.is_call = true;
    candidate.macro_result = true;
    candidate.callee = clang::ASTNameGenerator(context).getName(callee);
    candidate.return_type = scalar_return_type(callee);
    candidate.text =
        clang::Lexer::getSourceText(range, manager, context.getLangOpts())
            .str();
    if (candidate.text.empty())
      return true;
    candidate.begin = manager.getFileOffset(range.getBegin());
    candidate.end = manager.getFileOffset(range.getEnd());
    record_expression(manager.getSpellingLineNumber(range.getBegin()),
                      std::move(candidate));
    return true;
  }

  bool VisitStmt(clang::Stmt *statement) {
    if (parse_failed)
      return true;
    auto &manager = context.getSourceManager();
    const auto add = [&](clang::Stmt *body, clang::SourceLocation begin,
                         bool loop, bool initializer) {
      if (!body || llvm::isa<clang::CompoundStmt>(body))
        return;
      const auto opening = body->getBeginLoc();
      const auto closing = body->getEndLoc();
      const auto end = loop ? statement->getEndLoc() : closing;
      for (const auto location : {begin, opening, closing, end})
        if (location.isInvalid() || location.isMacroID() ||
            !manager.isWrittenInMainFile(location))
          return;
      const auto after = clang::Lexer::getLocForEndOfToken(
          end, 0, manager, context.getLangOpts());
      const auto after_body = clang::Lexer::getLocForEndOfToken(
          closing, 0, manager, context.getLangOpts());
      if (after.isInvalid() || after_body.isInvalid() ||
          !manager.isWrittenInMainFile(after) ||
          !manager.isWrittenInMainFile(after_body))
        return;
      Block candidate;
      candidate.has_braces = false;
      candidate.info.function =
          owning_function(clang::DynTypedNode::create(*statement));
      if (candidate.info.function.empty())
        return;
      auto &block = candidate.info.block;
      block.id = manager.getFileOffset(opening) + 1;
      block.kind = CT_SOURCE_BLOCK_CONTROL;
      block.start_line = manager.getSpellingLineNumber(begin);
      block.opening_line = manager.getSpellingLineNumber(opening);
      block.opening_column = manager.getSpellingColumnNumber(opening);
      block.first_body_line = block.opening_line;
      block.closing_line = manager.getSpellingLineNumber(after_body);
      block.closing_column = manager.getSpellingColumnNumber(after_body) - 1;
      block.has_for_initializer = initializer;
      if (loop) {
        block.loop_start_column = manager.getSpellingColumnNumber(begin);
        block.loop_end_line = manager.getSpellingLineNumber(after);
        block.loop_end_column = manager.getSpellingColumnNumber(after);
      }
      const size_t first = manager.getFileOffset(begin);
      const size_t last = manager.getFileOffset(opening);
      if (first >= last || last > source.size())
        return;
      clang::Lexer lexer(manager.getLocForStartOfFile(manager.getMainFileID()),
                         context.getLangOpts(), source.begin(),
                         source.begin() + first, source.end());
      std::string header;
      size_t previous = first;
      clang::Token token;
      while (!lexer.LexFromRawLexer(token) && !token.is(clang::tok::eof)) {
        const size_t offset = manager.getFileOffset(token.getLocation());
        if (offset >= last)
          break;
        if (token.is(clang::tok::comment))
          continue;
        const auto spelling = source.substr(offset, token.getLength());
        if (spelling.contains('\n') || spelling.contains('\r'))
          return;
        if (offset > previous && !header.empty())
          header += ' ';
        header += spelling;
        previous = offset + token.getLength();
      }
      if (header.empty() || header.size() >= sizeof(block.opening_context))
        return;
      std::memcpy(block.opening_context, header.c_str(), header.size() + 1);
      candidate.opening_begin = candidate.opening_end = last;
      candidate.closing_begin = candidate.closing_end =
          manager.getFileOffset(after_body);
      blocks.push_back(std::move(candidate));
    };
    if (auto *loop = llvm::dyn_cast<clang::ForStmt>(statement))
      add(loop->getBody(), loop->getBeginLoc(), true, loop->getInit());
    else if (auto *loop = llvm::dyn_cast<clang::WhileStmt>(statement))
      add(loop->getBody(), loop->getBeginLoc(), true, false);
    else if (auto *loop = llvm::dyn_cast<clang::DoStmt>(statement))
      add(loop->getBody(), loop->getBeginLoc(), true, false);
    else if (auto *loop = llvm::dyn_cast<clang::CXXForRangeStmt>(statement))
      add(loop->getBody(), loop->getBeginLoc(), true, true);
    return true;
  }

  bool VisitCompoundStmt(clang::CompoundStmt *body) {
    auto &manager = context.getSourceManager();
    const auto opening = body->getLBracLoc();
    const auto closing = body->getRBracLoc();
    if (parse_failed || opening.isInvalid() || closing.isInvalid() ||
        opening.isMacroID() || closing.isMacroID() ||
        !manager.isWrittenInMainFile(opening) ||
        !manager.isWrittenInMainFile(closing))
      return true;
    const auto parents = context.getParents(*body);
    if (parents.size() != 1)
      return true;
    Block candidate;
    candidate.info.function =
        owning_function(clang::DynTypedNode::create(*body));
    if (candidate.info.function.empty())
      return true;
    auto &block = candidate.info.block;
    block.id = manager.getFileOffset(opening) + 1;
    block.opening_line = manager.getSpellingLineNumber(opening);
    block.opening_column = manager.getSpellingColumnNumber(opening);
    block.start_line = block.opening_line;
    block.closing_line = manager.getSpellingLineNumber(closing);
    block.closing_column = manager.getSpellingColumnNumber(closing);
    auto context_begin = opening;
    if (const auto *function = parents[0].get<clang::FunctionDecl>()) {
      context_begin = function->getBeginLoc();
    } else if (const auto *conditional = parents[0].get<clang::IfStmt>()) {
      context_begin = conditional->getElse() == body
                          ? conditional->getElseLoc()
                          : conditional->getBeginLoc();
      if (conditional->getThen() == body) {
        const auto ancestors = context.getParents(*conditional);
        if (ancestors.size() == 1)
          if (const auto *outer = ancestors[0].get<clang::IfStmt>();
              outer && outer->getElse() == conditional)
            context_begin = outer->getElseLoc();
      }
      if (context_begin.isValid() && !context_begin.isMacroID())
        block.start_line = manager.getSpellingLineNumber(context_begin);
    } else if (const auto *expression = parents[0].get<clang::StmtExpr>()) {
      context_begin = expression->getLParenLoc();
      auto node = clang::DynTypedNode::create(*expression);
      while (true) {
        const auto owners = context.getParents(node);
        if (owners.size() != 1)
          break;
        node = owners[0];
        if (node.get<clang::ParenExpr>() ||
            node.get<clang::ImplicitCastExpr>() ||
            node.get<clang::ExprWithCleanups>())
          continue;
        if (const auto *assignment = node.get<clang::BinaryOperator>();
            assignment && assignment->isAssignmentOp() &&
            assignment->getRHS()->IgnoreParenImpCasts() == expression)
          context_begin = assignment->getBeginLoc();
        else if (const auto *variable = node.get<clang::VarDecl>())
          context_begin = variable->getBeginLoc();
        else if (const auto *statement = node.get<clang::ReturnStmt>())
          context_begin = statement->getBeginLoc();
        break;
      }
    } else if (const auto *parent = parents[0].get<clang::Stmt>();
               parent && !llvm::isa<clang::CompoundStmt>(parent)) {
      context_begin = parent->getBeginLoc();
    }
    if (context_begin.isValid() && !context_begin.isMacroID() &&
        manager.isWrittenInMainFile(context_begin)) {
      const size_t begin = manager.getFileOffset(context_begin);
      const size_t finish = manager.getFileOffset(opening) + 1;
      if (begin < finish && finish <= source.size()) {
        clang::Lexer lexer(
            manager.getLocForStartOfFile(manager.getMainFileID()),
            context.getLangOpts(), source.begin(), source.begin() + begin,
            source.end());
        std::string text;
        size_t previous = begin;
        clang::Token token;
        while (!lexer.LexFromRawLexer(token) && !token.is(clang::tok::eof)) {
          const size_t offset = manager.getFileOffset(token.getLocation());
          if (offset >= finish)
            break;
          if (token.is(clang::tok::comment))
            continue;
          const auto spelling = source.substr(offset, token.getLength());
          // Do not rewrite multiline string tokens into a different value.
          if (spelling.contains('\n') || spelling.contains('\r')) {
            text.clear();
            break;
          }
          if (offset > previous && !text.empty())
            text += ' ';
          text += spelling;
          previous = offset + token.getLength();
        }
        if (!text.empty() && text.back() == '{' &&
            text.size() < sizeof(block.opening_context)) {
          std::memcpy(block.opening_context, text.c_str(), text.size() + 1);
          ct_source_closure_info closure;
          closure.closure.id = block.id;
          closure.closure.function_body =
              parents[0].get<clang::FunctionDecl>() != nullptr;
          std::memcpy(closure.closure.opening, text.c_str(), text.size() + 1);
          closure.function = candidate.info.function;
          closure.offset = manager.getFileOffset(closing);
          closures[block.closing_line].push_back(std::move(closure));
        }
      }
    }
    if (parents[0].get<clang::FunctionDecl>())
      return true;
    if (block.opening_line > block.closing_line)
      return true;
    block.first_body_line = body->body_empty()
                                ? block.closing_line
                                : manager.getExpansionLineNumber(
                                      (*body->body_begin())->getBeginLoc());
    candidate.opening_begin = manager.getFileOffset(opening);
    candidate.opening_end = candidate.opening_begin + 1;
    candidate.closing_begin = manager.getFileOffset(closing);
    candidate.closing_end = candidate.closing_begin + 1;
    if (const auto *expression = parents[0].get<clang::StmtExpr>()) {
      block.kind = CT_SOURCE_BLOCK_STATEMENT_EXPRESSION;
      if (expression->getLParenLoc().isMacroID() ||
          expression->getRParenLoc().isMacroID() ||
          manager.getSpellingLineNumber(expression->getLParenLoc()) !=
              block.opening_line ||
          manager.getSpellingLineNumber(expression->getRParenLoc()) !=
              block.closing_line)
        return true;
      candidate.opening_begin =
          manager.getFileOffset(expression->getLParenLoc());
      candidate.closing_end =
          manager.getFileOffset(expression->getRParenLoc()) + 1;
      auto node = clang::DynTypedNode::create(*expression);
      while (true) {
        auto owners = context.getParents(node);
        if (owners.size() != 1)
          break;
        node = owners[0];
        if (node.get<clang::ParenExpr>() ||
            node.get<clang::ImplicitCastExpr>() ||
            node.get<clang::ExprWithCleanups>())
          continue;
        std::string assignment;
        if (const auto *operation = node.get<clang::BinaryOperator>()) {
          if (!operation->isAssignmentOp() ||
              operation->getRHS()->IgnoreParenImpCasts() != expression ||
              operation->getLHS()->HasSideEffects(context))
            break;
          bool invalid = false;
          assignment = clang::Lexer::getSourceText(
                           clang::CharSourceRange::getTokenRange(
                               operation->getLHS()->getSourceRange()),
                           manager, context.getLangOpts(), &invalid)
                           .str();
          if (invalid)
            break;
        } else if (const auto *variable = node.get<clang::VarDecl>()) {
          if (variable->isLocalVarDecl() && !variable->isStaticLocal())
            assignment = variable->getNameAsString();
        }
        if (assignment.size() >= sizeof(block.assignment))
          candidate.complete = false;
        else
          std::memcpy(block.assignment, assignment.c_str(),
                      assignment.size() + 1);
        break;
      }
    } else if (const auto *parent = parents[0].get<clang::Stmt>();
               parent && !llvm::isa<clang::CompoundStmt>(parent)) {
      block.kind = CT_SOURCE_BLOCK_CONTROL;
      if (const auto *loop = llvm::dyn_cast<clang::ForStmt>(parent))
        block.has_for_initializer = loop->getInit() != nullptr;
      if (llvm::isa<clang::ForStmt, clang::WhileStmt, clang::DoStmt,
                    clang::CXXForRangeStmt>(parent)) {
        const auto begin = parent->getBeginLoc();
        const auto end = parent->getEndLoc();
        if (begin.isValid() && end.isValid() && !begin.isMacroID() &&
            !end.isMacroID() && manager.isWrittenInMainFile(begin) &&
            manager.isWrittenInMainFile(end)) {
          const auto after = clang::Lexer::getLocForEndOfToken(
              end, 0, manager, context.getLangOpts());
          if (after.isValid() && manager.isWrittenInMainFile(after)) {
            block.start_line = manager.getSpellingLineNumber(begin);
            block.loop_start_column = manager.getSpellingColumnNumber(begin);
            block.loop_end_line = manager.getSpellingLineNumber(after);
            block.loop_end_column = manager.getSpellingColumnNumber(after);
          }
        }
      }
    }
    blocks.push_back(std::move(candidate));
    return true;
  }

  bool VisitSwitchStmt(clang::SwitchStmt *statement) {
    if (parse_failed)
      return true;
    auto &manager = context.getSourceManager();
    const auto *body =
        llvm::dyn_cast<clang::CompoundStmt>(statement->getBody());
    if (!body)
      return true;
    const auto begin = statement->getBeginLoc();
    const auto opening = body->getLBracLoc();
    const auto closing = body->getRBracLoc();
    if (begin.isInvalid() || opening.isInvalid() || closing.isInvalid() ||
        begin.isMacroID() || opening.isMacroID() || closing.isMacroID() ||
        !manager.isWrittenInMainFile(begin) ||
        !manager.isWrittenInMainFile(opening) ||
        !manager.isWrittenInMainFile(closing))
      return true;
    const auto function =
        owning_function(clang::DynTypedNode::create(*statement));
    if (function.empty())
      return true;
    const uint64_t switch_id = manager.getFileOffset(begin) + 1;
    std::vector<const clang::SwitchCase *> cases;
    for (auto *label = statement->getSwitchCaseList(); label;
         label = label->getNextSwitchCase()) {
      if (label->getBeginLoc().isInvalid() ||
          label->getColonLoc().isInvalid() ||
          label->getBeginLoc().isMacroID() ||
          label->getColonLoc().isMacroID() ||
          !manager.isWrittenInMainFile(label->getBeginLoc()) ||
          !manager.isWrittenInMainFile(label->getColonLoc()))
        return true;
      cases.push_back(label);
    }
    std::sort(cases.begin(), cases.end(),
              [&](const auto *left, const auto *right) {
                return manager.getFileOffset(left->getBeginLoc()) <
                       manager.getFileOffset(right->getBeginLoc());
              });
    std::vector<CaseGroup> collected;
    collected.push_back({switch_id,
                         function,
                         {},
                         manager.getFileOffset(begin),
                         manager.getFileOffset(begin),
                         manager.getFileOffset(opening) + 1});
    for (size_t index = 0; index < cases.size();) {
      CaseGroup group{
          switch_id, function,
          {},        manager.getFileOffset(cases[index]->getBeginLoc()),
          0,         manager.getFileOffset(closing)};
      const uint64_t group_id = group.begin + 1;
      while (index < cases.size()) {
        const auto *label = cases[index];
        const size_t label_begin = manager.getFileOffset(label->getBeginLoc());
        const size_t label_end =
            manager.getFileOffset(label->getColonLoc()) + 1;
        if (label_end > source.size() || label_begin >= label_end)
          return true;
        const auto spelling = source.slice(label_begin, label_end);
        ct_source_case value{};
        if (spelling.size() >= sizeof(value.text))
          return true;
        value.switch_id = switch_id;
        value.group_id = group_id;
        value.id = label_begin + 1;
        value.line = manager.getSpellingLineNumber(label->getBeginLoc());
        std::memcpy(value.text, spelling.data(), spelling.size());
        // A label spanning lines remains one log record without rewriting
        // its expression tokens or comments.
        for (char &byte : value.text)
          if (byte == '\n' || byte == '\r')
            byte = ' ';
        group.labels.push_back(value);
        group.body_begin = label_end;
        ++index;
        if (index >= cases.size() || label->getSubStmt() != cases[index])
          break;
      }
      if (index < cases.size())
        group.end = manager.getFileOffset(cases[index]->getBeginLoc());
      collected.push_back(std::move(group));
    }
    case_groups.insert(case_groups.end(),
                       std::make_move_iterator(collected.begin()),
                       std::make_move_iterator(collected.end()));
    return true;
  }

  bool VisitFunctionDecl(clang::FunctionDecl *function) {
    if (!function->doesThisDeclarationHaveABody())
      return true;
    const auto *body =
        llvm::dyn_cast_or_null<clang::CompoundStmt>(function->getBody());
    if (!body || parse_failed || function->getBeginLoc().isMacroID() ||
        body->getLBracLoc().isMacroID())
      return true;
    auto &manager = context.getSourceManager();
    if (!manager.isWrittenInMainFile(function->getBeginLoc()))
      return true;
    // Constructor initializer lists execute before the compound body.
    if (const auto *constructor =
            llvm::dyn_cast<clang::CXXConstructorDecl>(function))
      if (constructor->getNumCtorInitializers())
        return true;
    unsigned first = manager.getSpellingLineNumber(function->getBeginLoc());
    unsigned last = manager.getSpellingLineNumber(body->getLBracLoc());
    if (!body->body_empty() &&
        manager.getExpansionLineNumber((*body->body_begin())->getBeginLoc()) <=
            last)
      --last; // A one-line body must keep its executable statement's values.
    for (unsigned line = first; line <= last; ++line)
      structural_lines.insert(line);
    if (first > last || function->isDependentContext())
      return true;
    if (const auto *method = llvm::dyn_cast<clang::CXXMethodDecl>(function))
      if (method->getParent()->isLambda())
        return true;
    const size_t begin = manager.getFileOffset(function->getBeginLoc());
    const size_t finish = manager.getFileOffset(body->getLBracLoc()) + 1;
    clang::Lexer lexer(manager.getLocForStartOfFile(manager.getMainFileID()),
                       context.getLangOpts(), source.begin(),
                       source.begin() + begin, source.end());
    ct_source_declaration declaration;
    declaration.function = clang::ASTNameGenerator(context).getName(function);
    declaration.line = first;
    for (const auto *parameter : function->parameters()) {
      const auto location = parameter->getLocation();
      if (parameter->getName().empty() || location.isMacroID() ||
          !manager.isWrittenInMainFile(location))
        continue;
      declaration.variables.push_back({manager.getFileOffset(location),
                                       parameter->getNameAsString(),
                                       declaration.function, true});
    }
    size_t previous = begin;
    clang::Token token;
    while (!lexer.LexFromRawLexer(token) && !token.is(clang::tok::eof)) {
      const size_t offset = manager.getFileOffset(token.getLocation());
      if (offset >= finish)
        break;
      if (token.is(clang::tok::comment))
        continue;
      const auto spelling = source.substr(offset, token.getLength());
      // A multiline token cannot be collapsed without changing its spelling.
      if (spelling.contains('\n') || spelling.contains('\r'))
        return true;
      if (offset > previous && !declaration.text.empty())
        declaration.text += ' ';
      declaration.text += spelling;
      previous = offset + token.getLength();
    }
    if (declaration.text.empty() || declaration.text.back() != '{')
      return true;
    for (unsigned line = first; line <= last; ++line)
      declarations.emplace(line, declaration);
    return true;
  }

  bool VisitGCCAsmStmt(clang::GCCAsmStmt *statement) {
    if (syntax < 0)
      return true;
    auto &manager = context.getSourceManager();
    auto begin = manager.getExpansionLoc(statement->getBeginLoc());
    if (!manager.isWrittenInMainFile(begin))
      return true;
    auto end = manager.getExpansionLoc(statement->getEndLoc());
    unsigned first_line = manager.getSpellingLineNumber(begin);
    unsigned last_line = manager.getSpellingLineNumber(end);
    std::string error;
    std::optional<std::string> converted;
    const auto *literal =
        llvm::dyn_cast<clang::StringLiteral>(statement->getAsmStringExpr());
    if (parse_failed)
      error =
          "source parse failed; compilation settings/headers are incomplete";
    else if (statement->getBeginLoc().isMacroID() || !literal ||
             literal->getBeginLoc().isMacroID() ||
             literal->getEndLoc().isMacroID())
      error =
          "macro-generated inline asm cannot be safely rewritten for display";
    else
      converted = convert_template(*statement, context, syntax,
                                   configured_syntax, error);
    if (converted) {
      size_t offset = manager.getFileOffset(literal->getBeginLoc());
      auto after = clang::Lexer::getLocForEndOfToken(
          literal->getEndLoc(), 0, manager, context.getLangOpts());
      size_t finish = manager.getFileOffset(after);
      std::string replacement;
      llvm::raw_string_ostream stream(replacement);
      stream << '"';
      stream.write_escaped(*converted);
      stream << '"';
      // Keep original DWARF line numbers even for concatenated string tokens.
      replacement.append(
          std::count(source.begin() + offset, source.begin() + finish, '\n'),
          '\n');
      edits.push_back({offset, finish, std::move(replacement)});
    } else {
      if (error.empty())
        error = "inline asm conversion is unavailable";
      for (unsigned line = first_line; line <= last_line; ++line)
        errors[line] = error;
    }
    return true;
  }
};

// Clang probes absent paths as well as opening resolved headers. Retaining
// those probes covers __has_include, include_next, and headers newly added
// earlier in the search order, including relative compilation-directory paths.
static std::string source_dependency_key(const std::string &path,
                                         bool listing = false) {
  return ct_analysis_file_key(path, listing);
}

class SourceDependencyFileSystem : public llvm::vfs::ProxyFileSystem {
public:
  std::map<std::string, std::string> dependencies;
  bool valid = true;

  SourceDependencyFileSystem() : ProxyFileSystem(ct_analysis_filesystem()) {}

  void record_error(const std::error_code &error) {
    // Missing include candidates are stable dependencies. Access and I/O
    // failures can be transient even when file contents remain unchanged.
    if (error && error != std::errc::no_such_file_or_directory &&
        error != std::errc::not_a_directory)
      valid = false;
  }

  void record(const llvm::Twine &path, bool listing = false) {
    llvm::SmallString<256> absolute;
    path.toVector(absolute);
    if (makeAbsolute(absolute)) {
      valid = false;
      return;
    }
    // Preserve symlink/.. spelling: lexical normalization could refer to a
    // different file than the one Clang actually probed.
    const std::string file = absolute.str().str();
    if (listing || !dependencies.count(file)) {
      const std::string identity = source_dependency_key(file, listing);
      valid &= !identity.empty();
      dependencies.insert_or_assign(file, identity);
    }
  }

  llvm::ErrorOr<llvm::vfs::Status> status(const llvm::Twine &path) override {
    record(path);
    auto result = ProxyFileSystem::status(path);
    record_error(result.getError());
    return result;
  }
  bool exists(const llvm::Twine &path) override {
    auto result = status(path);
    return result && result->exists();
  }
  llvm::ErrorOr<std::unique_ptr<llvm::vfs::File>>
  openFileForRead(const llvm::Twine &path) override {
    record(path);
    auto result = ProxyFileSystem::openFileForRead(path);
    record_error(result.getError());
    return result;
  }
  llvm::vfs::directory_iterator dir_begin(const llvm::Twine &path,
                                          std::error_code &error) override {
    record(path, true);
    auto result = ProxyFileSystem::dir_begin(path, error);
    record_error(error);
    return result;
  }
};

std::map<unsigned, ct_source_asm_line>
ct_analyze_source(std::string_view bytes, const char *path, int syntax,
                  const char *module, std::string *cache_identity,
                  const char *source_prefix,
                  const ct_source_compile_context *compile_context) {
  if (cache_identity)
    cache_identity->clear();
  std::map<unsigned, ct_source_asm_line> result;
  llvm::StringRef source(bytes.data(), bytes.size());
  std::vector<std::string> arguments;
  std::string explicit_directory;
  std::optional<int> configured_syntax;
  std::string database_error;
  auto filesystem = llvm::makeIntrusiveRefCnt<SourceDependencyFileSystem>();
  llvm::SmallString<256> source_path(path);
  const auto source_path_error = filesystem->makeAbsolute(source_path);
  std::unique_ptr<clang::tooling::CompilationDatabase> database;
  std::vector<std::string> database_sources;
  if (compile_context && llvm::sys::path::is_absolute(compile_context->source))
    database_sources.push_back(compile_context->source);
  if (!source_path_error &&
      (database_sources.empty() || database_sources.front() != source_path))
    database_sources.push_back(source_path.str().str());
  std::set<std::string> visited_directories;
  for (const auto &database_source : database_sources) {
    for (auto directory = llvm::sys::path::parent_path(database_source).str();
         !directory.empty() && visited_directories.insert(directory).second;) {
      for (const char *name : {"compile_commands.json", "compile_flags.txt"}) {
        llvm::SmallString<256> candidate(directory);
        llvm::sys::path::append(candidate, name);
        filesystem->record(candidate);
        auto input = ct_analysis_read_file(candidate.str().str());
        filesystem->record_error(input.getError());
        if (!input)
          continue;
        if (std::strcmp(name, "compile_commands.json") == 0)
          database = clang::tooling::JSONCompilationDatabase::loadFromBuffer(
              (*input)->getBuffer(), database_error,
              clang::tooling::JSONCommandLineSyntax::AutoDetect);
        else
          database = clang::tooling::FixedCompilationDatabase::loadFromBuffer(
              directory, (*input)->getBuffer(), database_error);
        if (database)
          break;
      }
      if (database)
        break;
      const auto parent = llvm::sys::path::parent_path(directory).str();
      if (parent == directory)
        break;
      directory = parent;
    }
    if (database)
      break;
  }
  bool have_command = false, incomplete_context = false;
  std::string language, standard;
  if (database) {
    database =
        clang::tooling::expandResponseFiles(std::move(database), filesystem);
    database = clang::tooling::inferTargetAndDriverMode(std::move(database));
    std::vector<clang::tooling::CompileCommand> commands;
    if (compile_context &&
        llvm::sys::path::is_absolute(compile_context->source))
      commands = database->getCompileCommands(compile_context->source);
    if (commands.empty())
      commands = database->getCompileCommands(source_path);
    if (commands.empty() &&
        (!compile_context || compile_context->arguments.empty())) {
      // An unrelated database entry is weaker evidence than explicit build
      // arguments (for example the configured kernel's Kbuild flags).
      database =
          clang::tooling::inferMissingCompileCommands(std::move(database));
      commands = database->getCompileCommands(source_path);
    }
    if (!commands.empty()) {
      have_command = true;
      const auto &command = commands.front();
      const auto extension = llvm::sys::path::extension(command.Filename);
      if (!extension.empty()) {
        const auto kind = clang::driver::types::lookupTypeForExtension(
            extension.drop_front());
        if (clang::driver::types::isCXX(kind))
          language = "c++";
        else if (kind == clang::driver::types::TY_C)
          language = "c";
      }
      auto adjusted = clang::tooling::getClangStripOutputAdjuster()(
          command.CommandLine, path);
      adjusted =
          clang::tooling::getClangStripDependencyFileAdjuster()(adjusted, path);
      for (size_t index = 1; index < adjusted.size(); ++index) {
        const auto &argument = adjusted[index];
        const auto argument_path = std::filesystem::path(argument);
        const auto input_path =
            (argument_path.is_absolute()
                 ? argument_path
                 : std::filesystem::path(command.Directory) / argument_path)
                .lexically_normal();
        if (argument == "-c" || argument == path ||
            argument == command.Filename ||
            input_path == std::filesystem::path(path).lexically_normal())
          continue;
        arguments.push_back(argument);
      }
      if (std::find(arguments.begin(), arguments.end(), "--driver-mode=g++") !=
          arguments.end())
        language = "c++";
      arguments.push_back("-working-directory=" + command.Directory);
    }
  }
  if (compile_context) {
    using namespace llvm::dwarf;
    // The extension of an inline header does not identify its CU's language.
    for (const auto &[code, name, dialect] :
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
      if (compile_context->language == code) {
        if (language.empty())
          language = name;
        standard = dialect;
        break;
      }
    }
    llvm::StringRef producer(compile_context->producer);
    if (producer.consume_front("GNU ")) {
      const auto dialect = producer.take_until([](char c) { return c == ' '; });
      for (const char *name :
           {"C89", "C99", "C11", "C17", "C23", "C++98", "C++03", "C++11",
            "C++14", "C++17", "C++20", "C++23"}) {
        if (dialect == name) {
          const bool cpp = dialect.starts_with("C++");
          if (language.empty())
            language = cpp ? "c++" : "c";
          standard = std::string(cpp ? "gnu++" : "gnu") +
                     dialect.drop_front(cpp ? 3 : 1).str();
          break;
        }
      }
    }
    if (!have_command) {
      bool have_directory = false;
      if (llvm::sys::path::is_absolute(compile_context->directory)) {
        auto status = filesystem->status(compile_context->directory);
        have_directory = status && status->isDirectory();
        if (have_directory) {
          arguments.push_back("-working-directory=" +
                              compile_context->directory);
          explicit_directory = compile_context->directory;
        }
      }
      llvm::BumpPtrAllocator allocator;
      llvm::StringSaver saver(allocator);
      llvm::SmallVector<const char *, 32> tokens;
      if (compile_context->arguments.empty())
        llvm::cl::TokenizeGNUCommandLine(compile_context->producer, saver,
                                         tokens);
      else
        for (const auto &argument : compile_context->arguments)
          tokens.push_back(saver.save(argument).data());
      const auto first =
          std::find_if(tokens.begin(), tokens.end(),
                       [](const char *token) { return token[0] == '-'; });
      llvm::ArrayRef<const char *> options(first, tokens.end());
      unsigned missing_index = 0, missing_count = 0;
      auto parsed = clang::driver::getDriverOptTable().ParseArgs(
          options, missing_index, missing_count);
      using namespace clang::driver::options;
      // Producer strings are descriptive, not a lossless build command.
      // Unclaimed operands can indicate lost quoting: do not guess their argv.
      incomplete_context = missing_count || parsed.hasArg(OPT_INPUT);
      if (!incomplete_context) {
        for (const auto *argument : parsed) {
          const auto &option = argument->getOption();
          bool allowed = option.matches(OPT_m_x86_Features_Group) ||
                         option.matches(OPT_m_x86_AVX10_Features_Group) ||
                         option.matches(OPT_O_Group);
          bool file_operand = false;
          switch (option.getID()) {
          case OPT_I:
          case OPT_isystem:
          case OPT_iquote:
          case OPT_idirafter:
          case OPT_include:
          case OPT_imacros:
            file_operand = true;
            [[fallthrough]];
          case OPT_nostdinc:
          case OPT_nostdincxx:
          case OPT_fms_extensions:
          case OPT_fno_builtin:
          case OPT_D:
          case OPT_U:
          case OPT_std_EQ:
          case OPT_ansi:
          case OPT_x:
          case OPT_march_EQ:
          case OPT_mtune_EQ:
          case OPT_masm_EQ:
          case OPT_m32:
          case OPT_m64:
          case OPT_mx32:
          case OPT_fshort_enums:
          case OPT_fno_short_enums:
          case OPT_fshort_wchar:
          case OPT_fno_short_wchar:
          case OPT_fsigned_char:
          case OPT_funsigned_char:
          case OPT_fno_signed_char:
          case OPT_fno_unsigned_char:
          case OPT_fpack_struct:
          case OPT_fpack_struct_EQ:
          case OPT_fgnu89_inline:
          case OPT_fno_gnu89_inline:
          case OPT_fexceptions:
          case OPT_fno_exceptions:
          case OPT_frtti:
          case OPT_fno_rtti:
          case OPT_fPIC:
          case OPT_fpic:
          case OPT_fPIE:
          case OPT_fpie:
          case OPT_pthread:
          case OPT_ffreestanding:
          case OPT_fhosted:
            allowed = true;
            break;
          default:
            break;
          }
          if (!allowed)
            continue;
          if (file_operand && !have_directory &&
              !llvm::sys::path::is_absolute(argument->getValue())) {
            incomplete_context = true;
            continue;
          }
          llvm::opt::ArgStringList rendered;
          argument->render(parsed, rendered);
          for (const char *text : rendered)
            arguments.emplace_back(text);
        }
      }
    }
  }
  std::string explicit_language;
  for (size_t index = 0; index < arguments.size(); ++index) {
    const llvm::StringRef argument(arguments[index]);
    if ((argument == "-x" || argument == "--language") &&
        index + 1 < arguments.size())
      explicit_language = arguments[++index];
    else if (argument.starts_with("-x") && argument.size() > 2)
      explicit_language = argument.drop_front(2).str();
    else if (argument.starts_with("--language="))
      explicit_language = argument.drop_front(11).str();
  }
  if (!explicit_language.empty())
    language = explicit_language;
  if (!standard.empty() && !language.empty() &&
      (language.find("++") != std::string::npos) !=
          (standard.find("++") != std::string::npos))
    standard.clear();
  if (!language.empty() && explicit_language.empty()) {
    arguments.push_back("-x");
    arguments.push_back(language);
  }
  if (!standard.empty() &&
      std::none_of(
          arguments.begin(), arguments.end(), [](const std::string &argument) {
            return argument.rfind("-std=", 0) == 0 || argument == "-ansi";
          }))
    arguments.push_back("-std=" + standard);
  for (const auto &argument : arguments) {
    if (argument == "-masm=intel")
      configured_syntax = 1;
    if (argument == "-masm=att")
      configured_syntax = 0;
  }
  arguments.push_back("-fsyntax-only");
  arguments.push_back("-Xclang");
  arguments.push_back("-detailed-preprocessing-record");
  arguments.push_back("-Wno-everything");
  arguments.push_back("-target");
  arguments.push_back("x86_64-pc-linux-gnu");
  // Header contents and include resolution are dependencies, not merely the
  // source's modification time. The manifest is checked on every helper run;
  // SourceFile keeps the resulting AST map in memory for subsequent requests.
  std::string settings = std::to_string(syntax);
  for (const auto &argument : arguments) {
    settings.push_back('\0');
    settings += argument;
  }
  for (const char *name :
       {"CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
        "SDKROOT", "GCC_EXEC_PREFIX", "COMPILER_PATH", "CCC_OVERRIDE_OPTIONS",
        "CLANG_CONFIG_FILE_SYSTEM_DIR", "CLANG_CONFIG_FILE_USER_DIR"}) {
    settings.push_back('\0');
    settings += name;
    settings += '=';
    if (const char *value = std::getenv(name))
      settings += value;
  }
  if (compile_context)
    for (const auto &argument : compile_context->arguments) {
      settings.push_back('\0');
      settings += argument;
    }
  const auto working_directory = filesystem->getCurrentWorkingDirectory();
  std::string key_directory =
      working_directory ? *working_directory : std::string{};
  // The restricted compile-context flags resolve relative includes against
  // this directory. Keep caller cwd for relative sources and unrestricted
  // database commands, whose driver config files can be read before the working
  // directory changes. Relative built-in config search paths also need it.
  bool directory_independent =
      !explicit_directory.empty() && llvm::sys::path::is_absolute(path);
#ifdef CLANG_CONFIG_FILE_SYSTEM_DIR
  directory_independent &=
      llvm::StringRef(CLANG_CONFIG_FILE_SYSTEM_DIR).empty() ||
      llvm::sys::path::is_absolute(CLANG_CONFIG_FILE_SYSTEM_DIR);
#endif
#ifdef CLANG_CONFIG_FILE_USER_DIR
  directory_independent &=
      llvm::StringRef(CLANG_CONFIG_FILE_USER_DIR).empty() ||
      llvm::sys::path::is_absolute(CLANG_CONFIG_FILE_USER_DIR);
#endif
  if (directory_independent)
    key_directory = explicit_directory;
  const std::string key = ct_cache_key(
      {"source-ast-v6", path, bytes, settings, key_directory,
       compile_context ? compile_context->producer : std::string{},
       compile_context ? compile_context->directory : std::string{},
       compile_context ? compile_context->source : std::string{},
       std::to_string(compile_context ? compile_context->language : 0)});
  std::map<std::string, std::string> dependencies;
  std::vector<unsigned char> cached;
  if (ct_cache_read("source", key, cached)) {
    ct_analysis_archive reader{cached, true};
    bool failed = false;
    std::string saved_identity;
    reader.fields(dependencies, failed, saved_identity, result);
    if (reader.complete() &&
        std::all_of(
            dependencies.begin(), dependencies.end(), [](const auto &entry) {
              return !entry.second.empty() &&
                     source_dependency_key(
                         entry.first, entry.second.rfind("listing:", 0) == 0) ==
                         entry.second;
            })) {
      if (cache_identity && !failed)
        *cache_identity = std::move(saved_identity);
      return result;
    }
    dependencies.clear();
    result.clear();
  }
  ct_analysis_progress progress{};
  std::snprintf(progress.stage, sizeof(progress.stage), "instrumentation");
  std::snprintf(progress.module, sizeof(progress.module), "%s",
                module ? module : path);
  std::snprintf(progress.file, sizeof(progress.file), "%s", path);
  std::snprintf(progress.source_prefix, sizeof(progress.source_prefix), "%s",
                source_prefix ? source_prefix : "");
  std::snprintf(progress.detail, sizeof(progress.detail), "source analysis: %s",
                path);
  ct_analysis_report_progress(&progress);
  clang::DiagnosticConsumer diagnostics;
  auto ast = clang::tooling::buildASTFromCodeWithArgs(
      source, arguments, path, "clang",
      std::make_shared<clang::PCHContainerOperations>(),
      clang::tooling::getClangStripDependencyFileAdjuster(), {}, &diagnostics,
      filesystem);
  if (!ast) {
    if (syntax < 0)
      return result;
    // Driver/compilation-database errors can prevent AST creation altogether.
    // Raw lexing still identifies asm keywords without treating comments or
    // strings as code, so an unconverted statement is not silently accepted.
    auto buffer = llvm::MemoryBuffer::getMemBufferCopy(source);
    clang::LangOptions language;
    language.CPlusPlus = true;
    language.CPlusPlus11 = true;
    clang::Lexer lexer(clang::SourceLocation::getFromRawEncoding(1), language,
                       buffer->getBufferStart(), buffer->getBufferStart(),
                       buffer->getBufferEnd());
    llvm::SmallVector<llvm::StringRef> lines;
    source.split(lines, '\n');
    clang::Token token;
    unsigned line = 1;
    size_t previous = 0;
    bool at_end;
    do {
      at_end = lexer.LexFromRawLexer(token);
      if (token.is(clang::tok::eof))
        break;
      const size_t offset = token.getLocation().getRawEncoding() - 1;
      line +=
          std::count(source.begin() + previous, source.begin() + offset, '\n');
      previous = offset;
      if (!token.is(clang::tok::raw_identifier))
        continue;
      auto spelling = token.getRawIdentifier();
      if (spelling == "asm" || spelling == "__asm" || spelling == "__asm__")
        result[line] = {
            lines[line - 1].str(),
            "source parser unavailable; compilation settings are unsupported",
            false,
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {},
            {}};
    } while (!at_end);
    return result;
  }
  bool parse_failed = incomplete_context ||
                      ast->getDiagnostics().hasErrorOccurred() ||
                      diagnostics.getNumErrors() != 0;
  SourceAsmVisitor visitor(ast->getASTContext(), source, syntax,
                           configured_syntax, parse_failed);
  visitor.collect_macros(ast->getPreprocessor().getPreprocessingRecord());
  visitor.TraverseDecl(ast->getASTContext().getTranslationUnitDecl());
  // The raw lexer handles comments/strings without inventing a C/C++ parser.
  auto &manager = ast->getSourceManager();
  clang::Lexer lexer(manager.getMainFileID(),
                     manager.getBufferOrFake(manager.getMainFileID()), manager,
                     ast->getLangOpts());
  std::map<unsigned, bool> braces;
  std::map<unsigned, std::vector<clang::Token>> tokens;
  clang::Token token;
  bool at_end;
  do {
    at_end = lexer.LexFromRawLexer(token);
    if (token.is(clang::tok::eof))
      break;
    unsigned line = manager.getSpellingLineNumber(token.getLocation());
    if (!token.is(clang::tok::comment))
      tokens[line].push_back(token);
    const bool brace = token.isOneOf(clang::tok::l_brace, clang::tok::r_brace,
                                     clang::tok::semi);
    auto [entry, inserted] = braces.emplace(line, brace);
    if (!inserted && !brace)
      entry->second = false;
  } while (!at_end);
  for (const auto &[line, structural] : braces)
    if (structural)
      visitor.structural_lines.insert(line);
  for (auto &[line, variables] : visitor.variables)
    std::stable_sort(variables.begin(), variables.end(),
                     [](const auto &left, const auto &right) {
                       return left.offset < right.offset;
                     });
  for (auto expression = visitor.expressions.begin();
       expression != visitor.expressions.end();) {
    const auto &line_tokens = tokens[expression->first];
    const auto &candidate = expression->second;
    bool isolated = !visitor.ambiguous_lines.count(expression->first) &&
                    !line_tokens.empty() &&
                    manager.getFileOffset(line_tokens.front().getLocation()) ==
                        candidate.begin;
    if (candidate.macro_result) {
      const auto occurrences = visitor.line_calls.find(
          {expression->first, candidate.function, candidate.callee});
      // A helper or condition may call the same function as the final value
      // producer. Source-line association cannot distinguish those returns.
      isolated &=
          occurrences != visitor.line_calls.end() && occurrences->second == 1;
    }
    bool semicolon = false;
    for (const auto &token : line_tokens) {
      const auto offset = manager.getFileOffset(token.getLocation());
      if (offset < candidate.end) {
        // DeclStmt's range includes its terminating semicolon; expression
        // ranges do not. Semicolons earlier inside GNU bodies are unrelated.
        semicolon |= token.is(clang::tok::semi) &&
                     offset + token.getLength() == candidate.end;
        continue;
      }
      if (!semicolon && token.is(clang::tok::semi))
        semicolon = true;
      else if (!semicolon || !token.is(clang::tok::r_brace))
        isolated = false;
    }
    if (!isolated || !semicolon)
      expression = visitor.expressions.erase(expression);
    else
      ++expression;
  }
  std::string display = source.str();
  std::sort(visitor.edits.begin(), visitor.edits.end(),
            [](const auto &left, const auto &right) {
              return left.begin > right.begin;
            });
  for (const auto &edit : visitor.edits)
    display.replace(edit.begin, edit.end - edit.begin, edit.replacement);
  llvm::SmallVector<llvm::StringRef> original_lines, display_lines;
  source.split(original_lines, '\n');
  llvm::StringRef(display).split(display_lines, '\n');
  std::map<unsigned, std::vector<clang::Token>> display_tokens;
  clang::Lexer display_lexer(clang::SourceLocation::getFromRawEncoding(1),
                             ast->getLangOpts(), display.data(), display.data(),
                             display.data() + display.size());
  unsigned display_line = 1;
  size_t previous_offset = 0;
  std::vector<std::pair<size_t, unsigned>> display_braces;
  std::set<size_t> multiline_braces;
  do {
    at_end = display_lexer.LexFromRawLexer(token);
    if (token.is(clang::tok::eof))
      break;
    const size_t offset = token.getLocation().getRawEncoding() - 1;
    display_line += std::count(display.begin() + previous_offset,
                               display.begin() + offset, '\n');
    previous_offset = offset;
    display_tokens[display_line].push_back(token);
    if (token.is(clang::tok::l_brace))
      display_braces.emplace_back(offset, display_line);
    else if (token.is(clang::tok::r_brace) && !display_braces.empty()) {
      const auto opening = display_braces.back();
      display_braces.pop_back();
      if (opening.second != display_line) {
        multiline_braces.insert(opening.first);
        multiline_braces.insert(offset);
      }
    }
  } while (!at_end);
  std::map<unsigned, std::vector<ct_source_highlight>> highlights;
  for (const auto &[line, line_tokens] : display_tokens) {
    if (!line || line > display_lines.size())
      continue;
    const size_t line_start =
        display_lines[line - 1].ltrim().data() - display.data();
    for (size_t index = 0; index < line_tokens.size(); ++index) {
      const auto &token = line_tokens[index];
      if (!token.isOneOf(clang::tok::l_brace, clang::tok::r_brace) ||
          !multiline_braces.count(token.getLocation().getRawEncoding() - 1))
        continue;
      size_t first = index, last = index;
      if (token.is(clang::tok::l_brace) && index &&
          line_tokens[index - 1].is(clang::tok::l_paren))
        --first;
      if (token.is(clang::tok::r_brace) && index + 1 < line_tokens.size() &&
          line_tokens[index + 1].is(clang::tok::r_paren)) {
        ++last;
        if (last + 1 < line_tokens.size() &&
            line_tokens[last + 1].is(clang::tok::semi))
          ++last;
      }
      const size_t begin =
          line_tokens[first].getLocation().getRawEncoding() - 1;
      const size_t end = line_tokens[last].getLocation().getRawEncoding() - 1 +
                         line_tokens[last].getLength();
      highlights[line].push_back(
          {uint32_t(begin - line_start), uint32_t(end - line_start)});
    }
  }
  std::map<unsigned, std::vector<ct_source_block_info>> source_blocks;
  std::map<unsigned, std::vector<ct_source_macro_info>> source_macros;
  std::map<unsigned, std::vector<ct_source_call_info>> source_calls;
  for (auto &[key, contract] : visitor.call_contracts)
    if (contract)
      source_calls[std::get<0>(key)].push_back(std::move(*contract));
  std::map<unsigned, std::vector<ct_source_case_info>> source_cases;
  std::stable_sort(visitor.case_groups.begin(), visitor.case_groups.end(),
                   [](const auto &left, const auto &right) {
                     return std::tie(left.switch_id, left.begin) <
                            std::tie(right.switch_id, right.begin);
                   });
  const auto display_offset = [&](size_t offset) {
    size_t result = offset;
    for (const auto &edit : visitor.edits)
      if (edit.end <= offset)
        result = result - (edit.end - edit.begin) + edit.replacement.size();
    return result;
  };
  for (auto &[line, closures] : visitor.closures) {
    if (!line || line > display_lines.size())
      continue;
    std::sort(closures.begin(), closures.end(),
              [](const auto &left, const auto &right) {
                return left.offset < right.offset;
              });
    const size_t display_start =
        display_lines[line - 1].ltrim().data() - display.data();
    for (auto &closure : closures)
      closure.display_offset = display_offset(closure.offset) - display_start;
  }
  for (const auto &group : visitor.case_groups) {
    for (size_t index = 0;
         index < original_lines.size() && index < display_lines.size();
         ++index) {
      const auto original = original_lines[index];
      const size_t line_begin = original.data() - source.data();
      const size_t line_end = line_begin + original.size();
      if (group.begin >= line_end || group.end <= line_begin)
        continue;
      const size_t begin = std::max(group.begin, line_begin);
      const size_t end = std::min(group.end, line_end);
      const size_t visible_begin = original.ltrim().data() - source.data();
      if (end <= visible_begin)
        continue;
      const size_t body_begin = std::min(
          end, std::max({group.body_begin, line_begin, visible_begin}));
      ct_source_case_info candidate;
      candidate.function = group.function;
      candidate.begin = begin;
      candidate.end = end;
      candidate.begin_column = begin - line_begin + 1;
      candidate.end_column = end - line_begin + 1;
      candidate.column_required =
          (group.begin > visible_begin && group.begin < line_end) ||
          group.end < line_end;
      const size_t display_start =
          display_lines[index].ltrim().data() - display.data();
      candidate.display_begin = display_offset(body_begin) - display_start;
      candidate.display_end = display_offset(end) - display_start;
      if (group.labels.empty()) {
        candidate.label.switch_id = group.switch_id;
        source_cases[index + 1].push_back(std::move(candidate));
      } else {
        for (const auto &label : group.labels) {
          candidate.label = label;
          source_cases[index + 1].push_back(candidate);
        }
      }
    }
  }
  for (const auto &[offset, macro] : visitor.macros) {
    if (macro.calls.empty() || macro.function.empty())
      continue;
    ct_source_macro_info annotation;
    if (!visitor.macro_functions(macro, annotation.macro))
      continue;
    std::memcpy(annotation.macro.identity, macro.identity.c_str(),
                macro.identity.size() + 1);
    annotation.function = macro.function;
    source_macros[macro.line].push_back(std::move(annotation));
  }
  std::sort(visitor.blocks.begin(), visitor.blocks.end(),
            [](const auto &left, const auto &right) {
              return left.info.block.id < right.info.block.id;
            });
  for (auto &candidate : visitor.blocks) {
    auto &block = candidate.info.block;
    if (!block.start_line || block.closing_line > original_lines.size())
      continue;
    const auto opening = original_lines[block.opening_line - 1].ltrim();
    const auto closing = original_lines[block.closing_line - 1].ltrim();
    const auto &opening_tokens = tokens[block.opening_line];
    const auto &closing_tokens = tokens[block.closing_line];
    block.opening_standalone = candidate.has_braces &&
                               opening_tokens.size() == 1 &&
                               opening_tokens.front().is(clang::tok::l_brace);
    if (block.kind == CT_SOURCE_BLOCK_STATEMENT_EXPRESSION) {
      for (const auto &token : closing_tokens) {
        const size_t offset = manager.getFileOffset(token.getLocation());
        if (offset >= candidate.closing_end) {
          if (token.is(clang::tok::semi))
            candidate.closing_end = offset + token.getLength();
          break;
        }
      }
    }
    block.closing_standalone =
        candidate.has_braces && !closing_tokens.empty() &&
        manager.getFileOffset(closing_tokens.front().getLocation()) ==
            candidate.closing_begin &&
        manager.getFileOffset(closing_tokens.back().getLocation()) +
                closing_tokens.back().getLength() ==
            candidate.closing_end;
    const size_t opening_offset = opening.data() - source.data();
    const size_t closing_offset = closing.data() - source.data();
    candidate.complete &= opening.size() < sizeof(block.opening) &&
                          closing.size() < sizeof(block.closing) &&
                          candidate.opening_begin >= opening_offset &&
                          candidate.closing_begin >= closing_offset;
    if (candidate.complete) {
      std::memcpy(block.opening, opening.data(), opening.size());
      std::memcpy(block.closing, closing.data(), closing.size());
      block.opening_highlight_begin = candidate.opening_begin - opening_offset;
      block.opening_highlight_end = candidate.opening_end - opening_offset;
      block.closing_highlight_begin = candidate.closing_begin - closing_offset;
      block.closing_highlight_end = candidate.closing_end - closing_offset;
      std::set<std::string> seen;
      for (const auto &variable : visitor.variables[block.opening_line]) {
        if (variable.function != candidate.info.function ||
            !seen.insert(variable.name).second)
          continue;
        const size_t size = variable.name.size() + 1;
        if (size > sizeof(block.variables) - block.variables_size) {
          candidate.complete = false;
          break;
        }
        std::memcpy(block.variables + block.variables_size,
                    variable.name.c_str(), size);
        block.variables_size += size;
      }
    }
    candidate.info.complete = candidate.complete;
    for (uint64_t line = block.start_line;
         line <= std::max(block.closing_line, block.loop_end_line); ++line)
      source_blocks[line].push_back(candidate.info);
  }
  for (size_t index = 0;
       index < original_lines.size() && index < display_lines.size(); ++index) {
    unsigned line = (unsigned)index + 1;
    auto error = visitor.errors.find(line);
    if (original_lines[index] != display_lines[index] ||
        error != visitor.errors.end() || visitor.structural_lines.count(line) ||
        visitor.expressions.count(line) || visitor.variables.count(line) ||
        visitor.declarations.count(line) || source_blocks.count(line) ||
        highlights.count(line) || source_macros.count(line) ||
        source_cases.count(line) || visitor.closures.count(line) ||
        source_calls.count(line) || visitor.call_results.count(line))
      result[line] = {
          display_lines[index].str(),
          error == visitor.errors.end() ? "" : error->second,
          visitor.structural_lines.count(line) != 0,
          visitor.expressions.count(line) ? visitor.expressions.at(line)
                                          : ct_source_expression{},
          visitor.variables.count(line) ? std::move(visitor.variables.at(line))
                                        : std::vector<ct_source_variable>{},
          visitor.declarations.count(line) ? visitor.declarations.at(line)
                                           : ct_source_declaration{},
          source_blocks.count(line) ? std::move(source_blocks.at(line))
                                    : std::vector<ct_source_block_info>{},
          highlights.count(line) ? std::move(highlights.at(line))
                                 : std::vector<ct_source_highlight>{},
          source_macros.count(line) ? std::move(source_macros.at(line))
                                    : std::vector<ct_source_macro_info>{},
          source_cases.count(line) ? std::move(source_cases.at(line))
                                   : std::vector<ct_source_case_info>{},
          visitor.closures.count(line) ? std::move(visitor.closures.at(line))
                                       : std::vector<ct_source_closure_info>{},
          source_calls.count(line) ? std::move(source_calls.at(line))
                                   : std::vector<ct_source_call_info>{},
          visitor.call_results.count(line)
              ? std::move(visitor.call_results.at(line))
              : std::vector<ct_source_call_result_info>{}};
  }
  // Reuse reproducible parse failures as well as successful results. The
  // visitor already omits semantic claims after an error; preserve that
  // fallback and its failed status, without a successful location identity.
  // Missing includes and compilation databases are dependencies, so fixing
  // them invalidates a failed entry instead of permanently suppressing work.
  parse_failed |= ast->getDiagnostics().hasErrorOccurred() ||
                  diagnostics.getNumErrors() != 0;
  bool cacheable = working_directory && filesystem->valid;
  dependencies = filesystem->dependencies;
  // These builtin expansions depend on the current time or file metadata,
  // rather than the source contents. Keep their results only for this run.
  if (auto *record = ast->getPreprocessor().getPreprocessingRecord())
    for (auto *entity : *record)
      if (const auto *expansion = llvm::dyn_cast<clang::MacroExpansion>(entity);
          expansion && expansion->isBuiltinMacro()) {
        const auto name = expansion->getName()->getName();
        if (name == "__DATE__" || name == "__TIME__" || name == "__TIMESTAMP__")
          cacheable = false;
      }
  for (auto entry = manager.fileinfo_begin(); entry != manager.fileinfo_end();
       ++entry) {
    llvm::SmallString<256> absolute(entry->first.getName());
    if (filesystem->makeAbsolute(absolute)) {
      cacheable = false;
      break;
    }
    const std::string file = absolute.str().str();
    auto contents = entry->second->getBufferOrNone(ast->getDiagnostics(),
                                                   ast->getFileManager());
    auto current = ct_analysis_read_file(file);
    if (!contents || !current ||
        contents->getBuffer() != (*current)->getBuffer()) {
      cacheable = false;
      break;
    }
    dependencies[file] = source_dependency_key(file);
  }
  cacheable &= std::all_of(
      dependencies.begin(), dependencies.end(), [](const auto &entry) {
        return !entry.second.empty() &&
               source_dependency_key(entry.first,
                                     entry.second.rfind("listing:", 0) == 0) ==
                   entry.second;
      });
  if (cacheable) {
    std::vector<unsigned char> manifest;
    ct_analysis_archive manifest_writer{manifest, false};
    manifest_writer.field(dependencies);
    std::string identity = ct_cache_key(
        {key, std::string_view(reinterpret_cast<const char *>(manifest.data()),
                               manifest.size())});
    cached.clear();
    ct_analysis_archive writer{cached, false};
    writer.fields(dependencies, parse_failed, identity, result);
    ct_cache_write("source", key, cached);
    if (cache_identity && !parse_failed)
      *cache_identity = std::move(identity);
  }
  return result;
}
