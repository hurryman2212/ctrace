#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <tuple>
#include <utility>

#include <llvm/ADT/StringExtras.h>
#include <llvm/BinaryFormat/Dwarf.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCExpr.h>
#include <llvm/MC/MCFixup.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <elf.h>

#include "kernel_capture.h"
#include "kernel_decompile.h"
#include "kernel_flow.h"

static constexpr size_t kernel_decompile_site_limit = 1000000;
static constexpr size_t kernel_decompile_pool_limit = 65536;
static constexpr size_t kernel_decompile_text_limit = 64 * 1024 * 1024;
static constexpr unsigned kernel_decompile_layout_depth = 64;

static bool decompile_reserve(size_t &used, size_t extra, size_t limit,
                              std::string &error) {
  if (used > limit || extra > limit - used) {
    error = "kernel decompile metadata exceeds its bound";
    return false;
  }
  used += extra;
  return true;
}

static std::string decompile_assignment(const std::string &text) {
  const auto equal = text.find('=');
  if (equal == std::string::npos || !equal ||
      (equal + 1 < text.size() && text[equal + 1] == '=') ||
      std::string("=!<>").find(text[equal - 1]) != std::string::npos)
    return {};
  size_t end = equal;
  while (end && std::isspace(static_cast<unsigned char>(text[end - 1])))
    --end;
  if (end && std::string("+-*/%&|^").find(text[end - 1]) != std::string::npos)
    --end;
  while (end && std::isspace(static_cast<unsigned char>(text[end - 1])))
    --end;
  size_t begin = end;
  while (begin && (std::isalnum(static_cast<unsigned char>(text[begin - 1])) ||
                   text[begin - 1] == '_'))
    --begin;
  if (begin == end || std::isdigit(static_cast<unsigned char>(text[begin])))
    return {};
  for (size_t index = 0; index < begin; ++index)
    if (!std::isalnum(static_cast<unsigned char>(text[index])) &&
        !std::isspace(static_cast<unsigned char>(text[index])) &&
        text[index] != '_' && text[index] != '*')
      return {};
  return text.substr(begin, end - begin);
}

bool ct_kernel_decompile_identifier(const std::string &text,
                                    const std::string &name) {
  if (name.empty())
    return false;
  for (size_t position = 0; position < text.size();) {
    if (text.compare(position, 2, "//") == 0) {
      const auto end = text.find('\n', position + 2);
      position = end == std::string::npos ? text.size() : end + 1;
    } else if (text.compare(position, 2, "/*") == 0) {
      const auto end = text.find("*/", position + 2);
      position = end == std::string::npos ? text.size() : end + 2;
    } else if (text[position] == '"' || text[position] == '\'') {
      const char quote = text[position++];
      while (position < text.size()) {
        const char character = text[position++];
        if (character == '\\' && position < text.size())
          ++position;
        else if (character == quote)
          break;
      }
    } else if (std::isalpha(static_cast<unsigned char>(text[position])) ||
               text[position] == '_') {
      const size_t begin = position++;
      while (position < text.size() &&
             (std::isalnum(static_cast<unsigned char>(text[position])) ||
              text[position] == '_'))
        ++position;
      if (position - begin == name.size() &&
          text.compare(begin, name.size(), name) == 0)
        return true;
    } else {
      ++position;
    }
  }
  return false;
}

bool ct_kernel_complete_decompile_returns(
    ct_kernel_value_metadata &values, ct_kernel_decompile_metadata &metadata,
    std::string &error) {
  error.clear();
  size_t binding_count = 0, references = 0;
  for (const auto &site : values.sites)
    if (!decompile_reserve(binding_count, site.bindings.size(),
                           kernel_decompile_site_limit, error))
      return false;
  for (const auto &site : metadata.sites)
    if (!decompile_reserve(references, site.variables.size(),
                           kernel_decompile_site_limit, error))
      return false;
  size_t text_bytes = 0;
  for (const auto &function : metadata.functions)
    if (!decompile_reserve(text_bytes,
                           function.name.size() + function.prototype.size(),
                           kernel_decompile_text_limit, error))
      return false;
  for (const auto &site : metadata.sites)
    if (!decompile_reserve(text_bytes,
                           site.control_text.size() + site.control_kind.size(),
                           kernel_decompile_text_limit, error))
      return false;
  for (const auto &statement : metadata.statements)
    if (!decompile_reserve(
            text_bytes,
            statement.text.size() + statement.declaration_name.size() +
                statement.declaration_type.size() + statement.assignment.size(),
            kernel_decompile_text_limit, error))
      return false;
  for (const auto &block : metadata.blocks)
    if (!decompile_reserve(text_bytes, block.header.size(),
                           kernel_decompile_text_limit, error))
      return false;
  uint32_t return_recipe = 0;
  for (size_t index = 1; index < values.recipes.size(); ++index) {
    const auto &recipe = values.recipes[index];
    if (recipe.error.empty() && recipe.operations.size() == 1 &&
        recipe.operations.front().opcode == llvm::dwarf::DW_OP_regx &&
        recipe.operations.front().operand == 0)
      return_recipe = uint32_t(index);
  }
  std::map<std::string, uint64_t> registers;
  for (const auto &candidate_site : values.sites)
    for (const auto &binding : candidate_site.bindings) {
      const auto &candidate = values.variables[binding.variable];
      const size_t width = candidate.name == "RAX"   ? 8
                           : candidate.name == "EAX" ? 4
                           : candidate.name == "AX"  ? 2
                           : candidate.name == "AL"  ? 1
                                                     : 0;
      if (!candidate.register_alias || !width || !candidate.type ||
          candidate.type >= values.types.size() ||
          values.types[candidate.type].scalar.bytes != width || !binding.recipe)
        continue;
      const auto &recipe = values.recipes[binding.recipe];
      if (recipe.error.empty() && recipe.operations.size() == 1 &&
          recipe.operations.front().opcode == llvm::dwarf::DW_OP_regx &&
          recipe.operations.front().operand == 0)
        registers.emplace(candidate.name, candidate.id);
    }
  for (size_t index = 1; index < metadata.sites.size(); ++index) {
    auto &site = metadata.sites[index];
    if (!site.returned || site.statement || !site.function ||
        site.function >= metadata.functions.size() ||
        index >= values.sites.size())
      continue;
    const auto function = metadata.functions[site.function].value_function;
    if (!function || function >= values.functions.size())
      continue;
    if (metadata.statements.size() >= kernel_decompile_site_limit ||
        values.types.size() >= kernel_decompile_pool_limit ||
        values.variables.size() >= kernel_decompile_pool_limit ||
        values.recipes.size() >= kernel_decompile_pool_limit ||
        binding_count >= kernel_decompile_site_limit ||
        references >= kernel_decompile_site_limit) {
      error = "kernel decompile return metadata exceeds its bound";
      return false;
    }
    const auto &returned = values.functions[function];
    ct_kernel_decompile_statement statement;
    statement.function = site.function;
    statement.sites.push_back(index);
    if (returned.returns_void) {
      statement.text = "return;";
    } else {
      if (!returned.return_type || returned.return_type >= values.types.size())
        continue;
      const auto &definition = values.types[returned.return_type];
      const auto &type = definition.scalar;
      const size_t width = type.bytes;
      if ((width != 1 && width != 2 && width != 4 && width != 8) ||
          type.kind == CT_VALUE_FLOAT || type.kind > CT_VALUE_POINTER ||
          type.kind < CT_VALUE_UNKNOWN ||
          (type.kind == CT_VALUE_UNKNOWN && !definition.raw_scalar))
        continue;
      const std::string name = width == 8   ? "RAX"
                               : width == 4 ? "EAX"
                               : width == 2 ? "AX"
                                            : "AL";
      uint64_t variable = registers[name];
      if (!variable) {
        const auto type_id = uint32_t(values.types.size());
        values.types.push_back({{CT_VALUE_UNKNOWN, width},
                                "uint" + std::to_string(width * 8) + "_t",
                                false,
                                true});
        variable = values.variables.size();
        ct_kernel_value_variable definition;
        definition.id = variable;
        definition.type = type_id;
        definition.name = name;
        definition.global = true;
        definition.register_alias = true;
        values.variables.push_back(std::move(definition));
        registers[name] = variable;
      }
      if (!return_recipe) {
        return_recipe = uint32_t(values.recipes.size());
        values.recipes.push_back({{{llvm::dwarf::DW_OP_regx, 0, 0}}, {}});
      }
      auto &bindings = values.sites[index].bindings;
      if (std::none_of(bindings.begin(), bindings.end(),
                       [&](const auto &binding) {
                         return binding.variable == variable;
                       })) {
        bindings.push_back({variable, return_recipe});
        ++binding_count;
      }
      site.variables.push_back({variable, CT_DECOMPILED_READ});
      ++references;
      statement.text = "return " + name + ';';
    }
    site.statement = uint32_t(metadata.statements.size());
    site.index = 0;
    if (!decompile_reserve(text_bytes, statement.text.size(),
                           kernel_decompile_text_limit, error))
      return false;
    metadata.statements.push_back(std::move(statement));
  }
  return true;
}

bool ct_kernel_collect_decompile(
    const ct_kernel_image &image, const std::vector<ct_kernel_site> &sites,
    const ct_kernel_source_metadata &source,
    const ct_kernel_decompile_layout &layout,
    const std::function<bool(uint32_t, uint64_t, ct_decompile_view &,
                             std::string &)> &load_function,
    ct_kernel_value_metadata &values, ct_kernel_decompile_metadata &metadata,
    std::string &error) {
  error.clear();
  metadata = {};
  metadata.layout = layout;
  if (!load_function || values.types.empty() || values.variables.empty() ||
      values.recipes.empty() || values.functions.empty() ||
      values.types.size() >= kernel_decompile_pool_limit ||
      values.variables.size() >= kernel_decompile_pool_limit ||
      values.recipes.size() >= kernel_decompile_pool_limit ||
      values.functions.size() >= kernel_decompile_pool_limit ||
      values.layout_types.size() >= kernel_decompile_pool_limit ||
      values.layout_members.size() > kernel_decompile_site_limit) {
    error = "invalid kernel decompile normalization inputs";
    return false;
  }
  size_t binding_count = 0, reference_count = 0, text_bytes = 0;
  size_t block_memberships = 0;
  for (const auto &site : values.sites)
    if (!decompile_reserve(binding_count, site.bindings.size(),
                           kernel_decompile_site_limit, error))
      return false;
  using RecipeKey =
      std::vector<std::tuple<uint8_t, uint64_t, uint64_t, uint32_t>>;
  std::map<RecipeKey, uint32_t> recipes;
  const auto intern_recipe = [&](const ct_kernel_value_recipe &recipe) {
    RecipeKey key;
    for (const auto &operation : recipe.operations)
      key.emplace_back(operation.opcode, operation.operand, operation.operand2,
                       operation.section);
    const auto found = recipes.find(key);
    if (found != recipes.end())
      return found->second;
    if (values.recipes.size() >= kernel_decompile_pool_limit) {
      error = "kernel decompile location pool exceeds its bound";
      return uint32_t(0);
    }
    const auto id = uint32_t(values.recipes.size());
    values.recipes.push_back(recipe);
    recipes.emplace(std::move(key), id);
    return id;
  };
  for (size_t index = 1; index < values.recipes.size(); ++index) {
    const auto &recipe = values.recipes[index];
    if (recipe.error.empty() && !recipe.operations.empty()) {
      RecipeKey key;
      for (const auto &operation : recipe.operations)
        key.emplace_back(operation.opcode, operation.operand,
                         operation.operand2, operation.section);
      recipes.emplace(std::move(key), uint32_t(index));
    }
  }
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();
  const llvm::Triple triple("x86_64-pc-linux-gnu");
  const auto *target = llvm::TargetRegistry::lookupTarget(triple.str(), error);
  if (!target)
    return false;
  llvm::MCTargetOptions target_options;
  std::unique_ptr<llvm::MCRegisterInfo> machine_registers(
      target->createMCRegInfo(triple.str()));
  std::unique_ptr<llvm::MCAsmInfo> assembly(target->createMCAsmInfo(
      *machine_registers, triple.str(), target_options));
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget(
      target->createMCSubtargetInfo(triple.str(), "generic", ""));
  std::unique_ptr<llvm::MCInstrInfo> instructions(target->createMCInstrInfo());
  llvm::MCContext context(triple, assembly.get(), machine_registers.get(),
                          subtarget.get());
  std::unique_ptr<llvm::MCDisassembler> decoder(
      target->createMCDisassembler(*subtarget, context));
  std::unique_ptr<llvm::MCCodeEmitter> encoder(
      target->createMCCodeEmitter(*instructions, context));
  const auto *memory_symbol =
      llvm::MCSymbolRefExpr::create(context.createTempSymbol(), context);
  if (!decoder || !instructions || !encoder) {
    error = "kernel decompile access decoder unavailable";
    return false;
  }
  std::map<uint64_t, const ct_kernel_site *> addresses;
  const auto original_address = [&](uint64_t address, uint32_t &section,
                                    uint64_t &offset) {
    if (address > UINT64_MAX - layout.image_base)
      return false;
    address += layout.image_base;
    for (const auto &region : layout.regions)
      if (address >= region.address && address - region.address < region.size) {
        section = region.section;
        offset = address - region.address;
        return section < image.sections.size();
      }
    return false;
  };
  uint64_t maximum = 0;
  for (const auto &site : sites) {
    if (!site.probe)
      continue;
    if (!site.id || site.id > kernel_decompile_site_limit) {
      error = "kernel decompile probe identity exceeds limit";
      return false;
    }
    maximum = std::max(maximum, site.id);
    for (const auto &region : layout.regions)
      if (region.section == site.section && site.offset < region.size &&
          region.address >= layout.image_base &&
          site.offset <= UINT64_MAX - region.address) {
        const auto address = region.address - layout.image_base + site.offset;
        if (!addresses.emplace(address, &site).second) {
          error = "ambiguous kernel decompile instruction address";
          return false;
        }
      }
  }
  metadata.sites.resize(maximum + 1);
  values.sites.resize(std::max(values.sites.size(), metadata.sites.size()));
  const auto known_labels = [&](const std::string &text) {
    for (size_t position = 0; position < text.size();) {
      if (text[position] == '"' || text[position] == '\'') {
        const char quote = text[position++];
        while (position < text.size()) {
          const char character = text[position++];
          if (character == '\\' && position < text.size())
            ++position;
          else if (character == quote)
            break;
        }
      } else if (text.compare(position, 2, "@L") == 0) {
        const auto end = text.find('@', position + 2);
        if (end == std::string::npos)
          return false;
        uint64_t address = 0;
        const auto parsed = std::from_chars(text.data() + position + 2,
                                            text.data() + end, address, 16);
        if (parsed.ec != std::errc() || parsed.ptr != text.data() + end ||
            (!addresses.count(address) &&
             !layout.external_symbols.count(address)))
          return false;
        position = end + 1;
      } else {
        ++position;
      }
    }
    return true;
  };
  const auto source_available = [&](uint64_t site) {
    return ct_kernel_source_row(source, site) != 0;
  };
  std::map<std::tuple<unsigned, uint64_t, std::string, bool, bool, uint32_t>,
           uint32_t>
      types;
  const auto type_id = [&](const ct_value_type &scalar, const char *spelling,
                           bool inherited_guard = false,
                           bool raw_scalar = false, uint32_t layout_type = 0) {
    const std::string name(spelling);
    const bool guarded = inherited_guard ||
                         name.find("volatile") != std::string::npos ||
                         name.find("_Atomic") != std::string::npos;
    const auto key = std::make_tuple(unsigned(scalar.kind), scalar.bytes, name,
                                     guarded, raw_scalar, layout_type);
    const auto found = types.find(key);
    if (found != types.end())
      return found->second;
    if (values.types.size() >= kernel_decompile_pool_limit ||
        !decompile_reserve(text_bytes, name.size(), kernel_decompile_text_limit,
                           error)) {
      error = "kernel decompile type pool exceeds its bound";
      return uint32_t(0);
    }
    const auto id = uint32_t(values.types.size());
    values.types.push_back({scalar, name, guarded, raw_scalar, layout_type});
    types.emplace(key, id);
    return id;
  };
  const auto layout_key =
      [](const ct_value_layout_node &node,
         const std::vector<ct_value_layout_member> &members) {
        std::string key = std::to_string(node.kind) + ':' +
                          std::to_string(node.scalar.kind) + ':' +
                          std::to_string(node.scalar.bytes) + ':' +
                          std::to_string(node.bytes) + ':' +
                          std::to_string(node.element_type) + ':' +
                          std::to_string(node.element_count) + ':' +
                          std::to_string(node.element_stride) + ':' +
                          std::to_string(node.complete) + ':' +
                          std::to_string(node.guarded) + ';';
        for (const auto &member : members)
          key += std::to_string(std::strlen(member.name)) + ':' + member.name +
                 ':' + std::to_string(member.type) + ':' +
                 std::to_string(member.offset) + ':' +
                 std::to_string(member.available) + ';';
        return key;
      };
  std::map<std::string, uint32_t> layouts;
  for (uint32_t index = 0; index < values.layout_types.size(); ++index) {
    const auto &node = values.layout_types[index];
    if (node.first_member > values.layout_members.size() ||
        node.member_count > values.layout_members.size() - node.first_member) {
      error = "invalid inherited kernel aggregate layout";
      return false;
    }
    const std::vector<ct_value_layout_member> members(
        values.layout_members.begin() + node.first_member,
        values.layout_members.begin() + node.first_member + node.member_count);
    auto key = layout_key(node, members);
    if (!decompile_reserve(text_bytes, key.size(), kernel_decompile_text_limit,
                           error))
      return false;
    layouts.emplace(std::move(key), index + 1);
  }
  // DWARF register numbers, including aliases whose low bytes are captured.
  const std::vector<std::vector<std::string>> registers{
      {"RAX", "EAX", "AX", "AL"},      {"RDX", "EDX", "DX", "DL"},
      {"RCX", "ECX", "CX", "CL"},      {"RBX", "EBX", "BX", "BL"},
      {"RSI", "ESI", "SI", "SIL"},     {"RDI", "EDI", "DI", "DIL"},
      {"RBP", "EBP", "BP", "BPL"},     {"RSP", "ESP", "SP", "SPL"},
      {"R8", "R8D", "R8W", "R8B"},     {"R9", "R9D", "R9W", "R9B"},
      {"R10", "R10D", "R10W", "R10B"}, {"R11", "R11D", "R11W", "R11B"},
      {"R12", "R12D", "R12W", "R12B"}, {"R13", "R13D", "R13W", "R13B"},
      {"R14", "R14D", "R14W", "R14B"}, {"R15", "R15D", "R15W", "R15B"}};
  std::map<std::tuple<uint32_t, uint64_t, std::string, uint32_t>, uint64_t>
      variables;
  std::map<std::pair<uint32_t, uint64_t>, uint32_t> functions;
  std::vector<std::pair<uint64_t, ct_kernel_value_binding>> successors;
  std::map<std::pair<uint32_t, uint64_t>, uint32_t> global_locations;
  std::map<uint64_t, uint64_t> call_returns;
  auto statement = std::make_unique<ct_decompiled_statement>();
  auto display = std::make_unique<ct_decompiled_display>();
  auto inferred = std::make_unique<ct_decompiled_variables>();
  for (const auto &symbol : image.symbols) {
    if (symbol.type != STT_FUNC || !symbol.size ||
        symbol.section >= image.sections.size() ||
        !(image.sections[symbol.section].flags & SHF_EXECINSTR) ||
        symbol.name.compare(0, 6, "__pfx_") == 0 ||
        functions.count({symbol.section, symbol.offset}))
      continue;
    const auto function_id = uint32_t(metadata.functions.size());
    if (function_id >= kernel_decompile_pool_limit ||
        values.functions.size() >= kernel_decompile_pool_limit ||
        !decompile_reserve(text_bytes, symbol.name.size(),
                           kernel_decompile_text_limit, error)) {
      error = "kernel decompile function pool exceeds its bound";
      return false;
    }
    functions.emplace(std::make_pair(symbol.section, symbol.offset),
                      function_id);
    ct_kernel_decompile_function function;
    function.section = symbol.section;
    function.begin = symbol.offset;
    function.end = symbol.offset + symbol.size;
    function.name = symbol.name;
    metadata.functions.push_back(std::move(function));
    ct_decompile_view view;
    if (!load_function(symbol.section, symbol.offset, view, error))
      return false;
    if (!view.level()) {
      const auto warning = "Decompilation unavailable: " + symbol.name +
                           (error.empty() ? "" : ": " + error);
      if (!decompile_reserve(text_bytes, warning.size(),
                             kernel_decompile_text_limit, error))
        return false;
      metadata.warnings.push_back(warning);
      error.clear();
      continue;
    }
    // A FULL view owns one immutable type graph for this physical function.
    // Import only reachable value types, once per input type ID, and retain
    // no second graph after the function's view is released.
    std::map<uint32_t, uint32_t> imported_layouts;
    std::set<uint32_t> active_layouts;
    const auto import_layout = [&](const auto &self, uint32_t input,
                                   unsigned depth) -> uint32_t {
      if (!input || input > inferred->type_count ||
          depth >= kernel_decompile_layout_depth || active_layouts.count(input))
        return 0;
      if (const auto found = imported_layouts.find(input);
          found != imported_layouts.end())
        return found->second;
      active_layouts.insert(input);
      const auto &original = inferred->types[input - 1];
      ct_value_layout_node node{};
      node.bytes = original.bytes;
      node.guarded = original.guarded;
      node.complete = original.complete;
      std::vector<ct_value_layout_member> members;
      if (original.kind == CT_LAYOUT_POINTER && original.bytes == 8) {
        node.kind = CT_LAYOUT_POINTER; // Never import or read a pointee.
      } else if (original.kind == CT_LAYOUT_SCALAR && original.bytes &&
                 original.bytes <= 8 &&
                 original.scalar.bytes == original.bytes) {
        node.kind = CT_LAYOUT_SCALAR;
        node.scalar = original.scalar;
      } else if (original.kind == CT_LAYOUT_ARRAY && original.element_stride &&
                 original.element_count <=
                     original.bytes / original.element_stride &&
                 original.element_count * original.element_stride ==
                     original.bytes) {
        const auto element = self(self, original.element_type, depth + 1);
        if (element &&
            values.layout_types[element - 1].bytes <= original.element_stride) {
          node.kind = CT_LAYOUT_ARRAY;
          node.element_type = element;
          node.element_count = original.element_count;
          node.element_stride = original.element_stride;
        }
      } else if (original.kind == CT_LAYOUT_STRUCT &&
                 original.first_member <= inferred->member_count &&
                 original.member_count <=
                     inferred->member_count - original.first_member) {
        node.kind = CT_LAYOUT_STRUCT;
        for (size_t index = 0; index < original.member_count; ++index) {
          auto member = inferred->members[original.first_member + index];
          const auto child =
              member.available ? self(self, member.type, depth + 1) : 0;
          member.type = child;
          member.available = child && member.offset <= node.bytes &&
                             values.layout_types[child - 1].bytes <=
                                 node.bytes - member.offset;
          members.push_back(member);
        }
      }
      const auto key = layout_key(node, members);
      const auto found = layouts.find(key);
      uint32_t id = 0;
      if (found != layouts.end()) {
        id = found->second;
      } else if (values.layout_types.size() >= kernel_decompile_pool_limit ||
                 values.layout_members.size() > kernel_decompile_site_limit ||
                 members.size() > kernel_decompile_site_limit -
                                      values.layout_members.size()) {
        error = "kernel decompile aggregate layout exceeds its bound";
      } else {
        if (!decompile_reserve(text_bytes, key.size(),
                               kernel_decompile_text_limit, error)) {
          active_layouts.erase(input);
          return 0;
        }
        node.first_member = members.empty() ? 0 : values.layout_members.size();
        node.member_count = members.size();
        values.layout_members.insert(values.layout_members.end(),
                                     members.begin(), members.end());
        values.layout_types.push_back(node);
        id = values.layout_types.size();
        layouts.emplace(key, id);
      }
      active_layouts.erase(input);
      imported_layouts.emplace(input, id);
      return id;
    };
    const auto value_function = uint32_t(values.functions.size());
    metadata.functions[function_id].value_function = value_function;
    values.functions.push_back({UINT64_MAX - function_id, 0, 0, false});
    std::map<uint64_t, uint32_t> statements;
    std::vector<ct_decompiled_instruction> function_proof;
    for (const auto &[address, original] : addresses) {
      if (original->section != symbol.section ||
          original->offset < symbol.offset ||
          original->offset - symbol.offset >= symbol.size ||
          !view.contains(address) || !view.display(address, *display))
        continue;
      std::string issue;
      if (ct_kernel_validate_decompile_proof(image, sites, layout,
                                             {display->instruction}, issue))
        function_proof.push_back(display->instruction);
    }
    std::vector<ct_kernel_flow_region> regions;
    std::vector<ct_kernel_stack_location> stack_locations;
    std::string flow_error;
    const bool flow_valid = ct_kernel_decompile_flow(
        image, sites, layout, symbol.section, symbol.offset, function_proof,
        regions, flow_error, &stack_locations);
    std::map<uint64_t, ct_kernel_stack_location> stack;
    for (const auto &location : stack_locations)
      stack.emplace(location.probe, location);

    bool first_site = true;
    for (const auto &[address, original] : addresses) {
      if (original->section != symbol.section ||
          original->offset < symbol.offset ||
          original->offset - symbol.offset >= symbol.size ||
          !view.contains(address))
        continue;
      auto &site = metadata.sites[original->id];
      const bool entry_site = first_site;
      first_site = false;
      site.function = function_id;
      if (!values.sites[original->id].function)
        values.sites[original->id].function = value_function;
      llvm::MCInst decoded;
      uint64_t decoded_size = 0;
      const auto &original_section = image.sections[original->section];
      const bool decoded_valid =
          decoder->getInstruction(
              decoded, decoded_size,
              {image.bytes.data() + original_section.offset + original->offset,
               original->original_size},
              original->offset,
              llvm::nulls()) == llvm::MCDisassembler::Success &&
          decoded_size == original->original_size;
      const auto *machine =
          decoded_valid ? &instructions->get(decoded.getOpcode()) : nullptr;
      if (machine && machine->isCall()) {
        const auto next = addresses.find(address + original->original_size);
        if (next != addresses.end() &&
            next->second->section == symbol.section &&
            next->second->offset - symbol.offset < symbol.size)
          call_returns.emplace(original->id, next->second->id);
      }
      // The decompiler's function-wide inventory does not prove an access at
      // this PC. Decode a single, exact-width integer memory operand and its
      // relocation field independently of the inventory's READ/WRITE flags.
      uint32_t memory_section = UINT32_MAX;
      uint64_t memory_offset = 0;
      unsigned memory_width = 0;
      unsigned memory_operand = 0;
      bool memory_valid = false;
      std::string memory_base;
      int64_t memory_displacement = 0;
      if (machine && (machine->mayLoad() || machine->mayStore())) {
        auto opcode = instructions->getName(decoded.getOpcode());
        bool known = false;
        for (const llvm::StringRef name :
             {"MOV", "ADD", "SUB", "AND", "OR", "XOR", "ADC", "SBB", "CMP",
              "TEST", "INC", "DEC", "NEG", "NOT"})
          if (opcode.consume_front(name)) {
            known = true;
            break;
          }
        if (known)
          for (const unsigned bits : {8, 16, 32, 64})
            if (opcode.consume_front(std::to_string(bits))) {
              memory_width = bits / 8;
              break;
            }
        known = memory_width &&
                (opcode == "m" || opcode == "rm" || opcode == "mr" ||
                 opcode == "mi" || opcode == "mi8" || opcode == "mi32");
        unsigned count = 0;
        const auto *original_site = original;
        for (unsigned operand = 0;
             known && operand + 4 < decoded.getNumOperands(); ++operand)
          if (decoded.getOperand(operand).isReg() &&
              decoded.getOperand(operand + 1).isImm() &&
              decoded.getOperand(operand + 1).getImm() == 1 &&
              decoded.getOperand(operand + 2).isReg() &&
              !decoded.getOperand(operand + 2).getReg() &&
              decoded.getOperand(operand + 3).isImm() &&
              decoded.getOperand(operand + 4).isReg() &&
              !decoded.getOperand(operand + 4).getReg()) {
            memory_operand = operand;
            ++count;
          }
        if (count == 1) {
          memory_base = machine_registers->getName(
              decoded.getOperand(memory_operand).getReg());
          memory_displacement = decoded.getOperand(memory_operand + 3).getImm();
          if (memory_base == "RSP" || memory_base == "RBP") {
            memory_valid = std::none_of(
                image.relocations.begin(), image.relocations.end(),
                [&](const auto &relocation) {
                  return relocation.section == original_site->section &&
                         relocation.offset >= original_site->offset &&
                         relocation.offset - original_site->offset <
                             original_site->original_size;
                });
          } else if (memory_base == "RIP") {
            llvm::MCInst symbolic = decoded;
            symbolic.getOperand(memory_operand + 3) =
                llvm::MCOperand::createExpr(memory_symbol);
            llvm::SmallVector<char, 16> encoded;
            llvm::SmallVector<llvm::MCFixup, 1> fixups;
            encoder->encodeInstruction(symbolic, encoded, fixups, *subtarget);
            bool proven = encoded.size() == original->original_size &&
                          fixups.size() == 1 &&
                          fixups[0].getOffset() <= encoded.size() &&
                          encoded.size() - fixups[0].getOffset() >= 4;
            if (proven) {
              const auto field = fixups[0].getOffset();
              for (size_t byte = 0; byte < encoded.size(); ++byte)
                if ((byte < field || byte >= field + 4) &&
                    uint8_t(encoded[byte]) !=
                        image.bytes[original_section.offset + original->offset +
                                    byte])
                  proven = false;
              for (const auto &relocation : image.relocations) {
                if (!proven || relocation.section != original->section ||
                    relocation.offset != original->offset + field ||
                    relocation.type != R_X86_64_PC32)
                  continue;
                const auto target_symbol = std::find_if(
                    image.symbols.begin(), image.symbols.end(),
                    [&](const auto &candidate) {
                      return candidate.table == relocation.symbol_table &&
                             candidate.index == relocation.symbol;
                    });
                if (target_symbol == image.symbols.end() ||
                    target_symbol->section == SHN_UNDEF ||
                    target_symbol->section >= SHN_LORESERVE ||
                    target_symbol->section >= image.sections.size())
                  continue;
                const __int128 target_offset = __int128(target_symbol->offset) +
                                               relocation.addend +
                                               original->original_size - field;
                const auto &target_section =
                    image.sections[target_symbol->section];
                if ((target_section.flags & SHF_ALLOC) &&
                    !(target_section.flags & SHF_EXECINSTR) &&
                    target_offset >= 0 &&
                    target_offset + memory_width <= target_section.size) {
                  memory_section = target_symbol->section;
                  memory_offset = uint64_t(target_offset);
                  memory_valid = true;
                }
              }
            }
          }
        }
      }
      if (view.display(address, *display)) {
        std::vector<ct_decompiled_instruction> proof{display->instruction};
        std::string issue;
        if (ct_kernel_validate_decompile_proof(image, sites, layout, proof,
                                               issue)) {
          auto &owner = metadata.functions[function_id];
          if (owner.prototype.empty()) {
            if (!decompile_reserve(text_bytes, std::strlen(display->prototype),
                                   kernel_decompile_text_limit, error))
              return false;
            owner.prototype = display->prototype;
          }
          if (!decompile_reserve(text_bytes,
                                 std::strlen(display->control_text) +
                                     std::strlen(display->control_kind),
                                 kernel_decompile_text_limit, error))
            return false;
          site.control_text = display->control_text;
          site.control_kind = display->control_kind;
          site.conditional = display->control_conditional;
          const auto target = addresses.find(display->control_target);
          if (display->control_has_target && target != addresses.end()) {
            site.has_target = true;
            site.control_target = target->second->id;
          }
        }
      }
      if (source_available(original->id))
        continue;
      site.returned = machine && machine->isReturn();
      if (machine && machine->isUnconditionalBranch() &&
          original->original_size == 5 &&
          image.bytes[original_section.offset + original->offset] == 0xe9) {
        for (const auto &relocation : image.relocations) {
          if (relocation.section != original->section ||
              relocation.offset != original->offset + 1 ||
              relocation.addend != -4 ||
              (relocation.type != R_X86_64_PC32 &&
               relocation.type != R_X86_64_PLT32))
            continue;
          site.returned |=
              std::any_of(image.symbols.begin(), image.symbols.end(),
                          [&](const auto &candidate) {
                            return candidate.table == relocation.symbol_table &&
                                   candidate.index == relocation.symbol &&
                                   candidate.section == SHN_UNDEF &&
                                   candidate.name == "__x86_return_thunk";
                          });
        }
      }
      if (view.statement(address, *statement)) {
        auto [position, inserted] = statements.emplace(statement->id, 0);
        if (inserted) {
          std::vector<ct_decompiled_instruction> proof(
              statement->instructions,
              statement->instructions + statement->instruction_count);
          std::string issue;
          ct_kernel_decompile_statement normalized;
          normalized.function = function_id;
          normalized.text = statement->text;
          normalized.declaration_name = statement->declaration_name;
          normalized.declaration_type = statement->declaration_type;
          normalized.assignment = decompile_assignment(normalized.text);
          bool valid = !proof.empty() && known_labels(normalized.text) &&
                       ct_kernel_validate_decompile_proof(image, sites, layout,
                                                          proof, issue);
          std::set<uint64_t> unique;
          for (const auto &instruction : proof) {
            const auto found = addresses.find(instruction.offset);
            if (found == addresses.end() ||
                found->second->section != symbol.section ||
                found->second->offset < symbol.offset ||
                found->second->offset - symbol.offset >= symbol.size ||
                !unique.insert(found->second->id).second) {
              valid = false;
              break;
            }
            normalized.sites.push_back(found->second->id);
          }
          if (valid) {
            if (metadata.statements.size() >= kernel_decompile_site_limit ||
                !decompile_reserve(text_bytes,
                                   normalized.text.size() +
                                       normalized.declaration_name.size() +
                                       normalized.declaration_type.size() +
                                       normalized.assignment.size(),
                                   kernel_decompile_text_limit, error)) {
              error = "kernel decompile statement pool exceeds its bound";
              return false;
            }
            position->second = uint32_t(metadata.statements.size());
            metadata.statements.push_back(std::move(normalized));
          } else if (!issue.empty()) {
            const auto warning = symbol.name + ": " + issue;
            if (std::find(metadata.warnings.begin(), metadata.warnings.end(),
                          warning) == metadata.warnings.end()) {
              if (!decompile_reserve(text_bytes, warning.size(),
                                     kernel_decompile_text_limit, error))
                return false;
              metadata.warnings.push_back(warning);
            }
          }
        }
        if (position->second) {
          const auto &candidate = metadata.statements[position->second];
          const auto index = statement->instruction_index;
          if (index < candidate.sites.size() &&
              candidate.sites[index] == original->id) {
            site.statement = position->second;
            site.index = index;
          }
        }
      }
      if (!site.statement && !site.control_text.empty()) {
        ct_kernel_decompile_statement control;
        control.function = function_id;
        control.text = site.control_text;
        if (site.conditional && site.has_target)
          control.text = "if (" + site.control_text + ") goto @L" +
                         llvm::utohexstr(display->control_target) + "@;";
        control.sites.push_back(original->id);
        if (metadata.statements.size() >= kernel_decompile_site_limit ||
            !decompile_reserve(text_bytes, control.text.size(),
                               kernel_decompile_text_limit, error)) {
          error = "kernel decompile control pool exceeds its bound";
          return false;
        }
        site.statement = uint32_t(metadata.statements.size());
        metadata.statements.push_back(std::move(control));
      }
      if (!view.variables(address, *inferred))
        continue;
      std::string issue;
      if (!ct_kernel_validate_decompile_proof(image, sites, layout,
                                              {inferred->instruction}, issue))
        continue;
      auto &value_site = values.sites[original->id];
      if (!value_site.function)
        value_site.function = value_function;
      auto &returned = values.functions[value_function];
      std::string return_register = inferred->return_register;
      std::transform(return_register.begin(), return_register.end(),
                     return_register.begin(),
                     [](unsigned char c) { return std::toupper(c); });
      if (inferred->return_known && !inferred->return_unsupported &&
          (inferred->return_void || return_register == "RAX" ||
           return_register == "EAX" || return_register == "AX" ||
           return_register == "AL")) {
        returned.returns_void = inferred->return_void;
        if (!returned.returns_void)
          returned.return_type =
              type_id(inferred->return_type, inferred->return_type_name, false,
                      inferred->return_type.kind == CT_VALUE_UNKNOWN);
        if (!error.empty())
          return false;
      }
      std::vector<ct_decompiled_variable> inputs(
          inferred->entries, inferred->entries + inferred->count);
      const bool parameters =
          entry_site && inferred->parameters_known &&
          metadata.functions[function_id].parameters.empty();
      if (parameters)
        for (uint32_t index = 0; index < inferred->parameter_count; ++index) {
          const auto &parameter = inferred->parameters[index];
          if (std::none_of(inputs.begin(), inputs.end(),
                           [&](const auto &input) {
                             return std::string(input.name) == parameter.name;
                           })) {
            ct_decompiled_variable input{};
            input.id = UINT64_MAX - index;
            input.stack_offset = parameter.stack_offset;
            input.size = parameter.size;
            input.kind = parameter.kind;
            input.access = CT_DECOMPILED_READ;
            std::copy(std::begin(parameter.name), std::end(parameter.name),
                      std::begin(input.name));
            std::copy(std::begin(parameter.type_name),
                      std::end(parameter.type_name),
                      std::begin(input.type_name));
            std::copy(std::begin(parameter.register_name),
                      std::end(parameter.register_name),
                      std::begin(input.register_name));
            input.type = parameter.type;
            inputs.push_back(input);
          }
        }
      for (const auto &input : inputs) {
        const auto *layout_type =
            input.type_id && input.type_id <= inferred->type_count
                ? &inferred->types[input.type_id - 1]
                : nullptr;
        const bool aggregate = layout_type && layout_type->complete &&
                               layout_type->bytes == input.size &&
                               (layout_type->kind == CT_LAYOUT_STRUCT ||
                                layout_type->kind == CT_LAYOUT_ARRAY);
        if (!input.name[0] || !input.size || (input.size > 8 && !aggregate) ||
            (aggregate && input.kind == CT_DECOMPILED_REGISTER) ||
            input.type.bytes != input.size)
          continue;
        const bool parameter =
            parameters &&
            std::any_of(inferred->parameters,
                        inferred->parameters + inferred->parameter_count,
                        [&](const auto &entry) {
                          return std::string(entry.name) == input.name;
                        });
        const bool referenced =
            site.statement &&
            ct_kernel_decompile_identifier(
                metadata.statements[site.statement].text, input.name);
        // Keep proven per-PC register reads even on an assembly fallback: a
        // call's RAX result may first be consumed there, before its C lhs has
        // another representable statement. This adds no register read guess.
        if (!parameter && !referenced && input.kind != CT_DECOMPILED_REGISTER &&
            !aggregate)
          continue;
        ct_kernel_value_recipe recipe;
        uint32_t access =
            input.kind == CT_DECOMPILED_REGISTER ? input.access : 0;
        uint32_t section = UINT32_MAX;
        uint64_t offset = 0;
        std::string name = input.name;
        if (input.kind == CT_DECOMPILED_REGISTER) {
          std::string reg = input.register_name;
          std::transform(reg.begin(), reg.end(), reg.begin(),
                         [](unsigned char c) { return std::toupper(c); });
          for (uint32_t number = 0; number < registers.size(); ++number) {
            const auto &family = registers[number];
            if (std::find(family.begin(), family.end(), reg) == family.end())
              continue;
            bool read = false, write = false;
            const auto physical = [&](llvm::MCRegister operand, bool writing) {
              if (!operand)
                return false;
              const std::string spelling = machine_registers->getName(operand);
              const auto alias =
                  std::find(family.begin(), family.end(), spelling);
              if (alias == family.end())
                return false;
              const unsigned width = 8u >> (alias - family.begin());
              return input.size <= width ||
                     (writing && width == 4 && input.size == 8);
            };
            if (machine) {
              for (unsigned index = 0; index < decoded.getNumOperands();
                   ++index)
                if (decoded.getOperand(index).isReg()) {
                  const bool writing = index < machine->getNumDefs();
                  const bool matches =
                      physical(decoded.getOperand(index).getReg(), writing);
                  read |= matches && !writing;
                  write |= matches && writing;
                }
              for (const auto operand : machine->implicit_uses())
                read |= physical(operand, false);
              for (const auto operand : machine->implicit_defs())
                write |= physical(operand, true);
            }
            access = (read ? input.access & CT_DECOMPILED_READ : 0) |
                     (write ? input.access & CT_DECOMPILED_WRITE : 0);
            if (parameter || access)
              recipe.operations.push_back({llvm::dwarf::DW_OP_regx, number, 0});
            if (input.register_alias)
              name = reg;
            break;
          }
        } else if (input.kind == CT_DECOMPILED_GLOBAL &&
                   original_address(input.offset, section, offset) &&
                   ct_kernel_capture_section(image.sections[section])) {
          const auto object = std::find_if(
              image.symbols.begin(), image.symbols.end(),
              [&](const auto &item) {
                return item.type == STT_OBJECT && item.size &&
                       item.section == section && offset >= item.offset &&
                       offset - item.offset < item.size &&
                       input.size <= item.size - (offset - item.offset);
              });
          const bool physical =
              memory_valid && memory_section == section &&
              (aggregate
                   ? memory_offset >= offset &&
                         memory_offset - offset < input.size &&
                         memory_width <= input.size - (memory_offset - offset)
                   : memory_offset == offset && memory_width == input.size);
          if (object != image.symbols.end() && physical) {
            recipe.operations.push_back(
                {llvm::dwarf::DW_OP_addr, offset, 0, section});
            access = (machine->mayLoad() ? CT_DECOMPILED_READ : 0) |
                     (machine->mayStore() ? CT_DECOMPILED_WRITE : 0);
          }
        } else if (input.kind == CT_DECOMPILED_STACK) {
          const auto position = stack.find(original->id);
          if (position != stack.end()) {
            const auto &location = position->second;
            const bool use_rsp =
                location.rsp_known && (parameter || memory_base == "RSP");
            if (use_rsp ||
                (location.rbp_known && (parameter || memory_base == "RBP"))) {
              const __int128 displacement =
                  __int128(input.stack_offset) -
                  (use_rsp ? location.rsp_offset : location.rbp_offset);
              const auto base = use_rsp ? "RSP" : "RBP";
              const __int128 within =
                  __int128(memory_displacement) - displacement;
              const bool physical =
                  memory_valid && memory_base == base &&
                  (aggregate ? within >= 0 && within < input.size &&
                                   memory_width <= input.size - within
                             : memory_width == input.size &&
                                   displacement == memory_displacement);
              // Parameters at entry use ABI storage even without a memory
              // access. Other storage requires this exact machine operand.
              if ((physical || (parameter && !aggregate)) &&
                  displacement >= INT64_MIN && displacement <= INT64_MAX) {
                recipe.operations.push_back({llvm::dwarf::DW_OP_bregx,
                                             use_rsp ? 7u : 6u,
                                             uint64_t(int64_t(displacement))});
                access = physical
                             ? ((machine->mayLoad() ? CT_DECOMPILED_READ : 0) |
                                (machine->mayStore() ? CT_DECOMPILED_WRITE : 0))
                             : CT_DECOMPILED_READ;
              }
            }
          }
        }
        // A proven aggregate operand is useful on an assembly fallback too;
        // a function-wide inventory alone never requests aggregate storage.
        if (aggregate && !parameter && !referenced && recipe.operations.empty())
          continue;
        const uint32_t imported =
            aggregate ? import_layout(import_layout, input.type_id, 0) : 0;
        if (!error.empty())
          return false;
        const auto type = type_id(
            input.type, input.type_name, layout_type && layout_type->guarded,
            layout_type && layout_type->kind == CT_LAYOUT_SCALAR &&
                layout_type->complete && layout_type->bytes == input.size &&
                input.type.kind == CT_VALUE_UNKNOWN,
            imported);
        if (!type)
          return false;
        const bool global_register =
            input.kind == CT_DECOMPILED_REGISTER && input.register_alias;
        const auto identity = std::make_tuple(
            input.kind == CT_DECOMPILED_GLOBAL || global_register ? 0u
                                                                  : function_id,
            input.kind == CT_DECOMPILED_GLOBAL ? input.offset
            : global_register                  ? UINT64_C(0)
                                               : input.id,
            name, type);
        auto [position, inserted] = variables.emplace(identity, 0);
        if (inserted) {
          if (values.variables.size() >= kernel_decompile_pool_limit ||
              !decompile_reserve(text_bytes, name.size() + symbol.name.size(),
                                 kernel_decompile_text_limit, error)) {
            error = "kernel decompile variable pool exceeds its bound";
            return false;
          }
          position->second = values.variables.size();
          ct_kernel_value_variable variable;
          variable.id = position->second;
          variable.function = variable.scope = returned.die;
          variable.type = type;
          variable.name = name;
          variable.owner = symbol.name;
          variable.global =
              input.kind == CT_DECOMPILED_GLOBAL || global_register;
          variable.register_alias = global_register;
          values.variables.push_back(std::move(variable));
        }
        const auto variable = position->second;
        if ((!aggregate || recipe.operations.empty()) &&
            (!site.statement ||
             metadata.statements[site.statement].assignment != name))
          access &= ~CT_DECOMPILED_WRITE;
        if (!access && !parameter && input.kind == CT_DECOMPILED_REGISTER)
          recipe.operations.clear();
        uint32_t location = 0;
        if (!recipe.operations.empty()) {
          location = intern_recipe(recipe);
          if (!location)
            return false;
        }
        if (aggregate && input.kind == CT_DECOMPILED_GLOBAL && location &&
            recipe.error.empty() && recipe.operations.size() == 1 &&
            recipe.operations.front().opcode == llvm::dwarf::DW_OP_addr) {
          const auto [known, fresh] = global_locations.emplace(
              std::make_pair(function_id, variable), location);
          if (!fresh && known->second != location)
            known->second = 0;
        }
        const auto bound = std::find_if(
            value_site.bindings.begin(), value_site.bindings.end(),
            [&](const auto &entry) { return entry.variable == variable; });
        if (bound == value_site.bindings.end()) {
          if (!decompile_reserve(binding_count, 1, kernel_decompile_site_limit,
                                 error))
            return false;
          value_site.bindings.push_back({variable, location});
        } else if (!bound->recipe)
          bound->recipe = location;
        const auto existing = std::find_if(
            site.variables.begin(), site.variables.end(),
            [&](const auto &entry) { return entry.variable == variable; });
        if (existing == site.variables.end()) {
          if (!decompile_reserve(reference_count, 1,
                                 kernel_decompile_site_limit, error))
            return false;
          site.variables.push_back({variable, access});
        } else
          existing->access |= access;
      }
      if (parameters)
        for (uint32_t index = 0; index < inferred->parameter_count; ++index)
          for (const auto &reference : site.variables)
            if (values.variables[reference.variable].name ==
                inferred->parameters[index].name) {
              metadata.functions[function_id].parameters.push_back(
                  reference.variable);
              values.variables[reference.variable].parameter = true;
              break;
            }
      if (machine && !machine->isCall() && !machine->isBranch() &&
          !machine->isReturn()) {
        const auto next = addresses.find(address + original->original_size);
        if (next != addresses.end() &&
            next->second->section == original->section &&
            next->second->offset - symbol.offset < symbol.size) {
          for (const auto &reference : site.variables) {
            if (!(reference.access & CT_DECOMPILED_WRITE))
              continue;
            const auto location = std::find_if(
                value_site.bindings.begin(), value_site.bindings.end(),
                [&](const auto &binding) {
                  return binding.variable == reference.variable;
                });
            if (location != value_site.bindings.end() && location->recipe)
              successors.emplace_back(next->second->id, *location);
          }
        }
      }
    }
    if (flow_valid) {
      std::vector<ct_kernel_decompile_block> candidates;
      size_t candidate_memberships = 0;
      for (const auto &region : regions) {
        if (!region.branch || region.branch >= metadata.sites.size())
          continue;
        const auto &control = metadata.sites[region.branch];
        if (!decompile_reserve(candidate_memberships,
                               region.loop
                                   ? region.members.size()
                                   : region.taken_members.size() +
                                         region.fallthrough_members.size(),
                               kernel_decompile_site_limit, error))
          return false;
        if (region.loop) {
          ct_kernel_decompile_block block;
          block.function = function_id;
          block.header =
              control.control_text.empty() ? "loop" : control.control_text;
          if (!control.control_text.empty())
            block.header =
                region.header == region.branch
                    ? "while (" + control.control_text + ") {"
                    : "do { ... } while (" + control.control_text + ");";
          block.loop = true;
          block.sites = region.members;
          candidates.push_back(std::move(block));
        } else {
          for (bool taken : {true, false}) {
            ct_kernel_decompile_block block;
            block.function = function_id;
            const bool matches =
                taken != (control.has_target &&
                          control.control_target == region.fallthrough);
            block.header =
                matches ? "if (" + control.control_text + ") {" : "else {";
            if (matches && control.control_text.empty())
              block.header = "if (?) {";
            block.sites =
                taken ? region.taken_members : region.fallthrough_members;
            if (!block.sites.empty())
              candidates.push_back(std::move(block));
          }
        }
      }
      for (auto &block : candidates) {
        std::sort(block.sites.begin(), block.sites.end());
        block.sites.erase(std::unique(block.sites.begin(), block.sites.end()),
                          block.sites.end());
      }
      std::sort(candidates.begin(), candidates.end(),
                [](const auto &a, const auto &b) {
                  return a.sites.size() > b.sites.size();
                });
      std::vector<uint64_t> retained;
      for (auto &block : candidates) {
        bool valid = !block.sites.empty();
        uint64_t parent = 0;
        for (const auto id : retained) {
          const auto &outer = metadata.blocks[id];
          const bool inside =
              std::includes(outer.sites.begin(), outer.sites.end(),
                            block.sites.begin(), block.sites.end());
          if (inside) {
            if (outer.sites == block.sites) {
              valid = false;
              break;
            }
            if (!parent ||
                outer.sites.size() < metadata.blocks[parent].sites.size())
              parent = id;
          } else {
            for (const auto site : block.sites)
              if (std::binary_search(outer.sites.begin(), outer.sites.end(),
                                     site)) {
                valid = false;
                break;
              }
          }
          if (!valid)
            break;
        }
        for (const auto site : block.sites)
          valid &= site && site < metadata.sites.size() &&
                   metadata.sites[site].function == function_id;
        if (!valid)
          continue;
        if (metadata.blocks.size() >= kernel_decompile_pool_limit ||
            !decompile_reserve(block_memberships, block.sites.size(),
                               kernel_decompile_site_limit, error) ||
            !decompile_reserve(text_bytes, block.header.size(),
                               kernel_decompile_text_limit, error)) {
          error = "kernel decompile block pool exceeds its bound";
          return false;
        }
        block.parent = parent;
        const auto id = metadata.blocks.size();
        for (const auto site : block.sites)
          metadata.sites[site].blocks.push_back(id);
        metadata.blocks.push_back(std::move(block));
        retained.push_back(id);
      }
    }
  }
  for (const auto &[site_id, binding] : successors) {
    // Original C rows retain their own DWARF identity and location evidence.
    // A decompiler-only duplicate name must not make that lookup ambiguous.
    if (source_available(site_id))
      continue;
    auto &bindings = values.sites[site_id].bindings;
    const auto variable = binding.variable;
    const auto existing =
        std::find_if(bindings.begin(), bindings.end(), [&](const auto &entry) {
          return entry.variable == variable;
        });
    if (existing == bindings.end()) {
      if (!decompile_reserve(binding_count, 1, kernel_decompile_site_limit,
                             error))
        return false;
      bindings.push_back(binding);
    } else if (!existing->recipe && values.variables[binding.variable].global)
      existing->recipe = binding.recipe;
  }
  // A candidate may mention an instruction for which the producer selected a
  // different statement. Such overlap is not an execution proof; drop the
  // entire candidate rather than requiring an unavailable fragment at runtime.
  std::vector<uint32_t> remap(metadata.statements.size());
  std::vector<ct_kernel_decompile_statement> complete(1);
  for (size_t id = 1; id < metadata.statements.size(); ++id) {
    auto &statement = metadata.statements[id];
    bool valid = true;
    for (size_t index = 0; index < statement.sites.size(); ++index) {
      const auto site = statement.sites[index];
      valid &= site < metadata.sites.size() &&
               metadata.sites[site].statement == id &&
               metadata.sites[site].index == index;
    }
    if (valid) {
      remap[id] = uint32_t(complete.size());
      complete.push_back(std::move(statement));
    }
  }
  for (auto &site : metadata.sites)
    site.statement = remap[site.statement];
  metadata.statements = std::move(complete);
  for (const auto &statement : metadata.statements) {
    if (statement.sites.empty() || statement.assignment.empty())
      continue;
    const auto site_id = statement.sites.back();
    const auto next = call_returns.find(site_id);
    if (next == call_returns.end())
      continue;
    auto &site = metadata.sites[site_id];
    const auto &function = metadata.functions[statement.function];
    for (const auto &binding : values.sites[next->second].bindings) {
      const auto &variable = values.variables[binding.variable];
      if (variable.name != statement.assignment ||
          variable.owner != function.name || !binding.recipe)
        continue;
      const auto &recipe = values.recipes[binding.recipe];
      if (!recipe.error.empty() || recipe.operations.size() != 1 ||
          recipe.operations.front().opcode != llvm::dwarf::DW_OP_regx ||
          recipe.operations.front().operand != 0)
        continue;
      // A scalar result already has a proven RAX binding at the call's
      // successor. Only this direct call-ending assignment may use it.
      const auto reference = std::find_if(
          site.variables.begin(), site.variables.end(),
          [&](const auto &entry) { return entry.variable == variable.id; });
      if (reference == site.variables.end()) {
        if (!decompile_reserve(reference_count, 1, kernel_decompile_site_limit,
                               error))
          return false;
        site.variables.push_back({variable.id, CT_DECOMPILED_WRITE});
      } else
        reference->access |= CT_DECOMPILED_WRITE;
    }
  }
  std::map<uint32_t, std::set<uint64_t>> visible;
  for (const auto &site : metadata.sites)
    for (const auto &reference : site.variables)
      visible[site.function].insert(reference.variable);
  for (size_t function = 1; function < metadata.functions.size(); ++function)
    for (const auto parameter : metadata.functions[function].parameters)
      visible[function].insert(parameter);
  for (const auto &statement : metadata.statements) {
    if (statement.sites.empty())
      continue;
    auto &site = metadata.sites[statement.sites.front()];
    for (const auto variable : visible[statement.function]) {
      if (!ct_kernel_decompile_identifier(statement.text,
                                          values.variables[variable].name))
        continue;
      auto &bindings = values.sites[statement.sites.front()].bindings;
      auto binding = std::find_if(bindings.begin(), bindings.end(),
                                  [&](const auto &candidate) {
                                    return candidate.variable == variable;
                                  });
      const auto known = global_locations.find({statement.function, variable});
      if (known != global_locations.end() && known->second) {
        // A proved module object keeps a constant section-relative address.
        // Request a fresh snapshot here; never retain an earlier value or
        // extend register/stack locations beyond their individual PC proof.
        if (binding == bindings.end()) {
          if (!decompile_reserve(binding_count, 1, kernel_decompile_site_limit,
                                 error))
            return false;
          bindings.push_back({variable, known->second});
          binding = std::prev(bindings.end());
        } else if (!binding->recipe) {
          binding->recipe = known->second;
        }
      }
      if (binding != bindings.end())
        binding->preferred = true;
      const auto reference =
          std::find_if(site.variables.begin(), site.variables.end(),
                       [&](const auto &candidate) {
                         return candidate.variable == variable;
                       });
      if (reference == site.variables.end()) {
        if (!decompile_reserve(reference_count, 1, kernel_decompile_site_limit,
                               error))
          return false;
        site.variables.push_back({variable, CT_DECOMPILED_READ});
      }
    }
  }
  return ct_kernel_complete_decompile_returns(values, metadata, error);
}
