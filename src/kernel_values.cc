#include <algorithm>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <type_traits>
#include <utility>

#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDie.h>
#include <llvm/DebugInfo/DWARF/DWARFUnit.h>
#include <llvm/DebugInfo/DWARF/LowLevel/DWARFExpression.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBufferRef.h>
#include <llvm/Support/SHA256.h>

#include <elf.h>

#include "analysis_cache.h"
#include "cache.h"
#include "kernel_values.h"

static constexpr size_t kernel_value_entry_limit = 1048576;
static constexpr size_t kernel_value_pool_limit = 65536;
static constexpr size_t kernel_value_expression_limit = 128;
static constexpr size_t kernel_value_depth_limit = 64;
static constexpr size_t kernel_value_text_limit = 64 * 1024 * 1024;
static constexpr size_t kernel_value_format_limit = 8192;
static constexpr unsigned kernel_value_registers[] = {
    0, 3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17};

static uint32_t kernel_entry_register(const ct_kernel_value_recipe &recipe) {
  using namespace llvm::dwarf;
  const auto &operations = recipe.operations;
  if (!recipe.error.empty() || operations.size() != 3 ||
      (operations[0].opcode != DW_OP_entry_value &&
       operations[0].opcode != DW_OP_GNU_entry_value) ||
      operations[2].opcode != DW_OP_stack_value)
    return UINT32_MAX;
  for (const auto &operation : operations)
    if (operation.operand2 || operation.section != UINT32_MAX)
      return UINT32_MAX;
  if (operations[2].operand)
    return UINT32_MAX;
  const auto &reg = operations[1];
  // LLVM exposes the nested operations in sequence. The exact block length
  // proves that only this register belongs to entry_value. Noncanonical or
  // more complex blocks remain unavailable, including dereferences/pieces.
  if (reg.opcode >= DW_OP_reg0 && reg.opcode <= DW_OP_reg15 && !reg.operand &&
      operations[0].operand == 1)
    return reg.opcode - DW_OP_reg0;
  if (reg.opcode == DW_OP_regx && reg.operand < 16 &&
      operations[0].operand == 2)
    return reg.operand;
  return UINT32_MAX;
}

static std::string
kernel_value_cache_key(const ct_kernel_image &image,
                       const std::vector<ct_kernel_site> &sites) {
  if (sites.size() > kernel_value_entry_limit || image.sections.empty())
    return {};
  llvm::SHA256 identity;
  const auto number = [&](uint64_t value) {
    identity.update({reinterpret_cast<const uint8_t *>(&value), sizeof(value)});
  };
  const auto text = [&](const std::string &value) {
    number(value.size());
    identity.update(value);
  };
  number(image.bytes.size());
  identity.update(llvm::ArrayRef<uint8_t>(image.bytes));
  number(image.sections.size());
  for (const auto &section : image.sections) {
    if (section.type != SHT_NOBITS &&
        (section.offset > image.bytes.size() ||
         section.size > image.bytes.size() - section.offset))
      return {};
    text(section.name);
    for (const uint64_t value :
         {uint64_t(section.type), uint64_t(section.link),
          uint64_t(section.info), section.flags, section.offset, section.size,
          section.alignment, section.entry_size})
      number(value);
  }
  number(image.symbols.size());
  for (const auto &symbol : image.symbols) {
    text(symbol.name);
    for (const uint64_t value :
         {uint64_t(symbol.table), uint64_t(symbol.index),
          uint64_t(symbol.section), symbol.offset, symbol.size,
          uint64_t(symbol.type), uint64_t(symbol.binding)})
      number(value);
  }
  number(image.relocations.size());
  for (const auto &relocation : image.relocations) {
    if (relocation.section >= image.sections.size() ||
        relocation.symbol_table >= image.sections.size() ||
        relocation.offset >= image.sections[relocation.section].size)
      return {};
    for (const uint64_t value :
         {uint64_t(relocation.section), uint64_t(relocation.symbol_table),
          uint64_t(relocation.symbol), uint64_t(relocation.type),
          relocation.offset, uint64_t(relocation.addend)})
      number(value);
  }
  number(sites.size());
  std::set<uint64_t> ids;
  for (const auto &site : sites) {
    if (site.probe &&
        (!site.id || site.id > kernel_value_entry_limit ||
         !ids.insert(site.id).second || site.section >= image.sections.size() ||
         !(image.sections[site.section].flags & SHF_EXECINSTR) ||
         !site.original_size || site.original_size > 15 ||
         site.offset > image.sections[site.section].size ||
         site.original_size > image.sections[site.section].size - site.offset))
      return {};
    for (const uint64_t value :
         {site.id, uint64_t(site.section), site.offset,
          uint64_t(site.original_size), uint64_t(site.probe)})
      number(value);
  }
  const auto digest = identity.final();
  return ct_cache_key(
      {"kernel-values-v3",
       {reinterpret_cast<const char *>(digest.data()), digest.size()}});
}

static bool kernel_value_archive(ct_kernel_value_metadata &metadata,
                                 std::vector<unsigned char> &bytes,
                                 bool reading, const std::string &key) {
  ct_analysis_archive archive{bytes, reading};
  uint32_t format = 3;
  archive.field(format);
  if (!archive.valid || format != 3)
    return false;
  size_t text_bytes = 0, bindings = 0, operations = 0;
  const auto text = [&](std::string &value) {
    uint64_t size = value.size();
    archive.field(size);
    if (!archive.valid || size > kernel_value_text_limit - text_bytes ||
        (reading && size > bytes.size() - archive.offset)) {
      archive.valid = false;
      return;
    }
    text_bytes += size;
    if (reading) {
      const auto end = archive.offset + size;
      value.assign(
          reinterpret_cast<const char *>(bytes.data() + archive.offset), size);
      archive.offset = end;
    } else {
      bytes.insert(bytes.end(), value.begin(), value.end());
    }
    archive.valid &= value.find('\0') == std::string::npos;
  };
  const auto boolean = [&](bool &value) {
    uint8_t encoded = value ? 1 : 0;
    archive.field(encoded);
    if (encoded > 1)
      archive.valid = false;
    if (archive.valid && reading)
      value = encoded != 0;
  };
  const auto pool = [&](auto &items, size_t limit, auto fields) {
    uint64_t count = items.size();
    archive.field(count);
    if (!archive.valid || count > limit ||
        (reading && count > bytes.size() - archive.offset)) {
      archive.valid = false;
      return;
    }
    if (reading) {
      items.clear();
      items.reserve(count);
      for (uint64_t index = 0; archive.valid && index < count; ++index) {
        typename std::decay_t<decltype(items)>::value_type value{};
        fields(value);
        if (archive.valid)
          items.push_back(std::move(value));
      }
    } else {
      for (auto &value : items) {
        if (!archive.valid)
          break;
        fields(value);
      }
    }
  };
  std::string input = key;
  text(input);
  if (!archive.valid || input != key)
    return false;
  pool(metadata.types, kernel_value_pool_limit, [&](auto &value) {
    uint32_t kind = value.scalar.kind;
    uint64_t width = value.scalar.bytes;
    archive.fields(kind, width);
    if (kind > CT_VALUE_POINTER || width > SIZE_MAX)
      archive.valid = false;
    if (archive.valid && reading)
      value.scalar = {static_cast<ct_value_kind>(kind), size_t(width)};
    text(value.name);
    boolean(value.guarded);
    archive.field(value.layout_type);
  });
  pool(metadata.layout_types, kernel_value_pool_limit, [&](auto &value) {
    uint32_t kind = value.kind, scalar = value.scalar.kind;
    uint64_t width = value.bytes, scalar_width = value.scalar.bytes;
    uint64_t count = value.element_count, stride = value.element_stride;
    uint64_t members = value.member_count;
    archive.fields(kind, scalar, width, scalar_width, value.element_type, count,
                   stride, value.first_member, members);
    if (kind > CT_LAYOUT_POINTER || scalar > CT_VALUE_POINTER ||
        width > SIZE_MAX || scalar_width > SIZE_MAX || count > SIZE_MAX ||
        stride > SIZE_MAX || members > SIZE_MAX)
      archive.valid = false;
    if (archive.valid && reading) {
      value.kind = static_cast<ct_value_layout_kind>(kind);
      value.scalar = {static_cast<ct_value_kind>(scalar), size_t(scalar_width)};
      value.bytes = size_t(width);
      value.element_count = size_t(count);
      value.element_stride = size_t(stride);
      value.member_count = size_t(members);
    }
    boolean(value.complete);
    boolean(value.guarded);
  });
  pool(metadata.layout_members, kernel_value_entry_limit, [&](auto &value) {
    std::string name;
    if (!reading) {
      if (!std::memchr(value.name, 0, sizeof(value.name))) {
        archive.valid = false;
        return;
      }
      name = value.name;
    }
    text(name);
    uint64_t offset = value.offset;
    archive.fields(value.type, offset);
    boolean(value.available);
    if (name.size() >= sizeof(value.name) || offset > SIZE_MAX)
      archive.valid = false;
    if (archive.valid && reading) {
      std::memcpy(value.name, name.c_str(), name.size() + 1);
      value.offset = size_t(offset);
    }
  });
  pool(metadata.variables, kernel_value_pool_limit, [&](auto &value) {
    archive.fields(value.id, value.die, value.unit, value.scope, value.function,
                   value.depth, value.type);
    text(value.name);
    text(value.owner);
    boolean(value.global);
    boolean(value.parameter);
  });
  pool(metadata.recipes, kernel_value_pool_limit, [&](auto &value) {
    text(value.error);
    archive.field(value.entry_register);
    pool(value.operations, kernel_value_expression_limit, [&](auto &operation) {
      if (++operations > kernel_value_entry_limit) {
        archive.valid = false;
        return;
      }
      archive.fields(operation.opcode, operation.operand, operation.operand2,
                     operation.section);
    });
  });
  pool(metadata.functions, kernel_value_pool_limit, [&](auto &value) {
    archive.fields(value.die, value.unit, value.return_type);
    boolean(value.returns_void);
  });
  pool(metadata.sites, kernel_value_entry_limit + 1, [&](auto &value) {
    archive.fields(value.function, value.frame_recipe);
    pool(value.bindings, kernel_value_entry_limit, [&](auto &binding) {
      if (++bindings > kernel_value_entry_limit) {
        archive.valid = false;
        return;
      }
      archive.fields(binding.variable, binding.recipe);
    });
  });
  return archive.complete();
}

static bool kernel_value_cache_valid(const ct_kernel_image &image,
                                     const std::vector<ct_kernel_site> &sites,
                                     const ct_kernel_value_metadata &metadata) {
  if (metadata.types.empty() || metadata.variables.empty() ||
      metadata.recipes.empty() || metadata.functions.empty() ||
      metadata.types[0].scalar.kind != CT_VALUE_UNKNOWN ||
      metadata.types[0].scalar.bytes || !metadata.types[0].name.empty() ||
      metadata.types[0].guarded || metadata.types[0].raw_scalar ||
      metadata.types[0].layout_type || metadata.capture_groups.size() != 1 ||
      !metadata.capture_groups[0].empty() ||
      !metadata.recipes[0].operations.empty() ||
      !metadata.recipes[0].error.empty() ||
      metadata.recipes[0].entry_register != UINT32_MAX)
    return false;
  uint64_t debug_size = 0;
  for (const auto &section : image.sections) {
    if (section.name == ".debug_info") {
      uint64_t size = section.size;
      if (section.flags & SHF_COMPRESSED) {
        if (section.size < sizeof(Elf64_Chdr))
          return false;
        Elf64_Chdr header;
        std::memcpy(&header, image.bytes.data() + section.offset,
                    sizeof(header));
        size = header.ch_size;
      }
      debug_size = std::max(debug_size, size);
    } else if (section.name == ".zdebug_info" && section.size >= 12 &&
               !std::memcmp(image.bytes.data() + section.offset, "ZLIB", 4)) {
      uint64_t size = 0;
      for (unsigned index = 4; index < 12; ++index)
        size = (size << 8) | image.bytes[section.offset + index];
      debug_size = std::max(debug_size, size);
    }
  }
  for (size_t index = 0; index < metadata.variables.size(); ++index) {
    const auto &value = metadata.variables[index];
    if (value.id != index || value.type >= metadata.types.size() ||
        value.depth > kernel_value_depth_limit || value.register_alias ||
        (index &&
         (!value.die || value.die >= debug_size || value.unit >= value.die ||
          (value.scope &&
           (value.scope < value.unit || value.scope >= debug_size)) ||
          (value.function &&
           (value.function < value.unit || value.function >= debug_size)) ||
          value.name.empty())) ||
        (!index && (value.die || value.unit || value.scope || value.function ||
                    value.depth || value.type || !value.name.empty() ||
                    !value.owner.empty() || value.global || value.parameter)))
      return false;
  }
  for (const auto &type : metadata.types)
    if (type.raw_scalar || type.scalar.kind > CT_VALUE_POINTER ||
        type.scalar.kind < CT_VALUE_UNKNOWN ||
        type.layout_type > metadata.layout_types.size() ||
        (type.layout_type &&
         (metadata.layout_types[type.layout_type - 1].bytes !=
              type.scalar.bytes ||
          metadata.layout_types[type.layout_type - 1].guarded != type.guarded)))
      return false;
  for (const auto &member : metadata.layout_members)
    if (!std::memchr(member.name, 0, sizeof(member.name)) ||
        member.type > metadata.layout_types.size() ||
        (member.available && !member.type))
      return false;
  for (const auto &node : metadata.layout_types) {
    if (node.kind < CT_LAYOUT_UNKNOWN || node.kind > CT_LAYOUT_POINTER ||
        node.scalar.kind < CT_VALUE_UNKNOWN ||
        node.scalar.kind > CT_VALUE_POINTER ||
        node.element_type > metadata.layout_types.size() ||
        node.first_member > metadata.layout_members.size() ||
        node.member_count > metadata.layout_members.size() - node.first_member)
      return false;
    if (node.kind != CT_LAYOUT_ARRAY &&
        (node.element_type || node.element_count || node.element_stride))
      return false;
    if (node.kind != CT_LAYOUT_STRUCT &&
        (node.first_member || node.member_count))
      return false;
    if (node.kind == CT_LAYOUT_SCALAR) {
      if (!node.bytes || node.bytes > 8 || node.scalar.bytes != node.bytes ||
          node.scalar.kind < CT_VALUE_SIGNED ||
          node.scalar.kind >= CT_VALUE_POINTER ||
          (node.scalar.kind == CT_VALUE_FLOAT && node.bytes != 4 &&
           node.bytes != 8))
        return false;
    } else if (node.scalar.kind != CT_VALUE_UNKNOWN || node.scalar.bytes) {
      return false;
    }
    if (node.kind == CT_LAYOUT_POINTER && node.bytes != 8)
      return false;
    if (node.kind == CT_LAYOUT_ARRAY) {
      if (!node.element_type || !node.element_stride ||
          node.element_count > node.bytes / node.element_stride ||
          node.bytes != node.element_count * node.element_stride ||
          metadata.layout_types[node.element_type - 1].bytes >
              node.element_stride)
        return false;
    } else if (node.kind == CT_LAYOUT_STRUCT) {
      for (size_t index = 0; index < node.member_count; ++index) {
        const auto &member = metadata.layout_members[node.first_member + index];
        if (member.available && (member.offset > node.bytes ||
                                 metadata.layout_types[member.type - 1].bytes >
                                     node.bytes - member.offset))
          return false;
      }
    }
  }
  // Only by-value edges are retained; pointer targets are not graph edges.
  // Reject a forged cycle or excessive nesting before any traversal uses it.
  std::vector<unsigned char> visited(metadata.layout_types.size());
  std::vector<unsigned> heights(metadata.layout_types.size());
  struct LayoutVisit {
    uint32_t id;
    unsigned depth;
    bool finish;
  };
  for (uint32_t root = 1; root <= metadata.layout_types.size(); ++root) {
    std::vector<LayoutVisit> pending{{root, 0, false}};
    while (!pending.empty()) {
      const auto visit = pending.back();
      pending.pop_back();
      auto &state = visited[visit.id - 1];
      if (visit.finish) {
        const auto &node = metadata.layout_types[visit.id - 1];
        unsigned height = 1;
        if (node.kind == CT_LAYOUT_ARRAY)
          height += heights[node.element_type - 1];
        else if (node.kind == CT_LAYOUT_STRUCT)
          for (size_t index = 0; index < node.member_count; ++index) {
            const auto &member =
                metadata.layout_members[node.first_member + index];
            if (member.available)
              height = std::max(height, 1 + heights[member.type - 1]);
          }
        if (height > kernel_value_depth_limit)
          return false;
        heights[visit.id - 1] = height;
        state = 2;
        continue;
      }
      if (state == 2)
        continue;
      if (state || visit.depth >= kernel_value_depth_limit)
        return false;
      state = 1;
      pending.push_back({visit.id, visit.depth, true});
      const auto &node = metadata.layout_types[visit.id - 1];
      if (node.kind == CT_LAYOUT_ARRAY)
        pending.push_back({node.element_type, visit.depth + 1, false});
      else if (node.kind == CT_LAYOUT_STRUCT)
        for (size_t index = 0; index < node.member_count; ++index) {
          const auto &member =
              metadata.layout_members[node.first_member + index];
          if (member.available)
            pending.push_back({member.type, visit.depth + 1, false});
        }
    }
  }
  for (size_t index = 0; index < metadata.functions.size(); ++index) {
    const auto &value = metadata.functions[index];
    if (value.return_type >= metadata.types.size() ||
        (index &&
         (!value.die || value.die >= debug_size || value.unit >= value.die)) ||
        (!index &&
         (value.die || value.unit || value.return_type || value.returns_void)))
      return false;
  }
  for (const auto &recipe : metadata.recipes) {
    if (recipe.entry_register != kernel_entry_register(recipe))
      return false;
    for (const auto &operation : recipe.operations) {
      if (llvm::dwarf::OperationEncodingString(operation.opcode).empty())
        return false;
      // Decode the operation's operand shape through LLVM's DWARF table. A
      // zero-filled operand sequence supplies empty LEB/block operands; no
      // cached expression is executed or allowed to allocate block contents.
      std::array<uint8_t, 32> encoded{};
      encoded[0] = operation.opcode;
      const llvm::DataExtractor data(encoded, true, 8);
      const llvm::DWARFExpression expression(data, 8, llvm::dwarf::DWARF32);
      const auto first = expression.begin();
      const auto &shape = *first;
      if (shape.isError() || (!shape.getNumOperands() && operation.operand) ||
          (shape.getNumOperands() < 2 && operation.operand2) ||
          ((operation.opcode == llvm::dwarf::DW_OP_regx ||
            operation.opcode == llvm::dwarf::DW_OP_bregx) &&
           operation.operand > UINT32_MAX))
        return false;
      if (operation.opcode == llvm::dwarf::DW_OP_addr) {
        if (operation.section == UINT32_MAX && !recipe.error.empty())
          continue;
        if (operation.section >= image.sections.size() ||
            !(image.sections[operation.section].flags & SHF_ALLOC) ||
            operation.operand > image.sections[operation.section].size ||
            operation.operand2)
          return false;
      } else if (operation.section != UINT32_MAX) {
        return false;
      }
    }
  }
  uint64_t largest = 0;
  std::set<uint64_t> probes;
  for (const auto &site : sites)
    if (site.probe) {
      largest = std::max(largest, site.id);
      probes.insert(site.id);
    }
  if (metadata.sites.size() != largest + 1)
    return false;
  for (size_t index = 0; index < metadata.sites.size(); ++index) {
    const auto &site = metadata.sites[index];
    if (site.function >= metadata.functions.size() ||
        site.frame_recipe >= metadata.recipes.size() || site.capture_plan ||
        (!site.function && site.frame_recipe) ||
        (!probes.count(index) &&
         (site.function || site.frame_recipe || !site.bindings.empty())))
      return false;
    uint64_t previous = 0;
    for (const auto &binding : site.bindings) {
      if (binding.variable <= previous ||
          binding.variable >= metadata.variables.size() ||
          binding.recipe >= metadata.recipes.size() ||
          binding.capture_slot != UINT32_MAX || binding.capture_group ||
          binding.preferred)
        return false;
      previous = binding.variable;
    }
  }
  return true;
}

struct KernelValueLocation {
  std::optional<llvm::DWARFAddressRange> range;
  uint32_t recipe = 0;
};

struct KernelValueScope {
  llvm::DWARFAddressRangesVector ranges;
  std::vector<KernelValueLocation> locations, frame;
};

static ct_kernel_value_type kernel_value_type(llvm::DWARFDie type) {
  ct_kernel_value_type result;
  std::set<std::pair<const llvm::DWARFUnit *, uint64_t>> visited;
  while (type && visited.size() < kernel_value_depth_limit &&
         visited.emplace(type.getDwarfUnit(), type.getOffset()).second) {
    using namespace llvm::dwarf;
    const bool direct_name = result.name.empty();
    if (direct_name)
      if (const char *name = type.getName(llvm::DINameKind::ShortName))
        result.name = name;
    const auto tag = type.getTag();
    if (direct_name && !result.name.empty()) {
      if (tag == DW_TAG_structure_type)
        result.name = "struct " + result.name;
      else if (tag == DW_TAG_union_type)
        result.name = "union " + result.name;
      else if (tag == DW_TAG_enumeration_type)
        result.name = "enum " + result.name;
    }
    if (tag == DW_TAG_volatile_type || tag == DW_TAG_atomic_type)
      result.guarded = true;
    if (tag == DW_TAG_typedef || tag == DW_TAG_const_type ||
        tag == DW_TAG_volatile_type || tag == DW_TAG_restrict_type ||
        tag == DW_TAG_atomic_type) {
      type = type.getAttributeValueAsReferencedDie(DW_AT_type);
      continue;
    }
    result.scalar.bytes = type.getTypeSize(8).value_or(0);
    if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
        tag == DW_TAG_rvalue_reference_type) {
      result.scalar.kind = CT_VALUE_POINTER;
      if (result.name.empty()) {
        auto pointee = type.getAttributeValueAsReferencedDie(DW_AT_type);
        const char *name =
            pointee ? pointee.getName(llvm::DINameKind::ShortName) : nullptr;
        const bool untyped = !type.findRecursively({DW_AT_type});
        std::string prefix;
        if (pointee && pointee.getTag() == DW_TAG_structure_type)
          prefix = "struct ";
        else if (pointee && pointee.getTag() == DW_TAG_union_type)
          prefix = "union ";
        else if (pointee && pointee.getTag() == DW_TAG_enumeration_type)
          prefix = "enum ";
        result.name = prefix + (name ? name : untyped ? "void" : "?") + " *";
      }
    } else if (tag == DW_TAG_base_type || tag == DW_TAG_enumeration_type) {
      auto encoding = type.find(DW_AT_encoding);
      if (!encoding && tag == DW_TAG_enumeration_type) {
        auto underlying = type.getAttributeValueAsReferencedDie(DW_AT_type);
        if (underlying)
          encoding = underlying.find(DW_AT_encoding);
      }
      switch (encoding ? encoding->getAsUnsignedConstant().value_or(0) : 0) {
      case DW_ATE_signed:
      case DW_ATE_signed_char:
        result.scalar.kind = CT_VALUE_SIGNED;
        break;
      case DW_ATE_unsigned:
      case DW_ATE_unsigned_char:
      case DW_ATE_UTF:
        result.scalar.kind = CT_VALUE_UNSIGNED;
        break;
      case DW_ATE_boolean:
        result.scalar.kind = CT_VALUE_BOOLEAN;
        break;
      case DW_ATE_float:
        result.scalar.kind = CT_VALUE_FLOAT;
        break;
      default:
        break;
      }
    }
    if (result.name.empty())
      result.name = "?";
    return result;
  }
  result.scalar = {};
  if (result.name.empty())
    result.name = "?";
  return result;
}

static uint32_t kernel_value_layout(
    llvm::DWARFDie original, ct_kernel_value_metadata &metadata,
    std::map<std::pair<const llvm::DWARFUnit *, uint64_t>, uint32_t> &interned,
    std::set<std::pair<const llvm::DWARFUnit *, uint64_t>> &active,
    unsigned depth, std::string &error) {
  using namespace llvm::dwarf;
  if (!original || depth >= kernel_value_depth_limit)
    return 0;
  const auto identity =
      std::make_pair(original.getDwarfUnit(), original.getOffset());
  if (active.count(identity))
    return 0;
  if (const auto found = interned.find(identity); found != interned.end())
    return found->second;
  if (metadata.layout_types.size() >= kernel_value_pool_limit) {
    error = "kernel value layout inventory exceeds its bound";
    return 0;
  }
  const uint32_t id = metadata.layout_types.size() + 1;
  interned.emplace(identity, id);
  metadata.layout_types.emplace_back();
  active.insert(identity);
  const auto description = kernel_value_type(original);
  ct_value_layout_node node{};
  node.bytes = description.scalar.bytes;
  node.guarded = description.guarded;
  auto type = original;
  std::set<std::pair<const llvm::DWARFUnit *, uint64_t>> qualifiers;
  while (type && qualifiers.size() < kernel_value_depth_limit &&
         qualifiers.emplace(type.getDwarfUnit(), type.getOffset()).second) {
    const auto tag = type.getTag();
    if (tag == DW_TAG_typedef || tag == DW_TAG_const_type ||
        tag == DW_TAG_volatile_type || tag == DW_TAG_restrict_type ||
        tag == DW_TAG_atomic_type) {
      type = type.getAttributeValueAsReferencedDie(DW_AT_type);
      continue;
    }
    if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
        tag == DW_TAG_rvalue_reference_type) {
      if (node.bytes == 8) {
        node.kind = CT_LAYOUT_POINTER;
        node.complete = true;
      }
    } else if (tag == DW_TAG_base_type || tag == DW_TAG_enumeration_type) {
      const auto &scalar = description.scalar;
      if (scalar.kind >= CT_VALUE_SIGNED && scalar.kind < CT_VALUE_POINTER &&
          scalar.bytes && scalar.bytes <= 8 &&
          (scalar.kind != CT_VALUE_FLOAT || scalar.bytes == 4 ||
           scalar.bytes == 8)) {
        node.kind = CT_LAYOUT_SCALAR;
        node.scalar = scalar;
        node.complete = true;
      }
    } else if ((tag == DW_TAG_structure_type || tag == DW_TAG_class_type) &&
               node.bytes) {
      std::vector<ct_value_layout_member> members;
      for (const auto &member : type.children()) {
        if (member.getTag() != DW_TAG_member &&
            member.getTag() != DW_TAG_inheritance)
          continue;
        const auto external = member.find(DW_AT_external);
        const auto declaration = member.find(DW_AT_declaration);
        if ((external && external->getAsUnsignedConstant().value_or(0)) ||
            (declaration && declaration->getAsUnsignedConstant().value_or(0)))
          continue;
        if (metadata.layout_members.size() + members.size() >=
            kernel_value_entry_limit) {
          error = "kernel value member inventory exceeds its bound";
          break;
        }
        ct_value_layout_member output{};
        const auto member_type =
            member.getAttributeValueAsReferencedDie(DW_AT_type);
        const char *name = member.getName(llvm::DINameKind::ShortName);
        if (!name && member.getTag() == DW_TAG_inheritance && member_type)
          name = member_type.getName(llvm::DINameKind::ShortName);
        if (name && std::strlen(name) < sizeof(output.name))
          std::memcpy(output.name, name, std::strlen(name) + 1);
        else if (name)
          std::memcpy(output.name, "?", 2);
        const auto location = member.find(DW_AT_data_member_location);
        const auto offset = location ? location->getAsUnsignedConstant()
                                     : std::optional<uint64_t>{};
        if (!member.find(DW_AT_bit_size) &&
            !member.find(DW_AT_data_bit_offset) && offset &&
            *offset <= node.bytes) {
          output.type = kernel_value_layout(member_type, metadata, interned,
                                            active, depth + 1, error);
          output.offset = size_t(*offset);
          output.available =
              output.type && metadata.layout_types[output.type - 1].bytes <=
                                 node.bytes - output.offset;
        }
        members.push_back(output);
      }
      if (metadata.layout_members.size() + members.size() >
          kernel_value_entry_limit)
        error = "kernel value member inventory exceeds its bound";
      if (error.empty()) {
        node.kind = CT_LAYOUT_STRUCT;
        node.first_member = metadata.layout_members.size();
        node.member_count = members.size();
        const auto declaration = type.find(DW_AT_declaration);
        node.complete =
            !declaration || !declaration->getAsUnsignedConstant().value_or(0);
        metadata.layout_members.insert(metadata.layout_members.end(),
                                       members.begin(), members.end());
      }
    } else if (tag == DW_TAG_array_type && !type.find(DW_AT_bit_stride) &&
               !type.find(DW_AT_byte_stride)) {
      std::vector<uint64_t> counts;
      bool known = true;
      for (const auto &range : type.children()) {
        if (range.getTag() != DW_TAG_subrange_type)
          continue;
        if (counts.size() + depth + 1 >= kernel_value_depth_limit ||
            range.find(DW_AT_bit_stride) || range.find(DW_AT_byte_stride)) {
          known = false;
          break;
        }
        const auto count = range.find(DW_AT_count);
        auto number =
            count ? count->getAsUnsignedConstant() : std::optional<uint64_t>{};
        if (!number) {
          const auto upper = range.find(DW_AT_upper_bound);
          const auto lower = range.find(DW_AT_lower_bound);
          const auto high = upper ? upper->getAsUnsignedConstant()
                                  : std::optional<uint64_t>{};
          const auto low = lower ? lower->getAsUnsignedConstant()
                                 : std::optional<uint64_t>{0};
          if (high && low && *high >= *low && *high - *low != UINT64_MAX)
            number = *high - *low + 1;
        }
        if (!number || *number > SIZE_MAX) {
          known = false;
          break;
        }
        counts.push_back(*number);
      }
      uint32_t element =
          known && !counts.empty()
              ? kernel_value_layout(
                    type.getAttributeValueAsReferencedDie(DW_AT_type), metadata,
                    interned, active, depth + counts.size(), error)
              : 0;
      for (size_t dimension = counts.size(); element && dimension;
           --dimension) {
        const size_t stride = metadata.layout_types[element - 1].bytes;
        if (!stride || counts[dimension - 1] > SIZE_MAX / stride)
          break;
        ct_value_layout_node array{};
        array.kind = CT_LAYOUT_ARRAY;
        array.bytes = size_t(counts[dimension - 1]) * stride;
        array.element_type = element;
        array.element_count = counts[dimension - 1];
        array.element_stride = stride;
        array.complete = true;
        if (dimension == 1) {
          if (!node.bytes || node.bytes == array.bytes) {
            array.guarded = node.guarded;
            node = array;
          }
        } else {
          if (metadata.layout_types.size() >= kernel_value_pool_limit) {
            error = "kernel value array layout exceeds its bound";
            break;
          }
          metadata.layout_types.push_back(array);
          element = metadata.layout_types.size();
        }
      }
    }
    break;
  }
  metadata.layout_types[id - 1] = node;
  active.erase(identity);
  return id;
}

static uint32_t kernel_value_recipe(llvm::ArrayRef<uint8_t> bytes,
                                    const llvm::DWARFUnit &unit,
                                    std::optional<uint64_t> info_offset,
                                    const ct_kernel_image &image,
                                    ct_kernel_value_metadata &metadata,
                                    std::map<std::string, uint32_t> &interned,
                                    std::string failure = {}) {
  ct_kernel_value_recipe recipe;
  recipe.error = std::move(failure);
  if (bytes.size() > kernel_value_expression_limit * 16)
    recipe.error = "location expression exceeds its byte bound";
  if (recipe.error.empty()) {
    const llvm::DataExtractor data(bytes, true, unit.getAddressByteSize());
    const llvm::DWARFExpression expression(data, unit.getAddressByteSize(),
                                           unit.getFormat());
    for (const auto &operation : expression) {
      if (operation.isError() ||
          recipe.operations.size() >= kernel_value_expression_limit) {
        recipe.error = "malformed or oversized location expression";
        break;
      }
      ct_kernel_value_operation saved;
      saved.opcode = operation.getCode();
      if (operation.getNumOperands())
        saved.operand = operation.getRawOperand(0);
      if (operation.getNumOperands() > 1)
        saved.operand2 = operation.getRawOperand(1);
      if (saved.opcode == llvm::dwarf::DW_OP_addr) {
        if (info_offset) {
          const uint64_t operand_offset = *info_offset +
                                          operation.getOperandEndOffset(0) -
                                          unit.getAddressByteSize();
          for (const auto &relocation : image.relocations) {
            if (image.sections[relocation.section].name != ".debug_info" ||
                relocation.offset != operand_offset ||
                relocation.type != R_X86_64_64)
              continue;
            for (const auto &symbol : image.symbols) {
              if (symbol.table != relocation.symbol_table ||
                  symbol.index != relocation.symbol || !symbol.section ||
                  symbol.section >= image.sections.size())
                continue;
              const uint64_t offset = symbol.offset + relocation.addend;
              if (offset <= image.sections[symbol.section].size &&
                  (image.sections[symbol.section].flags & SHF_ALLOC)) {
                saved.section = symbol.section;
                saved.operand = offset;
              }
              break;
            }
            break;
          }
        }
        if (saved.section == UINT32_MAX)
          recipe.error = "module address lacks a resolved section relocation";
      }
      recipe.operations.push_back(saved);
    }
  }
  recipe.entry_register = kernel_entry_register(recipe);
  std::string key = recipe.error;
  key.push_back('\0');
  for (const auto &operation : recipe.operations) {
    key += std::to_string(operation.opcode) + ':' +
           std::to_string(operation.operand) + ':' +
           std::to_string(operation.operand2) + ':' +
           std::to_string(operation.section) + ';';
  }
  auto [entry, inserted] = interned.emplace(key, metadata.recipes.size());
  if (inserted)
    metadata.recipes.push_back(std::move(recipe));
  return entry->second;
}

static std::vector<KernelValueLocation>
kernel_value_locations(llvm::DWARFDie die, llvm::dwarf::Attribute attribute,
                       const ct_kernel_image &image,
                       ct_kernel_value_metadata &metadata,
                       std::map<std::string, uint32_t> &interned) {
  std::vector<KernelValueLocation> result;
  auto value = die.findRecursively({attribute});
  if (!value)
    return result;
  if (const auto bytes = value->getAsBlock()) {
    const auto *unit = value->getUnit();
    const auto &section = unit->getInfoSection().Data;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(section.data());
    const uintptr_t address = reinterpret_cast<uintptr_t>(bytes->data());
    std::optional<uint64_t> offset;
    if (address >= begin && address - begin <= section.size() &&
        bytes->size() <= section.size() - (address - begin))
      offset = address - begin;
    result.push_back({{},
                      kernel_value_recipe(*bytes, *unit, offset, image,
                                          metadata, interned)});
    return result;
  }
  auto locations = die.getLocations(attribute);
  if (!locations) {
    result.push_back(
        {{},
         kernel_value_recipe({}, *die.getDwarfUnit(), {}, image, metadata,
                             interned, llvm::toString(locations.takeError()))});
    return result;
  }
  if (locations->size() > kernel_value_pool_limit) {
    result.push_back({{},
                      kernel_value_recipe(
                          {}, *die.getDwarfUnit(), {}, image, metadata,
                          interned, "location list exceeds its entry bound")});
    return result;
  }
  for (const auto &location : *locations)
    result.push_back(
        {location.Range, kernel_value_recipe(location.Expr, *die.getDwarfUnit(),
                                             {}, image, metadata, interned)});
  return result;
}

static bool collect_kernel_values(const ct_kernel_image &image,
                                  const std::vector<ct_kernel_site> &sites,
                                  ct_kernel_value_metadata &metadata,
                                  std::string &error) {
  metadata = {};
  error.clear();
  uint64_t largest = 0;
  for (const auto &site : sites)
    if (site.probe)
      largest = std::max(largest, site.id);
  if (largest > kernel_value_entry_limit ||
      sites.size() > kernel_value_entry_limit) {
    error = "kernel value site inventory exceeds its bound";
    return false;
  }
  metadata.sites.resize(largest + 1);
  auto object = llvm::object::ObjectFile::createObjectFile(
      llvm::MemoryBufferRef({reinterpret_cast<const char *>(image.bytes.data()),
                             image.bytes.size()},
                            image.path));
  if (!object) {
    error = llvm::toString(object.takeError());
    return false;
  }
  const auto diagnostic = [&](llvm::Error issue) {
    auto message = llvm::toString(std::move(issue));
    if (error.empty())
      error = "kernel variable DWARF: " + message;
  };
  auto dwarf = llvm::DWARFContext::create(
      **object, llvm::DWARFContext::ProcessDebugRelocations::Process, nullptr,
      "", diagnostic, diagnostic);
  std::vector<KernelValueScope> scopes(1), functions(1);
  std::map<std::string, uint32_t> recipes;
  std::map<std::pair<const llvm::DWARFUnit *, uint64_t>, uint32_t> types;
  std::map<std::pair<const llvm::DWARFUnit *, uint64_t>, uint32_t> layouts;
  std::set<std::pair<const llvm::DWARFUnit *, uint64_t>> active_layouts;
  std::map<uint64_t, llvm::DWARFAddressRangesVector> unit_ranges;
  const auto collect_type = [&](llvm::DWARFDie die) {
    const auto attribute = die.findRecursively({llvm::dwarf::DW_AT_type});
    if (!attribute)
      return uint32_t(0);
    auto type = die.getAttributeValueAsReferencedDie(*attribute);
    if (!type)
      return uint32_t(0);
    auto [entry, inserted] =
        types.emplace(std::make_pair(type.getDwarfUnit(), type.getOffset()),
                      metadata.types.size());
    if (inserted) {
      auto value = kernel_value_type(type);
      value.layout_type = kernel_value_layout(type, metadata, layouts,
                                              active_layouts, 0, error);
      if (value.layout_type)
        value.scalar.bytes = metadata.layout_types[value.layout_type - 1].bytes;
      if (value.name == "?" && value.layout_type) {
        uint32_t layout = value.layout_type;
        std::string dimensions;
        unsigned depth = 0;
        while (layout && depth++ < kernel_value_depth_limit) {
          const auto &node = metadata.layout_types[layout - 1];
          if (node.kind != CT_LAYOUT_ARRAY || !node.complete)
            break;
          dimensions += '[' + std::to_string(node.element_count) + ']';
          layout = node.element_type;
        }
        auto element = type;
        depth = 0;
        while (element && depth++ < kernel_value_depth_limit) {
          const auto tag = element.getTag();
          if (tag != llvm::dwarf::DW_TAG_array_type &&
              tag != llvm::dwarf::DW_TAG_typedef &&
              tag != llvm::dwarf::DW_TAG_const_type &&
              tag != llvm::dwarf::DW_TAG_volatile_type &&
              tag != llvm::dwarf::DW_TAG_restrict_type &&
              tag != llvm::dwarf::DW_TAG_atomic_type)
            break;
          element =
              element.getAttributeValueAsReferencedDie(llvm::dwarf::DW_AT_type);
        }
        if (!dimensions.empty() && element &&
            depth < kernel_value_depth_limit) {
          const auto base = kernel_value_type(element);
          if (base.name != "?")
            value.name = base.name + dimensions;
        }
      }
      metadata.types.push_back(std::move(value));
    }
    return entry->second;
  };
  size_t dies = 0, location_count = 0;
  for (const auto &unit : dwarf->normal_units()) {
    struct Pending {
      llvm::DWARFDie die, function;
      llvm::DWARFAddressRangesVector ranges;
      uint64_t scope = 0;
      unsigned depth = 0;
      bool local = false, concrete = false;
      std::string owner;
    };
    std::vector<Pending> pending{
        {unit->getUnitDIE(false), {}, {}, 0, 0, false, false, {}}};
    while (!pending.empty()) {
      auto current = std::move(pending.back());
      pending.pop_back();
      if (!current.die)
        continue;
      if (++dies > kernel_value_entry_limit ||
          current.depth > kernel_value_depth_limit) {
        error = "kernel variable DIE tree exceeds its bound";
        return false;
      }
      using namespace llvm::dwarf;
      const auto tag = current.die.getTag();
      if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine) {
        const char *owner =
            current.die.getSubroutineName(llvm::DINameKind::LinkageName);
        if (!owner)
          owner = current.die.getSubroutineName(llvm::DINameKind::ShortName);
        current.owner = owner ? owner : "";
      }
      if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine ||
          tag == DW_TAG_lexical_block) {
        current.local = true;
        current.scope = current.die.getOffset();
        auto ranges = current.die.getAddressRanges();
        if (!ranges) {
          llvm::consumeError(ranges.takeError());
          current.ranges.clear();
        } else {
          current.ranges = std::move(*ranges);
          current.ranges.erase(
              std::remove_if(
                  current.ranges.begin(), current.ranges.end(),
                  [&](const auto &range) {
                    return range.SectionIndex >= image.sections.size() ||
                           !(image.sections[range.SectionIndex].flags &
                             SHF_EXECINSTR) ||
                           range.LowPC >= range.HighPC ||
                           range.HighPC >
                               image.sections[range.SectionIndex].size;
                  }),
              current.ranges.end());
        }
        if (tag == DW_TAG_subprogram) {
          current.function = current.die;
          current.concrete = !current.ranges.empty();
          auto &ranges = unit_ranges[unit->getOffset()];
          ranges.insert(ranges.end(), current.ranges.begin(),
                        current.ranges.end());
          if (!current.ranges.empty()) {
            if (metadata.functions.size() >= kernel_value_pool_limit) {
              error = "kernel function value inventory exceeds its bound";
              return false;
            }
            ct_kernel_value_function function;
            function.die = current.die.getOffset();
            function.unit = unit->getOffset();
            function.return_type = collect_type(current.die);
            function.returns_void = !current.die.findRecursively({DW_AT_type});
            metadata.functions.push_back(function);
            KernelValueScope scope;
            scope.ranges = current.ranges;
            scope.frame = kernel_value_locations(current.die, DW_AT_frame_base,
                                                 image, metadata, recipes);
            functions.push_back(std::move(scope));
          }
        }
      }
      if ((tag == DW_TAG_variable || tag == DW_TAG_formal_parameter) &&
          (!current.local || current.concrete)) {
        const char *name = current.die.getName(llvm::DINameKind::ShortName);
        if (name && *name) {
          if (metadata.variables.size() >= kernel_value_pool_limit) {
            error = "kernel variable inventory exceeds its bound";
            return false;
          }
          ct_kernel_value_variable variable;
          variable.id = metadata.variables.size();
          variable.die = current.die.getOffset();
          variable.unit = unit->getOffset();
          variable.scope = current.scope;
          variable.depth = current.depth;
          variable.function =
              current.function ? current.function.getOffset() : 0;
          variable.global = !current.local;
          variable.parameter = tag == DW_TAG_formal_parameter;
          variable.name = name;
          variable.owner = current.owner;
          variable.type = collect_type(current.die);
          KernelValueScope scope;
          scope.ranges = current.ranges;
          scope.locations = kernel_value_locations(current.die, DW_AT_location,
                                                   image, metadata, recipes);
          if (scope.locations.empty()) {
            const auto constant =
                current.die.findRecursively({DW_AT_const_value});
            if (constant) {
              auto value = constant->getAsUnsignedConstant();
              if (!value)
                if (const auto signed_value = constant->getAsSignedConstant())
                  value = uint64_t(*signed_value);
              if (value) {
                std::array<uint8_t, 10> expression{};
                expression[0] = DW_OP_const8u;
                std::memcpy(expression.data() + 1, &*value, 8);
                expression[9] = DW_OP_stack_value;
                scope.locations.push_back(
                    {{},
                     kernel_value_recipe(expression, *unit, {}, image, metadata,
                                         recipes)});
              }
            }
          }
          location_count += scope.locations.size() + scope.ranges.size();
          if (location_count > kernel_value_entry_limit ||
              metadata.recipes.size() >= kernel_value_pool_limit) {
            error = "kernel value location inventory exceeds its bound";
            return false;
          }
          metadata.variables.push_back(std::move(variable));
          scopes.push_back(std::move(scope));
        }
      }
      for (auto child : current.die.children())
        pending.push_back({child, current.function, current.ranges,
                           current.scope, current.depth + 1, current.local,
                           current.concrete, current.owner});
    }
  }
  struct Range {
    uint64_t begin, end, prefix_end, variable, function;
  };
  std::map<uint32_t, std::vector<Range>> index;
  for (size_t function = 1; function < functions.size(); ++function)
    for (const auto &range : functions[function].ranges)
      index[range.SectionIndex].push_back(
          {range.LowPC, range.HighPC, 0, 0, function});
  for (const auto &variable : metadata.variables) {
    if (!variable.id)
      continue;
    const auto &ranges = variable.global ? unit_ranges[variable.unit]
                                         : scopes[variable.id].ranges;
    for (const auto &range : ranges) {
      if (++location_count > kernel_value_entry_limit) {
        error = "kernel value scope ranges exceed their bound";
        return false;
      }
      index[range.SectionIndex].push_back(
          {range.LowPC, range.HighPC, 0, variable.id, 0});
    }
  }
  for (auto &[section, ranges] : index) {
    std::sort(ranges.begin(), ranges.end(), [](const auto &a, const auto &b) {
      return std::tie(a.begin, a.end, a.variable, a.function) <
             std::tie(b.begin, b.end, b.variable, b.function);
    });
    uint64_t end = 0;
    for (auto &range : ranges)
      range.prefix_end = end = std::max(end, range.end);
  }
  size_t binding_count = 0;
  for (const auto &site : sites) {
    if (!site.probe)
      continue;
    if (!site.id || site.section >= image.sections.size()) {
      error = "invalid kernel value site identity";
      return false;
    }
    const auto &ranges = index[site.section];
    auto position = std::upper_bound(ranges.begin(), ranges.end(), site.offset,
                                     [](uint64_t offset, const auto &range) {
                                       return offset < range.begin;
                                     });
    std::set<uint64_t> visible, owners;
    while (position != ranges.begin()) {
      --position;
      if (position->prefix_end <= site.offset)
        break;
      if (site.offset < position->end) {
        if (position->variable)
          visible.insert(position->variable);
        if (position->function)
          owners.insert(position->function);
      }
    }
    const auto select = [&](const auto &locations) {
      uint32_t found = 0, fallback = 0;
      for (const auto &location : locations) {
        if (!location.range) {
          if (fallback && fallback != location.recipe)
            return uint32_t(0);
          fallback = location.recipe;
        } else if (location.range->SectionIndex == site.section &&
                   location.range->LowPC <= site.offset &&
                   site.offset < location.range->HighPC) {
          if (found && found != location.recipe)
            return uint32_t(0);
          found = location.recipe;
        }
      }
      return found ? found : fallback;
    };
    auto &output = metadata.sites[site.id];
    if (owners.size() == 1) {
      output.function = *owners.begin();
      output.frame_recipe = select(functions[output.function].frame);
    }
    for (uint64_t variable : visible) {
      if (++binding_count > kernel_value_entry_limit) {
        error = "kernel value site bindings exceed their bound";
        return false;
      }
      output.bindings.push_back({variable, select(scopes[variable].locations)});
    }
  }
  if (!error.empty()) {
    metadata = {};
    return false;
  }
  return true;
}

bool ct_kernel_collect_values(const ct_kernel_image &image,
                              const std::vector<ct_kernel_site> &sites,
                              ct_kernel_value_metadata &metadata,
                              std::string &error, bool *reused) {
  metadata = {};
  error.clear();
  if (reused)
    *reused = false;
  const auto key = kernel_value_cache_key(image, sites);
  if (key.empty()) {
    error = "invalid kernel value input inventory";
    return false;
  }
  std::vector<unsigned char> cached;
  if (ct_cache_read("kernel-values", key, cached)) {
    ct_kernel_value_metadata restored;
    if (kernel_value_archive(restored, cached, true, key) &&
        kernel_value_cache_valid(image, sites, restored)) {
      metadata = std::move(restored);
      if (reused)
        *reused = true;
      return true;
    }
  }
  // Malformed payloads and partially decoded pools must not coexist with the
  // LLVM traversal. The returned object is later extended by decompilation;
  // no second raw-DWARF metadata object survives into module execution.
  std::vector<unsigned char>().swap(cached);
  if (!collect_kernel_values(image, sites, metadata, error))
    return false;
  if (kernel_value_cache_valid(image, sites, metadata) &&
      kernel_value_archive(metadata, cached, false, key))
    ct_cache_write("kernel-values", key, cached);
  return true;
}

bool ct_kernel_evaluate_value(const ct_kernel_value_metadata &metadata,
                              const ct_kernel_value_binding &binding,
                              const kctrace_event &event,
                              ct_kernel_value_result &result,
                              const kctrace_event *entry) {
  result = {};
  const auto fail = [&](const char *message) {
    result.size = 0;
    result.error = message;
    return false;
  };
  if (!binding.variable || binding.variable >= metadata.variables.size() ||
      event.size != sizeof(event) || binding.capture_group)
    return fail("invalid captured variable identity");
  const auto &variable = metadata.variables[binding.variable];
  if (!variable.type || variable.type >= metadata.types.size())
    return fail("variable type unavailable");
  const auto &type = metadata.types[variable.type];
  const size_t bytes = type.scalar.bytes;
  if (type.guarded || !bytes || bytes > 8 ||
      (type.scalar.kind < CT_VALUE_SIGNED &&
       !(type.scalar.kind == CT_VALUE_UNKNOWN && type.raw_scalar)) ||
      type.scalar.kind > CT_VALUE_POINTER || type.scalar.kind == CT_VALUE_FLOAT)
    return fail("unsupported or guarded variable type");
  if (!binding.recipe || binding.recipe >= metadata.recipes.size())
    return fail("no location at this instruction");
  const auto &recipe = metadata.recipes[binding.recipe];
  if (!recipe.error.empty())
    return fail(recipe.error.c_str());
  if (recipe.operations.empty() ||
      recipe.operations.size() > kernel_value_expression_limit)
    return fail("invalid location expression length");
  if (recipe.entry_register != UINT32_MAX) {
    if (recipe.entry_register != kernel_entry_register(recipe) ||
        binding.capture_slot != UINT32_MAX || !entry ||
        entry->size != sizeof(*entry) ||
        entry->type != KCTRACE_EVENT_EXECUTION ||
        !(entry->flags & KCTRACE_EVENT_HAVE_EXECUTION) ||
        !(event.flags & KCTRACE_EVENT_HAVE_EXECUTION) ||
        entry->execution.kind != KCTRACE_BOUNDARY_ENTER ||
        !(entry->execution.flags & KCTRACE_EXEC_ENTRY_VALUES) ||
        ((entry->execution.flags | event.execution.flags) &
         (KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY)) ||
        entry->execution.failure || event.execution.failure ||
        !entry->execution.frame_id || !entry->execution.function ||
        entry->execution.frame_id != event.execution.frame_id ||
        entry->execution.function != event.execution.function ||
        entry->session_id != event.session_id ||
        entry->generation != event.generation ||
        entry->task_start_ns != event.task_start_ns ||
        entry->tid != event.tid || entry->tgid != event.tgid ||
        entry->context != event.context ||
        entry->hardirq_depth != event.hardirq_depth ||
        entry->softirq_depth != event.softirq_depth ||
        (entry->context != KCTRACE_CONTEXT_TASK && entry->cpu != event.cpu) ||
        entry->sequence > event.sequence ||
        entry->monotonic_ns > event.monotonic_ns ||
        event.site_id >= metadata.sites.size() ||
        entry->site_id >= metadata.sites.size() || variable.global ||
        !variable.parameter || variable.scope != variable.function)
      return fail("entry register snapshot unavailable");
    const auto &site = metadata.sites[event.site_id];
    if (!site.function || site.function >= metadata.functions.size() ||
        site.function != metadata.sites[entry->site_id].function ||
        metadata.functions[site.function].die != variable.function ||
        metadata.functions[site.function].unit != variable.unit ||
        std::none_of(site.bindings.begin(), site.bindings.end(),
                     [&](const auto &current) {
                       return current.variable == binding.variable &&
                              current.recipe == binding.recipe &&
                              current.capture_slot == UINT32_MAX;
                     }))
      return fail("entry value does not belong to this physical parameter");
    const auto reg = kernel_value_registers[recipe.entry_register];
    if (!(entry->valid_registers & (UINT64_C(1) << reg)))
      return fail("entry register snapshot unavailable");
    std::memcpy(result.bytes.data(), &entry->registers[reg], bytes);
    result.size = bytes;
    return true;
  }
  if (binding.capture_slot != UINT32_MAX) {
    if (binding.capture_slot >= KCTRACE_VALUE_SLOTS ||
        event.site_id >= metadata.sites.size() ||
        !(event.flags & KCTRACE_EVENT_HAVE_VALUES) ||
        (event.flags & KCTRACE_EVENT_HAVE_MEMORY) ||
        event.capture_valid >> KCTRACE_VALUE_SLOTS)
      return fail("capture slots are absent or invalid");
    const auto &site = metadata.sites[event.site_id];
    if (!site.capture_plan || event.capture_plan != site.capture_plan ||
        !(event.capture_valid & (1U << binding.capture_slot)) ||
        std::none_of(site.bindings.begin(), site.bindings.end(),
                     [&](const auto &current) {
                       return current.variable == binding.variable &&
                              current.recipe == binding.recipe &&
                              current.capture_slot == binding.capture_slot;
                     }))
      return fail("capture slot does not match this instruction binding");
    std::memcpy(result.bytes.data(), event.capture_values[binding.capture_slot],
                bytes);
    result.size = bytes;
    return true;
  }
  enum Kind { address, reg, value };
  struct Item {
    Kind kind;
    uint64_t number;
  };
  std::array<Item, kernel_value_depth_limit> stack{};
  size_t depth = 0, written = 0;
  const auto register_value = [&](uint64_t number, uint64_t &output) {
    if (number >= std::size(kernel_value_registers) ||
        !(event.valid_registers &
          (UINT64_C(1) << kernel_value_registers[number])))
      return false;
    output = event.registers[kernel_value_registers[number]];
    return true;
  };
  const auto numeric = [&](const Item &item, uint64_t &output) {
    if (item.kind != address)
      return false;
    output = item.number;
    return true;
  };
  const auto materialize = [&](const Item &item, size_t count,
                               unsigned char *output) {
    uint64_t scalar;
    if (count > 8)
      return false;
    if (item.kind == reg) {
      if (!register_value(item.number, scalar))
        return false;
    } else {
      scalar = item.number;
    }
    if (item.kind == address) {
      if (!(event.flags & KCTRACE_EVENT_HAVE_MEMORY) ||
          (event.flags & KCTRACE_EVENT_HAVE_VALUES) ||
          event.memory_size > sizeof(event.memory) ||
          event.memory_size > UINT64_MAX - event.memory_address ||
          scalar < event.memory_address ||
          scalar - event.memory_address > event.memory_size ||
          count > event.memory_size - (scalar - event.memory_address))
        return false;
      std::memcpy(output, event.memory + (scalar - event.memory_address),
                  count);
    } else {
      std::memcpy(output, &scalar, count);
    }
    return true;
  };
  for (const auto &operation : recipe.operations) {
    using namespace llvm::dwarf;
    const auto code = operation.opcode;
    if (depth && stack[depth - 1].kind != address && code != DW_OP_piece &&
        code != DW_OP_nop)
      return fail("register/value location is not an arithmetic operand");
    const auto push = [&](Item item) {
      if (depth == stack.size())
        return false;
      stack[depth++] = item;
      return true;
    };
    if (code >= DW_OP_lit0 && code <= DW_OP_lit31) {
      if (!push({address, uint64_t(code - DW_OP_lit0)}))
        return fail("location stack overflow");
      continue;
    }
    if (code >= DW_OP_reg0 && code <= DW_OP_reg31) {
      if (!push({reg, uint64_t(code - DW_OP_reg0)}))
        return fail("location stack overflow");
      continue;
    }
    if ((code >= DW_OP_breg0 && code <= DW_OP_breg31) || code == DW_OP_bregx) {
      uint64_t scalar;
      if (!register_value(code == DW_OP_bregx ? operation.operand
                                              : code - DW_OP_breg0,
                          scalar))
        return fail("location register unavailable");
      if (!push({address, scalar + (code == DW_OP_bregx ? operation.operand2
                                                        : operation.operand)}))
        return fail("location stack overflow");
      continue;
    }
    if (code >= DW_OP_const1u && code <= DW_OP_consts) {
      if (!push({address, operation.operand}))
        return fail("location stack overflow");
      continue;
    }
    switch (code) {
    case DW_OP_regx:
      if (!push({reg, operation.operand}))
        return fail("location stack overflow");
      break;
    case DW_OP_addr:
      return fail("loaded section address unavailable");
    case DW_OP_fbreg:
    case DW_OP_call_frame_cfa:
      return fail("proven frame base or CFA unavailable");
    case DW_OP_entry_value:
    case DW_OP_GNU_entry_value:
      return fail("entry register snapshot unavailable");
    case DW_OP_stack_value: {
      uint64_t scalar;
      if (!depth || !numeric(stack[depth - 1], scalar))
        return fail("invalid stack value");
      stack[depth - 1] = {value, scalar};
      break;
    }
    case DW_OP_piece:
      if (depth != 1 || operation.operand > bytes - written ||
          !materialize(stack[depth - 1], operation.operand,
                       result.bytes.data() + written))
        return fail("unavailable or incomplete variable piece");
      written += operation.operand;
      depth = 0;
      break;
    case DW_OP_plus_uconst:
    case DW_OP_neg:
    case DW_OP_not:
    case DW_OP_abs: {
      uint64_t scalar;
      if (!depth || !numeric(stack[depth - 1], scalar))
        return fail("invalid unary location expression");
      if (code == DW_OP_plus_uconst)
        scalar += operation.operand;
      else if (code == DW_OP_not)
        scalar = ~scalar;
      else if (code == DW_OP_neg || int64_t(scalar) < 0)
        scalar = 0 - scalar;
      stack[depth - 1] = {address, scalar};
      break;
    }
    case DW_OP_plus:
    case DW_OP_minus:
    case DW_OP_mul:
    case DW_OP_and:
    case DW_OP_or:
    case DW_OP_xor:
    case DW_OP_shl:
    case DW_OP_shr:
    case DW_OP_shra: {
      uint64_t a, b;
      if (depth < 2 || !numeric(stack[depth - 2], a) ||
          !numeric(stack[depth - 1], b))
        return fail("invalid binary location expression");
      switch (code) {
      case DW_OP_plus:
        a += b;
        break;
      case DW_OP_minus:
        a -= b;
        break;
      case DW_OP_mul:
        a *= b;
        break;
      case DW_OP_and:
        a &= b;
        break;
      case DW_OP_or:
        a |= b;
        break;
      case DW_OP_xor:
        a ^= b;
        break;
      default:
        if (b >= 64)
          return fail("invalid location shift width");
        if (code == DW_OP_shl)
          a <<= b;
        else if (code == DW_OP_shr)
          a >>= b;
        else
          a = uint64_t(int64_t(a) >> b);
        break;
      }
      --depth;
      stack[depth - 1] = {address, a};
      break;
    }
    case DW_OP_dup:
    case DW_OP_over:
    case DW_OP_pick: {
      const uint64_t offset = code == DW_OP_dup    ? 0
                              : code == DW_OP_over ? 1
                                                   : operation.operand;
      if (offset >= depth || !push(stack[depth - 1 - offset]))
        return fail("invalid location stack copy");
      break;
    }
    case DW_OP_drop:
      if (!depth)
        return fail("location stack underflow");
      --depth;
      break;
    case DW_OP_swap:
      if (depth < 2)
        return fail("location stack underflow");
      std::swap(stack[depth - 1], stack[depth - 2]);
      break;
    case DW_OP_rot:
      if (depth < 3)
        return fail("location stack underflow");
      std::rotate(stack.begin() + depth - 3, stack.begin() + depth - 1,
                  stack.begin() + depth);
      break;
    case DW_OP_nop:
      break;
    default:
      return fail("unsupported location operation");
    }
  }
  if (written) {
    if (depth || written != bytes)
      return fail("incomplete variable pieces");
  } else if (depth != 1 || !materialize(stack[0], bytes, result.bytes.data())) {
    return fail("variable storage is absent from this snapshot");
  }
  result.size = bytes;
  return true;
}

std::string ct_kernel_format_value(const ct_kernel_value_metadata &metadata,
                                   const ct_kernel_value_binding &binding,
                                   const kctrace_event &event,
                                   const kctrace_event *entry) {
  if (!binding.variable || binding.variable >= metadata.variables.size() ||
      event.size != sizeof(event))
    return "?";
  const auto &variable = metadata.variables[binding.variable];
  if (!variable.type || variable.type >= metadata.types.size())
    return "?";
  const auto &type = metadata.types[variable.type];
  if (type.guarded || type.layout_type > metadata.layout_types.size())
    return "?";
  const auto *shape =
      type.layout_type ? &metadata.layout_types[type.layout_type - 1] : nullptr;
  if (!shape ||
      (shape->kind != CT_LAYOUT_STRUCT && shape->kind != CT_LAYOUT_ARRAY)) {
    ct_kernel_value_result value;
    if (!ct_kernel_evaluate_value(metadata, binding, event, value, entry))
      return "?";
    char output[128];
    const int length = ct_values_format_scalar(
        &type.scalar, value.bytes.data(), value.size, output, sizeof(output));
    return length >= 0 && size_t(length) < sizeof(output)
               ? std::string(output, size_t(length))
               : "?";
  }
  if (shape->guarded || shape->bytes != type.scalar.bytes ||
      event.site_id >= metadata.sites.size() ||
      binding.capture_slot != UINT32_MAX ||
      binding.capture_group >= metadata.capture_groups.size() ||
      (binding.capture_group &&
       (!binding.recipe || binding.recipe >= metadata.recipes.size() ||
        !metadata.recipes[binding.recipe].error.empty())))
    return "?";
  const auto &site = metadata.sites[event.site_id];
  if (std::none_of(site.bindings.begin(), site.bindings.end(),
                   [&](const auto &current) {
                     return current.variable == binding.variable &&
                            current.recipe == binding.recipe &&
                            current.capture_slot == UINT32_MAX &&
                            current.capture_group == binding.capture_group;
                   }))
    return "?";
  struct Captured {
    const kctrace_event *event;
    const std::vector<ct_kernel_value_capture> *spans;
    uint64_t bytes;
    bool available;
  } captured{
      &event, &metadata.capture_groups[binding.capture_group], shape->bytes,
      bool((event.flags & KCTRACE_EVENT_HAVE_VALUES) &&
           !(event.flags & KCTRACE_EVENT_HAVE_MEMORY) &&
           !(event.capture_valid >> KCTRACE_VALUE_SLOTS) && site.capture_plan &&
           event.capture_plan == site.capture_plan)};
  if (captured.spans->size() > KCTRACE_VALUE_SLOTS * 8)
    return "?";
  for (const auto &span : *captured.spans)
    if (!span.size || span.size > 8 || span.slot >= KCTRACE_VALUE_SLOTS ||
        span.offset > captured.bytes ||
        span.size > captured.bytes - span.offset)
      return "?";
  const auto read = [](void *argument, uint64_t offset, void *output,
                       size_t bytes) {
    const auto &source = *static_cast<const Captured *>(argument);
    if (!source.available || offset > source.bytes ||
        bytes > source.bytes - offset)
      return false;
    for (const auto &span : *source.spans)
      if (offset >= span.offset && offset - span.offset <= span.size &&
          bytes <= span.size - (offset - span.offset) &&
          (source.event->capture_valid & (UINT32_C(1) << span.slot))) {
        std::memcpy(output,
                    source.event->capture_values[span.slot] + offset -
                        span.offset,
                    bytes);
        return true;
      }
    return false;
  };
  const ct_value_layout layout{
      metadata.layout_types.data(), metadata.layout_types.size(),
      metadata.layout_members.data(), metadata.layout_members.size()};
  std::array<char, kernel_value_format_limit> output{};
  if (!ct_values_format_layout("v", &layout, type.layout_type, nullptr,
                               shape->bytes, 0, true, read, &captured,
                               output.data(), output.size()))
    return "?";
  return std::string(output.data() + 2);
}
