#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDataExtractor.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugFrame.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBufferRef.h>
#include <llvm/Support/SHA256.h>

#include <elf.h>

#include "analysis_cache.h"
#include "cache.h"
#include "kernel_capture.h"

static constexpr size_t capture_entry_limit = 1048576;
static constexpr size_t capture_plan_limit = 65536;
static constexpr size_t capture_expression_limit = 128;
static constexpr size_t capture_layout_visit_limit = 4096;
static constexpr size_t capture_cache_limit = 64 * 1024 * 1024;

bool ct_kernel_capture_section(const ct_kernel_section &section) {
  // Linux rewrite_section_headers() removes these input metadata sections
  // from the loaded module even when the original ELF marks them ALLOC.
  return (section.flags & SHF_ALLOC) &&
         !(section.flags & (SHF_EXECINSTR | SHF_TLS)) &&
         (section.type == SHT_PROGBITS || section.type == SHT_NOBITS) &&
         section.name.find("percpu") == std::string::npos &&
         section.name != ".modinfo" && section.name != "__versions" &&
         section.name != "__version_ext_crcs" &&
         section.name != "__version_ext_names";
}

struct CaptureAddress {
  uint8_t kind = KCTRACE_CAPTURE_NONE, reg = 0;
  uint32_t section = UINT32_MAX;
  __int128 offset = 0;
};

struct CaptureCFA {
  uint32_t section;
  uint64_t begin, end, prefix_end = 0;
  CaptureAddress address;
};

static bool capture_cfa(const ct_kernel_image &image,
                        std::map<uint32_t, std::vector<CaptureCFA>> &ranges,
                        std::string &error) {
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
      error = "kernel capture unwind metadata: " + message;
  };
  auto context = llvm::DWARFContext::create(
      **object, llvm::DWARFContext::ProcessDebugRelocations::Process, nullptr,
      "", diagnostic, diagnostic);
  auto frame = context->getDebugFrame();
  if (!frame) {
    error = llvm::toString(frame.takeError());
    return false;
  }
  if (!*frame)
    return error.empty();
  const auto &dwarf_object = context->getDWARFObj();
  const auto &section = dwarf_object.getFrameSection();
  const llvm::DWARFDataExtractor data(dwarf_object, section, true, 8);
  size_t count = 0;
  for (const auto &entry : (*frame)->entries()) {
    const auto *fde = llvm::dyn_cast<llvm::dwarf::FDE>(&entry);
    if (!fde || !fde->getLinkedCIE())
      continue;
    const auto *cie = fde->getLinkedCIE();
    if (!cie->getAugmentationString().empty() ||
        (cie->getVersion() != 1 && cie->getVersion() != 3 &&
         cie->getVersion() != 4))
      continue;
    llvm::Error issue = llvm::Error::success();
    if (cie->getVersion() == 4) {
      uint64_t offset = cie->getOffset();
      const auto length = data.getInitialLength(&offset, &issue);
      (void)data.getUnsigned(
          &offset, length.second == llvm::dwarf::DWARF64 ? 8 : 4, &issue);
      (void)data.getU8(&offset, &issue);
      (void)data.getCStrRef(&offset, &issue);
      const auto address_size = data.getU8(&offset, &issue);
      const auto segment_size = data.getU8(&offset, &issue);
      if (issue) {
        error = llvm::toString(std::move(issue));
        return false;
      }
      if (address_size != 8 || segment_size)
        continue;
    }
    uint64_t offset = fde->getOffset();
    const auto length = data.getInitialLength(&offset, &issue);
    (void)data.getUnsigned(
        &offset, length.second == llvm::dwarf::DWARF64 ? 8 : 4, &issue);
    const auto relocation = dwarf_object.find(section, offset);
    uint64_t code_section = llvm::object::SectionedAddress::UndefSection;
    const uint64_t begin =
        data.getRelocatedValue(8, &offset, &code_section, &issue);
    if (issue) {
      error = llvm::toString(std::move(issue));
      return false;
    }
    // Numeric initial PCs overlap across .text/.init.text/.exit.text in ET_REL.
    // Only an exact relocation proves which original code section owns an FDE.
    if (!relocation || relocation->Reloc2 ||
        relocation->Reloc.getType() != R_X86_64_64 ||
        code_section >= image.sections.size() ||
        !(image.sections[code_section].flags & SHF_EXECINSTR) ||
        begin != fde->getInitialLocation() ||
        begin > image.sections[code_section].size || !fde->getAddressRange() ||
        fde->getAddressRange() > image.sections[code_section].size - begin)
      continue;
    const auto absolute_row = [](const auto &program) {
      return std::any_of(program.begin(), program.end(), [](const auto &op) {
        return op.Opcode == llvm::dwarf::DW_CFA_set_loc;
      });
    };
    // Parsed set_loc operands no longer retain their relocation section.
    if (absolute_row(cie->cfis()) || absolute_row(fde->cfis())) {
      if (++count > capture_entry_limit) {
        error = "kernel capture CFA inventory exceeds its bound";
        return false;
      }
      ranges[code_section].push_back({uint32_t(code_section),
                                      begin,
                                      begin + fde->getAddressRange(),
                                      0,
                                      {}});
      continue;
    }
    auto table = llvm::dwarf::createUnwindTable(fde);
    if (!table) {
      error = llvm::toString(table.takeError());
      return false;
    }
    const uint64_t end = begin + fde->getAddressRange();
    for (size_t index = 0; index < table->size(); ++index) {
      const auto &row = (*table)[index];
      const auto finish = index + 1 == table->size() ? end
                          : (*table)[index + 1].hasAddress()
                              ? (*table)[index + 1].getAddress()
                              : 0;
      if (!row.hasAddress() || row.getAddress() < begin ||
          row.getAddress() > finish || finish > end) {
        error = "kernel capture CFA row exceeds its original FDE";
        return false;
      }
      const auto &cfa = row.getCFAValue();
      if (row.getAddress() == finish)
        continue;
      if (++count > capture_entry_limit) {
        error = "kernel capture CFA inventory exceeds its bound";
        return false;
      }
      CaptureAddress address;
      if (cfa.getLocation() == llvm::dwarf::UnwindLocation::RegPlusOffset &&
          !cfa.getDereference() && !cfa.hasAddressSpace() &&
          (cfa.getRegister() == 6 || cfa.getRegister() == 7))
        address = {
            KCTRACE_CAPTURE_STACK,
            uint8_t(cfa.getRegister() == 6 ? KCTRACE_REG_RBP : KCTRACE_REG_RSP),
            UINT32_MAX, cfa.getOffset()};
      ranges[code_section].push_back(
          {uint32_t(code_section), row.getAddress(), finish, 0, address});
    }
  }
  for (auto &[section_index, entries] : ranges) {
    std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
      return std::tie(a.begin, a.end, a.address.reg, a.address.offset) <
             std::tie(b.begin, b.end, b.address.reg, b.address.offset);
    });
    uint64_t end = 0;
    for (auto &range : entries)
      range.prefix_end = end = std::max(end, range.end);
  }
  return error.empty();
}

static std::optional<CaptureAddress>
capture_address(const ct_kernel_value_recipe &recipe,
                const std::optional<CaptureAddress> &frame,
                const std::optional<CaptureAddress> &cfa, size_t bytes,
                bool frame_base = false) {
  if (!recipe.error.empty() || recipe.operations.empty() ||
      recipe.operations.size() > capture_expression_limit)
    return {};
  std::array<CaptureAddress, 64> stack{};
  size_t depth = 0;
  bool complete = false;
  for (const auto &op : recipe.operations) {
    using namespace llvm::dwarf;
    if (complete && op.opcode != DW_OP_nop)
      return {};
    CaptureAddress value;
    bool push = true;
    if ((op.opcode >= DW_OP_breg0 && op.opcode <= DW_OP_breg31) ||
        op.opcode == DW_OP_bregx) {
      const auto reg =
          op.opcode == DW_OP_bregx ? op.operand : op.opcode - DW_OP_breg0;
      if (reg != 6 && reg != 7)
        return {};
      value.kind = KCTRACE_CAPTURE_STACK;
      value.reg = reg == 6 ? KCTRACE_REG_RBP : KCTRACE_REG_RSP;
      value.offset =
          int64_t(op.opcode == DW_OP_bregx ? op.operand2 : op.operand);
    } else if ((op.opcode >= DW_OP_reg0 && op.opcode <= DW_OP_reg31) ||
               op.opcode == DW_OP_regx) {
      const auto reg =
          op.opcode == DW_OP_regx ? op.operand : op.opcode - DW_OP_reg0;
      if (!frame_base || depth || (reg != 6 && reg != 7))
        return {};
      value.kind = KCTRACE_CAPTURE_STACK;
      value.reg = reg == 6 ? KCTRACE_REG_RBP : KCTRACE_REG_RSP;
      complete = true;
    } else if (op.opcode >= DW_OP_lit0 && op.opcode <= DW_OP_lit31) {
      value.offset = op.opcode - DW_OP_lit0;
    } else if (op.opcode >= DW_OP_const1u && op.opcode <= DW_OP_consts) {
      const bool signed_value =
          op.opcode == DW_OP_const1s || op.opcode == DW_OP_const2s ||
          op.opcode == DW_OP_const4s || op.opcode == DW_OP_const8s ||
          op.opcode == DW_OP_consts;
      value.offset =
          signed_value ? __int128(int64_t(op.operand)) : __int128(op.operand);
    } else {
      switch (op.opcode) {
      case DW_OP_addr:
        if (op.section == UINT32_MAX)
          return {};
        value.kind = KCTRACE_CAPTURE_OBJECT;
        value.section = op.section;
        value.offset = op.operand;
        break;
      case DW_OP_fbreg:
        if (!frame)
          return {};
        value = *frame;
        value.offset += int64_t(op.operand);
        break;
      case DW_OP_call_frame_cfa:
        if (!cfa)
          return {};
        value = *cfa;
        break;
      case DW_OP_plus_uconst:
        if (!depth)
          return {};
        stack[depth - 1].offset += op.operand;
        push = false;
        break;
      case DW_OP_plus:
      case DW_OP_minus:
        if (depth < 2)
          return {};
        value = stack[--depth];
        if (op.opcode == DW_OP_plus &&
            stack[depth - 1].kind == KCTRACE_CAPTURE_NONE)
          std::swap(value, stack[depth - 1]);
        if (value.kind != KCTRACE_CAPTURE_NONE)
          return {};
        stack[depth - 1].offset +=
            op.opcode == DW_OP_plus ? value.offset : -value.offset;
        push = false;
        break;
      case DW_OP_piece:
        if (frame_base || depth != 1 || op.operand != bytes)
          return {};
        complete = true;
        push = false;
        break;
      case DW_OP_nop:
        push = false;
        break;
      default:
        // stack_value is a computed value, not a memory capture request.
        // Dereferences, entry values and pointer arithmetic from other GPRs
        // are deliberately not converted into kernel reads.
        return {};
      }
    }
    if (push) {
      if (depth == stack.size())
        return {};
      stack[depth++] = value;
    }
    if (depth && (stack[depth - 1].offset < INT64_MIN ||
                  stack[depth - 1].offset > INT64_MAX))
      return {};
  }
  if (depth != 1 || stack[0].kind == KCTRACE_CAPTURE_NONE)
    return {};
  return stack[0];
}

// The same bounded typed coverage drives cold planning and cache validation.
// Adjacent scalar bytes may coalesce; padding and guarded leaves never do.
static std::vector<std::pair<uint64_t, uint32_t>>
capture_leaves(const ct_kernel_value_metadata &values, uint32_t type_id,
               bool aggregate) {
  const auto &type = values.types[type_id];
  std::vector<std::pair<uint64_t, uint32_t>> result;
  if (!aggregate) {
    result.push_back({0, uint32_t(type.scalar.bytes)});
  } else {
    struct Pending {
      uint32_t type;
      uint64_t offset;
      size_t next = 0, depth = 0;
    };
    std::vector<Pending> pending{{type.layout_type, 0}};
    size_t visited = 0;
    while (!pending.empty() && visited++ < capture_layout_visit_limit &&
           result.size() < KCTRACE_VALUE_SLOTS * 8) {
      auto &current = pending.back();
      if (!current.type || current.type > values.layout_types.size() ||
          current.depth >= 64) {
        pending.pop_back();
        continue;
      }
      const auto &node = values.layout_types[current.type - 1];
      if (node.guarded || !node.complete ||
          current.offset > type.scalar.bytes ||
          node.bytes > type.scalar.bytes - current.offset) {
        pending.pop_back();
        continue;
      }
      if (node.kind == CT_LAYOUT_SCALAR || node.kind == CT_LAYOUT_POINTER) {
        if (node.bytes && node.bytes <= 8 &&
            (node.kind == CT_LAYOUT_POINTER
                 ? node.bytes == 8 && !node.element_type
                 : node.scalar.bytes == node.bytes &&
                       node.scalar.kind >= CT_VALUE_UNKNOWN &&
                       node.scalar.kind < CT_VALUE_POINTER))
          result.push_back({current.offset, uint32_t(node.bytes)});
        pending.pop_back();
      } else if (node.kind == CT_LAYOUT_ARRAY) {
        if (!node.element_type || !node.element_stride ||
            current.next >= node.element_count ||
            current.next > node.bytes / node.element_stride) {
          pending.pop_back();
          continue;
        }
        const auto offset = current.next++ * node.element_stride;
        pending.push_back(
            {node.element_type, current.offset + offset, 0, current.depth + 1});
      } else if (node.kind == CT_LAYOUT_STRUCT) {
        if (node.first_member > values.layout_members.size() ||
            node.member_count >
                values.layout_members.size() - node.first_member ||
            current.next >= node.member_count) {
          pending.pop_back();
          continue;
        }
        const auto &member =
            values.layout_members[node.first_member + current.next++];
        if (member.available && member.offset <= node.bytes)
          pending.push_back({member.type, current.offset + member.offset, 0,
                             current.depth + 1});
      } else {
        pending.pop_back();
      }
    }
    std::sort(result.begin(), result.end());
    size_t count = 0;
    for (const auto &leaf : result) {
      if (count &&
          result[count - 1].first + result[count - 1].second == leaf.first &&
          result[count - 1].second + leaf.second <= 8) {
        result[count - 1].second += leaf.second;
      } else {
        result[count++] = leaf;
      }
    }
    result.resize(count);
  }
  return result;
}

using CaptureSites =
    std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_site *>;

static bool capture_inputs_valid(const ct_kernel_image &image,
                                 const std::vector<ct_kernel_site> &sites,
                                 const ct_kernel_value_metadata &values,
                                 CaptureSites &addresses, std::string &error) {
  if (values.variables.empty() || values.types.empty() ||
      values.recipes.empty() || values.functions.empty() ||
      sites.size() > capture_entry_limit ||
      values.sites.size() > capture_entry_limit + 1) {
    error = "kernel capture site inventory exceeds its bound";
    return false;
  }
  size_t bindings = 0;
  for (const auto &site : values.sites) {
    if (site.function >= values.functions.size() ||
        site.frame_recipe >= values.recipes.size()) {
      error = "invalid kernel capture function metadata";
      return false;
    }
    std::set<uint64_t> identities;
    for (const auto &binding : site.bindings)
      if (++bindings > capture_entry_limit || !binding.variable ||
          binding.variable >= values.variables.size() ||
          values.variables[binding.variable].id != binding.variable ||
          values.variables[binding.variable].type >= values.types.size() ||
          binding.recipe >= values.recipes.size() ||
          !identities.insert(binding.variable).second) {
        error = "invalid kernel capture variable binding";
        return false;
      }
  }
  std::set<uint64_t> site_ids;
  for (const auto &site : sites) {
    if (!site.probe)
      continue;
    if (!site.id || site.id >= values.sites.size() ||
        site.section >= image.sections.size() ||
        !(image.sections[site.section].flags & SHF_EXECINSTR) ||
        !site.original_size || site.original_size > 15 ||
        site.offset > image.sections[site.section].size ||
        site.original_size > image.sections[site.section].size - site.offset ||
        !site_ids.insert(site.id).second ||
        !addresses.emplace(std::make_pair(site.section, site.offset), &site)
             .second) {
      error = "invalid kernel capture site identity";
      return false;
    }
  }
  return true;
}

static bool plan_captures(const ct_kernel_image &image,
                          const CaptureSites &addresses,
                          const ct_kernel_source_metadata &source,
                          ct_kernel_value_metadata &values,
                          std::vector<ct_kernel_capture_plan> &plans,
                          std::string &error) {
  std::map<uint32_t, std::vector<CaptureCFA>> cfas;
  if (!capture_cfa(image, cfas, error))
    return false;
  std::map<uint32_t, uint64_t> first;
  for (const auto &[address, site] : addresses) {
    const auto function = values.sites[site->id].function;
    if (function)
      first.try_emplace(function, site->id);
  }
  std::map<std::string, uint32_t> interned;
  std::map<std::string, uint32_t> capture_groups;
  std::map<uint32_t, std::vector<std::pair<uint64_t, uint32_t>>> leaves;
  for (const auto &[address, original] : addresses) {
    auto &site = values.sites[original->id];
    std::optional<CaptureAddress> cfa;
    bool ambiguous = false;
    const auto &ranges = cfas[original->section];
    auto position = std::upper_bound(
        ranges.begin(), ranges.end(), original->offset,
        [](uint64_t pc, const auto &range) { return pc < range.begin; });
    while (position != ranges.begin()) {
      --position;
      if (position->prefix_end <= original->offset)
        break;
      if (position->end <= original->offset)
        continue;
      if (position->address.kind == KCTRACE_CAPTURE_NONE ||
          (cfa && (cfa->reg != position->address.reg ||
                   cfa->offset != position->address.offset)))
        ambiguous = true;
      cfa = position->address;
    }
    if (ambiguous)
      cfa.reset();
    std::optional<CaptureAddress> frame;
    if (site.frame_recipe && site.frame_recipe < values.recipes.size())
      frame =
          capture_address(values.recipes[site.frame_recipe], {}, cfa, 0, true);
    std::vector<uint64_t> wanted;
    const auto request = [&](uint64_t variable) {
      if (variable &&
          std::find(wanted.begin(), wanted.end(), variable) == wanted.end())
        wanted.push_back(variable);
    };
    for (const auto &binding : site.bindings)
      if (binding.preferred)
        request(binding.variable);
    if (site.function && first[site.function] == original->id)
      for (const auto &binding : site.bindings)
        if (binding.variable < values.variables.size() &&
            values.variables[binding.variable].parameter &&
            values.variables[binding.variable].scope ==
                values.variables[binding.variable].function &&
            values.variables[binding.variable].function ==
                values.functions[site.function].die)
          request(binding.variable);
    const auto references = [&](uint64_t site_id) {
      if (site_id >= source.sites.size() || site_id >= values.sites.size())
        return false;
      const auto line = source.sites[site_id].line;
      if (!line || line >= source.lines.size() ||
          !source.lines[line].presentation)
        return false;
      for (const auto &reference : source.lines[line].presentation->variables) {
        const ct_kernel_value_variable *selected = nullptr;
        bool conflict = false;
        for (const auto &binding : values.sites[site_id].bindings) {
          if (!binding.variable || binding.variable >= values.variables.size())
            continue;
          const auto &variable = values.variables[binding.variable];
          if (variable.name != reference.name ||
              (!variable.global && variable.owner != reference.function))
            continue;
          if (!selected || variable.depth > selected->depth) {
            selected = &variable;
            conflict = false;
          } else if (variable.depth == selected->depth &&
                     variable.id != selected->id) {
            conflict = true;
          }
        }
        if (selected && !conflict)
          request(selected->id);
      }
      return true;
    };
    const bool has_source = references(original->id);
    auto previous = addresses.find(address);
    if (previous != addresses.begin()) {
      --previous;
      const auto &before = *previous->second;
      if (before.section == original->section &&
          before.offset + before.original_size == original->offset &&
          values.sites[before.id].function == site.function)
        references(before.id);
    }
    if (!has_source) {
      // Without a stable AST, retain only bounded visible scalar storage.
      // Locals/parameters precede defined module objects; no adjacent bytes
      // are captured to fill unused slots or to recover missing locations.
      for (bool globals : {false, true})
        for (const auto &binding : site.bindings)
          if (binding.variable < values.variables.size() &&
              values.variables[binding.variable].global == globals)
            request(binding.variable);
    }
    ct_kernel_capture_plan plan;
    size_t used = 0;
    for (uint64_t variable_id : wanted) {
      auto binding = std::find_if(
          site.bindings.begin(), site.bindings.end(),
          [&](const auto &entry) { return entry.variable == variable_id; });
      if (binding == site.bindings.end() ||
          variable_id >= values.variables.size())
        continue;
      const auto &variable = values.variables[variable_id];
      if (!variable.type || variable.type >= values.types.size() ||
          !binding->recipe || binding->recipe >= values.recipes.size())
        continue;
      const auto &type = values.types[variable.type];
      if (type.guarded || !type.scalar.bytes ||
          type.layout_type > values.layout_types.size())
        continue;
      const bool aggregate =
          type.layout_type &&
          (values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_STRUCT ||
           values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_ARRAY);
      if (!aggregate &&
          (type.scalar.bytes > 8 ||
           (type.scalar.kind < CT_VALUE_SIGNED &&
            !(type.scalar.kind == CT_VALUE_UNKNOWN && type.raw_scalar)) ||
           type.scalar.kind > CT_VALUE_POINTER ||
           type.scalar.kind == CT_VALUE_FLOAT))
        continue;
      const auto location = capture_address(values.recipes[binding->recipe],
                                            frame, cfa, type.scalar.bytes);
      if (!location)
        continue;
      const ct_kernel_symbol *object = nullptr;
      if (location->kind == KCTRACE_CAPTURE_OBJECT) {
        if (location->section >= image.sections.size() || location->offset < 0)
          continue;
        const auto &section = image.sections[location->section];
        if (!ct_kernel_capture_section(section))
          continue;
        for (const auto &symbol : image.symbols)
          if (symbol.type == STT_OBJECT &&
              symbol.section == location->section && symbol.size &&
              symbol.offset <= section.size &&
              symbol.size <= section.size - symbol.offset &&
              location->offset >= symbol.offset &&
              location->offset - symbol.offset <= symbol.size &&
              type.scalar.bytes <=
                  symbol.size - (location->offset - symbol.offset) &&
              (!object || symbol.size < object->size))
            object = &symbol;
        if (!object)
          continue;
      }
      auto [shape, inserted] = leaves.try_emplace(variable.type);
      if (inserted)
        shape->second = capture_leaves(values, variable.type, aggregate);
      std::vector<ct_kernel_value_capture> captured;
      for (const auto &[offset, size] : shape->second) {
        const __int128 address = __int128(location->offset) + offset;
        if (offset > type.scalar.bytes || size > type.scalar.bytes - offset ||
            address < INT64_MIN || address > INT64_MAX)
          continue;
        ct_kernel_capture_slot slot;
        slot.capture.kind = location->kind;
        slot.capture.size = size;
        if (location->kind == KCTRACE_CAPTURE_STACK) {
          // Only live stack bytes, never padding or neighboring objects.
          if (location->reg == KCTRACE_REG_RSP && address < 0)
            continue;
          slot.capture.reg = location->reg;
          slot.capture.offset = int64_t(address);
        } else {
          slot.section = location->section;
          slot.object_offset = object->offset;
          slot.capture.object_size = object->size;
          slot.capture.offset = int64_t(address - object->offset);
        }
        const auto same = [&](const auto &other) {
          return std::tie(slot.section, slot.object_offset, slot.capture.kind,
                          slot.capture.reg, slot.capture.size,
                          slot.capture.offset, slot.capture.object_size) ==
                 std::tie(other.section, other.object_offset,
                          other.capture.kind, other.capture.reg,
                          other.capture.size, other.capture.offset,
                          other.capture.object_size);
        };
        const auto duplicate =
            std::find_if(plan.slots.begin(), plan.slots.begin() + used, same);
        uint32_t index;
        if (duplicate != plan.slots.begin() + used) {
          index = duplicate - plan.slots.begin();
        } else if (used < plan.slots.size()) {
          index = used;
          plan.slots[used++] = slot;
        } else {
          continue;
        }
        if (aggregate)
          captured.push_back({offset, size, index});
        else
          binding->capture_slot = index;
      }
      if (!captured.empty()) {
        std::string key;
        for (const auto &span : captured)
          key += std::to_string(span.offset) + ':' + std::to_string(span.size) +
                 ':' + std::to_string(span.slot) + ';';
        const auto [group, fresh] =
            capture_groups.emplace(key, values.capture_groups.size());
        if (fresh) {
          if (values.capture_groups.size() >= capture_plan_limit) {
            error = "kernel aggregate capture inventory exceeds its bound";
            return false;
          }
          values.capture_groups.push_back(std::move(captured));
        }
        binding->capture_group = group->second;
      }
    }
    if (!used)
      continue;
    std::string key;
    for (const auto &slot : plan.slots)
      key += std::to_string(slot.section) + ':' +
             std::to_string(slot.object_offset) + ':' +
             std::to_string(slot.capture.kind) + ':' +
             std::to_string(slot.capture.reg) + ':' +
             std::to_string(slot.capture.size) + ':' +
             std::to_string(slot.capture.offset) + ':' +
             std::to_string(slot.capture.object_size) + ';';
    auto [entry, inserted] = interned.emplace(key, plans.size());
    if (inserted) {
      if (plans.size() >= capture_plan_limit) {
        error = "kernel capture plan inventory exceeds its bound";
        return false;
      }
      plans.push_back(std::move(plan));
    }
    site.capture_plan = entry->second;
  }
  return true;
}

static std::string capture_cache_key(const ct_kernel_image &image,
                                     const std::vector<ct_kernel_site> &sites,
                                     const ct_kernel_source_metadata &source,
                                     const ct_kernel_value_metadata &values) {
  llvm::SHA256 hash;
  bool valid = true;
  size_t text_bytes = 0, entries = 0;
  const auto number = [&](uint64_t value) {
    hash.update({reinterpret_cast<const uint8_t *>(&value), sizeof(value)});
  };
  const auto count = [&](size_t size) {
    if (size > capture_entry_limit - entries)
      valid = false;
    else
      entries += size;
    number(size);
    return valid;
  };
  const auto text = [&](const std::string &value) {
    if (value.size() > capture_cache_limit - text_bytes) {
      valid = false;
      return;
    }
    text_bytes += value.size();
    number(value.size());
    hash.update(value);
  };
  // CFA relocation processing consumes the original ELF, not a path or an
  // already computed digest. Include the parsed inventory too: callers may
  // have normalized it independently of the original snapshot.
  number(image.bytes.size());
  hash.update(llvm::ArrayRef<uint8_t>(image.bytes));
  if (!count(image.sections.size()))
    return {};
  for (const auto &section : image.sections) {
    text(section.name);
    for (uint64_t value :
         {uint64_t(section.type), uint64_t(section.link),
          uint64_t(section.info), section.flags, section.offset, section.size,
          section.alignment, section.entry_size})
      number(value);
  }
  if (!count(image.symbols.size()) || !count(image.relocations.size()))
    return {};
  for (const auto &symbol : image.symbols) {
    text(symbol.name);
    for (uint64_t value : {uint64_t(symbol.table), uint64_t(symbol.index),
                           uint64_t(symbol.section), symbol.offset, symbol.size,
                           uint64_t(symbol.type), uint64_t(symbol.binding)})
      number(value);
  }
  for (const auto &relocation : image.relocations)
    for (uint64_t value :
         {uint64_t(relocation.section), uint64_t(relocation.symbol_table),
          uint64_t(relocation.symbol), uint64_t(relocation.type),
          relocation.offset, uint64_t(relocation.addend)})
      number(value);
  if (!count(sites.size()) || !count(values.types.size()) ||
      !count(values.variables.size()) || !count(values.functions.size()) ||
      !count(values.recipes.size()) || !count(values.sites.size()) ||
      !count(values.layout_types.size()) ||
      !count(values.layout_members.size()) || !count(source.sites.size()) ||
      !count(source.lines.size()))
    return {};
  for (const auto &site : sites)
    for (uint64_t value : {site.id, uint64_t(site.section), site.offset,
                           uint64_t(site.original_size), uint64_t(site.probe)})
      number(value);
  for (const auto &type : values.types)
    for (uint64_t value :
         {uint64_t(type.scalar.kind), uint64_t(type.scalar.bytes),
          uint64_t(type.guarded), uint64_t(type.raw_scalar),
          uint64_t(type.layout_type)})
      number(value);
  for (const auto &variable : values.variables) {
    for (uint64_t value :
         {variable.id, variable.scope, variable.function,
          uint64_t(variable.depth), uint64_t(variable.type),
          uint64_t(variable.global), uint64_t(variable.parameter)})
      number(value);
    text(variable.name);
    text(variable.owner);
  }
  for (const auto &function : values.functions)
    number(function.die);
  for (const auto &recipe : values.recipes) {
    text(recipe.error);
    if (!count(recipe.operations.size()))
      return {};
    for (const auto &operation : recipe.operations)
      for (uint64_t value : {uint64_t(operation.opcode), operation.operand,
                             operation.operand2, uint64_t(operation.section)})
        number(value);
  }
  for (const auto &site : values.sites) {
    number(site.function);
    number(site.frame_recipe);
    if (!count(site.bindings.size()))
      return {};
    for (const auto &binding : site.bindings) {
      number(binding.variable);
      number(binding.recipe);
      number(binding.preferred);
    }
  }
  for (const auto &node : values.layout_types)
    for (uint64_t value :
         {uint64_t(node.kind), uint64_t(node.scalar.kind),
          uint64_t(node.scalar.bytes), uint64_t(node.bytes),
          uint64_t(node.element_type), uint64_t(node.element_count),
          uint64_t(node.element_stride), uint64_t(node.first_member),
          uint64_t(node.member_count), uint64_t(node.complete),
          uint64_t(node.guarded)})
      number(value);
  for (const auto &member : values.layout_members) {
    number(member.type);
    number(member.offset);
    number(member.available);
  }
  // Source freshness is established upstream before joining normalized rows.
  // Only these ordered references affect capture selection. No AST, text,
  // filter policy or previous derived capture result belongs in this key.
  for (const auto &site : source.sites)
    number(site.line);
  for (const auto &line : source.lines) {
    number(bool(line.presentation));
    if (!line.presentation)
      continue;
    if (!count(line.presentation->variables.size()))
      return {};
    for (const auto &variable : line.presentation->variables) {
      text(variable.name);
      text(variable.function);
    }
  }
  if (!valid)
    return {};
  const auto digest = hash.final();
  return ct_cache_key(
      {"kernel-captures-v1",
       {reinterpret_cast<const char *>(digest.data()), digest.size()}});
}

struct CaptureBinding {
  uint32_t index = 0, slot = UINT32_MAX, group = 0;
};

struct CaptureSite {
  uint64_t id = 0;
  uint32_t plan = 0;
  std::vector<CaptureBinding> bindings;
};

struct CaptureOutput {
  std::vector<ct_kernel_capture_plan> plans{1};
  std::vector<std::vector<ct_kernel_value_capture>> groups{1};
  std::vector<CaptureSite> sites;
};

static bool capture_archive(CaptureOutput &output,
                            std::vector<unsigned char> &bytes, bool reading,
                            const std::string &key) {
  if (bytes.size() > capture_cache_limit)
    return false;
  ct_analysis_archive archive{bytes, reading};
  uint32_t format = 1;
  std::string identity = key;
  archive.fields(format, identity);
  if (!archive.valid || format != 1 || identity != key)
    return false;
  size_t entries = 0;
  const auto collection = [&](auto &items, size_t limit, auto encode) {
    uint64_t size = items.size();
    archive.field(size);
    if (!archive.valid || size > limit ||
        size > capture_entry_limit - entries ||
        (reading && size > bytes.size() - archive.offset)) {
      archive.valid = false;
      return;
    }
    entries += size;
    if (reading)
      items.resize(size);
    for (auto &item : items) {
      if (!archive.valid)
        break;
      encode(item);
    }
  };
  collection(output.plans, capture_plan_limit, [&](auto &plan) {
    for (auto &slot : plan.slots)
      archive.fields(slot.section, slot.object_offset, slot.capture.kind,
                     slot.capture.reg, slot.capture.size, slot.capture.offset,
                     slot.capture.object_size);
  });
  collection(output.groups, capture_plan_limit, [&](auto &group) {
    collection(group, KCTRACE_VALUE_SLOTS * 8, [&](auto &span) {
      archive.fields(span.offset, span.size, span.slot);
    });
  });
  collection(output.sites, capture_entry_limit, [&](auto &site) {
    archive.fields(site.id, site.plan);
    collection(site.bindings, capture_entry_limit, [&](auto &binding) {
      archive.fields(binding.index, binding.slot, binding.group);
    });
  });
  return bytes.size() <= capture_cache_limit && archive.complete();
}

static bool capture_output_valid(const ct_kernel_image &image,
                                 const CaptureSites &addresses,
                                 const ct_kernel_value_metadata &values,
                                 const CaptureOutput &output) {
  if (output.plans.empty() || output.groups.empty() ||
      !output.groups.front().empty())
    return false;
  std::set<std::tuple<uint32_t, uint64_t, uint64_t>> objects;
  for (const auto &symbol : image.symbols)
    if (symbol.type == STT_OBJECT)
      objects.emplace(symbol.section, symbol.offset, symbol.size);
  std::set<uint64_t> probes;
  for (const auto &[address, site] : addresses)
    probes.insert(site->id);
  std::vector<bool> used_plans(output.plans.size());
  std::vector<bool> used_groups(output.groups.size());
  used_plans[0] = used_groups[0] = true;
  for (size_t index = 0; index < output.plans.size(); ++index) {
    bool end = false;
    for (const auto &slot : output.plans[index].slots) {
      const auto &capture = slot.capture;
      if (capture.object || capture.reserved || capture.reserved2)
        return false;
      if (capture.kind == KCTRACE_CAPTURE_NONE) {
        if (capture.size || capture.reg || capture.offset ||
            capture.object_size || slot.section != UINT32_MAX ||
            slot.object_offset)
          return false;
        end = true;
        continue;
      }
      if (!index || end || !capture.size || capture.size > 8)
        return false;
      if (capture.kind == KCTRACE_CAPTURE_STACK) {
        if ((capture.reg != KCTRACE_REG_RSP &&
             capture.reg != KCTRACE_REG_RBP) ||
            (capture.reg == KCTRACE_REG_RSP && capture.offset < 0) ||
            capture.object_size || slot.section != UINT32_MAX ||
            slot.object_offset)
          return false;
      } else if (capture.kind == KCTRACE_CAPTURE_OBJECT) {
        if (capture.reg || capture.offset < 0 ||
            slot.section >= image.sections.size() ||
            !ct_kernel_capture_section(image.sections[slot.section]) ||
            !capture.object_size ||
            uint64_t(capture.offset) > capture.object_size ||
            capture.size > capture.object_size - uint64_t(capture.offset))
          return false;
        const auto &section = image.sections[slot.section];
        if (slot.object_offset > section.size ||
            capture.object_size > section.size - slot.object_offset ||
            !objects.count(
                {slot.section, slot.object_offset, capture.object_size}))
          return false;
      } else {
        return false;
      }
    }
  }
  std::map<uint32_t, std::vector<std::pair<uint64_t, uint32_t>>> leaves;
  uint64_t previous_site = 0;
  for (const auto &restored : output.sites) {
    if (restored.id <= previous_site || !probes.count(restored.id) ||
        !restored.plan || restored.plan >= output.plans.size() ||
        restored.bindings.empty())
      return false;
    previous_site = restored.id;
    used_plans[restored.plan] = true;
    const auto &site = values.sites[restored.id];
    const auto &plan = output.plans[restored.plan];
    std::array<bool, KCTRACE_VALUE_SLOTS> used_slots{};
    uint64_t previous_binding = 0;
    for (const auto &assignment : restored.bindings) {
      if (uint64_t(assignment.index) + 1 <= previous_binding ||
          assignment.index >= site.bindings.size() ||
          assignment.group >= output.groups.size())
        return false;
      previous_binding = uint64_t(assignment.index) + 1;
      const auto &binding = site.bindings[assignment.index];
      const auto &variable = values.variables[binding.variable];
      const auto &type = values.types[variable.type];
      if (!variable.type || !binding.recipe || type.guarded ||
          !type.scalar.bytes || type.layout_type > values.layout_types.size())
        return false;
      const bool aggregate =
          type.layout_type &&
          (values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_STRUCT ||
           values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_ARRAY);
      if (aggregate != bool(assignment.group) ||
          (aggregate ? assignment.slot != UINT32_MAX
                     : assignment.slot >= KCTRACE_VALUE_SLOTS ||
                           type.scalar.bytes > 8 ||
                           (type.scalar.kind < CT_VALUE_SIGNED &&
                            !(type.scalar.kind == CT_VALUE_UNKNOWN &&
                              type.raw_scalar)) ||
                           type.scalar.kind > CT_VALUE_POINTER ||
                           type.scalar.kind == CT_VALUE_FLOAT))
        return false;
      auto [shape, inserted] = leaves.try_emplace(variable.type);
      if (inserted)
        shape->second = capture_leaves(values, variable.type, aggregate);
      const auto &recipe = values.recipes[binding.recipe];
      const auto direct = capture_address(recipe, {}, {}, type.scalar.bytes);
      // A valid cache carries the prior CFA analysis, not an arbitrary address.
      // Reject unsupported recipes without reparsing CFA; exact direct recipes
      // are additionally compared with the restored root below.
      const CaptureAddress symbolic{KCTRACE_CAPTURE_STACK, KCTRACE_REG_RBP,
                                    UINT32_MAX, 0};
      const auto frame =
          site.frame_recipe ? capture_address(values.recipes[site.frame_recipe],
                                              {}, symbolic, 0, true)
                            : std::optional<CaptureAddress>{};
      if (!direct &&
          !capture_address(recipe, frame, symbolic, type.scalar.bytes))
        return false;
      const ct_kernel_value_capture scalar{0, uint32_t(type.scalar.bytes),
                                           assignment.slot};
      const auto &group = output.groups[assignment.group];
      const auto *spans = aggregate ? group.data() : &scalar;
      const size_t span_count = aggregate ? group.size() : 1;
      if (!span_count)
        return false;
      used_groups[assignment.group] = true;
      std::optional<CaptureAddress> root;
      uint64_t previous_end = 0;
      for (size_t index = 0; index < span_count; ++index) {
        const auto &span = spans[index];
        if (span.slot >= plan.slots.size() || !span.size ||
            span.offset < previous_end || span.offset > type.scalar.bytes ||
            span.size > type.scalar.bytes - span.offset ||
            !std::binary_search(shape->second.begin(), shape->second.end(),
                                std::make_pair(span.offset, span.size)))
          return false;
        previous_end = span.offset + span.size;
        const auto &slot = plan.slots[span.slot];
        if (slot.capture.size != span.size ||
            slot.capture.kind == KCTRACE_CAPTURE_NONE)
          return false;
        CaptureAddress base{slot.capture.kind, slot.capture.reg, slot.section,
                            __int128(slot.capture.offset) - span.offset};
        if (base.kind == KCTRACE_CAPTURE_OBJECT) {
          if (base.offset < 0 || base.offset > slot.capture.object_size ||
              type.scalar.bytes > slot.capture.object_size - base.offset)
            return false;
          base.offset += slot.object_offset;
          if (!direct)
            return false;
        }
        const auto matches = [&](const auto &expected) {
          return base.kind == expected.kind && base.reg == expected.reg &&
                 base.section == expected.section &&
                 base.offset == expected.offset;
        };
        if ((root && !matches(*root)) || (direct && !matches(*direct)))
          return false;
        root = base;
        used_slots[span.slot] = true;
      }
    }
    for (size_t index = 0; index < plan.slots.size(); ++index)
      if (used_slots[index] !=
          (plan.slots[index].capture.kind != KCTRACE_CAPTURE_NONE))
        return false;
  }
  return std::all_of(used_plans.begin(), used_plans.end(),
                     [](bool used) { return used; }) &&
         std::all_of(used_groups.begin(), used_groups.end(),
                     [](bool used) { return used; });
}

bool ct_kernel_plan_captures(const ct_kernel_image &image,
                             const std::vector<ct_kernel_site> &sites,
                             const ct_kernel_source_metadata &source,
                             ct_kernel_value_metadata &values,
                             std::vector<ct_kernel_capture_plan> &plans,
                             std::string &error, bool *reused) {
  error.clear();
  if (reused)
    *reused = false;
  plans.assign(1, {});
  values.capture_groups.assign(1, {});
  for (auto &site : values.sites) {
    site.capture_plan = 0;
    for (auto &binding : site.bindings) {
      binding.capture_slot = UINT32_MAX;
      binding.capture_group = 0;
    }
  }
  CaptureSites addresses;
  if (!capture_inputs_valid(image, sites, values, addresses, error))
    return false;
  const auto key = capture_cache_key(image, sites, source, values);
  std::vector<unsigned char> bytes;
  if (!key.empty() && ct_cache_read("kernel-captures", key, bytes)) {
    CaptureOutput restored;
    if (capture_archive(restored, bytes, true, key) &&
        capture_output_valid(image, addresses, values, restored)) {
      plans = std::move(restored.plans);
      values.capture_groups = std::move(restored.groups);
      for (const auto &site : restored.sites) {
        values.sites[site.id].capture_plan = site.plan;
        for (const auto &assignment : site.bindings) {
          auto &binding = values.sites[site.id].bindings[assignment.index];
          binding.capture_slot = assignment.slot;
          binding.capture_group = assignment.group;
        }
      }
      if (reused)
        *reused = true;
      return true;
    }
  }
  std::vector<unsigned char>().swap(bytes);
  if (!plan_captures(image, addresses, source, values, plans, error))
    return false;
  if (!key.empty()) {
    CaptureOutput output;
    // Temporarily borrow ownership of the prepared output, not a duplicate of
    // its type/source graph. It is returned to the caller before leaving.
    output.plans.swap(plans);
    output.groups.swap(values.capture_groups);
    for (size_t id = 1; id < values.sites.size(); ++id) {
      const auto &site = values.sites[id];
      if (!site.capture_plan)
        continue;
      CaptureSite stored{id, site.capture_plan, {}};
      for (size_t index = 0; index < site.bindings.size(); ++index) {
        const auto &binding = site.bindings[index];
        if (binding.capture_group || binding.capture_slot != UINT32_MAX)
          stored.bindings.push_back(
              {uint32_t(index), binding.capture_slot, binding.capture_group});
      }
      output.sites.push_back(std::move(stored));
    }
    if (capture_output_valid(image, addresses, values, output) &&
        capture_archive(output, bytes, false, key))
      ct_cache_write("kernel-captures", key, bytes);
    output.plans.swap(plans);
    output.groups.swap(values.capture_groups);
  }
  return true;
}
