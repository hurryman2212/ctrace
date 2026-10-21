// SPDX-License-Identifier: MIT

#include <algorithm>
#include <bitset>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/SHA256.h>

#include <elf.h>

#include "analysis_cache.hh"
#include "c_cpp_access.hh"
#include "cache.hh"
#include "capture.hh"
#include "dwarf/kernel_capture.hh"

// Slot references are uint32_t; UINT32_MAX is the unavailable-slot sentinel.
static constexpr size_t capture_slot_limit = UINT32_MAX;

ct_kernel_x87_write ct_kernel_x87_destination(std::string_view opcode,
                                              bool single_register_operand) {
  const auto split = opcode.find('_');
  const auto operation = opcode.substr(0, split);
  const auto form = split == std::string_view::npos ? std::string_view{}
                                                    : opcode.substr(split + 1);
  const bool arithmetic = operation == "ADD" || operation == "MUL" ||
                          operation == "SUB" || operation == "SUBR" ||
                          operation == "DIV" || operation == "DIVR";
  if ((arithmetic && (form == "FST0r" || form == "F32m" || form == "F64m" ||
                      form == "FI16m" || form == "FI32m")) ||
      opcode == "SQRT_F" || opcode == "ABS_F" || opcode == "CHS_F" ||
      opcode == "FRNDINT")
    return ct_kernel_x87_write::top;
  if (arithmetic && form == "FrST0" && single_register_operand)
    return ct_kernel_x87_write::operand;
  return ct_kernel_x87_write::none;
}

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

// The same bounded typed coverage drives cold planning and cache validation.
// Adjacent scalar bytes may coalesce; padding and guarded leaves never do.
static std::vector<std::pair<uint64_t, uint32_t>>
capture_leaves(const ct_kernel_value_metadata &values, uint32_t type_id,
               bool aggregate, uint32_t selected_layout = 0) {
  auto type = values.types[type_id];
  if (selected_layout && selected_layout <= values.layout_types.size()) {
    const auto &node = values.layout_types[selected_layout - 1];
    type.layout_type = selected_layout;
    type.scalar = node.scalar;
    type.scalar.bytes = node.bytes;
  }
  std::vector<std::pair<uint64_t, uint32_t>> result;
  if (!aggregate) {
    result.push_back({0, uint32_t(type.scalar.bytes)});
  } else {
    std::vector<std::pair<uint64_t, uint64_t>> guarded;
    struct Pending {
      uint32_t type;
      uint64_t offset;
      size_t next = 0, depth = 0;
    };
    std::vector<Pending> pending{{type.layout_type, 0}};
    bool union_views = false;
    while (!pending.empty() && result.size() < capture_slot_limit) {
      auto &current = pending.back();
      if (!current.type || current.type > values.layout_types.size() ||
          current.depth >= values.layout_types.size()) {
        pending.pop_back();
        continue;
      }
      const auto &node = values.layout_types[current.type - 1];
      union_views |= node.kind == CT_LAYOUT_UNION;
      if (current.offset > type.scalar.bytes ||
          node.bytes > type.scalar.bytes - current.offset) {
        pending.pop_back();
        continue;
      }
      if (node.guarded || !node.complete) {
        if (node.guarded && node.bytes)
          guarded.emplace_back(current.offset, current.offset + node.bytes);
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
      } else if (node.kind == CT_LAYOUT_STRUCT ||
                 node.kind == CT_LAYOUT_UNION) {
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
    // An unvisited alternative may contain volatile storage overlapping a
    // previously discovered view. A partial union traversal proves no read.
    if (union_views && !pending.empty())
      result.clear();
    // A nonvolatile union view must not read overlapping volatile storage.
    std::erase_if(result, [&](const auto &leaf) {
      return std::any_of(guarded.begin(), guarded.end(),
                         [&](const auto &range) {
                           return leaf.first < range.second &&
                                  range.first < leaf.first + leaf.second;
                         });
    });
    std::sort(result.begin(), result.end());
    size_t count = 0;
    for (const auto &leaf : result) {
      if (count &&
          result[count - 1].first + result[count - 1].second >= leaf.first &&
          leaf.first + leaf.second - result[count - 1].first <= UINT32_MAX) {
        // Union views overlap. Capture those bytes once so every view uses
        // the same observation rather than racing separate memory reads.
        result[count - 1].second = std::max<uint64_t>(
            result[count - 1].second,
            leaf.first + leaf.second - result[count - 1].first);
      } else {
        result[count++] = leaf;
      }
    }
    result.resize(count);
    std::vector<std::pair<uint64_t, uint32_t>> chunks;
    for (const auto &[offset, bytes] : result)
      for (uint64_t covered = 0; covered < bytes; covered += 8)
        chunks.emplace_back(offset + covered,
                            std::min<uint64_t>(8, bytes - covered));
    result = std::move(chunks);
  }
  return result;
}

using CaptureSites =
    std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_site *>;

struct CaptureSelection {
  std::string name;
  uint32_t layout = 0;
  bool address = false;
  std::vector<ct_kernel_capture_slot> chain;
};

static std::vector<CaptureSelection>
capture_selections(const ct_kernel_value_metadata &values, uint64_t variable,
                   const ct_source_access &access,
                   std::vector<ct_kernel_capture_slot> chain, bool direct) {
  std::vector<CaptureSelection> result;
  uint32_t layout = values.types[values.variables[variable].type].layout_type;
  uint32_t addressed = 0;
  const auto append = [&](const std::string &name, bool address) {
    if (name.empty() ||
        std::any_of(result.begin(), result.end(),
                    [&](const auto &item) { return item.name == name; }))
      return;
    auto selected = chain;
    if (!selected.empty()) {
      if (address) {
        if (direct && !addressed)
          selected.clear();
        else {
          selected.back().capture.reserved |= KCTRACE_CAPTURE_ADDRESS;
          selected.back().capture.size = 8;
        }
      } else if (!layout || layout > values.layout_types.size() ||
                 values.layout_types[layout - 1].guarded ||
                 !values.layout_types[layout - 1].complete ||
                 (direct &&
                  values.layout_types[layout - 1].kind != CT_LAYOUT_SCALAR &&
                  values.layout_types[layout - 1].kind != CT_LAYOUT_POINTER)) {
        selected.clear();
      }
    }
    result.push_back({name, layout, address, std::move(selected)});
  };
  const auto offset = [&](uint64_t displacement) {
    if (chain.empty())
      return;
    const __int128 next = __int128(chain.back().capture.offset) + displacement;
    if (next > INT64_MAX)
      chain.clear();
    else
      chain.back().capture.offset = int64_t(next);
  };
  const auto dereference = [&] {
    if (addressed) {
      layout = std::exchange(addressed, 0);
      direct = false;
      if (!chain.empty())
        chain.back().capture.reserved &= ~KCTRACE_CAPTURE_ADDRESS;
      return;
    }
    if (!layout || layout > values.layout_types.size() ||
        values.layout_types[layout - 1].kind != CT_LAYOUT_POINTER ||
        layout > values.layout_pointees.size()) {
      layout = 0;
      chain.clear();
      return;
    }
    if (values.layout_types[layout - 1].guarded)
      chain.clear();
    if (!chain.empty()) {
      if (direct) {
        chain.back().capture.reserved &= ~KCTRACE_CAPTURE_ADDRESS;
      } else {
        chain.back().capture.size = 8;
        ct_kernel_capture_slot following;
        following.capture.kind = KCTRACE_CAPTURE_SLOT;
        following.capture.reserved2 = chain.size();
        chain.push_back(following);
      }
    }
    direct = false;
    layout = values.layout_pointees[layout - 1];
  };
  bool previous_dereference = false;
  for (const auto &step : access.steps) {
    if (step.kind == ct_source_access_kind::dereference) {
      append(step.base, false);
      dereference();
    } else if (step.kind == ct_source_access_kind::member) {
      if (!previous_dereference)
        append(step.base, true);
      uint64_t displacement = 0;
      uint32_t member = 0;
      if (direct || addressed || !layout ||
          layout > values.layout_types.size() ||
          values.layout_types[layout - 1].guarded ||
          !ct_kernel_access_member(values, layout, step.member, displacement,
                                   member)) {
        chain.clear();
        layout = member;
      } else {
        offset(displacement);
        layout = member;
      }
    } else if (step.kind == ct_source_access_kind::index) {
      if (addressed ||
          (layout && layout <= values.layout_types.size() &&
           values.layout_types[layout - 1].kind == CT_LAYOUT_POINTER)) {
        append(step.base, false);
        dereference();
        if (!layout || layout > values.layout_types.size() ||
            !values.layout_types[layout - 1].bytes ||
            step.index > INT64_MAX / values.layout_types[layout - 1].bytes)
          chain.clear();
        else
          offset(step.index * values.layout_types[layout - 1].bytes);
      } else {
        append(step.base, true);
        if (direct || !layout || layout > values.layout_types.size()) {
          layout = 0;
          chain.clear();
        } else {
          const auto &node = values.layout_types[layout - 1];
          if (node.kind != CT_LAYOUT_ARRAY || node.guarded || !node.complete ||
              step.index >= node.element_count || !node.element_stride ||
              step.index > INT64_MAX / node.element_stride) {
            layout = 0;
            chain.clear();
          } else {
            offset(step.index * node.element_stride);
            layout = node.element_type;
          }
        }
      }
    } else {
      // &x displays the requested address and the selected x value. Taking
      // its address does not make volatile/guarded x readable.
      append(step.base, false);
      append(step.text, true);
      if (direct && !addressed)
        chain.clear();
      addressed = layout;
      direct = true;
      if (!chain.empty()) {
        chain.back().capture.reserved |= KCTRACE_CAPTURE_ADDRESS;
        chain.back().capture.size = 8;
      }
    }
    previous_dereference = step.kind == ct_source_access_kind::dereference;
  }
  append(access.text, addressed != 0);
  return result;
}

static uint32_t capture_chain(ct_kernel_capture_plan &plan,
                              const std::vector<ct_kernel_capture_slot> &chain,
                              size_t limit = capture_slot_limit) {
  if (chain.empty() || chain.size() > KCTRACE_VALUE_SLOTS)
    return UINT32_MAX;
  const auto same = [](const auto &a, const auto &b) {
    return a.section == b.section && a.object_offset == b.object_offset &&
           a.capture.kind == b.capture.kind && a.capture.reg == b.capture.reg &&
           a.capture.size == b.capture.size &&
           a.capture.offset == b.capture.offset &&
           a.capture.object_size == b.capture.object_size &&
           a.capture.reserved == b.capture.reserved &&
           a.capture.reserved2 == b.capture.reserved2;
  };
  const size_t original_size = plan.slots.size();
  for (unsigned attempt = 0; attempt != 2; ++attempt) {
    const size_t begin = plan.slots.size();
    const size_t chunk = begin - begin % KCTRACE_VALUE_SLOTS;
    std::vector<uint32_t> assigned;
    for (auto slot : chain) {
      const auto bytes = slot.capture.reserved & KCTRACE_CAPTURE_ADDRESS
                             ? 0U
                             : slot.capture.size;
      if (!slot.capture.size || slot.capture.size > 8 ||
          (slot.capture.kind == KCTRACE_CAPTURE_OBJECT &&
           (slot.capture.offset < 0 ||
            uint64_t(slot.capture.offset) > slot.capture.object_size ||
            bytes > slot.capture.object_size - uint64_t(slot.capture.offset))))
        break;
      if (slot.capture.kind == KCTRACE_CAPTURE_SLOT) {
        if (!slot.capture.reserved2 || slot.capture.reserved2 > assigned.size())
          break;
        slot.capture.reserved2 =
            assigned[slot.capture.reserved2 - 1] % KCTRACE_VALUE_SLOTS + 1;
      }
      const auto found =
          std::find_if(plan.slots.begin() + chunk, plan.slots.end(),
                       [&](const auto &other) { return same(slot, other); });
      if (found != plan.slots.end()) {
        assigned.push_back(found - plan.slots.begin());
      } else if (plan.slots.size() < limit &&
                 plan.slots.size() < chunk + KCTRACE_VALUE_SLOTS) {
        assigned.push_back(plan.slots.size());
        plan.slots.push_back(slot);
      } else {
        break;
      }
    }
    if (assigned.size() == chain.size())
      return assigned.back();
    plan.slots.resize(begin);
    if (!begin || !(begin % KCTRACE_VALUE_SLOTS) ||
        chunk + KCTRACE_VALUE_SLOTS >= limit)
      break;
    plan.slots.resize(chunk + KCTRACE_VALUE_SLOTS);
  }
  plan.slots.resize(original_size);
  return UINT32_MAX;
}

static bool capture_inputs_valid(const ct_kernel_image &image,
                                 const std::vector<ct_kernel_site> &sites,
                                 const ct_kernel_value_metadata &values,
                                 CaptureSites &addresses, std::string &error) {
  if (values.variables.empty() || values.types.empty() ||
      values.recipes.empty() || values.functions.empty() ||
      sites.size() > UINT32_MAX ||
      values.sites.size() > uint64_t(UINT32_MAX) + 1) {
    error = "kernel capture site inventory exceeds its bound";
    return false;
  }
  for (const auto &site : values.sites) {
    if (site.function >= values.functions.size() ||
        site.frame_recipe >= values.recipes.size()) {
      error = "invalid kernel capture function metadata";
      return false;
    }
    std::set<uint64_t> identities;
    for (const auto &binding : site.bindings)
      if (!binding.variable || binding.variable >= values.variables.size() ||
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

// Shared source demand: the source memory planner and xstate planner must
// agree which values are displayed, including inline callers and after-values.
static bool
capture_requests(const ct_kernel_source_metadata &source,
                 const ct_kernel_value_metadata &values, uint64_t id,
                 uint64_t previous, bool entry, std::vector<uint64_t> &wanted,
                 std::set<std::pair<uint64_t, std::string>> &selected_paths) {
  const auto request = [&](uint64_t variable) {
    if (variable &&
        std::find(wanted.begin(), wanted.end(), variable) == wanted.end())
      wanted.push_back(variable);
  };
  for (const auto &binding : values.sites[id].bindings)
    if (binding.preferred)
      request(binding.variable);
  if (entry && values.sites[id].function < values.functions.size())
    for (const auto &binding : values.sites[id].bindings)
      if (binding.variable < values.variables.size() &&
          values.variables[binding.variable].parameter &&
          values.variables[binding.variable].scope ==
              values.variables[binding.variable].function &&
          values.variables[binding.variable].function ==
              values.functions[values.sites[id].function].die)
        request(binding.variable);
  const auto references = [&](uint64_t site_id) {
    if (site_id >= source.sites.size() || site_id >= values.sites.size())
      return false;
    const auto row_references = [&](uint32_t line, const std::string *owner) {
      if (!line || line >= source.lines.size() ||
          !source.lines[line].presentation)
        return false;
      for (const auto &reference : source.lines[line].presentation->variables) {
        if (owner && reference.function != *owner)
          continue;
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
        if (selected && !conflict) {
          if (reference.access.empty())
            request(selected->id);
          else {
            selected_paths.emplace(selected->id, reference.access);
            // Existing call/assignment proofs still authenticate the root
            // scalar itself. Keep that witness without expanding a root
            // aggregate which the expression did not read.
            if (selected->type && selected->type < values.types.size()) {
              const auto &type = values.types[selected->type];
              if (type.scalar.kind >= CT_VALUE_SIGNED &&
                  type.scalar.kind <= CT_VALUE_POINTER)
                request(selected->id);
            }
          }
        }
      }
      return true;
    };
    // An inline body can replace the caller's entire line-table range.
    // Capture its exact caller references before body aggregates use the
    // bounded slots. All storage still comes from this observation's DWARF
    // bindings and is validated at the current instruction below.
    bool has_source = false;
    for (uint64_t id : source.sites[site_id].blocks) {
      if (!id || id >= source.blocks.size())
        continue;
      const auto &block = source.blocks[id];
      if (block.kind == ct_kernel_source_block_kind::inline_function)
        has_source |= row_references(block.call_line, &block.call_function);
    }
    return row_references(source.sites[site_id].line, nullptr) || has_source;
  };
  const bool has_source = references(id);
  if (previous)
    references(previous);
  return has_source;
}

static bool plan_captures(const ct_kernel_image &image,
                          const CaptureSites &addresses,
                          const ct_kernel_source_metadata &source,
                          ct_kernel_value_metadata &values,
                          std::vector<ct_kernel_capture_plan> &plans,
                          std::string &error) {
  std::map<uint32_t, std::vector<ct_kernel_cfa_range>> cfas;
  if (!ct_kernel_collect_cfa(image, cfas, error))
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
  std::map<std::tuple<uint64_t, std::string, std::string>, uint32_t> access_ids;
  for (size_t id = 1; id < values.accesses.size(); ++id) {
    const auto &access = values.accesses[id];
    access_ids.emplace(
        std::make_tuple(access.variable, access.expression, access.name), id);
  }
  for (const auto &[address, original] : addresses) {
    auto &site = values.sites[original->id];
    std::optional<ct_kernel_dwarf_address> cfa;
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
    std::optional<ct_kernel_dwarf_address> frame;
    if (site.frame_recipe && site.frame_recipe < values.recipes.size())
      frame = ct_kernel_resolve_capture_address(
          values.recipes[site.frame_recipe], {}, cfa, 0, true);
    std::vector<uint64_t> wanted;
    std::set<std::pair<uint64_t, std::string>> selected_paths;
    uint64_t previous_id = 0;
    auto previous = addresses.find(address);
    if (previous != addresses.begin()) {
      --previous;
      const auto &before = *previous->second;
      if (before.section == original->section &&
          before.offset + before.original_size == original->offset &&
          values.sites[before.id].function == site.function)
        previous_id = before.id;
    }
    const bool has_source =
        capture_requests(source, values, original->id, previous_id,
                         site.function && first[site.function] == original->id,
                         wanted, selected_paths);
    if (!has_source) {
      // Without a stable AST, retain only bounded visible scalar storage.
      // Locals/parameters precede defined module objects; no adjacent bytes
      // are captured to fill unused slots or to recover missing locations.
      for (bool globals : {false, true})
        for (const auto &binding : site.bindings)
          if (binding.variable < values.variables.size() &&
              values.variables[binding.variable].global == globals &&
              binding.variable &&
              std::find(wanted.begin(), wanted.end(), binding.variable) ==
                  wanted.end())
            wanted.push_back(binding.variable);
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
           values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_UNION ||
           values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_ARRAY);
      if (!aggregate &&
          (type.scalar.bytes > 8 ||
           (type.scalar.kind < CT_VALUE_SIGNED &&
            !(type.scalar.kind == CT_VALUE_UNKNOWN && type.raw_scalar)) ||
           type.scalar.kind > CT_VALUE_POINTER ||
           (type.scalar.kind == CT_VALUE_FLOAT && type.scalar.bytes != 4 &&
            type.scalar.bytes != 8)))
        continue;
      const auto location = ct_kernel_resolve_capture_address(
          values.recipes[binding->recipe], frame, cfa, type.scalar.bytes);
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
        } else if (used < capture_slot_limit) {
          index = used++;
          plan.slots.push_back(slot);
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
          if (values.capture_groups.size() >= UINT32_MAX) {
            error = "kernel aggregate capture inventory exceeds its bound";
            return false;
          }
          values.capture_groups.push_back(std::move(captured));
        }
        binding->capture_group = group->second;
      }
    }
    for (const auto &[variable_id, expression] : selected_paths) {
      ct_source_access parsed;
      if (!ct_parse_source_access(expression, parsed))
        continue;
      const auto &variable = values.variables[variable_id];
      if (!variable.type || variable.type >= values.types.size())
        continue;
      const auto &type = values.types[variable.type];
      const auto binding = std::find_if(
          site.bindings.begin(), site.bindings.end(),
          [&](const auto &item) { return item.variable == variable_id; });
      std::vector<ct_kernel_capture_slot> root;
      bool direct = false;
      if (binding != site.bindings.end() && binding->recipe &&
          binding->recipe < values.recipes.size() && !type.guarded) {
        const auto &recipe = values.recipes[binding->recipe];
        const auto location = ct_kernel_resolve_capture_address(
            recipe, frame, cfa, type.scalar.bytes);
        ct_kernel_capture_slot slot;
        if (location && location->offset >= INT64_MIN &&
            location->offset <= INT64_MAX) {
          slot.capture.kind = location->kind;
          slot.capture.reg = location->reg;
          slot.capture.offset = int64_t(location->offset);
          if (location->kind == KCTRACE_CAPTURE_OBJECT &&
              location->section < image.sections.size() &&
              ct_kernel_capture_section(image.sections[location->section])) {
            const ct_kernel_symbol *object = nullptr;
            for (const auto &symbol : image.symbols)
              if (symbol.type == STT_OBJECT &&
                  symbol.section == location->section && symbol.size &&
                  location->offset >= symbol.offset &&
                  location->offset - symbol.offset < symbol.size &&
                  (!object || symbol.size < object->size))
                object = &symbol;
            if (object) {
              slot.section = location->section;
              slot.object_offset = object->offset;
              slot.capture.object_size = object->size;
              slot.capture.offset -= object->offset;
              root.push_back(slot);
            }
          } else if (location->kind == KCTRACE_CAPTURE_STACK &&
                     (location->reg != KCTRACE_REG_RSP ||
                      location->offset >= 0)) {
            root.push_back(slot);
          }
        } else if (ct_kernel_resolve_capture_register(recipe, type.scalar.bytes,
                                                      slot.capture, direct)) {
          root.push_back(slot);
        }
      }
      for (auto selected :
           capture_selections(values, variable_id, parsed, root, direct)) {
        const auto identity =
            access_ids.find({variable_id, expression, selected.name});
        if (identity == access_ids.end())
          continue;
        ct_kernel_value_access_binding assigned;
        assigned.access = identity->second;
        if (!selected.chain.empty() &&
            (selected.address ||
             (selected.layout &&
              selected.layout <= values.layout_types.size()))) {
          const auto *node =
              selected.layout && selected.layout <= values.layout_types.size()
                  ? &values.layout_types[selected.layout - 1]
                  : nullptr;
          const bool aggregate =
              !selected.address && node &&
              (node->kind == CT_LAYOUT_STRUCT ||
               node->kind == CT_LAYOUT_UNION || node->kind == CT_LAYOUT_ARRAY);
          auto shape = selected.address
                           ? std::vector<std::pair<uint64_t, uint32_t>>{{0, 8}}
                           : capture_leaves(values, variable.type, aggregate,
                                            selected.layout);
          std::vector<ct_kernel_value_capture> captured;
          for (const auto &[offset, bytes] : shape) {
            auto chain = selected.chain;
            const __int128 displacement =
                __int128(chain.back().capture.offset) + offset;
            if (!bytes || bytes > 8 || displacement > INT64_MAX)
              continue;
            chain.back().capture.offset = int64_t(displacement);
            chain.back().capture.size =
                chain.back().capture.reserved & KCTRACE_CAPTURE_ADDRESS ? 8
                                                                        : bytes;
            const uint32_t slot = capture_chain(plan, chain);
            if (slot == UINT32_MAX)
              continue;
            if (aggregate)
              captured.push_back({offset, bytes, slot});
            else
              assigned.capture_slot = slot;
          }
          if (!captured.empty()) {
            std::string key;
            for (const auto &span : captured)
              key += std::to_string(span.offset) + ':' +
                     std::to_string(span.size) + ':' +
                     std::to_string(span.slot) + ';';
            const auto [group, fresh] =
                capture_groups.emplace(key, values.capture_groups.size());
            if (fresh && values.capture_groups.size() < UINT32_MAX)
              values.capture_groups.push_back(std::move(captured));
            if (group->second < values.capture_groups.size())
              assigned.capture_group = group->second;
          }
        }
        // Share the root snapshot with existing assignment/return proofs.
        // A selected member must not replace the root's ordinary value.
        if (binding != site.bindings.end() &&
            binding->capture_slot == UINT32_MAX && !binding->capture_group &&
            selected.name == variable.name && !selected.address &&
            selected.layout == type.layout_type && !assigned.capture_group &&
            (type.scalar.kind >= CT_VALUE_SIGNED || type.raw_scalar) &&
            type.scalar.kind <= CT_VALUE_POINTER &&
            (type.scalar.kind != CT_VALUE_FLOAT || type.scalar.bytes == 4 ||
             type.scalar.bytes == 8) &&
            assigned.capture_slot < plan.slots.size()) {
          const auto &captured = plan.slots[assigned.capture_slot].capture;
          if ((captured.kind == KCTRACE_CAPTURE_STACK ||
               captured.kind == KCTRACE_CAPTURE_OBJECT) &&
              !captured.reserved && captured.size == type.scalar.bytes)
            binding->capture_slot = assigned.capture_slot;
        }
        site.accesses.push_back(assigned);
      }
    }
    used = plan.slots.size();
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
             std::to_string(slot.capture.object_size) + ':' +
             std::to_string(slot.capture.reserved) + ':' +
             std::to_string(slot.capture.reserved2) + ';';
    auto [entry, inserted] = interned.emplace(key, plans.size());
    if (inserted) {
      if (plans.size() >= UINT32_MAX) {
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
  const auto number = [&](uint64_t value) {
    hash.update({reinterpret_cast<const uint8_t *>(&value), sizeof(value)});
  };
  const auto text = [&](const std::string &value) {
    number(value.size());
    hash.update(value);
  };
  // CFA relocation processing consumes the original ELF, not a path or an
  // already computed digest. Include the parsed inventory too: callers may
  // have normalized it independently of the original snapshot.
  number(image.bytes.size());
  hash.update(llvm::ArrayRef<uint8_t>(image.bytes));
  number(image.sections.size());
  for (const auto &section : image.sections) {
    text(section.name);
    for (uint64_t value :
         {uint64_t(section.type), uint64_t(section.link),
          uint64_t(section.info), section.flags, section.offset, section.size,
          section.alignment, section.entry_size})
      number(value);
  }
  number(image.symbols.size());
  number(image.relocations.size());
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
  for (const size_t count :
       {sites.size(), values.types.size(), values.variables.size(),
        values.functions.size(), values.recipes.size(), values.sites.size(),
        values.layout_types.size(), values.layout_members.size(),
        source.sites.size(), source.lines.size(), source.blocks.size()})
    number(count);
  for (const auto &site : sites)
    for (uint64_t value : {site.id, uint64_t(site.section), site.offset,
                           uint64_t(site.original_size), uint64_t(site.probe)})
      number(value);
  for (const auto &type : values.types)
    for (uint64_t value :
         {uint64_t(type.scalar.kind), uint64_t(type.scalar.bytes),
          uint64_t(type.guarded), uint64_t(type.raw_scalar),
          uint64_t(type.layout_type), uint64_t(type.pointee_layout_type)})
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
    number(recipe.operations.size());
    for (const auto &operation : recipe.operations)
      for (uint64_t value : {uint64_t(operation.opcode), operation.operand,
                             operation.operand2, uint64_t(operation.section)})
        number(value);
  }
  for (const auto &site : values.sites) {
    number(site.function);
    number(site.frame_recipe);
    number(site.bindings.size());
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
  for (uint32_t pointee : values.layout_pointees)
    number(pointee);
  for (const auto &name : values.layout_names)
    text(name);
  for (const auto &origin : values.layout_origins) {
    number(origin.unit);
    number(origin.die);
    number(origin.type_unit);
  }
  for (const auto &access : values.accesses) {
    number(access.variable);
    number(access.layout_type);
    number(access.address);
    text(access.expression);
    text(access.name);
  }
  for (const auto &member : values.layout_members) {
    number(member.type);
    number(member.offset);
    number(member.available);
  }
  // Source freshness is established upstream before joining normalized rows.
  // Only these ordered references affect capture selection. No AST, text,
  // filter policy or previous derived capture result belongs in this key.
  for (const auto &site : source.sites) {
    number(site.line);
    number(site.blocks.size());
    for (uint64_t block : site.blocks)
      number(block);
  }
  for (const auto &block : source.blocks) {
    number(uint64_t(block.kind));
    number(block.call_line);
    text(block.call_function);
  }
  for (const auto &line : source.lines) {
    number(bool(line.presentation));
    if (!line.presentation)
      continue;
    number(line.presentation->variables.size());
    for (const auto &variable : line.presentation->variables) {
      text(variable.name);
      text(variable.function);
      text(variable.access);
    }
  }
  const auto digest = hash.final();
  return ct_cache_key(
      {"kernel-captures",
       {reinterpret_cast<const char *>(digest.data()), digest.size()}});
}

struct CaptureBinding {
  uint32_t index = 0, slot = UINT32_MAX, group = 0;
};

struct CaptureSite {
  uint64_t id = 0;
  uint32_t plan = 0;
  std::vector<CaptureBinding> bindings;
  std::vector<ct_kernel_value_access_binding> accesses;
};

struct CaptureOutput {
  std::vector<ct_kernel_capture_plan> plans{1};
  std::vector<std::vector<ct_kernel_value_capture>> groups{1};
  std::vector<CaptureSite> sites;
};

static bool capture_archive(CaptureOutput &output,
                            std::vector<unsigned char> &bytes, bool reading,
                            const std::string &key) {
  ct_analysis_archive archive{bytes, reading};
  std::string identity = key;
  archive.field(identity);
  if (!archive.valid || identity != key)
    return false;
  const auto collection = [&](auto &items, size_t limit, auto encode) {
    uint64_t size = items.size();
    archive.field(size);
    if (!archive.valid || size > limit || size > items.max_size() ||
        (reading && size > bytes.size() - archive.offset)) {
      archive.valid = false;
      return;
    }
    if (reading)
      items.resize(size);
    for (auto &item : items) {
      if (!archive.valid)
        break;
      encode(item);
    }
  };
  collection(output.plans, UINT32_MAX, [&](auto &plan) {
    collection(plan.slots, capture_slot_limit, [&](auto &slot) {
      archive.fields(slot.section, slot.object_offset, slot.capture.kind,
                     slot.capture.reg, slot.capture.size, slot.capture.offset,
                     slot.capture.object_size, slot.capture.reserved,
                     slot.capture.reserved2);
    });
  });
  collection(output.groups, UINT32_MAX, [&](auto &group) {
    collection(group, group.max_size(), [&](auto &span) {
      archive.fields(span.offset, span.size, span.slot);
    });
  });
  collection(output.sites, UINT32_MAX, [&](auto &site) {
    archive.fields(site.id, site.plan);
    collection(site.bindings, UINT32_MAX, [&](auto &binding) {
      archive.fields(binding.index, binding.slot, binding.group);
    });
    collection(site.accesses, UINT32_MAX, [&](auto &binding) {
      archive.fields(binding.access, binding.capture_slot,
                     binding.capture_group);
    });
  });
  return archive.complete();
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
    if (output.plans[index].slots.size() > capture_slot_limit ||
        bool(index) == output.plans[index].slots.empty())
      return false;
    for (size_t slot_index = 0; slot_index < output.plans[index].slots.size();
         ++slot_index) {
      const auto &slot = output.plans[index].slots[slot_index];
      const auto &capture = slot.capture;
      if (capture.object || (capture.reserved & ~KCTRACE_CAPTURE_ADDRESS) ||
          (capture.kind != KCTRACE_CAPTURE_SLOT && capture.reserved2) ||
          ((capture.reserved & KCTRACE_CAPTURE_ADDRESS) && capture.size != 8))
        return false;
      if (capture.kind == KCTRACE_CAPTURE_NONE) {
        if (capture.size || capture.reg || capture.offset ||
            capture.object_size || slot.section != UINT32_MAX ||
            slot.object_offset || capture.reserved || capture.reserved2)
          return false;
        continue;
      }
      if (!index || !capture.size || capture.size > 8)
        return false;
      if (capture.kind == KCTRACE_CAPTURE_STACK) {
        if ((capture.reg != KCTRACE_REG_RSP &&
             capture.reg != KCTRACE_REG_RBP) ||
            (capture.reg == KCTRACE_REG_RSP && capture.offset < 0) ||
            capture.object_size || slot.section != UINT32_MAX ||
            slot.object_offset)
          return false;
      } else if (capture.kind == KCTRACE_CAPTURE_OBJECT) {
        const auto bytes =
            capture.reserved & KCTRACE_CAPTURE_ADDRESS ? 0U : capture.size;
        if (capture.reg || capture.offset < 0 ||
            slot.section >= image.sections.size() ||
            !ct_kernel_capture_section(image.sections[slot.section]) ||
            !capture.object_size ||
            uint64_t(capture.offset) > capture.object_size ||
            bytes > capture.object_size - uint64_t(capture.offset))
          return false;
        const auto &section = image.sections[slot.section];
        if (slot.object_offset > section.size ||
            capture.object_size > section.size - slot.object_offset ||
            !objects.count(
                {slot.section, slot.object_offset, capture.object_size}))
          return false;
      } else if (capture.kind == KCTRACE_CAPTURE_GPR ||
                 capture.kind == KCTRACE_CAPTURE_SLOT) {
        if (capture.object_size || slot.section != UINT32_MAX ||
            slot.object_offset)
          return false;
        if (capture.kind == KCTRACE_CAPTURE_GPR) {
          if (capture.reg >= KCTRACE_REG_RFLAGS)
            return false;
        } else if (capture.reg || !capture.reserved2 ||
                   capture.reserved2 > slot_index % KCTRACE_VALUE_SLOTS ||
                   output.plans[index]
                           .slots[slot_index -
                                  slot_index % KCTRACE_VALUE_SLOTS +
                                  capture.reserved2 - 1]
                           .capture.size != 8) {
          return false;
        }
      } else {
        return false;
      }
    }
  }
  std::map<uint32_t, std::vector<std::pair<uint64_t, uint32_t>>> leaves;
  uint64_t previous_site = 0;
  for (const auto &restored : output.sites) {
    if (restored.id <= previous_site || !probes.count(restored.id) ||
        restored.plan >= output.plans.size() ||
        (restored.bindings.empty() && restored.accesses.empty()))
      return false;
    previous_site = restored.id;
    used_plans[restored.plan] = true;
    const auto &site = values.sites[restored.id];
    const auto &plan = output.plans[restored.plan];
    std::vector<bool> used_slots(plan.slots.size());
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
           values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_UNION ||
           values.layout_types[type.layout_type - 1].kind == CT_LAYOUT_ARRAY);
      if (aggregate != bool(assignment.group) ||
          (aggregate ? assignment.slot != UINT32_MAX
                     : assignment.slot >= plan.slots.size() ||
                           type.scalar.bytes > 8 ||
                           (type.scalar.kind < CT_VALUE_SIGNED &&
                            !(type.scalar.kind == CT_VALUE_UNKNOWN &&
                              type.raw_scalar)) ||
                           type.scalar.kind > CT_VALUE_POINTER ||
                           (type.scalar.kind == CT_VALUE_FLOAT &&
                            type.scalar.bytes != 4 && type.scalar.bytes != 8)))
        return false;
      auto [shape, inserted] = leaves.try_emplace(variable.type);
      if (inserted)
        shape->second = capture_leaves(values, variable.type, aggregate);
      const auto &recipe = values.recipes[binding.recipe];
      const auto direct =
          ct_kernel_resolve_capture_address(recipe, {}, {}, type.scalar.bytes);
      // A valid cache carries the prior CFA analysis, not an arbitrary address.
      // Reject unsupported recipes without reparsing CFA; exact direct recipes
      // are additionally compared with the restored root below.
      const ct_kernel_dwarf_address symbolic{KCTRACE_CAPTURE_STACK,
                                             KCTRACE_REG_RBP, UINT32_MAX, 0};
      const auto frame =
          site.frame_recipe
              ? ct_kernel_resolve_capture_address(
                    values.recipes[site.frame_recipe], {}, symbolic, 0, true)
              : std::optional<ct_kernel_dwarf_address>{};
      if (!direct && !ct_kernel_resolve_capture_address(recipe, frame, symbolic,
                                                        type.scalar.bytes))
        return false;
      const ct_kernel_value_capture scalar{0, uint32_t(type.scalar.bytes),
                                           assignment.slot};
      const auto &group = output.groups[assignment.group];
      const auto *spans = aggregate ? group.data() : &scalar;
      const size_t span_count = aggregate ? group.size() : 1;
      if (!span_count)
        return false;
      used_groups[assignment.group] = true;
      std::optional<ct_kernel_dwarf_address> root;
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
        ct_kernel_dwarf_address base{
            slot.capture.kind, slot.capture.reg, slot.section,
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
    std::set<uint32_t> access_bindings;
    for (const auto &binding : restored.accesses) {
      if (!binding.access || binding.access >= values.accesses.size() ||
          !access_bindings.insert(binding.access).second ||
          binding.capture_group >= output.groups.size())
        return false;
      const auto &access = values.accesses[binding.access];
      if (!access.variable || access.variable >= values.variables.size() ||
          access.layout_type > values.layout_types.size())
        return false;
      if (binding.capture_slot == UINT32_MAX && !binding.capture_group)
        continue;
      if (!restored.plan || (!access.address && !access.layout_type))
        return false;
      const auto *node = access.layout_type
                             ? &values.layout_types[access.layout_type - 1]
                             : nullptr;
      const bool aggregate =
          !access.address && node &&
          (node->kind == CT_LAYOUT_STRUCT || node->kind == CT_LAYOUT_UNION ||
           node->kind == CT_LAYOUT_ARRAY);
      if (aggregate != bool(binding.capture_group) ||
          (!access.address && node->guarded) ||
          (aggregate && binding.capture_slot != UINT32_MAX))
        return false;
      const uint64_t width = access.address ? 8 : node->bytes;
      const ct_kernel_value_capture scalar{0, uint32_t(width),
                                           binding.capture_slot};
      const auto &group = output.groups[binding.capture_group];
      const auto *spans = aggregate ? group.data() : &scalar;
      const size_t count = aggregate ? group.size() : 1;
      const auto shape =
          access.address
              ? std::vector<std::pair<uint64_t, uint32_t>>{{0, 8}}
              : capture_leaves(values, values.variables[access.variable].type,
                               aggregate, access.layout_type);
      used_groups[binding.capture_group] = true;
      uint64_t previous_end = 0;
      for (size_t index = 0; index < count; ++index) {
        const auto &span = spans[index];
        if (!span.size || span.size > 8 || span.slot >= plan.slots.size() ||
            span.offset < previous_end || span.offset > width ||
            span.size > width - span.offset ||
            !std::binary_search(shape.begin(), shape.end(),
                                std::make_pair(span.offset, span.size)))
          return false;
        previous_end = span.offset + span.size;
        const auto &capture = plan.slots[span.slot].capture;
        if (capture.kind == KCTRACE_CAPTURE_NONE ||
            (capture.size != span.size &&
             !(capture.reserved & KCTRACE_CAPTURE_ADDRESS)) ||
            (access.address && !(capture.reserved & KCTRACE_CAPTURE_ADDRESS)))
          return false;
        size_t dependency = span.slot;
        for (;;) {
          used_slots[dependency] = true;
          const auto &slot = plan.slots[dependency].capture;
          if (slot.kind != KCTRACE_CAPTURE_SLOT)
            break;
          dependency = dependency - dependency % KCTRACE_VALUE_SLOTS +
                       slot.reserved2 - 1;
        }
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
  values.accesses.assign(1, {});
  for (auto &site : values.sites) {
    site.capture_plan = 0;
    site.accesses.clear();
    for (auto &binding : site.bindings) {
      binding.capture_slot = UINT32_MAX;
      binding.capture_group = 0;
    }
  }
  CaptureSites addresses;
  if (!capture_inputs_valid(image, sites, values, addresses, error))
    return false;
  std::set<std::pair<uint64_t, std::string>> selected;
  for (const auto &line : source.lines) {
    if (!line.presentation)
      continue;
    for (const auto &reference : line.presentation->variables) {
      if (reference.access.empty())
        continue;
      for (const auto &variable : values.variables)
        if (variable.id && variable.name == reference.name &&
            (variable.global || variable.owner == reference.function))
          selected.emplace(variable.id, reference.access);
    }
  }
  const std::vector<std::pair<uint64_t, std::string>> requests(selected.begin(),
                                                               selected.end());
  if (!ct_kernel_expand_access_layouts(image, values, requests, error))
    return false;
  for (const auto &[variable, expression] : requests) {
    ct_source_access parsed;
    if (!values.variables[variable].type ||
        values.variables[variable].type >= values.types.size() ||
        !ct_parse_source_access(expression, parsed))
      continue;
    for (auto &field :
         capture_selections(values, variable, parsed, {}, false)) {
      if (values.accesses.size() >= UINT32_MAX) {
        error = "kernel selected access inventory exceeds its bound";
        return false;
      }
      values.accesses.push_back({variable, expression, std::move(field.name),
                                 field.layout, field.address});
    }
  }
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
        values.sites[site.id].accesses = site.accesses;
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
      if (!site.capture_plan && site.accesses.empty())
        continue;
      CaptureSite stored{id, site.capture_plan, {}, site.accesses};
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

bool ct_kernel_plan_xstate(const std::vector<ct_kernel_xstate_site> &xstate,
                           ct_kernel_value_metadata &values,
                           std::vector<ct_kernel_capture_plan> &plans,
                           std::string &error,
                           const std::map<uint64_t, uint8_t> &tiles,
                           const std::map<uint64_t, uint32_t> &scalar,
                           const ct_kernel_source_metadata *source,
                           const std::vector<ct_kernel_site> *original,
                           const ct_kernel_decompile_metadata *decompile) {
  if (xstate.size() != values.sites.size()) {
    error = "xstate ownership inventory differs from capture sites";
    return false;
  }
  for (const auto &[id, mask] : tiles)
    if (!id || id >= xstate.size() || !mask || !xstate[id].owned ||
        !(xstate[id].components & 0x10)) {
      error = "AMX tile selection does not identify an owned data snapshot";
      return false;
    }
  for (const auto &[id, mask] : scalar)
    if (!id || id >= xstate.size() || !mask ||
        (mask & ~KCTRACE_XSTATE_SCALAR)) {
      error = "scalar xstate selection has an invalid site or component";
      return false;
    }
  // This transient demand map is needed only for FPU-bearing modules. A live
  // DWARF location alone does not mean a value is displayed on every row.
  std::map<uint64_t, uint64_t> previous;
  std::map<uint32_t, uint64_t> first;
  const bool owned = std::any_of(xstate.begin(), xstate.end(),
                                 [](const auto &site) { return site.owned; });
  if (source && original && owned)
    for (size_t index = 0; index < original->size(); ++index) {
      const auto &site = (*original)[index];
      if (!site.id || site.id >= values.sites.size())
        continue;
      const auto function = values.sites[site.id].function;
      if (function)
        first.try_emplace(function, site.id);
      if (!index || !xstate[site.id].owned)
        continue;
      const auto &before = (*original)[index - 1];
      if (before.id && before.id < values.sites.size() &&
          before.section == site.section &&
          before.offset + before.original_size == site.offset &&
          values.sites[before.id].function == function)
        previous.emplace(site.id, before.id);
    }
  const size_t original_count = plans.size();
  std::map<std::tuple<uint32_t, uint64_t, uint64_t>, uint32_t> interned;
  for (size_t id = 1; id < values.sites.size(); ++id) {
    const auto fixed = scalar.find(id);
    const uint32_t scalar_mask = fixed == scalar.end() ? 0 : fixed->second;
    if (!xstate[id].owned && !scalar_mask)
      continue;
    auto &site = values.sites[id];
    if (site.capture_plan >= plans.size()) {
      error = "xstate snapshot refers to an absent capture plan";
      return false;
    }
    unsigned components = xstate[id].owned ? xstate[id].components : 0;
    std::vector<uint64_t> wanted;
    if (source && original && xstate[id].owned) {
      std::set<std::pair<uint64_t, std::string>> selected_paths;
      const auto before = previous.find(id);
      capture_requests(
          *source, values, id, before == previous.end() ? 0 : before->second,
          site.function && first[site.function] == id, wanted, selected_paths);
      if (decompile)
        for (uint64_t point :
             {uint64_t(id), before == previous.end() ? 0 : before->second})
          if (point && point < decompile->sites.size()) {
            const auto &row = decompile->sites[point];
            if (row.statement && row.statement < decompile->statements.size()) {
              const auto &text = decompile->statements[row.statement].text;
              for (const auto &reference : row.variables)
                if (reference.variable &&
                    reference.variable < values.variables.size() &&
                    ct_kernel_decompile_identifier(
                        text, values.variables[reference.variable].name))
                  wanted.push_back(reference.variable);
            }
            // The return summary consumes the proven ABI value even when a
            // decompiled expression does not name its synthetic register.
            if (row.returned && row.function &&
                row.function < decompile->functions.size()) {
              const auto function =
                  decompile->functions[row.function].value_function;
              if (function && function < values.functions.size()) {
                const auto &returned = values.functions[function];
                for (const auto &binding : values.sites[point].bindings)
                  if (binding.variable &&
                      binding.variable < values.variables.size() &&
                      values.variables[binding.variable].type ==
                          returned.return_type &&
                      binding.recipe &&
                      binding.recipe < values.recipes.size() &&
                      ct_kernel_recipe_register(
                          values.recipes[binding.recipe]) ==
                          returned.return_register)
                    wanted.push_back(binding.variable);
              }
            }
          }
    }
    uint64_t value_registers = 0;
    for (const auto &binding : site.bindings) {
      if (!xstate[id].owned || (source && original &&
                                std::find(wanted.begin(), wanted.end(),
                                          binding.variable) == wanted.end()))
        continue;
      if (!binding.variable || binding.variable >= values.variables.size() ||
          !binding.recipe || binding.recipe >= values.recipes.size())
        continue;
      const auto type_id = values.variables[binding.variable].type;
      if (!type_id || type_id >= values.types.size())
        continue;
      const auto &type = values.types[type_id];
      const auto bytes = type.scalar.bytes;
      if (type.guarded || type.scalar.kind != CT_VALUE_FLOAT ||
          (bytes != 4 && bytes != 8 && bytes != 10 && bytes != 16))
        continue;
      const auto reg =
          ct_kernel_recipe_register(values.recipes[binding.recipe], bytes);
      if (reg && *reg >= 17 && *reg <= 32 && bytes <= 8)
        value_registers |= UINT64_C(1) << (*reg - 17);
      else if (reg && *reg >= 33 && *reg <= 40 && (bytes == 10 || bytes == 16))
        value_registers |= UINT64_C(1) << (16 + *reg - 33);
      else if (reg && *reg >= 67 && *reg <= 82 && bytes <= 8)
        value_registers |= UINT64_C(1) << (24 + *reg - 67);
    }
    unsigned tile_mask = 0;
    if (components & 0x10) {
      const auto found = tiles.find(id);
      if (found == tiles.end() || !found->second) {
        error = "AMX data snapshot has no proven tile selection";
        return false;
      }
      tile_mask = found->second;
    }
    auto [entry, inserted] = interned.try_emplace(
        std::make_tuple(site.capture_plan,
                        uint64_t(components) | (uint64_t(tile_mask) << 8) |
                            (uint64_t(scalar_mask) << 16),
                        value_registers),
        site.capture_plan);
    if (inserted && (components || scalar_mask || value_registers)) {
      auto plan = plans[site.capture_plan];
      const auto append_component = [&](unsigned component, unsigned begin,
                                        unsigned end) {
        for (unsigned offset = begin; offset < end; offset += 8) {
          ct_kernel_capture_slot slot;
          slot.capture.kind = KCTRACE_CAPTURE_XSTATE;
          slot.capture.reg = component;
          slot.capture.offset = offset;
          slot.capture.size = std::min(8U, end - offset);
          if (capture_chain(plan, {slot}) == UINT32_MAX)
            return false;
        }
        return true;
      };
      bool fits = true;
      if (components & 1)
        fits = append_component(0, 0, 24) && append_component(0, 32, 160);
      if (components & 2)
        fits = fits && append_component(1, 24, 28) &&
               append_component(1, 160, 416);
      for (unsigned component : {2U, 5U, 6U, 7U})
        if (components & (1U << component))
          fits = fits && append_component(component, 0,
                                          component == 2   ? 256
                                          : component == 5 ? 64
                                          : component == 6 ? 512
                                                           : 1024);
      if (components & 8)
        fits = fits && append_component(17, 0, 64);
      for (unsigned tile = 0; tile < 8; ++tile)
        if (tile_mask & (1U << tile))
          fits = fits && append_component(18, tile * 1024, (tile + 1) * 1024);
      for (unsigned component : {9U, 10U, 11U, 12U, 13U, 16U})
        if (scalar_mask & (1U << component))
          fits = fits && append_component(component, 0,
                                          component == 11   ? 16
                                          : component == 12 ? 24
                                                            : 8);
      // A displayed scalar needs only its storage, not every register in the
      // hardware component. Explicit instruction operands above already carry
      // these bytes in their component snapshots.
      for (unsigned reg = 0; reg < 40; ++reg)
        if (value_registers & (UINT64_C(1) << reg)) {
          if (reg < 16 && !(components & 2))
            fits = fits && append_component(1, 160 + reg * 16, 168 + reg * 16);
          else if (reg >= 16 && reg < 24 && !(components & 1))
            fits =
                fits && append_component(0, 0, 8) &&
                append_component(0, 32 + (reg - 16) * 16, 42 + (reg - 16) * 16);
          else if (reg >= 24 && !(components & 0x80))
            fits = fits &&
                   append_component(7, (reg - 24) * 64, (reg - 24) * 64 + 8);
        }
      if (!fits) {
        error = "xstate and source snapshots exceed the bounded capture bundle";
        return false;
      }
      if (plans.size() >= UINT32_MAX) {
        error = "xstate capture plan inventory exceeds its bound";
        return false;
      }
      entry->second = plans.size();
      plans.push_back(std::move(plan));
    }
    site.capture_plan = entry->second;
    const auto &plan = plans[site.capture_plan];
    for (auto &binding : site.bindings) {
      if (!xstate[id].owned || (source && original &&
                                std::find(wanted.begin(), wanted.end(),
                                          binding.variable) == wanted.end()))
        continue;
      if (binding.capture_slot != UINT32_MAX || binding.capture_group ||
          !binding.variable || binding.variable >= values.variables.size() ||
          !binding.recipe || binding.recipe >= values.recipes.size())
        continue;
      const auto type_id = values.variables[binding.variable].type;
      if (!type_id || type_id >= values.types.size())
        continue;
      const auto &type = values.types[type_id];
      const auto bytes = type.scalar.bytes;
      if (type.guarded ||
          (bytes != 4 && bytes != 8 && bytes != 10 && bytes != 16) ||
          type.scalar.kind != CT_VALUE_FLOAT)
        continue;
      const auto reg =
          ct_kernel_recipe_register(values.recipes[binding.recipe], bytes);
      if (!reg)
        continue;
      if (*reg >= 33 && *reg <= 40 && (bytes == 10 || bytes == 16)) {
        std::vector<ct_kernel_value_capture> spans;
        for (unsigned part = 0; part < 2; ++part) {
          const auto found = std::find_if(
              plan.slots.begin(), plan.slots.end(), [&](const auto &slot) {
                return slot.capture.kind == KCTRACE_CAPTURE_XSTATE &&
                       slot.capture.reg == 0 &&
                       slot.capture.offset ==
                           int64_t(32 + (*reg - 33) * 16 + part * 8) &&
                       slot.capture.size >= (part ? 2 : 8);
              });
          if (found != plan.slots.end())
            spans.push_back({part * 8U, part ? 2U : 8U,
                             uint32_t(found - plan.slots.begin())});
        }
        const auto environment = std::find_if(
            plan.slots.begin(), plan.slots.end(), [](const auto &slot) {
              return slot.capture.kind == KCTRACE_CAPTURE_XSTATE &&
                     slot.capture.reg == 0 && slot.capture.offset == 0 &&
                     slot.capture.size == 8;
            });
        if (spans.size() == 2 && environment != plan.slots.end()) {
          // The third span authenticates TOP and FTW, not variable storage.
          spans.push_back({16, 8, uint32_t(environment - plan.slots.begin())});
          binding.capture_group = values.capture_groups.size();
          values.capture_groups.push_back(std::move(spans));
        }
        continue;
      }
      const bool high_xmm = *reg >= 67 && *reg <= 82;
      if ((!high_xmm && (*reg < 17 || *reg > 32)) || bytes > 8)
        continue;
      const unsigned component = high_xmm ? 7 : 1;
      const int64_t offset =
          high_xmm ? (*reg - 67) * 64 : 160 + (*reg - 17) * 16;
      const auto found = std::find_if(
          plan.slots.begin(), plan.slots.end(), [&](const auto &slot) {
            return slot.capture.kind == KCTRACE_CAPTURE_XSTATE &&
                   slot.capture.reg == component &&
                   slot.capture.offset == offset && slot.capture.size >= bytes;
          });
      if (found != plan.slots.end())
        binding.capture_slot = found - plan.slots.begin();
    }
  }
  if (plans.size() != original_count) {
    // Enriched plans own the original source slots too. Drop a base plan only
    // after every site's reference has moved; slot numbers within a retained
    // plan and source capture groups are unchanged.
    std::vector<uint32_t> remap(plans.size());
    for (const auto &site : values.sites) {
      if (site.capture_plan >= plans.size()) {
        error = "source snapshot refers to an absent capture plan";
        return false;
      }
      remap[site.capture_plan] = 1;
    }
    size_t retained = 1;
    for (size_t index = 1; index < plans.size(); ++index) {
      if (!remap[index])
        continue;
      remap[index] = retained;
      if (index != retained)
        plans[retained] = std::move(plans[index]);
      ++retained;
    }
    if (retained != plans.size()) {
      plans.resize(retained);
      for (auto &site : values.sites)
        site.capture_plan = site.capture_plan ? remap[site.capture_plan] : 0;
    }
  }
  return true;
}

bool ct_kernel_xstate_bytes(const ct_kernel_capture_plan &plan,
                            const ct_kernel_observation &event,
                            unsigned component, uint64_t offset, void *output,
                            size_t bytes) {
  if (!output || !bytes || bytes > 64 || offset > UINT64_MAX - bytes)
    return false;
  auto *destination = static_cast<unsigned char *>(output);
  std::array<bool, 64> covered{};
  for (size_t index = 0; index < plan.slots.size(); ++index) {
    const auto &slot = plan.slots[index].capture;
    if (slot.kind != KCTRACE_CAPTURE_XSTATE || slot.reg != component ||
        slot.offset < 0 || slot.size > 8)
      continue;
    const auto *captured = event.capture_data(index);
    if (!captured)
      continue;
    for (size_t byte = 0; byte < slot.size; ++byte) {
      const auto address = uint64_t(slot.offset) + byte;
      if (address >= offset && address - offset < bytes) {
        destination[address - offset] = captured[byte];
        covered[address - offset] = true;
      }
    }
  }
  return std::all_of(covered.begin(), covered.begin() + bytes,
                     [](bool valid) { return valid; });
}

std::string ct_kernel_tile_value(const ct_kernel_capture_plan &plan,
                                 const ct_kernel_observation &event,
                                 unsigned tile, bool initialized, bool raw) {
  std::array<unsigned char, 64> config{};
  if (tile >= 8 || (raw && initialized))
    return "?";
  if (!raw) {
    if (!ct_kernel_xstate_bytes(plan, event, 17, 0, config.data(),
                                config.size()))
      return "?";
    if (!config[0])
      return "{}";
    if (config[0] != 1)
      return "?";
  }
  // State-transfer instructions save/restore all 1KiB of each tile, regardless
  // of TILECFG palette or dimensions. Normal tile operands use configured rows.
  const unsigned columns =
      raw ? 64 : config[16 + 2 * tile] | (unsigned(config[17 + 2 * tile]) << 8);
  const unsigned rows = raw ? 16 : config[48 + tile];
  if (columns > 64 || rows > 16 || (!columns != !rows))
    return "?";
  std::array<unsigned char, 1024> bytes{};
  std::bitset<1024> covered;
  if (initialized)
    covered.set();
  for (size_t index = 0; !initialized && index < plan.slots.size(); ++index) {
    const auto &slot = plan.slots[index].capture;
    if (slot.kind != KCTRACE_CAPTURE_XSTATE || slot.reg != 18 ||
        slot.offset < tile * 1024 || slot.offset >= (tile + 1) * 1024 ||
        !slot.size || slot.size > 8 ||
        slot.size > (tile + 1) * 1024 - slot.offset)
      continue;
    const auto *captured = event.capture_data(index);
    if (!captured)
      continue;
    const auto begin = size_t(slot.offset) - tile * 1024;
    for (unsigned byte = 0; byte < slot.size; ++byte) {
      bytes[begin + byte] = captured[byte];
      covered.set(begin + byte);
    }
  }
  std::string result = "{";
  for (unsigned row = 0; row < rows; ++row) {
    if (row)
      result += ", ";
    result += "0x";
    for (unsigned byte = columns; byte-- > 0;) {
      const auto offset = row * 64 + byte;
      if (!covered.test(offset))
        return "?";
      result += "0123456789abcdef"[bytes[offset] >> 4];
      result += "0123456789abcdef"[bytes[offset] & 15];
    }
  }
  return result + '}';
}

std::vector<uint32_t> ct_kernel_capture_xstate_masks(
    const ct_kernel_value_metadata &values,
    const std::vector<ct_kernel_capture_plan> &plans) {
  std::vector<uint32_t> masks(values.sites.size());
  for (size_t id = 1; id < values.sites.size(); ++id) {
    const auto plan = values.sites[id].capture_plan;
    if (plan < plans.size())
      for (const auto &slot : plans[plan].slots)
        if (slot.capture.kind == KCTRACE_CAPTURE_XSTATE &&
            slot.capture.reg < 32)
          masks[id] |= 1U << slot.capture.reg;
  }
  return masks;
}

bool ct_kernel_capture_chunks(const std::vector<ct_kernel_capture_plan> &plans,
                              std::vector<ct_kernel_capture_chunk_plan> &chunks,
                              std::string &error) {
  chunks.clear();
  if (plans.empty() || plans.size() > uint64_t(UINT32_MAX) + 1 ||
      !plans.front().slots.empty()) {
    error = "invalid capture plan roots";
    return false;
  }
  chunks.resize(plans.size() - 1);
  for (size_t root = 1; root < plans.size(); ++root) {
    const auto &slots = plans[root].slots;
    if (slots.empty() || slots.size() > capture_slot_limit) {
      error = "invalid capture plan slot count";
      return false;
    }
    size_t chunk = root - 1;
    for (size_t slot = 0; slot < slots.size(); ++slot) {
      if (slot && !(slot % KCTRACE_VALUE_SLOTS)) {
        if (chunks.size() >= UINT32_MAX) {
          error = "kernel capture chunk inventory exceeds its bound";
          return false;
        }
        chunks[chunk].next = chunks.size() + 1;
        chunk = chunks.size();
        chunks.emplace_back();
      }
      chunks[chunk].slots[slot % KCTRACE_VALUE_SLOTS] = slots[slot];
      if (slots[slot].capture.kind == KCTRACE_CAPTURE_XSTATE) {
        if (slots[slot].capture.reg >= 32 ||
            !(KCTRACE_XSTATE_SUPPORTED & (1U << slots[slot].capture.reg))) {
          error = "invalid xstate capture component";
          return false;
        }
        chunks[chunk].xstate_mask |= 1U << slots[slot].capture.reg;
      }
    }
  }
  return true;
}
