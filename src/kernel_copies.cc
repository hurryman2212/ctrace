#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <map>
#include <set>

#include <elf.h>

#include "uapi/kctrace.h"

#include "kernel_copies.h"
#include "kernel_gate.h"
#include "kernel_interrupt.h"
#include "kernel_object.h"
#include "kernel_policy.h"
#include "kernel_rewrite.h"

static constexpr size_t copy_binding_record_limit = 1000000;
static constexpr size_t copy_interrupt_range_limit = 16;
static constexpr size_t copy_interrupt_dispatch_limit = 64;
static constexpr size_t copy_interrupt_window_limit = 4096;
static constexpr size_t copy_interrupt_byte_limit = 65536;

bool ct_kernel_materialize_copies(const ct_kernel_image &image,
                                  const ct_kernel_policy &policy,
                                  const ct_kernel_copies &copies,
                                  uint32_t program_flags,
                                  const std::vector<uint32_t> &capture_plans,
                                  std::vector<unsigned char> &output,
                                  std::string &error,
                                  const ct_kernel_interrupt_proof *interrupt) {
  output.clear();
  error.clear();
  const auto fail = [&](const std::string &reason) {
    output.clear();
    error = reason;
    return false;
  };
  ct_kernel_object object(image);
  if (!object.valid(error))
    return false;
  const uint64_t records = uint64_t(copies.sections.size()) +
                           copies.sites.size() + copies.functions.size() +
                           copies.symbols.size() + copies.relocations.size() +
                           copies.boundaries.size() +
                           copies.regenerate_sections.size();
  if (records > copy_binding_record_limit || copies.functions.empty() ||
      copies.sites.empty() || image.sections.size() != object.section_count())
    return fail("invalid or oversized kernel copy binding inventory");
  if (policy.functions.empty() || policy.paths.empty() ||
      policy.functions.size() > copy_binding_record_limit ||
      policy.paths.size() > copy_binding_record_limit ||
      policy.sites.size() < 2 ||
      policy.sites.size() > copy_binding_record_limit + 1 ||
      (program_flags &
       ~(KCTRACE_PROGRAM_TERMINAL | KCTRACE_PROGRAM_PERFETTO |
         KCTRACE_PROGRAM_WITHIN_FILTER | KCTRACE_PROGRAM_SINGLE_FULL |
         KCTRACE_PROGRAM_WITHIN_INTR)) ||
      bool(program_flags & KCTRACE_PROGRAM_WITHIN_INTR) != bool(interrupt) ||
      bool(program_flags & KCTRACE_PROGRAM_SINGLE_FULL) != copies.single_full ||
      (!capture_plans.empty() &&
       (capture_plans.size() != policy.sites.size() || capture_plans[0])))
    return fail("invalid numeric policy or capture map for copy binding");

  uint32_t symbol_table = 0;
  for (uint32_t index = 1; index < image.sections.size(); ++index) {
    const auto *header = object.section_header(index);
    if (header->sh_type == SHT_SYMTAB) {
      if (symbol_table)
        return fail("kernel copy binding requires one symbol table");
      symbol_table = index;
    }
  }
  if (!symbol_table)
    return fail("kernel copy binding has no original symbol table");
  for (const auto &symbol : image.symbols)
    if (symbol.name.compare(0, 9, "__ctrace_") == 0 ||
        symbol.name == "kctrace_select" || symbol.name == "kctrace_probe" ||
        symbol.name == "kctrace_perfetto_probe")
      return fail("kernel copy binding contains a reserved symbol");

  std::map<uint32_t, const ct_kernel_copy_section *> sections;
  for (const auto &section : copies.sections) {
    if (!section.index || section.original_section >= image.sections.size() ||
        !section.original_section ||
        !sections.emplace(section.index, &section).second ||
        unsigned(section.level) > unsigned(ct_kernel_copy_level::full))
      return fail("copy sections have invalid or duplicate identities");
    const auto &original = image.sections[section.original_section];
    if ((original.flags & SHF_EXECINSTR) && !original.size)
      return fail("empty executable section has a generated copy");
    if (section.index < image.sections.size()) {
      if (section.index != section.original_section ||
          section.name != original.name || section.flags != original.flags ||
          section.alignment != original.alignment ||
          section.canonical != bool(original.flags & SHF_EXECINSTR) ||
          (copies.single_full && section.canonical &&
           section.level != ct_kernel_copy_level::full))
        return fail(
            "replacement copy section differs from its original identity");
    } else {
      const char *levels[] = {"arm", "perfetto", "full"};
      if (copies.single_full || section.canonical ||
          !(original.flags & SHF_EXECINSTR) ||
          section.flags != original.flags ||
          section.alignment != original.alignment ||
          section.name !=
              original.name + ".ctrace." + levels[unsigned(section.level)])
        return fail("body copy section differs from its original identity");
    }
  }
  for (uint32_t index = 1; index < image.sections.size(); ++index) {
    const auto &original = image.sections[index];
    if (!(original.flags & SHF_EXECINSTR))
      continue;
    const auto *header = object.section_header(index);
    if (!original.size &&
        (header->sh_size || header->sh_flags != original.flags))
      return fail("empty executable section differs from its original ELF");
    if (original.size && !sections.count(index))
      return fail("copy binding omits an original executable section");
  }
  // Every original RELA payload is superseded by the complete artifact graph.
  // Keeping one would apply stale fields twice or retain original code targets.
  for (uint32_t index = 1; index < image.sections.size(); ++index)
    if (image.sections[index].type == SHT_RELA &&
        !object.replace_section(index, {}, error))
      return false;
  const std::set<uint32_t> regenerate(copies.regenerate_sections.begin(),
                                      copies.regenerate_sections.end());
  if (regenerate.size() != copies.regenerate_sections.size())
    return fail("duplicate regenerated kernel metadata sections");
  for (uint32_t index : regenerate) {
    if (!index || index >= image.sections.size() || sections.count(index))
      return fail("invalid regenerated kernel metadata section");
    const auto &section = image.sections[index];
    const bool known =
        section.name == ".return_sites" || section.name == ".call_sites" ||
        section.name == ".retpoline_sites" ||
        section.name == ".ibt_endbr_seal" ||
        section.name == ".note.gnu.build-id" || section.name == ".orc_unwind" ||
        section.name == ".orc_unwind_ip";
    if ((!known &&
         !(section.type == SHT_RELA && regenerate.count(section.info))) ||
        !object.replace_section(index, {}, error))
      return fail("unexpected section requested for metadata regeneration");
  }
  // Append all body sections before adding a relocation table or other new
  // section, so their indexes agree exactly with the offline artifact.
  for (const auto &[index, section] : sections) {
    if (index < image.sections.size()) {
      if (!object.replace_section(index, section->bytes, error))
        return false;
    } else if (index != object.section_count() ||
               object.add_section(section->name, SHT_PROGBITS, section->flags,
                                  section->alignment, 0, 0, 0, section->bytes,
                                  error) != index) {
      return fail("body section indexes are not contiguous with the input ELF");
    }
  }
  const auto address_valid = [&](const ct_kernel_copy_address &address) {
    const auto *header = object.section_header(address.section);
    return address.section && header && address.section < SHN_LORESERVE &&
           address.offset <= header->sh_size &&
           !regenerate.count(address.section);
  };
  const auto relocation_width = [](uint32_t type) -> unsigned {
    switch (type) {
    case R_X86_64_NONE:
      return 0;
    case R_X86_64_64:
    case R_X86_64_PC64:
      return 8;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_32:
    case R_X86_64_32S:
    case R_X86_64_GOTPCREL:
    case R_X86_64_GOTPCRELX:
    case R_X86_64_REX_GOTPCRELX:
      return 4;
    case R_X86_64_16:
    case R_X86_64_PC16:
      return 2;
    case R_X86_64_8:
    case R_X86_64_PC8:
      return 1;
    default:
      return UINT_MAX;
    }
  };
  std::map<std::pair<uint32_t, uint32_t>, Elf64_Sym> original_symbols;
  for (const auto &symbol : image.symbols) {
    if (symbol.table != symbol_table)
      return fail("original symbol belongs to an unexpected symbol table");
    const auto *table = object.section_content(symbol.table);
    if (!table || symbol.index >= table->size() / sizeof(Elf64_Sym))
      return fail("original symbol index exceeds its table");
    Elf64_Sym raw;
    std::memcpy(&raw, table->data() + symbol.index * sizeof(raw), sizeof(raw));
    original_symbols.emplace(std::make_pair(symbol.table, symbol.index), raw);
    if (regenerate.count(symbol.section)) {
      raw.st_value = raw.st_size = 0;
      if (!object.replace_symbol(symbol.table, symbol.index, raw, error))
        return false;
    } else {
      const auto replacement = sections.find(symbol.section);
      if (replacement != sections.end() &&
          !(replacement->second->flags & SHF_EXECINSTR) &&
          replacement->second->bytes.size() !=
              image.sections[symbol.section].size &&
          symbol.type != STT_SECTION && (symbol.offset || symbol.size))
        return fail(
            "cloned instruction metadata has a nonsection symbol extent");
    }
  }
  std::set<std::pair<uint32_t, uint32_t>> replaced;
  for (const auto &symbol : copies.symbols) {
    const auto key = std::make_pair(symbol.table, symbol.index);
    const auto original = original_symbols.find(key);
    if (original == original_symbols.end() || !replaced.insert(key).second ||
        !address_valid(symbol.address))
      return fail("invalid or duplicate copied symbol mapping");
    auto raw = original->second;
    if (raw.st_shndx < image.sections.size() &&
        (image.sections[raw.st_shndx].flags & SHF_EXECINSTR) &&
        !image.sections[raw.st_shndx].size)
      return fail("empty executable symbol must remain unchanged");
    const auto *destination = object.section_header(symbol.address.section);
    if (symbol.size > destination->sh_size - symbol.address.offset ||
        !(destination->sh_flags & SHF_EXECINSTR))
      return fail("copied symbol exceeds its executable section");
    raw.st_shndx = symbol.address.section;
    raw.st_value = symbol.address.offset;
    raw.st_size = symbol.size;
    if (!object.replace_symbol(symbol.table, symbol.index, raw, error))
      return false;
  }
  for (const auto &symbol : image.symbols) {
    if (symbol.section < image.sections.size() &&
        (image.sections[symbol.section].flags & SHF_EXECINSTR) &&
        !replaced.count({symbol.table, symbol.index})) {
      const auto &raw = original_symbols.at({symbol.table, symbol.index});
      // Empty executable sections have no instruction/copy mapping. Keep
      // their zero-extent markers, including the ordinary .text section
      // symbol in modules whose code lives entirely in init/exit sections.
      if (image.sections[symbol.section].size || symbol.offset || symbol.size ||
          raw.st_shndx != symbol.section || raw.st_value || raw.st_size)
        return fail("copy binding omits an original executable symbol");
    }
  }

  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_copy_site *> sites;
  std::vector<const ct_kernel_copy_site *> original_sites(policy.sites.size());
  std::set<uint64_t> terminal_sites;
  for (const auto &boundary : copies.boundaries)
    if (boundary.kind == ct_kernel_copy_boundary_kind::return_ ||
        boundary.kind == ct_kernel_copy_boundary_kind::tail ||
        boundary.kind == ct_kernel_copy_boundary_kind::indirect ||
        boundary.kind == ct_kernel_copy_boundary_kind::unknown_control)
      terminal_sites.insert(boundary.site_id);
  for (const auto &site : copies.sites) {
    if (!sites
             .emplace(
                 std::make_pair(site.original.section, site.original.offset),
                 &site)
             .second)
      return fail("duplicate original instruction in the copy address map");
    if (site.id) {
      if (site.id >= original_sites.size() || original_sites[site.id] ||
          !policy.sites[site.id].function ||
          policy.sites[site.id].function >= policy.functions.size() ||
          policy.sites[site.id].path >= policy.paths.size())
        return fail("copy probe has an invalid original site identity");
      original_sites[site.id] = &site;
    }
    const bool terminal = terminal_sites.count(site.id);
    if ((!copies.single_full && site.levels[0].probe) ||
        site.levels[2].probe != (bool(site.id) && !terminal) ||
        (site.levels[1].probe && (!site.id || terminal)))
      return fail(
          "copy probe levels differ from the original instruction inventory");
    if (copies.single_full)
      for (unsigned level = 0; level < 2; ++level) {
        const auto &alias = site.levels[level];
        const auto &full = site.levels[2];
        if (alias.entry.section != full.entry.section ||
            alias.entry.offset != full.entry.offset ||
            alias.operation.section != full.operation.section ||
            alias.operation.offset != full.operation.offset ||
            alias.emitted_size != full.emitted_size ||
            alias.probe != full.probe)
          return fail("single-full instruction maps do not alias one body");
      }
    for (const auto &location : site.levels)
      if (!address_valid(location.entry) ||
          !address_valid(location.operation) ||
          location.entry.section != location.operation.section ||
          location.entry.offset > location.operation.offset ||
          location.emitted_size >
              object.section_header(location.operation.section)->sh_size -
                  location.operation.offset)
        return fail("copy instruction mapping exceeds its body");
  }
  if (std::any_of(original_sites.begin() + 1, original_sites.end(),
                  [](const auto *site) { return !site; }))
    return fail("copy probe inventory omits original site identities");
  std::map<uint32_t, std::map<uint64_t, std::pair<uint64_t, uint32_t>>>
      function_symbols;
  for (const auto &function : copies.functions) {
    if (!function.function || function.function >= policy.functions.size() ||
        !address_valid(function.canonical) || !function.size ||
        function.size >
            object.section_header(function.canonical.section)->sh_size -
                function.canonical.offset)
      return fail("copied function has no original numeric policy identity");
    const auto &original = policy.functions[function.function];
    const std::string parent_name =
        "__ctrace_function_" + std::to_string(function.function);
    Elf64_Sym parent{};
    parent.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    parent.st_other = STV_HIDDEN;
    parent.st_shndx = function.canonical.section;
    parent.st_value = function.canonical.offset;
    parent.st_size = function.size;
    uint32_t parent_index = 0;
    if (!object.append_symbol(symbol_table, parent_name, parent, parent_index,
                              error))
      return false;
    if (!function_symbols[function.canonical.section]
             .emplace(function.canonical.offset,
                      std::make_pair(function.canonical.offset + function.size,
                                     parent_index))
             .second)
      return fail("duplicate canonical function symbol extent");
    if (copies.single_full) {
      const auto &full = function.bodies[2];
      if (function.canonical.section != original.section ||
          full.section != function.canonical.section ||
          full.offset < function.canonical.offset ||
          full.offset - function.canonical.offset >= function.size)
        return fail("single-full function body leaves its canonical extent");
      for (const auto &body : function.bodies)
        if (body.section != full.section || body.offset != full.offset)
          return fail("single-full function bodies do not alias one address");
      continue;
    }
    const auto last = sites.find({original.section, original.end});
    for (unsigned level = 0; level < 3; ++level) {
      const auto &body = function.bodies[level];
      const auto section = sections.find(body.section);
      if (!address_valid(body) || section == sections.end() ||
          section->second->canonical ||
          section->second->original_section != original.section ||
          unsigned(section->second->level) != level)
        return fail("copied function body does not match its level section");
      uint64_t end = 0;
      if (original.end == image.sections[original.section].size)
        end = section->second->bytes.size();
      else if (last != sites.end() &&
               last->second->levels[level].entry.section == body.section)
        end = last->second->levels[level].entry.offset;
      else
        return fail("copied function end has no original boundary mapping");
      if (body.offset >= end)
        return fail("copied function has an empty or reversed body extent");
      Elf64_Sym symbol{};
      symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
      symbol.st_other = STV_HIDDEN;
      symbol.st_shndx = body.section;
      symbol.st_value = body.offset;
      symbol.st_size = end - body.offset;
      uint32_t index = 0;
      // Objtool recognizes .cold suffixes as fragments of the same parent
      // function. Gate continuations cross these fragments with identical
      // original stack state; they are not calls into unrelated functions.
      if (!object.append_symbol(symbol_table,
                                parent_name + ".cold." + std::to_string(level),
                                symbol, index, error))
        return false;
      if (!function_symbols[body.section]
               .emplace(body.offset, std::make_pair(end, index))
               .second)
        return fail("duplicate copied body symbol extent");
    }
  }
  std::array<uint32_t, 3> imports{};
  const char *names[] = {"kctrace_select", "kctrace_perfetto_probe",
                         "kctrace_probe"};
  for (unsigned index = copies.single_full ? 2 : 0; index < imports.size();
       ++index) {
    Elf64_Sym symbol{};
    symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
    if (!object.append_symbol(symbol_table, names[index], symbol,
                              imports[index], error))
      return false;
  }
  std::map<uint32_t, uint32_t> anchors;
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_copy_relocation *>
      relocation_fields;
  std::set<std::pair<uint32_t, uint64_t>> helper_fields, bound_helpers;
  const auto anchor_for = [&](uint32_t section, uint32_t &symbol) {
    auto anchor = anchors.find(section);
    if (anchor == anchors.end()) {
      Elf64_Sym raw{};
      raw.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
      raw.st_other = STV_HIDDEN;
      raw.st_shndx = section;
      uint32_t index = 0;
      if (!object.append_symbol(
              symbol_table, "__ctrace_copy_anchor_" + std::to_string(section),
              raw, index, error))
        return false;
      anchor = anchors.emplace(section, index).first;
    }
    symbol = anchor->second;
    return true;
  };
  // Keep an explicit base for every materialized section, including padding
  // sections without incoming edges. Final ld/objtool validation can compare
  // their bytes after section merging without guessing layout offsets.
  for (const auto &[index, section] : sections) {
    uint32_t symbol = 0;
    if (!anchor_for(index, symbol))
      return false;
  }
  for (const auto &relocation : copies.relocations) {
    if (!address_valid(relocation.source))
      return fail("copy relocation has an invalid or regenerated source");
    if (relocation.type != R_X86_64_NONE &&
        !relocation_fields
             .emplace(std::make_pair(relocation.source.section,
                                     relocation.source.offset),
                      &relocation)
             .second)
      return fail("duplicate copied relocation field");
    Elf64_Rela raw{};
    raw.r_offset = relocation.source.offset;
    raw.r_addend = relocation.addend;
    uint32_t symbol = 0;
    switch (relocation.kind) {
    case ct_kernel_copy_relocation_kind::address: {
      if (!address_valid(relocation.target))
        return fail("copy relocation has an invalid or regenerated target");
      const auto *target = object.section_header(relocation.target.section);
      if (relocation.type != R_X86_64_NONE &&
          (object.section_header(relocation.source.section)->sh_flags &
           SHF_ALLOC) &&
          (target->sh_flags & SHF_EXECINSTR) && !target->sh_size)
        return fail("live relocation targets an empty executable section");
      uint64_t symbol_offset = 0;
      if (object.section_header(relocation.source.section)->sh_flags &
          SHF_EXECINSTR) {
        const auto section = function_symbols.find(relocation.target.section);
        if (section != function_symbols.end()) {
          auto function = section->second.upper_bound(relocation.target.offset);
          if (function != section->second.begin()) {
            --function;
            if (relocation.target.offset < function->second.first) {
              symbol_offset = function->first;
              symbol = function->second.second;
            }
          }
        }
      }
      // Direct edges name their actual function fragment for objtool's CFG
      // proof. Lookup data continues to use independent section anchors.
      if (!symbol && !anchor_for(relocation.target.section, symbol))
        return false;
      const __int128 addend = __int128(relocation.target.offset) +
                              relocation.addend - symbol_offset;
      if (addend < INT64_MIN || addend > INT64_MAX)
        return fail("copy address relocation addend overflows");
      raw.r_addend = int64_t(addend);
      break;
    }
    case ct_kernel_copy_relocation_kind::original_symbol: {
      const auto found =
          original_symbols.find({relocation.symbol_table, relocation.symbol});
      if (found == original_symbols.end() ||
          regenerate.count(found->second.st_shndx))
        return fail("copy relocation imports an absent or regenerated symbol");
      const auto target = found->second.st_shndx;
      if (relocation.type != R_X86_64_NONE &&
          (object.section_header(relocation.source.section)->sh_flags &
           SHF_ALLOC) &&
          target < image.sections.size() &&
          (image.sections[target].flags & SHF_EXECINSTR) &&
          !image.sections[target].size)
        return fail("live relocation targets an empty executable section");
      symbol = relocation.symbol;
      break;
    }
    case ct_kernel_copy_relocation_kind::selector:
    case ct_kernel_copy_relocation_kind::perfetto_probe:
    case ct_kernel_copy_relocation_kind::full_probe: {
      if (copies.single_full &&
          relocation.kind != ct_kernel_copy_relocation_kind::full_probe)
        return fail("single-full code imports a level-selecting helper");
      const auto *header = object.section_header(relocation.source.section);
      const auto &bytes = *object.section_content(relocation.source.section);
      if (!(header->sh_flags & SHF_EXECINSTR) ||
          relocation.type != R_X86_64_PLT32 || relocation.addend != -4 ||
          relocation.source.offset < 2 ||
          relocation.source.offset > bytes.size() ||
          bytes.size() - relocation.source.offset < 4 ||
          bytes[relocation.source.offset - 1] != 0xe8)
        return fail("copy helper relocation does not identify a direct CALL");
      helper_fields.insert(
          {relocation.source.section, relocation.source.offset});
      symbol =
          imports[relocation.kind == ct_kernel_copy_relocation_kind::selector
                      ? 0
                  : relocation.kind ==
                          ct_kernel_copy_relocation_kind::perfetto_probe
                      ? 1
                      : 2];
      break;
    }
    default:
      return fail("unknown copied relocation target kind");
    }
    raw.r_info = ELF64_R_INFO(symbol, relocation.type);
    if (!object.add_relocation(relocation.source.section, symbol_table, raw,
                               error))
      return false;
  }
  uint32_t previous_section = 0;
  uint64_t previous_end = 0;
  for (const auto &[address, relocation] : relocation_fields) {
    const auto width = relocation_width(relocation->type);
    // add_relocation already validated the supported types and field bounds.
    if (address.first == previous_section && address.second < previous_end)
      return fail("overlapping copied relocation fields");
    previous_section = address.first;
    previous_end = address.second + width;
  }
  static_assert(sizeof(kctrace_program) == 96);
  static_assert(sizeof(kctrace_copy_probe) == 48);
  static_assert(sizeof(kctrace_gate_site) == 96);
  static_assert(sizeof(kctrace_policy_decisions) == 8);
  std::vector<kctrace_copy_probe> probes;
  std::vector<std::array<ct_kernel_copy_address, 2>> probe_addresses;
  for (const auto &site : copies.sites)
    for (unsigned level = copies.single_full ? 2 : 1; level < 3; ++level) {
      const auto &location = site.levels[level];
      if (!location.probe)
        continue;
      const auto &bytes = *object.section_content(location.operation.section);
      if (location.operation.offset < 7 ||
          bytes[location.operation.offset - 7] != 0x9c ||
          bytes[location.operation.offset - 6] != 0xe8 ||
          bytes[location.operation.offset - 1] != 0x9d)
        return fail("copied probe address does not match its saved-flags CALL");
      const auto field = std::make_pair(location.operation.section,
                                        location.operation.offset - 5);
      const auto relocation = relocation_fields.find(field);
      if (relocation == relocation_fields.end() ||
          relocation->second->kind !=
              (level == KCTRACE_LEVEL_FULL
                   ? ct_kernel_copy_relocation_kind::full_probe
                   : ct_kernel_copy_relocation_kind::perfetto_probe) ||
          !bound_helpers.insert(field).second)
        return fail("copied probe table differs from the helper CALL graph");
      kctrace_copy_probe record{};
      record.probe.site_id = site.id;
      record.probe.type = level == KCTRACE_LEVEL_FULL
                              ? KCTRACE_EVENT_INSTRUCTION_BEFORE
                              : KCTRACE_EVENT_BLOCK_POINT;
      if (level == KCTRACE_LEVEL_FULL && !capture_plans.empty())
        record.probe.capture_plan = capture_plans[site.id];
      record.function = policy.sites[site.id].function;
      record.path = policy.sites[site.id].path;
      record.level = level;
      auto return_pc = location.operation;
      --return_pc.offset;
      probes.push_back(record);
      probe_addresses.push_back({return_pc, location.operation});
    }
  std::vector<kctrace_gate_site> gates;
  std::set<std::pair<uint32_t, uint64_t>> gate_addresses;
  const auto &gate_template = ct_kernel_gate();
  for (const auto &boundary : copies.boundaries) {
    const bool indirect =
        boundary.kind == ct_kernel_copy_boundary_kind::indirect;
    const bool guarded =
        indirect ||
        boundary.kind == ct_kernel_copy_boundary_kind::unknown_control;
    if (!boundary.site_id || boundary.site_id >= original_sites.size() ||
        boundary.function != policy.sites[boundary.site_id].function ||
        boundary.path != policy.sites[boundary.site_id].path ||
        !address_valid(boundary.entry) || (guarded && !copies.single_full) ||
        (indirect ? boundary.target_register >= 16
                  : boundary.target_register != 0) ||
        boundary.selector_return.section != boundary.entry.section ||
        !gate_addresses
             .insert({boundary.selector_return.section,
                      boundary.selector_return.offset})
             .second)
      return fail("copy gate has an invalid original identity or return PC");
    const auto *header = object.section_header(boundary.entry.section);
    const auto &bytes = *object.section_content(boundary.entry.section);
    if (!(header->sh_flags & SHF_EXECINSTR))
      return fail("copy gate is not in an executable section");
    if (copies.single_full) {
      auto prefix = boundary.entry.offset;
      static constexpr unsigned char endbr[] = {0xf3, 0x0f, 0x1e, 0xfa};
      if (bytes.size() - prefix >= sizeof(endbr) &&
          !std::memcmp(bytes.data() + prefix, endbr, sizeof(endbr))) {
        if (boundary.kind != ct_kernel_copy_boundary_kind::entry &&
            boundary.kind != ct_kernel_copy_boundary_kind::scope)
          return fail("single-full nonlanding gate contains ENDBR");
        prefix += sizeof(endbr);
      }
      if (bytes.size() - prefix < 7 || bytes[prefix] != 0x9c ||
          bytes[prefix + 1] != 0xe8 || bytes[prefix + 6] != 0x9d ||
          boundary.selector_return.offset != prefix + 6)
        return fail("single-full boundary differs from its saved-flags CALL");
      const auto field = std::make_pair(boundary.entry.section, prefix + 2);
      const auto call = relocation_fields.find(field);
      if (call == relocation_fields.end() ||
          call->second->kind != ct_kernel_copy_relocation_kind::full_probe ||
          !bound_helpers.insert(field).second)
        return fail(
            "single-full boundary table differs from the helper CALL graph");
    } else {
      if (boundary.selector_return.offset !=
              boundary.entry.offset + gate_template.selector.next_pc ||
          gate_template.bytes.size() > bytes.size() - boundary.entry.offset)
        return fail("copy gate template exceeds its executable section");
      for (unsigned index = 0; index < gate_template.bytes.size(); ++index) {
        bool displacement =
            index >= gate_template.selector.displacement_offset &&
            index < gate_template.selector.next_pc;
        for (const auto &field : gate_template.continuations)
          displacement |=
              index >= field.displacement_offset && index < field.next_pc;
        if (!displacement &&
            bytes[boundary.entry.offset + index] != gate_template.bytes[index])
          return fail(
              "copy gate bytes differ from the direct-transfer template");
      }
      const auto selector = std::make_pair(
          boundary.entry.section,
          boundary.entry.offset + gate_template.selector.displacement_offset);
      const auto selection = relocation_fields.find(selector);
      if (selection == relocation_fields.end() ||
          selection->second->kind != ct_kernel_copy_relocation_kind::selector ||
          !bound_helpers.insert(selector).second)
        return fail("copy gate table differs from the selector CALL graph");
      for (unsigned level = 0; level < 3; ++level) {
        const auto field = relocation_fields.find(
            {boundary.entry.section,
             boundary.entry.offset +
                 gate_template.continuations[level].displacement_offset});
        const auto &continuation = boundary.continuations[level];
        if (field == relocation_fields.end() ||
            field->second->kind != ct_kernel_copy_relocation_kind::address ||
            field->second->type != R_X86_64_PC32 ||
            field->second->addend != -4 ||
            field->second->target.section != continuation.section ||
            field->second->target.offset != continuation.offset)
          return fail(
              "copy gate table differs from its direct continuation graph");
      }
    }
    kctrace_gate_site record{};
    record.site_id = boundary.site_id;
    record.related_site_id = boundary.related_site_id;
    record.function = boundary.function;
    record.path = boundary.path;
    switch (boundary.kind) {
    case ct_kernel_copy_boundary_kind::entry:
      record.kind = KCTRACE_BOUNDARY_ENTER;
      break;
    case ct_kernel_copy_boundary_kind::scope:
      record.kind = KCTRACE_BOUNDARY_SCOPE;
      break;
    case ct_kernel_copy_boundary_kind::call_before:
      record.kind = KCTRACE_BOUNDARY_CALL;
      break;
    case ct_kernel_copy_boundary_kind::call_after:
      record.kind = KCTRACE_BOUNDARY_AFTER_CALL;
      break;
    case ct_kernel_copy_boundary_kind::call_unpaired:
      record.kind = KCTRACE_BOUNDARY_CALL_UNPAIRED;
      break;
    case ct_kernel_copy_boundary_kind::return_:
      record.kind = KCTRACE_BOUNDARY_EXIT;
      break;
    case ct_kernel_copy_boundary_kind::tail:
      record.kind = KCTRACE_BOUNDARY_TAIL;
      break;
    case ct_kernel_copy_boundary_kind::indirect:
      record.kind = KCTRACE_GATE_INDIRECT_REG_BASE + boundary.target_register;
      break;
    case ct_kernel_copy_boundary_kind::unknown_control:
      record.kind = KCTRACE_GATE_UNKNOWN_CONTROL;
      break;
    default:
      return fail("unknown copied gate boundary kind");
    }
    if (!capture_plans.empty() &&
        (record.kind == KCTRACE_BOUNDARY_ENTER ||
         record.kind == KCTRACE_BOUNDARY_EXIT || guarded))
      record.capture_plan = capture_plans[boundary.site_id];
    gates.push_back(record);
  }
  if (helper_fields != bound_helpers)
    return fail("copy code has an unregistered helper CALL");
  const auto add_table = [&](const char *name, size_t entry_size,
                             const void *data, size_t count) {
    std::vector<unsigned char> bytes(entry_size * count);
    if (!bytes.empty())
      std::memcpy(bytes.data(), data, bytes.size());
    return object.add_section(std::string(".init.rodata.ctrace_") + name,
                              SHT_PROGBITS, SHF_ALLOC, 8, entry_size, 0, 0,
                              bytes, error);
  };
  const auto probes_section =
      add_table("copy_probes", sizeof(probes[0]), probes.data(), probes.size());
  const auto gates_section =
      add_table("gates", sizeof(gates[0]), gates.data(), gates.size());
  if (!probes_section || !gates_section)
    return false;
  std::vector<kctrace_policy_decisions> functions(policy.functions.size());
  std::vector<kctrace_policy_decisions> paths(policy.paths.size());
  for (size_t index = 0; index < functions.size(); ++index)
    for (unsigned flags = 0; flags < 8; ++flags) {
      const auto state = policy.functions[index].states[flags];
      if (state > 23 || (!index && state))
        return fail("invalid encoded function policy decision");
      functions[index].states[flags] = state;
    }
  for (size_t index = 0; index < paths.size(); ++index)
    for (unsigned flags = 0; flags < 8; ++flags) {
      const auto state = policy.paths[index].states[flags];
      if (state > 23 || (!index && state))
        return fail("invalid encoded inline policy decision");
      paths[index].states[flags] = state;
    }
  const auto functions_section = add_table("functions", sizeof(functions[0]),
                                           functions.data(), functions.size());
  const auto paths_section =
      add_table("paths", sizeof(paths[0]), paths.data(), paths.size());
  if (!functions_section || !paths_section)
    return false;
  kctrace_program program{};
  program.size = sizeof(program);
  program.abi = KCTRACE_ABI_VERSION;
  program.flags = program_flags;
  program.original_site_count = original_sites.size() - 1;
  program.probe_count = probes.size();
  program.gate_count = gates.size();
  program.function_count = functions.size();
  program.path_count = paths.size();
  const auto program_section =
      add_table("program", sizeof(program), &program, 1);
  if (!program_section || program_section >= SHN_LORESERVE)
    return false;
  Elf64_Sym descriptor{};
  descriptor.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
  descriptor.st_other = STV_HIDDEN;
  descriptor.st_shndx = program_section;
  descriptor.st_size = sizeof(program);
  uint32_t descriptor_index = 0;
  if (!object.append_symbol(symbol_table, "__ctrace_program", descriptor,
                            descriptor_index, error))
    return false;
  const auto count_section =
      add_table("count", sizeof(program.original_site_count),
                &program.original_site_count, 1);
  if (!count_section || count_section >= SHN_LORESERVE)
    return false;
  descriptor.st_shndx = count_section;
  descriptor.st_size = sizeof(program.original_site_count);
  if (!object.append_symbol(symbol_table, "__ctrace_site_count", descriptor,
                            descriptor_index, error))
    return false;
  const auto relocate_address = [&](uint32_t section, uint64_t offset,
                                    const ct_kernel_copy_address &target) {
    if (!address_valid(target)) {
      error = "immutable copy table contains an invalid target address";
      return false;
    }
    uint32_t symbol = 0;
    if (!anchor_for(target.section, symbol))
      return false;
    Elf64_Rela relocation{};
    relocation.r_offset = offset;
    relocation.r_info = ELF64_R_INFO(symbol, R_X86_64_64);
    relocation.r_addend = target.offset;
    return object.add_relocation(section, symbol_table, relocation, error);
  };
  if (interrupt) {
    static_assert(sizeof(kctrace_interrupt_proof) == 88);
    static_assert(sizeof(kctrace_interrupt_range) == 24);
    static_assert(sizeof(kctrace_interrupt_window) == 32);
    static_assert(sizeof(kctrace_interrupt_dispatch) == 24);
    const auto &proof = *interrupt;
    if (!(program_flags & KCTRACE_PROGRAM_WITHIN_FILTER) ||
        !proof.anchor_address || proof.build_id.empty() ||
        proof.image_digest.size() != 64 ||
        proof.relocation_digest.size() != 64 || proof.code.empty() ||
        proof.code.size() > copy_interrupt_range_limit ||
        proof.dispatches.empty() ||
        proof.dispatches.size() > copy_interrupt_dispatch_limit ||
        proof.windows.empty() ||
        proof.windows.size() > copy_interrupt_window_limit)
      return fail("missing bounded authenticated interrupt dispatch proof");
    std::vector<const ct_kernel_interrupt_code *> code;
    for (const auto &range : proof.code)
      code.push_back(&range);
    std::sort(code.begin(), code.end(),
              [](const auto *left, const auto *right) {
                return left->address < right->address;
              });
    std::vector<unsigned char> original;
    std::vector<kctrace_interrupt_range> ranges;
    std::vector<uint64_t> range_offsets;
    uint64_t end = 0;
    for (const auto *range : code) {
      if (!range->address || range->address < end || range->bytes.empty() ||
          range->bytes.size() > UINT64_MAX - range->address ||
          range->bytes.size() > copy_interrupt_byte_limit - original.size())
        return fail("invalid interrupt proof byte ranges");
      range_offsets.push_back(original.size());
      ranges.push_back({range->address, 0, range->bytes.size()});
      original.insert(original.end(), range->bytes.begin(), range->bytes.end());
      end = range->address + range->bytes.size();
    }
    const auto in_range = [&](uint64_t pc, uint64_t size) {
      return std::any_of(ranges.begin(), ranges.end(), [&](const auto &range) {
        return pc >= range.address && pc - range.address < range.size &&
               size <= range.size - (pc - range.address);
      });
    };
    std::vector<kctrace_interrupt_window> windows;
    end = 0;
    for (const auto &window : proof.windows) {
      if (!window.size || window.size > 8 || window.pc < end ||
          !in_range(window.pc, window.size) ||
          unsigned(window.kind) >
              unsigned(ct_kernel_interrupt_window_kind::relocate64))
        return fail("invalid interrupt proof patch windows");
      windows.push_back({window.pc, window.target, window.key,
                         uint8_t(window.kind), window.size, window.reg, 0, 0});
      end = window.pc + window.size;
    }
    std::vector<kctrace_interrupt_dispatch> dispatches;
    end = 0;
    const uint32_t saved_registers[] = {KCTRACE_REG_RBX, KCTRACE_REG_R13,
                                        KCTRACE_REG_RBP, KCTRACE_REG_RDX};
    for (const auto &dispatch : proof.dispatches) {
      if (dispatch.return_pc <= end || dispatch.call_pc >= dispatch.return_pc ||
          !in_range(dispatch.call_pc, dispatch.return_pc - dispatch.call_pc) ||
          unsigned(dispatch.kind) >
              unsigned(ct_kernel_interrupt_kind::tasklet) ||
          unsigned(dispatch.target) >
              unsigned(ct_kernel_interrupt_target::tasklet_token) ||
          unsigned(dispatch.reg) >= std::size(saved_registers) ||
          (dispatch.target != ct_kernel_interrupt_target::saved_register_word &&
           dispatch.word_offset))
        return fail("invalid interrupt proof callback identities");
      dispatches.push_back({dispatch.return_pc, uint32_t(dispatch.kind),
                            saved_registers[unsigned(dispatch.reg)],
                            dispatch.word_offset, uint32_t(dispatch.target)});
      end = dispatch.return_pc;
    }
    std::vector<uint64_t> entries(functions.size());
    std::vector<ct_kernel_copy_address> entry_addresses(functions.size());
    for (const auto &function : copies.functions) {
      if (entry_addresses[function.function].section)
        return fail("duplicate canonical interrupt callback identity");
      entry_addresses[function.function] = function.canonical;
    }
    for (size_t index = 1; index < entry_addresses.size(); ++index) {
      if (entry_addresses[index].section)
        continue;
      // __pfx_* symbols occupy policy IDs but describe compiler padding,
      // not callable functions. They have no canonical ENTER gate.
      const auto &function = policy.functions[index];
      if (!function.alias_count ||
          function.first_alias > policy.aliases.size() ||
          function.alias_count > policy.aliases.size() - function.first_alias)
        return fail("incomplete canonical interrupt callback identities");
      for (uint32_t alias = 0; alias < function.alias_count; ++alias) {
        const auto symbol = policy.aliases[function.first_alias + alias];
        if (symbol >= image.symbols.size() ||
            image.symbols[symbol].name.compare(0, 6, "__pfx_") != 0)
          return fail(
              "physical function lacks its canonical callback identity");
      }
    }
    const auto bytes_section =
        add_table("interrupt_bytes", 1, original.data(), original.size());
    const auto ranges_section = add_table("interrupt_ranges", sizeof(ranges[0]),
                                          ranges.data(), ranges.size());
    const auto windows_section =
        add_table("interrupt_windows", sizeof(windows[0]), windows.data(),
                  windows.size());
    const auto dispatches_section =
        add_table("interrupt_dispatches", sizeof(dispatches[0]),
                  dispatches.data(), dispatches.size());
    const auto entries_section =
        add_table("interrupt_entries", sizeof(entries[0]), entries.data(),
                  entries.size());
    kctrace_interrupt_proof record{};
    record.size = sizeof(record);
    record.anchor = proof.anchor_address;
    record.range_count = ranges.size();
    record.window_count = windows.size();
    record.dispatch_count = dispatches.size();
    record.entry_count = entries.size();
    const auto proof_section =
        add_table("interrupt_proof", sizeof(record), &record, 1);
    if (!bytes_section || !ranges_section || !windows_section ||
        !dispatches_section || !entries_section || !proof_section)
      return false;
    for (size_t index = 0; index < ranges.size(); ++index)
      if (!relocate_address(ranges_section,
                            index * sizeof(kctrace_interrupt_range) +
                                offsetof(kctrace_interrupt_range, bytes),
                            {bytes_section, range_offsets[index]}))
        return false;
    for (size_t index = 1; index < entry_addresses.size(); ++index)
      if (entry_addresses[index].section &&
          !relocate_address(entries_section, index * sizeof(uint64_t),
                            entry_addresses[index]))
        return false;
    for (const auto &field :
         {std::make_pair(offsetof(kctrace_interrupt_proof, ranges),
                         ranges_section),
          std::make_pair(offsetof(kctrace_interrupt_proof, windows),
                         windows_section),
          std::make_pair(offsetof(kctrace_interrupt_proof, dispatches),
                         dispatches_section),
          std::make_pair(offsetof(kctrace_interrupt_proof, entries),
                         entries_section)})
      if (!relocate_address(proof_section, field.first, {field.second, 0}))
        return false;
    if (!relocate_address(program_section,
                          offsetof(kctrace_program, interrupt_proof),
                          {proof_section, 0}))
      return false;
  }
  for (size_t index = 0; index < probes.size(); ++index) {
    const auto offset = index * sizeof(kctrace_copy_probe);
    if (!relocate_address(probes_section,
                          offset + offsetof(kctrace_copy_probe, probe) +
                              offsetof(kctrace_probe_site, return_pc),
                          probe_addresses[index][0]) ||
        !relocate_address(probes_section,
                          offset + offsetof(kctrace_copy_probe, probe) +
                              offsetof(kctrace_probe_site, pc),
                          probe_addresses[index][1]))
      return false;
  }
  for (size_t index = 0; index < gates.size(); ++index) {
    const auto offset = index * sizeof(kctrace_gate_site);
    const auto &boundary = copies.boundaries[index];
    if (!relocate_address(gates_section,
                          offset + offsetof(kctrace_gate_site, return_pc),
                          boundary.selector_return) ||
        !relocate_address(gates_section,
                          offset + offsetof(kctrace_gate_site, pc),
                          boundary.entry))
      return false;
    for (unsigned level = 0; level < 3; ++level) {
      const auto &continuation = boundary.continuations[level];
      if (copies.single_full) {
        if (continuation.section || continuation.offset)
          return fail("single-full boundary has a selector continuation");
      } else {
        const auto *header = object.section_header(continuation.section);
        if (!header || !(header->sh_flags & SHF_EXECINSTR) ||
            continuation.offset >= header->sh_size ||
            !relocate_address(gates_section,
                              offset +
                                  offsetof(kctrace_gate_site, continuations) +
                                  level * sizeof(__u64),
                              continuation))
          return fail("copy gate continuation is not executable");
      }
      const auto &return_pc = boundary.call_returns[level];
      const bool call =
          boundary.kind == ct_kernel_copy_boundary_kind::call_before ||
          boundary.kind == ct_kernel_copy_boundary_kind::call_after ||
          boundary.kind == ct_kernel_copy_boundary_kind::call_unpaired;
      if (call) {
        const uint64_t call_id =
            boundary.kind == ct_kernel_copy_boundary_kind::call_after
                ? boundary.related_site_id
                : boundary.site_id;
        if (!call_id || call_id >= original_sites.size() ||
            !original_sites[call_id] ||
            policy.sites[call_id].function != boundary.function)
          return fail("copy gate has no matching original CALL identity");
        const auto &location = original_sites[call_id]->levels[level];
        if (return_pc.section != location.operation.section ||
            return_pc.offset !=
                location.operation.offset + location.emitted_size)
          return fail(
              "copy gate return address differs from the original CALL end");
        if (copies.single_full &&
            (return_pc.section != boundary.call_returns[2].section ||
             return_pc.offset != boundary.call_returns[2].offset))
          return fail("single-full call returns do not alias one continuation");
        const auto *header = object.section_header(return_pc.section);
        if (!header || !(header->sh_flags & SHF_EXECINSTR) ||
            !relocate_address(gates_section,
                              offset +
                                  offsetof(kctrace_gate_site, call_returns) +
                                  level * sizeof(__u64),
                              return_pc))
          return fail("copy gate call-return address is not executable");
      } else if (return_pc.section || return_pc.offset) {
        return fail("noncall gate contains a call-return address");
      }
    }
  }
  for (const auto &field :
       {std::make_pair(offsetof(kctrace_program, probes), probes_section),
        std::make_pair(offsetof(kctrace_program, gates), gates_section),
        std::make_pair(offsetof(kctrace_program, functions), functions_section),
        std::make_pair(offsetof(kctrace_program, paths), paths_section)})
    if (!relocate_address(program_section, field.first, {field.second, 0}))
      return false;
  // RELA stores the entire addend in its record. The x86 module loader rejects
  // nonzero operands even when a normal ELF linker would ignore them. In
  // particular, the offline emitter has already filled some same-copy branch
  // displacements; clear those fields without changing the surrounding code.
  std::map<uint32_t, std::vector<std::pair<uint64_t, unsigned>>> operands;
  for (uint32_t section = 1; section < object.section_count(); ++section) {
    const auto *header = object.section_header(section);
    if (header->sh_type != SHT_RELA)
      continue;
    const auto &bytes = *object.section_content(section);
    for (size_t offset = 0; offset < bytes.size();
         offset += sizeof(Elf64_Rela)) {
      Elf64_Rela relocation;
      std::memcpy(&relocation, bytes.data() + offset, sizeof(relocation));
      const auto width = relocation_width(ELF64_R_TYPE(relocation.r_info));
      const auto *target = object.section_header(header->sh_info);
      if (width == UINT_MAX || !target ||
          relocation.r_offset > target->sh_size ||
          width > target->sh_size - relocation.r_offset)
        return fail("invalid relocation operand while clearing copy fields");
      if (width && target->sh_type != SHT_NOBITS)
        operands[header->sh_info].emplace_back(relocation.r_offset, width);
    }
  }
  for (const auto &[section, fields] : operands) {
    auto bytes = *object.section_content(section);
    for (const auto &[offset, width] : fields)
      std::fill_n(bytes.begin() + offset, width, 0);
    if (!object.replace_section(section, bytes, error))
      return false;
  }
  return object.serialize(output, error);
}
