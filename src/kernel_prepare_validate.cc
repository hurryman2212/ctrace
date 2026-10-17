#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/SHA256.h>

#include <elf.h>

#include "kernel_capture.h"
#include "kernel_copies.h"
#include "kernel_object.h"
#include "kernel_prepare_validate.h"

static constexpr uint64_t prepared_site_limit = 1000000;

static bool validate_parameter_data(
    const ct_kernel_image &image, const std::array<uint64_t, 4> &layout,
    const std::function<const unsigned char *(uint32_t, uint64_t, uint64_t)>
        &read,
    std::string &error) {
  const auto fail = [&](const std::string &reason) {
    error = "unsupported kernel parameter metadata: " + reason;
    return false;
  };
  if (!layout[0] || !layout[2] || layout[0] % 8 || layout[2] % 8 ||
      layout[1] % 8 || layout[3] % 8 || layout[1] > layout[0] ||
      8 > layout[0] - layout[1] || layout[3] > layout[2] ||
      8 > layout[2] - layout[3])
    return fail("invalid exact Kbuild layout");
  uint32_t parameters = 0;
  for (uint32_t index = 1; index < image.sections.size(); ++index)
    if (image.sections[index].name == "__param") {
      if (parameters)
        return fail("duplicate __param sections");
      parameters = index;
    }
  if (!parameters || !image.sections[parameters].size)
    return true;
  const auto &table = image.sections[parameters];
  if (table.type != SHT_PROGBITS || table.size % layout[0] ||
      (table.flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR)) != SHF_ALLOC)
    return fail("__param must contain complete immutable parameter entries");
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  for (const auto &symbol : image.symbols)
    if (!symbols.emplace(std::make_pair(symbol.table, symbol.index), &symbol)
             .second)
      return fail("duplicate symbol identity");
  std::map<uint32_t, std::map<uint64_t, const ct_kernel_relocation *>> fields;
  for (const auto &relocation : image.relocations) {
    if (relocation.type == R_X86_64_NONE)
      continue;
    if (!fields[relocation.section]
             .emplace(relocation.offset, &relocation)
             .second)
      return fail("duplicate relocation field");
  }
  const auto pointer = [&](uint32_t section, uint64_t offset,
                           const ct_kernel_relocation *&relocation) {
    relocation = nullptr;
    const auto *bytes = read(section, offset, 8);
    if (!bytes)
      return fail("pointer exceeds owned storage");
    uint64_t raw = 0;
    std::memcpy(&raw, bytes, sizeof(raw));
    if (raw)
      return fail("unresolved nonzero pointer bytes");
    const auto &references = fields[section];
    auto next = references.lower_bound(offset);
    if (next != references.begin()) {
      const auto &previous = *std::prev(next)->second;
      const uint64_t width =
          previous.type == R_X86_64_64 || previous.type == R_X86_64_PC64   ? 8
          : previous.type == R_X86_64_8 || previous.type == R_X86_64_PC8   ? 1
          : previous.type == R_X86_64_16 || previous.type == R_X86_64_PC16 ? 2
                                                                           : 4;
      if (offset - previous.offset < width)
        return fail("overlapping pointer relocation");
    }
    if (next == references.end() || next->first >= offset + 8)
      return true;
    relocation = next->second;
    if (next->first != offset || relocation->type != R_X86_64_64 ||
        (++next != references.end() && next->first < offset + 8))
      return fail("pointer needs one exact R_X86_64_64 relocation");
    return true;
  };
  const auto imported = [](const ct_kernel_symbol &symbol,
                           const ct_kernel_relocation &relocation) {
    return symbol.section == SHN_UNDEF && !symbol.name.empty() &&
           symbol.binding == STB_GLOBAL && !symbol.offset && !relocation.addend;
  };
  for (uint64_t entry = 0; entry < table.size; entry += layout[0]) {
    const ct_kernel_relocation *ops = nullptr;
    if (!pointer(parameters, entry + layout[1], ops))
      return false;
    if (!ops)
      return fail("parameter ops is NULL or has no relocation");
    const auto reference = symbols.find({ops->symbol_table, ops->symbol});
    if (reference == symbols.end())
      return fail("parameter ops symbol is missing");
    const auto &symbol = *reference->second;
    // Built-in/imported ops are not module-owned callbacks. This does not
    // claim to prove arbitrary behavior inside external callback code.
    if (imported(symbol, *ops) &&
        (symbol.type == STT_NOTYPE || symbol.type == STT_OBJECT))
      continue;
    if (!symbol.section || symbol.section >= SHN_LORESERVE ||
        symbol.section >= image.sections.size())
      return fail("parameter ops has an unresolved target");
    const auto &storage = image.sections[symbol.section];
    const __int128 address = __int128(symbol.offset) + ops->addend;
    if (storage.type != SHT_PROGBITS ||
        (storage.flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR)) !=
            SHF_ALLOC ||
        storage.name.rfind(".init", 0) == 0 || address < 0 ||
        address + layout[2] > storage.size)
      return fail(
          "module-owned parameter ops is mutable, temporary, or unbounded");
    const ct_kernel_relocation *release = nullptr;
    if (!pointer(symbol.section, uint64_t(address) + layout[3], release))
      return false;
    if (!release)
      continue; // Immutable ops with a literal NULL free member.
    const auto target = symbols.find({release->symbol_table, release->symbol});
    if (target == symbols.end())
      return fail("parameter free symbol is missing");
    if (imported(*target->second, *release) &&
        (target->second->type == STT_NOTYPE ||
         target->second->type == STT_FUNC))
      continue;
    if (target->second->section && target->second->section < SHN_LORESERVE &&
        target->second->section < image.sections.size() &&
        (image.sections[target->second->section].flags & SHF_EXECINSTR))
      return fail("module-owned parameter free callback runs after GOING: " +
                  target->second->name);
    return fail("parameter free target cannot be proven NULL or external");
  }
  return true;
}

bool ct_kernel_validate_parameters(const ct_kernel_image &image,
                                   const std::array<uint64_t, 4> &layout,
                                   std::string &error) {
  error.clear();
  return validate_parameter_data(
      image, layout,
      [&](uint32_t section, uint64_t offset, uint64_t size) {
        if (!section || section >= image.sections.size())
          return static_cast<const unsigned char *>(nullptr);
        const auto &header = image.sections[section];
        if (offset > header.size || size > header.size - offset ||
            header.offset > image.bytes.size() ||
            header.size > image.bytes.size() - header.offset)
          return static_cast<const unsigned char *>(nullptr);
        return image.bytes.data() + header.offset + offset;
      },
      error);
}

static bool validate_allocated_relocation_fields(const ct_kernel_object &object,
                                                 std::string &error) {
  for (uint32_t section = 1; section < object.section_count(); ++section) {
    const auto &header = *object.section_header(section);
    if (header.sh_type != SHT_RELA)
      continue;
    const auto *target = object.section_header(header.sh_info);
    if (!target || !(target->sh_flags & SHF_ALLOC))
      continue;
    const auto &relocations = *object.section_content(section);
    const auto &contents = *object.section_content(header.sh_info);
    for (size_t index = 0; index < relocations.size();
         index += sizeof(Elf64_Rela)) {
      Elf64_Rela relocation;
      std::memcpy(&relocation, relocations.data() + index, sizeof(relocation));
      const uint32_t type = ELF64_R_TYPE(relocation.r_info);
      uint64_t width = 0;
      switch (type) {
      case R_X86_64_NONE:
        continue;
      case R_X86_64_64:
      case R_X86_64_PC64:
        width = 8;
        break;
      case R_X86_64_PC32:
      case R_X86_64_PLT32:
      case R_X86_64_32:
      case R_X86_64_32S:
        width = 4;
        break;
      default:
        error = "unsupported allocated kernel relocation type " +
                std::to_string(type) + " in " +
                object.section_name(header.sh_info);
        return false;
      }
      if (relocation.r_offset > target->sh_size ||
          width > target->sh_size - relocation.r_offset) {
        error = "allocated kernel relocation exceeds its target section";
        return false;
      }
      if (target->sh_type == SHT_NOBITS)
        continue;
      // RELA carries its addend in the relocation record. Linux's x86 module
      // loader rejects prepopulated operands even when the symbol/addend pair
      // is correct; masking these bytes for code comparison is insufficient.
      if (relocation.r_offset > contents.size() ||
          width > contents.size() - relocation.r_offset ||
          std::any_of(contents.begin() + relocation.r_offset,
                      contents.begin() + relocation.r_offset + width,
                      [](unsigned char byte) { return byte != 0; })) {
        error = "nonzero allocated kernel RELA field in " +
                object.section_name(header.sh_info) + " at offset " +
                std::to_string(relocation.r_offset) + " (type " +
                std::to_string(type) + ")";
        return false;
      }
    }
  }
  return true;
}

static bool validate_copy_program(const ct_kernel_image &original,
                                  const ct_kernel_prepared &prepared,
                                  const ct_kernel_copies &copies,
                                  const ct_kernel_object &actual,
                                  const ct_kernel_image &graph,
                                  std::string &error) {
  const auto fail = [&](const std::string &reason) {
    error = "invalid prepared kernel copies: " + reason;
    return false;
  };
  if (!validate_allocated_relocation_fields(actual, error))
    return false;
  std::vector<uint32_t> capture_plans(prepared.probe_count + 1);
  for (size_t index = 1; index < capture_plans.size(); ++index)
    capture_plans[index] = prepared.values->sites[index].capture_plan;
  ct_kernel_image expected_image;
  if (!ct_kernel_materialize_copies(original, prepared.trace->prepared_policy(),
                                    copies, prepared.program_flags,
                                    capture_plans, expected_image.bytes, error,
                                    prepared.interrupt.get()))
    return false;
  ct_kernel_object expected(expected_image);
  expected_image.bytes.clear();
  if (!expected.valid(error))
    return false;
  uint32_t expected_table = 0;
  for (uint32_t section = 1; section < expected.section_count(); ++section)
    if (expected.section_header(section)->sh_type == SHT_SYMTAB)
      expected_table = section;
  if (!expected_table)
    return fail("expected symbol table is missing");
  const auto &expected_strings = *expected.section_content(
      expected.section_header(expected_table)->sh_link);
  const auto &symbol_bytes = *expected.section_content(expected_table);
  std::vector<Elf64_Sym> expected_symbols(symbol_bytes.size() /
                                          sizeof(Elf64_Sym));
  std::memcpy(expected_symbols.data(), symbol_bytes.data(),
              symbol_bytes.size());
  const auto symbol_name = [&](const Elf64_Sym &symbol) {
    return std::string(reinterpret_cast<const char *>(expected_strings.data() +
                                                      symbol.st_name));
  };
  std::map<std::string, std::vector<const ct_kernel_symbol *>> names;
  std::map<std::string, uint32_t> sections;
  for (const auto &symbol : graph.symbols)
    if (!symbol.name.empty())
      names[symbol.name].push_back(&symbol);
  for (uint32_t section = 1; section < graph.sections.size(); ++section)
    sections.emplace(graph.sections[section].name, section);
  const auto named = [&](const std::string &name) -> const ct_kernel_symbol * {
    const auto found = names.find(name);
    return found != names.end() && found->second.size() == 1 ? found->second[0]
                                                             : nullptr;
  };
  std::map<uint32_t, std::pair<uint32_t, uint64_t>> mapping;
  const auto mapped = [&](uint32_t section) -> bool {
    if (mapping.count(section))
      return true;
    const auto *header = expected.section_header(section);
    if (!section || !header)
      return false;
    const auto name = expected.section_name(section);
    uint32_t destination = 0;
    uint64_t base = 0;
    if (const auto *anchor =
            named("__ctrace_copy_anchor_" + std::to_string(section))) {
      if (!anchor->section || anchor->section >= graph.sections.size() ||
          anchor->type != STT_NOTYPE || anchor->binding != STB_GLOBAL ||
          anchor->size)
        return false;
      destination = anchor->section;
      base = anchor->offset;
    } else {
      const auto found_section = sections.find(name);
      if (found_section == sections.end())
        return false;
      destination = found_section->second;
      bool found = false;
      for (const auto &symbol : expected_symbols) {
        if (symbol.st_shndx != section || !symbol.st_name ||
            ELF64_ST_TYPE(symbol.st_info) == STT_SECTION)
          continue;
        const auto *current = named(symbol_name(symbol));
        if (!current)
          continue;
        if (current->section != destination ||
            current->offset < symbol.st_value)
          return false;
        const uint64_t candidate = current->offset - symbol.st_value;
        if (found && base != candidate)
          return false;
        base = candidate;
        found = true;
      }
    }
    const auto &target = graph.sections[destination];
    const bool merged = (target.name == ".text" || target.name == ".data" ||
                         target.name == ".bss" || target.name == ".rodata") &&
                        name.rfind(target.name + ".", 0) == 0;
    if (target.name != name && !merged)
      return false;
    if (header->sh_type != target.type || header->sh_flags != target.flags ||
        target.alignment < header->sh_addralign || base > target.size ||
        header->sh_size > target.size - base)
      return false;
    // module.lds coalesces .text.* bodies but retains immutable table names.
    if ((!merged && name.find(".ctrace.") != std::string::npos) ||
        name.rfind(".init.rodata.ctrace_", 0) == 0)
      if (base || header->sh_size != target.size)
        return false;
    // Distinct executable copies must still occupy distinct byte ranges after
    // linker section merging; anchors cannot alias an already verified copy.
    if (header->sh_flags & SHF_EXECINSTR)
      for (const auto &[other, location] : mapping) {
        const auto &other_header = *expected.section_header(other);
        if (location.first == destination &&
            (other_header.sh_flags & SHF_EXECINSTR) &&
            base < location.second + other_header.sh_size &&
            location.second < base + header->sh_size)
          return false;
      }
    mapping.emplace(section, std::make_pair(destination, base));
    return true;
  };
  std::map<uint32_t, std::map<uint64_t, Elf64_Rela>> expected_relocations;
  for (uint32_t section = 1; section < expected.section_count(); ++section) {
    const auto &header = *expected.section_header(section);
    if (header.sh_type != SHT_RELA)
      continue;
    const auto &bytes = *expected.section_content(section);
    for (size_t index = 0; index < bytes.size(); index += sizeof(Elf64_Rela)) {
      Elf64_Rela relocation;
      std::memcpy(&relocation, bytes.data() + index, sizeof(relocation));
      if (ELF64_R_TYPE(relocation.r_info) != R_X86_64_NONE)
        expected_relocations[header.sh_info].emplace(relocation.r_offset,
                                                     relocation);
    }
  }
  std::map<uint32_t, std::map<uint64_t, const ct_kernel_relocation *>>
      actual_relocations;
  for (const auto &relocation : graph.relocations)
    if (relocation.type != R_X86_64_NONE)
      actual_relocations[relocation.section].emplace(relocation.offset,
                                                     &relocation);
  const std::set<uint32_t> regenerated(copies.regenerate_sections.begin(),
                                       copies.regenerate_sections.end());
  std::set<std::pair<uint32_t, uint64_t>> helper_calls;
  for (uint32_t section = 1; section < expected.section_count(); ++section) {
    const auto &header = *expected.section_header(section);
    const auto name = expected.section_name(section);
    if (!(header.sh_flags & SHF_ALLOC) || regenerated.count(section) ||
        name.rfind(".discard", 0) == 0 || name == ".modinfo" ||
        name == "__versions" || name == ".gnu.linkonce.this_module")
      continue;
    if (name == ".note.gnu.property" && !sections.count(name)) {
      // GNU ld intersects feature-AND notes across inputs. Linking the
      // generated annotations object consumes this exact compiler IBT note;
      // instruction bytes and the regenerated IBT/ORC graph remain checked.
      static constexpr unsigned char ibt_note[] = {
          4, 0, 0, 0,    16, 0, 0, 0, 5, 0, 0, 0, 'G', 'N', 'U', 0,
          2, 0, 0, 0xc0, 4,  0, 0, 0, 1, 0, 0, 0, 0,   0,   0,   0};
      const auto &bytes = *expected.section_content(section);
      if (header.sh_type != SHT_NOTE || bytes.size() != sizeof(ibt_note) ||
          std::memcmp(bytes.data(), ibt_note, sizeof(ibt_note)))
        return fail("linker removed an unsupported GNU property note");
      continue;
    }
    if (!mapped(section))
      return fail("section identity or extent changed: " + name);
    const auto [destination, base] = mapping.at(section);
    const auto &references = actual_relocations[destination];
    const auto &wanted = expected_relocations[section];
    std::vector<unsigned char> mask(header.sh_size);
    for (const auto &[offset, relocation] : wanted) {
      const uint32_t type = ELF64_R_TYPE(relocation.r_info);
      const uint64_t width = type == R_X86_64_64 || type == R_X86_64_PC64   ? 8
                             : type == R_X86_64_8 || type == R_X86_64_PC8   ? 1
                             : type == R_X86_64_16 || type == R_X86_64_PC16 ? 2
                                                                            : 4;
      if (offset > mask.size() || width > mask.size() - offset)
        return fail("expected relocation exceeds its section");
      std::fill_n(mask.begin() + offset, width, 1);
      const auto found = references.find(base + offset);
      if (found == references.end() || found->second->type != type)
        return fail("missing or altered copied relocation: " + name);
      const auto &current = *found->second;
      if (current.symbol >= graph.symbols.size())
        return fail("copied relocation has an invalid symbol");
      const auto &target = expected_symbols[ELF64_R_SYM(relocation.r_info)];
      const auto &actual_target = graph.symbols[current.symbol];
      if (target.st_shndx == SHN_UNDEF) {
        const auto target_name = symbol_name(target);
        if (actual_target.section != SHN_UNDEF ||
            actual_target.name != target_name ||
            actual_target.binding != ELF64_ST_BIND(target.st_info) ||
            current.addend != relocation.r_addend)
          return fail("copied import target changed: " + target_name);
        if (target_name == "kctrace_select" || target_name == "kctrace_probe" ||
            target_name == "kctrace_perfetto_probe")
          helper_calls.emplace(destination, base + offset);
      } else if (target.st_shndx == SHN_ABS) {
        if (actual_target.section != SHN_ABS ||
            __int128(actual_target.offset) + current.addend !=
                __int128(target.st_value) + relocation.r_addend)
          return fail("absolute copied relocation changed");
      } else {
        if (!mapped(target.st_shndx))
          return fail("copied relocation target has no matching section: " +
                      name + " -> " + expected.section_name(target.st_shndx));
        const auto [target_section, target_base] = mapping.at(target.st_shndx);
        if (actual_target.section != target_section ||
            __int128(actual_target.offset) + current.addend !=
                __int128(target_base) + target.st_value + relocation.r_addend)
          return fail("copied relocation target changed: " + name);
      }
    }
    const auto first = references.lower_bound(base),
               last = references.lower_bound(base + header.sh_size);
    if (size_t(std::distance(first, last)) != wanted.size())
      return fail("extra relocation inside copied section: " + name);
    if (header.sh_type == SHT_NOBITS)
      continue;
    const auto &source_bytes = *expected.section_content(section);
    const auto &final_bytes = *actual.section_content(destination);
    for (uint64_t offset = 0; offset < header.sh_size; ++offset)
      if (!mask[offset] && source_bytes[offset] != final_bytes[base + offset])
        return fail("copied bytes changed outside relocation fields: " + name);
  }
  for (const auto &symbol : expected_symbols) {
    if (!symbol.st_name || !mapping.count(symbol.st_shndx) ||
        ELF64_ST_TYPE(symbol.st_info) == STT_SECTION)
      continue;
    const auto name = symbol_name(symbol);
    // Preparation explicitly strips these STT_FUNC prefix records before
    // selected-kernel objtool regenerates them. The code itself is checked.
    if (name.rfind("__pfx_", 0) == 0 &&
        ELF64_ST_TYPE(symbol.st_info) == STT_FUNC)
      continue;
    const auto *current = named(name);
    // Local duplicate names are checked through their exact relocation graph.
    if (!current && ELF64_ST_BIND(symbol.st_info) == STB_LOCAL)
      continue;
    const auto [section, base] = mapping.at(symbol.st_shndx);
    if (!current || current->section != section ||
        current->offset != base + symbol.st_value ||
        current->size != symbol.st_size ||
        current->type != ELF64_ST_TYPE(symbol.st_info) ||
        current->binding != ELF64_ST_BIND(symbol.st_info))
      return fail("copied symbol identity changed: " + name);
  }
  for (const auto &plan : *prepared.captures)
    for (const auto &slot : plan.slots) {
      if (slot.capture.kind != KCTRACE_CAPTURE_OBJECT)
        continue;
      if (!mapped(slot.section))
        return fail("capture data section cannot be normalized");
      const auto *anchor =
          named("__ctrace_data_anchor_" + std::to_string(slot.section));
      const auto [section, base] = mapping.at(slot.section);
      if (!anchor || anchor->section != section || anchor->offset != base)
        return fail("capture anchor differs from the verified copied graph");
    }
  for (const auto &relocation : graph.relocations) {
    const auto &target = graph.symbols[relocation.symbol];
    if ((target.name == "kctrace_select" || target.name == "kctrace_probe" ||
         target.name == "kctrace_perfetto_probe") &&
        !helper_calls.count({relocation.section, relocation.offset}))
      return fail("unregistered copied runtime reference");
  }
  return true;
}

bool ct_kernel_validate_prepared(
    const ct_kernel_image &original, ct_kernel_prepared &prepared,
    const std::array<uint64_t, 3> &layout,
    const std::array<uint64_t, 4> &parameter_layout, std::string &error,
    const ct_kernel_copies *copies) {
  error.clear();
  if (!ct_kernel_validate_parameters(original, parameter_layout, error))
    return false;
  const auto fail = [&](const std::string &reason) {
    error = "invalid prepared kernel module: " + reason;
    return false;
  };
  if (prepared.level_selection != (copies && !copies->single_full) ||
      bool(prepared.program_flags & KCTRACE_PROGRAM_WITHIN_INTR) !=
          bool(prepared.interrupt) ||
      (copies && (!prepared.trace ||
                  bool(prepared.program_flags & KCTRACE_PROGRAM_SINGLE_FULL) !=
                      copies->single_full)) ||
      prepared.module_name != original.name ||
      prepared.original_digest != (original.input_digest.empty()
                                       ? original.digest
                                       : original.input_digest) ||
      !prepared.probe_count || prepared.probe_count > prepared_site_limit ||
      prepared.sites.size() > prepared_site_limit || !layout[0] ||
      !prepared.values ||
      prepared.values->sites.size() <= prepared.probe_count ||
      !prepared.captures || prepared.captures->empty() ||
      prepared.captures->size() > 65537 || layout[1] > layout[0] ||
      sizeof(uint64_t) > layout[0] - layout[1] || layout[2] > layout[0] ||
      sizeof(uint64_t) > layout[0] - layout[2] || layout[1] == layout[2])
    return fail("identity, ABI layout or site count mismatch");
  if (prepared.values->sites[0].capture_plan ||
      std::any_of(prepared.values->sites.begin() + 1,
                  prepared.values->sites.end(), [&](const auto &site) {
                    return site.capture_plan >= prepared.captures->size();
                  }))
    return fail("original site references an unknown capture plan");
  for (const auto &symbol : original.symbols)
    if (symbol.name.rfind("kctrace_", 0) == 0 ||
        symbol.name.rfind("__ctrace_", 0) == 0 ||
        symbol.name.rfind("__pfx___ctrace_", 0) == 0)
      return fail("original object uses reserved runtime symbols");

  // Borrow the payload during construction instead of making another full
  // input copy. The object owns its bounded section snapshots afterwards.
  ct_kernel_image snapshot;
  snapshot.bytes.swap(prepared.bytes);
  ct_kernel_object object(snapshot);
  snapshot.bytes.swap(prepared.bytes);
  if (!object.valid(error))
    return false;
  {
    std::vector<unsigned char> checked;
    if (!object.serialize(checked, error))
      return false;
  }
  if (!validate_allocated_relocation_fields(object, error))
    return false;
  const auto digest =
      llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(prepared.bytes));
  std::string actual_digest;
  for (unsigned char byte : digest) {
    actual_digest += "0123456789abcdef"[byte >> 4];
    actual_digest += "0123456789abcdef"[byte & 15];
  }
  if (!prepared.template_digest.empty() &&
      prepared.template_digest != actual_digest)
    return fail("template content digest mismatch");

  std::map<std::string, uint32_t> sections;
  uint32_t symbol_table = 0;
  for (uint32_t index = 1; index < object.section_count(); ++index) {
    const auto &header = *object.section_header(index);
    const std::string name = object.section_name(index);
    const bool unique = sections.emplace(name, index).second;
    if (!unique && (header.sh_flags & SHF_ALLOC))
      return fail("duplicate allocated section " + name);
    if ((header.sh_flags & (SHF_WRITE | SHF_EXECINSTR)) ==
        (SHF_WRITE | SHF_EXECINSTR))
      return fail("writable executable section " + name);
    if (header.sh_type == SHT_SYMTAB) {
      if (symbol_table)
        return fail("multiple symbol tables");
      symbol_table = index;
    }
  }
  if (!symbol_table)
    return fail("missing symbol table");
  constexpr std::string_view signature = "~Module signature appended~\n";
  if (prepared.bytes.size() >= signature.size() &&
      std::memcmp(prepared.bytes.data() + prepared.bytes.size() -
                      signature.size(),
                  signature.data(), signature.size()) == 0)
    return fail("unsigned template contains an appended signature");
  const auto info_section = sections.find(".modinfo");
  if (info_section == sections.end())
    return fail("missing module metadata");
  const auto &information = *object.section_content(info_section->second);
  std::map<std::string, std::string> metadata;
  for (size_t offset = 0; offset < information.size();) {
    const char *begin =
        reinterpret_cast<const char *>(information.data() + offset);
    const char *end = static_cast<const char *>(
        std::memchr(begin, 0, information.size() - offset));
    if (!end)
      return fail("unterminated module metadata");
    std::string_view entry(begin, end - begin);
    offset += entry.size() + 1;
    const auto equals = entry.find('=');
    if (equals == std::string_view::npos)
      continue;
    const std::string key(entry.substr(0, equals)),
        value(entry.substr(equals + 1));
    if (key != "name" && key != "vermagic" && key != "license")
      continue;
    const auto inserted = metadata.emplace(key, value);
    if (!inserted.second && inserted.first->second != value)
      return fail("conflicting module metadata");
  }
  if (metadata["name"] != original.name ||
      metadata["vermagic"] != original.vermagic ||
      metadata["license"] != original.license)
    return fail("module metadata differs from the original");
  unsigned build_ids = 0;
  for (uint32_t index = 1; index < object.section_count(); ++index) {
    if (object.section_header(index)->sh_type != SHT_NOTE)
      continue;
    const auto &notes = *object.section_content(index);
    for (size_t offset = 0; offset < notes.size();) {
      if (notes.size() - offset < sizeof(Elf64_Nhdr))
        return fail("truncated ELF note header");
      Elf64_Nhdr note;
      std::memcpy(&note, notes.data() + offset, sizeof(note));
      offset += sizeof(note);
      const uint64_t name_size = (uint64_t(note.n_namesz) + 3) & ~UINT64_C(3);
      const uint64_t descriptor_size =
          (uint64_t(note.n_descsz) + 3) & ~UINT64_C(3);
      if (name_size > notes.size() - offset ||
          descriptor_size > notes.size() - offset - name_size)
        return fail("ELF note exceeds its section");
      if (note.n_namesz == 4 && !std::memcmp(notes.data() + offset, "GNU", 4) &&
          note.n_type == NT_GNU_BUILD_ID) {
        if (!note.n_descsz || ++build_ids != 1)
          return fail("missing or duplicated template GNU build ID");
      }
      offset += name_size + descriptor_size;
    }
  }
  if (build_ids != 1)
    return fail("template GNU build ID is missing");

  const auto &table_header = *object.section_header(symbol_table);
  const auto &table = *object.section_content(symbol_table);
  const auto &strings = *object.section_content(table_header.sh_link);
  std::vector<Elf64_Sym> symbols(table.size() / sizeof(Elf64_Sym));
  std::map<std::string, std::vector<size_t>> named;
  for (size_t index = 0; index < symbols.size(); ++index) {
    std::memcpy(&symbols[index], table.data() + index * sizeof(Elf64_Sym),
                sizeof(Elf64_Sym));
    const char *name =
        reinterpret_cast<const char *>(strings.data() + symbols[index].st_name);
    if (*name)
      named[name].push_back(index);
  }
  const auto unique_symbol = [&](const std::string &name) -> const Elf64_Sym * {
    const auto found = named.find(name);
    return found != named.end() && found->second.size() == 1
               ? &symbols[found->second.front()]
               : nullptr;
  };
  std::set<std::string> runtime_names{"kctrace_initialized", "kctrace_probe"};
  if (copies && !copies->single_full) {
    runtime_names.insert("kctrace_select");
    runtime_names.insert("kctrace_perfetto_probe");
  }
  for (const auto &name : runtime_names) {
    const auto *symbol = unique_symbol(name);
    if (!symbol || symbol->st_shndx != SHN_UNDEF || symbol->st_value ||
        symbol->st_size || ELF64_ST_BIND(symbol->st_info) != STB_GLOBAL ||
        (ELF64_ST_TYPE(symbol->st_info) != STT_NOTYPE &&
         ELF64_ST_TYPE(symbol->st_info) != STT_FUNC))
      return fail("runtime import is missing or locally defined: " + name);
  }
  for (const auto &[name, entries] : named)
    if (name.rfind("kctrace_", 0) == 0 && !runtime_names.count(name))
      return fail("unexpected runtime symbol " + name);

  struct Relocation {
    Elf64_Rela value;
    uint64_t width;
  };
  std::map<uint32_t, std::map<uint64_t, Relocation>> relocations;
  for (uint32_t index = 1; index < object.section_count(); ++index) {
    const auto &header = *object.section_header(index);
    if (header.sh_type != SHT_RELA)
      continue;
    if (header.sh_link != symbol_table)
      return fail("relocation uses a different symbol table");
    const auto &bytes = *object.section_content(index);
    auto &fields = relocations[header.sh_info];
    for (size_t offset = 0; offset < bytes.size();
         offset += sizeof(Elf64_Rela)) {
      Elf64_Rela relocation;
      std::memcpy(&relocation, bytes.data() + offset, sizeof(relocation));
      const uint32_t type = ELF64_R_TYPE(relocation.r_info);
      const uint64_t width = type == R_X86_64_NONE                          ? 0
                             : type == R_X86_64_64 || type == R_X86_64_PC64 ? 8
                             : type == R_X86_64_8 || type == R_X86_64_PC8   ? 1
                             : type == R_X86_64_16 || type == R_X86_64_PC16 ? 2
                                                                            : 4;
      if (!width)
        continue;
      if (!fields.emplace(relocation.r_offset, Relocation{relocation, width})
               .second)
        return fail("duplicate relocation field");
    }
  }
  for (const auto &[section, fields] : relocations) {
    uint64_t end = 0;
    for (const auto &[offset, relocation] : fields) {
      if (offset < end)
        return fail("overlapping relocation fields in " +
                    object.section_name(section));
      end = offset + relocation.width;
    }
  }
  // Repeat the parameter restriction on the final linked graph. A cache entry
  // with valid outer checksums must not introduce a module-local free callback
  // or substitute mutable ops storage after the original preflight passed.
  ct_kernel_image parameter_graph;
  parameter_graph.sections.resize(object.section_count());
  for (uint32_t index = 1; index < object.section_count(); ++index) {
    const auto &header = *object.section_header(index);
    parameter_graph.sections[index] = {object.section_name(index),
                                       header.sh_type,
                                       header.sh_link,
                                       header.sh_info,
                                       header.sh_flags,
                                       header.sh_offset,
                                       header.sh_size,
                                       header.sh_addralign,
                                       header.sh_entsize};
  }
  for (uint32_t index = 0; index < symbols.size(); ++index) {
    const auto &symbol = symbols[index];
    parameter_graph.symbols.push_back(
        {reinterpret_cast<const char *>(strings.data() + symbol.st_name),
         symbol_table, index, symbol.st_shndx, symbol.st_value, symbol.st_size,
         uint8_t(ELF64_ST_TYPE(symbol.st_info)),
         uint8_t(ELF64_ST_BIND(symbol.st_info))});
  }
  for (const auto &[section, fields] : relocations)
    for (const auto &[offset, relocation] : fields)
      parameter_graph.relocations.push_back(
          {section, symbol_table,
           uint32_t(ELF64_R_SYM(relocation.value.r_info)),
           uint32_t(ELF64_R_TYPE(relocation.value.r_info)), offset,
           relocation.value.r_addend});
  if (!validate_parameter_data(
          parameter_graph, parameter_layout,
          [&](uint32_t section, uint64_t offset, uint64_t size) {
            const auto *bytes = object.section_content(section);
            return bytes && offset <= bytes->size() &&
                           size <= bytes->size() - offset
                       ? bytes->data() + offset
                       : nullptr;
          },
          error))
    return false;
  const auto address = [&](uint32_t section, uint64_t field, uint32_t type,
                           uint32_t &target, uint64_t &offset) {
    const auto found = relocations.find(section);
    if (found == relocations.end())
      return false;
    const auto entry = found->second.find(field);
    if (entry == found->second.end() ||
        ELF64_R_TYPE(entry->second.value.r_info) != type)
      return false;
    const auto &relocation = entry->second.value;
    const auto &symbol = symbols[ELF64_R_SYM(relocation.r_info)];
    if (symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= SHN_LORESERVE)
      return false;
    const __int128 position = __int128(symbol.st_value) + relocation.r_addend;
    const auto *header = object.section_header(symbol.st_shndx);
    if (!header || position < 0 || position > header->sh_size)
      return false;
    target = symbol.st_shndx;
    offset = uint64_t(position);
    return true;
  };
  const auto readonly_object = [&](const std::string &name,
                                   const std::string &section_name,
                                   uint64_t size) -> const Elf64_Sym * {
    const auto *symbol = unique_symbol(name);
    if (!symbol || ELF64_ST_TYPE(symbol->st_info) != STT_OBJECT ||
        symbol->st_value || symbol->st_size != size ||
        symbol->st_shndx == SHN_UNDEF || symbol->st_shndx >= SHN_LORESERVE)
      return nullptr;
    const auto *header = object.section_header(symbol->st_shndx);
    if (!header || header->sh_type != SHT_PROGBITS || header->sh_size != size ||
        (header->sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR)) !=
            SHF_ALLOC ||
        object.section_name(symbol->st_shndx) != section_name)
      return nullptr;
    return symbol;
  };

  const auto *descriptor = unique_symbol("__this_module");
  if (!descriptor || descriptor->st_shndx == SHN_UNDEF ||
      descriptor->st_shndx >= SHN_LORESERVE || descriptor->st_value ||
      descriptor->st_size != layout[0] ||
      ELF64_ST_TYPE(descriptor->st_info) != STT_OBJECT ||
      object.section_name(descriptor->st_shndx) !=
          ".gnu.linkonce.this_module" ||
      object.section_header(descriptor->st_shndx)->sh_size != layout[0] ||
      object.section_header(descriptor->st_shndx)->sh_type != SHT_PROGBITS ||
      !(object.section_header(descriptor->st_shndx)->sh_flags & SHF_ALLOC) ||
      (object.section_header(descriptor->st_shndx)->sh_flags & SHF_EXECINSTR) ||
      relocations[descriptor->st_shndx].size() != 2)
    return fail("module descriptor layout mismatch");
  const ct_kernel_section *old_descriptor = nullptr;
  for (const auto &section : original.sections)
    if (section.name == ".gnu.linkonce.this_module")
      old_descriptor = &section;
  if (!old_descriptor || old_descriptor->size != layout[0] ||
      old_descriptor->offset > original.bytes.size() ||
      old_descriptor->size > original.bytes.size() - old_descriptor->offset ||
      std::memcmp(object.section_content(descriptor->st_shndx)->data(),
                  original.bytes.data() + old_descriptor->offset, layout[0]))
    return fail("module descriptor contents changed");
  for (const auto &[name, field] : {std::pair{"__ctrace_init", layout[1]},
                                    std::pair{"__ctrace_exit", layout[2]}}) {
    const auto *wrapper = unique_symbol(name);
    uint32_t section = 0;
    uint64_t offset = 0;
    if (!wrapper || !wrapper->st_size ||
        ELF64_ST_TYPE(wrapper->st_info) != STT_FUNC ||
        wrapper->st_shndx == SHN_UNDEF || wrapper->st_shndx >= SHN_LORESERVE ||
        !(object.section_header(wrapper->st_shndx)->sh_flags & SHF_EXECINSTR) ||
        !address(descriptor->st_shndx, field, R_X86_64_64, section, offset) ||
        section != wrapper->st_shndx || offset != wrapper->st_value)
      return fail("module descriptor does not enter the verified wrappers");
  }

  const auto *manifest =
      readonly_object("__ctrace_manifest", ".init.rodata.ctrace_manifest",
                      sizeof(kctrace_manifest));
  const auto *count = readonly_object(
      "__ctrace_site_count", ".init.rodata.ctrace_count", sizeof(uint64_t));
  const auto *sites =
      copies
          ? nullptr
          : readonly_object("__ctrace_sites", ".init.rodata.ctrace_sites",
                            prepared.probe_count * sizeof(kctrace_probe_site));
  const auto *program = copies ? readonly_object("__ctrace_program",
                                                 ".init.rodata.ctrace_program",
                                                 sizeof(kctrace_program))
                               : nullptr;
  if (!manifest || !count || (copies ? !program : !sites) ||
      !relocations[manifest->st_shndx].empty() ||
      !relocations[count->st_shndx].empty())
    return fail("manifest or site table storage mismatch");
  const auto &manifest_bytes = *object.section_content(manifest->st_shndx);
  if (std::any_of(manifest_bytes.begin(), manifest_bytes.end(),
                  [](unsigned char byte) { return byte != 0; }))
    return fail("template manifest is not entirely zero");
  const uint64_t manifest_offset =
      object.section_header(manifest->st_shndx)->sh_offset;
  if (prepared.manifest_offset && prepared.manifest_offset != manifest_offset)
    return fail("cached manifest offset mismatch");
  uint64_t stored_count = 0;
  std::memcpy(&stored_count, object.section_content(count->st_shndx)->data(),
              sizeof(stored_count));
  if (stored_count != prepared.probe_count ||
      (!copies &&
       relocations[sites->st_shndx].size() != 2 * prepared.probe_count))
    return fail("site count or address relocation count mismatch");

  const uint64_t capture_count = prepared.captures->size() - 1;
  const auto *capture_count_symbol =
      readonly_object("__ctrace_capture_plan_count",
                      ".init.rodata.ctrace_capture_count", sizeof(uint64_t));
  const auto *captures = readonly_object(
      "__ctrace_capture_plans", ".init.rodata.ctrace_capture_plans",
      capture_count * sizeof(kctrace_capture_plan));
  if (!capture_count_symbol || !captures ||
      !relocations[capture_count_symbol->st_shndx].empty())
    return fail("capture plan storage mismatch");
  uint64_t serialized_capture_count = 0;
  std::memcpy(&serialized_capture_count,
              object.section_content(capture_count_symbol->st_shndx)->data(),
              sizeof(serialized_capture_count));
  if (serialized_capture_count != capture_count)
    return fail("capture plan count mismatch");
  const auto *parameter_layout_symbol = readonly_object(
      "__ctrace_param_layout", ".init.rodata.ctrace_param_layout",
      sizeof(parameter_layout));
  if (!parameter_layout_symbol ||
      !relocations[parameter_layout_symbol->st_shndx].empty() ||
      std::memcmp(
          object.section_content(parameter_layout_symbol->st_shndx)->data(),
          parameter_layout.data(), sizeof(parameter_layout)))
    return fail("parameter layout differs from exact Kbuild headers");
  const auto *bootstrap =
      readonly_object("__ctrace_bootstrap", ".init.rodata.ctrace_bootstrap",
                      sizeof(kctrace_bootstrap));
  const auto *binding = unique_symbol("__ctrace_binding");
  if (!bootstrap || !binding ||
      ELF64_ST_BIND(bootstrap->st_info) != STB_GLOBAL ||
      ELF64_ST_BIND(binding->st_info) != STB_GLOBAL ||
      ELF64_ST_TYPE(binding->st_info) != STT_OBJECT ||
      binding->st_size != sizeof(uint64_t) || binding->st_value % 8 ||
      !binding->st_shndx || binding->st_shndx >= SHN_LORESERVE)
    return fail("bootstrap descriptor or binding slot identity mismatch");
  const auto *binding_section = object.section_header(binding->st_shndx);
  if (!binding_section || binding_section->sh_type != SHT_NOBITS ||
      binding_section->sh_addralign < 8 ||
      (binding_section->sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR)) !=
          (SHF_ALLOC | SHF_WRITE) ||
      object.section_name(binding->st_shndx).rfind(".init", 0) == 0 ||
      binding->st_value > binding_section->sh_size ||
      binding->st_size > binding_section->sh_size - binding->st_value)
    return fail("bootstrap binding slot is not permanent zeroed writable data");
  for (const auto &symbol : symbols)
    if (&symbol != binding && symbol.st_shndx == binding->st_shndx &&
        ELF64_ST_TYPE(symbol.st_info) == STT_OBJECT && symbol.st_size &&
        __int128(symbol.st_value) <
            __int128(binding->st_value) + binding->st_size &&
        __int128(binding->st_value) <
            __int128(symbol.st_value) + symbol.st_size)
      return fail("bootstrap binding slot aliases another object");
  for (const auto &[offset, relocation] : relocations[binding->st_shndx])
    if (__int128(offset) < __int128(binding->st_value) + binding->st_size &&
        __int128(binding->st_value) < __int128(offset) + relocation.width)
      return fail("bootstrap binding slot contains a relocation");
  kctrace_bootstrap bootstrap_value{};
  std::memcpy(&bootstrap_value,
              object.section_content(bootstrap->st_shndx)->data(),
              sizeof(bootstrap_value));
  kctrace_bootstrap expected_bootstrap{};
  expected_bootstrap.size = sizeof(kctrace_bootstrap);
  expected_bootstrap.abi = KCTRACE_ABI_VERSION;
  if (std::memcmp(&bootstrap_value, &expected_bootstrap,
                  sizeof(bootstrap_value)) ||
      relocations[bootstrap->st_shndx].size() != 6)
    return fail(
        "bootstrap ABI, flags, pointer bytes or relocation count mismatch");
  for (const auto &[field, target] :
       {std::pair{offsetof(kctrace_bootstrap, manifest), manifest},
        {copies ? offsetof(kctrace_bootstrap, program)
                : offsetof(kctrace_bootstrap, sites),
         copies ? program : sites},
        {offsetof(kctrace_bootstrap, site_count_address), count},
        {offsetof(kctrace_bootstrap, capture_plans), captures},
        {offsetof(kctrace_bootstrap, capture_plan_count_address),
         capture_count_symbol},
        {offsetof(kctrace_bootstrap, binding_slot), binding}}) {
    const auto reference = relocations[bootstrap->st_shndx].find(field);
    if (reference == relocations[bootstrap->st_shndx].end() ||
        ELF64_R_TYPE(reference->second.value.r_info) != R_X86_64_64 ||
        reference->second.value.r_addend ||
        &symbols[ELF64_R_SYM(reference->second.value.r_info)] != target)
      return fail("bootstrap pointer does not name its exact generated object");
  }
  const auto &capture_bytes = *object.section_content(captures->st_shndx);
  size_t capture_relocations = 0;
  std::map<uint32_t, const Elf64_Sym *> capture_data_anchors;
  for (size_t index = 1; index < prepared.captures->size(); ++index) {
    for (size_t slot_index = 0; slot_index < KCTRACE_VALUE_SLOTS;
         ++slot_index) {
      const auto &slot = (*prepared.captures)[index].slots[slot_index];
      const auto &expected = slot.capture;
      const uint64_t field = (index - 1) * sizeof(kctrace_capture_plan) +
                             slot_index * sizeof(kctrace_capture);
      kctrace_capture record{};
      std::memcpy(&record, capture_bytes.data() + field, sizeof(record));
      if (std::memcmp(&record, &expected, sizeof(record)) || expected.object ||
          expected.reserved || expected.reserved2)
        return fail("capture descriptor differs from its offline plan");
      if (expected.kind == KCTRACE_CAPTURE_NONE) {
        const kctrace_capture empty{};
        if (std::memcmp(&expected, &empty, sizeof(empty)) ||
            slot.section != UINT32_MAX || slot.object_offset)
          return fail("nonempty unavailable capture slot");
        continue;
      }
      if (!expected.size || expected.size > 8)
        return fail("invalid capture scalar width");
      if (expected.kind == KCTRACE_CAPTURE_STACK) {
        if (expected.object_size || slot.section != UINT32_MAX ||
            slot.object_offset ||
            (expected.reg != KCTRACE_REG_RSP &&
             expected.reg != KCTRACE_REG_RBP))
          return fail("invalid capture stack basis");
        continue;
      }
      if (expected.kind != KCTRACE_CAPTURE_OBJECT || expected.reg ||
          !slot.section || slot.section >= original.sections.size() ||
          expected.offset < 0 ||
          uint64_t(expected.offset) > expected.object_size ||
          expected.size > expected.object_size - uint64_t(expected.offset))
        return fail("invalid capture object bounds");
      const auto &original_section = original.sections[slot.section];
      if (!ct_kernel_capture_section(original_section) ||
          slot.object_offset > original_section.size ||
          expected.object_size > original_section.size - slot.object_offset ||
          std::none_of(original.symbols.begin(), original.symbols.end(),
                       [&](const auto &symbol) {
                         return symbol.section == slot.section &&
                                symbol.type == STT_OBJECT &&
                                symbol.offset == slot.object_offset &&
                                symbol.size == expected.object_size;
                       }))
        return fail("capture does not name a complete original data object");
      const auto *anchor =
          unique_symbol("__ctrace_data_anchor_" + std::to_string(slot.section));
      uint32_t section = 0;
      uint64_t offset = 0;
      if (!anchor || anchor->st_shndx == SHN_UNDEF ||
          anchor->st_shndx >= SHN_LORESERVE ||
          !address(captures->st_shndx,
                   field + offsetof(kctrace_capture, object), R_X86_64_64,
                   section, offset) ||
          section != anchor->st_shndx ||
          offset != anchor->st_value + slot.object_offset)
        return fail(
            "capture relocation does not reference its original object");
      const auto *data = object.section_header(section);
      if (!data || !(data->sh_flags & SHF_ALLOC) ||
          (data->sh_flags & SHF_EXECINSTR) ||
          anchor->st_value > data->sh_size ||
          original_section.size > data->sh_size - anchor->st_value)
        return fail("capture data anchor exceeds allocated storage");
      capture_data_anchors[slot.section] = anchor;
      ++capture_relocations;
    }
  }
  if (relocations[captures->st_shndx].size() != capture_relocations)
    return fail("unexpected capture plan relocation");

  const std::map<std::string, std::set<std::string>> wrapper_edges{
      {"__ctrace_init", {"kctrace_initialized", "init_module"}},
      {"__ctrace_exit", {"cleanup_module"}}};
  for (const auto &[wrapper_name, expected] : wrapper_edges) {
    const auto &wrapper = *unique_symbol(wrapper_name);
    std::set<std::string> seen;
    for (const auto &[offset, relocation] : relocations[wrapper.st_shndx]) {
      if (offset < wrapper.st_value ||
          offset >= wrapper.st_value + wrapper.st_size)
        continue;
      const auto &target = symbols[ELF64_R_SYM(relocation.value.r_info)];
      const std::string name(
          reinterpret_cast<const char *>(strings.data() + target.st_name));
      if (expected.count(name) &&
          (ELF64_R_TYPE(relocation.value.r_info) == R_X86_64_PLT32 ||
           ELF64_R_TYPE(relocation.value.r_info) == R_X86_64_PC32) &&
          relocation.value.r_addend == -4)
        seen.insert(name);
    }
    if (seen != expected)
      return fail("wrapper does not connect original lifecycle and runtime: " +
                  wrapper_name);
  }
  if (copies) {
    if (!validate_copy_program(original, prepared, *copies, object,
                               parameter_graph, error))
      return false;
  } else {
    std::map<uint32_t, const Elf64_Sym *> anchors;
    std::map<uint32_t, std::pair<uint64_t, uint64_t>> extents;
    std::map<uint32_t, std::vector<const ct_kernel_site *>> instruction_maps;
    std::vector<const ct_kernel_site *> identifiers(prepared.probe_count,
                                                    nullptr);
    for (const auto &site : prepared.sites) {
      if (!site.section || site.section >= original.sections.size() ||
          !(original.sections[site.section].flags & SHF_EXECINSTR) ||
          !site.original_size || site.original_size > 15 ||
          !site.emitted_size || site.emitted_size > 15 ||
          site.operation != site.entry + (site.probe ? 7 : 0))
        return fail("invalid original-to-expanded site mapping");
      auto &extent = extents[site.section];
      if (extent.first != site.offset || extent.second != site.entry ||
          site.original_size >
              original.sections[site.section].size -
                  std::min(site.offset, original.sections[site.section].size))
        return fail("noncontiguous or out-of-range instruction map");
      extent = {site.offset + site.original_size,
                site.operation + site.emitted_size};
      instruction_maps[site.section].push_back(&site);
      if (!site.probe) {
        if (site.id)
          return fail("padding or IBT landing pad has a probe ID");
        continue;
      }
      if (!site.id || site.id > prepared.probe_count ||
          identifiers[site.id - 1])
        return fail("invalid or duplicated probe ID");
      identifiers[site.id - 1] = &site;
      if (!anchors.count(site.section)) {
        const auto *anchor =
            unique_symbol("__ctrace_anchor_" + std::to_string(site.section));
        if (!anchor || anchor->st_shndx == SHN_UNDEF ||
            anchor->st_shndx >= SHN_LORESERVE ||
            !(object.section_header(anchor->st_shndx)->sh_flags &
              SHF_EXECINSTR))
          return fail("missing original code-section anchor");
        anchors[site.section] = anchor;
      }
    }
    for (uint32_t index = 1; index < original.sections.size(); ++index)
      if ((original.sections[index].flags & SHF_EXECINSTR) &&
          original.sections[index].size &&
          extents[index].first != original.sections[index].size)
        return fail("site map omits original executable bytes");
    const auto mapped_offset = [&](uint32_t section, uint64_t offset,
                                   uint64_t &result) {
      const auto found = instruction_maps.find(section);
      if (found == instruction_maps.end())
        return false;
      if (offset == original.sections[section].size) {
        result = extents.at(section).second;
        return true;
      }
      const auto &rows = found->second;
      auto next = std::upper_bound(
          rows.begin(), rows.end(), offset,
          [](uint64_t value, const auto *row) { return value < row->offset; });
      if (next == rows.begin())
        return false;
      const auto &row = **std::prev(next);
      const uint64_t delta = offset - row.offset;
      if (delta >= row.original_size ||
          (delta && row.original_size != row.emitted_size))
        return false;
      result = delta ? row.operation + delta : row.entry;
      return true;
    };
    for (const auto &original_symbol : original.symbols) {
      if (original_symbol.binding == STB_LOCAL || !original_symbol.section ||
          original_symbol.section >= SHN_LORESERVE ||
          !(original.sections[original_symbol.section].flags & SHF_EXECINSTR))
        continue;
      const auto *symbol = unique_symbol(original_symbol.name);
      const auto anchor = anchors.find(original_symbol.section);
      uint64_t first = 0, last = 0;
      if (!symbol || anchor == anchors.end() ||
          !mapped_offset(original_symbol.section, original_symbol.offset,
                         first) ||
          !mapped_offset(original_symbol.section,
                         original_symbol.offset + original_symbol.size, last) ||
          symbol->st_shndx != anchor->second->st_shndx ||
          symbol->st_value != anchor->second->st_value + first ||
          symbol->st_size != last - first ||
          ELF64_ST_TYPE(symbol->st_info) != original_symbol.type)
        return fail("original code symbol identity changed: " +
                    original_symbol.name);
    }
    // Tie data anchors to independent original symbols and code references.
    // A capture relocation pointing back to its own forged anchor is not proof
    // that the anchor denotes the original ELF data section.
    std::set<uint32_t> proven_data_anchors;
    std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *>
        original_symbols;
    for (const auto &symbol : original.symbols) {
      original_symbols[{symbol.table, symbol.index}] = &symbol;
      const auto anchor = capture_data_anchors.find(symbol.section);
      if (anchor == capture_data_anchors.end() || symbol.type != STT_OBJECT ||
          symbol.name.empty())
        continue;
      const auto *current = unique_symbol(symbol.name);
      if (!current || ELF64_ST_TYPE(current->st_info) != STT_OBJECT ||
          ELF64_ST_BIND(current->st_info) != symbol.binding ||
          current->st_size != symbol.size)
        continue;
      if (current->st_shndx != anchor->second->st_shndx ||
          __int128(current->st_value) !=
              __int128(anchor->second->st_value) + symbol.offset)
        return fail(
            "capture data anchor differs from an original object symbol");
      proven_data_anchors.insert(symbol.section);
    }
    for (const auto &original_reference : original.relocations) {
      const auto target = original_symbols.find(
          {original_reference.symbol_table, original_reference.symbol});
      if (target == original_symbols.end())
        continue;
      const auto data_anchor =
          capture_data_anchors.find(target->second->section);
      const auto code_anchor = anchors.find(original_reference.section);
      if (data_anchor == capture_data_anchors.end() ||
          code_anchor == anchors.end() ||
          (original_reference.type != R_X86_64_64 &&
           original_reference.type != R_X86_64_PC64 &&
           original_reference.type != R_X86_64_PC32 &&
           original_reference.type != R_X86_64_32 &&
           original_reference.type != R_X86_64_32S))
        continue;
      uint64_t field = 0;
      if (!mapped_offset(original_reference.section, original_reference.offset,
                         field))
        continue;
      const auto &references = relocations[code_anchor->second->st_shndx];
      const auto reference =
          references.find(code_anchor->second->st_value + field);
      if (reference == references.end() ||
          ELF64_R_TYPE(reference->second.value.r_info) !=
              original_reference.type)
        return fail("original data reference is missing from prepared code");
      const auto &relocation = reference->second.value;
      const auto &symbol = symbols[ELF64_R_SYM(relocation.r_info)];
      if (symbol.st_shndx != data_anchor->second->st_shndx ||
          __int128(symbol.st_value) + relocation.r_addend !=
              __int128(data_anchor->second->st_value) + target->second->offset +
                  original_reference.addend)
        return fail(
            "capture data anchor differs from an original code reference");
      proven_data_anchors.insert(target->second->section);
    }
    if (proven_data_anchors.size() != capture_data_anchors.size())
      return fail("capture data section identity is unproven");
    const auto &site_bytes = *object.section_content(sites->st_shndx);
    std::set<std::pair<uint32_t, uint64_t>> expected_calls;
    for (uint64_t index = 0; index < prepared.probe_count; ++index) {
      const auto *site = identifiers[index];
      if (!site)
        return fail("missing probe ID");
      kctrace_probe_site record;
      std::memcpy(&record, site_bytes.data() + index * sizeof(record),
                  sizeof(record));
      if (record.return_pc || record.pc || record.site_id != index + 1 ||
          record.type != KCTRACE_EVENT_INSTRUCTION_BEFORE || record.reserved ||
          record.capture_plan !=
              prepared.values->sites[site->id].capture_plan ||
          record.capture_plan > capture_count)
        return fail("invalid serialized probe site");
      const auto &anchor = *anchors.at(site->section);
      const auto &code = *object.section_content(anchor.st_shndx);
      if (anchor.st_value > code.size() ||
          site->operation > code.size() - anchor.st_value ||
          site->emitted_size > code.size() - anchor.st_value - site->operation)
        return fail("probe operation exceeds final code section");
      const uint64_t entry = anchor.st_value + site->entry;
      const uint64_t operation = anchor.st_value + site->operation;
      if (code[entry] != 0x9c || code[entry + 1] != 0xe8 ||
          code[entry + 6] != 0x9d ||
          !expected_calls.emplace(anchor.st_shndx, entry + 2).second)
        return fail("probe is not one unique CALL instruction");
      const auto call = relocations[anchor.st_shndx].find(entry + 2);
      if (call == relocations[anchor.st_shndx].end() ||
          ELF64_R_TYPE(call->second.value.r_info) != R_X86_64_PLT32 ||
          call->second.value.r_addend != -4 ||
          &symbols[ELF64_R_SYM(call->second.value.r_info)] !=
              unique_symbol("kctrace_probe"))
        return fail("probe CALL relocation does not resolve the runtime");
      for (uint64_t field : {offsetof(kctrace_probe_site, return_pc),
                             offsetof(kctrace_probe_site, pc)}) {
        uint32_t section = 0;
        uint64_t offset = 0;
        if (!address(sites->st_shndx, index * sizeof(record) + field,
                     R_X86_64_64, section, offset) ||
            section != anchor.st_shndx ||
            offset !=
                operation -
                    (field == offsetof(kctrace_probe_site, return_pc) ? 1 : 0))
          return fail(
              "site address does not match its original instruction map");
      }
    }
    for (const auto &[section, fields] : relocations)
      for (const auto &[offset, relocation] : fields)
        if (&symbols[ELF64_R_SYM(relocation.value.r_info)] ==
                unique_symbol("kctrace_probe") &&
            !expected_calls.count({section, offset}))
          return fail("unexpected reference to the probe runtime");
  }

  const auto unwind = sections.find(".orc_unwind"),
             ips = sections.find(".orc_unwind_ip");
  if (unwind == sections.end() || ips == sections.end())
    return fail("missing regenerated ORC tables");
  const auto unwind_size = object.section_header(unwind->second)->sh_size;
  const auto ip_size = object.section_header(ips->second)->sh_size;
  if (!unwind_size || unwind_size % 6 || ip_size % 4 ||
      unwind_size / 6 != ip_size / 4 ||
      relocations[ips->second].size() != ip_size / 4)
    return fail("regenerated ORC table sizes disagree");
  for (uint64_t offset = 0; offset < ip_size; offset += 4) {
    uint32_t section = 0;
    uint64_t target = 0;
    if (!address(ips->second, offset, R_X86_64_PC32, section, target) ||
        !(object.section_header(section)->sh_flags & SHF_EXECINSTR))
      return fail("ORC IP does not reference executable code");
  }
  prepared.manifest_offset = manifest_offset;
  prepared.template_digest = std::move(actual_digest);
  return true;
}
