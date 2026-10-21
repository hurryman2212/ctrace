// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <llvm/Support/JSON.h>

#include <elf.h>

#include "../flow.hh"
#include "ctrace_contract.h"
#include "decompile_image.hh"
#include "object.hh"

bool ct_kernel_make_decompile_image(const ct_kernel_image &original,
                                    std::vector<unsigned char> &bytes,
                                    std::string &error) {
  bytes.clear();
  error.clear();
  ct_kernel_object object(original);
  if (!object.valid(error))
    return false;
  if (object.section_count() != original.sections.size()) {
    error = "decompile image section inventory differs from original ELF";
    return false;
  }
  for (const auto &symbol : original.symbols)
    if (symbol.name.rfind("__ctrace_analysis_section_", 0) == 0) {
      error = "original module uses a reserved decompile anchor";
      return false;
    }
  uint32_t symbols = 0;
  for (uint32_t index = 1; index < object.section_count(); ++index) {
    const auto &section = *object.section_header(index);
    const auto &expected = original.sections[index];
    if (section.sh_size != expected.size ||
        section.sh_flags != expected.flags ||
        section.sh_type != expected.type ||
        object.section_name(index) != expected.name) {
      error = "decompile image section identity differs from original ELF";
      return false;
    }
    if (section.sh_type == SHT_SYMTAB) {
      if (symbols) {
        error = "multiple symbol tables in decompile image";
        return false;
      }
      symbols = index;
    }
  }
  if (!symbols) {
    error = "decompile image has no symbol table";
    return false;
  }
  for (uint32_t index = 1; index < original.sections.size(); ++index) {
    const auto &section = original.sections[index];
    if (!(section.flags & SHF_ALLOC) || !section.size)
      continue;
    Elf64_Sym anchor{};
    anchor.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
    anchor.st_other = STV_HIDDEN;
    anchor.st_shndx = index;
    uint32_t symbol = 0;
    if (!object.append_symbol(
            symbols, "__ctrace_analysis_section_" + std::to_string(index),
            anchor, symbol, error))
      return false;
  }
  return object.serialize(bytes, error);
}

bool ct_kernel_parse_decompile_layout(const ct_kernel_image &original,
                                      const std::string &manifest,
                                      ct_kernel_decompile_layout &layout,
                                      std::string &error) {
  layout = {};
  error.clear();
  const auto fail = [&](const std::string &reason) {
    error = "invalid kernel decompile manifest: " + reason;
    return false;
  };
  auto parsed = llvm::json::parse(manifest);
  if (!parsed) {
    llvm::consumeError(parsed.takeError());
    return fail("malformed JSON");
  }
  const auto *object = parsed->getAsObject();
  const auto address = [](const llvm::json::Object &record, const char *name,
                          uint64_t &value) {
    const auto text = record.getString(name);
    if (!text || !text->starts_with("0x") || text->size() <= 2)
      return false;
    const char *begin = text->data() + 2, *end = text->data() + text->size();
    const auto result = std::from_chars(begin, end, value, 16);
    return result.ec == std::errc() && result.ptr == end;
  };
  if (!object || object->getString("contract_hash") != CTRACE_CONTRACT_HASH ||
      !object->getBoolean("ok").value_or(false) ||
      object->getInteger("pointer_size") != 8 ||
      object->getBoolean("big_endian") != false ||
      !address(*object, "image_base", layout.image_base))
    return fail("unsupported address model");
  const auto space = object->getString("address_space");
  const auto *sections = object->getArray("sections");
  const auto *imports = object->getArray("symbols");
  const auto *relocations = object->getArray("relocations");
  if (!space || space->empty() || !sections || !imports || !relocations ||
      sections->size() > original.sections.size())
    return fail("missing or excessive inventory");
  layout.address_space = space->str();
  std::map<uint32_t, ct_kernel_decompile_region> regions;
  for (const auto &item : *sections) {
    const auto *record = item.getAsObject();
    const auto index = record ? record->getInteger("index") : std::nullopt;
    uint64_t begin = 0, block_begin = 0;
    if (!record || !index || *index <= 0 ||
        uint64_t(*index) >= original.sections.size() ||
        !address(*record, "address", begin) ||
        !address(*record, "block_begin", block_begin))
      return fail("invalid section anchor");
    const auto &section = original.sections[*index];
    if (!(section.flags & SHF_ALLOC) || !section.size ||
        begin < layout.image_base || section.size > UINT64_MAX - begin ||
        block_begin != begin ||
        record->getInteger("block_size") != int64_t(section.size) ||
        record->getString("block_name") != section.name ||
        record->getString("space") != layout.address_space ||
        record->getString("anchor") !=
            "__ctrace_analysis_section_" + std::to_string(*index) ||
        record->getBoolean("overlay") != false ||
        record->getBoolean("read") != true ||
        record->getBoolean("write") != bool(section.flags & SHF_WRITE) ||
        record->getBoolean("execute") != bool(section.flags & SHF_EXECINSTR) ||
        (section.type != SHT_NOBITS &&
         record->getBoolean("initialized") != true) ||
        !regions
             .emplace(uint32_t(*index),
                      ct_kernel_decompile_region{uint32_t(*index), begin,
                                                 section.size})
             .second)
      return fail("section anchor does not match its original section");
  }
  for (uint32_t index = 1; index < original.sections.size(); ++index)
    if ((original.sections[index].flags & SHF_ALLOC) &&
        original.sections[index].size && !regions.count(index))
      return fail("allocated section has no anchor");
  std::vector<ct_kernel_decompile_region> ordered;
  for (const auto &[index, region] : regions) {
    layout.regions.push_back(region);
    ordered.push_back(region);
  }
  std::sort(ordered.begin(), ordered.end(),
            [](const auto &a, const auto &b) { return a.address < b.address; });
  for (size_t index = 1; index < ordered.size(); ++index)
    if (ordered[index].address <
        ordered[index - 1].address + ordered[index - 1].size)
      return fail("overlapping original sections");
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  for (const auto &symbol : original.symbols)
    if (!symbols.emplace(std::make_pair(symbol.table, symbol.index), &symbol)
             .second)
      return fail("duplicate original symbol identity");
  std::map<uint64_t, const llvm::json::Object *> records;
  for (const auto &item : *relocations) {
    const auto *record = item.getAsObject();
    uint64_t field = 0;
    if (!record || !address(*record, "address", field))
      return fail("malformed relocation record");
    if (record->getString("space") != layout.address_space)
      continue; // Nonallocated DWARF/metadata may live in OTHER overlays.
    if (!records.emplace(field, record).second)
      return fail("duplicate relocation record");
  }
  const auto hex_bytes = [](llvm::StringRef text, unsigned size,
                            std::vector<unsigned char> &bytes) {
    if (text.size() != 2 * size)
      return false;
    bytes.clear();
    for (unsigned index = 0; index < size; ++index) {
      unsigned byte = 0;
      const char *begin = text.data() + 2 * index;
      const auto result = std::from_chars(begin, begin + 2, byte, 16);
      if (result.ec != std::errc() || result.ptr != begin + 2)
        return false;
      bytes.push_back(static_cast<unsigned char>(byte));
    }
    return true;
  };
  std::set<uint64_t> consumed;
  std::set<uint64_t> ambiguous_imports;
  for (const auto &relocation : original.relocations) {
    const auto region = regions.find(relocation.section);
    if (region == regions.end() || relocation.type == R_X86_64_NONE)
      continue;
    ct_kernel_decompile_fixup fixup;
    fixup.section = relocation.section;
    fixup.offset = relocation.offset;
    fixup.type = relocation.type;
    bool relative = false, signed_value = false;
    switch (relocation.type) {
    case R_X86_64_64:
      fixup.width = 8;
      break;
    case R_X86_64_PC64:
      fixup.width = 8;
      relative = true;
      break;
    case R_X86_64_32:
      fixup.width = 4;
      break;
    case R_X86_64_32S:
      fixup.width = 4;
      signed_value = true;
      break;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
      fixup.width = 4;
      relative = signed_value = true;
      break;
    case R_X86_64_16:
      fixup.width = 2;
      break;
    case R_X86_64_PC16:
      fixup.width = 2;
      relative = signed_value = true;
      break;
    case R_X86_64_8:
      fixup.width = 1;
      break;
    case R_X86_64_PC8:
      fixup.width = 1;
      relative = signed_value = true;
      break;
    default:
      fixup.error = "unsupported original relocation type";
      break;
    }
    if (relocation.offset >= region->second.size ||
        fixup.width > region->second.size - relocation.offset)
      return fail("relocation exceeds its original section");
    const uint64_t field = region->second.address + relocation.offset;
    if (!consumed.insert(field).second)
      return fail("duplicate original relocation field");
    const auto found = records.find(field);
    const auto symbol =
        symbols.find({relocation.symbol_table, relocation.symbol});
    if (symbol == symbols.end())
      return fail("relocation has no original symbol");
    const auto &target = *symbol->second;
    const std::string name = !target.name.empty() ? target.name
                             : target.section < original.sections.size()
                                 ? original.sections[target.section].name
                                 : "";
    if (found == records.end() ||
        found->second->getInteger("type") != relocation.type ||
        found->second->getInteger("symbol_index") != relocation.symbol ||
        found->second->getString("symbol_name") != name ||
        found->second->getString("status") != "APPLIED" ||
        found->second->getInteger("length") != fixup.width)
      fixup.error = "loader relocation identity or applied status is unproven";
    uint64_t symbol_address = 0;
    bool target_known = false;
    if (target.section == SHN_ABS) {
      symbol_address = target.offset;
      target_known = true;
    } else if (target.section != SHN_UNDEF) {
      const auto defined = regions.find(target.section);
      if (defined != regions.end() && target.offset <= defined->second.size) {
        symbol_address = defined->second.address + target.offset;
        target_known = true;
      }
    } else {
      unsigned matches = 0;
      for (const auto &item : *imports) {
        const auto *candidate = item.getAsObject();
        uint64_t imported_address = 0;
        if (!candidate || candidate->getString("name") != target.name ||
            candidate->getString("space") != layout.address_space ||
            candidate->getString("block") != "EXTERNAL" ||
            !address(*candidate, "address", imported_address))
          continue;
        bool imported = candidate->getString("source") == "IMPORTED";
        if (!imported && candidate->getString("type") == "Function") {
          const auto *thunk = candidate->getObject("thunk");
          uint64_t thunk_address = 0;
          if (thunk && thunk->getString("name") == target.name &&
              thunk->getString("source") == "IMPORTED" &&
              thunk->getBoolean("external") == true &&
              address(*thunk, "address", thunk_address)) {
            unsigned targets = 0;
            for (const auto &external_item : *imports) {
              const auto *external = external_item.getAsObject();
              uint64_t external_address = 0;
              targets +=
                  external && external->getString("name") == target.name &&
                  external->getString("space") == thunk->getString("space") &&
                  external->getString("source") == "IMPORTED" &&
                  external->getBoolean("external") == true &&
                  address(*external, "address", external_address) &&
                  external_address == thunk_address;
            }
            imported = targets == 1;
          }
        }
        if (!imported || imported_address < layout.image_base ||
            std::any_of(
                ordered.begin(), ordered.end(),
                [&](const auto &owned) {
                  return imported_address >= owned.address &&
                         imported_address - owned.address < owned.size;
                }))
          continue;
        ++matches;
        symbol_address = imported_address;
      }
      target_known = matches == 1;
    }
    if (!target_known)
      fixup.error = "relocation target has no unique independent address proof";
    if (fixup.error.empty()) {
      const __int128 value = __int128(symbol_address) + relocation.addend -
                             (relative ? __int128(field) : 0);
      // ELF64 relocation arithmetic wraps at 64 bits before narrower range
      // checks. A high-half SHN_ABS kernel address may be a valid signed32
      // value even though its unsigned symbol value exceeds INT64_MAX.
      const uint64_t encoded = uint64_t(value);
      const __int128 bounded = signed_value && (encoded >> 63)
                                   ? __int128(encoded) - (__int128(1) << 64)
                                   : __int128(encoded);
      const unsigned bits = 8 * fixup.width;
      if (bits < 64 &&
          (signed_value ? (bounded < -(__int128(1) << (bits - 1)) ||
                           bounded >= (__int128(1) << (bits - 1)))
                        : bounded >= (__int128(1) << bits))) {
        fixup.error = "relocation value overflows its field";
      } else {
        fixup.value = encoded;
        const auto *record = found->second;
        const auto before = record->getString("original_bytes");
        const auto after = record->getString("current_bytes");
        std::vector<unsigned char> raw, relocated;
        if (!before || !after || !hex_bytes(*before, fixup.width, raw) ||
            !hex_bytes(*after, fixup.width, relocated)) {
          fixup.error = "relocation bytes are malformed";
        } else {
          const auto &section = original.sections[fixup.section];
          if (section.type != SHT_NOBITS &&
              (section.offset > original.bytes.size() ||
               section.size > original.bytes.size() - section.offset))
            return fail("original relocation bytes exceed input");
          fixup.proven = true;
          for (unsigned byte = 0; byte < fixup.width; ++byte) {
            const unsigned char original_byte =
                section.type == SHT_NOBITS
                    ? 0
                    : original.bytes[section.offset + fixup.offset + byte];
            if (raw[byte] != original_byte ||
                relocated[byte] != uint8_t(fixup.value >> (8 * byte))) {
              fixup.proven = false;
              fixup.error = "relocation bytes differ from original or "
                            "independently computed value";
            }
          }
        }
      }
    }
    if (fixup.proven && target.section == SHN_UNDEF &&
        symbol_address >= layout.image_base && !target.name.empty()) {
      const auto letter = [](char byte) {
        return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
               byte == '_';
      };
      if (letter(target.name.front()) &&
          std::all_of(target.name.begin(), target.name.end(), [&](char byte) {
            return letter(byte) || (byte >= '0' && byte <= '9');
          })) {
        const uint64_t relative = symbol_address - layout.image_base;
        if (!ambiguous_imports.count(relative)) {
          const auto [entry, inserted] =
              layout.external_symbols.emplace(relative, target.name);
          if (!inserted && entry->second != target.name) {
            layout.external_symbols.erase(entry);
            ambiguous_imports.insert(relative);
          }
        }
      }
    }
    layout.fixups.push_back(std::move(fixup));
  }
  for (const auto &[field, record] : records)
    if (!consumed.count(field))
      return fail("loader added an unaccounted relocation");
  std::sort(layout.fixups.begin(), layout.fixups.end(),
            [](const auto &a, const auto &b) {
              return std::tie(a.section, a.offset) <
                     std::tie(b.section, b.offset);
            });
  for (size_t index = 1; index < layout.fixups.size(); ++index) {
    const auto &a = layout.fixups[index - 1], &b = layout.fixups[index];
    if (a.section == b.section && b.offset - a.offset < a.width)
      return fail("overlapping original relocation fields");
  }
  const auto *returns = object->getArray("kernel_returns");
  if (object->get("kernel_returns") && !returns)
    return fail("invalid kernel return override inventory");
  if (returns) {
    std::set<uint64_t> seen;
    for (const auto &item : *returns) {
      const auto *record = item.getAsObject();
      uint64_t pc = 0;
      if (!record || !address(*record, "address", pc) ||
          record->getString("space") != layout.address_space ||
          !seen.insert(pc).second)
        return fail("invalid kernel return override address");
      bool matched = false;
      for (const auto &relocation : original.relocations) {
        const auto region = regions.find(relocation.section);
        const auto symbol =
            symbols.find({relocation.symbol_table, relocation.symbol});
        if (region == regions.end() || !relocation.offset ||
            pc < region->second.address ||
            pc - region->second.address >= relocation.offset ||
            symbol == symbols.end() || symbol->second->section != SHN_UNDEF ||
            symbol->second->name != "__x86_return_thunk" ||
            relocation.addend != -4 ||
            (relocation.type != R_X86_64_PC32 &&
             relocation.type != R_X86_64_PLT32))
          continue;
        const auto &section = original.sections[relocation.section];
        const uint64_t offset = pc - region->second.address;
        const uint64_t field = relocation.offset - offset;
        if (!(section.flags & SHF_EXECINSTR) ||
            section.offset > original.bytes.size() ||
            section.size > original.bytes.size() - section.offset ||
            relocation.offset > section.size ||
            4 > section.size - relocation.offset ||
            field > 11 || // An x86 instruction has at most 15 bytes.
            original.bytes[section.offset + relocation.offset - 1] != 0xe9)
          continue;
        // Decode only this transfer. Its RELA displacement is independently
        // validated below; zero it to avoid following unrelocated bytes as a
        // local control-flow edge.
        std::array<unsigned char, 15> jump{};
        std::copy_n(original.bytes.data() + section.offset + offset,
                    size_t(field), jump.data());
        const auto decoded =
            ct_analyze_flow({jump.data(), size_t(field + 4)}, offset, offset);
        if (decoded.instructions.size() != 1 ||
            decoded.instructions.front().size != field + 4 ||
            !(decoded.instructions.front().flags & CT_FLOW_BRANCH) ||
            (decoded.instructions.front().flags &
             (CT_FLOW_CONDITIONAL | CT_FLOW_INDIRECT | CT_FLOW_CALL)))
          continue;
        matched = std::any_of(layout.fixups.begin(), layout.fixups.end(),
                              [&](const auto &fixup) {
                                return fixup.proven && fixup.width == 4 &&
                                       fixup.section == relocation.section &&
                                       fixup.offset == relocation.offset;
                              });
        if (matched)
          break;
      }
      if (!matched)
        return fail("kernel return override has no proven original thunk jump");
      layout.returns.push_back(pc - layout.image_base);
    }
  }
  return true;
}

bool ct_kernel_validate_decompile_proof(
    const ct_kernel_image &original, const std::vector<ct_kernel_site> &sites,
    const ct_kernel_decompile_layout &layout,
    const std::vector<ct_decompiled_instruction> &instructions,
    std::string &error) {
  error.clear();
  const auto fail = [&](const std::string &reason) {
    error = "invalid kernel decompile instruction proof: " + reason;
    return false;
  };
  if (instructions.empty())
    return fail("empty instruction inventory");
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_site *> boundaries;
  for (const auto &site : sites)
    if (!boundaries.emplace(std::make_pair(site.section, site.offset), &site)
             .second)
      return fail("duplicate original instruction boundary");
  for (uint64_t offset : layout.returns) {
    if (offset > UINT64_MAX - layout.image_base)
      return fail("kernel return override address overflows");
    const uint64_t pc = offset + layout.image_base;
    const ct_kernel_site *boundary = nullptr;
    for (const auto &region : layout.regions)
      if (pc >= region.address && pc - region.address < region.size) {
        const auto found =
            boundaries.find({region.section, pc - region.address});
        if (found != boundaries.end())
          boundary = found->second;
        break;
      }
    if (!boundary || boundary->original_size < 5 ||
        boundary->original_size > 15)
      return fail("kernel return override is not an original jump boundary");
  }
  std::set<uint64_t> seen;
  for (const auto &instruction : instructions) {
    if (!instruction.size || instruction.size > sizeof(instruction.bytes) ||
        instruction.offset > UINT64_MAX - layout.image_base ||
        !seen.insert(instruction.offset).second)
      return fail("invalid or duplicate instruction address");
    const uint64_t address = layout.image_base + instruction.offset;
    const ct_kernel_decompile_region *region = nullptr;
    for (const auto &candidate : layout.regions)
      if (address >= candidate.address &&
          address - candidate.address < candidate.size) {
        if (region)
          return fail("ambiguous instruction section");
        region = &candidate;
      }
    if (!region || region->section >= original.sections.size() ||
        !(original.sections[region->section].flags & SHF_EXECINSTR))
      return fail("instruction is outside original executable sections");
    const uint64_t offset = address - region->address;
    const auto found = boundaries.find({region->section, offset});
    if (found == boundaries.end() ||
        found->second->original_size != instruction.size)
      return fail("instruction does not match an original decoded boundary");
    const auto &section = original.sections[region->section];
    if (offset > section.size || instruction.size > section.size - offset ||
        section.offset > original.bytes.size() ||
        section.size > original.bytes.size() - section.offset)
      return fail("instruction exceeds original bytes");
    std::vector<unsigned char> expected(
        original.bytes.begin() + section.offset + offset,
        original.bytes.begin() + section.offset + offset + instruction.size);
    for (const auto &fixup : layout.fixups) {
      if (fixup.section != region->section ||
          fixup.offset >= offset + instruction.size ||
          (fixup.offset < offset && offset - fixup.offset >= fixup.width))
        continue;
      if (!fixup.proven)
        return fail(fixup.error.empty() ? "relocation is unproven"
                                        : fixup.error);
      if (fixup.offset < offset ||
          fixup.width > offset + instruction.size - fixup.offset)
        return fail("relocation crosses an instruction boundary");
      for (unsigned byte = 0; byte < fixup.width; ++byte)
        expected[fixup.offset - offset + byte] =
            uint8_t(fixup.value >> (8 * byte));
    }
    if (std::memcmp(instruction.bytes, expected.data(), expected.size()))
      return fail("instruction bytes differ outside proved relocation fields");
  }
  return true;
}
