#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string_view>
#include <utility>

#include <llvm-c/Disassembler.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCExpr.h>
#include <llvm/MC/MCFixup.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <elf.h>

#include "uapi/kctrace.h"

#include "cache.h"
#include "kernel_gate.h"
#include "kernel_object.h"
#include "kernel_policy.h"
#include "kernel_rewrite.h"

static constexpr size_t expanded_code_limit = 128 * 1024 * 1024;
static constexpr size_t expanded_instruction_limit = 1000000;
static constexpr size_t expanded_record_limit = 1000000;
static constexpr size_t noreturn_symbol_limit = 65536;
static constexpr size_t noreturn_symbol_bytes_limit = 16 * 1024 * 1024;

struct ct_kernel_rewrite_plan::Data {
  struct Instruction {
    ct_kernel_site site;
    uint64_t destination = 0;
    uint64_t address_target = 0;
    unsigned relative = 0, relative_size = 0;
    unsigned address_relative = 0;
    bool direct = false, relocated = false;
    int indirect_register = -1;
    bool terminal_trap = false;
    bool call = false, branch = false, conditional = false, returns = false;
    std::vector<unsigned char> code;
    bool relax(const unsigned char *begin, uint64_t length);
  };
  struct Section {
    std::vector<Instruction> instructions;
    uint64_t old_size = 0, size = 0;
  };
  std::map<uint32_t, Section> code;
  std::map<std::pair<uint32_t, uint32_t>, Elf64_Sym> original_symbols;
  std::string key;
  uint64_t site_count = 0, instruction_count = 0;
  bool restore(const ct_kernel_image &image,
               const std::vector<unsigned char> &cached,
               std::vector<ct_kernel_site> &sites);
  void store() const;
  bool address_boundaries() const;

  bool decode(const ct_kernel_image &image, std::vector<ct_kernel_site> &sites,
              std::string &error);
  bool matches(const std::vector<ct_kernel_site> &sites) const;
  bool emit_copies(const ct_kernel_image &image, const ct_kernel_policy &policy,
                   ct_kernel_copies &copies, std::string &error,
                   const std::vector<uint64_t> &timing_sites,
                   const std::vector<std::string> &noreturn_symbols,
                   ct_kernel_copy_failure *failure, bool single_full) const;
  bool emit(const ct_kernel_image &image,
            const std::vector<ct_kernel_site> &sites,
            std::vector<unsigned char> &output, std::string &error) const;
};

ct_kernel_rewrite_plan::ct_kernel_rewrite_plan() = default;
ct_kernel_rewrite_plan::~ct_kernel_rewrite_plan() = default;

bool ct_kernel_rewrite_plan::Data::Instruction::relax(
    const unsigned char *begin, uint64_t length) {
  // LLVM proves instruction identity before byte-level relaxation.
  if (length >= 5 && (begin[length - 5] == 0xe8 || begin[length - 5] == 0xe9)) {
    relative = length - 4;
    relative_size = 4;
  } else if (length >= 6 && begin[length - 6] == 0x0f &&
             (begin[length - 5] & 0xf0) == 0x80) {
    relative = length - 4;
    relative_size = 4;
  } else if (length == 2 && begin[0] == 0xeb) {
    code = {0xe9, 0, 0, 0, 0};
    relative = 1;
    relative_size = 1;
  } else if (length == 2 && (begin[0] & 0xf0) == 0x70) {
    code = {0x0f, uint8_t(0x80 | (begin[0] & 15)), 0, 0, 0, 0};
    relative = 1;
    relative_size = 1;
  } else if ((length == 2 || (length == 3 && begin[0] == 0x67)) &&
             begin[length - 2] >= 0xe0 && begin[length - 2] <= 0xe3) {
    // Preserve LOOP/J[ER]CXZ flags and counter width with a nearby
    // island.
    code[length - 1] = 2;
    code.insert(code.end(), {0xeb, 5, 0xe9, 0, 0, 0, 0});
    relative = length - 1;
    relative_size = 1;
  } else {
    return false;
  }
  return true;
}

bool ct_kernel_rewrite_plan::Data::restore(
    const ct_kernel_image &image, const std::vector<unsigned char> &cached,
    std::vector<ct_kernel_site> &sites) {
  // cache.cc checks the bounded checksum envelope and executable/dependency
  // identity. This schema additionally binds every restored recipe to the
  // unchanged input inventory and the byte transformations used by decode().
  static constexpr unsigned char magic[] = {'C', 'T', 'K', 'D',
                                            'E', 'C', '0', '2'};
  if (cached.size() < sizeof(magic) ||
      std::memcmp(cached.data(), magic, sizeof(magic)))
    return false;
  size_t offset = sizeof(magic);
  const auto field = [&](auto &value) {
    if (sizeof(value) > cached.size() - offset)
      return false;
    std::memcpy(&value, cached.data() + offset, sizeof(value));
    offset += sizeof(value);
    return true;
  };
  uint64_t section_count = 0, count = 0, probes = 0;
  if (!field(section_count) || !field(count) || !field(probes) || !count ||
      count > expanded_instruction_limit || probes > count || !section_count ||
      section_count > count || section_count > image.sections.size())
    return false;
  ct_kernel_object object(image);
  std::string error;
  if (!object.valid(error) || object.section_count() != image.sections.size())
    return false;
  std::map<uint32_t, std::vector<std::pair<uint64_t, uint64_t>>> functions;
  for (const auto &symbol : image.symbols) {
    const auto *table = object.section_content(symbol.table);
    if (!table || symbol.index >= table->size() / sizeof(Elf64_Sym) ||
        symbol.name == "kctrace_probe" ||
        symbol.name.compare(0, 9, "__ctrace_") == 0)
      return false;
    Elf64_Sym raw;
    std::memcpy(&raw, table->data() + symbol.index * sizeof(raw), sizeof(raw));
    if (!original_symbols
             .emplace(std::make_pair(symbol.table, symbol.index), raw)
             .second)
      return false;
    if (symbol.section && symbol.section < image.sections.size() &&
        (image.sections[symbol.section].flags & SHF_EXECINSTR) &&
        symbol.type == STT_FUNC && symbol.size &&
        symbol.name.compare(0, 6, "__pfx_") != 0) {
      if (symbol.offset > image.sections[symbol.section].size ||
          symbol.size > image.sections[symbol.section].size - symbol.offset)
        return false;
      functions[symbol.section].emplace_back(symbol.offset,
                                             symbol.offset + symbol.size);
    }
  }
  for (auto &[section, ranges] : functions) {
    std::sort(ranges.begin(), ranges.end());
    ranges.erase(std::unique(ranges.begin(), ranges.end()), ranges.end());
    for (size_t index = 1; index < ranges.size(); ++index)
      if (ranges[index].first < ranges[index - 1].second)
        return false;
  }
  std::map<uint32_t, std::map<uint64_t, const ct_kernel_relocation *>> fields;
  for (const auto &relocation : image.relocations) {
    if (relocation.section >= image.sections.size())
      return false;
    if (image.sections[relocation.section].name ==
        "__patchable_function_entries") {
      const auto symbol =
          original_symbols.find({relocation.symbol_table, relocation.symbol});
      if (symbol == original_symbols.end() || relocation.type != R_X86_64_64)
        return false;
      const __int128 entry =
          __int128(symbol->second.st_value) + relocation.addend;
      if (entry < 0 || entry > UINT64_MAX)
        return false;
      const auto &ranges = functions[symbol->second.st_shndx];
      const auto next = std::upper_bound(
          ranges.begin(), ranges.end(), uint64_t(entry),
          [](uint64_t pc, const auto &range) { return pc < range.first; });
      if (next != ranges.begin() && entry < std::prev(next)->second)
        return false;
    }
    if (relocation.type != R_X86_64_NONE &&
        !fields[relocation.section]
             .emplace(relocation.offset, &relocation)
             .second)
      return false;
  }
  uint64_t expanded_size = 0, actual_sections = 0;
  for (uint32_t index = 0; index < image.sections.size(); ++index) {
    const auto &source = image.sections[index];
    if (source.size &&
        (source.name == ".altinstructions" ||
         source.name == ".static_call_sites" || source.name == "__jump_table" ||
         source.name == "__bug_table" || source.name == ".noinstr.text" ||
         ((source.flags & SHF_EXECINSTR) && (source.flags & SHF_WRITE))))
      return false;
    if (!(source.flags & SHF_EXECINSTR) || !source.size)
      continue;
    uint32_t cached_section = 0;
    uint64_t rows = 0;
    if (!field(cached_section) || cached_section != index || !field(rows) ||
        !rows || rows > count - instruction_count || rows > source.size ||
        rows > (cached.size() - offset) / 17 ||
        source.offset > image.bytes.size() ||
        source.size > image.bytes.size() - source.offset)
      return false;
    ++actual_sections;
    auto &section = code[index];
    section.old_size = source.size;
    section.instructions.reserve(rows);
    const auto &ranges = functions[index];
    size_t function = 0;
    uint64_t pc = 0;
    auto relocation = fields[index].begin();
    for (uint64_t row = 0; row < rows; ++row) {
      Instruction instruction;
      uint8_t length = 0, emitted = 0, flags = 0, relative = 0,
              relative_size = 0;
      uint8_t reg = 0, address_relative = 0, reserved = 0;
      if (!field(length) || !field(emitted) || !field(flags) ||
          !field(relative) || !field(relative_size) || !field(reg) ||
          !field(address_relative) || !field(reserved) ||
          !field(instruction.destination) ||
          (address_relative && !field(instruction.address_target)) || !length ||
          length > 15 || !emitted || emitted > 15 ||
          emitted > cached.size() - offset || pc > source.size ||
          length > source.size - pc || reg > 16 || reserved)
        return false;
      while (function < ranges.size() && pc >= ranges[function].second)
        ++function;
      const bool body =
          function < ranges.size() && pc >= ranges[function].first;
      if ((body && length > ranges[function].second - pc) ||
          (!body && function < ranges.size() &&
           length > ranges[function].first - pc))
        return false;
      const auto *begin = image.bytes.data() + source.offset + pc;
      const bool endbr =
          length == 4 && !std::memcmp(begin, "\xf3\x0f\x1e\xfa", 4);
      instruction.site = {index,
                          pc,
                          section.size,
                          section.size + ((flags & 1) ? 7 : 0),
                          (flags & 1) ? ++site_count : 0,
                          length,
                          emitted,
                          bool(flags & 1)};
      instruction.direct = flags & 2;
      instruction.relocated = flags & 4;
      instruction.call = flags & 8;
      instruction.branch = flags & 16;
      instruction.conditional = flags & 32;
      instruction.returns = flags & 64;
      instruction.terminal_trap = flags & 128;
      instruction.indirect_register = int(reg) - 1;
      instruction.address_relative = address_relative;
      if (instruction.site.probe != (body && !endbr) ||
          (instruction.direct && !(instruction.call || instruction.branch)) ||
          (instruction.call && instruction.branch) ||
          (instruction.conditional &&
           !(instruction.branch && instruction.direct)) ||
          (instruction.returns &&
           (instruction.call || instruction.branch || instruction.direct)) ||
          (instruction.terminal_trap !=
           (length == 2 && begin[0] == 0x0f && begin[1] == 0x0b)) ||
          (instruction.terminal_trap &&
           (instruction.call || instruction.branch || instruction.returns)) ||
          (reg && (!instruction.branch || instruction.direct ||
                   instruction.conditional || instruction.call ||
                   instruction.returns)) ||
          (!instruction.site.probe && (flags & ~1U)))
        return false;
      instruction.code.assign(begin, begin + length);
      if (instruction.direct) {
        if (!instruction.relax(begin, length) ||
            instruction.relative != relative ||
            instruction.relative_size != relative_size)
          return false;
        int64_t displacement = 0;
        if (relative_size == 1)
          displacement = int8_t(begin[relative]);
        else {
          int32_t value;
          std::memcpy(&value, begin + relative, sizeof(value));
          displacement = value;
        }
        if (instruction.destination != pc + length + displacement)
          return false;
        const bool call = length >= 5 && begin[length - 5] == 0xe8;
        const bool conditional = !(length >= 5 && begin[length - 5] == 0xe9) &&
                                 !(length == 2 && begin[0] == 0xeb) && !call;
        if (instruction.call != call || instruction.branch == call ||
            instruction.conditional != conditional)
          return false;
      } else if (instruction.destination || relative || relative_size ||
                 instruction.relocated) {
        return false;
      }
      const bool address_encoding = length == 7 &&
                                    (begin[0] == 0x48 || begin[0] == 0x4c) &&
                                    begin[1] == 0x8d && (begin[2] & 0xc7) == 5;
      if (address_relative) {
        int32_t displacement;
        if (!address_encoding || address_relative != 3 ||
            !instruction.site.probe || instruction.direct || instruction.call ||
            instruction.branch || instruction.returns ||
            instruction.terminal_trap)
          return false;
        std::memcpy(&displacement, begin + 3, sizeof(displacement));
        const __int128 target = __int128(pc) + length + displacement;
        if (target < 0 || target >= source.size ||
            uint64_t(target) != instruction.address_target)
          return false;
      } else if (instruction.address_target) {
        return false;
      }
      if (reg) {
        // This is the cached register-JMP guard's exact encoding, not a
        // replacement instruction decoder. Unfamiliar prefixes cause a miss.
        if (length < 2 || begin[length - 2] != 0xff ||
            (begin[length - 1] & 0xf8) != 0xe0)
          return false;
        for (unsigned byte = 0; byte + 2 < length; ++byte)
          if ((begin[byte] < 0x40 || begin[byte] > 0x4f) &&
              begin[byte] != 0xf2 && begin[byte] != 0xf3 &&
              begin[byte] != 0x66 && begin[byte] != 0x67 &&
              begin[byte] != 0x2e && begin[byte] != 0x3e &&
              begin[byte] != 0x26 && begin[byte] != 0x36 &&
              begin[byte] != 0x64 && begin[byte] != 0x65)
            return false;
        const unsigned rex = length >= 3 && begin[length - 3] >= 0x40 &&
                                     begin[length - 3] <= 0x4f
                                 ? begin[length - 3]
                                 : 0;
        const unsigned encoded = (begin[length - 1] & 7) | ((rex & 1) << 3);
        const unsigned registers[] = {0, 2, 3,  1,  7,  6,  4,  5,
                                      8, 9, 10, 11, 12, 13, 14, 15};
        if (instruction.indirect_register != int(registers[encoded]))
          return false;
      }
      if (instruction.code.size() != emitted ||
          std::memcmp(instruction.code.data(), cached.data() + offset, emitted))
        return false;
      offset += emitted;
      bool relocated = false;
      bool address_relocated = false;
      uint64_t previous_end = pc;
      while (relocation != fields[index].end() &&
             relocation->first < pc + length) {
        const auto &field = *relocation->second;
        const unsigned width =
            field.type == R_X86_64_64 || field.type == R_X86_64_PC64 ? 8
            : field.type == R_X86_64_PC32 || field.type == R_X86_64_PLT32 ||
                    field.type == R_X86_64_32 || field.type == R_X86_64_32S
                ? 4
                : 0;
        if (!width || field.offset < previous_end ||
            width > pc + length - field.offset)
          return false;
        if (instruction.direct) {
          if (field.offset != pc + relative || relative_size != 4)
            return false;
          relocated = true;
        }
        if (address_relative)
          return false;
        address_relocated |= address_encoding && field.offset == pc + 3 &&
                             field.type == R_X86_64_PC32;
        previous_end = field.offset + width;
        ++relocation;
      }
      if (instruction.relocated != relocated ||
          (address_encoding && !address_relocated && !address_relative))
        return false;
      section.size = instruction.site.operation + emitted;
      if (section.size > expanded_code_limit - expanded_size)
        return false;
      sites.push_back(instruction.site);
      section.instructions.push_back(std::move(instruction));
      ++instruction_count;
      pc += length;
    }
    if (pc != source.size || relocation != fields[index].end())
      return false;
    expanded_size += section.size;
  }
  return actual_sections == section_count && instruction_count == count &&
         site_count == probes && offset == cached.size() &&
         address_boundaries();
}

bool ct_kernel_rewrite_plan::Data::address_boundaries() const {
  for (const auto &[index, section] : code)
    for (const auto &instruction : section.instructions) {
      if (!instruction.address_relative)
        continue;
      const auto target = std::lower_bound(
          section.instructions.begin(), section.instructions.end(),
          instruction.address_target, [](const auto &row, uint64_t offset) {
            return row.site.offset < offset;
          });
      if (target == section.instructions.end() ||
          target->site.offset != instruction.address_target)
        return false;
    }
  return true;
}

void ct_kernel_rewrite_plan::Data::store() const {
  std::vector<unsigned char> cached{'C', 'T', 'K', 'D', 'E', 'C', '0', '2'};
  const auto field = [&](const auto &value) {
    const auto *begin = reinterpret_cast<const unsigned char *>(&value);
    cached.insert(cached.end(), begin, begin + sizeof(value));
  };
  field(uint64_t(code.size()));
  field(instruction_count);
  field(site_count);
  for (const auto &[index, section] : code) {
    field(index);
    field(uint64_t(section.instructions.size()));
    for (const auto &instruction : section.instructions) {
      field(instruction.site.original_size);
      field(instruction.site.emitted_size);
      field(uint8_t(instruction.site.probe | (instruction.direct << 1) |
                    (instruction.relocated << 2) | (instruction.call << 3) |
                    (instruction.branch << 4) | (instruction.conditional << 5) |
                    (instruction.returns << 6) |
                    (instruction.terminal_trap << 7)));
      field(uint8_t(instruction.relative));
      field(uint8_t(instruction.relative_size));
      field(uint8_t(instruction.indirect_register + 1));
      field(uint8_t(instruction.address_relative));
      field(uint8_t(0));
      field(instruction.destination);
      if (instruction.address_relative)
        field(instruction.address_target);
      cached.insert(cached.end(), instruction.code.begin(),
                    instruction.code.end());
    }
  }
  ct_cache_write("kernel-decoded", key, cached);
}

bool ct_kernel_rewrite_plan::Data::decode(const ct_kernel_image &image,
                                          std::vector<ct_kernel_site> &sites,
                                          std::string &error) {
  sites.clear();
  error.clear();
  {
    ct_kernel_object object(image);
    if (!object.valid(error))
      return false;
  }
  const auto fail = [&](const std::string &reason) {
    error = reason;
    sites.clear();
    return false;
  };
  for (const auto &section : image.sections)
    if (section.size &&
        (section.name == ".altinstructions" ||
         section.name == ".static_call_sites" ||
         section.name == "__jump_table" || section.name == "__bug_table" ||
         section.name == ".noinstr.text" ||
         ((section.flags & SHF_EXECINSTR) && (section.flags & SHF_WRITE))))
      return fail("code expansion requires a dedicated handler for " +
                  section.name);

  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();
  llvm::Triple triple("x86_64-pc-linux-gnu");
  const auto *target = llvm::TargetRegistry::lookupTarget(triple.str(), error);
  if (!target)
    return false;
  llvm::MCTargetOptions options;
  std::unique_ptr<llvm::MCRegisterInfo> registers(
      target->createMCRegInfo(triple.str()));
  if (!registers)
    return fail("x86 register metadata unavailable");
  std::unique_ptr<llvm::MCAsmInfo> assembly(
      target->createMCAsmInfo(*registers, triple.str(), options));
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget(
      target->createMCSubtargetInfo(triple.str(), "generic", ""));
  std::unique_ptr<llvm::MCInstrInfo> instructions(target->createMCInstrInfo());
  if (!assembly || !subtarget || !instructions)
    return fail("x86 instruction metadata unavailable");
  llvm::MCContext context(triple, assembly.get(), registers.get(),
                          subtarget.get());
  std::unique_ptr<llvm::MCDisassembler> decoder(
      target->createMCDisassembler(*subtarget, context));
  std::unique_ptr<llvm::MCInstrAnalysis> analysis(
      target->createMCInstrAnalysis(instructions.get()));
  std::unique_ptr<llvm::MCCodeEmitter> encoder(
      target->createMCCodeEmitter(*instructions, context));
  if (!decoder || !analysis || !encoder)
    return fail("x86 instruction analysis unavailable");
  const auto *memory_symbol = llvm::MCSymbolRefExpr::create(
      context.getOrCreateSymbol(".Lctrace_memory_displacement"), context);

  for (const auto &symbol : image.symbols) {
    if (symbol.name == "kctrace_probe" ||
        symbol.name.compare(0, 9, "__ctrace_") == 0)
      return fail("module already contains reserved ctrace probe symbols");
    const auto &table = image.sections[symbol.table];
    Elf64_Sym raw;
    std::memcpy(&raw,
                image.bytes.data() + table.offset + symbol.index * sizeof(raw),
                sizeof(raw));
    original_symbols.emplace(std::make_pair(symbol.table, symbol.index), raw);
  }
  std::map<uint32_t, std::vector<uint64_t>> patchable_entries;
  for (const auto &relocation : image.relocations) {
    if (image.sections[relocation.section].name !=
        "__patchable_function_entries")
      continue;
    const auto symbol =
        original_symbols.find({relocation.symbol_table, relocation.symbol});
    if (symbol == original_symbols.end() || relocation.type != R_X86_64_64)
      return fail("unsupported patchable function entry relocation");
    const __int128 offset =
        __int128(symbol->second.st_value) + relocation.addend;
    if (offset < 0 || offset > UINT64_MAX)
      return fail("invalid patchable function entry offset");
    patchable_entries[symbol->second.st_shndx].push_back(uint64_t(offset));
  }
  std::map<uint32_t, std::vector<const ct_kernel_relocation *>>
      relocation_fields;
  for (const auto &relocation : image.relocations)
    relocation_fields[relocation.section].push_back(&relocation);
  for (auto &[section, fields] : relocation_fields)
    std::sort(fields.begin(), fields.end(),
              [](const auto *left, const auto *right) {
                return left->offset < right->offset;
              });
  size_t expanded_size = 0, instruction_count = 0;
  for (uint32_t index = 0; index < image.sections.size(); ++index) {
    const auto &source = image.sections[index];
    if (!(source.flags & SHF_EXECINSTR) || !source.size)
      continue;
    auto &section = code[index];
    const auto &fields = relocation_fields[index];
    section.old_size = source.size;
    std::vector<std::pair<uint64_t, uint64_t>> functions;
    for (const auto &symbol : image.symbols)
      if (symbol.section != SHN_UNDEF && symbol.section < SHN_LORESERVE &&
          symbol.section == index && symbol.type == STT_FUNC && symbol.size &&
          symbol.name.compare(0, 6, "__pfx_") != 0)
        functions.emplace_back(symbol.offset, symbol.offset + symbol.size);
    std::sort(functions.begin(), functions.end());
    functions.erase(std::unique(functions.begin(), functions.end()),
                    functions.end());
    for (size_t i = 1; i < functions.size(); ++i)
      if (functions[i].first < functions[i - 1].second)
        return fail("overlapping function extents in " + source.name);
    for (uint64_t entry : patchable_entries[index]) {
      const auto next =
          std::upper_bound(functions.begin(), functions.end(), entry,
                           [](uint64_t pc, const auto &function) {
                             return pc < function.first;
                           });
      if (next != functions.begin() && entry < std::prev(next)->second)
        return fail(
            "in-body patchable function entry needs an intact slot handler");
    }
    size_t function = 0;
    for (uint64_t offset = 0; offset < source.size;) {
      if (++instruction_count > expanded_instruction_limit)
        return fail("expanded kernel instruction inventory exceeds size limit");
      while (function < functions.size() &&
             offset >= functions[function].second)
        ++function;
      const bool body =
          function < functions.size() && offset >= functions[function].first;
      llvm::MCInst decoded;
      uint64_t length = 0, prefix_size = 0;
      for (;;) {
        uint64_t part = 0;
        prefix_size = length;
        decoded.clear();
        if (length >= 15 || offset + length >= source.size ||
            decoder->getInstruction(
                decoded, part,
                {image.bytes.data() + source.offset + offset + length,
                 size_t(std::min<uint64_t>(15 - length,
                                           source.size - offset - length))},
                offset + length,
                llvm::nulls()) != llvm::MCDisassembler::Success ||
            !part || part > 15 - length)
          return fail("undecodable instruction in " + source.name + "+" +
                      std::to_string(offset));
        length += part;
        // LLVM can expose LOCK/REP as standalone prefix pseudo-instructions.
        // A probe must never split a prefix from the operation it modifies.
        if (!instructions->getName(decoded.getOpcode()).ends_with("_PREFIX"))
          break;
      }
      const auto opcode = instructions->getName(decoded.getOpcode());
      // Ordinary kernel-call ABI is the first supported probe context. A
      // helper CALL would consume interrupt shadows or execute with altered
      // direction/address-space state in these sequences. Reject them rather
      // than hiding objtool diagnostics with artificial annotations.
      if (opcode == "STD" || opcode == "STI" || opcode.starts_with("POPF") ||
          opcode == "STAC" || opcode == "CLAC" || opcode == "SWAPGS" ||
          opcode.starts_with("WRMSR") || opcode.starts_with("WRGSBASE") ||
          opcode.starts_with("WRFSBASE") || opcode.starts_with("POPGS") ||
          opcode.starts_with("POPSS") || opcode.starts_with("POPDS") ||
          opcode.starts_with("POPES") || opcode.starts_with("LSS") ||
          opcode.starts_with("LGS") || opcode.starts_with("LFS") ||
          opcode.starts_with("LDS") || opcode.starts_with("LES") ||
          opcode == "MOV64cr" || opcode == "MOV32cr" || opcode == "WRPKRU" ||
          opcode.starts_with("IRET") || opcode.starts_with("SYSRET") ||
          opcode == "SYSENTER" || opcode.starts_with("SYSEXIT") ||
          opcode == "SYSCALL")
        return fail("probe ABI does not support " + opcode.str() + " in " +
                    source.name);
      const auto segment = [&](unsigned reg) {
        const std::string_view name = registers->getName(reg);
        return name == "CS" || name == "DS" || name == "ES" || name == "SS" ||
               name == "FS" || name == "GS";
      };
      const auto &description = instructions->get(decoded.getOpcode());
      if (std::any_of(description.implicit_defs().begin(),
                      description.implicit_defs().end(), segment))
        return fail("probe ABI does not support implicit segment updates");
      const unsigned definitions = description.getNumDefs();
      for (unsigned operand = 0;
           operand < definitions && operand < decoded.getNumOperands();
           ++operand)
        if (decoded.getOperand(operand).isReg() &&
            segment(decoded.getOperand(operand).getReg()))
          return fail("probe ABI does not support segment-register updates");
      const bool padding = opcode.starts_with("NOOP") || opcode == "INT3";
      if (!body && !padding)
        return fail("unclassified executable bytes in " + source.name + "+" +
                    std::to_string(offset));
      if ((body && offset + length > functions[function].second) ||
          (!body && function < functions.size() &&
           offset + length > functions[function].first))
        return fail("function boundary splits an instruction in " +
                    source.name);
      Data::Instruction instruction;
      instruction.site.section = index;
      instruction.site.offset = offset;
      instruction.site.original_size = length;
      // Preserve IBT landing pads and compiler patchable-entry padding.
      instruction.site.probe = body && opcode != "ENDBR64";
      if (instruction.site.probe)
        instruction.site.id = ++site_count;
      const auto *begin = image.bytes.data() + source.offset + offset;
      instruction.code.assign(begin, begin + length);
      const auto relocation_begin = std::lower_bound(
          fields.begin(), fields.end(), offset,
          [](const auto *field, uint64_t pc) { return field->offset < pc; });
      const auto relocation_end = std::lower_bound(
          relocation_begin, fields.end(), offset + length,
          [](const auto *field, uint64_t pc) { return field->offset < pc; });
      uint64_t previous_end = offset;
      for (auto field = relocation_begin; field != relocation_end; ++field) {
        unsigned width = 0;
        switch ((*field)->type) {
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
          return fail("unsupported kernel code relocation in " + source.name);
        }
        if ((*field)->offset < previous_end ||
            width > offset + length - (*field)->offset)
          return fail("code relocation overlaps another field or instruction");
        previous_end = (*field)->offset + width;
      }
      uint64_t destination = 0;
      if (opcode == "JMP64r" && decoded.getNumOperands() == 1 &&
          decoded.getOperand(0).isReg()) {
        const std::string_view name =
            registers->getName(decoded.getOperand(0).getReg());
        const char *names[] = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI",
                               "RBP", "RSP", "R8",  "R9",  "R10", "R11",
                               "R12", "R13", "R14", "R15"};
        for (unsigned reg = 0; reg < 16; ++reg)
          if (name == names[reg])
            instruction.indirect_register = reg;
      }
      instruction.call = analysis->isCall(decoded);
      instruction.branch = analysis->isBranch(decoded);
      instruction.conditional = analysis->isConditionalBranch(decoded);
      instruction.returns = analysis->isReturn(decoded);
      // LLVM's UD2 descriptor is not marked Barrier. Its exact decoded
      // architectural encoding still proves that ordinary execution cannot
      // fall through; a fault handler may recover without completing a RET.
      instruction.terminal_trap = opcode == "TRAP" && length == 2 &&
                                  begin[0] == 0x0f && begin[1] == 0x0b;
      instruction.direct =
          (instruction.branch || instruction.call) &&
          analysis->evaluateBranch(decoded, offset, length, destination);
      instruction.destination = destination;
      if (instruction.direct) {
        // Rel32 is always in the last four bytes of these direct transfers.
        if (!instruction.relax(begin, length))
          return fail("unsupported direct branch encoding in " + source.name);
        for (auto field = relocation_begin; field != relocation_end; ++field) {
          if ((*field)->offset != offset + instruction.relative ||
              instruction.relative_size != 4)
            return fail("unsupported branch relocation in " + source.name);
          instruction.relocated = true;
        }
      }
      // Non-relocated RIP-relative memory references require a distinct data
      // proof. Do not silently preserve a stale displacement after expansion.
      for (unsigned operand_index = 0; operand_index < decoded.getNumOperands();
           ++operand_index) {
        const auto &operand = decoded.getOperand(operand_index);
        if (operand.isReg() &&
            std::strcmp(registers->getName(operand.getReg()), "EIP") == 0)
          return fail(
              "32-bit instruction-pointer addressing is unsupported in " +
              source.name);
        if (operand.isReg() &&
            std::strcmp(registers->getName(operand.getReg()), "RIP") == 0) {
          // X86 MC memory operands are base, scale, index, displacement,
          // segment. Encoding a symbolic displacement identifies its field
          // even when the instruction also has a trailing immediate operand.
          if (operand_index + 4 >= decoded.getNumOperands() ||
              !decoded.getOperand(operand_index + 1).isImm() ||
              !decoded.getOperand(operand_index + 2).isReg() ||
              !decoded.getOperand(operand_index + 3).isImm() ||
              !decoded.getOperand(operand_index + 4).isReg())
            return fail("unsupported x86 memory operand layout");
          llvm::MCInst symbolic = decoded;
          symbolic.getOperand(operand_index + 3) =
              llvm::MCOperand::createExpr(memory_symbol);
          llvm::SmallVector<char, 16> encoded;
          llvm::SmallVector<llvm::MCFixup, 1> fixups;
          encoder->encodeInstruction(symbolic, encoded, fixups, *subtarget);
          if (encoded.size() + prefix_size != length || fixups.size() != 1 ||
              fixups[0].getOffset() > encoded.size() ||
              encoded.size() - fixups[0].getOffset() < 4)
            return fail("x86 memory displacement encoding is not proven");
          const unsigned field = fixups[0].getOffset();
          for (size_t byte = 0; byte < encoded.size(); ++byte)
            if ((byte < field || byte >= field + 4) &&
                uint8_t(encoded[byte]) != begin[prefix_size + byte])
              return fail("x86 memory encoding changed outside displacement");
          const bool relocated = std::any_of(
              relocation_begin, relocation_end, [&](const auto *relocation) {
                return relocation->offset == offset + prefix_size + field &&
                       relocation->type == R_X86_64_PC32;
              });
          if (!relocated) {
            // LEA computes an address; it does not read memory. Accept only
            // the exact 64-bit RIP+rel32 form whose target remains a proved
            // instruction boundary in this executable section.
            if (opcode != "LEA64r" || prefix_size || length != 7 ||
                field != 3 || operand_index != 1 ||
                decoded.getNumOperands() != 6 ||
                decoded.getOperand(operand_index + 1).getImm() != 1 ||
                decoded.getOperand(operand_index + 2).getReg() ||
                decoded.getOperand(operand_index + 4).getReg() ||
                (begin[0] != 0x48 && begin[0] != 0x4c) || begin[1] != 0x8d ||
                (begin[2] & 0xc7) != 5 || relocation_begin != relocation_end)
              return fail("unrelocated RIP-relative memory operand in " +
                          source.name);
            int32_t displacement;
            std::memcpy(&displacement, begin + field, sizeof(displacement));
            const __int128 target = __int128(offset) + length + displacement;
            if (target < 0 || target >= source.size)
              return fail(
                  "RIP-relative code address leaves its executable section");
            instruction.address_relative = field;
            instruction.address_target = uint64_t(target);
          }
        }
      }
      instruction.site.entry = section.size;
      instruction.site.operation =
          section.size + (instruction.site.probe ? 7 : 0);
      instruction.site.emitted_size = instruction.code.size();
      section.size = instruction.site.operation + instruction.code.size();
      if (section.size > expanded_code_limit - expanded_size)
        return fail("expanded kernel code exceeds size limit");
      sites.push_back(instruction.site);
      section.instructions.push_back(std::move(instruction));
      offset += length;
    }
    expanded_size += section.size;
  }
  if (code.empty())
    return fail("module has no executable code");
  if (!address_boundaries())
    return fail("RIP-relative code address splits an instruction");
  this->instruction_count = instruction_count;
  return true;
}

bool ct_kernel_rewrite_plan::Data::emit(
    const ct_kernel_image &image, const std::vector<ct_kernel_site> &sites,
    std::vector<unsigned char> &output, std::string &error) const {
  output.clear();
  ct_kernel_object object(image);
  if (!object.valid(error))
    return false;
  const auto fail = [&](const std::string &reason) {
    error = reason;
    output.clear();
    return false;
  };

  const auto containing = [&](uint32_t section,
                              uint64_t offset) -> const Instruction * {
    const auto found = code.find(section);
    if (found == code.end())
      return nullptr;
    const auto &rows = found->second.instructions;
    auto next = std::upper_bound(
        rows.begin(), rows.end(), offset,
        [](uint64_t pc, const auto &row) { return pc < row.site.offset; });
    if (next == rows.begin())
      return nullptr;
    --next;
    return offset < next->site.offset + next->site.original_size ? &*next
                                                                 : nullptr;
  };
  const auto translate = [&](uint32_t section, uint64_t offset, bool operation,
                             uint64_t &result) {
    const auto found = code.find(section);
    if (found == code.end()) {
      result = offset;
      return section < image.sections.size() &&
             offset <= image.sections[section].size;
    }
    if (offset == found->second.old_size) {
      result = found->second.size;
      return true;
    }
    const auto *row = containing(section, offset);
    if (!row)
      return false;
    const uint64_t delta = offset - row->site.offset;
    if (delta && row->code.size() != row->site.original_size)
      return false;
    result = delta || operation ? row->site.operation + delta : row->site.entry;
    return true;
  };

  uint32_t symbol_table = 0;
  for (const auto &symbol : image.symbols) {
    const auto &table = image.sections[symbol.table];
    Elf64_Sym raw;
    std::memcpy(&raw,
                image.bytes.data() + table.offset + symbol.index * sizeof(raw),
                sizeof(raw));
    if (symbol_table && symbol_table != symbol.table)
      return fail(
          "multiple kernel symbol tables require separate probe imports");
    symbol_table = symbol.table;
    if (symbol.section == SHN_UNDEF || symbol.section >= SHN_LORESERVE ||
        !code.count(symbol.section))
      continue;
    uint64_t start = 0, end = 0;
    if (!translate(symbol.section, raw.st_value, false, start) ||
        !translate(symbol.section, raw.st_value + raw.st_size, false, end))
      return fail("symbol points inside a relaxed instruction: " + symbol.name);
    raw.st_value = start;
    raw.st_size = end - start;
    if (!object.replace_symbol(symbol.table, symbol.index, raw, error))
      return false;
  }
  if (!symbol_table)
    return fail("kernel symbol table missing");
  uint32_t probe_symbol = 0;
  Elf64_Sym probe{};
  probe.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
  if (!object.append_symbol(symbol_table, "kctrace_probe", probe, probe_symbol,
                            error))
    return false;

  for (const auto &[index, section] : code) {
    std::vector<unsigned char> bytes;
    bytes.reserve(section.size);
    for (const auto &row : section.instructions) {
      if (row.site.probe) {
        // Kernel call-depth/return thunks may alter flags. Save them outside
        // the CALL/RET boundary, including the kernel's own thunk code.
        bytes.insert(bytes.end(), {0x9c, 0xe8, 0, 0, 0, 0, 0x9d});
      }
      bytes.insert(bytes.end(), row.code.begin(), row.code.end());
      if (row.direct && !row.relocated) {
        uint64_t target_offset = 0;
        const auto *destination = containing(index, row.destination);
        if (!destination || destination->site.offset != row.destination ||
            !translate(index, row.destination, false, target_offset))
          return fail("direct branch leaves classified instruction boundaries");
        const int64_t displacement =
            int64_t(target_offset) -
            int64_t(row.site.operation + row.code.size());
        if (displacement < INT32_MIN || displacement > INT32_MAX)
          return fail("expanded direct branch exceeds rel32 range");
        const int32_t value = displacement;
        std::memcpy(bytes.data() + bytes.size() - 4, &value, sizeof(value));
      }
      if (row.address_relative) {
        uint64_t target_offset = 0;
        if (!translate(index, row.address_target, false, target_offset))
          return fail("RIP-relative code address has no expanded entry");
        const __int128 displacement =
            __int128(target_offset) - row.site.operation - row.code.size();
        if (displacement < INT32_MIN || displacement > INT32_MAX)
          return fail("expanded RIP-relative code address exceeds rel32");
        const int32_t value = displacement;
        std::memcpy(bytes.data() + row.site.operation + row.address_relative,
                    &value, sizeof(value));
      }
    }
    if (!object.replace_section(index, bytes, error))
      return false;
  }

  // Metadata relocations identify either an entry boundary or the actual
  // original instruction (patch sites and faulting exception-table entries).
  for (uint32_t table = 0; table < image.sections.size(); ++table) {
    const auto &relocations = image.sections[table];
    if (relocations.type != SHT_RELA)
      continue;
    const auto &owner = image.sections[relocations.info];
    for (uint32_t index = 0; index < relocations.size / sizeof(Elf64_Rela);
         ++index) {
      Elf64_Rela raw;
      std::memcpy(&raw,
                  image.bytes.data() + relocations.offset + index * sizeof(raw),
                  sizeof(raw));
      const auto symbol = original_symbols.find(
          {relocations.link, uint32_t(ELF64_R_SYM(raw.r_info))});
      if (symbol == original_symbols.end())
        return fail("relocation symbol is missing");
      const auto &target_symbol = symbol->second;
      const bool pc_relative = ELF64_R_TYPE(raw.r_info) == R_X86_64_PC32 ||
                               ELF64_R_TYPE(raw.r_info) == R_X86_64_PLT32 ||
                               ELF64_R_TYPE(raw.r_info) == R_X86_64_PC64;
      uint64_t new_field = raw.r_offset;
      int64_t old_bias = 0, new_bias = 0;
      if (code.count(relocations.info)) {
        const auto *row = containing(relocations.info, raw.r_offset);
        if (!row || !translate(relocations.info, raw.r_offset, true, new_field))
          return fail("relocation field overlaps a relaxed instruction");
        if (pc_relative) {
          old_bias = row->site.offset + row->site.original_size - raw.r_offset;
          new_bias = row->site.operation + row->code.size() - new_field;
        }
      }
      if (target_symbol.st_shndx < SHN_LORESERVE &&
          code.count(target_symbol.st_shndx)) {
        const __int128 old_target =
            __int128(target_symbol.st_value) + raw.r_addend + old_bias;
        if (old_target < 0 || old_target > UINT64_MAX)
          return fail("code relocation target is outside its section");
        const bool exact_instruction =
            owner.name == ".return_sites" || owner.name == ".call_sites" ||
            owner.name == ".retpoline_sites" || owner.name == ".smp_locks" ||
            owner.name == "__mcount_loc" || owner.name == "__kcfi_traps" ||
            owner.name == ".ibt_endbr_seal" || owner.name == ".cfi_sites" ||
            (owner.name == "__ex_table" && raw.r_offset % 12 == 0);
        uint64_t target_offset = 0, symbol_offset = 0;
        if (!translate(target_symbol.st_shndx, uint64_t(old_target),
                       exact_instruction, target_offset) ||
            !translate(target_symbol.st_shndx, target_symbol.st_value, false,
                       symbol_offset))
          return fail(
              "metadata relocation points inside a relaxed instruction");
        const __int128 addend =
            __int128(target_offset) - symbol_offset - new_bias;
        if (addend < INT64_MIN || addend > INT64_MAX)
          return fail("rewritten relocation addend overflows");
        raw.r_addend = int64_t(addend);
      } else if (pc_relative) {
        const __int128 addend = __int128(raw.r_addend) + old_bias - new_bias;
        if (addend < INT64_MIN || addend > INT64_MAX)
          return fail("rewritten external relocation addend overflows");
        raw.r_addend = int64_t(addend);
      }
      raw.r_offset = new_field;
      if (!object.replace_relocation(table, index, raw, error))
        return false;
    }
  }
  for (const auto &site : sites)
    if (site.probe) {
      Elf64_Rela relocation{};
      relocation.r_offset = site.entry + 2;
      relocation.r_info = ELF64_R_INFO(probe_symbol, R_X86_64_PLT32);
      relocation.r_addend = -4;
      if (!object.add_relocation(site.section, symbol_table, relocation, error))
        return false;
    }

  // The loader resolves these immutable addresses. The runtime receives no
  // original instruction bytes and performs no decoding or code generation.
  static_assert(sizeof(kctrace_probe_site) == 32);
  std::vector<unsigned char> records(site_count * sizeof(kctrace_probe_site));
  for (const auto &site : sites)
    if (site.probe) {
      kctrace_probe_site record{};
      record.site_id = site.id;
      record.type = KCTRACE_EVENT_INSTRUCTION_BEFORE;
      std::memcpy(records.data() + (site.id - 1) * sizeof(record), &record,
                  sizeof(record));
    }
  // Registration retains its own core-only table. The loader can release
  // this original full table and count together with the target's init code.
  const uint32_t table_section =
      object.add_section(".init.rodata.ctrace_sites", SHT_PROGBITS, SHF_ALLOC,
                         8, sizeof(kctrace_probe_site), 0, 0, records, error);
  if (!table_section)
    return false;
  if (table_section >= SHN_LORESERVE)
    return fail("probe table requires unsupported extended section indexes");
  Elf64_Sym table_symbol{};
  table_symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
  table_symbol.st_other = STV_HIDDEN;
  table_symbol.st_shndx = table_section;
  table_symbol.st_size = records.size();
  uint32_t appended = 0;
  if (!object.append_symbol(symbol_table, "__ctrace_sites", table_symbol,
                            appended, error))
    return false;
  std::map<uint32_t, uint32_t> anchors;
  for (const auto &symbol : image.symbols)
    if (symbol.table == symbol_table && symbol.type == STT_SECTION &&
        !symbol.offset && code.count(symbol.section))
      anchors.emplace(symbol.section, symbol.index);
  for (const auto &[index, section] : code) {
    if (anchors.count(index))
      continue;
    if (index >= SHN_LORESERVE)
      return fail("probe address requires unsupported extended section index");
    Elf64_Sym anchor{};
    anchor.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
    anchor.st_other = STV_HIDDEN;
    anchor.st_shndx = index;
    if (!object.append_symbol(symbol_table,
                              "__ctrace_section_" + std::to_string(index),
                              anchor, appended, error))
      return false;
    anchors[index] = appended;
  }
  for (const auto &site : sites)
    if (site.probe)
      for (size_t field : {offsetof(kctrace_probe_site, return_pc),
                           offsetof(kctrace_probe_site, pc)}) {
        Elf64_Rela relocation{};
        relocation.r_offset =
            (site.id - 1) * sizeof(kctrace_probe_site) + field;
        relocation.r_info = ELF64_R_INFO(anchors.at(site.section), R_X86_64_64);
        relocation.r_addend =
            site.operation - (field == offsetof(kctrace_probe_site, return_pc));
        if (!object.add_relocation(table_section, symbol_table, relocation,
                                   error))
          return false;
      }
  std::vector<unsigned char> count_bytes(sizeof(site_count));
  std::memcpy(count_bytes.data(), &site_count, sizeof(site_count));
  const uint32_t count_section =
      object.add_section(".init.rodata.ctrace_count", SHT_PROGBITS, SHF_ALLOC,
                         8, sizeof(site_count), 0, 0, count_bytes, error);
  if (!count_section)
    return false;
  if (count_section >= SHN_LORESERVE)
    return fail("probe count requires unsupported extended section indexes");
  table_symbol.st_shndx = count_section;
  table_symbol.st_size = sizeof(site_count);
  if (!object.append_symbol(symbol_table, "__ctrace_site_count", table_symbol,
                            appended, error))
    return false;
  return object.serialize(output, error);
}

bool ct_kernel_rewrite_plan::Data::emit_copies(
    const ct_kernel_image &image, const ct_kernel_policy &policy,
    ct_kernel_copies &copies, std::string &error,
    const std::vector<uint64_t> &timing_sites,
    const std::vector<std::string> &noreturn_symbols,
    ct_kernel_copy_failure *failure, bool single_full) const {
  copies = {};
  error.clear();
  copies.single_full = single_full;
  const auto fail = [&](const std::string &reason,
                        ct_kernel_copy_failure kind =
                            ct_kernel_copy_failure::invalid) {
    copies = {};
    error = reason;
    if (failure)
      *failure = kind;
    return false;
  };
  if (policy.functions.empty() || policy.paths.empty() ||
      policy.inlines.empty() || policy.sites.size() != site_count + 1 ||
      policy.functions.size() > expanded_instruction_limit + 1 ||
      policy.paths.size() > expanded_instruction_limit + 1 ||
      policy.inlines.size() > expanded_instruction_limit + 1 ||
      timing_sites.size() > site_count)
    return fail("copy policy does not cover the original instruction IDs");
  std::set<uint64_t> timing;
  for (uint64_t id : timing_sites) {
    if (!id || id > site_count)
      return fail("copy timing boundary has no original probe identity");
    timing.insert(id);
  }
  if (noreturn_symbols.size() > noreturn_symbol_limit)
    return fail("selected kernel noreturn symbol inventory exceeds its bound");
  std::set<std::string_view> noreturn;
  size_t noreturn_bytes = 0;
  for (const auto &name : noreturn_symbols) {
    if (name.empty() ||
        name.size() > noreturn_symbol_bytes_limit - noreturn_bytes ||
        (name.front() >= '0' && name.front() <= '9') ||
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU"
                               "VWXYZ0123456789_") != std::string::npos ||
        !noreturn.insert(name).second)
      return fail("invalid or duplicate selected kernel noreturn symbol");
    noreturn_bytes += name.size();
  }

  // Recoverable copy limitations must never hide malformed compiled policy.
  // Validate the complete decision pools before checking feature support.
  if (policy.sites[0].function || policy.sites[0].path ||
      policy.paths[0].parent || policy.paths[0].scope)
    return fail("copy policy contains an invalid zero sentinel");
  for (size_t index = 0; index < policy.functions.size(); ++index) {
    const auto &function = policy.functions[index];
    if (function.mode < KCTRACE_POLICY_SKIP ||
        function.mode > KCTRACE_POLICY_RECURSE)
      return fail("copy policy has an invalid function mode");
    for (unsigned flags = 0; flags < 8; ++flags) {
      const auto expected = index ? kctrace_policy_encode(kctrace_policy_enter(
                                        kctrace_policy_decode(flags),
                                        function.mode, function.within))
                                  : 0;
      if (function.states[flags] != expected)
        return fail("copy policy function decisions are inconsistent");
    }
  }
  for (size_t index = 0; index < policy.inlines.size(); ++index)
    if (policy.inlines[index].mode < KCTRACE_POLICY_SKIP ||
        policy.inlines[index].mode > KCTRACE_POLICY_RECURSE)
      return fail("copy policy has an invalid inline mode");
  for (size_t index = 0; index < policy.paths.size(); ++index) {
    const auto &path = policy.paths[index];
    if (index && (path.parent >= index || !path.scope ||
                  path.scope >= policy.inlines.size()))
      return fail("copy policy has an invalid inline path");
    for (unsigned flags = 0; flags < 8; ++flags) {
      unsigned expected = 0;
      if (index) {
        const auto &scope = policy.inlines[path.scope];
        const auto parent =
            path.parent ? policy.paths[path.parent].states[flags] : flags;
        expected = kctrace_policy_encode(kctrace_policy_enter(
            kctrace_policy_decode(parent), scope.mode, scope.within));
      }
      if (path.states[flags] != expected)
        return fail("copy policy inline decisions are inconsistent");
    }
  }
  std::set<uint32_t> regenerate, duplicate, exceptions;
  for (uint32_t index = 0; index < image.sections.size(); ++index) {
    const auto &section = image.sections[index];
    // This is the existing prepared-module pipeline's regeneration list.
    // Dropping these is an explicit obligation on the eventual ELF binder.
    if (section.name == ".return_sites" || section.name == ".call_sites" ||
        section.name == ".retpoline_sites" ||
        section.name == ".ibt_endbr_seal" ||
        section.name == ".note.gnu.build-id" || section.name == ".orc_unwind" ||
        section.name == ".orc_unwind_ip")
      regenerate.insert(index);
    if (section.name == ".smp_locks" || section.name == "__mcount_loc" ||
        section.name == "__kcfi_traps" || section.name == ".cfi_sites" ||
        section.name == ".discard.annotate_insn" ||
        section.name == ".discard.unreachable" ||
        section.name == ".discard.reachable" ||
        section.name == ".discard.intra_function_calls" ||
        section.name == ".discard.noendbr" ||
        section.name == ".discard.retpoline_safe")
      duplicate.insert(index);
    if (section.size && section.name == "__ex_table") {
      if (section.type != SHT_PROGBITS || section.size % 12)
        return fail("invalid x86 exception table extent");
      exceptions.insert(index);
    }
  }
  for (uint32_t index = 0; index < image.sections.size(); ++index)
    if (image.sections[index].type == SHT_RELA &&
        regenerate.count(image.sections[index].info))
      regenerate.insert(index);

  std::map<std::pair<uint32_t, uint64_t>, uint32_t> function_entries;
  std::string unsupported;
  const auto limitation = [&](const std::string &reason) {
    if (unsupported.empty())
      unsupported = reason;
  };
  std::set<uint32_t> aliases;
  for (uint32_t index = 1; index < policy.functions.size(); ++index) {
    const auto &function = policy.functions[index];
    if (!code.count(function.section) || function.begin >= function.end ||
        function.end > image.sections[function.section].size ||
        function.first_alias > policy.aliases.size() || !function.alias_count ||
        function.alias_count > policy.aliases.size() - function.first_alias)
      return fail("copy policy function has an invalid original extent");
    bool physical = false;
    for (uint32_t offset = 0; offset < function.alias_count; ++offset) {
      const auto alias = policy.aliases[function.first_alias + offset];
      if (alias >= image.symbols.size() || !aliases.insert(alias).second)
        return fail("copy policy function alias is outside the input image");
      const auto &symbol = image.symbols[alias];
      if (symbol.section != function.section ||
          symbol.offset != function.begin ||
          symbol.size != function.end - function.begin ||
          symbol.type != STT_FUNC)
        return fail("copy policy function alias differs from the input image");
      physical |= symbol.name.compare(0, 6, "__pfx_") != 0;
    }
    if (physical &&
        !function_entries
             .emplace(std::make_pair(function.section, function.begin), index)
             .second)
      return fail("copy policy contains duplicate physical functions");
  }
  const auto owner = [&](uint32_t section, uint64_t offset) -> uint32_t {
    auto next = function_entries.upper_bound({section, offset});
    if (next == function_entries.begin())
      return 0;
    --next;
    const auto &function = policy.functions[next->second];
    return function.section == section && offset < function.end ? next->second
                                                                : 0;
  };
  struct Boundary {
    ct_kernel_copy_boundary_kind kind;
    uint64_t site_id;
  };
  struct Row {
    const Instruction *instruction;
    uint32_t function = 0, path = 0, target_function = 0;
    size_t target = SIZE_MAX, after = SIZE_MAX, landing = SIZE_MAX;
    int indirect_register = -1;
    bool unknown_control = false;
    bool leader = false, scope = false, tail = false, return_thunk = false;
    bool unpaired_call = false, timing = false;
    std::vector<Boundary> boundaries;
  };
  std::vector<Row> rows;
  std::vector<uint64_t> first_probes(policy.functions.size());
  std::map<std::pair<uint32_t, uint64_t>, size_t> row_index;
  for (const auto &[index, section] : code)
    for (const auto &instruction : section.instructions) {
      Row row{};
      row.instruction = &instruction;
      row.timing = timing.count(instruction.site.id);
      row.function = owner(index, instruction.site.offset);
      if (instruction.site.probe) {
        const auto id = instruction.site.id;
        if (!row.function || id >= policy.sites.size() ||
            policy.sites[id].function != row.function ||
            policy.sites[id].path >= policy.paths.size())
          return fail("copy policy site differs from its original function");
        row.path = policy.sites[id].path;
        if (!first_probes[row.function])
          first_probes[row.function] = id;
      } else if (row.function) {
        const auto first = policy.functions[row.function].first_probe;
        if (first >= policy.sites.size())
          return fail("physical function has an invalid first probe");
        if (!first)
          limitation("physical function has no supported executable body");
        else
          row.path = policy.sites[first].path;
      }
      row_index.emplace(std::make_pair(index, instruction.site.offset),
                        rows.size());
      rows.push_back(std::move(row));
    }
  for (size_t index = 1; index < policy.functions.size(); ++index)
    if (policy.functions[index].first_probe != first_probes[index])
      return fail("copy policy function has an inconsistent first probe");
  for (uint32_t section : duplicate)
    if (image.sections[section].size &&
        image.sections[section].type != SHT_PROGBITS)
      return fail("instruction metadata has an invalid section type");
  for (const auto &symbol : image.symbols)
    if (!single_full && duplicate.count(symbol.section) &&
        image.sections[symbol.section].size && symbol.type != STT_SECTION &&
        (symbol.offset || symbol.size))
      limitation("cloned instruction metadata has a nonsection symbol extent");
  std::map<uint32_t, std::set<uint64_t>> exception_fields;
  for (const auto &relocation : image.relocations) {
    if (!exceptions.count(relocation.section) ||
        relocation.type == R_X86_64_NONE)
      continue;
    const auto symbol =
        original_symbols.find({relocation.symbol_table, relocation.symbol});
    if (relocation.type != R_X86_64_PC32 ||
        (relocation.offset % 12 != 0 && relocation.offset % 12 != 4) ||
        relocation.offset >= image.sections[relocation.section].size ||
        !exception_fields[relocation.section]
             .insert(relocation.offset)
             .second ||
        symbol == original_symbols.end() ||
        !code.count(symbol->second.st_shndx))
      return fail("invalid x86 exception table relocation");
    const __int128 target =
        __int128(symbol->second.st_value) + relocation.addend;
    if (target < 0 || target > UINT64_MAX ||
        !row_index.count({symbol->second.st_shndx, uint64_t(target)}))
      return fail(
          "exception table address is not an original instruction boundary");
  }
  for (uint32_t section : exceptions) {
    if (exception_fields[section].size() !=
        image.sections[section].size / 12 * 2)
      return fail("exception table entry is missing an address relocation");
    if (!single_full)
      limitation("three-copy exception tables require a per-copy handler");
  }
  for (size_t index = rows.size(); index-- > 0;)
    if (rows[index].function && !rows[index].instruction->site.probe &&
        index + 1 < rows.size() &&
        rows[index + 1].function == rows[index].function)
      rows[index].path = rows[index + 1].path;
  for (const auto &[address, function] : function_entries) {
    const auto first = row_index.find(address);
    if (first == row_index.end())
      return fail("physical function entry splits an original instruction");
    rows[first->second].leader = true;
    const auto &extent = policy.functions[function];
    const auto last = row_index.lower_bound({extent.section, extent.end});
    if (last == row_index.begin())
      return fail("physical function has no original instruction");
    const auto &final = rows[std::prev(last)->second];
    const auto &instruction = *final.instruction;
    if (final.function != function ||
        instruction.site.offset + instruction.site.original_size != extent.end)
      return fail(
          "physical function extent differs from its instruction inventory");
    if (!(instruction.returns || instruction.call ||
          (instruction.branch && !instruction.conditional) ||
          (single_full && instruction.terminal_trap)))
      limitation("physical function may fall through its canonical extent");
  }
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_relocation *>
      code_relocations;
  std::map<std::pair<uint32_t, uint32_t>, std::string_view> symbol_names;
  for (const auto &symbol : image.symbols)
    symbol_names[{symbol.table, symbol.index}] = symbol.name;
  for (const auto &relocation : image.relocations)
    if (code.count(relocation.section) && relocation.type != R_X86_64_NONE)
      code_relocations.emplace(
          std::make_pair(relocation.section, relocation.offset), &relocation);
  const auto relocation_row =
      [&](const ct_kernel_relocation &relocation) -> const Row * {
    if (!code.count(relocation.section))
      return nullptr;
    const auto next =
        row_index.upper_bound({relocation.section, relocation.offset});
    if (next == row_index.begin())
      return nullptr;
    const auto &row = rows[std::prev(next)->second];
    const auto &site = row.instruction->site;
    const auto delta = relocation.offset - site.offset;
    return site.section == relocation.section &&
                   (delta < site.original_size ||
                    (relocation.type == R_X86_64_NONE &&
                     delta == site.original_size))
               ? &row
               : nullptr;
  };
  const auto relocation_target = [](const ct_kernel_relocation &relocation,
                                    const Elf64_Sym &symbol, const Row *row) {
    const bool relative = relocation.type == R_X86_64_PC32 ||
                          relocation.type == R_X86_64_PLT32 ||
                          relocation.type == R_X86_64_PC64;
    const int64_t bias = row && relative
                             ? row->instruction->site.offset +
                                   row->instruction->site.original_size -
                                   relocation.offset
                             : 0;
    return std::make_pair(bias,
                          __int128(symbol.st_value) + relocation.addend + bias);
  };
  for (size_t index = 0; index < rows.size(); ++index) {
    auto &row = rows[index];
    const auto &instruction = *row.instruction;
    const auto &site = instruction.site;
    if (!row.function)
      continue;
    if (instruction.branch && !instruction.direct) {
      if (!single_full) {
        limitation("three-copy indirect jumps require a proven target table");
        continue;
      }
      row.indirect_register = instruction.indirect_register;
      row.unknown_control = row.indirect_register < 0;
    }
    if (instruction.direct) {
      uint32_t target_section = site.section;
      uint64_t target_offset = instruction.destination;
      bool local = !instruction.relocated;
      if (instruction.relocated) {
        const auto field = code_relocations.find(
            {site.section, site.offset + instruction.relative});
        if (field == code_relocations.end())
          return fail("direct transfer has no original relocation field");
        const auto &relocation = *field->second;
        if (relocation.type != R_X86_64_PC32 &&
            relocation.type != R_X86_64_PLT32)
          return fail(
              "direct transfer requires a PC-relative branch relocation");
        const auto symbol =
            original_symbols.find({relocation.symbol_table, relocation.symbol});
        if (symbol == original_symbols.end())
          return fail("direct transfer refers to an absent original symbol");
        target_section = symbol->second.st_shndx;
        row.unpaired_call =
            instruction.call && symbol->second.st_shndx == SHN_UNDEF &&
            (relocation.type == R_X86_64_PC32 ||
             relocation.type == R_X86_64_PLT32) &&
            relocation.addend == -4 && instruction.relative_size == 4 &&
            noreturn.count(
                symbol_names[{relocation.symbol_table, relocation.symbol}]);
        row.return_thunk =
            instruction.branch && !instruction.conditional &&
            symbol->second.st_shndx == SHN_UNDEF && site.original_size == 5 &&
            instruction.code[0] == 0xe9 && instruction.relative == 1 &&
            (relocation.type == R_X86_64_PC32 ||
             relocation.type == R_X86_64_PLT32) &&
            relocation.addend == -4 &&
            symbol_names[{relocation.symbol_table, relocation.symbol}] ==
                "__x86_return_thunk";
        if (single_full && instruction.branch && !instruction.conditional &&
            symbol->second.st_shndx == SHN_UNDEF && site.original_size == 5 &&
            instruction.code[0] == 0xe9 && instruction.relative == 1 &&
            (relocation.type == R_X86_64_PC32 ||
             relocation.type == R_X86_64_PLT32) &&
            relocation.addend == -4) {
          const auto name =
              symbol_names[{relocation.symbol_table, relocation.symbol}];
          const char *registers[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                     "rbp", "rsp", "r8",  "r9",  "r10", "r11",
                                     "r12", "r13", "r14", "r15"};
          for (unsigned reg = 0; reg < 16; ++reg)
            if (name == std::string("__x86_indirect_thunk_") + registers[reg])
              row.indirect_register = reg;
        }
        local = code.count(target_section);
        if (local) {
          const auto target =
              relocation_target(relocation, symbol->second, &row).second;
          if (target < 0 || target > UINT64_MAX)
            return fail("direct transfer target exceeds its original section");
          target_offset = uint64_t(target);
        }
      }
      if (local) {
        const auto target = row_index.find({target_section, target_offset});
        if (target == row_index.end())
          return fail("direct transfer leaves physical instruction boundaries");
        row.target = target->second;
        row.target_function = rows[row.target].function;
        if (!row.target_function) {
          limitation(
              "direct transfer into canonical padding requires a handler");
          continue;
        }
        if (instruction.call && target_section == site.section &&
            target_offset == site.offset + site.original_size)
          limitation("call-to-next requires a separate stack-effect proof");
        const auto &function = policy.functions[row.target_function];
        if ((instruction.call || row.target_function != row.function) &&
            target_offset != function.begin)
          limitation("cross-function transfer targets an interior label");
        if (!instruction.call && row.target_function == row.function) {
          rows[row.target].leader = true;
          rows[row.target].scope |= rows[row.target].path != row.path;
        }
      }
      row.tail =
          instruction.branch && (!local || row.target_function != row.function);
      if (row.tail && instruction.conditional) {
        if (single_full)
          row.unknown_control = true;
        else
          limitation(
              "conditional tail transfer requires an edge-specific gate");
      }
      if (row.indirect_register >= 0 || row.unknown_control)
        row.tail = false;
    }
    if (index + 1 < rows.size() && rows[index + 1].function == row.function &&
        (instruction.call || instruction.branch || instruction.returns))
      rows[index + 1].leader = true;
    if (instruction.call) {
      row.unpaired_call |=
          index + 1 == rows.size() || rows[index + 1].function != row.function;
      if (!row.unpaired_call) {
        row.after = index + 1;
        if (single_full)
          while (row.after < rows.size() &&
                 rows[row.after].function == row.function &&
                 !rows[row.after].instruction->site.probe)
            ++row.after;
        if (row.after == rows.size() ||
            rows[row.after].function != row.function ||
            !rows[row.after].instruction->site.probe)
          limitation(
              "call return edge has no following original probe identity");
      }
    }
  }
  for (const auto &row : rows) {
    const auto &instruction = *row.instruction;
    if (!instruction.address_relative)
      continue;
    const auto target =
        row_index.find({instruction.site.section, instruction.address_target});
    if (target == row_index.end())
      return fail("RIP-relative code address lacks an instruction boundary");
    if (rows[target->second].function &&
        !function_entries.count(target->first)) {
      if (!single_full)
        limitation("three-copy code address escapes to an interior label");
      else {
        rows[target->second].scope = true;
        rows[target->second].landing = target->second;
      }
    }
  }
  if (single_full) {
    for (const auto &relocation : image.relocations) {
      if (regenerate.count(relocation.section) ||
          !(image.sections[relocation.section].flags & SHF_ALLOC) ||
          relocation.type == R_X86_64_NONE)
        continue;
      const auto symbol =
          original_symbols.find({relocation.symbol_table, relocation.symbol});
      if (symbol == original_symbols.end() ||
          !code.count(symbol->second.st_shndx))
        continue;
      const auto *source = relocation_row(relocation);
      if (code.count(relocation.section) && !source)
        return fail("copy relocation field has no original instruction");
      // A code-address operand uses precisely the same original-PC bias as
      // final relocation rewriting. Direct control edges retain their own
      // canonical/function-local mapping and do not create address landings.
      if (source && source->instruction->direct)
        continue;
      const auto offset =
          relocation_target(relocation, symbol->second, source).second;
      if (offset < 0 || offset > UINT64_MAX)
        continue;
      const auto target =
          row_index.find({symbol->second.st_shndx, uint64_t(offset)});
      if (target != row_index.end() && rows[target->second].function &&
          !function_entries.count(target->first)) {
        rows[target->second].scope = true;
        rows[target->second].landing = target->second;
      }
    }
  }
  if (!unsupported.empty())
    return fail(unsupported, ct_kernel_copy_failure::unsupported);
  for (size_t index = 0; index < rows.size(); ++index) {
    auto &row = rows[index];
    if (!row.function)
      continue;
    const auto &instruction = *row.instruction;
    const bool previous = index && rows[index - 1].function == row.function;
    // Only changing inline paths require a scope selector. Plain basic-block
    // events belong to perfetto and must not impose a gate on the arm body.
    row.scope |= previous && !rows[index - 1].instruction->call &&
                 rows[index - 1].path != row.path;
    if (!instruction.site.probe) {
      if (single_full && row.landing == index) {
        auto next = index + 1;
        while (next < rows.size() && rows[next].function == row.function &&
               !rows[next].instruction->site.probe)
          ++next;
        if (next == rows.size() || rows[next].function != row.function)
          return fail("address-taken landing has no original probe identity");
        // Keep this ENDBR's pointer distinct from a separately addressed
        // following instruction. Its own SCOPE executes just after ENDBR.
        row.boundaries.push_back({ct_kernel_copy_boundary_kind::scope,
                                  rows[next].instruction->site.id});
      } else if (index + 1 < rows.size() &&
                 rows[index + 1].function == row.function) {
        rows[index + 1].leader |= row.leader;
        rows[index + 1].scope |= row.scope;
      }
      continue;
    }
    if (row.scope)
      row.boundaries.push_back(
          {ct_kernel_copy_boundary_kind::scope, instruction.site.id});
    if (instruction.call)
      row.boundaries.push_back(
          {row.unpaired_call ? ct_kernel_copy_boundary_kind::call_unpaired
                             : ct_kernel_copy_boundary_kind::call_before,
           instruction.site.id});
    if (row.indirect_register >= 0 || row.unknown_control)
      row.boundaries.push_back(
          {row.unknown_control ? ct_kernel_copy_boundary_kind::unknown_control
                               : ct_kernel_copy_boundary_kind::indirect,
           instruction.site.id});
    if (instruction.returns || row.tail)
      row.boundaries.push_back({instruction.returns || row.return_thunk
                                    ? ct_kernel_copy_boundary_kind::return_
                                    : ct_kernel_copy_boundary_kind::tail,
                                instruction.site.id});
  }

  // Bound the complete emitted inventory before allocating artifact arrays.
  // Count original symbols/relocations conservatively, even when regeneration
  // or unchanged noncode symbols reduce the actual output record count.
  const unsigned variants = single_full ? 1 : 3;
  uint64_t gates = function_entries.size(), branches = 0, probes = 0;
  for (const auto &row : rows) {
    const auto &instruction = *row.instruction;
    gates += variants *
             (row.boundaries.size() + (instruction.call && !row.unpaired_call));
    branches += variants * (instruction.direct && !instruction.relocated);
    if (!instruction.returns && !row.tail)
      probes += instruction.site.probe +
                (instruction.site.probe && (row.leader || row.timing));
  }
  const uint64_t records =
      rows.size() + function_entries.size() +
      code.size() * (variants + !single_full) + duplicate.size() +
      image.symbols.size() + regenerate.size() +
      image.relocations.size() * variants + branches + probes + gates * 5;
  if (records > expanded_record_limit)
    return fail("three-copy emitted record inventory exceeds size limit",
                ct_kernel_copy_failure::unsupported);
  copies.regenerate_sections.assign(regenerate.begin(), regenerate.end());

  const auto &gate = ct_kernel_gate();
  const std::vector<unsigned char> prefix = {0x9c, 0xe8, 0, 0, 0, 0, 0x9d};
  const size_t gate_size = single_full ? prefix.size() : gate.bytes.size();
  const size_t selector_next = single_full ? 6 : gate.selector.next_pc;
  std::map<uint32_t, size_t> section_index;
  std::map<uint32_t, std::array<uint32_t, 3>> body_sections;
  uint32_t next_section = image.sections.size();
  for (const auto &[index, section] : code) {
    const auto &original = image.sections[index];
    section_index[index] = copies.sections.size();
    copies.sections.push_back(
        {index,
         index,
         original.name,
         original.flags,
         original.alignment,
         true,
         single_full ? ct_kernel_copy_level::full : ct_kernel_copy_level::arm,
         {}});
    if (single_full) {
      body_sections[index].fill(index);
      continue;
    }
    for (unsigned level = 0; level < 3; ++level) {
      if (next_section >= SHN_LORESERVE)
        return fail("three-copy code requires extended section indexes",
                    ct_kernel_copy_failure::unsupported);
      const auto destination = next_section++;
      body_sections[index][level] = destination;
      section_index[destination] = copies.sections.size();
      const char *suffix[] = {"arm", "perfetto", "full"};
      copies.sections.push_back({destination,
                                 index,
                                 original.name + ".ctrace." + suffix[level],
                                 original.flags,
                                 original.alignment,
                                 false,
                                 ct_kernel_copy_level(level),
                                 {}});
    }
  }
  size_t total_size = 0;
  std::map<uint32_t, size_t> function_index;
  std::map<std::pair<uint32_t, uint64_t>, uint64_t> canonical_padding;
  copies.sites.resize(rows.size());
  for (size_t index = 0; index < rows.size(); ++index) {
    const auto &row = rows[index];
    const auto &instruction = *row.instruction;
    auto &site = copies.sites[index];
    site.id = instruction.site.id;
    site.original = {instruction.site.section, instruction.site.offset};
    if (single_full) {
      auto &bytes =
          copies.sections[section_index.at(site.original.section)].bytes;
      if (!row.function)
        canonical_padding[{site.original.section, site.original.offset}] =
            bytes.size();
      else if (instruction.site.offset ==
               policy.functions[row.function].begin) {
        const auto &original = policy.functions[row.function];
        ct_kernel_copy_function function;
        function.function = row.function;
        function.canonical = {site.original.section, bytes.size()};
        const bool endbr = !instruction.site.probe;
        if (endbr && instruction.code !=
                         std::vector<unsigned char>({0xf3, 0x0f, 0x1e, 0xfa}))
          return fail(
              "canonical entry contains an unsupported landing instruction");
        const size_t size = prefix.size() + (endbr ? 4 : 0);
        if (size > expanded_code_limit - total_size)
          return fail("single FULL canonical code exceeds size limit",
                      ct_kernel_copy_failure::unsupported);
        total_size += size;
        if (endbr)
          bytes.insert(bytes.end(), instruction.code.begin(),
                       instruction.code.end());
        ct_kernel_copy_boundary boundary;
        boundary.kind = ct_kernel_copy_boundary_kind::entry;
        boundary.function = row.function;
        boundary.path = row.path;
        boundary.site_id = original.first_probe;
        boundary.original = site.original;
        boundary.entry = function.canonical;
        boundary.selector_return = {site.original.section, bytes.size() + 6};
        bytes.insert(bytes.end(), prefix.begin(), prefix.end());
        function.bodies.fill({site.original.section, bytes.size()});
        function_index[row.function] = copies.functions.size();
        copies.functions.push_back(function);
        copies.boundaries.push_back(boundary);
      }
    }
    for (unsigned level = single_full ? 2 : 0; level < 3; ++level) {
      const auto section = body_sections.at(site.original.section)[level];
      auto &bytes = copies.sections[section_index.at(section)].bytes;
      auto &location = site.levels[level];
      location.entry = {section, bytes.size()};
      // EXIT/TAIL changes the active execution frame. Its gate snapshot is
      // the terminal observation; no body probe runs after that transition.
      const bool probe =
          instruction.site.probe && !instruction.returns && !row.tail &&
          row.indirect_register < 0 && !row.unknown_control &&
          (level == 2 || (level == 1 && (row.leader || row.timing)));
      const size_t size =
          (row.boundaries.size() + (instruction.call && !row.unpaired_call)) *
              gate_size +
          (probe ? 7 : 0) + instruction.code.size();
      if (size > expanded_code_limit - total_size)
        return fail("three-copy kernel code exceeds size limit",
                    ct_kernel_copy_failure::unsupported);
      total_size += size;
      if (instruction.site.probe)
        for (size_t boundary = 0; boundary < row.boundaries.size();
             ++boundary) {
          if (single_full)
            bytes.insert(bytes.end(), prefix.begin(), prefix.end());
          else
            bytes.insert(bytes.end(), gate.bytes.begin(), gate.bytes.end());
        }
      if (probe) {
        ct_kernel_copy_relocation relocation;
        relocation.source = {section, bytes.size() + 2};
        relocation.type = R_X86_64_PLT32;
        relocation.addend = -4;
        relocation.kind = level == 2
                              ? ct_kernel_copy_relocation_kind::full_probe
                              : ct_kernel_copy_relocation_kind::perfetto_probe;
        copies.relocations.push_back(relocation);
        bytes.insert(bytes.end(), {0x9c, 0xe8, 0, 0, 0, 0, 0x9d});
      }
      location.operation = {section, bytes.size()};
      location.probe = probe;
      location.emitted_size = instruction.code.size();
      bytes.insert(bytes.end(), instruction.code.begin(),
                   instruction.code.end());
      if (single_full && !instruction.site.probe)
        for (size_t boundary = 0; boundary < row.boundaries.size(); ++boundary)
          bytes.insert(bytes.end(), prefix.begin(), prefix.end());
      if (instruction.call && !row.unpaired_call) {
        if (single_full)
          bytes.insert(bytes.end(), prefix.begin(), prefix.end());
        else
          bytes.insert(bytes.end(), gate.bytes.begin(), gate.bytes.end());
      }
      if (single_full && row.function) {
        auto &function = copies.functions[function_index.at(row.function)];
        function.size = bytes.size() - function.canonical.offset;
      }
    }
    if (single_full)
      site.levels[0] = site.levels[1] = site.levels[2];
  }
  if (!single_full)
    for (size_t index = 0; index < rows.size(); ++index) {
      const auto &row = rows[index];
      const auto &site = row.instruction->site;
      auto &bytes = copies.sections[section_index.at(site.section)].bytes;
      if (!row.function) {
        canonical_padding[{site.section, site.offset}] = bytes.size();
        if (row.instruction->code.size() > expanded_code_limit - total_size)
          return fail("canonical kernel code exceeds size limit",
                      ct_kernel_copy_failure::unsupported);
        total_size += row.instruction->code.size();
        bytes.insert(bytes.end(), row.instruction->code.begin(),
                     row.instruction->code.end());
        continue;
      }
      const auto &original = policy.functions[row.function];
      if (site.offset != original.begin)
        continue;
      ct_kernel_copy_function function;
      function.function = row.function;
      function.canonical = {site.section, bytes.size()};
      const bool endbr = !site.probe;
      if (endbr && row.instruction->code !=
                       std::vector<unsigned char>({0xf3, 0x0f, 0x1e, 0xfa}))
        return fail(
            "canonical entry contains an unsupported landing instruction");
      const size_t size = gate.bytes.size() + (endbr ? 4 : 0);
      if (size > expanded_code_limit - total_size)
        return fail("canonical kernel code exceeds size limit",
                    ct_kernel_copy_failure::unsupported);
      total_size += size;
      if (endbr)
        bytes.insert(bytes.end(), row.instruction->code.begin(),
                     row.instruction->code.end());
      ct_kernel_copy_boundary boundary;
      boundary.kind = ct_kernel_copy_boundary_kind::entry;
      boundary.function = row.function;
      boundary.path = row.path;
      boundary.site_id = original.first_probe;
      boundary.original = {site.section, site.offset};
      boundary.entry = {site.section, bytes.size()};
      boundary.selector_return = {site.section,
                                  bytes.size() + gate.selector.next_pc};
      for (unsigned level = 0; level < 3; ++level)
        boundary.continuations[level] = function.bodies[level] =
            copies.sites[index].levels[level].entry;
      bytes.insert(bytes.end(), gate.bytes.begin(), gate.bytes.end());
      function.size = bytes.size() - function.canonical.offset;
      function_index[row.function] = copies.functions.size();
      copies.functions.push_back(function);
      copies.boundaries.push_back(boundary);
    }
  for (size_t index = 0; index < rows.size(); ++index) {
    const auto &row = rows[index];
    if (row.instruction->call && !row.unpaired_call)
      for (unsigned level = single_full ? 2 : 0; level < 3; ++level) {
        // Only the CALL return edge visits this gate. Direct branches to the
        // following instruction skip it, since those edges did not call.
        ct_kernel_copy_boundary boundary;
        boundary.kind = ct_kernel_copy_boundary_kind::call_after;
        boundary.function = row.function;
        boundary.path = rows[row.after].path;
        boundary.target_function = row.target_function;
        boundary.site_id = rows[row.after].instruction->site.id;
        boundary.related_site_id = row.instruction->site.id;
        boundary.original = copies.sites[row.after].original;
        boundary.entry = copies.sites[index].levels[level].operation;
        boundary.entry.offset += row.instruction->code.size();
        boundary.call_return = boundary.entry;
        boundary.selector_return = boundary.entry;
        boundary.selector_return.offset += selector_next;
        for (unsigned target = 0; target < 3; ++target) {
          boundary.call_returns[target] =
              copies.sites[index].levels[target].operation;
          boundary.call_returns[target].offset += row.instruction->code.size();
          if (!single_full) {
            boundary.continuations[target] =
                copies.sites[index].levels[target].operation;
            boundary.continuations[target].offset +=
                row.instruction->code.size() + gate_size;
          }
        }
        copies.boundaries.push_back(boundary);
      }
    for (size_t ordinal = 0; ordinal < row.boundaries.size(); ++ordinal)
      for (unsigned level = single_full ? 2 : 0; level < 3; ++level) {
        ct_kernel_copy_boundary boundary;
        boundary.kind = row.boundaries[ordinal].kind;
        boundary.function = row.function;
        boundary.path = row.path;
        boundary.target_function = row.target_function;
        if (boundary.kind == ct_kernel_copy_boundary_kind::indirect)
          boundary.target_register = row.indirect_register;
        boundary.site_id = row.boundaries[ordinal].site_id;
        if (boundary.kind == ct_kernel_copy_boundary_kind::call_before ||
            boundary.kind == ct_kernel_copy_boundary_kind::call_unpaired) {
          if (row.unpaired_call)
            copies.requires_noreturn_validation = true;
          else
            boundary.related_site_id = rows[row.after].instruction->site.id;
          boundary.call_return = copies.sites[index].levels[level].operation;
          boundary.call_return.offset += row.instruction->code.size();
          for (unsigned target = 0; target < 3; ++target) {
            boundary.call_returns[target] =
                copies.sites[index].levels[target].operation;
            boundary.call_returns[target].offset +=
                row.instruction->code.size();
          }
        }
        boundary.original = copies.sites[index].original;
        boundary.entry = copies.sites[index].levels[level].entry;
        boundary.entry.offset += ordinal * gate_size;
        boundary.selector_return = boundary.entry;
        boundary.selector_return.offset += selector_next;
        if (single_full && !row.instruction->site.probe)
          boundary.selector_return.offset += row.instruction->code.size();
        if (!single_full)
          for (unsigned target = 0; target < 3; ++target) {
            boundary.continuations[target] =
                copies.sites[index].levels[target].entry;
            boundary.continuations[target].offset += (ordinal + 1) * gate_size;
          }
        if (single_full &&
            boundary.kind == ct_kernel_copy_boundary_kind::scope &&
            row.landing != SIZE_MAX) {
          boundary.entry = copies.sites[row.landing].levels[2].entry;
          boundary.address_taken = true;
        }
        copies.boundaries.push_back(boundary);
      }
  }
  for (const auto &boundary : copies.boundaries) {
    ct_kernel_copy_relocation selector;
    selector.source = single_full ? boundary.selector_return : boundary.entry;
    if (single_full)
      selector.source.offset -= 4;
    else
      selector.source.offset += gate.selector.displacement_offset;
    selector.kind = single_full ? ct_kernel_copy_relocation_kind::full_probe
                                : ct_kernel_copy_relocation_kind::selector;
    selector.type = R_X86_64_PLT32;
    selector.addend = -4;
    copies.relocations.push_back(selector);
    if (single_full)
      continue;
    for (unsigned level = 0; level < 3; ++level) {
      ct_kernel_copy_relocation continuation;
      continuation.source = boundary.entry;
      continuation.source.offset +=
          gate.continuations[level].displacement_offset;
      continuation.target = boundary.continuations[level];
      continuation.type = R_X86_64_PC32;
      continuation.addend = -4;
      copies.relocations.push_back(continuation);
    }
  }
  const auto map_address = [&](uint32_t section, uint64_t offset,
                               unsigned level, bool operation,
                               ct_kernel_copy_address &result) {
    const auto found = code.find(section);
    if (found == code.end()) {
      result = {section, offset};
      return section < image.sections.size() &&
             offset <= image.sections[section].size;
    }
    if (offset == found->second.old_size) {
      const auto target = body_sections.at(section)[level];
      result = {target, copies.sections[section_index.at(target)].bytes.size()};
      return true;
    }
    auto next = row_index.upper_bound({section, offset});
    if (next == row_index.begin())
      return false;
    --next;
    const auto &row = rows[next->second];
    const auto &instruction = *row.instruction;
    const auto &site = instruction.site;
    if (site.section != section || offset < site.offset ||
        offset - site.offset >= site.original_size)
      return false;
    const auto delta = offset - site.offset;
    if (delta && instruction.code.size() != site.original_size)
      return false;
    const auto &location = copies.sites[next->second].levels[level];
    result = delta || operation ? location.operation : location.entry;
    result.offset += delta;
    return true;
  };
  const auto canonical_address = [&](uint32_t section, uint64_t offset,
                                     ct_kernel_copy_address &result) {
    const auto function = function_entries.find({section, offset});
    if (function != function_entries.end()) {
      result = copies.functions[function_index.at(function->second)].canonical;
      return true;
    }
    auto padding = canonical_padding.upper_bound({section, offset});
    if (padding == canonical_padding.begin())
      return false;
    --padding;
    if (padding->first.first != section)
      return false;
    const auto row = row_index.at(padding->first);
    const auto delta = offset - padding->first.second;
    if (delta >= rows[row].instruction->site.original_size)
      return false;
    result = {section, padding->second + delta};
    return true;
  };

  for (const auto &symbol : image.symbols) {
    if (!code.count(symbol.section))
      continue;
    ct_kernel_copy_symbol replacement;
    replacement.table = symbol.table;
    replacement.index = symbol.index;
    if (symbol.type == STT_SECTION) {
      replacement.address = {symbol.section, 0};
    } else if (symbol.type == STT_FUNC &&
               symbol.name.compare(0, 6, "__pfx_") != 0) {
      const auto function =
          function_entries.find({symbol.section, symbol.offset});
      if (function == function_entries.end())
        return fail("code function symbol has no canonical entry");
      const auto &entry = copies.functions[function_index.at(function->second)];
      replacement.address = entry.canonical;
      replacement.size = entry.size;
    } else if (canonical_address(symbol.section, symbol.offset,
                                 replacement.address)) {
      replacement.size = symbol.size;
    } else {
      ct_kernel_copy_address end;
      if (!map_address(symbol.section, symbol.offset, 2, false,
                       replacement.address) ||
          !map_address(symbol.section, symbol.offset + symbol.size, 2, false,
                       end) ||
          replacement.address.section != end.section ||
          replacement.address.offset > end.offset)
        return fail("code label symbol has no full-copy address mapping");
      replacement.size = end.offset - replacement.address.offset;
    }
    copies.symbols.push_back(replacement);
  }
  for (uint32_t section : duplicate) {
    const auto &original = image.sections[section];
    if (!original.size)
      continue;
    if (original.type != SHT_PROGBITS)
      return fail("instruction metadata has an invalid section type");
    if (original.size > expanded_code_limit / variants ||
        original.size * variants > expanded_code_limit - total_size)
      return fail("per-copy instruction metadata exceeds its bound",
                  ct_kernel_copy_failure::unsupported);
    total_size += original.size * variants;
    ct_kernel_copy_section metadata;
    metadata.index = metadata.original_section = section;
    metadata.name = original.name;
    metadata.flags = original.flags;
    metadata.alignment = original.alignment;
    const auto *begin = image.bytes.data() + original.offset;
    for (unsigned level = 0; level < variants; ++level)
      metadata.bytes.insert(metadata.bytes.end(), begin, begin + original.size);
    copies.sections.push_back(std::move(metadata));
  }
  for (const auto &relocation : image.relocations) {
    if (regenerate.count(relocation.section))
      continue;
    const auto symbol =
        original_symbols.find({relocation.symbol_table, relocation.symbol});
    if (symbol == original_symbols.end())
      return fail("copy relocation has no original symbol");
    const auto &target_symbol = symbol->second;
    const bool source_code = code.count(relocation.section);
    const bool metadata = duplicate.count(relocation.section);
    const auto &source_section = image.sections[relocation.section];
    const bool debug = !(source_section.flags & SHF_ALLOC) &&
                       (source_section.name.compare(0, 6, ".debug") == 0 ||
                        source_section.name.compare(0, 7, ".zdebug") == 0);
    const bool pc_relative = relocation.type == R_X86_64_PC32 ||
                             relocation.type == R_X86_64_PLT32 ||
                             relocation.type == R_X86_64_PC64;
    const auto *row = relocation_row(relocation);
    if (source_code && !row)
      return fail("copy relocation field has no original instruction");
    if (source_code && !single_full && !row->function)
      return fail("canonical prefix relocation requires a dedicated handler",
                  ct_kernel_copy_failure::unsupported);
    const auto [old_bias, old_target] =
        relocation_target(relocation, target_symbol, row);
    for (unsigned level = 0; level < (source_code || metadata ? variants : 1U);
         ++level) {
      ct_kernel_copy_relocation rewritten;
      rewritten.source = {relocation.section, relocation.offset};
      rewritten.type = relocation.type;
      rewritten.symbol_table = relocation.symbol_table;
      rewritten.symbol = relocation.symbol;
      rewritten.addend = relocation.addend;
      rewritten.kind = ct_kernel_copy_relocation_kind::original_symbol;
      int64_t new_bias = 0;
      if (source_code) {
        if (!map_address(relocation.section, relocation.offset, level, true,
                         rewritten.source))
          return fail("copy relocation overlaps a relaxed instruction");
        if (pc_relative) {
          const auto &instruction = *row->instruction;
          const auto index =
              row_index.at({instruction.site.section, instruction.site.offset});
          new_bias = copies.sites[index].levels[level].operation.offset +
                     instruction.code.size() - rewritten.source.offset;
        }
      } else if (metadata) {
        rewritten.source.offset += level * source_section.size;
      }
      if (code.count(target_symbol.st_shndx) &&
          relocation.type != R_X86_64_NONE) {
        if (old_target < 0 || old_target > UINT64_MAX)
          return fail("copy relocation target exceeds its original section");
        const auto target_section = target_symbol.st_shndx;
        const auto target_offset = uint64_t(old_target);
        bool mapped = false;
        if (source_code && row->instruction->direct) {
          if (row->instruction->call || row->tail ||
              row->target_function != row->function)
            mapped = canonical_address(target_section, target_offset,
                                       rewritten.target);
          else
            mapped = map_address(target_section, target_offset, level, false,
                                 rewritten.target);
        } else if (metadata || debug ||
                   (single_full && exceptions.count(relocation.section))) {
          // Debug relocation anchors follow the full body; unchanged DWARF
          // line/range deltas and CFI are not generated-code coverage. Runtime
          // observations retain the independently analyzed original metadata.
          mapped =
              map_address(target_section, target_offset, debug ? 2 : level,
                          metadata || (exceptions.count(relocation.section) &&
                                       relocation.offset % 12 == 0),
                          rewritten.target);
        } else {
          // Data/function pointers and code taking an address have one fixed
          // identity. Escaped interior labels need an explicit target proof.
          mapped = canonical_address(target_section, target_offset,
                                     rewritten.target);
          if (!mapped && single_full &&
              (row_index.count({target_section, target_offset}) ||
               target_offset == image.sections[target_section].size))
            mapped = map_address(target_section, target_offset, 2, false,
                                 rewritten.target);
        }
        if (!mapped && !metadata && !debug &&
            (!source_code || !row->instruction->direct) &&
            (row_index.count({target_section, target_offset}) ||
             target_offset == image.sections[target_section].size))
          return fail("code address escapes without a canonical function or "
                      "supported per-copy metadata mapping in " +
                          source_section.name,
                      ct_kernel_copy_failure::unsupported);
        if (!mapped)
          return fail("code address escapes without a canonical function or "
                      "supported per-copy metadata mapping in " +
                      source_section.name);
        rewritten.kind = ct_kernel_copy_relocation_kind::address;
        rewritten.addend = -new_bias;
      } else if (pc_relative) {
        const __int128 addend =
            __int128(relocation.addend) + old_bias - new_bias;
        if (addend < INT64_MIN || addend > INT64_MAX)
          return fail("copy relocation addend overflows");
        rewritten.addend = int64_t(addend);
      }
      copies.relocations.push_back(rewritten);
    }
  }
  for (size_t index = 0; index < rows.size(); ++index) {
    const auto &row = rows[index];
    const auto &instruction = *row.instruction;
    if (instruction.address_relative) {
      ct_kernel_copy_address target;
      if (!canonical_address(instruction.site.section,
                             instruction.address_target, target) &&
          !(single_full &&
            map_address(instruction.site.section, instruction.address_target, 2,
                        false, target)))
        return fail("RIP-relative code address has no canonical mapping",
                    ct_kernel_copy_failure::unsupported);
      for (unsigned level = single_full ? 2 : 0; level < 3; ++level) {
        ct_kernel_copy_relocation relocation;
        relocation.source = copies.sites[index].levels[level].operation;
        relocation.source.offset += instruction.address_relative;
        relocation.target = target;
        relocation.type = R_X86_64_PC32;
        relocation.addend = int64_t(instruction.address_relative) -
                            int64_t(instruction.code.size());
        copies.relocations.push_back(relocation);
      }
    }
    if (!instruction.direct || instruction.relocated)
      continue;
    if (row.target == SIZE_MAX)
      return fail("unrelocated direct transfer has no local target");
    for (unsigned level = single_full ? 2 : 0; level < 3; ++level) {
      ct_kernel_copy_relocation relocation;
      relocation.source = copies.sites[index].levels[level].operation;
      relocation.source.offset += instruction.code.size() - 4;
      relocation.type = R_X86_64_PC32;
      relocation.addend = -4;
      if (instruction.call || row.tail || row.target_function != row.function)
        relocation.target =
            copies.functions[function_index.at(row.target_function)].canonical;
      else
        relocation.target = copies.sites[row.target].levels[level].entry;
      copies.relocations.push_back(relocation);
    }
  }
  // Resolve same-section direct edges now. Cross-section edges and helper
  // imports remain relocations, as in any ordinary relocatable code object.
  for (const auto &relocation : copies.relocations) {
    if (relocation.kind != ct_kernel_copy_relocation_kind::address ||
        relocation.source.section != relocation.target.section ||
        (relocation.type != R_X86_64_PC32 && relocation.type != R_X86_64_PLT32))
      continue;
    const auto section = section_index.find(relocation.source.section);
    if (section == section_index.end())
      continue;
    auto &bytes = copies.sections[section->second].bytes;
    const __int128 displacement = __int128(relocation.target.offset) +
                                  relocation.addend - relocation.source.offset;
    if (displacement < INT32_MIN || displacement > INT32_MAX ||
        relocation.source.offset > bytes.size() ||
        bytes.size() - relocation.source.offset < 4)
      return fail("three-copy direct edge exceeds its rel32 range");
    const int32_t value = displacement;
    std::memcpy(bytes.data() + relocation.source.offset, &value, sizeof(value));
  }
  if (failure)
    *failure = ct_kernel_copy_failure::none;
  return true;
}

static std::string kernel_rewrite_key(const ct_kernel_image &image) {
  // Include parsed fields as well as file bytes: callers may validate a
  // modified inventory, and such a request must never reuse another plan.
  llvm::SHA256 identity;
  const auto number = [&](uint64_t value) {
    identity.update({reinterpret_cast<const uint8_t *>(&value), sizeof(value)});
  };
  const auto text = [&](std::string_view value) {
    number(value.size());
    identity.update(llvm::StringRef(value.data(), value.size()));
  };
  identity.update(llvm::ArrayRef<uint8_t>(image.bytes));
  text(image.name);
  text(image.vermagic);
  text(image.license);
  number(image.signature_present);
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
  for (const auto &symbol : image.symbols) {
    text(symbol.name);
    for (uint64_t value : {uint64_t(symbol.table), uint64_t(symbol.index),
                           uint64_t(symbol.section), symbol.offset, symbol.size,
                           uint64_t(symbol.type), uint64_t(symbol.binding)})
      number(value);
  }
  number(image.relocations.size());
  for (const auto &relocation : image.relocations)
    for (uint64_t value :
         {uint64_t(relocation.section), uint64_t(relocation.symbol_table),
          uint64_t(relocation.symbol), uint64_t(relocation.type),
          relocation.offset, uint64_t(relocation.addend)})
      number(value);
  const auto digest = identity.final();
  return ct_cache_key(
      {"kernel-decoded-v2",
       std::to_string(KCTRACE_ABI_VERSION),
       {reinterpret_cast<const char *>(digest.data()), digest.size()}});
}

static bool validate_kernel_expansion(const ct_kernel_image &image,
                                      const std::vector<unsigned char> &cached,
                                      std::vector<ct_kernel_site> &sites,
                                      size_t &code_offset, std::string &error) {
  sites.clear();
  code_offset = 0;
  size_t offset = 0;
  const auto field = [&](auto &value) {
    if (sizeof(value) > cached.size() - offset)
      return false;
    std::memcpy(&value, cached.data() + offset, sizeof(value));
    offset += sizeof(value);
    return true;
  };
  uint64_t count = 0, size = 0, identifier = 0;
  bool valid = field(count) && field(size) &&
               count <= expanded_instruction_limit &&
               size <= expanded_code_limit;
  std::map<uint32_t, std::pair<uint64_t, uint64_t>> extents;
  for (uint64_t index = 0; valid && index < count; ++index) {
    ct_kernel_site site;
    uint8_t probe = 0;
    valid = field(site.section) && field(site.offset) && field(site.entry) &&
            field(site.operation) && field(site.id) &&
            field(site.original_size) && field(site.emitted_size) &&
            field(probe) && probe <= 1;
    if (!valid || !site.section || site.section >= image.sections.size()) {
      valid = false;
      break;
    }
    const auto &section = image.sections[site.section];
    auto &extent = extents[site.section];
    site.probe = probe;
    valid = (section.flags & SHF_EXECINSTR) && site.offset == extent.first &&
            site.entry == extent.second && site.original_size &&
            site.original_size <= 15 && site.emitted_size &&
            site.emitted_size <= 15 && site.offset <= section.size &&
            site.original_size <= section.size - site.offset &&
            site.operation == site.entry + (probe ? 7 : 0) &&
            site.id == (probe ? ++identifier : 0);
    extent = {site.offset + site.original_size,
              site.operation + site.emitted_size};
    sites.push_back(site);
  }
  for (uint32_t section = 0; valid && section < image.sections.size();
       ++section)
    if ((image.sections[section].flags & SHF_EXECINSTR) &&
        extents[section].first != image.sections[section].size)
      valid = false;
  if (valid && size == cached.size() - offset) {
    ct_kernel_image snapshot;
    snapshot.bytes.assign(cached.begin() + offset, cached.end());
    ct_kernel_object object(snapshot);
    valid = object.valid(error);
    if (valid) {
      std::vector<unsigned char> checked;
      valid = object.serialize(checked, error);
    }
    for (const auto &[section, extent] : extents) {
      const auto *header = object.section_header(section);
      if (!header || header->sh_type != SHT_PROGBITS ||
          header->sh_size != extent.second ||
          object.section_name(section) != image.sections[section].name)
        valid = false;
    }
    if (valid) {
      llvm::InitializeNativeTarget();
      llvm::InitializeNativeTargetDisassembler();
      std::unique_ptr<void, decltype(&LLVMDisasmDispose)> decoder(
          LLVMCreateDisasm("x86_64-pc-linux-gnu", nullptr, 0, nullptr, nullptr),
          LLVMDisasmDispose);
      valid = bool(decoder);
      for (const auto &site : sites) {
        if (!valid)
          break;
        const auto &section = image.sections[site.section];
        const auto &code = *object.section_content(site.section);
        if (site.probe &&
            (code[site.entry] != 0x9c || code[site.entry + 1] != 0xe8 ||
             code[site.entry + 6] != 0x9d)) {
          valid = false;
          break;
        }
        size_t decoded = 0;
        bool prefix = false;
        do {
          auto *instruction = const_cast<unsigned char *>(
              image.bytes.data() + section.offset + site.offset + decoded);
          char text[128];
          const size_t part = LLVMDisasmInstruction(
              decoder.get(), instruction,
              std::min<uint64_t>(15 - decoded,
                                 section.size - site.offset - decoded),
              site.offset + decoded, text, sizeof(text));
          if (!part || part > site.original_size - decoded) {
            valid = false;
            break;
          }
          // LLVM may return an x86 prefix pseudo-instruction separately.
          // Prefix bytes have no standalone operation in this 64-bit mode.
          const unsigned byte = instruction[0];
          prefix = part == 1 && ((byte >= 0x40 && byte <= 0x4f) ||
                                 byte == 0xf0 || byte == 0xf2 || byte == 0xf3 ||
                                 byte == 0x66 || byte == 0x67 || byte == 0x26 ||
                                 byte == 0x2e || byte == 0x36 || byte == 0x3e ||
                                 byte == 0x64 || byte == 0x65);
          decoded += part;
        } while (prefix && decoded < site.original_size);
        valid &= !prefix && decoded == site.original_size;
      }
    }
    // This cache is only an expansion input. The final template still goes
    // through kernel/objtool and full prepared-artifact validation.
    if (valid) {
      code_offset = offset;
      return true;
    }
  }
  sites.clear();
  error.clear();
  return false;
}

bool ct_kernel_rewrite_plan::Data::matches(
    const std::vector<ct_kernel_site> &sites) const {
  if (sites.size() != instruction_count)
    return false;
  const auto equal = [](const ct_kernel_site &left,
                        const ct_kernel_site &right) {
    return left.section == right.section && left.offset == right.offset &&
           left.entry == right.entry && left.operation == right.operation &&
           left.id == right.id && left.original_size == right.original_size &&
           left.emitted_size == right.emitted_size && left.probe == right.probe;
  };
  size_t index = 0;
  for (const auto &[section, plan] : code)
    for (const auto &instruction : plan.instructions)
      if (index >= sites.size() || !equal(instruction.site, sites[index++]))
        return false;
  return index == sites.size();
}

bool ct_kernel_rewrite_plan::prepare(const ct_kernel_image &image,
                                     std::vector<ct_kernel_site> &sites,
                                     std::string &error,
                                     const std::function<void()> &on_miss) {
  data.reset();
  sites.clear();
  error.clear();
  const auto key = kernel_rewrite_key(image);
  auto prepared = std::make_unique<Data>();
  prepared->key = key;
  std::vector<unsigned char> cached;
  if (!ct_cache_read("kernel-decoded", prepared->key, cached) ||
      !prepared->restore(image, cached, sites)) {
    std::vector<unsigned char>().swap(cached);
    prepared = std::make_unique<Data>();
    prepared->key = key;
    sites.clear();
    if (on_miss)
      on_miss();
    if (!prepared->decode(image, sites, error))
      return false;
    prepared->store();
  }
  data = std::move(prepared);
  return true;
}

bool ct_kernel_rewrite_plan::emit(const ct_kernel_image &image,
                                  std::vector<unsigned char> &output,
                                  std::string &error,
                                  const std::function<void()> &on_miss) const {
  output.clear();
  error.clear();
  if (!data || data->key != kernel_rewrite_key(image)) {
    error = "kernel emission requires the unchanged prepared input";
    return false;
  }
  const auto &key = data->key;
  std::vector<unsigned char> cached;
  std::vector<ct_kernel_site> sites;
  if (ct_cache_read("kernel-expanded", key, cached)) {
    size_t offset = 0;
    if (!validate_kernel_expansion(image, cached, sites, offset, error) ||
        !data->matches(sites))
      offset = 0;
    if (offset && offset < cached.size()) {
      output.assign(cached.begin() + offset, cached.end());
      return true;
    }
  }
  std::vector<unsigned char>().swap(cached);
  sites.clear();
  error.clear();
  if (on_miss)
    on_miss();
  sites.reserve(data->instruction_count);
  for (const auto &[section, plan] : data->code)
    for (const auto &instruction : plan.instructions)
      sites.push_back(instruction.site);
  if (!data->emit(image, sites, output, error))
    return false;
  cached.clear();
  const auto field = [&](const auto &value) {
    const auto *begin = reinterpret_cast<const unsigned char *>(&value);
    cached.insert(cached.end(), begin, begin + sizeof(value));
  };
  field(uint64_t(sites.size()));
  field(uint64_t(output.size()));
  for (const auto &site : sites) {
    field(site.section);
    field(site.offset);
    field(site.entry);
    field(site.operation);
    field(site.id);
    field(site.original_size);
    field(site.emitted_size);
    field(uint8_t(site.probe));
  }
  cached.insert(cached.end(), output.begin(), output.end());
  ct_cache_write("kernel-expanded", key, cached);
  return true;
}

bool ct_kernel_rewrite_plan::emit_copies(
    const ct_kernel_image &image, const ct_kernel_policy &policy,
    ct_kernel_copies &copies, std::string &error,
    const std::vector<uint64_t> &timing_sites,
    const std::vector<std::string> &noreturn_symbols,
    ct_kernel_copy_failure *failure, bool single_full) const {
  copies = {};
  error.clear();
  if (failure)
    *failure = ct_kernel_copy_failure::invalid;
  if (!data || data->key != kernel_rewrite_key(image)) {
    error = "kernel copy emission requires the unchanged prepared input";
    return false;
  }
  return data->emit_copies(image, policy, copies, error, timing_sites,
                           noreturn_symbols, failure, single_full);
}

bool ct_kernel_expand(const ct_kernel_image &image,
                      std::vector<unsigned char> &output,
                      std::vector<ct_kernel_site> &sites, std::string &error,
                      const std::function<void()> &on_miss) {
  output.clear();
  ct_kernel_rewrite_plan plan;
  bool notified = false;
  const auto miss = [&] {
    if (!notified) {
      notified = true;
      if (on_miss)
        on_miss();
    }
  };
  if (!plan.prepare(image, sites, error, miss))
    return false;
  if (!plan.emit(image, output, error, miss)) {
    sites.clear();
    return false;
  }
  return true;
}
