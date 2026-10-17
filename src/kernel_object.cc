#include <algorithm>
#include <cstring>
#include <utility>

#include <zlib.h>
#include <zstd.h>

#include "kernel_object.h"

static constexpr size_t object_size_limit = 128 * 1024 * 1024;
static constexpr size_t object_section_limit = 1000000;

static bool object_relocation_fits(const Elf64_Rela &relocation, uint64_t size,
                                   std::string &error) {
  size_t width;
  switch (ELF64_R_TYPE(relocation.r_info)) {
  case R_X86_64_NONE:
    width = 0;
    break;
  case R_X86_64_64:
  case R_X86_64_PC64:
    width = 8;
    break;
  case R_X86_64_PC32:
  case R_X86_64_PLT32:
  case R_X86_64_32:
  case R_X86_64_32S:
  case R_X86_64_GOTPCREL:
  case R_X86_64_GOTPCRELX:
  case R_X86_64_REX_GOTPCRELX:
    width = 4;
    break;
  case R_X86_64_16:
  case R_X86_64_PC16:
    width = 2;
    break;
  case R_X86_64_8:
  case R_X86_64_PC8:
    width = 1;
    break;
  default:
    error = "unsupported relocation type in mutable kernel object";
    return false;
  }
  if (relocation.r_offset > size || width > size - relocation.r_offset) {
    error = "relocation extends beyond its target section";
    return false;
  }
  return true;
}

ct_kernel_object::ct_kernel_object(const ct_kernel_image &image) {
  const auto &bytes = image.bytes;
  const auto range = [&](uint64_t offset, uint64_t size) {
    return offset <= bytes.size() && size <= bytes.size() - offset;
  };
  if (bytes.size() < sizeof(header_) || bytes.size() > object_size_limit) {
    error_ = "kernel object snapshot exceeds supported size bounds";
    return;
  }
  std::memcpy(&header_, bytes.data(), sizeof(header_));
  if (std::memcmp(header_.e_ident, ELFMAG, SELFMAG) ||
      header_.e_ident[EI_CLASS] != ELFCLASS64 ||
      header_.e_ident[EI_DATA] != ELFDATA2LSB ||
      header_.e_ident[EI_VERSION] != EV_CURRENT ||
      header_.e_version != EV_CURRENT || header_.e_type != ET_REL ||
      header_.e_machine != EM_X86_64 || header_.e_phnum ||
      header_.e_ehsize != sizeof(header_) ||
      header_.e_shentsize != sizeof(Elf64_Shdr) ||
      !range(header_.e_shoff, sizeof(Elf64_Shdr))) {
    error_ = "mutable kernel object requires ELF64 little-endian x86-64 ET_REL";
    return;
  }
  Elf64_Shdr first;
  std::memcpy(&first, bytes.data() + header_.e_shoff, sizeof(first));
  const uint64_t count = header_.e_shnum ? header_.e_shnum : first.sh_size;
  const uint64_t names =
      header_.e_shstrndx == SHN_XINDEX ? first.sh_link : header_.e_shstrndx;
  if (first.sh_type != SHT_NULL || !count || count > object_section_limit ||
      !names || names >= count ||
      !range(header_.e_shoff, count * sizeof(Elf64_Shdr))) {
    error_ = "invalid mutable kernel object section table";
    return;
  }
  names_ = names;
  size_t retained = 0;
  for (uint32_t index = 0; index < count; ++index) {
    Section section;
    std::memcpy(&section.header,
                bytes.data() + header_.e_shoff + index * sizeof(Elf64_Shdr),
                sizeof(Elf64_Shdr));
    const auto &raw = section.header;
    if (raw.sh_addralign && (raw.sh_addralign & (raw.sh_addralign - 1))) {
      error_ = "invalid mutable kernel object section alignment/entry size";
      return;
    }
    if (raw.sh_type != SHT_NOBITS && raw.sh_type != SHT_NULL) {
      if (!range(raw.sh_offset, raw.sh_size) ||
          raw.sh_size > object_size_limit - retained) {
        error_ = "kernel object section payloads exceed size bounds";
        return;
      }
      retained += raw.sh_size;
      section.content.assign(bytes.begin() + raw.sh_offset,
                             bytes.begin() + raw.sh_offset + raw.sh_size);
    }
    sections_.push_back(std::move(section));
  }
  const auto &strings = sections_[names_];
  retained_ = retained;
  if (strings.header.sh_type != SHT_STRTAB || strings.content.empty() ||
      strings.content.front() || strings.content.back()) {
    error_ = "invalid kernel object section-name string table";
    return;
  }
  retained = 0;
  for (auto &section : sections_) {
    const auto offset = section.header.sh_name;
    if (offset >= strings.content.size()) {
      error_ = "kernel object section name exceeds its string table";
      return;
    }
    const char *begin =
        reinterpret_cast<const char *>(strings.content.data() + offset);
    const char *end = static_cast<const char *>(
        std::memchr(begin, 0, strings.content.size() - offset));
    if (!end || size_t(end - begin) > object_size_limit - retained) {
      error_ = "kernel object section-name inventory exceeds size bounds";
      return;
    }
    retained += end - begin;
    section.name.assign(begin, end);
    const auto &raw = section.header;
    if (!(raw.sh_flags & SHF_COMPRESSED) &&
        section.name.compare(0, 8, ".zdebug_") != 0 && raw.sh_entsize &&
        raw.sh_size % raw.sh_entsize) {
      error_ = "invalid mutable kernel object section entry size";
      return;
    }
  }
}

bool ct_kernel_object::valid(std::string &error) const {
  error = error_;
  return error.empty();
}

bool ct_kernel_object::decompress_debug_sections(bool &changed,
                                                 std::string &error) {
  changed = false;
  if (!valid(error))
    return false;
  std::vector<bool> renamed(sections_.size());
  for (size_t index = 1; index < sections_.size(); ++index) {
    auto &section = sections_[index];
    const bool gnu = section.name.compare(0, 8, ".zdebug_") == 0;
    const bool elf = section.header.sh_flags & SHF_COMPRESSED;
    if (!gnu && !elf)
      continue;
    if ((gnu && elf) || section.header.sh_type != SHT_PROGBITS ||
        (section.header.sh_flags & (SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE)) ||
        (!gnu && section.name.compare(0, 7, ".debug_") != 0)) {
      error = "unsupported compressed kernel section: " + section.name;
      return false;
    }
    uint64_t size = 0, alignment = section.header.sh_addralign;
    uint32_t kind = ELFCOMPRESS_ZLIB;
    size_t header_size = 12;
    if (gnu) {
      if (section.content.size() < header_size ||
          std::memcmp(section.content.data(), "ZLIB", 4)) {
        error = "invalid GNU compressed debug header: " + section.name;
        return false;
      }
      for (unsigned byte = 4; byte < header_size; ++byte)
        size = (size << 8) | section.content[byte];
    } else {
      header_size = sizeof(Elf64_Chdr);
      if (section.content.size() < header_size) {
        error = "truncated ELF compressed debug header: " + section.name;
        return false;
      }
      Elf64_Chdr header;
      std::memcpy(&header, section.content.data(), sizeof(header));
      size = header.ch_size;
      alignment = header.ch_addralign;
      kind = header.ch_type;
      if (header.ch_reserved || (alignment && (alignment & (alignment - 1))) ||
          (kind != ELFCOMPRESS_ZLIB && kind != ELFCOMPRESS_ZSTD)) {
        error = "invalid ELF compressed debug header: " + section.name;
        return false;
      }
    }
    if ((section.header.sh_entsize && size % section.header.sh_entsize) ||
        size > object_size_limit - (retained_ - section.content.size())) {
      error = "decompressed debug sections exceed the 128 MiB size limit";
      return false;
    }
    const size_t input_size = section.content.size() - header_size;
    const auto *input = section.content.data() + header_size;
    std::vector<unsigned char> output(size);
    unsigned char empty = 0;
    auto *destination = output.empty() ? &empty : output.data();
    bool decoded = false;
    if (kind == ELFCOMPRESS_ZLIB) {
      uLongf produced = std::max<size_t>(1, output.size());
      uLong consumed = input_size;
      decoded = uncompress2(destination, &produced, input, &consumed) == Z_OK &&
                produced == size && consumed == input_size;
    } else {
      const auto frame_size = ZSTD_findFrameCompressedSize(input, input_size);
      const auto produced =
          ZSTD_decompress(destination, output.size(), input, input_size);
      decoded = input_size >= 4 && !std::memcmp(input, "\x28\xb5\x2f\xfd", 4) &&
                !ZSTD_isError(frame_size) && frame_size == input_size &&
                !ZSTD_isError(produced) && produced == size;
    }
    if (!decoded) {
      error = "compressed debug section is corrupt, truncated, or has trailing "
              "data: " +
              section.name;
      return false;
    }
    retained_ = retained_ - section.content.size() + output.size();
    section.content = std::move(output);
    section.header.sh_size = size;
    section.header.sh_flags &= ~uint64_t(SHF_COMPRESSED);
    section.header.sh_addralign = alignment;
    renamed[index] = gnu;
    changed = true;
  }
  // Names change only after decompression. Relocation targets and symbol
  // section indexes are authoritative and must never be renumbered.
  for (size_t index = 1; index < sections_.size(); ++index) {
    auto &section = sections_[index];
    std::string name;
    if (renamed[index])
      name = ".debug_" + section.name.substr(8);
    else if (section.header.sh_type == SHT_RELA &&
             section.header.sh_info < renamed.size() &&
             renamed[section.header.sh_info] &&
             section.name.compare(0, 13, ".rela.zdebug_") == 0)
      name = ".rela.debug_" + section.name.substr(13);
    if (name.empty())
      continue;
    if (std::any_of(sections_.begin(), sections_.end(),
                    [&](const auto &other) {
                      return &other != &section && other.name == name;
                    }) ||
        name.size() + 1 > object_size_limit - retained_) {
      error = "ambiguous or oversized decompressed debug section name";
      return false;
    }
    auto &strings = sections_[names_];
    section.header.sh_name = strings.content.size();
    strings.content.insert(strings.content.end(), name.begin(), name.end());
    strings.content.push_back(0);
    strings.header.sh_size = strings.content.size();
    retained_ += name.size() + 1;
    section.name = std::move(name);
  }
  return true;
}

uint32_t ct_kernel_object::section_count() const { return sections_.size(); }

std::string ct_kernel_object::section_name(uint32_t index) const {
  return index < sections_.size() ? sections_[index].name : std::string();
}

const Elf64_Shdr *ct_kernel_object::section_header(uint32_t index) const {
  return index < sections_.size() ? &sections_[index].header : nullptr;
}

const std::vector<unsigned char> *
ct_kernel_object::section_content(uint32_t index) const {
  return index < sections_.size() ? &sections_[index].content : nullptr;
}

bool ct_kernel_object::replace_section(
    uint32_t index, const std::vector<unsigned char> &content,
    std::string &error) {
  if (!valid(error))
    return false;
  if (!index || index >= sections_.size() ||
      sections_[index].header.sh_type == SHT_NULL ||
      sections_[index].header.sh_type == SHT_NOBITS ||
      content.size() >
          object_size_limit - (retained_ - sections_[index].content.size()) ||
      (sections_[index].header.sh_entsize &&
       content.size() % sections_[index].header.sh_entsize)) {
    error = "invalid kernel object replacement section";
    return false;
  }
  retained_ = retained_ - sections_[index].content.size() + content.size();
  sections_[index].content = content;
  sections_[index].header.sh_size = content.size();
  return true;
}

bool ct_kernel_object::resize_nobits(uint32_t index, uint64_t size,
                                     std::string &error) {
  if (!valid(error))
    return false;
  if (!index || index >= sections_.size() ||
      sections_[index].header.sh_type != SHT_NOBITS ||
      size > object_size_limit ||
      (sections_[index].header.sh_entsize &&
       size % sections_[index].header.sh_entsize)) {
    error = "invalid or oversized kernel NOBITS section";
    return false;
  }
  sections_[index].header.sh_size = size;
  return true;
}

uint32_t ct_kernel_object::add_section(
    const std::string &name, uint32_t type, uint64_t flags, uint64_t alignment,
    uint64_t entry_size, uint32_t link, uint32_t info,
    const std::vector<unsigned char> &content, std::string &error) {
  if (!valid(error))
    return 0;
  if (name.empty() || name.find('\0') != std::string::npos ||
      sections_.size() >= object_section_limit || type == SHT_NULL ||
      (type == SHT_NOBITS && !content.empty()) ||
      (alignment && (alignment & (alignment - 1))) ||
      (entry_size && content.size() % entry_size) ||
      content.size() > object_size_limit ||
      std::any_of(
          sections_.begin(), sections_.end(),
          [&](const Section &section) { return section.name == name; })) {
    error = "invalid or duplicate new kernel object section";
    return 0;
  }
  auto &strings = sections_[names_];
  if (name.size() >= object_size_limit - retained_ ||
      content.size() > object_size_limit - retained_ - name.size() - 1) {
    error = "kernel object section-name table exceeds size limit";
    return 0;
  }
  Section section;
  section.name = name;
  section.header.sh_name = strings.content.size();
  section.header.sh_type = type;
  section.header.sh_flags = flags;
  section.header.sh_size = content.size();
  section.header.sh_link = link;
  section.header.sh_info = info;
  section.header.sh_addralign = alignment;
  section.header.sh_entsize = entry_size;
  section.content = content;
  strings.content.insert(strings.content.end(), name.begin(), name.end());
  strings.content.push_back(0);
  strings.header.sh_size = strings.content.size();
  retained_ += name.size() + 1 + content.size();
  const uint32_t index = sections_.size();
  sections_.push_back(std::move(section));
  return index;
}

bool ct_kernel_object::replace_symbol(uint32_t table, uint32_t index,
                                      const Elf64_Sym &symbol,
                                      std::string &error) {
  if (!valid(error))
    return false;
  if (table >= sections_.size() ||
      sections_[table].header.sh_type != SHT_SYMTAB ||
      sections_[table].header.sh_entsize != sizeof(Elf64_Sym) ||
      index >= sections_[table].content.size() / sizeof(Elf64_Sym) ||
      ((ELF64_ST_BIND(symbol.st_info) == STB_LOCAL) !=
       (index < sections_[table].header.sh_info))) {
    error = "invalid symbol replacement or local/global ordering change";
    return false;
  }
  std::memcpy(sections_[table].content.data() + index * sizeof(symbol), &symbol,
              sizeof(symbol));
  return true;
}

bool ct_kernel_object::append_symbol(uint32_t table, const std::string &name,
                                     Elf64_Sym symbol, uint32_t &index,
                                     std::string &error) {
  index = 0;
  if (!valid(error))
    return false;
  if (table >= sections_.size() ||
      sections_[table].header.sh_type != SHT_SYMTAB ||
      sections_[table].header.sh_entsize != sizeof(Elf64_Sym) || name.empty() ||
      name.find('\0') != std::string::npos ||
      (ELF64_ST_BIND(symbol.st_info) != STB_GLOBAL &&
       ELF64_ST_BIND(symbol.st_info) != STB_WEAK)) {
    error = "new kernel symbols must be named global or weak symbols";
    return false;
  }
  auto &symbols = sections_[table];
  if (symbols.header.sh_link >= sections_.size() ||
      sections_[symbols.header.sh_link].header.sh_type != SHT_STRTAB ||
      sizeof(symbol) > object_size_limit - retained_) {
    error = "invalid or oversized kernel symbol table";
    return false;
  }
  auto &strings = sections_[symbols.header.sh_link];
  if (strings.content.empty() || strings.content.back() ||
      name.size() >= object_size_limit - retained_ - sizeof(symbol)) {
    error = "invalid or oversized kernel symbol string table";
    return false;
  }
  symbol.st_name = strings.content.size();
  strings.content.insert(strings.content.end(), name.begin(), name.end());
  strings.content.push_back(0);
  strings.header.sh_size = strings.content.size();
  index = symbols.content.size() / sizeof(symbol);
  const auto *bytes = reinterpret_cast<const unsigned char *>(&symbol);
  symbols.content.insert(symbols.content.end(), bytes, bytes + sizeof(symbol));
  symbols.header.sh_size = symbols.content.size();
  retained_ += name.size() + 1 + sizeof(symbol);
  return true;
}

bool ct_kernel_object::replace_relocation(uint32_t table, uint32_t index,
                                          const Elf64_Rela &relocation,
                                          std::string &error) {
  if (!valid(error))
    return false;
  if (table >= sections_.size() ||
      sections_[table].header.sh_type != SHT_RELA ||
      sections_[table].header.sh_entsize != sizeof(Elf64_Rela) ||
      index >= sections_[table].content.size() / sizeof(Elf64_Rela)) {
    error = "invalid relocation replacement";
    return false;
  }
  std::memcpy(sections_[table].content.data() + index * sizeof(relocation),
              &relocation, sizeof(relocation));
  return true;
}

bool ct_kernel_object::add_relocation(uint32_t target, uint32_t symbols,
                                      const Elf64_Rela &relocation,
                                      std::string &error) {
  if (!valid(error))
    return false;
  if (!target || target >= sections_.size() || symbols >= sections_.size() ||
      sections_[symbols].header.sh_type != SHT_SYMTAB ||
      sections_[symbols].header.sh_entsize != sizeof(Elf64_Sym) ||
      ELF64_R_SYM(relocation.r_info) >=
          sections_[symbols].content.size() / sizeof(Elf64_Sym)) {
    error = "invalid new relocation target or symbol";
    return false;
  }
  if (!object_relocation_fits(relocation, sections_[target].header.sh_size,
                              error))
    return false;
  for (auto &section : sections_) {
    if (section.header.sh_type != SHT_RELA ||
        section.header.sh_info != target || section.header.sh_link != symbols)
      continue;
    if (section.header.sh_entsize != sizeof(relocation) ||
        sizeof(relocation) > object_size_limit - retained_) {
      error = "invalid or oversized relocation table";
      return false;
    }
    const auto *bytes = reinterpret_cast<const unsigned char *>(&relocation);
    section.content.insert(section.content.end(), bytes,
                           bytes + sizeof(relocation));
    section.header.sh_size = section.content.size();
    retained_ += sizeof(relocation);
    return true;
  }
  const auto *bytes = reinterpret_cast<const unsigned char *>(&relocation);
  return add_section(".rela" + sections_[target].name, SHT_RELA, SHF_INFO_LINK,
                     alignof(Elf64_Rela), sizeof(Elf64_Rela), symbols, target,
                     {bytes, bytes + sizeof(relocation)}, error) != 0;
}

bool ct_kernel_object::serialize(std::vector<unsigned char> &bytes,
                                 std::string &error) const {
  bytes.clear();
  if (!valid(error))
    return false;
  const auto fail = [&](const char *reason) {
    bytes.clear();
    error = reason;
    return false;
  };
  const auto string_valid = [&](uint32_t index, uint32_t offset) {
    if (index >= sections_.size())
      return false;
    const auto &section = sections_[index];
    return section.header.sh_type == SHT_STRTAB &&
           offset < section.content.size() &&
           std::memchr(section.content.data() + offset, 0,
                       section.content.size() - offset);
  };
  std::vector<Elf64_Shdr> headers;
  size_t size = sizeof(header_);
  for (uint32_t index = 0; index < sections_.size(); ++index) {
    const auto &section = sections_[index];
    auto raw = section.header;
    if (!string_valid(names_, raw.sh_name))
      return fail("invalid section name after kernel object rewriting");
    if (raw.sh_type == SHT_STRTAB &&
        (section.content.empty() || section.content.front() ||
         section.content.back()))
      return fail("invalid string table after kernel object rewriting");
    if (raw.sh_type == SHT_SYMTAB) {
      if (raw.sh_entsize != sizeof(Elf64_Sym) ||
          raw.sh_info > section.content.size() / sizeof(Elf64_Sym))
        return fail("invalid symbol table after kernel object rewriting");
      for (size_t offset = 0; offset < section.content.size();
           offset += sizeof(Elf64_Sym)) {
        Elf64_Sym symbol;
        std::memcpy(&symbol, section.content.data() + offset, sizeof(symbol));
        if (!string_valid(raw.sh_link, symbol.st_name) ||
            ((ELF64_ST_BIND(symbol.st_info) == STB_LOCAL) !=
             (offset / sizeof(symbol) < raw.sh_info)))
          return fail("invalid symbol name or local/global ordering");
        if (symbol.st_shndx == SHN_XINDEX)
          return fail(
              "extended symbol indexes are not supported for rewriting");
        if (symbol.st_shndx != SHN_UNDEF && symbol.st_shndx < SHN_LORESERVE &&
            (symbol.st_shndx >= sections_.size() ||
             symbol.st_value > sections_[symbol.st_shndx].header.sh_size ||
             symbol.st_size >
                 sections_[symbol.st_shndx].header.sh_size - symbol.st_value))
          return fail("rewritten symbol extends beyond its section");
      }
    } else if (raw.sh_type == SHT_REL) {
      return fail("implicit-addend relocations are unsupported for rewriting");
    } else if (raw.sh_type == SHT_RELA) {
      if (raw.sh_entsize != sizeof(Elf64_Rela) ||
          raw.sh_info >= sections_.size() || raw.sh_link >= sections_.size() ||
          sections_[raw.sh_link].header.sh_type != SHT_SYMTAB)
        return fail("invalid relocation table after kernel object rewriting");
      const size_t symbols =
          sections_[raw.sh_link].content.size() / sizeof(Elf64_Sym);
      for (size_t offset = 0; offset < section.content.size();
           offset += sizeof(Elf64_Rela)) {
        Elf64_Rela relocation;
        std::memcpy(&relocation, section.content.data() + offset,
                    sizeof(relocation));
        if (ELF64_R_SYM(relocation.r_info) >= symbols)
          return fail("rewritten relocation refers to an absent symbol");
        if (!object_relocation_fits(
                relocation, sections_[raw.sh_info].header.sh_size, error))
          return false;
      }
    }
    if (index && raw.sh_type != SHT_NULL) {
      const uint64_t alignment = std::max<uint64_t>(1, raw.sh_addralign);
      const uint64_t padding = -uint64_t(size) & (alignment - 1);
      if (padding > object_size_limit - size)
        return fail("kernel object alignment exceeds output size limit");
      raw.sh_offset = size + padding;
      if (raw.sh_type != SHT_NOBITS) {
        if (section.content.size() != raw.sh_size ||
            section.content.size() > object_size_limit - raw.sh_offset)
          return fail("kernel object payload exceeds output size limit");
        size = raw.sh_offset + section.content.size();
      }
    }
    headers.push_back(raw);
  }
  const size_t padding = -size & (alignof(Elf64_Shdr) - 1);
  if (padding > object_size_limit - size ||
      headers.size() >
          (object_size_limit - size - padding) / sizeof(Elf64_Shdr))
    return fail("kernel object section table exceeds output size limit");
  Elf64_Ehdr header = header_;
  header.e_shoff = size + padding;
  header.e_shnum = headers.size() >= SHN_LORESERVE ? 0 : headers.size();
  header.e_shstrndx = names_ >= SHN_LORESERVE ? SHN_XINDEX : names_;
  headers[0].sh_size = header.e_shnum ? 0 : headers.size();
  headers[0].sh_link = header.e_shstrndx == SHN_XINDEX ? names_ : 0;
  bytes.resize(header.e_shoff + headers.size() * sizeof(Elf64_Shdr));
  std::memcpy(bytes.data(), &header, sizeof(header));
  for (uint32_t index = 1; index < sections_.size(); ++index) {
    const auto &content = sections_[index].content;
    if (!content.empty())
      std::memcpy(bytes.data() + headers[index].sh_offset, content.data(),
                  content.size());
  }
  std::memcpy(bytes.data() + header.e_shoff, headers.data(),
              headers.size() * sizeof(Elf64_Shdr));
  return true;
}
