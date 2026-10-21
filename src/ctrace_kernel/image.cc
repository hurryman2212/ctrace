// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <map>
#include <memory>
#include <string_view>

#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/SHA256.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>

#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cache.hh"
#include "image.hh"
#include "object.hh"
#include "sign.hh"

static bool decompress_kernel(std::vector<unsigned char> &bytes,
                              bool boot_payload, std::string &error) {
  const auto starts = [&](std::string_view magic) {
    return bytes.size() >= magic.size() &&
           std::memcmp(bytes.data(), magic.data(), magic.size()) == 0;
  };
  const bool gzip = starts("\x1f\x8b");
  const bool xz = starts(std::string_view("\xfd"
                                          "7zXZ\0",
                                          6));
  const bool zstd = starts("\x28\xb5\x2f\xfd");
  if (!gzip && !xz && !zstd) {
    if (boot_payload)
      error = "kernel boot payload uses an unsupported compression format";
    return !boot_payload;
  }
  const std::string subject = boot_payload ? "kernel boot payload" : "module";

  std::vector<unsigned char> output;
  // Streaming avoids trusting a frame's claimed decompressed size.
  std::array<unsigned char, 64 * 1024> chunk;
  const auto append = [&](size_t size) {
    if (size > output.max_size() - output.size()) {
      error = "decompressed " + subject + " size is not representable";
      return false;
    }
    output.insert(output.end(), chunk.begin(), chunk.begin() + size);
    return true;
  };
  bool valid = true, complete = false;
  size_t remaining = 0;
  if (gzip) {
    z_stream stream{};
    if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK) {
      error = "cannot initialize gzip " + subject + " decoder";
      return false;
    }
    size_t consumed = 0;
    while (valid && !complete) {
      if (!stream.avail_in && consumed < bytes.size()) {
        const size_t part = std::min<size_t>(bytes.size() - consumed, UINT_MAX);
        stream.next_in = bytes.data() + consumed;
        stream.avail_in = part;
        consumed += part;
      }
      const auto before = stream.avail_in;
      stream.next_out = chunk.data();
      stream.avail_out = chunk.size();
      const int result = inflate(&stream, Z_NO_FLUSH);
      const size_t produced = chunk.size() - stream.avail_out;
      complete = result == Z_STREAM_END;
      valid = (result == Z_OK || complete) && append(produced) &&
              (complete || produced || before != stream.avail_in);
    }
    remaining = bytes.size() - consumed + stream.avail_in;
    inflateEnd(&stream);
  } else if (xz) {
    lzma_stream stream = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&stream, UINT64_MAX, 0) != LZMA_OK) {
      error = "cannot initialize xz " + subject + " decoder";
      return false;
    }
    stream.next_in = bytes.data();
    stream.avail_in = bytes.size();
    while (valid && !complete) {
      const auto before = stream.avail_in;
      stream.next_out = chunk.data();
      stream.avail_out = chunk.size();
      const auto result = lzma_code(&stream, LZMA_FINISH);
      const size_t produced = chunk.size() - stream.avail_out;
      complete = result == LZMA_STREAM_END;
      valid = (result == LZMA_OK || complete) && append(produced) &&
              (complete || produced || before != stream.avail_in);
    }
    remaining = stream.avail_in;
    lzma_end(&stream);
  } else {
    std::unique_ptr<ZSTD_DStream, decltype(&ZSTD_freeDStream)> stream(
        ZSTD_createDStream(), ZSTD_freeDStream);
    const auto bounds = ZSTD_dParam_getBounds(ZSTD_d_windowLogMax);
    if (!stream || ZSTD_isError(bounds.error) ||
        ZSTD_isError(ZSTD_DCtx_setParameter(stream.get(), ZSTD_d_windowLogMax,
                                            bounds.upperBound))) {
      error = "cannot initialize zstd " + subject + " decoder";
      return false;
    }
    ZSTD_inBuffer input{bytes.data(), bytes.size(), 0};
    while (valid && !complete) {
      const auto before = input.pos;
      ZSTD_outBuffer decoded{chunk.data(), chunk.size(), 0};
      const auto result = ZSTD_decompressStream(stream.get(), &decoded, &input);
      complete = result == 0;
      valid = !ZSTD_isError(result) && append(decoded.pos) &&
              (complete || decoded.pos || before != input.pos);
    }
    remaining = input.size - input.pos;
  }
  // x86 boot payloads may append the decoded size (scripts/Makefile.lib).
  // Modules cannot: their signature, if present, belongs inside the stream.
  if (boot_payload && valid && complete && remaining == 4) {
    const size_t offset = bytes.size() - remaining;
    uint32_t expected_size = 0;
    for (unsigned index = 0; index < 4; ++index)
      expected_size |= uint32_t(bytes[offset + index]) << (8 * index);
    if (expected_size == output.size())
      remaining = 0;
  }
  // Reject additional streams and arbitrary trailing bytes.
  if (!valid || !complete || remaining) {
    if (error.empty())
      error =
          "compressed " + subject +
          (remaining && complete ? " contains trailing data or multiple streams"
                                 : " is truncated, corrupt, or unsupported");
    return false;
  }
  bytes = std::move(output);
  return true;
}

bool ct_kernel_boot_elf(const std::vector<unsigned char> &input,
                        std::vector<unsigned char> &output,
                        std::string &error) {
  error.clear();
  const auto elf = [](const std::vector<unsigned char> &bytes) {
    return bytes.size() >= SELFMAG &&
           std::memcmp(bytes.data(), ELFMAG, SELFMAG) == 0;
  };
  if (elf(input)) {
    output = input;
    return true;
  }
  // These fields are part of the x86 boot protocol, not ELF offsets.
  // Protocol 2.08 first defined payload_offset and payload_length.
  if (input.size() < 0x250 || input[0x1fe] != 0x55 || input[0x1ff] != 0xaa ||
      std::memcmp(input.data() + 0x202, "HdrS", 4) != 0) {
    error = "kernel image has no supported x86 boot header";
    return false;
  }
  const auto little = [&](size_t offset, unsigned size) {
    uint32_t value = 0;
    for (unsigned index = 0; index < size; ++index)
      value |= uint32_t(input[offset + index]) << (8 * index);
    return value;
  };
  if (little(0x206, 2) < 0x208) {
    error = "kernel boot image predates the payload geometry protocol";
    return false;
  }
  const size_t setup_size = (size_t(input[0x1f1] ? input[0x1f1] : 4) + 1) * 512;
  const size_t offset = little(0x248, 4), length = little(0x24c, 4);
  if (setup_size > input.size() || offset > input.size() - setup_size ||
      !length || length > input.size() - setup_size - offset) {
    error = "kernel boot payload is outside the input image";
    return false;
  }
  const size_t begin = setup_size + offset;
  std::vector<unsigned char> decoded(input.begin() + begin,
                                     input.begin() + begin + length);
  if (!elf(decoded) && !decompress_kernel(decoded, true, error))
    return false;
  if (!elf(decoded)) {
    error = "kernel boot payload does not contain a vmlinux ELF";
    return false;
  }
  output = std::move(decoded);
  return true;
}

bool ct_kernel_read_image(const std::string &path, ct_kernel_image &image,
                          std::string &error) {
  image = {};
  error.clear();
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) {
    error = std::strerror(errno);
    return false;
  }
  struct stat before{}, after{};
  bool valid = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
               before.st_size >= 2 &&
               uint64_t(before.st_size) <= image.bytes.max_size();
  if (valid) {
    image.bytes.resize(before.st_size);
    size_t done = 0;
    while (done < image.bytes.size()) {
      const ssize_t count =
          read(fd, image.bytes.data() + done, image.bytes.size() - done);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0) {
        valid = false;
        break;
      }
      done += size_t(count);
    }
  }
  valid = valid && fstat(fd, &after) == 0 && before.st_size == after.st_size &&
          before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
          before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
          before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
          before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  close(fd);
  if (!valid) {
    image = {};
    error = "module must be a stable regular file with a representable size";
    return false;
  }
  image.path = path;
  const auto fail = [&](const std::string &reason) {
    error = reason;
    image = {};
    return false;
  };
  const auto range = [&](uint64_t offset, uint64_t size) {
    return offset <= image.bytes.size() && size <= image.bytes.size() - offset;
  };
  if (!decompress_kernel(image.bytes, false, error))
    return fail(error);
  const auto checksum = [](const std::vector<unsigned char> &bytes) {
    const auto digest = llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(bytes));
    std::string text;
    for (unsigned char byte : digest) {
      text += "0123456789abcdef"[byte >> 4];
      text += "0123456789abcdef"[byte & 15];
    }
    return text;
  };
  image.input_digest = checksum(image.bytes);
  constexpr std::string_view signature = "~Module signature appended~\n";
  image.signature_present =
      image.bytes.size() >= signature.size() &&
      std::memcmp(image.bytes.data() + image.bytes.size() - signature.size(),
                  signature.data(), signature.size()) == 0;
  if (image.signature_present) {
    std::string signature_error;
    image.signature_format_valid = ct_kernel_signature_hash(
        image.bytes, image.signature_hash, signature_error);
  }
  if (image.bytes.size() < sizeof(Elf64_Ehdr))
    return fail("not a Linux x86-64 relocatable module image");
  Elf64_Ehdr header;
  std::memcpy(&header, image.bytes.data(), sizeof(header));
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_ident[EI_VERSION] != EV_CURRENT ||
      header.e_version != EV_CURRENT || header.e_machine != EM_X86_64 ||
      header.e_type != ET_REL || header.e_ehsize != sizeof(header) ||
      header.e_phnum || header.e_shentsize != sizeof(Elf64_Shdr) ||
      !range(header.e_shoff, sizeof(Elf64_Shdr)))
    return fail("not a Linux x86-64 relocatable module image");
  Elf64_Shdr first;
  std::memcpy(&first, image.bytes.data() + header.e_shoff, sizeof(first));
  const uint64_t count = header.e_shnum ? header.e_shnum : first.sh_size;
  const uint64_t strings =
      header.e_shstrndx == SHN_XINDEX ? first.sh_link : header.e_shstrndx;
  if (first.sh_type != SHT_NULL || !count || strings >= count ||
      count > uint64_t(UINT32_MAX) ||
      count > image.bytes.size() / sizeof(Elf64_Shdr) ||
      !range(header.e_shoff, count * sizeof(Elf64_Shdr)))
    return fail("invalid ELF section table");
  Elf64_Shdr string_table;
  std::memcpy(&string_table,
              image.bytes.data() + header.e_shoff +
                  strings * sizeof(Elf64_Shdr),
              sizeof(string_table));
  if (string_table.sh_type != SHT_STRTAB ||
      !range(string_table.sh_offset, string_table.sh_size))
    return fail("invalid ELF section-name table");
  bool compressed_debug = false;
  for (uint64_t index = 1; index < count; ++index) {
    Elf64_Shdr section;
    std::memcpy(&section,
                image.bytes.data() + header.e_shoff + index * sizeof(section),
                sizeof(section));
    if (section.sh_name >= string_table.sh_size)
      return fail("invalid section name offset");
    compressed_debug |=
        (section.sh_flags & SHF_COMPRESSED) ||
        (string_table.sh_size - section.sh_name >= 8 &&
         !std::memcmp(image.bytes.data() + string_table.sh_offset +
                          section.sh_name,
                      ".zdebug_", 8));
  }
  if (compressed_debug) {
    ct_kernel_object object(image);
    bool changed = false;
    std::vector<unsigned char> normalized;
    if (!object.decompress_debug_sections(changed, error) || !changed ||
        !object.serialize(normalized, error))
      return fail(error.empty()
                      ? "compressed debug normalization made no progress"
                      : error);
    image.bytes = std::move(normalized);
    std::memcpy(&header, image.bytes.data(), sizeof(header));
  }
  std::vector<uint32_t> names;
  for (uint64_t index = 0; index < count; ++index) {
    Elf64_Shdr raw;
    std::memcpy(&raw, image.bytes.data() + header.e_shoff + index * sizeof(raw),
                sizeof(raw));
    if (raw.sh_type != SHT_NULL && raw.sh_type != SHT_NOBITS &&
        !range(raw.sh_offset, raw.sh_size))
      return fail("section contents exceed module image");
    if ((raw.sh_addralign && (raw.sh_addralign & (raw.sh_addralign - 1))) ||
        (raw.sh_entsize && raw.sh_size % raw.sh_entsize))
      return fail("invalid ELF section alignment or entry size");
    image.sections.push_back({{},
                              raw.sh_type,
                              raw.sh_link,
                              raw.sh_info,
                              raw.sh_flags,
                              raw.sh_offset,
                              raw.sh_size,
                              raw.sh_addralign,
                              raw.sh_entsize});
    names.push_back(raw.sh_name);
  }
  size_t string_bytes = 0;
  const auto text = [&](uint32_t section, uint64_t offset, std::string &value) {
    if (section >= image.sections.size())
      return false;
    const auto &table = image.sections[section];
    if (table.type != SHT_STRTAB || offset >= table.size)
      return false;
    const char *begin = reinterpret_cast<const char *>(image.bytes.data() +
                                                       table.offset + offset);
    const auto *end =
        static_cast<const char *>(std::memchr(begin, 0, table.size - offset));
    if (!end || size_t(end - begin) > SIZE_MAX - string_bytes)
      return false;
    string_bytes += size_t(end - begin);
    value.assign(begin, end);
    return true;
  };
  std::map<std::string, std::string> metadata;
  uint32_t descriptor = 0;
  for (uint32_t index = 0; index < count; ++index) {
    auto &section = image.sections[index];
    if (!text(strings, names[index], section.name))
      return fail("invalid section name");
    if (section.name == ".gnu.linkonce.this_module") {
      if (descriptor || section.type != SHT_PROGBITS || !section.size ||
          !(section.flags & SHF_ALLOC))
        return fail("invalid module descriptor section");
      descriptor = index;
    }
    if (section.name != ".modinfo")
      continue;
    if (section.type != SHT_PROGBITS || (section.flags & SHF_COMPRESSED))
      return fail("invalid module metadata section");
    for (uint64_t offset = 0; offset < section.size;) {
      const char *begin = reinterpret_cast<const char *>(
          image.bytes.data() + section.offset + offset);
      const auto *end = static_cast<const char *>(
          std::memchr(begin, 0, section.size - offset));
      if (!end)
        return fail("unterminated module metadata entry");
      const std::string_view entry(begin, end - begin);
      offset += entry.size() + 1;
      const auto equals = entry.find('=');
      if (equals == std::string_view::npos)
        continue;
      const std::string key(entry.substr(0, equals));
      if (key != "name" && key != "vermagic" && key != "license")
        continue;
      const std::string value(entry.substr(equals + 1));
      const auto inserted = metadata.emplace(key, value);
      if (!inserted.second && inserted.first->second != value)
        return fail("conflicting module metadata: " + key);
    }
  }
  bool this_module = false, executable = false;
  std::map<uint32_t, uint64_t> symbol_counts;
  for (uint32_t index = 0; index < count; ++index) {
    const auto &section = image.sections[index];
    if (section.flags & SHF_EXECINSTR) {
      if (section.type != SHT_PROGBITS || (section.flags & SHF_COMPRESSED) ||
          !(section.flags & SHF_ALLOC))
        return fail("unsupported executable section: " + section.name);
      executable |= section.size != 0;
    }
    if (section.type != SHT_SYMTAB)
      continue;
    if (section.entry_size != sizeof(Elf64_Sym) || section.link >= count ||
        image.sections[section.link].type != SHT_STRTAB ||
        section.info > section.size / sizeof(Elf64_Sym))
      return fail("invalid module symbol table");
    symbol_counts[index] = section.size / sizeof(Elf64_Sym);
    if (symbol_counts[index] > uint64_t(UINT32_MAX) - image.symbols.size())
      return fail("module symbol inventory exceeds size limit");
    for (uint32_t item = 0; item < symbol_counts[index]; ++item) {
      Elf64_Sym raw;
      std::memcpy(&raw,
                  image.bytes.data() + section.offset + item * sizeof(raw),
                  sizeof(raw));
      ct_kernel_symbol symbol;
      if (!text(section.link, raw.st_name, symbol.name))
        return fail("invalid symbol name");
      if (raw.st_shndx == SHN_XINDEX)
        return fail("extended symbol section indexes are not supported yet");
      if (raw.st_shndx < SHN_LORESERVE && raw.st_shndx != SHN_UNDEF &&
          (raw.st_shndx >= count ||
           raw.st_value > image.sections[raw.st_shndx].size ||
           raw.st_size > image.sections[raw.st_shndx].size - raw.st_value))
        return fail("symbol extends beyond its section");
      symbol.table = index;
      symbol.index = item;
      symbol.section = raw.st_shndx;
      symbol.offset = raw.st_value;
      symbol.size = raw.st_size;
      symbol.type = ELF64_ST_TYPE(raw.st_info);
      symbol.binding = ELF64_ST_BIND(raw.st_info);
      if (symbol.name == "__this_module") {
        if (this_module || !descriptor || symbol.section != descriptor ||
            symbol.type != STT_OBJECT || symbol.offset ||
            symbol.size != image.sections[descriptor].size)
          return fail("invalid __this_module descriptor");
        this_module = true;
      }
      image.symbols.push_back(std::move(symbol));
    }
  }
  for (uint32_t index = 0; index < count; ++index) {
    const auto &section = image.sections[index];
    if (section.type == SHT_REL)
      return fail("x86-64 module requires explicit-addend relocations");
    if (section.type != SHT_RELA)
      continue;
    if (section.entry_size != sizeof(Elf64_Rela) || section.info >= count ||
        !symbol_counts.count(section.link))
      return fail("invalid relocation table");
    if (section.size / sizeof(Elf64_Rela) >
        uint64_t(UINT32_MAX) - image.relocations.size())
      return fail("module relocation inventory exceeds size limit");
    for (uint64_t offset = 0; offset < section.size;
         offset += sizeof(Elf64_Rela)) {
      Elf64_Rela raw;
      std::memcpy(&raw, image.bytes.data() + section.offset + offset,
                  sizeof(raw));
      size_t width = 0;
      switch (ELF64_R_TYPE(raw.r_info)) {
      case R_X86_64_NONE:
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
        return fail("unsupported x86-64 module relocation type " +
                    std::to_string(ELF64_R_TYPE(raw.r_info)));
      }
      if (raw.r_offset > image.sections[section.info].size ||
          width > image.sections[section.info].size - raw.r_offset ||
          ELF64_R_SYM(raw.r_info) >= symbol_counts[section.link])
        return fail(
            "relocation references an invalid section offset or symbol");
      image.relocations.push_back(
          {section.info, section.link, uint32_t(ELF64_R_SYM(raw.r_info)),
           uint32_t(ELF64_R_TYPE(raw.r_info)), raw.r_offset, raw.r_addend});
    }
  }
  if (!this_module || !executable || metadata["name"].empty() ||
      metadata["vermagic"].empty() || metadata["name"].size() >= 64 ||
      metadata["name"].find_first_not_of(
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") !=
          std::string::npos)
    return fail("ELF object lacks complete Linux module metadata");
  image.name = metadata["name"];
  image.vermagic = metadata["vermagic"];
  image.license = metadata["license"];
  image.digest = compressed_debug ? checksum(image.bytes) : image.input_digest;
  return true;
}

bool ct_kernel_inventory(const ct_kernel_image &image, std::string &json,
                         std::string &error) {
  error.clear();
  const std::string key = ct_cache_key({"kernel-inventory", image.digest});
  const auto valid_inventory = [&](const llvm::json::Value &value) {
    const auto *object = value.getAsObject();
    if (!object ||
        object->getString("contract_sha256") != KCTRACE_CONTRACT_HEX ||
        object->getBoolean("instrumented") != false ||
        object->getString("sha256") != image.digest ||
        object->getString("name") != image.name ||
        object->getString("vermagic") != image.vermagic ||
        object->getString("license") != image.license ||
        object->getBoolean("signature_present") != image.signature_present)
      return false;
    const auto *sections = object->getArray("sections");
    const auto *relocations = object->getArray("relocations");
    const auto *functions = object->getArray("functions");
    if (!sections || sections->size() != image.sections.size() ||
        !relocations || relocations->size() != image.relocations.size() ||
        !functions)
      return false;
    for (size_t index = 0; index < sections->size(); ++index) {
      const auto *item = (*sections)[index].getAsObject();
      const auto &expected = image.sections[index];
      if (!item || item->getInteger("index") != int64_t(index) ||
          item->getString("name") != expected.name ||
          item->getInteger("type") != expected.type ||
          item->getInteger("size") != int64_t(expected.size) ||
          !item->get("flags") ||
          item->get("flags")->getAsUINT64() != expected.flags)
        return false;
    }
    for (size_t index = 0; index < relocations->size(); ++index) {
      const auto *item = (*relocations)[index].getAsObject();
      const auto &expected = image.relocations[index];
      if (!item || item->getInteger("section") != expected.section ||
          item->getInteger("offset") != int64_t(expected.offset) ||
          item->getInteger("type") != expected.type ||
          item->getInteger("symbol_table") != expected.symbol_table ||
          item->getInteger("symbol") != expected.symbol ||
          item->getInteger("addend") != expected.addend)
        return false;
    }
    size_t index = 0, total = 0;
    for (const auto &symbol : image.symbols) {
      if (symbol.type != STT_FUNC || symbol.section == SHN_UNDEF ||
          symbol.section >= SHN_LORESERVE ||
          symbol.section >= image.sections.size() ||
          !(image.sections[symbol.section].flags & SHF_EXECINSTR))
        continue;
      if (index >= functions->size())
        return false;
      const auto *item = (*functions)[index++].getAsObject();
      if (!item || item->getString("name") != symbol.name ||
          item->getInteger("section") != symbol.section ||
          item->getInteger("offset") != int64_t(symbol.offset) ||
          item->getInteger("size") != int64_t(symbol.size) ||
          !item->getBoolean("decoded").has_value())
        return false;
      const auto *instructions = item->getArray("instructions");
      if (!instructions || instructions->size() > SIZE_MAX - total)
        return false;
      total += instructions->size();
      uint64_t offset = symbol.offset;
      for (const auto &instruction : *instructions) {
        const auto *row = instruction.getAsObject();
        if (!row)
          return false;
        const auto length = row->getInteger("size");
        const auto assembly = row->getString("assembly");
        if (row->getInteger("offset") != int64_t(offset) || !length ||
            *length <= 0 || *length > 15 ||
            uint64_t(*length) > symbol.offset + symbol.size - offset ||
            !assembly || assembly->empty() || assembly->size() >= 1024)
          return false;
        offset += *length;
      }
      if (*item->getBoolean("decoded") &&
          (!symbol.size || offset != symbol.offset + symbol.size))
        return false;
    }
    return index == functions->size();
  };
  std::vector<unsigned char> saved;
  if (ct_cache_read("kernel-analysis", key, saved)) {
    const std::string candidate(saved.begin(), saved.end());
    auto parsed = llvm::json::parse(candidate);
    if (parsed && valid_inventory(*parsed)) {
      json = candidate;
      return true;
    }
    if (!parsed)
      llvm::consumeError(parsed.takeError());
  }
  if (LLVMInitializeNativeTarget() || LLVMInitializeNativeDisassembler()) {
    error = "LLVM x86 disassembler initialization failed";
    return false;
  }
  const auto dispose = [](LLVMDisasmContextRef context) {
    LLVMDisasmDispose(context);
  };
  std::unique_ptr<void, decltype(dispose)> decoder(
      LLVMCreateDisasm("x86_64-pc-linux-gnu", nullptr, 0, nullptr, nullptr),
      dispose);
  if (!decoder) {
    error = "LLVM x86 disassembler unavailable";
    return false;
  }
  llvm::json::Array functions, sections, relocations;
  for (uint32_t index = 0; index < image.sections.size(); ++index) {
    const auto &section = image.sections[index];
    sections.emplace_back(llvm::json::Object{{"index", index},
                                             {"name", section.name},
                                             {"type", section.type},
                                             {"flags", section.flags},
                                             {"size", section.size}});
  }
  for (const auto &symbol : image.symbols) {
    if (symbol.type != STT_FUNC || symbol.section == SHN_UNDEF ||
        symbol.section >= SHN_LORESERVE ||
        symbol.section >= image.sections.size() ||
        !(image.sections[symbol.section].flags & SHF_EXECINSTR))
      continue;
    const auto &section = image.sections[symbol.section];
    llvm::json::Array instructions;
    bool complete = symbol.size != 0;
    for (uint64_t offset = 0; offset < symbol.size;) {
      char assembly[1024]{};
      // LLVM's C API takes a mutable buffer but never writes instruction bytes.
      const size_t length = LLVMDisasmInstruction(
          decoder.get(),
          const_cast<uint8_t *>(image.bytes.data()) + section.offset +
              symbol.offset + offset,
          std::min<uint64_t>(15, symbol.size - offset), symbol.offset + offset,
          assembly, sizeof(assembly));
      if (!length) {
        complete = false;
        break;
      }
      instructions.emplace_back(
          llvm::json::Object{{"offset", symbol.offset + offset},
                             {"size", length},
                             {"assembly", std::string(assembly)}});
      offset += length;
    }
    functions.emplace_back(
        llvm::json::Object{{"name", symbol.name},
                           {"section", symbol.section},
                           {"offset", symbol.offset},
                           {"size", symbol.size},
                           {"decoded", complete},
                           {"instructions", std::move(instructions)}});
  }
  for (const auto &relocation : image.relocations)
    relocations.emplace_back(
        llvm::json::Object{{"section", relocation.section},
                           {"offset", relocation.offset},
                           {"type", relocation.type},
                           {"symbol_table", relocation.symbol_table},
                           {"symbol", relocation.symbol},
                           {"addend", relocation.addend}});
  llvm::json::Object inventory{{"contract_sha256", KCTRACE_CONTRACT_HEX},
                               {"name", image.name},
                               {"sha256", image.digest},
                               {"vermagic", image.vermagic},
                               {"license", image.license},
                               {"signature_present", image.signature_present},
                               {"instrumented", false},
                               {"sections", std::move(sections)},
                               {"functions", std::move(functions)},
                               {"relocations", std::move(relocations)}};
  json = llvm::formatv("{0}", llvm::json::Value(std::move(inventory))).str();
  ct_cache_write("kernel-analysis", key, {json.begin(), json.end()});
  return true;
}
