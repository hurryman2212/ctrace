// SPDX-License-Identifier: MIT

#include <cerrno>
#include <cstring>

#include <elf.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "analysis_image.hh"
#include "ctrace_contract.h"
#include "shared_objects_platform.hh"

// ELF64 code payload offset, shared by the writer and instruction validator.
enum { image_code_offset = 4096 };

bool ct_analysis_image_matches(int descriptor, uint64_t offset,
                               const unsigned char *bytes, size_t size) {
  unsigned char original[15]; // Maximum x86 instruction size.
  if (descriptor < 0 || !bytes || !size || size > sizeof(original) ||
      offset >= CT_ANALYSIS_IMAGE_LIMIT ||
      size > CT_ANALYSIS_IMAGE_LIMIT - offset)
    return false;
  size_t read = 0;
  while (read < size) {
    const ssize_t count = pread(descriptor, original + read, size - read,
                                image_code_offset + offset + read);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    read += (size_t)count;
  }
  return memcmp(original, bytes, size) == 0;
}

int ct_analysis_image_create(const unsigned char *bytes, size_t size,
                             uint64_t entry_offset, char identity[65]) {
  if (identity)
    identity[0] = 0;
  if (!bytes || !identity || !size || size > CT_ANALYSIS_IMAGE_LIMIT ||
      entry_offset >= size) {
    errno = EINVAL;
    return -1;
  }
#if !defined(__linux__) || !defined(__x86_64__) ||                             \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
  errno = ENOTSUP;
  return -1;
#else
  static_assert(sizeof(Elf64_Ehdr) == 64 && sizeof(Elf64_Phdr) == 56 &&
                    sizeof(Elf64_Shdr) == 64,
                "ELF64 file layout");
  // This is a file-format offset/alignment, not the live mapping's page size.
  // Header bytes are outside PT_LOAD and never masquerade as original code.
  unsigned char header[image_code_offset] = {};
  Elf64_Ehdr elf = {};
  memcpy(elf.e_ident, ELFMAG, SELFMAG);
  elf.e_ident[EI_CLASS] = ELFCLASS64;
  elf.e_ident[EI_DATA] = ELFDATA2LSB;
  elf.e_ident[EI_VERSION] = EV_CURRENT;
  elf.e_type = ET_DYN;
  elf.e_machine = EM_X86_64;
  elf.e_version = EV_CURRENT;
  elf.e_entry = entry_offset;
  elf.e_phoff = sizeof(elf);
  elf.e_shoff = sizeof(elf) + sizeof(Elf64_Phdr);
  elf.e_ehsize = sizeof(elf);
  elf.e_phentsize = sizeof(Elf64_Phdr);
  elf.e_phnum = 1;
  elf.e_shentsize = sizeof(Elf64_Shdr);
  elf.e_shnum = 3;
  elf.e_shstrndx = 2;
  const Elf64_Phdr segment = {.p_type = PT_LOAD,
                              .p_flags = PF_R | PF_X,
                              .p_offset = sizeof(header),
                              .p_vaddr = {},
                              .p_paddr = {},
                              .p_filesz = size,
                              .p_memsz = size,
                              .p_align = sizeof(header)};
  static const char names[] = "\0.text\0.shstrtab";
  const size_t names_offset = elf.e_shoff + 3 * sizeof(Elf64_Shdr);
  Elf64_Shdr sections[3] = {};
  sections[1].sh_name = 1;
  sections[1].sh_type = SHT_PROGBITS;
  sections[1].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  sections[1].sh_offset = sizeof(header);
  sections[1].sh_size = size;
  sections[1].sh_addralign = 1;
  sections[2].sh_name = 7;
  sections[2].sh_type = SHT_STRTAB;
  sections[2].sh_offset = names_offset;
  sections[2].sh_size = sizeof(names);
  sections[2].sh_addralign = 1;
  memcpy(header, &elf, sizeof(elf));
  memcpy(header + elf.e_phoff, &segment, sizeof(segment));
  memcpy(header + elf.e_shoff, sections, sizeof(sections));
  memcpy(header + names_offset, names, sizeof(names));
  static const char contract[] = "ctrace-analysis-image:" CTRACE_CONTRACT_HASH;
  const ct_digest_part parts[] = {
      {contract, sizeof(contract)}, {header, sizeof(header)}, {bytes, size}};
  unsigned char digest[32];
  if (!ct_shared_platform_digest_parts(parts, 3, digest)) {
    errno = EIO;
    return -1;
  }
  bool noexec = true;
  int descriptor =
      (int)syscall(SYS_memfd_create, "ctrace-analysis-image",
                   MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL);
  if (descriptor < 0 && errno == EINVAL) {
    noexec = false;
    descriptor = (int)syscall(SYS_memfd_create, "ctrace-analysis-image",
                              MFD_CLOEXEC | MFD_ALLOW_SEALING);
  }
  if (descriptor < 0)
    return -1;
  if (!ct_shared_platform_adopt(descriptor, true)) {
    const int error = errno;
    close(descriptor);
    errno = error;
    return -1;
  }
  bool complete = fchmod(descriptor, 0444) == 0 &&
                  ftruncate(descriptor, sizeof(header) + size) == 0;
  off_t offset = 0;
  for (size_t part = 1; complete && part < 3; ++part) {
    size_t written = 0;
    while (written < parts[part].size) {
      const ssize_t count =
          pwrite(descriptor, (const unsigned char *)parts[part].data + written,
                 parts[part].size - written, offset + written);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0) {
        if (!count)
          errno = EIO;
        complete = false;
        break;
      }
      written += (size_t)count;
    }
    offset += parts[part].size;
  }
  if (complete)
    complete = fcntl(descriptor, F_ADD_SEALS,
                     F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL |
                         (noexec ? F_SEAL_EXEC : 0)) == 0;
  if (!complete) {
    const int error = errno;
    ct_shared_platform_close(descriptor);
    errno = error;
    return -1;
  }
  static const char hex[] = "0123456789abcdef";
  for (size_t index = 0; index < sizeof(digest); ++index) {
    identity[index * 2] = hex[digest[index] >> 4];
    identity[index * 2 + 1] = hex[digest[index] & 15];
  }
  identity[64] = 0;
  return descriptor;
#endif
}
