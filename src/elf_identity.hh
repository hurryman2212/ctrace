// SPDX-License-Identifier: MIT

#ifndef CTRACE_ELF_IDENTITY_H
#define CTRACE_ELF_IDENTITY_H

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <elf.h>

/* A build-id verifies that a content-hashed file describes the loaded image.
 * It is not itself the content hash. Missing/malformed notes fail closed. */
static inline bool
ct_elf_build_id(bool (*read_bytes)(void *, uint64_t, void *, size_t),
                void *context, bool loaded, char identity[129]) {
  identity[0] = '\0';
  Elf64_Ehdr header;
  if (!read_bytes(context, 0, &header, sizeof(header)) ||
      memcmp(header.e_ident, ELFMAG, SELFMAG) ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum ||
      header.e_phnum > 1024 ||
      header.e_phoff > UINT64_MAX - header.e_phnum * sizeof(Elf64_Phdr))
    return false;
  uint64_t preferred_base = 0;
  if (loaded) {
    bool found = false;
    for (unsigned index = 0; index < header.e_phnum; ++index) {
      Elf64_Phdr segment;
      if (!read_bytes(context, header.e_phoff + index * sizeof(segment),
                      &segment, sizeof(segment)))
        return false;
      if (segment.p_type == PT_LOAD && segment.p_offset == 0 &&
          segment.p_filesz >= sizeof(header)) {
        preferred_base = segment.p_vaddr;
        found = true;
        break;
      }
    }
    if (!found)
      return false;
  }
  for (unsigned index = 0; index < header.e_phnum; ++index) {
    Elf64_Phdr segment;
    if (!read_bytes(context, header.e_phoff + index * sizeof(segment), &segment,
                    sizeof(segment)))
      return false;
    if (segment.p_type != PT_NOTE)
      continue;
    if (loaded && segment.p_vaddr < preferred_base)
      return false;
    const uint64_t begin =
        loaded ? segment.p_vaddr - preferred_base : segment.p_offset;
    if (segment.p_filesz > 1024 * 1024 || begin > UINT64_MAX - segment.p_filesz)
      return false;
    const uint64_t end = begin + segment.p_filesz;
    for (uint64_t offset = begin; end - offset >= sizeof(Elf64_Nhdr);) {
      Elf64_Nhdr note;
      if (!read_bytes(context, offset, &note, sizeof(note)))
        return false;
      offset += sizeof(note);
      const uint64_t name_size = ((uint64_t)note.n_namesz + 3) & ~UINT64_C(3);
      const uint64_t data_size = ((uint64_t)note.n_descsz + 3) & ~UINT64_C(3);
      if (name_size > end - offset || data_size > end - offset - name_size)
        return false;
      if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
          note.n_descsz && note.n_descsz <= 64) {
        char name[4];
        unsigned char bytes[64];
        if (!read_bytes(context, offset, name, sizeof(name)) ||
            !read_bytes(context, offset + name_size, bytes, note.n_descsz))
          return false;
        if (!memcmp(name, "GNU", 4)) {
          static const char hex[] = "0123456789abcdef";
          for (unsigned byte = 0; byte < note.n_descsz; ++byte) {
            identity[byte * 2] = hex[bytes[byte] >> 4];
            identity[byte * 2 + 1] = hex[bytes[byte] & 15];
          }
          identity[note.n_descsz * 2] = '\0';
          return true;
        }
      }
      offset += name_size + data_size;
    }
  }
  return false;
}

#endif
