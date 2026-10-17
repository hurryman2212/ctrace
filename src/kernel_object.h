#ifndef CTRACE_KERNEL_OBJECT_H
#define CTRACE_KERNEL_OBJECT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <elf.h>

#include "kernel_image.h"

// Mutable ET_REL layout. Existing section indexes and unmodified payloads stay
// intact; serialization discards file gaps and any old appended signature.
class ct_kernel_object {
  struct Section {
    Elf64_Shdr header{};
    std::string name;
    std::vector<unsigned char> content;
  };

  Elf64_Ehdr header_{};
  uint32_t names_ = 0;
  size_t retained_ = 0;
  std::vector<Section> sections_;
  std::string error_;

public:
  explicit ct_kernel_object(const ct_kernel_image &image);
  bool valid(std::string &error) const;
  // Normalize only nonallocated compressed debug sections. Existing section
  // indexes, symbols and relocation offsets retain their original meanings.
  bool decompress_debug_sections(bool &changed, std::string &error);
  uint32_t section_count() const;
  std::string section_name(uint32_t index) const;
  const Elf64_Shdr *section_header(uint32_t index) const;
  const std::vector<unsigned char> *section_content(uint32_t index) const;
  bool replace_section(uint32_t index,
                       const std::vector<unsigned char> &content,
                       std::string &error);
  bool resize_nobits(uint32_t index, uint64_t size, std::string &error);
  // Zero means failure. New NOBITS sections start empty and may be resized
  // without allocating a payload. Existing NOBITS sizes remain preserved.
  // Header/content pointers are invalidated by adding a section.
  uint32_t add_section(const std::string &name, uint32_t type, uint64_t flags,
                       uint64_t alignment, uint64_t entry_size, uint32_t link,
                       uint32_t info, const std::vector<unsigned char> &content,
                       std::string &error);
  bool replace_symbol(uint32_t table, uint32_t index, const Elf64_Sym &symbol,
                      std::string &error);
  // Appended global/weak entries preserve sh_info and existing relocation IDs.
  // Adding local symbols would require reordering and is rejected.
  bool append_symbol(uint32_t table, const std::string &name, Elf64_Sym symbol,
                     uint32_t &index, std::string &error);
  bool replace_relocation(uint32_t table, uint32_t index,
                          const Elf64_Rela &relocation, std::string &error);
  bool add_relocation(uint32_t target, uint32_t symbols,
                      const Elf64_Rela &relocation, std::string &error);
  // Validate the completed graph after all offset remapping, then repack it.
  bool serialize(std::vector<unsigned char> &bytes, std::string &error) const;
};

#endif
