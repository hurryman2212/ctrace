// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_IMAGE_H
#define CTRACE_KERNEL_IMAGE_H

#include <cstdint>
#include <string>
#include <vector>

struct ct_kernel_section {
  std::string name;
  uint32_t type = 0, link = 0, info = 0;
  uint64_t flags = 0, offset = 0, size = 0, alignment = 0, entry_size = 0;
};

struct ct_kernel_symbol {
  std::string name;
  uint32_t table = 0, index = 0, section = 0;
  uint64_t offset = 0, size = 0;
  uint8_t type = 0, binding = 0;
};

struct ct_kernel_relocation {
  uint32_t section = 0, symbol_table = 0, symbol = 0, type = 0;
  uint64_t offset = 0;
  int64_t addend = 0;
};

// An immutable snapshot. All addresses remain section-relative until load.
struct ct_kernel_image {
  std::string path, name, vermagic, license, digest;
  // Input ELF after whole-file decompression, before debug-section expansion.
  // digest always identifies bytes; input_digest preserves load provenance.
  std::string input_digest;
  std::vector<unsigned char> bytes;
  std::vector<ct_kernel_section> sections;
  std::vector<ct_kernel_symbol> symbols;
  std::vector<ct_kernel_relocation> relocations;
  bool signature_present = false;
  bool signature_format_valid = false;
  // Preserve the original signer digest before debug-section normalization.
  std::string signature_hash;
};

// Decode a bounded x86 boot image; callers validate the ELF and build ID.
bool ct_kernel_boot_elf(const std::vector<unsigned char> &input,
                        std::vector<unsigned char> &output, std::string &error);

bool ct_kernel_read_image(const std::string &path, ct_kernel_image &image,
                          std::string &error);
// A cached analysis inventory, not an executable or a full-coverage claim.
bool ct_kernel_inventory(const ct_kernel_image &image, std::string &json,
                         std::string &error);

#endif
