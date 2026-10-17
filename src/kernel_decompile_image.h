#ifndef CTRACE_KERNEL_DECOMPILE_IMAGE_H
#define CTRACE_KERNEL_DECOMPILE_IMAGE_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "analysis.h"
#include "kernel_image.h"
#include "kernel_rewrite.h"

struct ct_kernel_decompile_region {
  uint32_t section = 0;
  uint64_t address = 0, size = 0;
};

struct ct_kernel_decompile_fixup {
  uint32_t section = 0, type = 0;
  uint64_t offset = 0, value = 0;
  unsigned width = 0;
  bool proven = false;
  std::string error;
};

struct ct_kernel_decompile_layout {
  uint64_t image_base = 0;
  std::string address_space;
  // Absolute Ghidra addresses; original section indexes remain authoritative.
  std::vector<ct_kernel_decompile_region> regions;
  std::vector<ct_kernel_decompile_fixup> fixups;
  // Ghidra-image-relative RETURN overrides, independently checked against
  // original decoded five-byte kernel return-thunk jumps before using C proof.
  std::vector<uint64_t> returns;
  // Proven imported C symbol names, keyed by Ghidra-image-relative address.
  // Ambiguous aliases and non-identifier spellings are omitted.
  std::map<uint64_t, std::string> external_symbols;
};

// Append hidden section anchors to an analysis-only ET_REL copy. Original
// section indexes, instruction bytes, symbols and relocations stay unchanged.
bool ct_kernel_make_decompile_image(const ct_kernel_image &original,
                                    std::vector<unsigned char> &bytes,
                                    std::string &error);

// Validate the Ghidra manifest against original ELF identities. A fixup whose
// external target cannot be proved stays unavailable; it never derives its
// expected value from the relocated bytes being checked.
bool ct_kernel_parse_decompile_layout(const ct_kernel_image &original,
                                      const std::string &manifest,
                                      ct_kernel_decompile_layout &layout,
                                      std::string &error);

// Existing decompiler proof offsets are relative to Ghidra's image base.
// Compare every byte with original bytes plus independently proved ELF
// relocation values, and require exact original instruction boundaries.
bool ct_kernel_validate_decompile_proof(
    const ct_kernel_image &original, const std::vector<ct_kernel_site> &sites,
    const ct_kernel_decompile_layout &layout,
    const std::vector<ct_decompiled_instruction> &instructions,
    std::string &error);

#endif
