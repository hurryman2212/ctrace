// SPDX-License-Identifier: MIT

#ifndef CTRACE_USERSPACE_VERSION_CACHE_H
#define CTRACE_USERSPACE_VERSION_CACHE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "userspace_version.hh"

// No process addresses belong in these templates. A token below 256 is an
// opcode/prefix byte; higher tokens refer to a byte of the current original
// instruction. An empty encoding means reuse the original encoding directly.
// Relocation holes are zeroed before binding to an RX allocation.
struct ct_userspace_instruction_template {
  bool dr_only = false, branch = false, fallthrough = false;
  uint8_t length = 0;
  enum Relocation : uint8_t {
    None,
    RipRelative,
    InternalBranch
  } relocation = None;
  uint8_t relocation_offset = 0;
  // RIP: target minus the original instruction PC. Branch: instruction index.
  int64_t target = 0;
  std::vector<uint16_t> encoding;
};

struct ct_userspace_template_layout {
  size_t ingress = 0, entry = 0, operation = 0, successor = 0;
  uint8_t gate = 0;
};

struct ct_userspace_template_keys {
  std::string common, index, family;
  // Preparation-owned RPC buffers. The enclosing version retains these across
  // suspendable helper calls so fork/thread-exit cleanup can reclaim them.
  mutable std::vector<unsigned char> scratch;
  std::string identity;
};

bool ct_userspace_template_identify(
    const ct_userspace_version_cache *cache, ct_instrument_level level,
    size_t gate_size, const ct_userspace_version_instruction *instructions,
    size_t count, ct_userspace_template_keys &keys);
bool ct_userspace_template_load_common(
    const ct_userspace_template_keys &keys,
    const ct_userspace_version_instruction *instructions, size_t count,
    std::vector<ct_userspace_instruction_template> &templates);
void ct_userspace_template_store_common(
    const ct_userspace_template_keys &keys,
    const std::vector<ct_userspace_instruction_template> &templates);
bool ct_userspace_template_load_layout(
    const ct_userspace_template_keys &keys, ct_instrument_level level,
    size_t gate_size, const ct_userspace_version_instruction *instructions,
    const std::vector<ct_userspace_instruction_template> &templates,
    std::vector<ct_userspace_template_layout> &layout, size_t &used);
void ct_userspace_template_store_layout(
    const ct_userspace_template_keys &keys, ct_instrument_level level,
    size_t gate_size, const std::vector<ct_userspace_template_layout> &layout,
    size_t used);

#endif
