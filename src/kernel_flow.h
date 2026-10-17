#ifndef CTRACE_KERNEL_FLOW_H
#define CTRACE_KERNEL_FLOW_H

#include <cstdint>
#include <string>
#include <vector>

#include "kernel_decompile_image.h"

struct ct_kernel_flow_region {
  bool loop = false;
  uint64_t header = 0, branch = 0, taken = 0, fallthrough = 0, join = 0;
  // Original probe IDs, never an address envelope over unproved instructions.
  // Loops include their header/test/update so iterations retain one scope.
  std::vector<uint64_t> members, taken_members, fallthrough_members;
};

struct ct_kernel_stack_location {
  uint64_t probe = 0;
  // Before the original instruction: RSP/RBP = entry RSP + offset. An
  // unknown value is never an entry-SP approximation or a frame-size guess.
  bool rsp_known = false, rbp_known = false;
  int64_t rsp_offset = 0, rbp_offset = 0;
};

// Offline CFG only. Reuses the common decoder; labels and scope parents are
// assigned by the collector. Incomplete control flow returns false with a
// reason and no regions, while callers may keep individually proven C rows.
bool ct_kernel_decompile_flow(
    const ct_kernel_image &original, const std::vector<ct_kernel_site> &sites,
    const ct_kernel_decompile_layout &layout, uint32_t section,
    uint64_t entry_offset,
    const std::vector<ct_decompiled_instruction> &instructions,
    std::vector<ct_kernel_flow_region> &regions, std::string &error,
    std::vector<ct_kernel_stack_location> *stack = nullptr);

// Source scopes use the same CFG without a Ghidra image. Only original
// intra-section branch relocations and the canonical return thunk are known.
bool ct_kernel_source_flow(const ct_kernel_image &original,
                           const std::vector<ct_kernel_site> &sites,
                           uint32_t section, uint64_t begin, uint64_t end,
                           std::vector<ct_kernel_flow_region> &regions,
                           std::string &error);

#endif
