// SPDX-License-Identifier: MIT

#ifndef CTRACE_DWARF_KERNEL_CAPTURE_H
#define CTRACE_DWARF_KERNEL_CAPTURE_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "ctrace_kernel/image.hh"
#include "dwarf/kernel_values.hh"
#include "kctrace/runtime.h"

struct ct_kernel_dwarf_address {
  uint8_t kind = KCTRACE_CAPTURE_NONE, reg = 0;
  uint32_t section = UINT32_MAX;
  __int128 offset = 0;
};

struct ct_kernel_cfa_range {
  uint32_t section;
  uint64_t begin, end, prefix_end = 0;
  ct_kernel_dwarf_address address;
};

// Original ET_REL unwind rows retain their owning code section. Unknown or
// ambiguous CFA forms remain unavailable instead of creating memory reads.
bool ct_kernel_collect_cfa(
    const ct_kernel_image &image,
    std::map<uint32_t, std::vector<ct_kernel_cfa_range>> &ranges,
    std::string &error);

// Reduce the supported DWARF location operations to a bounded stack/object
// address. This plans storage without reading any live kernel memory.
std::optional<ct_kernel_dwarf_address> ct_kernel_resolve_capture_address(
    const ct_kernel_value_recipe &recipe,
    const std::optional<ct_kernel_dwarf_address> &frame,
    const std::optional<ct_kernel_dwarf_address> &cfa, size_t bytes,
    bool frame_base = false);

// A plain register or register-relative value usable as the root of a
// requested source access. No unrequested register becomes a memory read.
bool ct_kernel_resolve_capture_register(const ct_kernel_value_recipe &recipe,
                                        size_t bytes, kctrace_capture &capture,
                                        bool &direct);

#endif
