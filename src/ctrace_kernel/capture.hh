// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_CAPTURE_H
#define CTRACE_KERNEL_CAPTURE_H

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "decompile.hh"
#include "dwarf/kernel_source.hh"
#include "dwarf/kernel_values.hh"
#include "image.hh"
#include "kctrace/runtime.h"
#include "rewrite.hh"

struct ct_kernel_capture_slot {
  kctrace_capture capture{};
  // OBJECT's capture.object is zero until the linker relocates this original
  // section+offset. capture.object_size bounds the complete STT_OBJECT.
  uint32_t section = UINT32_MAX;
  uint64_t object_offset = 0;
};

struct ct_kernel_capture_plan {
  std::vector<ct_kernel_capture_slot> slots;
};

struct ct_kernel_capture_chunk_plan {
  std::array<ct_kernel_capture_slot, KCTRACE_VALUE_SLOTS> slots{};
  uint32_t next = 0;
  uint32_t xstate_mask = 0;
};

enum class ct_kernel_x87_write { none, top, operand };

// Exact non-popping x87 forms whose destination LLVM MC omits. TOP remains
// unchanged; this proof never reindexes a stack-changing instruction.
ct_kernel_x87_write ct_kernel_x87_destination(std::string_view opcode,
                                              bool single_register_operand);

// Extend cached memory plans with owned FPU and explicit scalar snapshots.
bool ct_kernel_plan_xstate(
    const std::vector<ct_kernel_xstate_site> &xstate,
    ct_kernel_value_metadata &values,
    std::vector<ct_kernel_capture_plan> &plans, std::string &error,
    const std::map<uint64_t, uint8_t> &tiles = {},
    const std::map<uint64_t, uint32_t> &scalar = {},
    const ct_kernel_source_metadata *source = nullptr,
    const std::vector<ct_kernel_site> *original = nullptr,
    const ct_kernel_decompile_metadata *decompile = nullptr);

std::vector<uint32_t> ct_kernel_capture_xstate_masks(
    const ct_kernel_value_metadata &values,
    const std::vector<ct_kernel_capture_plan> &plans);

bool ct_kernel_xstate_bytes(const ct_kernel_capture_plan &plan,
                            const ct_kernel_observation &event,
                            unsigned component, uint64_t offset, void *output,
                            size_t bytes);

// Palette-1 rows use their configured width; no unconfigured tile bytes are
// presented as live values. This path is used only for explicit TMM operands.
std::string ct_kernel_tile_value(const ct_kernel_capture_plan &plan,
                                 const ct_kernel_observation &event,
                                 unsigned tile, bool initialized = false,
                                 bool raw = false);

// Keep logical root IDs stable; append their additional physical chunks.
bool ct_kernel_capture_chunks(const std::vector<ct_kernel_capture_plan> &plans,
                              std::vector<ct_kernel_capture_chunk_plan> &chunks,
                              std::string &error);

// Original ELF data which the Linux module loader retains as ordinary module
// storage. Metadata-only/discarded input sections are never capture targets.
bool ct_kernel_capture_section(const ct_kernel_section &section);

// Offline only. Pool index zero is a sentinel and is not emitted into the
// runtime array; sites refer to plans[1..] by the same one-based plan IDs.
// Bounded scalar leaves of declared structs/static arrays are also eligible;
// uncaptured leaves remain unknown. Explicit source paths may use bounded
// pointer-prefix slots; only their selected leaf or embedded aggregate is read.
// No unrequested pointer targets, padding, volatile/atomic or MMIO reads.
// Cache normalized inputs and output recipes only; a hit avoids CFA parsing.
// Source dependency validation and live capture checks remain mandatory.
bool ct_kernel_plan_captures(const ct_kernel_image &image,
                             const std::vector<ct_kernel_site> &sites,
                             const ct_kernel_source_metadata &source,
                             ct_kernel_value_metadata &values,
                             std::vector<ct_kernel_capture_plan> &plans,
                             std::string &error, bool *reused = nullptr);

#endif
