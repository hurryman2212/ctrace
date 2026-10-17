#ifndef CTRACE_KERNEL_CAPTURE_H
#define CTRACE_KERNEL_CAPTURE_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "uapi/kctrace.h"

#include "kernel_image.h"
#include "kernel_rewrite.h"
#include "kernel_source.h"
#include "kernel_values.h"

struct ct_kernel_capture_slot {
  kctrace_capture capture{};
  // OBJECT's capture.object is zero until the linker relocates this original
  // section+offset. capture.object_size bounds the complete STT_OBJECT.
  uint32_t section = UINT32_MAX;
  uint64_t object_offset = 0;
};

struct ct_kernel_capture_plan {
  std::array<ct_kernel_capture_slot, KCTRACE_VALUE_SLOTS> slots{};
};

// Original ELF data which the Linux module loader retains as ordinary module
// storage. Metadata-only/discarded input sections are never capture targets.
bool ct_kernel_capture_section(const ct_kernel_section &section);

// Offline only. Pool index zero is a sentinel and is not emitted into the
// runtime array; sites refer to plans[1..] by the same one-based plan IDs.
// Bounded scalar leaves of declared structs/static arrays are also eligible;
// uncaptured leaves remain unknown. No pointer chasing, padding, volatile or
// atomic reads, address inference from current values, or neighboring reads.
// Cache normalized inputs and output recipes only; a hit avoids CFA parsing.
// Source dependency validation and live capture checks remain mandatory.
bool ct_kernel_plan_captures(const ct_kernel_image &image,
                             const std::vector<ct_kernel_site> &sites,
                             const ct_kernel_source_metadata &source,
                             ct_kernel_value_metadata &values,
                             std::vector<ct_kernel_capture_plan> &plans,
                             std::string &error, bool *reused = nullptr);

#endif
