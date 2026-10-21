// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_EVENT_H
#define CTRACE_KERNEL_EVENT_H

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "linux/kctrace.h"

struct ct_kernel_capture_chunk {
  uint32_t valid = 0;
  std::array<std::array<unsigned char, 8>, KCTRACE_VALUE_SLOTS> values{};
};

// Wire records stay small. Only observations requiring additional captured
// storage allocate a shared payload, retained by pending rows and entry frames.
struct ct_kernel_observation : kctrace_event {
  std::shared_ptr<const std::vector<ct_kernel_capture_chunk>> extra_values;

  ct_kernel_observation() : kctrace_event{} {}
  ct_kernel_observation(const kctrace_event &event) : kctrace_event(event) {}

  const unsigned char *capture_data(uint32_t slot) const {
    if (!(flags & KCTRACE_EVENT_HAVE_VALUES) ||
        (flags & KCTRACE_EVENT_HAVE_MEMORY))
      return nullptr;
    if (slot < KCTRACE_VALUE_SLOTS)
      return capture_valid & (1U << slot) ? capture_values[slot] : nullptr;
    const auto chunk = slot / KCTRACE_VALUE_SLOTS - 1;
    if (!extra_values || chunk >= extra_values->size())
      return nullptr;
    const auto &extra = (*extra_values)[chunk];
    slot %= KCTRACE_VALUE_SLOTS;
    return extra.valid & (1U << slot) ? extra.values[slot].data() : nullptr;
  }
};

// The producer reserves and publishes each bundle atomically. Interleaving,
// missing records, and mismatched identities are rejected before rendering.
class ct_kernel_event_buffer {
  ct_kernel_observation pending;
  std::shared_ptr<std::vector<ct_kernel_capture_chunk>> extra;

public:
  bool incomplete() const { return bool(extra); }

  bool append(const kctrace_event &event, ct_kernel_observation &complete,
              bool &ready, std::string &error) {
    ready = false;
    const auto fail = [&]() {
      error = "invalid or incomplete kernel capture bundle";
      return false;
    };
    if (event.size != sizeof(kctrace_event))
      return fail();
    if (!extra) {
      if (event.type == KCTRACE_EVENT_CAPTURE)
        return fail();
      if (!(event.flags & KCTRACE_EVENT_HAVE_VALUES)) {
        if (event.reserved2)
          return fail();
        complete = event;
        ready = true;
        return true;
      }
      if ((event.flags & KCTRACE_EVENT_HAVE_MEMORY) || !event.capture_plan ||
          !event.reserved2 || (event.capture_valid >> KCTRACE_VALUE_SLOTS) ||
          event.sequence >
              std::numeric_limits<uint64_t>::max() - (event.reserved2 - 1))
        return fail();
      if (event.reserved2 == 1) {
        complete = event;
        ready = true;
        return true;
      }
      pending = event;
      extra = std::make_shared<std::vector<ct_kernel_capture_chunk>>();
      return true;
    }
    const auto identity = [](const kctrace_event &item) {
      return std::tie(item.session_id, item.generation, item.site_id, item.pc,
                      item.monotonic_ns, item.probe_end_ns, item.task_start_ns,
                      item.tid, item.tgid, item.cpu, item.context, item.level,
                      item.hardirq_depth, item.softirq_depth,
                      item.dropped_total, item.capture_plan);
    };
    const kctrace_execution_record empty{};
    const std::array<uint64_t, KCTRACE_REGISTER_COUNT> empty_registers{};
    if (event.type != KCTRACE_EVENT_CAPTURE ||
        event.sequence != pending.sequence + extra->size() + 1 ||
        event.reserved2 != extra->size() + 1 ||
        identity(event) != identity(pending) ||
        event.flags != (KCTRACE_EVENT_HAVE_VALUES |
                        (pending.flags & KCTRACE_EVENT_SEQUENCE_GAP)) ||
        (event.capture_valid >> KCTRACE_VALUE_SLOTS) || event.valid_registers ||
        std::memcmp(event.registers, empty_registers.data(),
                    sizeof(event.registers)) ||
        std::memcmp(&event.execution, &empty, sizeof(empty)))
      return fail();
    ct_kernel_capture_chunk chunk;
    chunk.valid = event.capture_valid;
    std::memcpy(chunk.values.data(), event.capture_values,
                sizeof(event.capture_values));
    extra->push_back(chunk);
    if (extra->size() + 1 == pending.reserved2) {
      pending.extra_values = std::move(extra);
      complete = std::move(pending);
      pending = {};
      ready = true;
    }
    return true;
  }
};

#endif
