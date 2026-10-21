// SPDX-License-Identifier: MIT

#ifndef CTRACE_BACKEND_HH
#define CTRACE_BACKEND_HH

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

// Initial measurements are private to a thread. Completed or restored choices
// stay fixed for their code/route identity and never change instrumentation
// level, preparation tokens or the immutable code image.
struct ct_backend_key {
  uintptr_t pc = 0;
  uint64_t incarnation = 0, generation = 0;
  unsigned level = 0;
  uint64_t policy = 0;
  // Observation, discretionary entry, or a pre-transfer quiet boundary.
  uint8_t entry = 0;
  bool operator==(const ct_backend_key &) const = default;
};

// Completed, address-independent evidence only. No sampled registers, timing
// intervals, visits, trial budgets or live incarnation numbers are persisted.
struct ct_backend_hint {
  uint64_t offset = 0, successor = 0;
  std::array<unsigned char, 32> path{};
  std::array<uint64_t, 2> median{}, spread{};
  uint8_t level = 0, entry = 0, successor_entry = 0;
  bool managed = false, conflict = false;
};

// Module-sized batches are bounded both before decoding and after merging.
inline constexpr size_t ct_backend_hint_limit = 256;
bool ct_backend_hints_decode(const unsigned char *data, size_t size,
                             uint64_t module_size,
                             std::vector<ct_backend_hint> &hints);
std::vector<unsigned char>
ct_backend_hints_encode(const std::vector<ct_backend_hint> &hints);
void ct_backend_hint_merge(std::vector<ct_backend_hint> &hints,
                           const ct_backend_hint &hint);

struct ct_backend_summary {
  size_t instructions = 0, boundaries = 0;
  bool ready = false;
  std::array<unsigned char, 32> path{};
  uintptr_t module_base = 0;
  const ct_backend_hint *hint = nullptr;
  bool allow_hint = true;
};

struct ct_backend_selector {
  static constexpr size_t capacity = 64, sample_count = 8;
  struct Record {
    ct_backend_key key;
    uintptr_t successor = 0;
    uint8_t successor_entry = 0;
    uint64_t visits = 0, recheck = 0, prepare_ticks = 0;
    std::array<std::array<uint64_t, sample_count>, 2> samples{};
    std::array<unsigned, 2> counts{};
    unsigned trials = 0, discarded = 0, warmup = 0;
    bool managed = false, testing = false, sample = false;
    bool settled = false, validated = false;
    struct {
      std::array<unsigned char, 32> path{};
      std::array<uint64_t, 2> median{}, spread{};
      uintptr_t successor = 0;
      uint8_t successor_entry = 0;
      bool managed = false;
    } completed;
  };
  std::array<Record, capacity> records{};
  uint64_t visits = 0, measurements = 0, samples = 0, rejected = 0,
           switches = 0;
  uint64_t dr_entries = 0, managed_entries = 0, prepare_ticks = 0;
  uint64_t decisions = 0, managed_wins = 0;
  uint64_t hints_applied = 0, hints_rejected = 0;
  size_t active = capacity;
  uint64_t started = 0;
  unsigned started_cpu = 0;
  bool active_managed = false;

  Record &select(const ct_backend_key &, const ct_backend_summary &);
  void complete(const ct_backend_key &successor, uint64_t ticks, unsigned cpu);
  void cancel();
  bool evidence(const Record &, uintptr_t module_base, uint64_t module_size,
                ct_backend_hint &) const;
};

#endif
