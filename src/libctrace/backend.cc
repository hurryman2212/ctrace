// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cstring>
#include <limits>
#include <tuple>

#include "backend.hh"

// Exploration is bounded independently of the application's run length.
static constexpr uint64_t initial_visits = 16, dense_visits = 64;
static constexpr uint64_t retry_visits = 1024, maximum_samples = 4096;
static constexpr unsigned maximum_trials = 3, maximum_discarded = 32;
static constexpr unsigned warmup_samples = 2, improvement_percent = 10;
static constexpr uint64_t maximum_interval_ticks = uint64_t{1} << 32;

ct_backend_selector::Record &
ct_backend_selector::select(const ct_backend_key &key,
                            const ct_backend_summary &summary) {
  ++visits;
  const size_t first = ((key.pc >> 2) ^ key.incarnation ^ key.level) % capacity;
  size_t slot = first;
  for (size_t probe = 0; probe < 4; ++probe) {
    slot = (first + probe) % capacity;
    if (!records[slot].key.pc || records[slot].key == key)
      break;
  }
  Record &record = records[slot];
  if (!(record.key == key)) {
    if (active == slot)
      cancel();
    record = {};
    record.key = key;
  }
  ++record.visits;
  record.sample = false;
  if (summary.ready && record.completed.path != summary.path) {
    if (std::any_of(record.completed.path.begin(), record.completed.path.end(),
                    [](unsigned char byte) { return byte != 0; })) {
      // Different executable routing is a natural miss, not a performance
      // recheck. Old samples and the settled choice belong to the old path.
      if (active == slot)
        cancel();
      if (record.settled)
        ++hints_rejected;
      record = {};
      record.key = key;
      record.visits = 1;
    }
    record.completed.path = summary.path;
  }
  if (record.settled)
    return record;
  if (summary.allow_hint && summary.hint) {
    const auto &hint = *summary.hint;
    if ((!summary.ready || hint.path == summary.path) &&
        std::any_of(hint.path.begin(), hint.path.end(),
                    [](unsigned char byte) { return byte != 0; })) {
      if (active == slot)
        cancel();
      record.completed = {};
      record.completed.path = hint.path;
      record.managed = hint.managed && !hint.conflict;
      record.testing = false;
      record.settled = true;
      record.validated = false;
      ++hints_applied;
      // A cached managed choice may request code preparation. Its readiness
      // and execution eligibility remain the caller's responsibility; neither
      // warmup samples nor this run's measurement budget gate a cache hit.
      return record;
    }
    ++hints_rejected;
  }
  const uint64_t minimum =
      summary.instructions &&
              summary.boundaries >= (summary.instructions + 1) / 2
          ? dense_visits
          : initial_visits;
  if (!record.testing && record.visits >= std::max(minimum, record.recheck) &&
      record.trials < maximum_trials && measurements < maximum_samples) {
    if (record.managed)
      ++switches;
    record.managed = false;
    record.testing = true;
    record.counts = {};
    record.successor = 0;
    record.discarded = 0;
    record.warmup = warmup_samples;
    ++record.trials;
  }
  if (record.testing) {
    if (measurements >= maximum_samples) {
      if (record.managed)
        ++switches;
      record.managed = record.testing = false;
    } else if (record.warmup)
      --record.warmup;
    else
      record.sample = true;
  }
  return record;
}

void ct_backend_selector::complete(const ct_backend_key &successor,
                                   uint64_t ticks, unsigned cpu) {
  if (active >= capacity)
    return;
  Record &record = records[active];
  active = capacity;
  if (!record.testing || record.settled)
    return;
  const bool compatible =
      record.key.incarnation == successor.incarnation &&
      record.key.generation == successor.generation &&
      record.key.policy == successor.policy &&
      record.key.level == successor.level &&
      (!record.successor || (record.successor == successor.pc &&
                             record.successor_entry == successor.entry));
  if (!compatible || cpu != started_cpu || ticks <= started ||
      ticks - started > maximum_interval_ticks) {
    ++rejected;
    if (++record.discarded >= maximum_discarded) {
      if (record.managed)
        ++switches;
      record.managed = record.testing = record.validated = false;
      record.recheck = record.visits + (retry_visits << record.trials);
    }
    return;
  }
  record.successor = successor.pc;
  record.successor_entry = successor.entry;
  const size_t backend = active_managed ? 1 : 0;
  unsigned &count = record.counts[backend];
  if (count >= sample_count)
    return;
  record.samples[backend][count++] = ticks - started;
  ++samples;
  if (count != sample_count)
    return;
  if (!active_managed) {
    record.managed = true;
    record.warmup = warmup_samples;
    ++switches;
    return;
  }
  auto dr = record.samples[0], managed = record.samples[1];
  std::sort(dr.begin(), dr.end());
  std::sort(managed.begin(), managed.end());
  const uint64_t dr_median = dr[sample_count / 2];
  const uint64_t managed_median = managed[sample_count / 2];
  // Interquartile spread rejects noisy apparent wins without pretending to
  // distinguish preemption from application work using wall-clock samples.
  const uint64_t spread =
      (dr[3 * sample_count / 4] - dr[sample_count / 4]) +
      (managed[3 * sample_count / 4] - managed[sample_count / 4]);
  const uint64_t saving =
      dr_median > managed_median ? dr_median - managed_median : 0;
  const uint64_t amortized =
      saving && record.visits <= std::numeric_limits<uint64_t>::max() / saving
          ? saving * record.visits
          : std::numeric_limits<uint64_t>::max();
  const bool keep_managed =
      record.prepare_ticks != std::numeric_limits<uint64_t>::max() &&
      saving > dr_median * improvement_percent / 100 && saving > spread &&
      saving && amortized >= record.prepare_ticks;
  ++decisions;
  managed_wins += keep_managed;
  const bool stable_dr =
      managed_median > dr_median && managed_median - dr_median > spread &&
      managed_median - dr_median > managed_median * improvement_percent / 100;
  record.validated = keep_managed || stable_dr;
  record.completed.median = {dr_median, managed_median};
  record.completed.spread = {dr[3 * sample_count / 4] - dr[sample_count / 4],
                             managed[3 * sample_count / 4] -
                                 managed[sample_count / 4]};
  record.completed.managed = keep_managed;
  record.completed.successor = record.successor;
  record.completed.successor_entry = record.successor_entry;
  if (!keep_managed)
    ++switches;
  record.managed = keep_managed;
  record.testing = false;
  record.settled = true;
  record.recheck = 0;
}

void ct_backend_selector::cancel() {
  if (active < capacity && records[active].testing &&
      !records[active].settled) {
    ++rejected;
    Record &record = records[active];
    if (++record.discarded >= maximum_discarded) {
      if (record.managed)
        ++switches;
      record.managed = record.testing = record.validated = false;
      record.recheck = record.visits + (retry_visits << record.trials);
    }
  }
  active = capacity;
}

bool ct_backend_selector::evidence(const Record &record, uintptr_t base,
                                   uint64_t size, ct_backend_hint &hint) const {
  if (!record.settled || !record.completed.median[0] ||
      !record.completed.median[1] || !record.key.pc || record.key.pc < base ||
      record.key.pc - base >= size || record.completed.successor < base ||
      record.completed.successor - base >= size ||
      !std::any_of(
          record.completed.path.begin(), record.completed.path.end(),
          [](unsigned char byte) { return byte != 0; }))
    return false;
  hint = {};
  hint.path = record.completed.path;
  hint.median = record.completed.median;
  hint.spread = record.completed.spread;
  hint.managed = record.completed.managed;
  hint.successor_entry = record.completed.successor_entry;
  hint.conflict = !record.validated;
  hint.offset = record.key.pc - base;
  hint.successor = record.completed.successor - base;
  hint.level = record.key.level;
  hint.entry = record.key.entry;
  return true;
}

void ct_backend_hint_merge(std::vector<ct_backend_hint> &hints,
                           const ct_backend_hint &hint) {
  const auto key = [](const ct_backend_hint &value) {
    return std::tie(value.offset, value.level, value.entry, value.path);
  };
  auto found = std::lower_bound(hints.begin(), hints.end(), hint,
                                [&](const auto &left, const auto &right) {
                                  return key(left) < key(right);
                                });
  if (found != hints.end() && key(*found) == key(hint)) {
    if (found->managed != hint.managed || found->successor != hint.successor ||
        found->successor_entry != hint.successor_entry || hint.conflict)
      found->conflict = true;
    if (found->conflict)
      found->managed = false;
    // Disagreement settles on DR; it never asks for another measurement or
    // manufactures a new statistical population by averaging threads.
    return;
  }
  if (hints.size() < ct_backend_hint_limit) {
    auto inserted = hints.insert(found, hint);
    if (inserted->conflict)
      inserted->managed = false;
  }
}

std::vector<unsigned char>
ct_backend_hints_encode(const std::vector<ct_backend_hint> &hints) {
  if (hints.size() > ct_backend_hint_limit)
    return {};
  std::vector<unsigned char> bytes;
  const auto number = [&](uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      bytes.push_back(value >> shift);
  };
  number(hints.size());
  for (const auto &hint : hints) {
    number(hint.offset);
    number(hint.successor);
    bytes.insert(bytes.end(), hint.path.begin(), hint.path.end());
    for (uint64_t value : hint.median)
      number(value);
    for (uint64_t value : hint.spread)
      number(value);
    bytes.push_back(hint.level);
    bytes.push_back(hint.entry);
    bytes.push_back(hint.successor_entry);
    bytes.push_back(hint.managed);
    bytes.push_back(hint.conflict);
  }
  return bytes;
}

bool ct_backend_hints_decode(const unsigned char *data, size_t size,
                             uint64_t module_size,
                             std::vector<ct_backend_hint> &hints) {
  hints.clear();
  // Each complete decision has two sets of eight samples; counts are implicit.
  constexpr size_t record_size = 85;
  if (!data || size < 8 || size > 8 + ct_backend_hint_limit * record_size)
    return false;
  size_t position = 0;
  const auto number = [&]() {
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
      value |= uint64_t(data[position++]) << shift;
    return value;
  };
  const uint64_t count = number();
  if (count > ct_backend_hint_limit || size != 8 + count * record_size)
    return false;
  for (uint64_t index = 0; index < count; ++index) {
    ct_backend_hint hint;
    hint.offset = number();
    hint.successor = number();
    std::memcpy(hint.path.data(), data + position, hint.path.size());
    position += hint.path.size();
    for (uint64_t &value : hint.median)
      value = number();
    for (uint64_t &value : hint.spread)
      value = number();
    hint.level = data[position++];
    hint.entry = data[position++];
    hint.successor_entry = data[position++];
    const unsigned managed = data[position++], conflict = data[position++];
    hint.managed = managed;
    hint.conflict = conflict;
    if (hint.offset >= module_size || hint.successor >= module_size ||
        hint.level > 2 || hint.entry > 2 || hint.successor_entry > 2 ||
        managed > 1 || conflict > 1 || (conflict && managed) ||
        !hint.median[0] || !hint.median[1] ||
        hint.median[0] > maximum_interval_ticks ||
        hint.median[1] > maximum_interval_ticks ||
        hint.spread[0] > maximum_interval_ticks ||
        hint.spread[1] > maximum_interval_ticks ||
        !std::any_of(hint.path.begin(), hint.path.end(),
                     [](unsigned char byte) { return byte != 0; })) {
      hints.clear();
      return false;
    }
    if (!hint.conflict) {
      const uint64_t faster = hint.median[hint.managed ? 1 : 0];
      const uint64_t slower = hint.median[hint.managed ? 0 : 1];
      if (slower <= faster ||
          slower - faster <= slower * improvement_percent / 100 ||
          slower - faster <= hint.spread[0] + hint.spread[1]) {
        hints.clear();
        return false;
      }
    }
    ct_backend_hint_merge(hints, hint);
    if (hints.size() != index + 1) {
      hints.clear();
      return false;
    }
  }
  return true;
}
