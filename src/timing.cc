#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include <dr_api.h>
#include <drmgr.h>
#include <drreg.h>

#include <cpuid.h>
#include <time.h>

#include "output.h"
#include "perfetto.h"
#include "timing.h"

// Calibration is a startup fallback for CPUs without CPUID TSC frequency.
static constexpr long calibration_nanoseconds = 20000000;
static constexpr unsigned calibration_attempts = 5;
static constexpr unsigned calibration_samples = 3;

enum class TimingInterval : uint64_t { None, Quiet, Kernel };

struct TimingPublication {
  void *context;
  process_id_t process;
  thread_id_t tid;
  uint64_t track_token;
  TimingPublication *next;
  std::atomic<uint64_t> clock{0};
};

static_assert(std::atomic<uint64_t>::is_always_lock_free);

struct TimingState {
  uint64_t start_low, start_high, start_cpu;
  uint64_t stop_low, stop_high, stop_cpu;
  uint64_t start_valid, stop_valid;
  uint64_t total;
  uint64_t interval_start, interval_start_cpu, interval_start_nanoseconds;
  TimingInterval interval;
  uint64_t interval_monotonic_valid;
  TimingPublication *publication;
};

static reg_id_t timing_segment;
static uint timing_offset;
static int timing_index = -1;
static uint64_t timing_frequency;
static bool timing_enabled;
static void *timing_registry_mutex;
static TimingPublication *timing_publications;
static constexpr uint timing_slots = sizeof(TimingState) / sizeof(reg_t);
static constexpr uint64_t timing_running = uint64_t{1} << 63;
static constexpr uint64_t timing_value_mask = timing_running - 1;

static void publish_timing(TimingState *state) {
  if (!state || !state->publication)
    return;
  const unsigned __int128 nanoseconds =
      static_cast<unsigned __int128>(state->total) * 1000000000 /
      timing_frequency;
  uint64_t value = static_cast<uint64_t>(
      std::min(nanoseconds, static_cast<unsigned __int128>(timing_value_mask)));
  if (state->interval != TimingInterval::None &&
      state->interval_monotonic_valid) {
    // One atomic word is always readable, even if another thread is interrupted
    // in this callback. Running values encode the monotonic origin of the
    // adjusted application clock; paused values are accumulated nanoseconds.
    value = timing_running |
            ((state->interval_start_nanoseconds - value) & timing_value_mask);
  }
  state->publication->clock.store(value, std::memory_order_release);
}

static TimingState *timing_state(void *context) {
  if (!timing_enabled)
    return nullptr;
  if (!context)
    context = dr_get_current_drcontext();
  auto *state =
      static_cast<TimingState *>(drmgr_get_tls_field(context, timing_index));
  if (!state && context == dr_get_current_drcontext()) {
    state = reinterpret_cast<TimingState *>(
        static_cast<byte *>(dr_get_dr_segment_base(timing_segment)) +
        timing_offset);
    drmgr_set_tls_field(context, timing_index, state);
  }
  return state;
}

bool ct_timing_init() {
  if (timing_enabled)
    return true;
  unsigned eax, ebx, ecx, edx;
  if (!__get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx) || !(edx & (1U << 27)) ||
      !__get_cpuid(0x80000007, &eax, &ebx, &ecx, &edx) || !(edx & (1U << 8))) {
    ct_output_printf("ctrace: timing requires invariant TSC and RDTSCP\n");
    return false;
  }
  timing_frequency = 0;
  if (__get_cpuid(0x15, &eax, &ebx, &ecx, &edx) && eax && ebx && ecx)
    timing_frequency = uint64_t(ecx) * ebx / eax;
  if (!timing_frequency) {
    uint64_t samples[calibration_samples]{};
    unsigned count = 0;
    for (unsigned attempt = 0;
         attempt < calibration_attempts && count < calibration_samples;
         ++attempt) {
      struct timespec before{}, after{};
      if (clock_gettime(CLOCK_MONOTONIC, &before) != 0)
        continue;
      unsigned start_low, start_high, start_cpu;
      asm volatile("lfence\n\trdtscp\n\tlfence"
                   : "=a"(start_low), "=d"(start_high), "=c"(start_cpu)
                   :
                   : "memory");
      const struct timespec delay{0, calibration_nanoseconds};
      nanosleep(&delay, nullptr);
      unsigned stop_low, stop_high, stop_cpu;
      asm volatile("lfence\n\trdtscp\n\tlfence"
                   : "=a"(stop_low), "=d"(stop_high), "=c"(stop_cpu)
                   :
                   : "memory");
      if (clock_gettime(CLOCK_MONOTONIC, &after) != 0 || start_cpu != stop_cpu)
        continue;
      const uint64_t start = (uint64_t(start_high) << 32) | start_low;
      const uint64_t stop = (uint64_t(stop_high) << 32) | stop_low;
      const int64_t elapsed =
          int64_t(after.tv_sec - before.tv_sec) * 1000000000 + after.tv_nsec -
          before.tv_nsec;
      if (stop <= start || elapsed < calibration_nanoseconds)
        continue;
      samples[count++] = static_cast<uint64_t>(
          static_cast<long double>(stop - start) * 1000000000.0L / elapsed);
    }
    if (count) {
      for (unsigned index = 1; index < count; ++index)
        for (unsigned position = index;
             position && samples[position - 1] > samples[position]; --position)
          std::swap(samples[position - 1], samples[position]);
      timing_frequency = samples[count / 2];
    }
  }
  if (!timing_frequency) {
    ct_output_printf("ctrace: cannot determine invariant TSC frequency\n");
    return false;
  }
  drreg_options_t options{};
  options.struct_size = sizeof(options);
  options.num_spill_slots = 4; // Three timestamp outputs plus the flags slot.
  options.conservative = true;
  if (drreg_init(&options) != DRREG_SUCCESS)
    return false;
  if (!dr_raw_tls_calloc(&timing_segment, &timing_offset, timing_slots, 0)) {
    drreg_exit();
    return false;
  }
  timing_index = drmgr_register_tls_field();
  if (timing_index < 0) {
    dr_raw_tls_cfree(timing_offset, timing_slots);
    drreg_exit();
    return false;
  }
  timing_enabled = true;
  timing_registry_mutex = dr_mutex_create();
  return true;
}

void ct_timing_register_thread(void *context) {
  if (!timing_enabled)
    return;
  if (!context)
    context = dr_get_current_drcontext();
  TimingState *state = timing_state(context);
  if (!state)
    return;
  const uint64_t track_token = ct_perfetto_track_token(context);
  dr_mutex_lock(timing_registry_mutex);
  if (!state->publication) {
    auto *publication = new TimingPublication;
    publication->context = context;
    publication->process = dr_get_process_id_from_drcontext(context);
    publication->tid = dr_get_thread_id(context);
    publication->track_token = track_token;
    publication->next = timing_publications;
    state->publication = publication;
    timing_publications = publication;
  }
  publish_timing(state);
  dr_mutex_unlock(timing_registry_mutex);
}

void ct_timing_unregister_thread(void *context) {
  if (!timing_enabled)
    return;
  if (!context)
    context = dr_get_current_drcontext();
  const process_id_t process = dr_get_process_id_from_drcontext(context);
  dr_mutex_lock(timing_registry_mutex);
  for (TimingPublication **link = &timing_publications; *link;
       link = &(*link)->next) {
    TimingPublication *publication = *link;
    if (publication->context != context || publication->process != process)
      continue;
    if (TimingState *state = timing_state(context))
      state->publication = nullptr;
    *link = publication->next;
    delete publication;
    break;
  }
  dr_mutex_unlock(timing_registry_mutex);
}

std::vector<ct_timing_thread_snapshot> ct_timing_snapshot_process() {
  std::vector<ct_timing_thread_snapshot> snapshots;
  if (!timing_enabled)
    return snapshots;
  const process_id_t process = dr_get_process_id();
  dr_mutex_lock(timing_registry_mutex);
  for (const TimingPublication *publication = timing_publications; publication;
       publication = publication->next) {
    if (publication->process != process)
      continue;
    uint64_t value;
    bool available = true;
    for (;;) {
      value = publication->clock.load(std::memory_order_acquire);
      if (!(value & timing_running))
        break;
      struct timespec now{};
      if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        available = false;
        break;
      }
      if (publication->clock.load(std::memory_order_acquire) != value)
        continue;
      const uint64_t nanoseconds =
          uint64_t(now.tv_sec) * 1000000000 + now.tv_nsec;
      value = (nanoseconds - (value & timing_value_mask)) & timing_value_mask;
      break;
    }
    if (available)
      snapshots.push_back({publication->tid, publication->track_token, value});
  }
  dr_mutex_unlock(timing_registry_mutex);
  return snapshots;
}

static void insert_timestamp(void *context, instrlist_t *block, instr_t *where,
                             bool start) {
  if (!timing_enabled)
    return;
  drvector_t allowed;
  if (drreg_init_and_fill_vector(&allowed, false) != DRREG_SUCCESS)
    dr_abort();
  const reg_id_t outputs[] = {DR_REG_RAX, DR_REG_RDX, DR_REG_RCX};
  for (reg_id_t reg : outputs) {
    reg_id_t reserved = DR_REG_NULL;
    if (drreg_set_vector_entry(&allowed, reg, true) != DRREG_SUCCESS ||
        drreg_reserve_register(context, block, where, &allowed, &reserved) !=
            DRREG_SUCCESS ||
        reserved != reg ||
        drreg_set_vector_entry(&allowed, reg, false) != DRREG_SUCCESS)
      dr_abort();
  }
  drvector_delete(&allowed);

  // MOV, RDTSCP and LFENCE leave application arithmetic flags unchanged.
  const uint valid =
      timing_offset + (start ? offsetof(TimingState, start_valid)
                             : offsetof(TimingState, stop_valid));
  instrlist_meta_preinsert(
      block, where,
      INSTR_CREATE_mov_st(context,
                          dr_raw_tls_opnd(context, timing_segment, valid),
                          OPND_CREATE_INT32(0)));
  if (start)
    instrlist_meta_preinsert(
        block, where,
        INSTR_CREATE_mov_st(
            context,
            dr_raw_tls_opnd(context, timing_segment,
                            timing_offset + offsetof(TimingState, stop_valid)),
            OPND_CREATE_INT32(0)));
  instrlist_meta_preinsert(block, where, INSTR_CREATE_lfence(context));
  instrlist_meta_preinsert(block, where, INSTR_CREATE_rdtscp(context));
  const uint values = timing_offset + (start ? offsetof(TimingState, start_low)
                                             : offsetof(TimingState, stop_low));
  for (unsigned index = 0; index < 3; ++index)
    dr_insert_write_raw_tls(context, block, where, timing_segment,
                            values + index * sizeof(uint64_t), outputs[index]);
  if (start) {
    instrlist_meta_preinsert(
        block, where,
        INSTR_CREATE_mov_st(context,
                            dr_raw_tls_opnd(context, timing_segment, valid),
                            OPND_CREATE_INT32(1)));
  } else {
    // A stop consumes its armed start even when this path has no observer.
    // Further stops cannot extend that old interval across unobserved work.
    const uint armed = timing_offset + offsetof(TimingState, start_valid);
    dr_insert_read_raw_tls(context, block, where, timing_segment, armed,
                           DR_REG_RAX);
    dr_insert_write_raw_tls(context, block, where, timing_segment, valid,
                            DR_REG_RAX);
    instrlist_meta_preinsert(
        block, where,
        INSTR_CREATE_mov_st(context,
                            dr_raw_tls_opnd(context, timing_segment, armed),
                            OPND_CREATE_INT32(0)));
  }
  for (reg_id_t reg : outputs)
    if (drreg_unreserve_register(context, block, where, reg) != DRREG_SUCCESS)
      dr_abort();
  if (drreg_restore_all(context, block, where) != DRREG_SUCCESS)
    dr_abort();
  instrlist_meta_preinsert(block, where, INSTR_CREATE_lfence(context));
}

void ct_timing_stop(void *context, instrlist_t *block, instr_t *where) {
  insert_timestamp(context, block, where, false);
}

void ct_timing_start(void *context, instrlist_t *block, instr_t *where) {
  insert_timestamp(context, block, where, true);
}

static void begin_interval(TimingState *state, TimingInterval interval) {
  if (!state || state->interval != TimingInterval::None)
    return;
  state->start_valid = state->stop_valid = 0;
  struct timespec now{};
  state->interval_monotonic_valid = clock_gettime(CLOCK_MONOTONIC, &now) == 0;
  state->interval_start_nanoseconds =
      uint64_t(now.tv_sec) * 1000000000 + now.tv_nsec;
  unsigned low, high, cpu;
  asm volatile("lfence\n\trdtscp\n\tlfence"
               : "=a"(low), "=d"(high), "=c"(cpu)
               :
               : "memory");
  state->interval_start = (uint64_t(high) << 32) | low;
  state->interval_start_cpu = cpu;
  state->interval = interval;
  publish_timing(state);
}

static uint64_t end_interval(TimingState *state, TimingInterval interval) {
  if (!state)
    return 0;
  if (state->interval != interval)
    return state->total;
  unsigned low, high, cpu;
  asm volatile("lfence\n\trdtscp\n\tlfence"
               : "=a"(low), "=d"(high), "=c"(cpu)
               :
               : "memory");
  const uint64_t stop = (uint64_t(high) << 32) | low;
  struct timespec now{};
  const bool have_monotonic = clock_gettime(CLOCK_MONOTONIC, &now) == 0;
  state->interval = TimingInterval::None;
  state->start_valid = state->stop_valid = 0;
  uint64_t elapsed = 0;
  if (cpu == state->interval_start_cpu && stop >= state->interval_start) {
    elapsed = stop - state->interval_start;
  } else if (have_monotonic && state->interval_monotonic_valid) {
    // Quiet application spans and blocking system calls can migrate CPUs.
    // Preserve elapsed time without assuming cross-CPU TSC alignment.
    const uint64_t stop_nanoseconds =
        uint64_t(now.tv_sec) * 1000000000 + now.tv_nsec;
    if (stop_nanoseconds >= state->interval_start_nanoseconds) {
      const unsigned __int128 ticks =
          static_cast<unsigned __int128>(stop_nanoseconds -
                                         state->interval_start_nanoseconds) *
          timing_frequency / 1000000000;
      elapsed = static_cast<uint64_t>(
          std::min(ticks, static_cast<unsigned __int128>(UINT64_MAX)));
    }
  }
  state->total += std::min(elapsed, UINT64_MAX - state->total);
  publish_timing(state);
  return state->total;
}

uint64_t ct_timing_sample(void *context) {
  TimingState *state = timing_state(context);
  if (!state)
    return 0;
  // Any observer reached from a quiet span must stop that span before doing
  // analysis or output. Kernel intervals remain owned by their callbacks.
  end_interval(state, TimingInterval::Quiet);
  if (state->stop_valid && state->start_cpu == state->stop_cpu) {
    const uint64_t start = (state->start_high << 32) | state->start_low;
    const uint64_t stop = (state->stop_high << 32) | state->stop_low;
    if (stop >= start)
      state->total += std::min(stop - start, UINT64_MAX - state->total);
  }
  state->start_valid = state->stop_valid = 0;
  publish_timing(state);
  return state->total;
}

void ct_timing_discard(void *context) {
  if (TimingState *state = timing_state(context)) {
    state->start_valid = state->stop_valid = 0;
    publish_timing(state);
  }
}

bool ct_timing_quiet_active(void *context) {
  TimingState *state = timing_state(context);
  return state && state->interval == TimingInterval::Quiet;
}

void ct_timing_quiet_begin(void *context) {
  TimingState *state = timing_state(context);
  if (!state || state->interval != TimingInterval::None)
    return;
  ct_timing_sample(context);
  begin_interval(state, TimingInterval::Quiet);
}

uint64_t ct_timing_quiet_end(void *context) {
  return end_interval(timing_state(context), TimingInterval::Quiet);
}

void ct_timing_kernel_begin(void *context) {
  TimingState *state = timing_state(context);
  end_interval(state, TimingInterval::Quiet);
  begin_interval(state, TimingInterval::Kernel);
}

uint64_t ct_timing_kernel_end(void *context) {
  return end_interval(timing_state(context), TimingInterval::Kernel);
}

uint64_t ct_timing_frequency() { return timing_frequency; }

void ct_timing_after_fork(void *context) {
  if (!timing_enabled)
    return;
  dr_mutex_reset_after_fork(timing_registry_mutex);
  // Links are published only after initialization and removed before freeing.
  // Unlike a reallocating container, the copied list is safe to discard even
  // if another parent thread was registering or unregistering at fork time.
  while (timing_publications) {
    TimingPublication *publication = timing_publications;
    timing_publications = publication->next;
    delete publication;
  }
  if (TimingState *state = timing_state(context))
    *state = TimingState{};
}

void ct_timing_exit() {
  if (!timing_enabled)
    return;
  timing_enabled = false;
  while (timing_publications) {
    TimingPublication *publication = timing_publications;
    timing_publications = publication->next;
    delete publication;
  }
  dr_mutex_destroy(timing_registry_mutex);
  timing_registry_mutex = nullptr;
  drmgr_unregister_tls_field(timing_index);
  timing_index = -1;
  dr_raw_tls_cfree(timing_offset, timing_slots);
  drreg_exit();
}
