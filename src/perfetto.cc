#include <algorithm>
#include <atomic>
#include <cstdio>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <dr_api.h>
#include <drmgr.h>

#include "analysis.h"
#include "output.h"
#include "perfetto.h"
#include "perfetto_json.h"

struct PerfettoSlice {
  uint64_t token;
  ct_perfetto_timestamp timestamp;
};

struct PerfettoThreadId {
  uint64_t token;
  process_id_t process;
  thread_id_t thread;
};

struct PerfettoThread {
  PerfettoThreadId id;
  std::vector<PerfettoSlice> stack;
  ct_perfetto_timestamp timestamp;
};

static void *trace_mutex;
static int trace_identity_index = -1;
static std::atomic<uint64_t> trace_identity_token{0};
static std::atomic<bool> trace_enabled{false};
static std::atomic<uint64_t> trace_userspace_spans{0},
    trace_userspace_gate_hits{0}, trace_userspace_detailed_steps{0};
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "userspace signal counters require lock-free atomics");
static uint64_t trace_frequency, trace_token, trace_origin;
static std::map<uint64_t, PerfettoThread> trace_threads;
static std::map<uint64_t, uint64_t> trace_tokens;
static std::string trace_footer, trace_footer_sent, trace_program;

struct PerfettoLock {
  PerfettoLock() { dr_mutex_lock(trace_mutex); }
  ~PerfettoLock() { dr_mutex_unlock(trace_mutex); }
};

static std::string current_footer() {
  // Read gate hits first: their release increment follows the span increment,
  // so this snapshot cannot report more gate hits than completed spans.
  const uint64_t gates =
      trace_userspace_gate_hits.load(std::memory_order_acquire);
  const uint64_t spans = trace_userspace_spans.load(std::memory_order_relaxed);
  return trace_footer + ",\"userspace_spans\":" + std::to_string(spans) +
         ",\"userspace_gate_hits\":" + std::to_string(gates) +
         ",\"userspace_detailed_steps\":" +
         std::to_string(
             trace_userspace_detailed_steps.load(std::memory_order_relaxed)) +
         "}";
}

static bool publish_footer() {
  const std::string footer = current_footer();
  if (footer == trace_footer_sent)
    return true;
  if (!ct_analysis_trace_footer(footer.data(), footer.size())) {
    trace_enabled.store(false);
    ct_output_printf(
        "ctrace: cannot publish Perfetto metadata; recording stopped\n");
    return false;
  }
  trace_footer_sent = footer;
  return true;
}

static bool write_event(const std::string &event) {
  if (!trace_enabled.load() || !publish_footer())
    return false;
  // The broker serializes process sessions and keeps a complete JSON suffix
  // after each event, including when an application terminates abnormally.
  if (!ct_analysis_trace_event(event.data(), event.size())) {
    trace_enabled.store(false);
    ct_output_printf(
        "ctrace: cannot publish Perfetto event; recording stopped\n");
    return false;
  }
  return true;
}

uint64_t ct_perfetto_track_token(void *context) {
  if (!trace_enabled.load(std::memory_order_relaxed) ||
      trace_identity_index < 0)
    return 0;
  if (!context)
    context = dr_get_current_drcontext();
  if (!context)
    return 0;
  const uintptr_t saved = reinterpret_cast<uintptr_t>(
      drmgr_get_tls_field(context, trace_identity_index));
  // The sentinel survives duplicate teardown/begin calls until DR destroys
  // this context. A recycled context receives a fresh, zeroed TLS field.
  if (saved == UINTPTR_MAX)
    return 0;
  if (saved || context != dr_get_current_drcontext())
    return saved;
  const uint64_t token =
      trace_identity_token.fetch_add(1, std::memory_order_relaxed) + 1;
  if (!token || token >= UINTPTR_MAX || token > uint64_t(INT64_MAX)) {
    trace_enabled.store(false);
    ct_output_printf("ctrace: Perfetto context identities exhausted\n");
    return 0;
  }
  if (!drmgr_set_tls_field(context, trace_identity_index,
                           reinterpret_cast<void *>(uintptr_t(token)))) {
    trace_enabled.store(false);
    ct_output_printf("ctrace: cannot retain Perfetto context identity\n");
    return 0;
  }
  return token;
}

static PerfettoThreadId trace_identity(void *context) {
  if (!context)
    context = dr_get_current_drcontext();
  const uint64_t token = ct_perfetto_track_token(context);
  return token ? PerfettoThreadId{token,
                                  dr_get_process_id_from_drcontext(context),
                                  dr_get_thread_id(context)}
               : PerfettoThreadId{};
}

static std::string application_nanoseconds(uint64_t ticks) {
  // Keep the multiplication wide: even valid long-running traces can exceed
  // uint64_t when converting cumulative ticks into nanoseconds.
  const unsigned __int128 nanoseconds =
      static_cast<unsigned __int128>(ticks) * 1000000000 / trace_frequency;
  unsigned __int128 remaining = nanoseconds;
  std::string integral;
  do {
    integral += static_cast<char>('0' + remaining % 10);
    remaining /= 10;
  } while (remaining);
  std::reverse(integral.begin(), integral.end());
  return integral;
}

static std::string event_position(PerfettoThreadId id,
                                  ct_perfetto_timestamp timestamp) {
  const uint64_t nanoseconds = timestamp.wall_nanoseconds - trace_origin;
  char fractional[5];
  std::snprintf(fractional, sizeof(fractional), ".%03u",
                static_cast<unsigned>(nanoseconds % 1000));
  return "\"ctrace_context\":" + std::to_string(id.token) +
         ",\"pid\":" + std::to_string(id.process) +
         ",\"tid\":" + std::to_string(id.thread) +
         ",\"ts\":" + std::to_string(nanoseconds / 1000) + fractional;
}

static std::string pc_argument(uint64_t pc) {
  char text[32];
  std::snprintf(text, sizeof(text), "\"0x%llx\"",
                static_cast<unsigned long long>(pc));
  return text;
}

static PerfettoThread &trace_thread(PerfettoThreadId id,
                                    ct_perfetto_timestamp timestamp) {
  auto inserted = trace_threads.emplace(id.token, PerfettoThread{});
  if (inserted.second) {
    inserted.first->second.id = id;
    inserted.first->second.timestamp = timestamp;
    const std::string identity =
        "\"ctrace_context\":" + std::to_string(id.token) +
        ",\"pid\":" + std::to_string(id.process);
    // This first record is emitted by the owning context. The broker binds
    // the opaque token to its SCM_CREDENTIALS owner before any cross-context E.
    write_event("{\"ph\":\"M\",\"name\":\"thread_name\"," + identity +
                ",\"tid\":" + std::to_string(id.thread) +
                ",\"args\":{\"name\":\"PID " + std::to_string(id.process) +
                ", TID " + std::to_string(id.thread) +
                " (namespace IDs; wall time)\",\"namespace_pid\":" +
                std::to_string(id.process) +
                ",\"namespace_tid\":" + std::to_string(id.thread) + "}}");
    write_event("{\"ph\":\"M\",\"name\":\"process_name\"," + identity +
                ",\"tid\":0,\"args\":{\"name\":" +
                ct_perfetto_json_string(trace_program.c_str()) + "}}");
    // The client supplies the target's argv[0], not the tracer/helper name.
    // Fork retains it; exec initializes a new track with the new program.
    const size_t separator = trace_program.rfind('/');
    const std::string execution_name =
        "[" +
        trace_program.substr(separator == std::string::npos ? 0
                                                            : separator + 1) +
        "]";
    if (write_event(
            "{\"ph\":\"B\",\"cat\":\"ctrace.execution\","
            "\"name\":" +
            ct_perfetto_json_string(execution_name.c_str()) + "," +
            event_position(id, timestamp) + ",\"args\":{\"begin_ticks\":" +
            std::to_string(timestamp.ticks) + ",\"begin_application_ns\":" +
            application_nanoseconds(timestamp.ticks) + "}}")) {
      const uint64_t token = ++trace_token;
      inserted.first->second.stack.push_back({token, timestamp});
      trace_tokens.emplace(token, id.token);
    }
  }
  return inserted.first->second;
}

static void end_slice(PerfettoThreadId id, PerfettoThread &thread,
                      ct_perfetto_timestamp timestamp, const char *status,
                      const char *details = nullptr) {
  const PerfettoSlice slice = thread.stack.back();
  thread.timestamp.ticks = std::max(
      {thread.timestamp.ticks, timestamp.ticks, slice.timestamp.ticks});
  thread.timestamp.wall_nanoseconds =
      std::max({thread.timestamp.wall_nanoseconds, timestamp.wall_nanoseconds,
                slice.timestamp.wall_nanoseconds});
  const uint64_t duration_ticks =
      thread.timestamp.ticks - slice.timestamp.ticks;
  write_event(
      "{\"ph\":\"E\"," + event_position(id, thread.timestamp) +
      ",\"args\":{\"status\":" + ct_perfetto_json_string(status) +
      ",\"end_ticks\":" + std::to_string(thread.timestamp.ticks) +
      ",\"duration_ticks\":" + std::to_string(duration_ticks) +
      ",\"application_duration_ns\":" +
      application_nanoseconds(duration_ticks) +
      (details ? ",\"end_details\":" + ct_perfetto_json_string(details) : "") +
      "}}");
  trace_tokens.erase(slice.token);
  thread.stack.pop_back();
}

bool ct_perfetto_init(uint64_t tsc_hz, ct_instrument_level initial_level,
                      const char *program) {
  if (trace_mutex || !tsc_hz)
    return false;
  trace_origin = ct_analysis_trace_origin_ns();
  if (!trace_origin) {
    ct_output_printf(
        "ctrace: shared Perfetto clock origin unavailable; recording "
        "stopped\n");
    return false;
  }
  trace_mutex = dr_mutex_create();
  if (!trace_mutex)
    return false;
  trace_identity_index = drmgr_register_tls_field();
  if (trace_identity_index < 0) {
    dr_mutex_destroy(trace_mutex);
    trace_mutex = nullptr;
    return false;
  }
  trace_frequency = tsc_hz;
  trace_footer =
      "{\"clock\":\"CLOCK_MONOTONIC_RAW (time-namespace normalized)\","
      "\"trace_origin_ns\":" +
      std::to_string(trace_origin) +
      ",\"tsc_frequency_hz\":" + std::to_string(tsc_hz) +
      ",\"timestamp_unit\":\"microseconds\","
      "\"pid_semantics\":\"broker PID namespace\","
      "\"tid_semantics\":\"logical context lifetime\","
      "\"thread_metadata_preserves_namespace_ids\":true,"
      "\"exec_starts_new_thread_track\":true,"
      "\"timestamps_comparable_across_threads\":true,"
      "\"timestamps_comparable_across_processes\":true,"
      "\"untraced_gaps_preserved\":true,"
      "\"callback_time_excluded\":false,"
      "\"terminal_output_time_excluded\":false,"
      "\"application_clock\":\"per-thread adjusted TSC\","
      "\"application_callback_time_excluded\":true,"
      "\"application_terminal_output_time_excluded\":true,"
      "\"syscall_elapsed_includes_wait\":true,"
      "\"syscall_clock\":\"TSC; monotonic fallback on CPU migration\","
      "\"syscall_runtime_boundary_cost_excluded\":false,"
      "\"userspace_gate_boundary_cost_excluded\":false,"
      "\"userspace_gate_mechanism\":\"userspace JMP\","
      "\"exact_uninstrumented_cost\":false,"
      "\"residual_probe_and_runtime_cost\":true";
  trace_footer +=
      ",\"initial_instrumentation\":" +
      ct_perfetto_json_string(ct_instrument_level_name(initial_level));
  trace_userspace_spans.store(0, std::memory_order_relaxed);
  trace_userspace_gate_hits.store(0, std::memory_order_relaxed);
  trace_userspace_detailed_steps.store(0, std::memory_order_relaxed);
  trace_token = 0;
  trace_program = program && *program ? program : dr_get_application_name();
  trace_footer_sent.clear();
  trace_enabled.store(true);
  if (!publish_footer()) {
    drmgr_unregister_tls_field(trace_identity_index);
    trace_identity_index = -1;
    dr_mutex_destroy(trace_mutex);
    trace_mutex = nullptr;
    return false;
  }
  return true;
}

bool ct_perfetto_enabled() { return trace_enabled.load(); }

ct_perfetto_timestamp ct_perfetto_now(uint64_t ticks) {
  if (!trace_enabled.load())
    return {ticks, 0};
  const uint64_t nanoseconds = ct_analysis_wall_nanoseconds();
  if (!nanoseconds) {
    if (trace_enabled.exchange(false))
      ct_output_printf("ctrace: cannot read time-namespace normalized "
                       "CLOCK_MONOTONIC_RAW; Perfetto recording stopped\n");
    return {ticks, 0};
  }
  return {ticks, nanoseconds};
}

void ct_perfetto_fork_prepare() {
  if (trace_mutex)
    dr_mutex_lock(trace_mutex);
}

void ct_perfetto_fork_parent() {
  if (trace_mutex)
    dr_mutex_unlock(trace_mutex);
}

bool ct_perfetto_fork_child(void *context, bool recording) {
  if (!trace_mutex)
    return true;
  const ct_perfetto_timestamp timestamp = ct_perfetto_now(0);
  const bool enabled = recording && trace_enabled.load();
  trace_enabled.store(enabled);
  dr_mutex_reset_after_fork(trace_mutex);
  trace_threads.clear();
  trace_tokens.clear();
  drmgr_set_tls_field(context, trace_identity_index, nullptr);
  trace_userspace_spans.store(0, std::memory_order_relaxed);
  trace_userspace_gate_hits.store(0, std::memory_order_relaxed);
  trace_userspace_detailed_steps.store(0, std::memory_order_relaxed);
  trace_footer_sent.clear();
  // Retain the token high-water mark so a stale inherited token cannot close
  // a newly opened child slice while the owner resets its saved scope state.
  if (enabled) {
    PerfettoLock lock;
    const auto id = trace_identity(context);
    if (id.token)
      trace_thread(id, timestamp);
  }
  return !enabled || trace_enabled.load();
}

void ct_perfetto_userspace_span(bool gate, bool detailed) {
  if (!trace_enabled.load(std::memory_order_relaxed))
    return;
  trace_userspace_spans.fetch_add(1, std::memory_order_relaxed);
  if (gate && detailed)
    trace_userspace_detailed_steps.fetch_add(1, std::memory_order_relaxed);
  if (gate)
    trace_userspace_gate_hits.fetch_add(1, std::memory_order_release);
}

void ct_perfetto_thread_begin(void *context) {
  const ct_perfetto_timestamp timestamp = ct_perfetto_now(0);
  if (!trace_enabled.load())
    return;
  PerfettoLock lock;
  if (trace_enabled.load()) {
    const auto id = trace_identity(context);
    if (id.token)
      trace_thread(id, timestamp);
  }
}

uint64_t ct_perfetto_begin(ct_perfetto_timestamp timestamp,
                           const char *category, const char *name,
                           const char *module, const char *file, unsigned line,
                           uint64_t pc, const char *origin,
                           const char *details) {
  if (!trace_enabled.load())
    return 0;
  const PerfettoThreadId id = trace_identity(nullptr);
  if (!id.token)
    return 0;
  PerfettoLock lock;
  if (!trace_enabled.load())
    return 0;
  PerfettoThread &thread = trace_thread(id, timestamp);
  timestamp.ticks = std::max(timestamp.ticks, thread.timestamp.ticks);
  timestamp.wall_nanoseconds =
      std::max(timestamp.wall_nanoseconds, thread.timestamp.wall_nanoseconds);
  const uint64_t token = ++trace_token;
  const std::string event =
      "{\"ph\":\"B\",\"cat\":" + ct_perfetto_json_string(category) +
      ",\"name\":" + ct_perfetto_json_string(name) + "," +
      event_position(id, timestamp) +
      ",\"args\":{\"module\":" + ct_perfetto_json_string(module) +
      ",\"file\":" + ct_perfetto_json_string(file) +
      ",\"line\":" + std::to_string(line) + ",\"pc\":" + pc_argument(pc) +
      ",\"origin\":" + ct_perfetto_json_string(origin) +
      ",\"begin_ticks\":" + std::to_string(timestamp.ticks) +
      ",\"begin_application_ns\":" + application_nanoseconds(timestamp.ticks) +
      (details ? ",\"details\":" + ct_perfetto_json_string(details) : "") +
      "}}";
  if (!write_event(event))
    return 0;
  thread.timestamp = timestamp;
  thread.stack.push_back({token, timestamp});
  trace_tokens.emplace(token, id.token);
  return token;
}

void ct_perfetto_end(uint64_t token, ct_perfetto_timestamp timestamp,
                     const char *status, const char *details) {
  if (!token || !trace_enabled.load())
    return;
  PerfettoLock lock;
  const auto found = trace_tokens.find(token);
  if (found == trace_tokens.end())
    return;
  PerfettoThread &thread = trace_threads.at(found->second);
  const PerfettoThreadId id = thread.id;
  while (thread.stack.back().token != token)
    end_slice(id, thread, timestamp, "incomplete");
  end_slice(id, thread, timestamp, status ? status : "complete", details);
}

void ct_perfetto_instant(ct_perfetto_timestamp timestamp, const char *name,
                         const char *details, uint64_t pc) {
  if (!trace_enabled.load())
    return;
  const PerfettoThreadId id = trace_identity(nullptr);
  if (!id.token)
    return;
  PerfettoLock lock;
  if (!trace_enabled.load())
    return;
  PerfettoThread &thread = trace_thread(id, timestamp);
  thread.timestamp.ticks = std::max(timestamp.ticks, thread.timestamp.ticks);
  thread.timestamp.wall_nanoseconds =
      std::max(timestamp.wall_nanoseconds, thread.timestamp.wall_nanoseconds);
  write_event("{\"ph\":\"i\",\"s\":\"t\",\"cat\":\"signal\",\"name\":" +
              ct_perfetto_json_string(name) + "," +
              event_position(id, thread.timestamp) + ",\"args\":{\"details\":" +
              ct_perfetto_json_string(details) + ",\"pc\":" + pc_argument(pc) +
              ",\"ticks\":" + std::to_string(thread.timestamp.ticks) + "}}");
}

void ct_perfetto_thread_end(void *context, ct_perfetto_timestamp timestamp,
                            const char *status) {
  if (!trace_enabled.load())
    return;
  if (!context)
    context = dr_get_current_drcontext();
  const PerfettoThreadId id = trace_identity(context);
  if (!id.token)
    return;
  PerfettoLock lock;
  const auto found = trace_threads.find(id.token);
  if (found != trace_threads.end()) {
    while (!found->second.stack.empty())
      end_slice(id, found->second, timestamp, status ? status : "incomplete");
    trace_threads.erase(found);
  }
  drmgr_set_tls_field(context, trace_identity_index,
                      reinterpret_cast<void *>(UINTPTR_MAX));
}

void ct_perfetto_exit() {
  if (!trace_mutex)
    return;
  {
    PerfettoLock lock;
    for (auto &thread : trace_threads) {
      while (!thread.second.stack.empty())
        end_slice(thread.second.id, thread.second, thread.second.timestamp,
                  "incomplete");
    }
    // Userspace execution can finish without another visible source event.
    if (trace_enabled.load() && !publish_footer())
      ct_output_printf("ctrace: cannot finalize Perfetto trace metadata\n");
    if (trace_enabled.load() && !ct_analysis_trace_flush())
      ct_output_printf("ctrace: cannot flush Perfetto trace\n");
    trace_enabled.store(false);
    trace_threads.clear();
    trace_tokens.clear();
  }
  drmgr_unregister_tls_field(trace_identity_index);
  trace_identity_index = -1;
  dr_mutex_destroy(trace_mutex);
  trace_mutex = nullptr;
}
