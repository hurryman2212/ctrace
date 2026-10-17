#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <tuple>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

#include "kernel_perfetto.h"
#include "perfetto_json.h"

static constexpr size_t perfetto_scope_limit = 1000000;
static constexpr size_t perfetto_track_limit = 65536;

static std::string perfetto_time(uint64_t nanoseconds) {
  char text[48];
  std::snprintf(text, sizeof(text), "%llu.%03llu",
                static_cast<unsigned long long>(nanoseconds / 1000),
                static_cast<unsigned long long>(nanoseconds % 1000));
  return text;
}

struct ct_kernel_perfetto::Data {
  using Key = std::tuple<uint32_t, uint32_t, uint64_t, uint32_t, uint32_t,
                         uint16_t, uint16_t, bool>;
  struct Track {
    uint64_t id = 0, probe_ns = 0, epoch = 0, last_end = 0, last_sequence = 0;
    bool reliable = true;
    std::vector<uint64_t> stack;
  };
  struct Slice {
    ct_kernel_trace_transition begin;
    Key key;
    uint64_t probe_ns = 0, epoch = 0;
    bool reliable = false;
  };
  FILE *file = nullptr;
  std::string destination, module, input;
  uint32_t controller = 0;
  uint64_t origin = 0, last = 0, begin = 0, dropped = 0, timed = 0;
  uint64_t session = 0, generation = 0;
  __int128 clock_offset = 0;
  bool first = true, failed = false, closed = false, bound = false;
  std::map<Key, Track> tracks;
  std::map<uint64_t, Slice> slices;

  ~Data() {
    if (file) {
      // Normal/failure returns that happen before loading still leave readable
      // JSON. SIGKILL itself cannot run this best-effort footer.
      const char footer[] = "\n],\"displayTimeUnit\":\"ns\",\"otherData\":{"
                            "\"incomplete\":true}}\n";
      if (!closed && !failed)
        (void)std::fwrite(footer, 1, sizeof(footer) - 1, file);
      std::fclose(file);
    }
  }

  uint64_t now() const {
    timespec stamp{};
    if (clock_gettime(CLOCK_MONOTONIC, &stamp) != 0)
      return 0;
    const __int128 value =
        __int128(stamp.tv_sec) * 1000000000 + stamp.tv_nsec - clock_offset;
    return value > 0 && value <= UINT64_MAX ? uint64_t(value) : 0;
  }

  bool emit(const std::string &text, std::string &error) {
    if (!file || closed || failed) {
      error = "kernel Perfetto output is not writable";
      return false;
    }
    const std::string line = (first ? "" : ",\n") + text;
    if (std::fwrite(line.data(), 1, line.size(), file) != line.size() ||
        std::fflush(file) != 0) {
      failed = true;
      error = "cannot write kernel Perfetto output: " +
              std::string(std::strerror(errno));
      return false;
    }
    first = false;
    return true;
  }

  static Key key(uint32_t tgid, uint32_t tid, uint64_t start, uint32_t context,
                 uint32_t cpu, uint16_t hardirq, uint16_t softirq,
                 bool has_execution) {
    const bool irq_lane = has_execution && context != KCTRACE_CONTEXT_TASK;
    return {irq_lane ? 0 : tgid,
            irq_lane ? 0 : tid,
            irq_lane ? 0 : start,
            context,
            context == KCTRACE_CONTEXT_TASK && tid ? 0 : cpu,
            hardirq,
            softirq,
            irq_lane};
  }

  bool transitions(const std::vector<ct_kernel_trace_transition> &events,
                   std::string &error) {
    for (const auto &event : events) {
      if (!event.token || event.monotonic_ns < origin) {
        error = "invalid kernel Perfetto scope identity or timestamp";
        return false;
      }
      const Key context = key(event.tgid, event.tid, event.task_start_ns,
                              event.context, event.cpu, event.hardirq_depth,
                              event.softirq_depth, event.has_execution);
      auto found = tracks.find(context);
      if (found == tracks.end()) {
        if (tracks.size() >= perfetto_track_limit) {
          error = "kernel Perfetto track limit exceeded";
          return false;
        }
        found = tracks.emplace(context, Track{}).first;
        found->second.id = tracks.size();
        std::string name;
        if (!event.has_execution || event.context == KCTRACE_CONTEXT_TASK)
          name = "task " + std::to_string(event.tid) + " (tgid " +
                 std::to_string(event.tgid) + ")";
        if (event.context != KCTRACE_CONTEXT_TASK)
          name += (name.empty() ? "CPU " : " / CPU ") +
                  std::to_string(event.cpu) +
                  (event.context == KCTRACE_CONTEXT_HARDIRQ ? " hardirq "
                                                            : " softirq ") +
                  std::to_string(event.hardirq_depth) + "/" +
                  std::to_string(event.softirq_depth);
        if (!emit("{\"ph\":\"M\",\"name\":\"thread_name\",\"pid\":" +
                      std::to_string(controller) +
                      ",\"tid\":" + std::to_string(found->second.id) +
                      ",\"args\":{\"name\":" +
                      ct_perfetto_json_string(name.c_str()) + "}}",
                  error))
          return false;
      }
      auto &track = found->second;
      if (event.phase == ct_kernel_trace_phase::begin) {
        if (slices.size() >= perfetto_scope_limit ||
            slices.count(event.token) ||
            event.parent != (track.stack.empty() ? 0 : track.stack.back()) ||
            (event.parent &&
             (!slices.count(event.parent) ||
              slices.at(event.parent).key != context ||
              event.monotonic_ns <
                  slices.at(event.parent).begin.monotonic_ns))) {
          error = "invalid or excessive kernel Perfetto scope nesting";
          return false;
        }
        slices.emplace(
            event.token,
            Slice{event, context, track.probe_ns, track.epoch,
                  track.reliable && event.monotonic_ns >= track.last_end});
        if (!emit(
                "{\"ph\":\"B\",\"cat\":" +
                    ct_perfetto_json_string(
                        event.kind == ct_kernel_trace_kind::function
                            ? "ctrace.function"
                            : "ctrace.block") +
                    ",\"name\":" + ct_perfetto_json_string(event.name.c_str()) +
                    ",\"pid\":" + std::to_string(controller) +
                    ",\"tid\":" + std::to_string(track.id) +
                    ",\"ts\":" + perfetto_time(event.monotonic_ns - origin) +
                    ",\"args\":{\"module\":" +
                    ct_perfetto_json_string(module.c_str()) +
                    ",\"file\":" + ct_perfetto_json_string(event.file.c_str()) +
                    ",\"line\":" + std::to_string(event.line) +
                    ",\"pc\":" + std::to_string(event.pc) + ",\"origin\":" +
                    ct_perfetto_json_string(event.origin.c_str()) +
                    ",\"token\":" + std::to_string(event.token) +
                    ",\"parent\":" + std::to_string(event.parent) +
                    ",\"task_tid\":" + std::to_string(event.tid) +
                    ",\"task_tgid\":" + std::to_string(event.tgid) +
                    ",\"task_start_ns\":" +
                    std::to_string(event.task_start_ns) +
                    ",\"context\":" + std::to_string(event.context) +
                    ",\"cpu\":" + std::to_string(event.cpu) +
                    ",\"hardirq_depth\":" +
                    std::to_string(event.hardirq_depth) +
                    ",\"softirq_depth\":" +
                    std::to_string(event.softirq_depth) + "}}",
                error))
          return false;
        track.stack.push_back(event.token);
        continue;
      }
      const auto slice = slices.find(event.token);
      if (slice == slices.end() || slice->second.key != context ||
          track.stack.empty() || track.stack.back() != event.token) {
        error = "kernel Perfetto scope ended in another execution context";
        return false;
      }
      const auto &saved = slice->second;
      const uint64_t end =
          std::max(event.monotonic_ns, saved.begin.monotonic_ns);
      const uint64_t elapsed = end - saved.begin.monotonic_ns;
      const uint64_t measured = track.probe_ns - saved.probe_ns;
      const bool valid = saved.reliable && track.reliable &&
                         saved.epoch == track.epoch && measured <= elapsed &&
                         event.monotonic_ns >= track.last_end;
      std::string args =
          "{\"status\":" + ct_perfetto_json_string(event.status.c_str()) +
          ",\"elapsed_ns\":" + std::to_string(elapsed) +
          ",\"measured_probe_ns\":" +
          (valid ? std::to_string(measured) : "null") +
          ",\"probe_excluded_elapsed_ns\":" +
          (valid ? std::to_string(elapsed - measured) : "null") +
          ",\"cost_valid\":" + (valid ? "true" : "false") + "}";
      if (!emit("{\"ph\":\"E\",\"pid\":" + std::to_string(controller) +
                    ",\"tid\":" + std::to_string(track.id) + ",\"ts\":" +
                    perfetto_time(end - origin) + ",\"args\":" + args + "}",
                error))
        return false;
      track.stack.pop_back();
      slices.erase(slice);
    }
    return true;
  }
};

ct_kernel_perfetto::ct_kernel_perfetto() : data(std::make_unique<Data>()) {}
ct_kernel_perfetto::~ct_kernel_perfetto() = default;

bool ct_kernel_perfetto::open(const std::string &prefix, int directory,
                              uint32_t controller_tid,
                              const std::string &module,
                              const std::string &input, std::string &error) {
  error.clear();
  if (data->file || directory < 0 || prefix.empty() || !controller_tid) {
    error = "invalid or repeated kernel Perfetto initialization";
    return false;
  }
  std::ifstream offsets("/proc/self/timens_offsets");
  if (offsets) {
    std::string line;
    bool monotonic = false;
    while (std::getline(offsets, line)) {
      std::istringstream fields(line);
      std::string clock;
      int64_t seconds = 0, nanoseconds = 0;
      if (!(fields >> clock >> seconds >> nanoseconds)) {
        error = "cannot parse the controller's time namespace offset";
        return false;
      }
      if (clock == "monotonic") {
        data->clock_offset = __int128(seconds) * 1000000000 + nanoseconds;
        monotonic = true;
      }
    }
    if (!monotonic || !offsets.eof()) {
      error = "controller monotonic time namespace offset is unavailable";
      return false;
    }
  } else if (access("/proc/self/ns/time", F_OK) == 0) {
    error = "cannot read the controller's time namespace offset";
    return false;
  }
  data->origin = data->now();
  if (!data->origin) {
    error = "kernel monotonic clock normalization failed";
    return false;
  }
  const time_t wall = std::time(nullptr);
  tm local{};
  char stamp[32];
  if (wall == time_t(-1) || !localtime_r(&wall, &local) ||
      !std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &local)) {
    error = "cannot obtain kernel Perfetto file creation time";
    return false;
  }
  const std::string suffix =
      "." + std::string(stamp) + "." + std::to_string(controller_tid) + ".json";
  const std::string name =
      std::filesystem::path(prefix).filename().string() + suffix;
  const int descriptor = openat(directory, name.c_str(),
                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (descriptor < 0) {
    error = "cannot create kernel Perfetto output: " +
            std::string(std::strerror(errno));
    return false;
  }
  data->file = fdopen(descriptor, "w");
  if (!data->file) {
    const int failure = errno;
    close(descriptor);
    error = "cannot open kernel Perfetto stream: " +
            std::string(std::strerror(failure));
    return false;
  }
  data->destination = prefix + suffix;
  data->module = module;
  data->input = input;
  data->controller = controller_tid;
  if (std::fputs("{\"traceEvents\":[\n", data->file) == EOF ||
      !data->emit("{\"ph\":\"M\",\"name\":\"process_name\",\"pid\":" +
                      std::to_string(controller_tid) +
                      ",\"tid\":0,\"args\":{\"name\":" +
                      ct_perfetto_json_string(
                          ("ctrace kernel module " + module).c_str()) +
                      "}}",
                  error) ||
      !data->emit("{\"ph\":\"M\",\"name\":\"thread_name\",\"pid\":" +
                      std::to_string(controller_tid) +
                      ",\"tid\":0,\"args\":{\"name\":\"module lifetime\"}}",
                  error)) {
    if (error.empty())
      error = "cannot write kernel Perfetto header";
    data->failed = true;
    return false;
  }
  return true;
}

bool ct_kernel_perfetto::observe(
    const kctrace_event &event,
    const std::vector<ct_kernel_trace_transition> &transitions,
    std::string &error) {
  error.clear();
  if (!data->file || data->closed || event.size != sizeof(event) ||
      event.monotonic_ns < data->origin || !event.session_id ||
      !event.generation ||
      (data->session && (data->session != event.session_id ||
                         data->generation != event.generation))) {
    error = "invalid kernel Perfetto event/session clock";
    return false;
  }
  data->session = event.session_id;
  data->generation = event.generation;
  data->last = std::max<uint64_t>(data->last, event.monotonic_ns);
  if (event.type == KCTRACE_EVENT_BOUND) {
    if (data->bound) {
      error = "duplicate kernel module lifetime begin";
      return false;
    }
    data->begin = event.monotonic_ns;
    data->bound = true;
    if (!data->emit(
            "{\"ph\":\"B\",\"cat\":\"ctrace.module\",\"name\":" +
                ct_perfetto_json_string(("[" + data->module + "]").c_str()) +
                ",\"pid\":" + std::to_string(data->controller) +
                ",\"tid\":0,\"ts\":" +
                perfetto_time(data->begin - data->origin) +
                ",\"args\":{\"module\":" +
                ct_perfetto_json_string(data->input.c_str()) + "}}",
            error))
      return false;
  }
  if (event.dropped_total > data->dropped) {
    for (auto &[key, track] : data->tracks)
      ++track.epoch;
    data->dropped = event.dropped_total;
    if (!data->emit("{\"ph\":\"i\",\"s\":\"t\",\"name\":\"kernel events lost\","
                    "\"pid\":" +
                        std::to_string(data->controller) +
                        ",\"tid\":0,\"ts\":" +
                        perfetto_time(event.monotonic_ns - data->origin) +
                        ",\"args\":{\"dropped_total\":" +
                        std::to_string(data->dropped) + "}}",
                    error))
      return false;
  }
  const auto key =
      Data::key(event.tgid, event.tid, event.task_start_ns, event.context,
                event.cpu, event.hardirq_depth, event.softirq_depth,
                event.flags & KCTRACE_EVENT_HAVE_EXECUTION);
  auto found = data->tracks.find(key);
  if (found != data->tracks.end()) {
    const bool ordered = event.sequence > found->second.last_sequence &&
                         event.monotonic_ns >= found->second.last_end;
    if (!ordered)
      ++found->second.epoch;
    found->second.reliable = ordered;
  }
  // Scope endpoints are sampled before this event's recorder work. Charge the
  // current interval only after applying begin/end transitions at that point.
  if (!data->transitions(transitions, error))
    return false;
  found = data->tracks.find(key);
  if (found != data->tracks.end()) {
    auto &track = found->second;
    const bool timed = event.flags & KCTRACE_EVENT_PROBE_TIMING;
    if (timed && event.probe_end_ns >= event.monotonic_ns &&
        event.probe_end_ns - event.monotonic_ns <=
            UINT64_MAX - track.probe_ns) {
      track.probe_ns += event.probe_end_ns - event.monotonic_ns;
      track.last_end = std::max<uint64_t>(track.last_end, event.probe_end_ns);
      ++data->timed;
    } else if (event.type == KCTRACE_EVENT_INSTRUCTION_BEFORE ||
               event.type == KCTRACE_EVENT_BLOCK_POINT ||
               event.type == KCTRACE_EVENT_EXECUTION) {
      ++track.epoch;
      track.reliable = false;
    }
    track.last_sequence =
        std::max<uint64_t>(track.last_sequence, event.sequence);
  }
  return true;
}

bool ct_kernel_perfetto::finish(
    const std::vector<ct_kernel_trace_transition> &transitions,
    const char *status, std::string &error) {
  error.clear();
  if (!data->file || data->closed) {
    error = "kernel Perfetto output was not opened or already finished";
    return false;
  }
  if (!data->transitions(transitions, error))
    return false;
  while (!data->slices.empty()) {
    auto end = data->slices.rbegin()->second.begin;
    end.phase = ct_kernel_trace_phase::end;
    end.monotonic_ns = std::max(data->last, end.monotonic_ns);
    end.status = "incomplete";
    if (!data->transitions({end}, error))
      return false;
  }
  const uint64_t now = data->now();
  const uint64_t end = std::max(now, data->last);
  if (data->bound &&
      !data->emit(
          "{\"ph\":\"E\",\"pid\":" + std::to_string(data->controller) +
              ",\"tid\":0,\"ts\":" + perfetto_time(end - data->origin) +
              ",\"args\":{\"status\":" + ct_perfetto_json_string(status) +
              ",\"end_clock_observed\":" +
              (now >= data->last ? "true" : "false") + "}}",
          error))
    return false;
  const std::string footer =
      "\n],\"displayTimeUnit\":\"ns\",\"otherData\":{"
      "\"clock\":\"kernel "
      "CLOCK_MONOTONIC\",\"timestamp_unit\":\"microseconds\","
      "\"timestamps_comparable_across_threads\":true,\"wall_timeline\":true,"
      "\"cost_field\":\"probe_excluded_elapsed_ns\",\"cost_unit\":"
      "\"nanoseconds\","
      "\"measured_probe_time_excluded_from_cost\":true,"
      "\"terminal_output_time_excluded\":true,\"exact_native_cost\":false,"
      "\"off_cpu_time_excluded\":false,\"unobserved_irq_time_excluded\":false,"
      "\"residual_probe_cost\":true,"
      "\"probe_interval\":\"after recursion guard through ring publication; "
      "excludes assembly entry/restore, wakeup and cleanup; may include "
      "interrupts\","
      "\"timed_events\":" +
      std::to_string(data->timed) +
      ",\"dropped_events\":" + std::to_string(data->dropped) + "}}\n";
  if (std::fwrite(footer.data(), 1, footer.size(), data->file) !=
          footer.size() ||
      std::fflush(data->file) != 0) {
    data->failed = true;
    error = "cannot finish kernel Perfetto output";
    return false;
  }
  data->closed = true;
  return true;
}

const std::string &ct_kernel_perfetto::path() const {
  return data->destination;
}
