#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "decompile.h"
#include "decompile_provider.h"
#include "decompile_record.h"
#include "decompile_view.h"
#include "flow.h"
#include "shared_objects.h"
#include "shared_objects_host.h"

// Headless analysis can include a cold JVM start. Bound each request and the
// amount of untrusted analysis output retained by the analysis helper.
static constexpr auto worker_timeout = std::chrono::seconds(180);
static constexpr size_t response_limit = 16 * 1024 * 1024;
static constexpr size_t line_limit = 65536;
static constexpr auto worker_shutdown_timeout = std::chrono::seconds(15);
static constexpr auto worker_shutdown_poll = std::chrono::milliseconds(10);

extern char **environ;

class DecompileWorker {
  pid_t process = -1;
  int socket = -1;
  int diagnostics = -1;
  int cancellation = -1;
  bool failed = false;
  std::string pending, diagnostic_text;

  bool read_diagnostics() {
    if (diagnostics < 0)
      return true;
    char chunk[8192];
    for (;;) {
      const ssize_t count = read(diagnostics, chunk, sizeof(chunk));
      if (count > 0) {
        if (size_t(count) > response_limit - diagnostic_text.size())
          return false;
        diagnostic_text.append(chunk, size_t(count));
      } else if (count < 0 && errno == EINTR) {
        continue;
      } else if (count == 0) {
        close(diagnostics);
        diagnostics = -1;
        return true;
      } else {
        return errno == EAGAIN;
      }
    }
  }

  void stop(bool graceful = false) {
    if (socket >= 0) {
      shutdown(socket, SHUT_RDWR);
      close(socket);
      socket = -1;
    }
    if (process > 0) {
      // The worker and its analyzers belong to a private process group.
      if (graceful) {
        const auto deadline =
            std::chrono::steady_clock::now() + worker_shutdown_timeout;
        for (;;) {
          const pid_t status = waitpid(process, nullptr, WNOHANG);
          if (status == process || (status < 0 && errno == ECHILD)) {
            kill(-process, SIGKILL);
            process = -1;
            break;
          }
          if (std::chrono::steady_clock::now() >= deadline)
            break;
          std::this_thread::sleep_for(worker_shutdown_poll);
        }
      }
    }
    if (process > 0) {
      kill(-process, SIGKILL);
      while (waitpid(process, nullptr, 0) < 0 && errno == EINTR) {
      }
      process = -1;
    }
    if (diagnostics >= 0) {
      read_diagnostics();
      if (diagnostics >= 0)
        close(diagnostics);
      diagnostics = -1;
    }
    pending.clear();
  }

public:
  std::string error;
  bool healthy() const { return !failed; }
  int event_fd() const { return diagnostics; }
  void cancel_with(int descriptor) { cancellation = descriptor; }

  void service() {
    if (!read_diagnostics()) {
      error = "decompiler diagnostics cannot be read";
      failed = true;
      stop();
      return;
    }
    if (process > 0) {
      const pid_t ended = waitpid(process, nullptr, WNOHANG);
      if (diagnostics < 0 || ended == process ||
          (ended < 0 && errno == ECHILD)) {
        error = "decompiler worker exited";
        failed = true;
        stop();
      }
    }
  }

  ~DecompileWorker() { stop(true); }
  void finish() { stop(true); }

  bool exchange(const llvm::json::Object &request, std::string &response) {
    pollfd cancelled{cancellation, POLLIN, 0};
    if (cancellation >= 0 && poll(&cancelled, 1, 0) > 0) {
      error = "decompiler producer control closed or request cancelled";
      failed = true;
      stop();
      return false;
    }
    if (failed) {
      stop();
      failed = false;
      error.clear();
    }
    if (process < 0) {
      const char *worker = std::getenv("CTRACE_DECOMPILE_WORKER");
      if (!worker || !worker[0]) {
        error = "Ghidra decompiler worker is not configured";
        failed = true;
        return false;
      }
      int sockets[2];
      if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
        error = "cannot create decompiler worker connection";
        failed = true;
        return false;
      }
      int diagnostic_pipe[2];
      if (pipe2(diagnostic_pipe, O_CLOEXEC) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        error = "cannot create decompiler diagnostic connection";
        failed = true;
        return false;
      }
      // dup2(a, a) would retain CLOEXEC if a standard descriptor was closed.
      for (int *descriptor : {&sockets[0], &sockets[1], &diagnostic_pipe[0],
                              &diagnostic_pipe[1]}) {
        if (*descriptor >= 3)
          continue;
        const int replacement = fcntl(*descriptor, F_DUPFD_CLOEXEC, 3);
        if (replacement < 0) {
          close(sockets[0]);
          close(sockets[1]);
          close(diagnostic_pipe[0]);
          close(diagnostic_pipe[1]);
          error = "cannot allocate decompiler worker descriptors";
          failed = true;
          return false;
        }
        close(*descriptor);
        *descriptor = replacement;
      }
      if (fcntl(diagnostic_pipe[0], F_SETFL, O_NONBLOCK) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        close(diagnostic_pipe[0]);
        close(diagnostic_pipe[1]);
        error = "cannot configure decompiler diagnostic connection";
        failed = true;
        return false;
      }
      posix_spawn_file_actions_t actions;
      posix_spawnattr_t attributes;
      int status = posix_spawn_file_actions_init(&actions);
      const bool actions_ready = status == 0;
      if (!status)
        status = posix_spawnattr_init(&attributes);
      const bool attributes_ready = status == 0;
      if (!status)
        status = posix_spawn_file_actions_adddup2(&actions, sockets[1],
                                                  STDIN_FILENO);
      if (!status)
        status = posix_spawn_file_actions_adddup2(&actions, sockets[1],
                                                  STDOUT_FILENO);
      if (!status)
        status = posix_spawn_file_actions_adddup2(&actions, diagnostic_pipe[1],
                                                  STDERR_FILENO);
      if (!status)
        status = posix_spawn_file_actions_addclosefrom_np(&actions, 3);
      if (!status)
        status = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
      if (!status)
        status = posix_spawnattr_setpgroup(&attributes, 0);
      char *arguments[] = {const_cast<char *>(worker), nullptr};
      if (!status)
        status = posix_spawnp(&process, worker, &actions, &attributes,
                              arguments, environ);
      if (attributes_ready)
        posix_spawnattr_destroy(&attributes);
      if (actions_ready)
        posix_spawn_file_actions_destroy(&actions);
      close(sockets[1]);
      close(diagnostic_pipe[1]);
      if (status) {
        close(sockets[0]);
        close(diagnostic_pipe[0]);
        process = -1;
        error = "cannot start decompiler worker: " +
                std::string(std::strerror(status));
        failed = true;
        return false;
      }
      socket = sockets[0];
      diagnostics = diagnostic_pipe[0];
    }
    std::string encoded;
    llvm::raw_string_ostream output(encoded);
    output << llvm::json::Value(llvm::json::Object(request));
    output << '\n';
    output.flush();
    const auto deadline = std::chrono::steady_clock::now() + worker_timeout;
    size_t sent = 0;
    for (;;) {
      const bool writing = sent < encoded.size();
      if (!writing) {
        const size_t newline = pending.find('\n');
        if (newline != std::string::npos) {
          response = pending.substr(0, newline);
          pending.erase(0, newline + 1);
          auto parsed = llvm::json::parse(response);
          if (!parsed) {
            llvm::consumeError(parsed.takeError());
            return true; // The caller reports a malformed final response.
          }
          const auto *object = parsed->getAsObject();
          const auto *update = object ? object->getObject("progress") : nullptr;
          if (!update)
            return true;
          ct_analysis_progress progress{};
          const auto stage = update->getString("stage");
          const auto module = update->getString("module");
          const auto detail = update->getString("detail");
          const auto begin = update->getInteger("begin_offset");
          const auto end = update->getInteger("end_offset");
          if (!stage || !module || !detail ||
              stage->size() >= sizeof(progress.stage) ||
              module->size() >= sizeof(progress.module) ||
              (update->get("begin_offset") && !begin) ||
              (update->get("end_offset") && !end) ||
              (begin.has_value() != end.has_value()) ||
              (begin && (*begin < 0 || *end < *begin))) {
            error = "decompiler returned an invalid progress notification";
            break;
          }
          std::memcpy(progress.stage, stage->data(), stage->size());
          std::memcpy(progress.module, module->data(), module->size());
          const size_t detail_size =
              std::min(detail->size(), sizeof(progress.detail) - 1);
          std::memcpy(progress.detail, detail->data(), detail_size);
          // Long C++ names are valid; shortening an observational message must
          // not make the actual decompilation fail.
          if (detail->size() > detail_size)
            std::memcpy(progress.detail + detail_size - 3, "...", 3);
          if (begin) {
            progress.begin_offset = *begin;
            progress.end_offset = *end;
            progress.has_range = true;
          }
          ct_analysis_report_progress(&progress);
          continue;
        }
      }
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now())
                            .count();
      if (left <= 0) {
        error = "Ghidra decompilation timed out";
        break;
      }
      pollfd ready[] = {
          {socket, static_cast<short>(writing ? POLLOUT : POLLIN), 0},
          {diagnostics, POLLIN, 0},
          {cancellation, POLLIN, 0}};
      const int available = poll(ready, 3, static_cast<int>(left));
      if (available < 0 && errno == EINTR)
        continue;
      if (available < 0) {
        error = "decompiler worker connection failed";
        break;
      }
      if (!available)
        continue;
      if (ready[2].revents) {
        error = "decompiler producer control closed or request cancelled";
        break;
      }
      if (ready[1].revents && !read_diagnostics()) {
        error =
            "decompiler diagnostics exceed the size limit or cannot be read";
        break;
      }
      if (!ready[0].revents)
        continue;
      if (writing) {
        const ssize_t count =
            send(socket, encoded.data() + sent, encoded.size() - sent,
                 MSG_NOSIGNAL | MSG_DONTWAIT);
        if (count > 0) {
          sent += static_cast<size_t>(count);
          continue;
        }
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
          continue;
      } else {
        char chunk[8192];
        const ssize_t count = recv(socket, chunk, sizeof(chunk), MSG_DONTWAIT);
        if (count > 0) {
          if (static_cast<size_t>(count) > response_limit - pending.size()) {
            error = "decompiler response exceeds the size limit";
            break;
          }
          pending.append(chunk, static_cast<size_t>(count));
          continue;
        }
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
          continue;
      }
      error = "decompiler worker exited before returning a result";
      break;
    }
    failed = true;
    stop();
    if (!diagnostic_text.empty()) {
      while (!diagnostic_text.empty() && diagnostic_text.back() == '\n')
        diagnostic_text.pop_back();
      error += ": " + diagnostic_text;
      diagnostic_text.clear();
    }
    return false;
  }
};

static DecompileWorker worker;

int ct_decompile_worker_event_fd() { return worker.event_fd(); }
void ct_decompile_service_worker() { worker.service(); }

struct ct_decompile_module {
  using Function = ct_decompile_record;
  std::string path, error, analysis_identity, artifact_identity;
  uint64_t link_base = 0, next_id = 0;
  int module_fd = -1;
  bool unavailable = false, producer = false, retry = false;
  bool initialization_failed = false;
  ct_shared_channel *channel = nullptr;
  int provider = -1;
  struct SharedFunction {
    ct_decompile_view view;
    ct_shared_key common{};
    uint64_t common_id = 0, full_id = 0;
    uint64_t catalog_sequence = 0;
  };
  std::vector<std::unique_ptr<SharedFunction>> shared;
  std::vector<Function> functions;
  std::set<std::pair<uint64_t, uint32_t>> failed_offsets;

  ~ct_decompile_module() {
    if (provider >= 0)
      close(provider);
    for (auto &function : shared) {
      if (function->common_id)
        ct_shared_release(channel, function->common_id);
      if (function->full_id)
        ct_shared_release(channel, function->full_id);
    }
    shared.clear();
    if (channel)
      ct_shared_close(channel);
    if (module_fd >= 0)
      close(module_fd);
  }
};

static ct_decompile_view *shared_function(ct_decompile_module &module,
                                          uint64_t offset, uint32_t level) {
  if (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL)
    return nullptr;
  ct_decompile_module::SharedFunction *previous = nullptr;
  for (auto &function : module.shared)
    if (function->view.contains(offset)) {
      if (function->view.level() == CT_DECOMPILE_FULL)
        return &function->view;
      if (function->view.level() >= level) {
        uint64_t sequence = 0;
        if (!ct_shared_poll(module.channel, 0, &sequence)) {
          module.error = "cannot check shared decompile updates";
          return nullptr;
        }
        if (sequence == function->catalog_sequence)
          return &function->view;
        // A busy producer must not stall an already usable lower view.
        // Inspect only published supplements; their common-content digest
        // proves whether they belong to this exact view.
        ct_shared_scan_page page{};
        bool scanned = false;
        do {
          if (!ct_shared_scan(module.channel, CT_SHARED_DECOMPILE,
                              page.upper_bound, page.cursor, &page))
            break;
          for (uint32_t index = 0; index < page.count; ++index) {
            const auto &descriptor = page.entries[index];
            if (descriptor.key.kind != CT_SHARED_DECOMPILE ||
                descriptor.key.schema != ct_decompile_view_schema ||
                descriptor.key.level != CT_DECOMPILE_FULL ||
                descriptor.key.reserved)
              continue;
            ct_shared_result result{};
            result.fd = -1;
            if (ct_shared_acquire(module.channel, &descriptor.key, &result)) {
              if (result.status == CT_SHARED_READY) {
                std::string error;
                if (function->view.map_full(
                        result.fd, result.object.payload_offset,
                        result.object.payload_size, error)) {
                  function->full_id = result.object.object_id;
                } else {
                  ct_shared_release(module.channel, result.object.object_id);
                }
              } else if (result.status == CT_SHARED_CREATE) {
                ct_shared_fail(module.channel, result.token);
              } else if (result.status == CT_SHARED_WAIT) {
                ct_shared_cancel_wait(module.channel, result.token);
              }
            }
            ct_shared_result_close(&result);
            if (function->full_id)
              break;
          }
          scanned = !page.more;
        } while (page.more && !function->full_id);
        // Do not acknowledge publications racing this bounded scan. Their
        // newer sequence must trigger another probe on the next lower query.
        if (scanned || function->full_id)
          function->catalog_sequence = sequence;
        return &function->view;
      }
      previous = function.get();
      break;
    }
  if (!module.channel)
    module.channel = ct_shared_open();
  if (!module.channel) {
    module.error = "cannot open shared decompile catalog";
    return nullptr;
  }
  if (module.module_fd < 0) {
    // Standalone callers may not already have a module descriptor. Broker
    // analysis workers receive one from the traced address space instead.
    module.module_fd = open(module.path.c_str(), O_RDONLY | O_CLOEXEC);
    if (module.module_fd < 0) {
      module.error = "cannot open shared decompile module";
      return nullptr;
    }
  }
  for (unsigned retry = 0; retry < 2; ++retry) {
    // Acquire replies can observe newer publications than the provider's key
    // reply. Keep the sequence from before that reply so a racing upgrade is
    // checked again instead of being mistaken for an already consumed update.
    const uint64_t sequence = ct_shared_sequence(module.channel);
    ct_shared_key common{}, full{};
    if (!ct_decompile_provider_request(module.provider, module.path.c_str(),
                                       module.module_fd, module.link_base,
                                       module.analysis_identity, offset, level,
                                       common, full, module.error))
      return nullptr;
    if (common.kind != CT_SHARED_DECOMPILE ||
        common.schema != ct_decompile_view_schema ||
        common.level != CT_DECOMPILE_PERFETTO || common.reserved ||
        (full.kind && (full.kind != CT_SHARED_DECOMPILE ||
                       full.schema != ct_decompile_view_schema ||
                       full.level != CT_DECOMPILE_FULL || full.reserved)) ||
        (level == CT_DECOMPILE_FULL && !full.kind)) {
      module.error = "shared decompiler returned invalid object identities";
      return nullptr;
    }
    ct_shared_result display{}, extra{};
    display.fd = extra.fd = -1;
    const bool reuse =
        previous && !std::memcmp(&previous->common, &common, sizeof(common));
    bool ready =
        reuse || (ct_shared_acquire(module.channel, &common, &display) &&
                  display.status == CT_SHARED_READY);
    if (ready && full.kind)
      ready = ct_shared_acquire(module.channel, &full, &extra) &&
              extra.status == CT_SHARED_READY;
    auto replacement = std::make_unique<ct_decompile_module::SharedFunction>();
    auto *target = reuse ? previous : replacement.get();
    if (ready && !reuse)
      ready =
          target->view.map_common(display.fd, display.object.payload_offset,
                                  display.object.payload_size, module.error);
    if (ready && full.kind)
      ready = target->view.map_full(extra.fd, extra.object.payload_offset,
                                    extra.object.payload_size, module.error);
    if (ready &&
        (!target->view.contains(offset) || target->view.level() < level)) {
      module.error = "shared decompiler view does not contain the request";
      ready = false;
    }
    if (ready) {
      target->catalog_sequence = sequence;
      if (!reuse) {
        target->common = common;
        target->common_id = display.object.object_id;
      }
      if (full.kind) {
        if (target->full_id)
          ct_shared_release(module.channel, target->full_id);
        target->full_id = extra.object.object_id;
      }
      if (!reuse) {
        if (previous) {
          ct_shared_release(module.channel, previous->common_id);
          if (previous->full_id)
            ct_shared_release(module.channel, previous->full_id);
          for (auto &function : module.shared)
            if (function.get() == previous) {
              function = std::move(replacement);
              break;
            }
        } else
          module.shared.push_back(std::move(replacement));
      }
      ct_shared_result_close(&display);
      ct_shared_result_close(&extra);
      module.error.clear();
      return &target->view;
    }
    for (auto *result : {&display, &extra}) {
      if (result->status == CT_SHARED_READY)
        ct_shared_release(module.channel, result->object.object_id);
      else if (result->status == CT_SHARED_CREATE)
        ct_shared_fail(module.channel, result->token);
      else if (result->status == CT_SHARED_WAIT)
        ct_shared_cancel_wait(module.channel, result->token);
      ct_shared_result_close(result);
    }
    // Publication pins may have disappeared with a dead producer between the
    // reply and acquire. Reconnect and regenerate or acquire the surviving
    // identical object; never consume an unpublished partial payload.
    if (module.provider >= 0)
      close(module.provider);
    module.provider = -1;
  }
  if (module.error.empty())
    module.error = "shared decompile publication could not be acquired";
  return nullptr;
}

static bool json_address(const llvm::json::Object &object, const char *key,
                         uint64_t &address) {
  const auto text = object.getString(key);
  if (!text || !text->starts_with("0x") || text->size() <= 2)
    return false;
  const char *begin = text->data() + 2, *end = text->end();
  const auto parsed = std::from_chars(begin, end, address, 16);
  return parsed.ec == std::errc{} && parsed.ptr == end;
}

static bool
json_instruction(const llvm::json::Value &value, uint64_t link_base,
                 const std::vector<std::pair<uint64_t, uint64_t>> &membership,
                 ct_decompiled_instruction &output) {
  const auto *instruction = value.getAsObject();
  uint64_t pc = 0;
  const auto bytes =
      instruction ? instruction->getString("bytes") : std::nullopt;
  if (!instruction || !json_address(*instruction, "address", pc) ||
      pc < link_base || !bytes || bytes->empty() || bytes->size() > 30 ||
      bytes->size() % 2)
    return false;
  output.offset = pc - link_base;
  output.size = static_cast<uint8_t>(bytes->size() / 2);
  if (std::none_of(membership.begin(), membership.end(),
                   [&](const auto &range) {
                     return pc >= range.first && pc < range.second &&
                            output.size <= range.second - pc;
                   }))
    return false;
  for (size_t index = 0; index < output.size; ++index) {
    unsigned byte = 0;
    const char *start = bytes->data() + 2 * index;
    const auto result = std::from_chars(start, start + 2, byte, 16);
    if (result.ec != std::errc{} || result.ptr != start + 2)
      return false;
    output.bytes[index] = static_cast<uint8_t>(byte);
  }
  return true;
}

static void parse_value_layouts(const llvm::json::Object &object,
                                ct_decompile_module::Function &function) {
  const auto *types = object.getArray("types");
  if (!types || types->size() > CT_DECOMPILED_TYPE_LIMIT)
    return;
  function.types.resize(types->size());
  bool valid = true;
  for (size_t index = 0; index < types->size() && valid; ++index) {
    const auto *item = (*types)[index].getAsObject();
    if (!item) {
      valid = false;
      break;
    }
    auto &node = function.types[index];
    const auto size = item->getInteger("size");
    const auto kind = item->getString("kind");
    if (!size || *size <= 0 || static_cast<uint64_t>(*size) > SIZE_MAX ||
        !kind) {
      valid = false;
      break;
    }
    node.bytes = static_cast<size_t>(*size);
    node.scalar.bytes = node.bytes;
    node.complete = item->getBoolean("complete").value_or(false);
    node.guarded = item->getBoolean("guarded").value_or(false);
    const auto scalar = item->getString("value_kind");
    if (scalar == "signed")
      node.scalar.kind = CT_VALUE_SIGNED;
    else if (scalar == "unsigned")
      node.scalar.kind = CT_VALUE_UNSIGNED;
    else if (scalar == "boolean")
      node.scalar.kind = CT_VALUE_BOOLEAN;
    else if (scalar == "float")
      node.scalar.kind = CT_VALUE_FLOAT;
    else if (scalar == "pointer")
      node.scalar.kind = CT_VALUE_POINTER;
    if (*kind == "scalar") {
      node.kind = CT_LAYOUT_SCALAR;
      if ((node.scalar.kind == CT_VALUE_FLOAT && node.bytes != 4 &&
           node.bytes != 8) ||
          (node.scalar.kind != CT_VALUE_FLOAT && node.bytes != 1 &&
           node.bytes != 2 && node.bytes != 4 && node.bytes != 8))
        node.kind = CT_LAYOUT_UNKNOWN;
    } else if (*kind == "pointer" || *kind == "array") {
      const auto element = item->getInteger("element_type");
      if (!element || *element < 0 ||
          static_cast<uint64_t>(*element) > types->size()) {
        valid = false;
        break;
      }
      node.element_type = static_cast<uint32_t>(*element);
      if (*kind == "pointer") {
        node.kind = node.bytes == 8 ? CT_LAYOUT_POINTER : CT_LAYOUT_UNKNOWN;
        node.scalar.kind = CT_VALUE_POINTER;
      } else {
        const auto count = item->getInteger("element_count");
        const auto stride = item->getInteger("element_stride");
        if (!count || *count < 0 || !stride || *stride <= 0 ||
            static_cast<uint64_t>(*count) > SIZE_MAX ||
            static_cast<uint64_t>(*stride) > SIZE_MAX ||
            static_cast<uint64_t>(*count) >
                node.bytes / static_cast<uint64_t>(*stride)) {
          valid = false;
          break;
        }
        node.kind = CT_LAYOUT_ARRAY;
        node.element_count = static_cast<size_t>(*count);
        node.element_stride = static_cast<size_t>(*stride);
      }
    } else if (*kind == "struct") {
      const auto *members = item->getArray("members");
      if (!members || members->size() > CT_DECOMPILED_MEMBER_LIMIT -
                                            function.members.size()) {
        valid = false;
        break;
      }
      node.kind = CT_LAYOUT_STRUCT;
      node.first_member = static_cast<uint32_t>(function.members.size());
      node.member_count = members->size();
      for (const auto &value : *members) {
        const auto *member = value.getAsObject();
        if (!member) {
          valid = false;
          break;
        }
        ct_value_layout_member entry{};
        const auto name = member->getString("name");
        const auto offset = member->getInteger("offset");
        const auto type = member->getInteger("type");
        if (!name || name->empty() || name->size() >= sizeof(entry.name) ||
            !offset || *offset < 0 ||
            static_cast<uint64_t>(*offset) > node.bytes || !type || *type < 0 ||
            static_cast<uint64_t>(*type) > types->size() ||
            std::any_of(name->begin(), name->end(), [](unsigned char value) {
              return value < ' ' || value == 127;
            })) {
          valid = false;
          break;
        }
        std::memcpy(entry.name, name->data(), name->size());
        entry.offset = static_cast<size_t>(*offset);
        entry.type = static_cast<uint32_t>(*type);
        entry.available =
            entry.type && member->getBoolean("available").value_or(false);
        function.members.push_back(entry);
      }
    } else if (*kind != "unknown") {
      valid = false;
    }
  }
  if (!valid) {
    function.types.clear();
    function.members.clear();
    return;
  }
  // Check references only after every node is loaded; children may precede or
  // follow their parents, and pointer-linked recursive types are legitimate.
  for (auto &node : function.types) {
    if (node.kind == CT_LAYOUT_ARRAY && node.element_type &&
        function.types[node.element_type - 1].bytes > node.element_stride) {
      node.element_type = 0;
      node.complete = false;
    }
    if (node.kind != CT_LAYOUT_STRUCT)
      continue;
    for (size_t index = 0; index < node.member_count; ++index) {
      auto &member = function.members[node.first_member + index];
      if (member.type &&
          function.types[member.type - 1].bytes > node.bytes - member.offset)
        member.available = false;
    }
  }
}

ct_decompile_module *ct_decompile_open(const char *path, uint64_t link_base,
                                       const char *analysis_identity,
                                       int module_fd) {
  if (!path || !path[0])
    return nullptr;
  auto module = std::make_unique<ct_decompile_module>();
  module->path = path;
  module->link_base = link_base;
  module->analysis_identity = analysis_identity ? analysis_identity : "";
  if (module_fd >= 0) {
    module->module_fd = fcntl(module_fd, F_DUPFD_CLOEXEC, 3);
    if (module->module_fd < 0)
      return nullptr;
  }
  return module.release();
}

void ct_decompile_close(ct_decompile_module *module) { delete module; }

const char *ct_decompile_error(const ct_decompile_module *module) {
  return module ? module->error.c_str() : "";
}

const char *ct_decompile_producer_identity(ct_decompile_module *module) {
  if (!module)
    return "";
  module->producer = true;
  if (!module->artifact_identity.empty())
    return module->artifact_identity.c_str();
  char base[32];
  std::snprintf(base, sizeof(base), "0x%llx",
                static_cast<unsigned long long>(module->link_base));
  const std::string file = module->module_fd < 0
                               ? module->path
                               : "/proc/" + std::to_string(getpid()) + "/fd/" +
                                     std::to_string(module->module_fd);
  std::string response;
  if (!worker.exchange(
          llvm::json::Object{{"command", "identity"},
                             {"module", module->path},
                             {"module_file", file},
                             {"link_base", base},
                             {"address", base},
                             {"analysis_identity", module->analysis_identity}},
          response)) {
    module->error = worker.error;
    return "";
  }
  auto parsed = llvm::json::parse(response);
  if (!parsed) {
    llvm::consumeError(parsed.takeError());
    module->error = "decompiler returned an invalid content identity";
    return "";
  }
  const auto *object = parsed->getAsObject();
  const auto identity = object ? object->getString("identity") : std::nullopt;
  if (!object || object->getInteger("version") != 1 ||
      !object->getBoolean("ok").value_or(false) || !identity ||
      identity->size() != 64 ||
      identity->find_first_not_of("0123456789abcdef") !=
          llvm::StringRef::npos) {
    module->error = "decompiler returned no valid content identity";
    if (object)
      if (const auto detail = object->getString("error"))
        module->error += ": " + detail->str();
    return "";
  }
  module->artifact_identity = identity->str();
  return module->artifact_identity.c_str();
}

bool ct_decompile_producer_manifest(ct_decompile_module *module,
                                    std::string &manifest, std::string &error) {
  manifest.clear();
  error.clear();
  if (!module || !*ct_decompile_producer_identity(module)) {
    error = module ? module->error : "no decompile producer module";
    return false;
  }
  const std::string base = llvm::formatv("0x{0:x-}", module->link_base).str();
  const std::string file = module->module_fd < 0
                               ? module->path
                               : "/proc/" + std::to_string(getpid()) + "/fd/" +
                                     std::to_string(module->module_fd);
  if (!worker.exchange(
          llvm::json::Object{{"command", "image_manifest"},
                             {"module", module->path},
                             {"module_file", file},
                             {"link_base", base},
                             {"address", base},
                             {"analysis_identity", module->analysis_identity}},
          manifest)) {
    error = worker.error;
    return false;
  }
  auto parsed = llvm::json::parse(manifest);
  if (!parsed) {
    llvm::consumeError(parsed.takeError());
    error = "decompiler returned an invalid image manifest";
    return false;
  }
  const auto *object = parsed->getAsObject();
  if (!object || object->getInteger("version") != 1 ||
      object->getInteger("manifest_version") != 1 ||
      !object->getBoolean("ok").value_or(false) ||
      object->getString("identity") != module->artifact_identity) {
    error = "decompiler returned no valid image manifest";
    if (object)
      if (const auto detail = object->getString("error"))
        error += ": " + detail->str();
    return false;
  }
  return true;
}

void ct_decompile_producer_shutdown() { worker.finish(); }
void ct_decompile_producer_cancel_fd(int descriptor) {
  worker.cancel_with(descriptor);
}

bool ct_decompile_lookup(ct_decompile_module *module, uint64_t offset,
                         uint32_t level, ct_decompiled_statement *statement) {
  if (!statement)
    return false;
  *statement = {};
  if (!module || offset > UINT64_MAX - module->link_base ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  if (!module->producer && ct_shared_host_available()) {
    const auto *view = shared_function(*module, offset, level);
    return view && view->statement(offset, *statement);
  }
  for (const auto &function : module->functions) {
    if (offset < function.begin || offset >= function.end)
      continue;
    if (std::none_of(function.ranges.begin(), function.ranges.end(),
                     [&](const auto &range) {
                       return offset >= range.first && offset < range.second;
                     }))
      continue;
    if (function.level < level)
      break;
    const auto found = function.instructions.find(offset);
    if (found == function.instructions.end())
      return false;
    *statement = function.statements[found->second.first];
    statement->instruction_index = found->second.second;
    return true;
  }
  if (module->initialization_failed || module->unavailable ||
      module->failed_offsets.count({offset, level}))
    return false;
  module->failed_offsets.insert({offset, level});
  char address[32], base[32];
  std::snprintf(address, sizeof(address), "0x%llx",
                static_cast<unsigned long long>(offset + module->link_base));
  std::snprintf(base, sizeof(base), "0x%llx",
                static_cast<unsigned long long>(module->link_base));
  std::string response;
  const std::string module_file =
      module->module_fd < 0 ? module->path
                            : "/proc/" + std::to_string(getpid()) + "/fd/" +
                                  std::to_string(module->module_fd);
  if (!worker.exchange(
          llvm::json::Object{
              {"module", module->path},
              {"module_file", module_file},
              {"address", address},
              {"link_base", base},
              {"analysis_identity", module->analysis_identity},
              {"shared_export", module->producer},
              {"level", level == CT_DECOMPILE_FULL ? "full" : "perfetto"}},
          response)) {
    module->error = worker.error;
    module->unavailable = true;
    return false;
  }
  auto parsed = llvm::json::parse(response);
  if (!parsed) {
    llvm::consumeError(parsed.takeError());
    module->error = "decompiler returned invalid JSON";
    module->unavailable = true;
    return false;
  }
  const auto *object = parsed->getAsObject();
  if (!object || object->getInteger("version") != 1 ||
      !object->getBoolean("ok").has_value()) {
    module->error = "decompiler returned an invalid protocol response";
    module->unavailable = true;
    return false;
  }
  if (!*object->getBoolean("ok")) {
    if (const auto *scope = object->get("scope")) {
      const auto name = scope->getAsString();
      if (!name || *name != "module") {
        module->error = "decompiler returned an invalid failure scope";
        module->unavailable = true;
        return false;
      }
      // This parser belongs to one content/analysis identity. A different
      // offset or observation level cannot repair a failed module import.
      module->initialization_failed = true;
    }
    const auto detail = object->getString("error");
    module->error = detail ? detail->str() : "decompilation failed";
    for (char &character : module->error)
      if (static_cast<unsigned char>(character) < ' ' || character == 127)
        character = ' ';
    module->retry = !module->initialization_failed &&
                    object->getBoolean("transient").value_or(false);
    if (module->retry)
      module->failed_offsets.erase({offset, level});
    return false;
  }
  if (const auto identity = object->getString("identity");
      identity && identity->size() == 64 &&
      identity->find_first_not_of("0123456789abcdef") == llvm::StringRef::npos)
    if (!module->artifact_identity.empty() &&
        module->artifact_identity != *identity) {
      module->error = "decompiler content identity changed during analysis";
      return false;
    } else
      module->artifact_identity = identity->str();
  else if (module->producer) {
    module->error = "decompiler returned no content identity";
    return false;
  }
  uint64_t begin = 0, end = 0;
  const auto *lines = object->getArray("lines");
  const auto *ranges = object->getArray("ranges");
  if (!json_address(*object, "entry", begin) ||
      !json_address(*object, "end", end) || begin < module->link_base ||
      end <= begin || !lines || lines->size() > line_limit || !ranges ||
      ranges->empty() || ranges->size() > line_limit) {
    module->error = "decompiler returned an invalid function mapping";
    module->unavailable = true;
    return false;
  }
  std::vector<std::pair<uint64_t, uint64_t>> membership;
  bool contains_entry = false, contains_request = false;
  for (const auto &range : *ranges) {
    const auto *item = range.getAsObject();
    uint64_t start = 0, stop = 0;
    if (!item || !json_address(*item, "start", start) ||
        !json_address(*item, "end", stop) || start < module->link_base ||
        stop <= start || stop > end) {
      module->error = "decompiler returned invalid function address ranges";
      module->unavailable = true;
      return false;
    }
    contains_entry |= begin >= start && begin < stop;
    contains_request |= offset + module->link_base >= start &&
                        offset + module->link_base < stop;
    membership.emplace_back(start, stop);
  }
  if (!contains_entry || !contains_request) {
    module->error =
        "decompiler function does not contain the requested address";
    module->unavailable = true;
    return false;
  }
  std::sort(membership.begin(), membership.end());
  ct_decompile_module::Function function{};
  function.identity = module->artifact_identity;
  const auto returned_level = object->getString("level");
  function.level = returned_level == "full"       ? CT_DECOMPILE_FULL
                   : returned_level == "perfetto" ? CT_DECOMPILE_PERFETTO
                                                  : 0;
  if (function.level < level) {
    module->error = "decompiler returned an incomplete information level";
    return false;
  }
  if (const auto name = object->getString("name");
      name && name->size() < sizeof(ct_decompiled_display::function_name) &&
      std::none_of(name->begin(), name->end(),
                   [](unsigned char ch) { return ch < ' ' || ch == 127; }))
    function.name = name->str();
  function.begin = membership.front().first - module->link_base;
  function.end = end - module->link_base;
  function.entry = begin - module->link_base;
  if (const auto *result = object->getObject("return"))
    function.return_unsupported =
        result->getBoolean("unsupported").value_or(false);
  if (const auto *result = object->getObject("return");
      result && result->getBoolean("known").value_or(false)) {
    const bool is_void = result->getBoolean("void").value_or(false);
    const auto name = result->getString("type");
    const auto size = result->getInteger("size");
    const auto reg = result->getString("register");
    const auto kind = result->getString("value_kind");
    ct_value_type type{};
    if (kind == "signed")
      type.kind = CT_VALUE_SIGNED;
    else if (kind == "unsigned")
      type.kind = CT_VALUE_UNSIGNED;
    else if (kind == "float")
      type.kind = CT_VALUE_FLOAT;
    else if (kind == "boolean")
      type.kind = CT_VALUE_BOOLEAN;
    else if (kind == "pointer")
      type.kind = CT_VALUE_POINTER;
    bool valid = name && !name->empty() &&
                 name->size() < sizeof(function.return_type_name);
    if (name)
      for (unsigned char character : *name)
        valid &= character >= ' ' && character != 127;
    if (is_void) {
      valid &= name == "void";
    } else {
      valid &=
          size && reg && (type.kind != CT_VALUE_UNKNOWN || kind == "unknown");
      if (size && reg) {
        type.bytes = static_cast<size_t>(*size);
        if (type.kind == CT_VALUE_FLOAT)
          valid &= (*size == 4 || *size == 8) && *reg == "xmm0";
        else {
          valid &=
              (*size == 1 && *reg == "al") || (*size == 2 && *reg == "ax") ||
              (*size == 4 && *reg == "eax") || (*size == 8 && *reg == "rax");
          if (type.kind == CT_VALUE_POINTER)
            valid &= *size == 8;
        }
      }
    }
    if (valid) {
      function.return_known = true;
      function.return_unsupported = false;
      function.return_void = is_void;
      function.return_type = type;
      std::memcpy(function.return_type_name, name->data(), name->size());
      if (!is_void)
        std::memcpy(function.return_register, reg->data(), reg->size());
    }
  }
  if (object->getBoolean("parameters_known").value_or(false)) {
    const auto *parameters = object->getArray("parameters");
    bool valid =
        parameters && parameters->size() <= CT_DECOMPILED_PARAMETER_LIMIT;
    std::set<std::string> names, registers;
    std::vector<std::pair<int64_t, int64_t>> stack_ranges;
    if (valid) {
      for (const auto &value : *parameters) {
        const auto *item = value.getAsObject();
        if (!item) {
          valid = false;
          break;
        }
        ct_decompiled_parameter parameter{};
        const auto name = item->getString("name");
        const auto spelling = item->getString("type");
        const auto kind = item->getString("kind");
        const auto value_kind = item->getString("value_kind");
        const auto size = item->getInteger("size");
        valid = name && !name->empty() &&
                name->size() < sizeof(parameter.name) && kind && size &&
                (*size == 1 || *size == 2 || *size == 4 || *size == 8) &&
                spelling && !spelling->empty() &&
                spelling->size() < sizeof(parameter.type_name);
        if (!valid)
          break;
        for (size_t index = 0; index < name->size(); ++index) {
          const unsigned char character = (*name)[index];
          valid &= (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') || character == '_' ||
                   (index && character >= '0' && character <= '9');
        }
        // Scalar declarators are emitted as "type name" by the client.
        // Complex pointer declarators retain their address without pretending
        // that appending a name produces a valid function-pointer declaration.
        bool complex_declarator = false;
        for (const unsigned char character : *spelling)
          if (character == '(' || character == ')' || character == '[' ||
              character == ']')
            complex_declarator = true;
          else
            valid &= character >= ' ' && character != 127 && character != ';' &&
                     character != '{' && character != '}';
        valid &= names.insert(name->str()).second;
        if (!valid)
          break;
        parameter.size = static_cast<uint32_t>(*size);
        parameter.type.bytes = parameter.size;
        if (value_kind == "signed")
          parameter.type.kind = CT_VALUE_SIGNED;
        else if (value_kind == "unsigned")
          parameter.type.kind = CT_VALUE_UNSIGNED;
        else if (value_kind == "float")
          parameter.type.kind = CT_VALUE_FLOAT;
        else if (value_kind == "boolean")
          parameter.type.kind = CT_VALUE_BOOLEAN;
        else if (value_kind == "pointer")
          parameter.type.kind = CT_VALUE_POINTER;
        else if (value_kind != "unknown")
          valid = false;
        if (parameter.type.kind == CT_VALUE_POINTER)
          valid &= parameter.size == 8;
        if (parameter.type.kind == CT_VALUE_FLOAT)
          valid &= parameter.size == 4 || parameter.size == 8;
        if (complex_declarator)
          valid &= parameter.type.kind == CT_VALUE_POINTER;
        if (!valid)
          break;
        std::memcpy(parameter.name, name->data(), name->size());
        if (parameter.type.kind == CT_VALUE_UNKNOWN) {
          // An inferred register width is evidence of bits, not signedness.
          std::snprintf(parameter.type_name, sizeof(parameter.type_name),
                        "uint%u_t", parameter.size * 8);
        } else if (complex_declarator) {
          std::strcpy(parameter.type_name, "uintptr_t");
        } else {
          std::memcpy(parameter.type_name, spelling->data(), spelling->size());
        }
        if (*kind == "stack") {
          const auto location = item->getInteger("offset");
          valid = location && *location >= 8 &&
                  *location <= INT64_MAX - parameter.size;
          if (!valid)
            break;
          parameter.kind = CT_DECOMPILED_STACK;
          parameter.stack_offset = *location;
          const int64_t stop = *location + parameter.size;
          for (const auto &[start, end] : stack_ranges)
            valid &= stop <= start || *location >= end;
          stack_ranges.emplace_back(*location, stop);
        } else if (*kind == "register") {
          const auto reg = item->getString("register");
          valid = reg && !reg->empty() &&
                  reg->size() < sizeof(parameter.register_name);
          if (!valid)
            break;
          std::string normalized = reg->str();
          for (char &character : normalized)
            if (character >= 'A' && character <= 'Z')
              character += 'a' - 'A';
          // The backend currently targets the x86-64 SysV scalar ABI only.
          static constexpr const char *general[][4] = {
              {"dil", "di", "edi", "rdi"}, {"sil", "si", "esi", "rsi"},
              {"dl", "dx", "edx", "rdx"},  {"cl", "cx", "ecx", "rcx"},
              {"r8b", "r8w", "r8d", "r8"}, {"r9b", "r9w", "r9d", "r9"}};
          std::string storage;
          if (parameter.type.kind == CT_VALUE_FLOAT) {
            if (normalized.size() == 4 &&
                normalized.compare(0, 3, "xmm") == 0 && normalized[3] >= '0' &&
                normalized[3] <= '7')
              storage = normalized;
          } else {
            for (const auto &family : general)
              for (size_t width = 0; width < 4; ++width)
                if (normalized == family[width] &&
                    parameter.size <= (1u << width))
                  storage = family[3];
          }
          valid = !storage.empty() && registers.insert(storage).second;
          if (!valid)
            break;
          parameter.kind = CT_DECOMPILED_REGISTER;
          std::memcpy(parameter.register_name, normalized.data(),
                      normalized.size());
        } else {
          valid = false;
        }
        if (!valid)
          break;
        function.parameters.push_back(parameter);
      }
    }
    if (valid) {
      function.parameters_known = true;
      function.variadic = object->getBoolean("variadic").value_or(false);
    } else {
      function.parameters.clear();
    }
  }
  for (const auto &range : membership)
    function.ranges.emplace_back(range.first - module->link_base,
                                 range.second - module->link_base);
  if (const auto *instructions = object->getArray("instructions");
      instructions && instructions->size() <= line_limit) {
    bool valid = true;
    for (const auto &value : *instructions) {
      ct_decompiled_instruction instruction{};
      if (!json_instruction(value, module->link_base, membership,
                            instruction) ||
          !function.original_instructions
               .emplace(instruction.offset, instruction)
               .second) {
        valid = false;
        break;
      }
    }
    uint64_t previous_end = 0;
    for (const auto &[pc, instruction] : function.original_instructions) {
      if (pc < previous_end)
        valid = false;
      previous_end = pc + instruction.size;
    }
    if (!valid)
      function.original_instructions.clear();
  }
  function.prototype = function.return_known ? function.return_type_name : "?";
  function.prototype += " " + function.name + "(";
  for (size_t index = 0; index < function.parameters.size(); ++index) {
    if (index)
      function.prototype += ", ";
    function.prototype += std::string(function.parameters[index].type_name) +
                          " " + function.parameters[index].name;
  }
  if (function.variadic)
    function.prototype += function.parameters.empty() ? "..." : ", ...";
  else if (function.parameters_known && function.parameters.empty())
    function.prototype += "void";
  function.prototype += ")";
  if (function.prototype.size() >= sizeof(ct_decompiled_display::prototype))
    function.prototype.clear();
  if (const auto *controls = object->getArray("controls");
      controls && controls->size() <= line_limit) {
    for (const auto &value : *controls) {
      const auto *control = value.getAsObject();
      if (!control)
        continue;
      const auto text = control->getString("text");
      const auto *instruction = control->get("instruction");
      ct_decompiled_display display{};
      if (!text || text->empty() ||
          text->size() >= sizeof(display.control_text) ||
          std::any_of(text->begin(), text->end(),
                      [](unsigned char ch) { return ch < ' ' || ch == 127; }) ||
          !instruction ||
          !json_instruction(*instruction, module->link_base, membership,
                            display.instruction))
        continue;
      std::memcpy(display.control_text, text->data(), text->size());
      for (const auto &[key, destination, capacity] :
           {std::tuple{"kind", display.control_kind,
                       sizeof(display.control_kind)},
            std::tuple{"initializer", display.control_initializer,
                       sizeof(display.control_initializer)},
            std::tuple{"update", display.control_update,
                       sizeof(display.control_update)}}) {
        const auto value = control->getString(key);
        if (value && value->size() < capacity &&
            std::none_of(value->begin(), value->end(), [](unsigned char ch) {
              return ch < ' ' || ch == 127;
            }))
          std::memcpy(destination, value->data(), value->size());
      }
      display.control_conditional =
          control->getBoolean("conditional").value_or(false);
      uint64_t target;
      if (json_address(*control, "target", target) &&
          target >= module->link_base) {
        display.control_has_target = true;
        display.control_target = target - module->link_base;
      }
      function.controls.emplace(display.instruction.offset, display);
    }
  }
  if (function.level == CT_DECOMPILE_FULL)
    parse_value_layouts(*object, function);
  if (const auto *variables = object->getArray("variables");
      variables && variables->size() <= line_limit) {
    for (const auto &value : *variables) {
      const auto *item = value.getAsObject();
      if (!item)
        continue;
      ct_decompiled_variable variable{};
      const auto name = item->getString("name");
      const auto type = item->getString("type");
      const auto kind = item->getString("kind");
      const auto size = item->getInteger("size");
      const auto register_alias = item->getBoolean("register_alias");
      if (!json_address(*item, "id", variable.id) || !variable.id || !name ||
          name->empty() || name->size() >= sizeof(variable.name) || !kind ||
          !size || *size <= 0 || *size > UINT32_MAX ||
          (item->get("register_alias") && !register_alias) ||
          (type && type->size() >= sizeof(variable.type_name)))
        continue;
      bool valid = true;
      for (size_t index = 0; index < name->size(); ++index) {
        const unsigned char character = (*name)[index];
        valid &= (character >= 'a' && character <= 'z') ||
                 (character >= 'A' && character <= 'Z') || character == '_' ||
                 (index && character >= '0' && character <= '9');
      }
      if (type)
        for (const unsigned char character : *type)
          valid &= character >= ' ' && character != 127;
      if (!valid)
        continue;
      std::memcpy(variable.name, name->data(), name->size());
      if (type)
        std::memcpy(variable.type_name, type->data(), type->size());
      variable.size = static_cast<uint32_t>(*size);
      variable.type.bytes = variable.size;
      const auto type_id = item->getInteger("type_id");
      if (type_id && *type_id > 0 &&
          static_cast<uint64_t>(*type_id) <= function.types.size() &&
          function.types[*type_id - 1].bytes == variable.size)
        variable.type_id = static_cast<uint32_t>(*type_id);
      const auto value_kind = item->getString("value_kind");
      if (value_kind == "signed")
        variable.type.kind = CT_VALUE_SIGNED;
      else if (value_kind == "unsigned")
        variable.type.kind = CT_VALUE_UNSIGNED;
      else if (value_kind == "float")
        variable.type.kind = CT_VALUE_FLOAT;
      else if (value_kind == "boolean")
        variable.type.kind = CT_VALUE_BOOLEAN;
      else if (value_kind == "pointer")
        variable.type.kind = CT_VALUE_POINTER;
      if (variable.type.kind != CT_VALUE_UNKNOWN &&
          ((variable.type.kind == CT_VALUE_FLOAT && variable.size != 4 &&
            variable.size != 8) ||
           (variable.type.kind == CT_VALUE_POINTER && variable.size != 8) ||
           (variable.type.kind != CT_VALUE_FLOAT && variable.size != 1 &&
            variable.size != 2 && variable.size != 4 && variable.size != 8)))
        variable.type.kind = CT_VALUE_UNKNOWN;
      variable.access = CT_DECOMPILED_READ | CT_DECOMPILED_WRITE;
      const auto access = item->getString("access");
      if (access == "read")
        variable.access = CT_DECOMPILED_READ;
      else if (access == "write")
        variable.access = CT_DECOMPILED_WRITE;
      else if (access && access != "readwrite")
        continue;
      uint64_t pc = 0;
      const bool scoped = item->get("address") != nullptr;
      if (scoped && (!json_address(*item, "address", pc) ||
                     std::none_of(membership.begin(), membership.end(),
                                  [&](const auto &range) {
                                    return pc >= range.first &&
                                           pc < range.second;
                                  })))
        continue;
      if (*kind == "stack") {
        variable.kind = CT_DECOMPILED_STACK;
        const auto location = item->getInteger("offset");
        if (!location || *location > INT64_MAX - variable.size)
          continue;
        variable.stack_offset = *location;
      } else if (*kind == "global") {
        variable.kind = CT_DECOMPILED_GLOBAL;
        uint64_t location = 0;
        if (!json_address(*item, "offset", location) ||
            location < module->link_base ||
            location > UINT64_MAX - variable.size)
          continue;
        variable.offset = location - module->link_base;
      } else if (*kind == "register") {
        variable.kind = CT_DECOMPILED_REGISTER;
        const auto reg = item->getString("register");
        if (!scoped || !access || !reg || reg->empty() ||
            reg->size() >= sizeof(variable.register_name) || variable.size > 64)
          continue;
        for (size_t index = 0; index < reg->size(); ++index) {
          unsigned char character = (*reg)[index];
          if (character >= 'A' && character <= 'Z')
            character += 'a' - 'A';
          valid &= (character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9');
          variable.register_name[index] = static_cast<char>(character);
        }
        if (!valid)
          continue;
      } else
        continue;
      if (register_alias.value_or(false)) {
        // Renaming an input to a physical register is valid only for the
        // exact scoped read and storage width proven by the backend. Never
        // let an alias mark writes, stack/global storage, or another name.
        if (!scoped || variable.kind != CT_DECOMPILED_REGISTER ||
            variable.access != CT_DECOMPILED_READ ||
            (value_kind != "unknown" && value_kind != "unsigned") ||
            !llvm::StringRef(variable.name)
                 .equals_insensitive(variable.register_name))
          continue;
        static constexpr const char *general[][4] = {
            {"al", "ax", "eax", "rax"},      {"cl", "cx", "ecx", "rcx"},
            {"dl", "dx", "edx", "rdx"},      {"bl", "bx", "ebx", "rbx"},
            {"spl", "sp", "esp", "rsp"},     {"bpl", "bp", "ebp", "rbp"},
            {"sil", "si", "esi", "rsi"},     {"dil", "di", "edi", "rdi"},
            {"r8b", "r8w", "r8d", "r8"},     {"r9b", "r9w", "r9d", "r9"},
            {"r10b", "r10w", "r10d", "r10"}, {"r11b", "r11w", "r11d", "r11"},
            {"r12b", "r12w", "r12d", "r12"}, {"r13b", "r13w", "r13d", "r13"},
            {"r14b", "r14w", "r14d", "r14"}, {"r15b", "r15w", "r15d", "r15"}};
        uint32_t register_size = 0;
        for (const auto &family : general)
          for (size_t width = 0; width < 4; ++width)
            if (std::strcmp(variable.register_name, family[width]) == 0)
              register_size = 1u << width;
        for (const char *high_byte : {"ah", "ch", "dh", "bh"})
          if (std::strcmp(variable.register_name, high_byte) == 0)
            register_size = 1;
        if (register_size != variable.size)
          continue;
        variable.register_alias = true;
        for (char *character = variable.name; *character; ++character)
          if (*character >= 'a' && *character <= 'z')
            *character -= 'a' - 'A';
      }
      auto &destination =
          scoped ? function.scoped_variables[pc - module->link_base]
                 : function.variables;
      destination.push_back(variable);
    }
  }
  std::vector<ct_decompiled_statement> candidates;
  std::map<uint64_t, size_t> uses;
  for (const auto &line : *lines) {
    const auto *item = line.getAsObject();
    if (!item || !item->getBoolean("safe").value_or(false))
      continue;
    const auto text = item->getString("text");
    const auto *instructions = item->getArray("instructions");
    if (!text || text->empty() || text->size() >= sizeof(statement->text) ||
        std::any_of(text->begin(), text->end(),
                    [](unsigned char character) {
                      return character < ' ' || character == 127;
                    }) ||
        !instructions || instructions->empty() ||
        instructions->size() > CT_DECOMPILED_INSTRUCTION_LIMIT)
      continue;
    ct_decompiled_statement candidate{};
    candidate.id = ++module->next_id;
    candidate.function_offset = begin - module->link_base;
    bool valid = true;
    std::string normalized = text->str();
    for (size_t cursor = 0; cursor < normalized.size();) {
      // Labels are exporter-generated tokens. Identical text inside a C
      // string or character literal is program data and must stay unchanged.
      if (normalized[cursor] == '"' || normalized[cursor] == '\'') {
        const char quote = normalized[cursor++];
        while (cursor < normalized.size()) {
          const char character = normalized[cursor++];
          if (character == '\\' && cursor < normalized.size())
            ++cursor;
          else if (character == quote)
            break;
        }
        continue;
      }
      if (normalized.compare(cursor, 2, "@L") != 0) {
        ++cursor;
        continue;
      }
      const size_t finish = normalized.find('@', cursor + 2);
      uint64_t target = 0;
      if (finish == std::string::npos || finish == cursor + 2) {
        valid = false;
        break;
      }
      const char *first = normalized.data() + cursor + 2;
      const char *last = normalized.data() + finish;
      const auto converted = std::from_chars(first, last, target, 16);
      if (converted.ec != std::errc{} || converted.ptr != last ||
          target < module->link_base) {
        valid = false;
        break;
      }
      char label[32];
      std::snprintf(
          label, sizeof(label), "@L%llx@",
          static_cast<unsigned long long>(target - module->link_base));
      normalized.replace(cursor, finish - cursor + 1, label);
      cursor += std::strlen(label);
    }
    if (!valid || normalized.size() >= sizeof(candidate.text))
      continue;
    std::memcpy(candidate.text, normalized.data(), normalized.size());
    if (const auto *declaration = item->getObject("declaration")) {
      uint64_t id = 0;
      const auto name = declaration->getString("name");
      const auto type = declaration->getString("type");
      bool declared = json_address(*declaration, "id", id) && id && name &&
                      !name->empty() &&
                      name->size() < sizeof(candidate.declaration_name) &&
                      type && !type->empty() &&
                      type->size() < sizeof(candidate.declaration_type);
      if (declared) {
        for (size_t index = 0; index < name->size(); ++index) {
          const unsigned char ch = (*name)[index];
          declared &= (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                      ch == '_' || (index && ch >= '0' && ch <= '9');
        }
        for (size_t index = 0; index < type->size(); ++index) {
          const unsigned char ch = (*type)[index];
          declared &=
              (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              ch == '_' ||
              (index && ((ch >= '0' && ch <= '9') || ch == ' ' || ch == '*'));
        }
        declared &= *type != "void";
        const size_t start = normalized.find_first_not_of(' ');
        size_t assignment = start == std::string::npos ? normalized.size()
                                                       : start + name->size();
        declared &= start != std::string::npos &&
                    normalized.compare(start, name->size(), name->str()) == 0;
        while (assignment < normalized.size() && normalized[assignment] == ' ')
          ++assignment;
        declared &= assignment < normalized.size() &&
                    normalized[assignment] == '=' &&
                    assignment + 1 < normalized.size() &&
                    normalized[assignment + 1] != '=';
      }
      // Optional symbol typing must never weaken instruction/storage proof or
      // discard an otherwise valid executable statement when it is malformed.
      if (declared) {
        candidate.declaration_id = id;
        std::memcpy(candidate.declaration_name, name->data(), name->size());
        std::memcpy(candidate.declaration_type, type->data(), type->size());
      }
    }
    for (const auto &entry : *instructions) {
      auto &output = candidate.instructions[candidate.instruction_count++];
      if (!json_instruction(entry, module->link_base, membership, output)) {
        valid = false;
        break;
      }
    }
    if (!valid)
      continue;
    std::sort(candidate.instructions,
              candidate.instructions + candidate.instruction_count,
              [](const auto &left, const auto &right) {
                return left.offset < right.offset;
              });
    for (size_t index = 1; index < candidate.instruction_count; ++index)
      if (candidate.instructions[index - 1].offset +
              candidate.instructions[index - 1].size !=
          candidate.instructions[index].offset)
        valid = false;
    if (!valid)
      continue;
    // Legacy cached responses may spell proven hardware aliases in lowercase.
    // Rename only aliases read by this statement, never recovered C symbols or
    // coincidentally matching words in strings, comments, or member names.
    std::set<std::string> register_aliases;
    for (size_t index = 0; index < candidate.instruction_count; ++index) {
      const auto variables =
          function.scoped_variables.find(candidate.instructions[index].offset);
      if (variables != function.scoped_variables.end())
        for (const auto &variable : variables->second)
          if (variable.register_alias)
            register_aliases.insert(variable.register_name);
    }
    if (!register_aliases.empty()) {
      std::set<std::string> preserved_names;
      for (const auto &parameter : function.parameters)
        preserved_names.insert(parameter.name);
      for (const auto &variable : function.variables)
        preserved_names.insert(variable.name);
      for (const auto &[pc, variables] : function.scoped_variables)
        for (const auto &variable : variables)
          if (!variable.register_alias)
            preserved_names.insert(variable.name);
      for (size_t cursor = 0; cursor < normalized.size();) {
        if (normalized[cursor] == '"' || normalized[cursor] == '\'') {
          const char quote = normalized[cursor++];
          while (cursor < normalized.size()) {
            const char character = normalized[cursor++];
            if (character == '\\' && cursor < normalized.size())
              ++cursor;
            else if (character == quote)
              break;
          }
          continue;
        }
        if (normalized.compare(cursor, 2, "//") == 0)
          break;
        if (normalized.compare(cursor, 2, "/*") == 0) {
          const size_t end = normalized.find("*/", cursor + 2);
          cursor = end == std::string::npos ? normalized.size() : end + 2;
          continue;
        }
        const size_t start = cursor;
        while (cursor < normalized.size() &&
               ((normalized[cursor] >= 'a' && normalized[cursor] <= 'z') ||
                (normalized[cursor] >= 'A' && normalized[cursor] <= 'Z') ||
                (normalized[cursor] >= '0' && normalized[cursor] <= '9') ||
                normalized[cursor] == '_'))
          ++cursor;
        if (cursor == start) {
          ++cursor;
          continue;
        }
        const std::string token = normalized.substr(start, cursor - start);
        const size_t previous =
            start ? normalized.find_last_not_of(' ', start - 1)
                  : std::string::npos;
        const size_t following = normalized.find_first_not_of(' ', cursor);
        size_t qualifier = previous == std::string::npos ? 0 : previous + 1;
        while (qualifier && normalized[qualifier - 1] >= 'a' &&
               normalized[qualifier - 1] <= 'z')
          --qualifier;
        const std::string preceding =
            previous == std::string::npos
                ? std::string()
                : normalized.substr(qualifier, previous + 1 - qualifier);
        if (preserved_names.count(token) ||
            (following != std::string::npos && normalized[following] == '(') ||
            preceding == "struct" || preceding == "union" ||
            preceding == "enum" || preceding == "goto" ||
            (following != std::string::npos && normalized[following] == ':' &&
             (previous == std::string::npos || normalized[previous] == ';' ||
              normalized[previous] == '{' || normalized[previous] == '}')) ||
            (previous != std::string::npos &&
             (normalized[previous] == '.' ||
              (normalized[previous] == '>' && previous &&
               normalized[previous - 1] == '-'))))
          continue;
        if (std::any_of(register_aliases.begin(), register_aliases.end(),
                        [&](const auto &reg) {
                          return llvm::StringRef(token).equals_insensitive(reg);
                        }))
          for (size_t index = start; index < cursor; ++index)
            if (normalized[index] >= 'a' && normalized[index] <= 'z')
              normalized[index] -= 'a' - 'A';
      }
      std::memcpy(candidate.text, normalized.data(), normalized.size());
    }
    for (size_t index = 0; index < candidate.instruction_count; ++index)
      for (size_t byte = 0; byte < candidate.instructions[index].size; ++byte)
        ++uses[candidate.instructions[index].offset + byte];
    candidates.push_back(candidate);
  }
  for (auto &candidate : candidates) {
    bool unique = true;
    for (size_t index = 0; index < candidate.instruction_count; ++index)
      for (size_t byte = 0; byte < candidate.instructions[index].size; ++byte)
        unique &= uses[candidate.instructions[index].offset + byte] == 1;
    if (!unique)
      continue;
    const size_t statement_index = function.statements.size();
    function.statements.push_back(candidate);
    for (uint32_t index = 0; index < candidate.instruction_count; ++index) {
      function.instructions.emplace(candidate.instructions[index].offset,
                                    std::make_pair(statement_index, index));
    }
  }
  auto existing = std::find_if(
      module->functions.begin(), module->functions.end(),
      [&](const auto &known) { return known.entry == function.entry; });
  if (existing == module->functions.end()) {
    module->functions.push_back(std::move(function));
    existing = std::prev(module->functions.end());
  } else {
    // The proof is level-independent. Preserve its allocation and digest when
    // enrichment describes the same ranges and original instruction bytes.
    if (!existing->proof.empty() && existing->ranges == function.ranges &&
        existing->original_instructions.size() ==
            function.original_instructions.size() &&
        std::equal(existing->original_instructions.begin(),
                   existing->original_instructions.end(),
                   function.original_instructions.begin(),
                   [](const auto &left, const auto &right) {
                     return left.first == right.first &&
                            std::memcmp(&left.second, &right.second,
                                        sizeof(left.second)) == 0;
                   })) {
      function.proof = std::move(existing->proof);
      ct_decompiled_proof_header header;
      std::memcpy(&header, function.proof.data(), sizeof(header));
      header.loaded_level = function.level;
      std::memcpy(function.proof.data(), &header, sizeof(header));
    }
    // Upgrade the one function record; lower-level data is no longer retained
    // separately, and existing callers already own their copied descriptions.
    *existing = std::move(function);
  }
  module->error.clear();
  module->failed_offsets.erase({offset, level});
  const auto found = existing->instructions.find(offset);
  if (found == existing->instructions.end())
    return false;
  *statement = existing->statements[found->second.first];
  statement->instruction_index = found->second.second;
  return true;
}

bool ct_decompile_proof(ct_decompile_module *module, uint64_t offset,
                        uint32_t level, std::vector<unsigned char> &proof) {
  proof.clear();
  if (!module || (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  if (!module->producer && ct_shared_host_available()) {
    const auto *view = shared_function(*module, offset, level);
    return view && view->proof(offset, proof);
  }
  auto statement = std::make_unique<ct_decompiled_statement>();
  ct_decompile_lookup(module, offset, level, statement.get());
  for (auto &function : module->functions) {
    if (function.level < level || !function.original_instructions.count(offset))
      continue;
    if (function.proof.empty()) {
      std::vector<ct_decompiled_range> ranges;
      std::vector<ct_decompiled_instruction> instructions;
      for (const auto &[begin, end] : function.ranges)
        ranges.push_back({begin, end});
      for (const auto &[pc, instruction] : function.original_instructions)
        instructions.push_back(instruction);
      if (!ct_build_code_proof(function.entry, function.level, ranges,
                               instructions, function.proof))
        return false;
    }
    proof = function.proof;
    return true;
  }
  return false;
}

bool ct_decompile_display(ct_decompile_module *module, uint64_t offset,
                          uint32_t level, ct_decompiled_display *display) {
  if (!display)
    return false;
  *display = {};
  if (!module || (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  if (!module->producer && ct_shared_host_available()) {
    const auto *view = shared_function(*module, offset, level);
    return view && view->display(offset, *display);
  }
  auto statement = std::make_unique<ct_decompiled_statement>();
  ct_decompile_lookup(module, offset, level, statement.get());
  for (const auto &function : module->functions) {
    if (function.level < level)
      continue;
    const auto instruction = function.original_instructions.find(offset);
    if (instruction == function.original_instructions.end())
      continue;
    if (const auto control = function.controls.find(offset);
        control != function.controls.end())
      *display = control->second;
    display->function_offset = function.entry;
    display->loaded_level = function.level;
    display->instruction = instruction->second;
    std::memcpy(display->function_name, function.name.data(),
                function.name.size());
    std::memcpy(display->prototype, function.prototype.data(),
                function.prototype.size());
    return true;
  }
  return false;
}

bool ct_decompile_variables(ct_decompile_module *module, uint64_t offset,
                            uint32_t level,
                            ct_decompiled_variables *variables) {
  if (!variables)
    return false;
  *variables = {};
  if (!module || (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  if (!module->producer && ct_shared_host_available()) {
    const auto *view = shared_function(*module, offset, level);
    return view && view->variables(offset, *variables);
  }
  // Both queries share the function cache, including functions with no safe
  // statement replacements. Loading names must not launch a second analysis.
  ct_decompiled_statement statement{};
  ct_decompile_lookup(module, offset, level, &statement);
  for (const auto &function : module->functions) {
    if (function.level < level ||
        std::none_of(
            function.ranges.begin(), function.ranges.end(),
            [&](const auto &range) {
              return offset >= range.first && offset < range.second;
            }))
      continue;
    const auto original = function.original_instructions.find(offset);
    if (original == function.original_instructions.end())
      return false;
    const auto scoped = function.scoped_variables.find(offset);
    const size_t count =
        function.variables.size() +
        (scoped == function.scoped_variables.end() ? 0 : scoped->second.size());
    if (count > CT_DECOMPILED_VARIABLE_LIMIT)
      return false;
    variables->function_offset = function.entry;
    variables->instruction = original->second;
    variables->return_known = function.return_known;
    variables->return_void = function.return_void;
    variables->return_unsupported = function.return_unsupported;
    variables->return_type = function.return_type;
    std::memcpy(variables->return_type_name, function.return_type_name,
                sizeof(variables->return_type_name));
    std::memcpy(variables->return_register, function.return_register,
                sizeof(variables->return_register));
    variables->parameters_known = function.parameters_known;
    variables->variadic = function.variadic;
    for (const auto &parameter : function.parameters)
      variables->parameters[variables->parameter_count++] = parameter;
    for (const auto &variable : function.variables)
      variables->entries[variables->count++] = variable;
    if (scoped != function.scoped_variables.end())
      for (const auto &variable : scoped->second)
        variables->entries[variables->count++] = variable;
    variables->type_count = static_cast<uint32_t>(function.types.size());
    std::copy(function.types.begin(), function.types.end(), variables->types);
    variables->member_count = static_cast<uint32_t>(function.members.size());
    std::copy(function.members.begin(), function.members.end(),
              variables->members);
    return true;
  }
  return false;
}

bool ct_decompile_produce(ct_decompile_module *module, uint64_t offset,
                          uint32_t level, std::vector<unsigned char> &common,
                          std::vector<unsigned char> &full,
                          std::string &identity, std::string &error) {
  if (!module)
    return false;
  module->producer = true;
  auto statement = std::make_unique<ct_decompiled_statement>();
  for (unsigned attempt = 0; attempt < 2; ++attempt) {
    if (!worker.healthy()) {
      module->unavailable = false;
      module->failed_offsets.erase({offset, level});
    }
    ct_decompile_lookup(module, offset, level, statement.get());
    if (module->retry) {
      module->retry = false;
      continue;
    }
    if (worker.healthy())
      break;
  }
  bool valid = false;
  for (const auto &function : module->functions)
    if (function.level >= level &&
        function.original_instructions.count(offset)) {
      valid = ct_decompile_view_encode(function, common, full, error);
      break;
    }
  identity = module->artifact_identity;
  if (!valid && error.empty())
    error = module->error;
  // The catalog contains the compact permanent representation. Discard parser
  // trees, fixed-size RPC statements and scope maps as soon as it is encoded.
  module->functions.clear();
  module->next_id = 0;
  return valid;
}
