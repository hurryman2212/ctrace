#include <cerrno>
#include <chrono>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "analysis.h"
#include "analysis_protocol.h"
#include "decompile.h"
#include "decompile_provider.h"
#include "kernel_decompile_worker.h"

static constexpr auto producer_cleanup_timeout = std::chrono::seconds(3);
static constexpr auto producer_cleanup_interval = std::chrono::milliseconds(10);

static bool producer_packet(int descriptor, ct_kernel_decompile_kind kind,
                            const void *data, uint64_t bytes) {
  ct_kernel_decompile_packet packet{1, kind, bytes};
  return ct_analysis_transfer(descriptor, &packet, sizeof(packet), true) &&
         ct_analysis_transfer(descriptor, const_cast<void *>(data), bytes,
                              true);
}

static bool producer_json(int descriptor, ct_kernel_decompile_kind kind,
                          llvm::json::Object object) {
  std::string text;
  llvm::raw_string_ostream output(text);
  output << llvm::json::Value(std::move(object));
  output.flush();
  return text.size() <= ct_kernel_decompile_json_limit &&
         producer_packet(descriptor, kind, text.data(), text.size());
}

int ct_kernel_decompile_worker(int control, int image) {
  using Kind = ct_kernel_decompile_kind;
  static_assert(sizeof(ct_kernel_decompile_packet) == 16);
  static_assert(sizeof(ct_kernel_decompile_query) == 16);
  struct stat information{};
  constexpr int required =
      F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  const int seals = fcntl(image, F_GET_SEALS);
  const int descriptor_flags = fcntl(control, F_GETFD);
  if (control < 0 || image < 0 || control == image ||
      fstat(image, &information) != 0 || !S_ISREG(information.st_mode) ||
      information.st_size <= 0 ||
      uint64_t(information.st_size) > ct_kernel_decompile_view_limit ||
      seals < 0 || (seals & required) != required || descriptor_flags < 0 ||
      fcntl(control, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0 ||
      prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
    producer_json(control, Kind::error,
                  llvm::json::Object{
                      {"scope", "protocol"},
                      {"error", "kernel decompile producer requires a sealed "
                                "image and child cleanup"}});
    return 2;
  }
  struct Progress {
    int descriptor;
    bool connected = true;
  } progress{control};
  ct_decompile_producer_cancel_fd(control);
  ct_analysis_set_progress_callback(
      [](const ct_analysis_progress *record, void *opaque) {
        auto &state = *static_cast<Progress *>(opaque);
        if (state.connected)
          state.connected = producer_packet(state.descriptor, Kind::progress,
                                            record, sizeof(*record));
      },
      &progress);
  std::unique_ptr<ct_decompile_module, decltype(&ct_decompile_close)> module(
      nullptr, ct_decompile_close);
  bool finished = false;
  while (progress.connected) {
    ct_kernel_decompile_packet packet{};
    if (!ct_analysis_transfer(control, &packet, sizeof(packet), false))
      break;
    if (packet.version != 1)
      break;
    if (packet.kind == Kind::finish && !packet.bytes) {
      finished = true;
      break;
    }
    if (packet.kind == Kind::open && !module && packet.bytes &&
        packet.bytes <= ct_kernel_decompile_json_limit) {
      std::string request(packet.bytes, '\0');
      if (!ct_analysis_transfer(control, request.data(), request.size(), false))
        break;
      auto parsed = llvm::json::parse(request);
      if (!parsed) {
        llvm::consumeError(parsed.takeError());
        break;
      }
      const auto *object = parsed->getAsObject();
      const auto path = object ? object->getString("module") : std::nullopt;
      const auto identity =
          object ? object->getString("analysis_identity") : std::nullopt;
      if (!path || path->empty() || path->contains('\0') || !identity ||
          identity->size() != 64 ||
          identity->find_first_not_of("0123456789abcdef") !=
              llvm::StringRef::npos)
        break;
      module.reset(ct_decompile_open(path->str().c_str(), 0,
                                     identity->str().c_str(), image));
      std::string manifest, error;
      if (!ct_decompile_producer_manifest(module.get(), manifest, error) ||
          manifest.size() > ct_kernel_decompile_manifest_limit) {
        producer_json(
            control, Kind::error,
            llvm::json::Object{
                {"scope", "module"},
                {"error", error.empty() ? "image manifest exceeds its bound"
                                        : error.substr(0, 2048)}});
        break;
      }
      progress.connected = producer_packet(control, Kind::manifest,
                                           manifest.data(), manifest.size());
    } else if (packet.kind == Kind::function && module &&
               packet.bytes == sizeof(ct_kernel_decompile_query)) {
      ct_kernel_decompile_query query{};
      if (!ct_analysis_transfer(control, &query, sizeof(query), false) ||
          query.reserved ||
          (query.level != CT_DECOMPILE_PERFETTO &&
           query.level != CT_DECOMPILE_FULL))
        break;
      std::vector<unsigned char> common, full;
      std::string identity, error;
      if (!ct_decompile_produce(module.get(), query.address, query.level,
                                common, full, identity, error) ||
          common.empty() ||
          (query.level == CT_DECOMPILE_FULL && full.empty()) ||
          common.size() > ct_kernel_decompile_view_limit ||
          full.size() > ct_kernel_decompile_view_limit) {
        progress.connected = producer_json(
            control, Kind::error,
            llvm::json::Object{
                {"scope", "function"},
                {"error", error.empty() ? "decompiled view exceeds its bound"
                                        : error.substr(0, 2048)}});
        continue;
      }
      llvm::json::Object response;
      response["address"] = llvm::formatv("0x{0:x-}", query.address).str();
      response["identity"] = identity;
      response["common_bytes"] = common.size();
      response["full_bytes"] = full.size();
      progress.connected =
          producer_json(control, Kind::result, std::move(response)) &&
          producer_packet(control, Kind::common, common.data(),
                          common.size()) &&
          producer_packet(control, Kind::full, full.data(), full.size());
    } else {
      break;
    }
  }
  ct_analysis_set_progress_callback(nullptr, nullptr);
  ct_decompile_producer_cancel_fd(-1);
  module.reset();
  ct_decompile_producer_shutdown();
  // This isolated worker adopts any orphaned analyzer grandchildren. Backend
  // shutdown normally reaps everything; never report FINISHED with live ones.
  bool clean = false;
  const auto deadline =
      std::chrono::steady_clock::now() + producer_cleanup_timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    const pid_t child = waitpid(-1, nullptr, WNOHANG);
    if (child > 0 || (child < 0 && errno == EINTR))
      continue;
    if (child < 0 && errno == ECHILD) {
      clean = true;
      break;
    }
    std::ifstream children("/proc/self/task/" + std::to_string(getpid()) +
                           "/children");
    int64_t process;
    while (children >> process)
      if (process > 0 && process <= INT32_MAX)
        kill(pid_t(process), SIGKILL);
    std::this_thread::sleep_for(producer_cleanup_interval);
  }
  if (!clean) {
    producer_json(control, Kind::error,
                  llvm::json::Object{
                      {"scope", "module"},
                      {"error", "decompiler child cleanup did not complete"}});
    return 1;
  }
  return finished && progress.connected &&
                 producer_packet(control, Kind::finished, nullptr, 0)
             ? 0
             : 1;
}
