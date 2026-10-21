// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <optional>

#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "contract.hh"
#include "decompile_transport.hh"
#include "kernel_decompile_worker.hh"

static constexpr size_t decompile_copy_chunk = 64 * 1024;

extern char **environ;

struct KernelDecompileFile {
  int descriptor = -1;
  ~KernelDecompileFile() {
    if (descriptor >= 0)
      close(descriptor);
  }
};

static bool decompile_write_file(int descriptor, const void *data, size_t size,
                                 std::string &error) {
  const auto *bytes = static_cast<const unsigned char *>(data);
  for (size_t done = 0; done < size;) {
    const ssize_t count = write(descriptor, bytes + done, size - done);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      error = "cannot write kernel decompile object: " +
              std::string(std::strerror(count < 0 ? errno : EIO));
      return false;
    }
    done += size_t(count);
  }
  return true;
}

static bool decompile_seal_file(int descriptor, std::string &error) {
  if (fcntl(descriptor, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL |
                F_SEAL_EXEC) == 0)
    return true;
  error = "cannot seal kernel decompile object: " +
          std::string(std::strerror(errno));
  return false;
}

struct ct_kernel_decompile_client::State {
  using Kind = ct_kernel_decompile_kind;
  int control = -1;
  pid_t process = -1;
  bool failed = false;
  std::string identity;
  std::function<void(const ct_analysis_progress &)> progress;

  ~State() {
    if (control >= 0) {
      shutdown(control, SHUT_RDWR);
      close(control);
    }
    if (process <= 0)
      return;
    // EOF cancels the producer's analyzer exchange and runs its cleanup. Do
    // not kill the cleanup owner immediately and orphan its analyzer group.
    while (waitpid(process, nullptr, 0) < 0 && errno == EINTR) {
    }
  }

  bool fail(std::string &error, const std::string &reason) {
    error = reason;
    failed = true;
    if (control >= 0)
      shutdown(control, SHUT_RDWR);
    return false;
  }

  bool transfer(void *bytes, size_t size, bool sending, std::string &error) {
    auto *data = static_cast<unsigned char *>(bytes);
    for (size_t done = 0; done < size;) {
      const ssize_t count =
          sending ? send(control, data + done, size - done,
                         MSG_NOSIGNAL | MSG_DONTWAIT)
                  : recv(control, data + done, size - done, MSG_DONTWAIT);
      if (count > 0) {
        done += size_t(count);
        continue;
      }
      if (count < 0 && errno == EINTR)
        continue;
      if (!count || (errno != EAGAIN && errno != EWOULDBLOCK))
        return fail(error, "kernel decompile producer connection closed");
      pollfd descriptor{control, short(sending ? POLLOUT : POLLIN), 0};
      const int ready = poll(&descriptor, 1, -1);
      if (ready < 0 && errno == EINTR)
        continue;
      if (ready <= 0 || (descriptor.revents & (POLLERR | POLLNVAL)))
        return fail(error, "kernel decompile producer did not respond");
      // Drain a final packet even when its peer has already closed the socket.
    }
    return true;
  }

  bool send_packet(Kind kind, const void *data, size_t size,
                   std::string &error) {
    ct_kernel_decompile_packet packet;
    packet.kind = kind;
    packet.bytes = size;
    return transfer(&packet, sizeof(packet), true, error) &&
           transfer(const_cast<void *>(data), size, true, error);
  }

  bool receive(ct_kernel_decompile_packet &packet, std::string &error) {
    for (;;) {
      if (!transfer(&packet, sizeof(packet), false, error))
        return false;
      if (packet.reserved || !ct_contract_matches(packet.contract_hash))
        return fail(error, "kernel decompile contract hash mismatch");
      if (packet.kind != Kind::progress)
        return true;
      ct_analysis_progress record{};
      if (packet.bytes != sizeof(record) ||
          !transfer(&record, sizeof(record), false, error))
        return fail(error, "invalid kernel decompile progress packet");
      const auto terminated = [](const auto &text) {
        return std::memchr(text, 0, sizeof(text)) != nullptr;
      };
      const auto *raw = reinterpret_cast<const unsigned char *>(&record);
      if (!terminated(record.stage) || !terminated(record.module) ||
          !terminated(record.detail) || !terminated(record.file) ||
          !terminated(record.source_prefix) || !terminated(record.function) ||
          raw[offsetof(ct_analysis_progress, has_range)] > 1)
        return fail(error, "invalid kernel decompile progress fields");
      if (record.has_range && record.end_offset < record.begin_offset)
        return fail(error, "invalid kernel decompile progress range");
      if (progress)
        progress(record);
    }
  }

  bool text(const ct_kernel_decompile_packet &packet, std::string &result,
            std::string &error) {
    if (!packet.bytes || packet.bytes > result.max_size())
      return fail(error, "kernel decompile response size is not representable");
    result.resize(size_t(packet.bytes));
    return transfer(result.data(), result.size(), false, error);
  }

  bool worker_error(const ct_kernel_decompile_packet &packet, bool function,
                    std::string &error) {
    std::string message;
    if (!text(packet, message, error))
      return false;
    auto parsed = llvm::json::parse(message);
    if (!parsed) {
      llvm::consumeError(parsed.takeError());
      return fail(error, "malformed kernel decompile error response");
    }
    const auto *object = parsed->getAsObject();
    const auto scope = object ? object->getString("scope") : std::nullopt;
    const auto detail = object ? object->getString("error") : std::nullopt;
    if (!scope || !detail || detail->contains('\0'))
      return fail(error, "invalid kernel decompile error fields");
    error = detail->str();
    if (function && *scope == "function")
      return true;
    return fail(error, error);
  }

  bool blob(Kind expected, uint64_t size, int descriptor, std::string &error) {
    ct_kernel_decompile_packet packet;
    if (!receive(packet, error))
      return false;
    if (packet.kind != expected || packet.bytes != size)
      return fail(error, "kernel decompile view framing mismatch");
    std::array<unsigned char, decompile_copy_chunk> buffer;
    for (uint64_t done = 0; done < size;) {
      const size_t count = std::min<uint64_t>(buffer.size(), size - done);
      if (!transfer(buffer.data(), count, false, error) ||
          !decompile_write_file(descriptor, buffer.data(), count, error))
        return fail(error, error);
      done += count;
    }
    return decompile_seal_file(descriptor, error) || fail(error, error);
  }
};

ct_kernel_decompile_client::ct_kernel_decompile_client() = default;
ct_kernel_decompile_client::~ct_kernel_decompile_client() = default;

bool ct_kernel_decompile_client::open(
    const std::string &helper, const std::string &module,
    const std::string &identity,
    const std::vector<unsigned char> &analysis_image,
    const std::function<void(const ct_analysis_progress &)> &progress,
    std::string &manifest, std::string &error) {
  error.clear();
  manifest.clear();
  if (state || analysis_image.empty() || helper.empty() ||
      helper.find('\0') != std::string::npos || module.empty() ||
      module.find('\0') != std::string::npos || identity.size() != 64 ||
      identity.find_first_not_of("0123456789abcdef") != std::string::npos) {
    error = "invalid kernel decompile preparation request";
    return false;
  }
  KernelDecompileFile image{
      memfd_create("ctrace-kernel-analysis",
                   MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)};
  if (image.descriptor < 0 ||
      !decompile_write_file(image.descriptor, analysis_image.data(),
                            analysis_image.size(), error) ||
      !decompile_seal_file(image.descriptor, error)) {
    if (error.empty())
      error = "cannot create kernel decompile analysis object";
    return false;
  }
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    error = "cannot create kernel decompile producer channel";
    return false;
  }
  KernelDecompileFile parent{sockets[0]}, child{sockets[1]};
  // Reserve 3/4 for the child's control/image descriptors without a dup2
  // source being clobbered when the caller started with closed stdio FDs.
  for (auto *file : {&image, &parent, &child}) {
    if (file->descriptor >= 5)
      continue;
    const int replacement = fcntl(file->descriptor, F_DUPFD_CLOEXEC, 5);
    if (replacement < 0) {
      error = "cannot reserve kernel decompile descriptors";
      return false;
    }
    close(file->descriptor);
    file->descriptor = replacement;
  }
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  int failure = posix_spawn_file_actions_init(&actions);
  if (failure) {
    error = "cannot create kernel decompile spawn actions";
    return false;
  }
  failure = posix_spawnattr_init(&attributes);
  if (failure) {
    posix_spawn_file_actions_destroy(&actions);
    error = "cannot create kernel decompile spawn attributes";
    return false;
  }
  if (!(failure =
            posix_spawn_file_actions_adddup2(&actions, child.descriptor, 3)) &&
      !(failure =
            posix_spawn_file_actions_adddup2(&actions, image.descriptor, 4)) &&
      !(failure = posix_spawn_file_actions_addclosefrom_np(&actions, 5)) &&
      !(failure = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
                                                   "/dev/null", O_RDONLY, 0)) &&
      !(failure = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO,
                                                   "/dev/null", O_WRONLY, 0)) &&
      !(failure = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP)))
    failure = posix_spawnattr_setpgroup(&attributes, 0);
  auto pending = std::make_unique<State>();
  pid_t process = -1;
  char *arguments[] = {const_cast<char *>(helper.c_str()),
                       const_cast<char *>("--kernel-decompile-worker"),
                       const_cast<char *>("3"), const_cast<char *>("4"),
                       nullptr};
  if (!failure)
    failure = posix_spawn(&process, helper.c_str(), &actions, &attributes,
                          arguments, environ);
  posix_spawnattr_destroy(&attributes);
  posix_spawn_file_actions_destroy(&actions);
  if (failure) {
    error = "cannot start kernel decompile producer: " +
            std::string(std::strerror(failure));
    return false;
  }
  pending->process = process;
  pending->control = parent.descriptor;
  parent.descriptor = -1;
  pending->progress = progress;
  state = std::move(pending);
  // Close the parent's copy of the child endpoint before waiting for EOF.
  close(child.descriptor);
  child.descriptor = -1;
  std::string request;
  llvm::raw_string_ostream output(request);
  output << llvm::json::Value(
      llvm::json::Object{{"module", module}, {"analysis_identity", identity}});
  output.flush();
  if (!state->send_packet(State::Kind::open, request.data(), request.size(),
                          error))
    return state->fail(error, "cannot send kernel decompile module request");
  ct_kernel_decompile_packet packet;
  if (!state->receive(packet, error))
    return false;
  if (packet.kind == State::Kind::error)
    return state->worker_error(packet, false, error);
  if (packet.kind != State::Kind::manifest)
    return state->fail(error, "kernel decompile manifest was not returned");
  if (!state->text(packet, manifest, error))
    return false;
  auto parsed = llvm::json::parse(manifest);
  if (!parsed) {
    llvm::consumeError(parsed.takeError());
    return state->fail(error, "malformed kernel decompile manifest");
  }
  const auto *object = parsed->getAsObject();
  const auto artifact = object ? object->getString("identity") : std::nullopt;
  if (!object || object->getString("contract_hash") != CTRACE_CONTRACT_HASH ||
      !object->getBoolean("ok").value_or(false) || !artifact ||
      artifact->size() != 64 ||
      artifact->find_first_not_of("0123456789abcdef") != llvm::StringRef::npos)
    return state->fail(error, "invalid kernel decompile manifest identity");
  state->identity = artifact->str();
  return true;
}

std::string ct_kernel_decompile_client::identity() const {
  return state ? state->identity : std::string{};
}

bool ct_kernel_decompile_client::function(uint64_t address, uint32_t level,
                                          ct_decompile_view &view,
                                          std::string &error) {
  error.clear();
  if (!state || state->failed || view.level() ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL)) {
    error = "kernel decompile function request is not ready";
    return false;
  }
  const ct_kernel_decompile_query query{address, level, 0};
  ct_kernel_decompile_packet packet;
  if (!state->send_packet(State::Kind::function, &query, sizeof(query),
                          error) ||
      !state->receive(packet, error))
    return false;
  if (packet.kind == State::Kind::error)
    return state->worker_error(packet, true, error);
  std::string text;
  if (packet.kind != State::Kind::result || !state->text(packet, text, error))
    return state->fail(error, "invalid kernel decompile result packet");
  auto parsed = llvm::json::parse(text);
  if (!parsed) {
    llvm::consumeError(parsed.takeError());
    return state->fail(error, "malformed kernel decompile result");
  }
  const auto *object = parsed->getAsObject();
  const auto encoded = object ? object->getString("address") : std::nullopt;
  const auto identity = object ? object->getString("identity") : std::nullopt;
  const auto common_size =
      object ? object->getInteger("common_bytes") : std::nullopt;
  const auto full_size =
      object ? object->getInteger("full_bytes") : std::nullopt;
  uint64_t returned = 0;
  bool same_address = false;
  if (encoded && encoded->starts_with("0x")) {
    const auto result =
        std::from_chars(encoded->begin() + 2, encoded->end(), returned, 16);
    same_address = result.ec == std::errc{} && result.ptr == encoded->end() &&
                   returned == address;
  }
  if (!same_address || !identity || identity->size() != 64 ||
      identity->find_first_not_of("0123456789abcdef") !=
          llvm::StringRef::npos ||
      (!state->identity.empty() && state->identity != *identity) ||
      !common_size || *common_size <= 0 || uint64_t(*common_size) > SIZE_MAX ||
      !full_size || *full_size < 0 || uint64_t(*full_size) > SIZE_MAX ||
      (level == CT_DECOMPILE_FULL && !*full_size))
    return state->fail(error, "kernel decompile result identity/size mismatch");
  KernelDecompileFile common{
      memfd_create("ctrace-kernel-decompile-common",
                   MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)};
  KernelDecompileFile full{
      memfd_create("ctrace-kernel-decompile-full",
                   MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)};
  if (common.descriptor < 0 || full.descriptor < 0)
    return state->fail(error, "cannot create kernel decompile view objects");
  if (!state->blob(State::Kind::common, *common_size, common.descriptor,
                   error) ||
      !state->blob(State::Kind::full, *full_size, full.descriptor, error))
    return false;
  if (!view.map_common(common.descriptor, 0, *common_size, error) ||
      (*full_size && !view.map_full(full.descriptor, 0, *full_size, error)) ||
      view.identity() != *identity || view.level() < level ||
      !view.contains(address))
    return state->fail(error,
                       "kernel decompile view validation failed: " + error);
  state->identity = identity->str();
  return true;
}

bool ct_kernel_decompile_client::finish(std::string &error) {
  error.clear();
  if (!state || state->failed || state->process <= 0) {
    error = "kernel decompile producer is not ready to finish";
    return false;
  }
  ct_kernel_decompile_packet packet;
  if (!state->send_packet(State::Kind::finish, nullptr, 0, error) ||
      !state->receive(packet, error))
    return false;
  if (packet.kind == State::Kind::error)
    return state->worker_error(packet, false, error);
  if (packet.kind != State::Kind::finished || packet.bytes)
    return state->fail(error, "kernel decompile cleanup was not acknowledged");
  int status = 0;
  pid_t done;
  do {
    done = waitpid(state->process, &status, 0);
  } while (done < 0 && errno == EINTR);
  if (done != state->process)
    return state->fail(error, "cannot confirm kernel decompile producer exit");
  state->process = -1;
  if (!WIFEXITED(status) || WEXITSTATUS(status))
    return state->fail(error, "kernel decompile producer cleanup failed");
  state.reset();
  return true;
}
