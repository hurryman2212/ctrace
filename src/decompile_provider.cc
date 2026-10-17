#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/SHA256.h>

#include <fcntl.h>
#include <linux/memfd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "analysis_protocol.h"
#include "decompile.h"
#include "decompile_provider.h"
#include "decompile_view.h"
#include "shared_objects_host.h"
#include "shared_objects_server.h"

static constexpr auto provider_timeout = std::chrono::seconds(240);
static constexpr auto provider_write_timeout = std::chrono::seconds(1);

struct DecompileRequest {
  uint32_t version = 1, level = 0;
  uint64_t link_base = 0, offset = 0;
  char path[4096]{};
  char identity[65]{};
};

struct DecompileResponse {
  uint32_t version = 1, success = 0;
  ct_shared_key common{}, full{};
  char error[CT_DECOMPILE_ERROR_CAPACITY]{};
};

static bool send_decompile_packet(int socket, const void *data, size_t size,
                                  int descriptor = -1) {
  iovec vector{const_cast<void *>(data), size};
  union {
    cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(int))];
  } ancillary{};
  msghdr message{};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  if (descriptor >= 0) {
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    auto *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  }
  ssize_t count;
  do {
    count = sendmsg(socket, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
  } while (count < 0 && errno == EINTR);
  return count >= 0 && size_t(count) == size;
}

static ssize_t receive_decompile_packet(int socket, void *data, size_t size,
                                        int &descriptor) {
  descriptor = -1;
  iovec vector{data, size};
  union {
    cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(int) * 4)];
  } ancillary{};
  msghdr message{};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = ancillary.bytes;
  message.msg_controllen = sizeof(ancillary.bytes);
  ssize_t count;
  do {
    count = recvmsg(socket, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
  } while (count < 0 && errno == EINTR);
  bool valid = count > 0 && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
  for (auto *header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(0)) {
      valid = false;
      continue;
    }
    const size_t descriptors = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    for (size_t index = 0; index < descriptors; ++index) {
      int received;
      std::memcpy(&received, CMSG_DATA(header) + index * sizeof(int),
                  sizeof(received));
      if (descriptor < 0)
        descriptor = received;
      else {
        close(received);
        valid = false;
      }
    }
  }
  if (!valid && descriptor >= 0) {
    close(descriptor);
    descriptor = -1;
  }
  return valid ? count : -1;
}

static bool send_decompile_result(int socket, uint32_t kind, const void *data,
                                  uint32_t size) {
  ct_analysis_response header{kind, size};
  std::vector<unsigned char> packet(sizeof(header) + size);
  std::memcpy(packet.data(), &header, sizeof(header));
  std::memcpy(packet.data() + sizeof(header), data, size);
  const auto deadline =
      std::chrono::steady_clock::now() + provider_write_timeout;
  for (;;) {
    if (send_decompile_packet(socket, packet.data(), packet.size()))
      return true;
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      break;
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                          deadline - std::chrono::steady_clock::now())
                          .count();
    if (left <= 0)
      break;
    pollfd ready{socket, POLLOUT, 0};
    const int status = poll(&ready, 1, int(left));
    if (status < 0 && errno == EINTR)
      continue;
    if (status <= 0 || !(ready.revents & POLLOUT))
      break;
  }
  // A dropped final response must not leave a live peer waiting for minutes.
  // The existing reconnect path can acquire the completed immutable result.
  shutdown(socket, SHUT_RDWR);
  return false;
}

bool ct_decompile_provider_request(int &connection, const char *path,
                                   int module_fd, uint64_t link_base,
                                   const std::string &analysis_identity,
                                   uint64_t offset, uint32_t level,
                                   ct_shared_key &common, ct_shared_key &full,
                                   std::string &error) {
  common = {};
  full = {};
  if (!path || std::strlen(path) >= sizeof(DecompileRequest::path) ||
      analysis_identity.size() >= sizeof(DecompileRequest::identity) ||
      module_fd < 0 ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL)) {
    error = "invalid shared decompile request";
    return false;
  }
  DecompileRequest request;
  request.level = level;
  request.link_base = link_base;
  request.offset = offset;
  std::memcpy(request.path, path, std::strlen(path));
  std::memcpy(request.identity, analysis_identity.data(),
              analysis_identity.size());
  // Reconnect once if a producer died. Its incomplete leases disappear with
  // its helper session; the next dedicated producer can take over safely.
  for (unsigned attempt = 0; attempt < 2; ++attempt) {
    if (connection < 0) {
      int pair[2];
      if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) {
        error = "cannot create shared decompiler connection";
        return false;
      }
      const bool accepted =
          ct_shared_host_connect(CT_SHARED_HOST_DECOMPILE_CONNECT, pair[1]);
      close(pair[1]);
      if (!accepted) {
        close(pair[0]);
        error = "cannot connect shared decompiler producer";
        return false;
      }
      connection = pair[0];
    }
    bool active =
        send_decompile_packet(connection, &request, sizeof(request), module_fd);
    const auto deadline = std::chrono::steady_clock::now() + provider_timeout;
    while (active) {
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - std::chrono::steady_clock::now())
                            .count();
      if (left <= 0)
        break;
      pollfd ready{connection, POLLIN, 0};
      int available;
      do {
        available = poll(&ready, 1, int(left));
      } while (available < 0 && errno == EINTR);
      if (available <= 0 || !(ready.revents & POLLIN))
        break;
      std::array<unsigned char, sizeof(ct_analysis_response) +
                                    sizeof(ct_analysis_progress) +
                                    sizeof(DecompileResponse)>
          packet{};
      int descriptor = -1;
      const ssize_t size = receive_decompile_packet(connection, packet.data(),
                                                    packet.size(), descriptor);
      if (descriptor >= 0)
        close(descriptor);
      if (size < ssize_t(sizeof(ct_analysis_response)) || descriptor >= 0)
        break;
      ct_analysis_response header;
      std::memcpy(&header, packet.data(), sizeof(header));
      if (size_t(size) != sizeof(header) + header.size)
        break;
      if (header.kind == CT_ANALYSIS_PROGRESS &&
          header.size == sizeof(ct_analysis_progress)) {
        ct_analysis_progress progress;
        std::memcpy(&progress, packet.data() + sizeof(header),
                    sizeof(progress));
        progress.stage[sizeof(progress.stage) - 1] = 0;
        progress.module[sizeof(progress.module) - 1] = 0;
        progress.detail[sizeof(progress.detail) - 1] = 0;
        ct_analysis_report_progress(&progress);
        continue;
      }
      if (header.kind != CT_ANALYSIS_RESULT ||
          header.size != sizeof(DecompileResponse))
        break;
      DecompileResponse response;
      std::memcpy(&response, packet.data() + sizeof(header), sizeof(response));
      if (response.version != 1 || response.success > 1 ||
          !std::memchr(response.error, 0, sizeof(response.error)))
        break;
      if (!response.success) {
        error = response.error;
        return false;
      }
      common = response.common;
      full = response.full;
      error.clear();
      return true;
    }
    close(connection);
    connection = -1;
  }
  error = "shared decompiler producer closed or timed out";
  return false;
}

struct ProviderFunction {
  ct_decompile_view view;
  ct_shared_key common{}, full{};
  uint64_t common_id = 0, full_id = 0;
};

struct ProviderModule {
  ct_shared_channel *channel = nullptr;
  ct_decompile_module *parser = nullptr;
  std::set<int> consumers;
  std::vector<std::unique_ptr<ProviderFunction>> functions;
  ~ProviderModule() {
    for (const auto &function : functions) {
      ct_shared_release(channel, function->common_id);
      if (function->full_id)
        ct_shared_release(channel, function->full_id);
    }
    functions.clear();
    ct_decompile_close(parser);
  }
};

static bool publish_decompile(ct_shared_channel *channel,
                              const std::string &identity, uint32_t level,
                              const std::vector<unsigned char> &bytes,
                              ct_shared_result &result, std::string &error) {
  ct_shared_key key{};
  key.kind = CT_SHARED_DECOMPILE;
  key.schema = ct_decompile_view_schema;
  key.level = level;
  llvm::SHA256 digest;
  digest.update("ctrace-shared-decompile-v1");
  digest.update(identity);
  digest.update(llvm::ArrayRef<uint8_t>(bytes));
  const auto hash = digest.final();
  std::memcpy(key.identity, hash.data(), hash.size());
  if (!ct_shared_acquire(channel, &key, &result)) {
    error = "cannot acquire shared decompile object";
    return false;
  }
  if (result.status == CT_SHARED_WAIT) {
    // Producers are serialized here. A WAIT can only be a still-publishing
    // predecessor; never wait while owning a module or runtime analysis lock.
    const auto deadline = std::chrono::steady_clock::now() + provider_timeout;
    const uint64_t ticket = result.token;
    do {
      if (!ct_shared_wait(channel, ticket, 1000, &result))
        break;
    } while (result.status == CT_SHARED_WAIT &&
             std::chrono::steady_clock::now() < deadline);
    if (result.status == CT_SHARED_WAIT) {
      ct_shared_cancel_wait(channel, ticket);
      error = "shared decompile publication timed out";
      return false;
    }
  }
  if (result.status == CT_SHARED_CREATE) {
    const uint64_t lease = result.token;
    ct_shared_file file{};
    file.fd = -1;
    if (!ct_shared_file_create(&key, bytes.data(), bytes.size(), &file) ||
        !ct_shared_publish(channel, lease, &file, &result)) {
      if (file.fd >= 0)
        ct_shared_file_close(&file);
      ct_shared_fail(channel, lease);
      error = "cannot publish shared decompile object";
      return false;
    }
    ct_shared_file_close(&file);
  }
  if (result.status != CT_SHARED_READY) {
    error = "shared decompile object is not ready";
    return false;
  }
  return true;
}

static std::unique_ptr<ProviderFunction>
restore_decompile(ct_shared_channel *channel,
                  const std::vector<ct_shared_descriptor> &catalog,
                  const char *identity, uint64_t offset) {
  if (!identity || !identity[0])
    return {};
  std::unique_ptr<ProviderFunction> function;
  for (const auto &descriptor : catalog) {
    if (descriptor.key.level != CT_DECOMPILE_PERFETTO)
      continue;
    ct_shared_result result{};
    result.fd = -1;
    if (!ct_shared_acquire(channel, &descriptor.key, &result))
      continue;
    if (result.status == CT_SHARED_CREATE)
      ct_shared_fail(channel, result.token);
    else if (result.status == CT_SHARED_WAIT)
      ct_shared_cancel_wait(channel, result.token);
    else if (result.status == CT_SHARED_READY) {
      auto candidate = std::make_unique<ProviderFunction>();
      std::string error;
      if (candidate->view.map_common(result.fd, result.object.payload_offset,
                                     result.object.payload_size, error) &&
          identity == std::string(candidate->view.identity()) &&
          candidate->view.contains(offset)) {
        candidate->common = result.object.key;
        candidate->common_id = result.object.object_id;
        function = std::move(candidate);
      } else
        ct_shared_release(channel, result.object.object_id);
    }
    ct_shared_result_close(&result);
    if (function)
      break;
  }
  if (!function)
    return {};
  for (const auto &descriptor : catalog) {
    if (descriptor.key.level != CT_DECOMPILE_FULL)
      continue;
    ct_shared_result result{};
    result.fd = -1;
    if (!ct_shared_acquire(channel, &descriptor.key, &result))
      continue;
    if (result.status == CT_SHARED_CREATE)
      ct_shared_fail(channel, result.token);
    else if (result.status == CT_SHARED_WAIT)
      ct_shared_cancel_wait(channel, result.token);
    else if (result.status == CT_SHARED_READY) {
      std::string error;
      if (function->view.map_full(result.fd, result.object.payload_offset,
                                  result.object.payload_size, error)) {
        function->full = result.object.key;
        function->full_id = result.object.object_id;
      } else
        ct_shared_release(channel, result.object.object_id);
    }
    ct_shared_result_close(&result);
    if (function->full_id)
      break;
  }
  return function;
}

static int decompile_provider_run(int control) {
  ct_shared_channel *channel = ct_shared_open();
  if (!channel)
    return 2;
  // Only a replacement producer can find pre-existing decompile objects.
  // Remember their advertised identities before generating anything; ordinary
  // requests then use the local index without repeatedly scanning every code
  // object in the shared session. Mapping still waits for an actual query.
  std::vector<ct_shared_descriptor> inherited;
  uint64_t upper_bound = 0, cursor = 0;
  for (;;) {
    ct_shared_scan_page snapshot{};
    if (!ct_shared_scan(channel, CT_SHARED_DECOMPILE, upper_bound, cursor,
                        &snapshot))
      break;
    for (uint32_t index = 0; index < snapshot.count; ++index) {
      const auto &object = snapshot.entries[index];
      if (object.key.kind == CT_SHARED_DECOMPILE &&
          object.key.schema == ct_decompile_view_schema)
        inherited.push_back(object);
    }
    if (!snapshot.more)
      break;
    upper_bound = snapshot.upper_bound;
    cursor = snapshot.cursor;
  }
  std::vector<int> connections;
  std::map<std::array<unsigned char, 32>, ProviderModule> modules;
  int current = -1;
  ct_analysis_set_progress_callback(
      [](const ct_analysis_progress *progress, void *context) {
        const int socket = *static_cast<int *>(context);
        if (socket >= 0)
          send_decompile_result(socket, CT_ANALYSIS_PROGRESS, progress,
                                sizeof(*progress));
      },
      &current);
  for (;;) {
    std::vector<pollfd> descriptors{{control, POLLIN, 0}};
    const int worker_event = ct_decompile_worker_event_fd();
    if (worker_event >= 0)
      descriptors.push_back({worker_event, POLLIN, 0});
    for (int connection : connections)
      descriptors.push_back({connection, POLLIN, 0});
    if (poll(descriptors.data(), descriptors.size(), -1) < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (descriptors.front().revents & (POLLHUP | POLLERR | POLLNVAL))
      break;
    if (descriptors.front().revents & POLLIN) {
      uint64_t marker = 0;
      int connection = -1;
      if (receive_decompile_packet(control, &marker, sizeof(marker),
                                   connection) == sizeof(marker) &&
          marker == 1 && connection >= 0)
        connections.push_back(connection);
      else if (connection >= 0)
        close(connection);
    }
    for (size_t index = 1; index < descriptors.size(); ++index) {
      const auto &ready = descriptors[index];
      if (!ready.revents)
        continue;
      if (ready.fd == worker_event) {
        ct_decompile_service_worker();
        continue;
      }
      DecompileRequest request;
      int module_fd = -1;
      const ssize_t received = receive_decompile_packet(
          ready.fd, &request, sizeof(request), module_fd);
      if (received != sizeof(request) || module_fd < 0 ||
          request.version != 1 ||
          (request.level != CT_DECOMPILE_PERFETTO &&
           request.level != CT_DECOMPILE_FULL) ||
          !std::memchr(request.path, 0, sizeof(request.path)) ||
          !std::memchr(request.identity, 0, sizeof(request.identity))) {
        if (module_fd >= 0)
          close(module_fd);
        close(ready.fd);
        connections.erase(
            std::find(connections.begin(), connections.end(), ready.fd));
        for (auto item = modules.begin(); item != modules.end();) {
          item->second.consumers.erase(ready.fd);
          if (item->second.consumers.empty())
            item = modules.erase(item);
          else
            ++item;
        }
        continue;
      }
      current = ready.fd;
      DecompileResponse response;
      std::string error;
      struct stat before{}, after{};
      bool valid = fstat(module_fd, &before) == 0 && S_ISREG(before.st_mode) &&
                   before.st_size >= 0;
      const int required_seals =
          F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
      const int seals = fcntl(module_fd, F_GET_SEALS);
      int snapshot = -1;
      if (valid && (seals < 0 || (seals & required_seals) != required_seals)) {
        snapshot =
            int(syscall(SYS_memfd_create, "ctrace-decompile-module",
                        MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL));
        valid = snapshot >= 0 && ftruncate(snapshot, before.st_size) == 0;
      }
      llvm::SHA256 digest;
      digest.update("ctrace-decompile-module-v1");
      digest.update(llvm::ArrayRef<uint8_t>(
          reinterpret_cast<const uint8_t *>(&request.link_base),
          sizeof(request.link_base)));
      digest.update(request.identity);
      std::array<unsigned char, 65536> chunk;
      for (off_t offset = 0; valid && offset < before.st_size;) {
        const ssize_t count = pread(
            module_fd, chunk.data(),
            std::min<off_t>(chunk.size(), before.st_size - offset), offset);
        if (count < 0 && errno == EINTR)
          continue;
        if (count <= 0) {
          valid = false;
          break;
        }
        digest.update(llvm::ArrayRef<uint8_t>(chunk.data(), size_t(count)));
        for (ssize_t written = 0; snapshot >= 0 && valid && written < count;) {
          const ssize_t amount =
              pwrite(snapshot, chunk.data() + written, size_t(count - written),
                     offset + written);
          if (amount < 0 && errno == EINTR)
            continue;
          if (amount <= 0)
            valid = false;
          else
            written += amount;
        }
        offset += count;
      }
      valid &= fstat(module_fd, &after) == 0 && before.st_dev == after.st_dev &&
               before.st_ino == after.st_ino &&
               before.st_size == after.st_size &&
               before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
               before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
               before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
               before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
      if (snapshot >= 0) {
        valid &=
            fcntl(snapshot, F_ADD_SEALS, required_seals | F_SEAL_EXEC) == 0;
        close(module_fd);
        module_fd = snapshot;
      }
      if (!valid)
        error = "cannot fingerprint decompile module descriptor";
      ProviderModule *module = nullptr;
      if (valid) {
        module = &modules[digest.final()];
        module->channel = channel;
        module->consumers.insert(ready.fd);
        if (!module->parser)
          module->parser = ct_decompile_open(request.path, request.link_base,
                                             request.identity, module_fd);
        if (!module->parser)
          error = "cannot retain decompile module descriptor";
      }
      close(module_fd);
      ProviderFunction *function = nullptr;
      if (module && module->parser)
        for (const auto &known : module->functions)
          if (known->view.contains(request.offset)) {
            function = known.get();
            break;
          }
      if (!function && module && module->parser) {
        const char *identity = ct_decompile_producer_identity(module->parser);
        if (auto restored = restore_decompile(channel, inherited, identity,
                                              request.offset)) {
          function = restored.get();
          module->functions.push_back(std::move(restored));
        }
      }
      if (module && module->parser &&
          (!function || function->view.level() < request.level)) {
        std::vector<unsigned char> common, full;
        std::string identity;
        if (ct_decompile_produce(module->parser, request.offset, request.level,
                                 common, full, identity, error)) {
          ct_shared_result display{}, extra{};
          display.fd = extra.fd = -1;
          bool published = publish_decompile(
              channel, identity, CT_DECOMPILE_PERFETTO, common, display, error);
          if (published && !full.empty())
            published = publish_decompile(channel, identity, CT_DECOMPILE_FULL,
                                          full, extra, error);
          auto replacement = std::make_unique<ProviderFunction>();
          if (published)
            published = replacement->view.map_common(
                display.fd, display.object.payload_offset,
                display.object.payload_size, error);
          if (published && !full.empty())
            published = replacement->view.map_full(
                extra.fd, extra.object.payload_offset,
                extra.object.payload_size, error);
          if (published) {
            replacement->common = display.object.key;
            replacement->common_id = display.object.object_id;
            if (!full.empty()) {
              replacement->full = extra.object.key;
              replacement->full_id = extra.object.object_id;
            }
            if (function) {
              ct_shared_release(channel, function->common_id);
              if (function->full_id)
                ct_shared_release(channel, function->full_id);
              for (auto &known : module->functions)
                if (known.get() == function) {
                  known = std::move(replacement);
                  function = known.get();
                  break;
                }
            } else {
              function = replacement.get();
              module->functions.push_back(std::move(replacement));
            }
          } else {
            if (display.status == CT_SHARED_READY)
              ct_shared_release(channel, display.object.object_id);
            if (extra.status == CT_SHARED_READY)
              ct_shared_release(channel, extra.object.object_id);
          }
          ct_shared_result_close(&display);
          ct_shared_result_close(&extra);
        }
      }
      if (function && function->view.level() >= request.level) {
        response.success = 1;
        response.common = function->common;
        response.full = function->full;
      } else {
        if (error.empty())
          error = "shared decompilation produced no matching function";
        std::snprintf(response.error, sizeof(response.error), "%s",
                      error.c_str());
      }
      send_decompile_result(current, CT_ANALYSIS_RESULT, &response,
                            sizeof(response));
      current = -1;
    }
  }
  ct_analysis_set_progress_callback(nullptr, nullptr);
  for (int connection : connections)
    close(connection);
  modules.clear();
  ct_shared_close(channel);
  return 0;
}

struct ct_decompile_broker::State {
  struct Host {
    int descriptor;
    uint64_t session;
    int64_t process = 0;
  };
  ct_shared_broker &objects;
  std::vector<Host> hosts;
  std::deque<int> pending;
  uint64_t next_session = UINT64_C(1) << 63;
  int provider = -1;
  pid_t process = -1;
  explicit State(ct_shared_broker &objects) : objects(objects) {}
};

ct_decompile_broker::ct_decompile_broker(ct_shared_broker &objects)
    : state(std::make_unique<State>(objects)) {}

ct_decompile_broker::~ct_decompile_broker() {
  if (state->provider >= 0)
    close(state->provider);
  for (const auto &host : state->hosts)
    close(host.descriptor);
  for (int descriptor : state->pending)
    close(descriptor);
}

bool ct_decompile_broker::worker_channel(int &descriptor, uint64_t &session) {
  descriptor = -1;
  session = 0;
  int pair[2];
  if (state->next_session == UINT64_MAX ||
      socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0)
    return false;
  session = ++state->next_session;
  state->hosts.push_back({pair[0], session, 0});
  descriptor = pair[1];
  return true;
}

void ct_decompile_broker::worker_started(uint64_t session, int64_t process) {
  for (auto &host : state->hosts)
    if (host.session == session) {
      host.process = process;
      return;
    }
}

void ct_decompile_broker::append_poll(std::vector<pollfd> &descriptors) const {
  for (const auto &host : state->hosts)
    descriptors.push_back({host.descriptor, POLLIN, 0});
  if (state->provider >= 0)
    descriptors.push_back(
        {state->provider, short(state->pending.empty() ? 0 : POLLOUT), 0});
}

void ct_decompile_broker::service(const std::vector<pollfd> &descriptors) {
  for (const auto &ready : descriptors) {
    if (!ready.revents)
      continue;
    if (ready.fd == state->provider) {
      if (ready.revents & (POLLHUP | POLLERR | POLLNVAL)) {
        close(state->provider);
        state->provider = -1;
        state->process = -1;
      }
      continue;
    }
    auto found = std::find_if(
        state->hosts.begin(), state->hosts.end(),
        [&](const auto &host) { return host.descriptor == ready.fd; });
    if (found == state->hosts.end())
      continue;
    ct_shared_host_request request;
    int descriptor = -1;
    const ssize_t size = receive_decompile_packet(ready.fd, &request,
                                                  sizeof(request), descriptor);
    if (size != sizeof(request) || descriptor < 0 || request.reserved ||
        request.session != found->session || found->process <= 0) {
      if (descriptor >= 0)
        close(descriptor);
      state->objects.close_session(found->session);
      close(found->descriptor);
      state->hosts.erase(found);
      continue;
    }
    if (request.operation == CT_SHARED_HOST_OBJECT_CONNECT) {
      if (!state->objects.connect(descriptor, found->process, found->session))
        close(descriptor);
    } else if (request.operation == CT_SHARED_HOST_DECOMPILE_CONNECT) {
      state->pending.push_back(descriptor);
    } else {
      close(descriptor);
    }
  }
  if (state->provider < 0 && !state->pending.empty()) {
    int pair[2], host = -1;
    uint64_t session = 0;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0)
      return;
    if (!worker_channel(host, session)) {
      close(pair[0]);
      close(pair[1]);
      return;
    }
    const pid_t owner = getpid();
    const pid_t child = fork();
    if (child == 0) {
      if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() != owner)
        _exit(2);
      state->objects.close_for_worker();
      close_for_worker();
      // Retain only the producer control and its private broker channel. The
      // broker's application connection must not be kept alive by this child.
      const int command = fcntl(pair[1], F_DUPFD_CLOEXEC, 10);
      const int management = fcntl(host, F_DUPFD_CLOEXEC, 10);
      if (command < 0 || management < 0 || dup2(command, 3) < 0 ||
          dup2(management, 4) < 0 || syscall(SYS_close_range, 5u, ~0u, 0) != 0)
        _exit(2);
      ct_shared_host_init(4, session);
      struct sigaction action{};
      action.sa_handler = SIG_DFL;
      sigemptyset(&action.sa_mask);
      if (sigaction(SIGCHLD, &action, nullptr) != 0)
        _exit(2);
      std::exit(decompile_provider_run(3));
    }
    close(host);
    close(pair[1]);
    worker_started(session, child);
    if (child < 0) {
      close(pair[0]);
      return;
    }
    state->process = child;
    state->provider = pair[0];
  }
  while (state->provider >= 0 && !state->pending.empty()) {
    const uint64_t marker = 1;
    if (!send_decompile_packet(state->provider, &marker, sizeof(marker),
                               state->pending.front()))
      break;
    close(state->pending.front());
    state->pending.pop_front();
  }
}

void ct_decompile_broker::close_for_worker() {
  for (const auto &host : state->hosts)
    close(host.descriptor);
  state->hosts.clear();
  for (int descriptor : state->pending)
    close(descriptor);
  state->pending.clear();
  if (state->provider >= 0)
    close(state->provider);
  state->provider = -1;
}
