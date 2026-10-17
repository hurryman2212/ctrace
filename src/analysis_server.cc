#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <llvm/Support/Error.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/SHA256.h>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include "analysis.h"
#include "analysis_descriptors.h"
#include "analysis_files.h"
#include "analysis_protocol.h"
#include "cache.h"
#include "decompile_provider.h"
#include "exec_resources.h"
#include "kernel_decompile_worker.h"
#include "shared_objects_host.h"
#include "shared_objects_server.h"
#include "thread_suspend_server.h"
#include "trace_clock.h"

static bool transfer(int fd, void *buffer, size_t size, bool sending) {
  if (sending) {
    if (size > UINT32_MAX)
      return false;
    ct_analysis_response response{CT_ANALYSIS_RESULT,
                                  static_cast<uint32_t>(size)};
    if (!ct_analysis_transfer(fd, &response, sizeof(response), true))
      return false;
  }
  return ct_analysis_transfer(fd, buffer, size, sending);
}

static bool send_record(int fd, const void *record, size_t decoded_size) {
  std::vector<unsigned char> packed(ct_analysis_record_capacity(decoded_size));
  uint32_t size = ct_analysis_record_pack(packed.data(), record, decoded_size);
  return transfer(fd, &size, sizeof(size), true) &&
         transfer(fd, packed.data(), size, true);
}

struct BrokerTrace {
  int fd = -1;
  uint64_t origin_ns = 0;
  off_t offset = 0;
  bool events = false;
  llvm::json::Object metadata;
  std::map<uint64_t, llvm::json::Object> sessions;
  struct Track {
    int64_t owner = 0;
    int64_t namespace_pid = 0;
    int64_t namespace_tid = 0;
    int64_t output_tid = 0;
    double last = 0;
    std::vector<llvm::json::Object> begins;
  };
  std::map<std::pair<uint64_t, uint64_t>, Track> tracks;
  int64_t next_output_tid = 0;

  bool write(const std::string &entry) {
    llvm::json::Object combined = metadata;
    for (const char *name : {"userspace_spans", "userspace_gate_hits",
                             "userspace_detailed_steps"}) {
      uint64_t total = 0;
      for (const auto &session : sessions) {
        const auto value = session.second.getInteger(name);
        if (value && *value >= 0)
          total += uint64_t(*value);
      }
      combined[name] = total;
    }
    combined["process_sessions"] = uint64_t(sessions.size());
    const std::string suffix =
        "\n],\"displayTimeUnit\":\"ns\",\"otherData\":" +
        llvm::formatv("{0}", llvm::json::Value(std::move(combined))).str() +
        "}\n";
    const std::string bytes = entry + suffix;
    size_t written = 0;
    while (written < bytes.size()) {
      const ssize_t count = pwrite(fd, bytes.data() + written,
                                   bytes.size() - written, offset + written);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        return false;
      written += size_t(count);
    }
    if (ftruncate(fd, offset + bytes.size()) != 0)
      return false;
    offset += entry.size();
    return true;
  }

  bool begin_session(
      uint64_t session, int64_t owner, uint64_t replaced_session = 0,
      const std::map<uint64_t, ct_exec_timestamp> *timestamps = nullptr) {
    // Only an authenticated successful exec calls this operation. A new
    // metadata record with a recycled PID must not implicitly exec another
    // context's stack, even when both images borrowed the same parent session.
    for (auto item = tracks.begin(); item != tracks.end();) {
      if (item->second.owner != owner || item->first.first == session ||
          (replaced_session && item->first.first != replaced_session)) {
        ++item;
        continue;
      }
      const ct_exec_timestamp *timestamp = nullptr;
      if (timestamps && !item->second.begins.empty() &&
          item->first.first == replaced_session) {
        const auto found = timestamps->find(item->first.second);
        if (found != timestamps->end()) {
          timestamp = &found->second;
          const uint64_t wall_ns = timestamp->wall_nanoseconds;
          const double wall_us =
              wall_ns > origin_ns ? (wall_ns - origin_ns) / 1000.0 : 0;
          item->second.last = std::max(item->second.last, wall_us);
        }
      }
      while (!item->second.begins.empty()) {
        llvm::json::Object arguments = item->second.begins.back();
        arguments["status"] = "exec";
        if (timestamp) {
          const auto *begin = arguments.get("begin_application_ns");
          if (begin) {
            const auto begin_ns = begin->getAsUINT64();
            if (begin_ns) {
              const uint64_t end_ns =
                  std::max(*begin_ns, timestamp->nanoseconds);
              arguments["end_application_ns"] = end_ns;
              arguments["application_duration_ns"] = end_ns - *begin_ns;
            }
          }
        }
        llvm::json::Object closure{{"ph", "E"},
                                   {"pid", owner},
                                   {"tid", item->second.output_tid},
                                   {"ts", item->second.last},
                                   {"args", std::move(arguments)}};
        const std::string json =
            llvm::formatv("{0}", llvm::json::Value(std::move(closure))).str();
        if (!write((events ? ",\n" : "") + json))
          return false;
        events = true;
        item->second.begins.pop_back();
      }
      item = tracks.erase(item);
    }
    return true;
  }

  bool event(uint64_t session, llvm::json::Object event, int64_t process) {
    const auto pid = event.getInteger("pid");
    const auto tid = event.getInteger("tid");
    const auto phase = event.getString("ph");
    const auto *context = event.get("ctrace_context");
    const auto token = context ? context->getAsUINT64() : std::nullopt;
    if (!pid || !tid || !phase || !token || !*token || *pid <= 0 || *tid < 0)
      return false;
    const auto name = event.getString("name");
    const bool thread_metadata =
        *phase == "M" && name && *name == "thread_name";
    const bool process_metadata =
        *phase == "M" && name && *name == "process_name";
    const auto identity = std::make_pair(session, *token);
    auto position = tracks.find(identity);
    if (position == tracks.end()) {
      // Old contexts can be cleaned up in a different task after exec or ID
      // reuse. Their value-owned tokens cannot recreate or close a new track.
      if (!thread_metadata)
        return *phase == "E";
      if (process <= 0 || *tid == 0)
        return false;
      // Logical track IDs never alias an earlier context, even if its delayed
      // cleanup timestamp overlaps a recycled kernel TID or a new exec image.
      // Namespace PID/TID remain explicit in the thread metadata and its name.
      if (next_output_tid == INT64_MAX)
        return false;
      Track track;
      track.owner = process;
      track.namespace_pid = *pid;
      track.namespace_tid = *tid;
      track.output_tid = ++next_output_tid;
      position = tracks.emplace(identity, std::move(track)).first;
    }
    Track &track = position->second;
    if (*pid != track.namespace_pid ||
        (*tid != track.namespace_tid && !process_metadata) ||
        (process != track.owner && *phase != "E"))
      return false;
    event.erase("ctrace_context");
    event["pid"] = track.owner;
    event["tid"] = process_metadata ? 0 : track.output_tid;
    if (const auto timestamp = event.getNumber("ts")) {
      const double current = std::max(track.last, *timestamp);
      event["ts"] = current;
      track.last = current;
    }
    if (*phase == "B") {
      llvm::json::Object begin;
      if (const auto *arguments = event.getObject("args"))
        for (const char *name : {"begin_ticks", "begin_application_ns"})
          if (const auto *value = arguments->get(name))
            begin[name] = *value;
      track.begins.push_back(std::move(begin));
    } else if (*phase == "E") {
      if (track.begins.empty())
        return true;
      track.begins.pop_back();
    }
    const bool finished = *phase == "E" && track.begins.empty();
    const std::string json =
        llvm::formatv("{0}", llvm::json::Value(std::move(event))).str();
    if (!write((events ? ",\n" : "") + json))
      return false;
    events = true;
    if (finished)
      tracks.erase(position);
    return true;
  }
};

// The broker never analyzes code. Forking workers therefore cannot inherit
// locks owned by LLVM/Ghidra background threads or another client's stream.
static int broker(int control_fd, const char *path, int filename_tid,
                  ct_analysis_worker_handshake &handshake) {
  BrokerTrace trace;
  if (path) {
    int64_t offset;
    if (!ct_trace_clock_offset(&offset) ||
        !(trace.origin_ns = ct_trace_clock_now(offset)))
      return -1;
    std::string output_path = path;
    if (filename_tid) {
      // Choose the timestamp at file creation, after launcher preflight work.
      // Only format the date: percent signs in names and paths are literal.
      const std::time_t created = std::time(nullptr);
      struct tm local{};
      char timestamp[16];
      if (created == std::time_t(-1) || !localtime_r(&created, &local) ||
          !std::strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &local))
        return -1;
      output_path += "." + std::string(timestamp) + "." +
                     std::to_string(filename_tid) + ".json";
    }
    trace.fd = open(output_path.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (trace.fd < 0) {
      const std::string message = "ctrace: cannot create Perfetto output " +
                                  output_path + ": " + std::strerror(errno) +
                                  "\n";
      // The launcher sends this helper's stderr to the same log descriptor as
      // the client. Match its record lock so diagnostics cannot split a trace.
      struct stat information{};
      const bool regular = fstat(STDERR_FILENO, &information) == 0 &&
                           S_ISREG(information.st_mode);
      struct flock lock{};
      lock.l_type = F_WRLCK;
      lock.l_whence = SEEK_SET;
      lock.l_len = 1;
      int locked = 0;
      if (regular) {
        do {
          locked = fcntl(STDERR_FILENO, F_SETLKW, &lock);
        } while (locked < 0 && errno == EINTR);
      }
      if (locked == 0) {
        size_t offset = 0;
        while (offset < message.size()) {
          const ssize_t count = ::write(STDERR_FILENO, message.data() + offset,
                                        message.size() - offset);
          if (count < 0 && errno == EINTR)
            continue;
          if (count <= 0)
            break;
          offset += size_t(count);
        }
        if (regular) {
          lock.l_type = F_UNLCK;
          do {
            locked = fcntl(STDERR_FILENO, F_SETLK, &lock);
          } while (locked < 0 && errno == EINTR);
        }
      }
    }
    if (trace.fd < 0 || !trace.write("{\"traceEvents\":[\n"))
      return -1;
  }
  struct sigaction action{};
  action.sa_handler = SIG_IGN;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGCHLD, &action, nullptr) != 0)
    return -1;
  uint64_t next_session = 0;
  uint64_t next_exec_nonce = 0;
  struct ExecAttempt {
    int64_t sender = 0;
    uint64_t session = 0;
    bool recording = false;
    std::map<uint64_t, ct_exec_timestamp> timestamps;
    std::unique_ptr<ct_exec_resources> resources{};
    unsigned resource_gets = 0;
  };
  std::map<uint64_t, ExecAttempt> exec_attempts;
  std::map<uint64_t, int64_t> session_owners;
  ct_shared_broker objects;
  ct_decompile_broker decompiler(objects);
  ct_thread_suspend_broker suspension;
  std::vector<char> bytes(sizeof(ct_analysis_broker_packet) +
                          CT_ANALYSIS_BROKER_LIMIT);
  for (;;) {
    std::vector<pollfd> descriptors{{control_fd, POLLIN, 0}};
    suspension.append_poll(descriptors);
    objects.append_poll(descriptors);
    decompiler.append_poll(descriptors);
    for (const auto &entry : exec_attempts)
      if (entry.second.resources)
        descriptors.push_back(
            {entry.second.resources->liveness_descriptor(), POLLIN, 0});
    const int ready = poll(descriptors.data(), descriptors.size(),
                           objects.validating() ? 0 : -1);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    // Suspension never depends on an analysis worker completing a request.
    // Service ready control channels before bounded object-validation work.
    suspension.service(descriptors);
    objects.service(descriptors);
    decompiler.service(descriptors);
    for (auto entry = exec_attempts.begin(); entry != exec_attempts.end();) {
      const int owner = entry->second.resources
                            ? entry->second.resources->liveness_descriptor()
                            : -1;
      const bool exited =
          owner >= 0 && std::any_of(descriptors.begin(), descriptors.end(),
                                    [&](const pollfd &descriptor) {
                                      return descriptor.fd == owner &&
                                             descriptor.revents;
                                    });
      if (exited)
        entry = exec_attempts.erase(entry);
      else
        ++entry;
    }
    if (!(descriptors.front().revents & POLLIN)) {
      if (descriptors.front().revents & (POLLERR | POLLHUP | POLLNVAL))
        break;
      continue;
    }
    union {
      struct cmsghdr alignment;
      char bytes[CMSG_SPACE(sizeof(int) * (DR_EXEC_RESOURCE_LIMIT + 2)) +
                 CMSG_SPACE(sizeof(struct ucred))];
    } ancillary{};
    struct iovec vector{bytes.data(), bytes.size()};
    struct msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    ssize_t count;
    do {
      count = recvmsg(control_fd, &message, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count <= 0)
      break;
    int worker = -1;
    std::vector<int> received_files;
    int64_t sender = 0;
    bool valid = !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header;
         header = CMSG_NXTHDR(&message, header)) {
      if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
          header->cmsg_len >= CMSG_LEN(0)) {
        const size_t descriptors =
            (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t index = 0; index < descriptors; ++index) {
          int received;
          std::memcpy(&received, CMSG_DATA(header) + index * sizeof(int),
                      sizeof(received));
          received_files.push_back(received);
        }
      } else if (header->cmsg_level == SOL_SOCKET &&
                 header->cmsg_type == SCM_CREDENTIALS &&
                 header->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
        struct ucred credentials{};
        std::memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
        valid &= sender == 0;
        sender = credentials.pid;
      } else
        valid = false;
    }
    if (!received_files.empty())
      worker = received_files.front();
    uint64_t magic = 0;
    if (size_t(count) >= sizeof(magic))
      std::memcpy(&magic, bytes.data(), sizeof(magic));
    if (magic == DR_THREAD_SUSPEND_MAGIC) {
      dr_thread_suspend_request_t request{};
      if (size_t(count) == sizeof(request))
        std::memcpy(&request, bytes.data(), sizeof(request));
      else
        valid = false;
      if (!valid)
        request.operation = 0;
      suspension.connect(request, std::move(received_files), sender);
      continue;
    }
    if (magic == DR_EXEC_RESOURCE_MAGIC) {
      dr_exec_resource_request_t request{};
      if (size_t(count) == sizeof(request))
        std::memcpy(&request, bytes.data(), sizeof(request));
      else
        valid = false;
      valid &= request.magic == DR_EXEC_RESOURCE_MAGIC &&
               request.version == DR_EXEC_RESOURCE_VERSION &&
               !request.reserved && worker >= 0 && sender > 0 &&
               request.exec_nonce;
      int reply_type = 0;
      socklen_t reply_type_size = sizeof(reply_type);
      valid = valid &&
              getsockopt(worker, SOL_SOCKET, SO_TYPE, &reply_type,
                         &reply_type_size) == 0 &&
              reply_type == SOCK_SEQPACKET;
      const auto attempt = exec_attempts.find(request.exec_nonce);
      const bool authenticated = valid && attempt != exec_attempts.end() &&
                                 attempt->second.sender == sender;
      dr_exec_resource_reply_t reply{DR_EXEC_RESOURCE_MAGIC,
                                     DR_EXEC_RESOURCE_VERSION,
                                     DR_EXEC_RESOURCE_INVALID,
                                     request.exec_nonce,
                                     0,
                                     0,
                                     0};
      bool replied = false;
      if (authenticated && request.operation == DR_EXEC_RESOURCE_REGISTER &&
          !attempt->second.resources && !attempt->second.resource_gets &&
          request.resource_count &&
          request.resource_count <= DR_EXEC_RESOURCE_LIMIT &&
          received_files.size() == request.resource_count + 2) {
        std::vector<int> files(received_files.begin() + 1,
                               received_files.end());
        received_files.resize(1);
        auto resources =
            ct_exec_resources::accept(std::move(files), request.resource_count,
                                      request.manifest_size, worker, sender);
        if (resources) {
          attempt->second.resources = std::move(resources);
          reply.status = DR_EXEC_RESOURCE_OK;
        }
      } else if (authenticated && request.operation == DR_EXEC_RESOURCE_GET &&
                 received_files.size() == 1 && !request.resource_count &&
                 !request.manifest_size && attempt->second.resources &&
                 attempt->second.resource_gets < DR_EXEC_RESOURCE_GET_LIMIT) {
        // Repeated GET is only for a runtime self-relocation before client
        // initialization. The worker HELLO, not this early FD transfer,
        // consumes the nonce and its tracing policy.
        ++attempt->second.resource_gets;
        replied = attempt->second.resources->send(worker, request.exec_nonce);
      }
      if (!replied && worker >= 0)
        ct_exec_resource_reply(worker, reply);
      for (int fd : received_files)
        close(fd);
      continue;
    }
    if (received_files.size() > 1) {
      valid = false;
      for (size_t index = 1; index < received_files.size(); ++index)
        close(received_files[index]);
    }
    ct_analysis_broker_packet packet{};
    if (size_t(count) < sizeof(packet))
      valid = false;
    else {
      std::memcpy(&packet, bytes.data(), sizeof(packet));
      valid &= packet.size <= CT_ANALYSIS_BROKER_LIMIT &&
               size_t(count) == sizeof(packet) + packet.size;
    }
    if (valid && packet.operation == CT_ANALYSIS_BROKER_CONNECT &&
        worker >= 0 && packet.size == sizeof(uint64_t) && sender > 0) {
      uint64_t nonce;
      std::memcpy(&nonce, bytes.data() + sizeof(packet), sizeof(nonce));
      bool eligible = next_session == 0 && nonce == 0;
      ExecAttempt replacement;
      if (nonce) {
        const auto attempt = exec_attempts.find(nonce);
        if (attempt == exec_attempts.end() ||
            attempt->second.sender != sender) {
          close(worker);
          continue;
        }
        replacement = std::move(attempt->second);
        eligible = replacement.recording;
        // A task pidfd survives exec. Retire its old-image registrations only
        // once the authenticated winning exec connects; failed exec keeps them.
        suspension.commit_exec(sender);
        // Only the kernel's winning exec carries this nonce into its new
        // image. Other in-flight attempts belonged to threads it destroyed.
        for (auto entry = exec_attempts.begin(); entry != exec_attempts.end();)
          if (entry->second.sender == sender)
            entry = exec_attempts.erase(entry);
          else
            ++entry;
      }
      if (next_session == (UINT64_C(1) << 63) - 1) {
        close(worker);
        break;
      }
      const uint64_t assigned = ++next_session;
      if (nonce) {
        // A CLONE_VM child borrows the parent's analysis session until exec.
        // Its new image must not retire objects still used by that parent.
        // Trace closure below is separately scoped to the exec sender's PID.
        const auto previous = session_owners.find(replacement.session);
        if (previous != session_owners.end() && previous->second == sender) {
          objects.close_session(replacement.session);
          session_owners.erase(previous);
        }
      }
      session_owners.emplace(assigned, sender);
      // Successful exec ends the old image even when the replacement is not
      // recorded and will therefore never submit another trace event.
      if (nonce && trace.fd >= 0 &&
          !trace.begin_session(assigned, sender, replacement.session,
                               &replacement.timestamps)) {
        close(worker);
        break;
      }
      int host_control = -1;
      uint64_t host_session = 0;
      if (!decompiler.worker_channel(host_control, host_session)) {
        close(worker);
        break;
      }
      const pid_t child = fork();
      if (child == 0) {
        close(control_fd);
        suspension.close_for_worker();
        objects.close_for_worker();
        decompiler.close_for_worker();
        ct_shared_host_init(host_control, host_session);
        if (trace.fd >= 0)
          close(trace.fd);
        action.sa_handler = SIG_DFL;
        if (sigaction(SIGCHLD, &action, nullptr) != 0)
          _exit(2);
        handshake.session = assigned;
        handshake.trace_origin_ns = trace.origin_ns;
        handshake.recording_allowed = eligible ? 1u : 0u;
        return worker;
      }
      close(host_control);
      decompiler.worker_started(host_session, child);
      close(worker);
      if (child < 0)
        break;
      continue;
    }
    if (valid && packet.operation == CT_ANALYSIS_BROKER_OBJECT_CONNECT) {
      const auto owner = session_owners.find(packet.session);
      if (worker < 0 || packet.size || owner == session_owners.end() ||
          owner->second != sender ||
          !objects.connect(worker, sender, packet.session)) {
        if (worker >= 0)
          close(worker);
      }
      continue;
    }
    if (valid && packet.operation == CT_ANALYSIS_BROKER_PREPARE_EXEC &&
        worker >= 0 && packet.session && packet.session <= next_session &&
        sender > 0) {
      ct_analysis_exec_header header{};
      bool complete = packet.size >= sizeof(header);
      if (complete) {
        std::memcpy(&header, bytes.data() + sizeof(packet), sizeof(header));
        complete = header.recording <= 1 &&
                   header.count <= (CT_ANALYSIS_BROKER_LIMIT - sizeof(header)) /
                                       sizeof(ct_exec_timestamp) &&
                   packet.size == sizeof(header) +
                                      header.count * sizeof(ct_exec_timestamp);
      }
      ExecAttempt attempt{sender, packet.session, header.recording != 0, {}};
      for (uint32_t index = 0; complete && index < header.count; ++index) {
        ct_exec_timestamp timestamp;
        std::memcpy(&timestamp,
                    bytes.data() + sizeof(packet) + sizeof(header) +
                        index * sizeof(timestamp),
                    sizeof(timestamp));
        complete =
            timestamp.track_token && timestamp.track_token <= INT64_MAX &&
            attempt.timestamps.emplace(timestamp.track_token, timestamp).second;
      }
      uint64_t nonce = 0;
      if (complete && next_exec_nonce != UINT64_MAX) {
        nonce = ++next_exec_nonce;
        exec_attempts.emplace(nonce, std::move(attempt));
      }
      ct_analysis_transfer(worker, &nonce, sizeof(nonce), true);
      close(worker);
      continue;
    }
    if (valid && packet.operation == CT_ANALYSIS_BROKER_EXEC_TIMESTAMPS &&
        worker >= 0 && packet.session && packet.session <= next_session &&
        sender > 0) {
      ct_analysis_exec_timestamps_header header{};
      bool complete = packet.size >= sizeof(header);
      if (complete) {
        std::memcpy(&header, bytes.data() + sizeof(packet), sizeof(header));
        complete = header.count &&
                   header.count <= (CT_ANALYSIS_BROKER_LIMIT - sizeof(header)) /
                                       sizeof(ct_exec_timestamp) &&
                   packet.size == sizeof(header) +
                                      header.count * sizeof(ct_exec_timestamp);
      }
      const auto attempt = exec_attempts.find(header.nonce);
      const bool authenticated = attempt != exec_attempts.end() &&
                                 attempt->second.sender == sender &&
                                 attempt->second.session == packet.session;
      complete &= authenticated;
      for (uint64_t index = 0; complete && index < header.count; ++index) {
        ct_exec_timestamp timestamp;
        std::memcpy(&timestamp,
                    bytes.data() + sizeof(packet) + sizeof(header) +
                        index * sizeof(timestamp),
                    sizeof(timestamp));
        complete =
            timestamp.track_token && timestamp.track_token <= INT64_MAX &&
            attempt->second.timestamps.emplace(timestamp.track_token, timestamp)
                .second;
      }
      // Invalid or duplicated records invalidate the complete attempt, so a
      // failed chunk can never leave a partially usable exec snapshot.
      if (!complete && authenticated)
        exec_attempts.erase(attempt);
      ct_analysis_transfer(worker, &complete, sizeof(complete), true);
      close(worker);
      continue;
    }
    if (valid && packet.operation == CT_ANALYSIS_BROKER_CANCEL_EXEC &&
        worker >= 0 && packet.size == sizeof(uint64_t) && packet.session &&
        packet.session <= next_session && sender > 0) {
      uint64_t nonce;
      std::memcpy(&nonce, bytes.data() + sizeof(packet), sizeof(nonce));
      const auto attempt = exec_attempts.find(nonce);
      bool accepted = attempt == exec_attempts.end() ||
                      (attempt->second.sender == sender &&
                       attempt->second.session == packet.session);
      if (accepted && attempt != exec_attempts.end())
        exec_attempts.erase(attempt);
      ct_analysis_transfer(worker, &accepted, sizeof(accepted), true);
      close(worker);
      continue;
    }
    if (valid && packet.operation == CT_ANALYSIS_BROKER_TRACE_FLUSH &&
        worker >= 0 && packet.size == 0 && packet.session &&
        packet.session <= next_session) {
      bool accepted = trace.fd >= 0;
      ct_analysis_transfer(worker, &accepted, sizeof(accepted), true);
      close(worker);
      continue;
    }
    if (worker >= 0)
      close(worker);
    if (!valid || trace.fd < 0 || !packet.session ||
        packet.session > next_session)
      break;
    auto parsed = llvm::json::parse(
        llvm::StringRef(bytes.data() + sizeof(packet), packet.size));
    if (!parsed) {
      llvm::consumeError(parsed.takeError());
      break;
    }
    auto *object = parsed->getAsObject();
    if (!object)
      break;
    if (packet.operation == CT_ANALYSIS_BROKER_TRACE_FOOTER) {
      if (trace.sessions.empty())
        trace.metadata = *object;
      trace.sessions[packet.session] = *object;
      if (!trace.write(""))
        break;
    } else if (packet.operation == CT_ANALYSIS_BROKER_TRACE_EVENT) {
      if (!trace.event(packet.session, std::move(*object), sender))
        break;
    } else
      break;
  }
  if (trace.fd >= 0)
    close(trace.fd);
  close(control_fd);
  return -1;
}

int main(int argc, char **argv) {
  if (argc == 4 && std::strcmp(argv[1], "--kernel-decompile-worker") == 0) {
    int descriptors[2];
    for (unsigned index = 0; index < 2; ++index) {
      char *end;
      const long descriptor = std::strtol(argv[index + 2], &end, 10);
      if (end == argv[index + 2] || *end || descriptor < 0 ||
          descriptor > INT32_MAX)
        return 2;
      descriptors[index] = int(descriptor);
    }
    return ct_kernel_decompile_worker(descriptors[0], descriptors[1]);
  }
  const bool detach = argc >= 3 && std::strcmp(argv[1], "--detach") == 0;
  const bool detached_broker =
      argc >= 3 && std::strcmp(argv[1], "--broker-detach") == 0;
  if ((!detached_broker && argc != (detach ? 3 : 2)) ||
      (detached_broker && argc != 3 && argc != 4 && argc != 5))
    return 2;
  const char *argument = argv[(detach || detached_broker) ? 2 : 1];
  char *end;
  long parsed = std::strtol(argument, &end, 10);
  if (end == argument || *end || parsed < 0 || parsed > INT32_MAX)
    return 2;
  int fd = int(parsed);
  int filename_tid = 0;
  if (detached_broker && argc == 5) {
    parsed = std::strtol(argv[4], &end, 10);
    if (end == argv[4] || *end || parsed <= 0 || parsed > INT32_MAX)
      return 2;
    filename_tid = int(parsed);
  }
  if (detached_broker) {
    // Enable credentials before the launcher observes a successful detach.
    // Packets queued before SO_PASSCRED is enabled carry an unusable PID 0.
    int credentials = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &credentials,
                   sizeof(credentials)) != 0)
      return 2;
  }
  if (detach || detached_broker) {
    pid_t child = fork();
    if (child < 0)
      return 2;
    if (child > 0)
      _exit(0);
    if (setsid() < 0)
      return 2;
  }
  if (detached_broker) {
    ct_analysis_worker_handshake handshake{};
    fd = broker(fd, argc >= 4 ? argv[3] : nullptr, filename_tid, handshake);
    if (fd < 0)
      return 0;
    if (!ct_analysis_transfer(fd, &handshake, sizeof(handshake), true))
      return 2;
  }
  const char *perfetto_only = std::getenv("CTRACE_PERFETTO_ONLY");
  if (perfetto_only && std::strcmp(perfetto_only, "1") == 0)
    ct_analysis_set_progress_callback(nullptr, nullptr);
  else
    ct_analysis_set_progress_callback(
        [](const ct_analysis_progress *progress, void *context) {
          const int socket = *static_cast<const int *>(context);
          ct_analysis_response response{CT_ANALYSIS_PROGRESS,
                                        sizeof(*progress)};
          if (!ct_analysis_transfer(socket, &response, sizeof(response),
                                    true) ||
              !ct_analysis_transfer(
                  socket, const_cast<ct_analysis_progress *>(progress),
                  sizeof(*progress), true))
            _exit(1);
        },
        const_cast<int *>(&fd));
  std::map<uint64_t, ct_analysis *> modules;
  uint64_t next_handle = 0;
  ct_analysis_request request;
  bool connected = true;
  while (connected && transfer(fd, &request, sizeof(request), false)) {
    std::string text(request.text_size, '\0');
    std::string maps(request.maps_size, '\0');
    if (!transfer(fd, text.data(), text.size(), false) ||
        !transfer(fd, maps.data(), maps.size(), false))
      break;
    if (request.operation == CT_ANALYSIS_FILESYSTEM) {
      if (request.handle || !text.empty() || !maps.empty() ||
          request.offset != 1 || !modules.empty())
        break;
      ct_analysis_set_filesystem([fd](ct_analysis_file_operation kind,
                                      const std::string &path) {
        ct_analysis_file_result result;
        ct_analysis_file_request file{};
        if (path.size() >= sizeof(file.path)) {
          result.error = std::make_error_code(std::errc::filename_too_long);
          return result;
        }
        file.operation = kind;
        std::memcpy(file.path, path.c_str(), path.size() + 1);
        ct_analysis_response header{CT_ANALYSIS_FILE, sizeof(file)};
        ct_analysis_file_reply reply{};
        if (!ct_analysis_transfer(fd, &header, sizeof(header), true) ||
            !ct_analysis_transfer(fd, &file, sizeof(file), true) ||
            !ct_analysis_transfer(fd, &reply, sizeof(reply), false) ||
            reply.error < 0 || reply.error > 4095 ||
            reply.text_size > sizeof(file.path))
          _exit(1);
        if (reply.error) {
          if (reply.text_size)
            _exit(1);
          result.error = std::error_code(reply.error, std::generic_category());
        } else if (kind == CT_ANALYSIS_FILE_READ ||
                   kind == CT_ANALYSIS_FILE_STATUS) {
          if (reply.text_size)
            _exit(1);
          result.descriptor = ct_analysis_receive_descriptor(fd);
          if (result.descriptor < 0)
            _exit(1);
        } else {
          if (!reply.text_size ||
              !ct_analysis_transfer(fd, file.path, reply.text_size, false) ||
              file.path[reply.text_size - 1] ||
              std::strlen(file.path) != reply.text_size - 1)
            _exit(1);
          result.path = file.path;
        }
        return result;
      });
      continue;
    }
    if (request.operation == CT_ANALYSIS_RUNTIME_IDENTITY) {
      if (text.empty() || maps.empty() || text.size() > 256 ||
          maps.size() > 256 || request.handle || request.offset)
        break;
      const auto identity = ct_cache_runtime_identity(text, maps);
      char digest[65]{};
      if (identity.size() == 64)
        memcpy(digest, identity.data(), identity.size());
      connected = transfer(fd, digest, sizeof(digest), true);
      continue;
    } else if (request.operation == CT_ANALYSIS_CONTENT_DIGEST) {
      if (!text.empty() || !maps.empty() || request.handle ||
          request.offset > 128 * 1024 * 1024)
        break;
      std::vector<unsigned char> bytes(request.offset);
      if (!transfer(fd, bytes.data(), bytes.size(), false))
        break;
      const auto digest = llvm::SHA256::hash(bytes);
      if (!transfer(fd, const_cast<unsigned char *>(digest.data()),
                    digest.size(), true))
        break;
      continue;
    } else if (request.operation == CT_ANALYSIS_CACHE_DIGEST) {
      if (text.empty() || !maps.empty() || request.handle || request.offset)
        break;
      std::string digest = ct_cache_key({text});
      digest.push_back('\0');
      connected = transfer(fd, digest.data(), digest.size(), true);
      continue;
    }
    if (request.operation == CT_ANALYSIS_CACHE_READ ||
        request.operation == CT_ANALYSIS_CACHE_WRITE) {
      // Recipes use file-relative offsets and original bytes, never live
      // register values, thread state, or process-specific executable code.
      if (text != "values" && text != "functions" &&
          text != "userspace-patches" && text != "userspace-flow" &&
          text != "dr-blocks" && text != "execution/objects" &&
          text != "execution/arm" && text != "execution/perfetto" &&
          text != "execution/full")
        break;
      const std::string key = ct_cache_key({text, maps});
      std::vector<unsigned char> bytes;
      if (request.operation == CT_ANALYSIS_CACHE_READ) {
        bool found = ct_cache_read(text.c_str(), key, bytes);
        uint32_t size = static_cast<uint32_t>(bytes.size());
        connected = transfer(fd, &found, sizeof(found), true) &&
                    transfer(fd, &size, sizeof(size), true) &&
                    transfer(fd, bytes.data(), bytes.size(), true);
      } else {
        if (request.offset > 128 * 1024 * 1024)
          break;
        bytes.resize(request.offset);
        if (!transfer(fd, bytes.data(), bytes.size(), false))
          break;
        ct_cache_write(text.c_str(), key, bytes);
        bool accepted = true;
        connected = transfer(fd, &accepted, sizeof(accepted), true);
      }
      continue;
    }
    if (request.operation == CT_ANALYSIS_SYNTAX) {
      if (request.offset > 2)
        break;
      ct_analysis_set_syntax((int)request.offset - 1);
      continue;
    }
    if (request.operation == CT_ANALYSIS_BYPASS) {
      if (request.offset > 1 || !modules.empty())
        break;
      ct_analysis_set_source_bypass(request.offset != 0);
      continue;
    }
    if (request.operation == CT_ANALYSIS_DISASSEMBLE) {
      ct_analysis_instruction instruction{};
      if (!transfer(fd, &instruction, sizeof(instruction), false))
        break;
      ct_analysis_disassembly result{};
      result.valid = ct_analysis_disassemble(
          request.offset, instruction.bytes, instruction.size, result.att,
          sizeof(result.att), result.intel, sizeof(result.intel));
      connected = transfer(fd, &result, sizeof(result), true);
      continue;
    }
    if (request.operation == CT_ANALYSIS_OPEN) {
      if (request.handle || request.offset > 2)
        break;
      ct_analysis_open_capture capture{};
      const bool replay = request.offset == 2;
      if (replay &&
          (!transfer(fd, &capture, sizeof(capture), false) ||
           (capture.present &
            ~uint32_t(CT_ANALYSIS_CAPTURE_MODULE | CT_ANALYSIS_CAPTURE_DEBUG |
                      CT_ANALYSIS_CAPTURE_SUPPLEMENT)) ||
           !memchr(capture.debug_file, 0, sizeof(capture.debug_file)) ||
           !memchr(capture.supplement_file, 0,
                   sizeof(capture.supplement_file)) ||
           !memchr(capture.identity, 0, sizeof(capture.identity))))
        break;
      const uint32_t present =
          replay ? capture.present : uint32_t(request.offset);
      std::array<int, 3> inputs{-1, -1, -1};
      bool received = true;
      for (size_t index = 0; index < inputs.size(); ++index)
        if (present & (1u << index)) {
          inputs[index] = ct_analysis_receive_descriptor(fd);
          if (inputs[index] < 0) {
            received = false;
            break;
          }
        }
      ct_analysis *analysis = nullptr;
      if (received) {
        const ct_analysis_file_bundle bundle{inputs[0],
                                             inputs[1],
                                             inputs[2],
                                             capture.debug_file,
                                             capture.supplement_file,
                                             capture.identity,
                                             capture.debug_bias_correction};
        analysis =
            replay
                ? ct_analysis_open_bundle(text.c_str(), maps.c_str(), &bundle)
                : ct_analysis_open_fd(text.c_str(), maps.c_str(), inputs[0]);
      }
      for (const int input : inputs)
        if (input >= 0)
          close(input);
      if (!received)
        break;
      ct_analysis_handle result{};
      result.handle = analysis ? ++next_handle : 0;
      result.has_dwarf = ct_analysis_has_dwarf(analysis);
      const int frozen = ct_analysis_module_file(analysis);
      result.has_module_descriptor = frozen >= 0;
      const int debug = ct_analysis_debug_file_descriptor(analysis);
      result.has_debug_descriptor = debug >= 0;
      const int supplement = ct_analysis_supplement_file_descriptor(analysis);
      result.has_supplement_descriptor = supplement >= 0;
      result.debug_bias_correction =
          ct_analysis_debug_bias_correction(analysis);
      std::snprintf(result.debug_file, sizeof(result.debug_file), "%s",
                    ct_analysis_debug_file(analysis));
      std::snprintf(result.supplement_file, sizeof(result.supplement_file),
                    "%s", ct_analysis_supplement_file(analysis));
      std::snprintf(result.soname, sizeof(result.soname), "%s",
                    ct_analysis_soname(analysis));
      std::snprintf(result.identity, sizeof(result.identity), "%s",
                    ct_analysis_identity(analysis));
      if (analysis)
        modules[result.handle] = analysis;
      connected =
          transfer(fd, &result, sizeof(result), true) &&
          (frozen < 0 || ct_analysis_send_descriptor(fd, frozen)) &&
          (debug < 0 || ct_analysis_send_descriptor(fd, debug)) &&
          (supplement < 0 || ct_analysis_send_descriptor(fd, supplement));
      continue;
    }
    auto module = modules.find(request.handle);
    if (module == modules.end())
      break;
    switch (request.operation) {
    case CT_ANALYSIS_CODE_PROOF:
    case CT_ANALYSIS_DECOMPILE_PROOF: {
      unsigned char *proof = nullptr;
      size_t size = 0;
      bool valid = request.operation == CT_ANALYSIS_CODE_PROOF
                       ? ct_analysis_code_proof(module->second, request.offset,
                                                &proof, &size)
                       : ct_analysis_decompile_proof(
                             module->second, request.offset,
                             text == "full"       ? CT_DECOMPILE_FULL
                             : text == "perfetto" ? CT_DECOMPILE_PERFETTO
                                                  : 0,
                             &proof, &size);
      uint32_t bytes = static_cast<uint32_t>(size);
      connected = transfer(fd, &valid, sizeof(valid), true) &&
                  transfer(fd, &bytes, sizeof(bytes), true) &&
                  transfer(fd, proof, size, true);
      std::free(proof);
      break;
    }
    case CT_ANALYSIS_DECOMPILE_DISPLAY: {
      ct_decompiled_display display{};
      bool valid = ct_analysis_decompile_display(
          module->second, request.offset,
          text == "full"       ? CT_DECOMPILE_FULL
          : text == "perfetto" ? CT_DECOMPILE_PERFETTO
                               : 0,
          &display);
      connected = transfer(fd, &valid, sizeof(valid), true) &&
                  transfer(fd, &display, sizeof(display), true);
      break;
    }
    case CT_ANALYSIS_DECOMPILE: {
      ct_decompiled_statement statement{};
      bool valid =
          ct_analysis_decompile(module->second, request.offset,
                                text == "full"       ? CT_DECOMPILE_FULL
                                : text == "perfetto" ? CT_DECOMPILE_PERFETTO
                                                     : 0,
                                &statement);
      connected = transfer(fd, &valid, sizeof(valid), true) &&
                  transfer(fd, &statement, sizeof(statement), true);
      break;
    }
    case CT_ANALYSIS_DECOMPILE_VARIABLES: {
      auto variables = std::make_unique<ct_decompiled_variables>();
      bool valid = ct_analysis_decompile_variables(
          module->second, request.offset,
          text == "full"       ? CT_DECOMPILE_FULL
          : text == "perfetto" ? CT_DECOMPILE_PERFETTO
                               : 0,
          variables.get());
      connected = transfer(fd, &valid, sizeof(valid), true) &&
                  transfer(fd, variables.get(), sizeof(*variables), true);
      break;
    }
    case CT_ANALYSIS_DECOMPILE_ERROR: {
      const char *error = ct_analysis_decompile_error(module->second);
      std::string message = error ? error : "";
      if (message.size() >= CT_DECOMPILE_ERROR_CAPACITY)
        message.resize(CT_DECOMPILE_ERROR_CAPACITY - 1);
      uint32_t size = static_cast<uint32_t>(message.size());
      connected = transfer(fd, &size, sizeof(size), true) &&
                  transfer(fd, message.data(), size, true);
      break;
    }
    case CT_ANALYSIS_LOOKUP: {
      ct_location location;
      ct_analysis_lookup(module->second, request.offset, &location);
      connected = send_record(fd, &location, sizeof(location));
      break;
    }
    case CT_ANALYSIS_LOOKUP_ARMING: {
      auto location = std::make_unique<ct_location>();
      ct_analysis_lookup_arming(module->second, request.offset, location.get());
      ct_arming_location arming;
      ct_arming_location_pack(&arming, location.get());
      connected = send_record(fd, &arming, sizeof(arming));
      break;
    }
    case CT_ANALYSIS_LOOKUP_BATCH: {
      if (!request.offset || request.offset > CT_LOCATION_BATCH_COUNT_LIMIT ||
          !maps.empty() || (text != "arming" && text != "full")) {
        connected = false;
        break;
      }
      std::array<uint64_t, CT_LOCATION_BATCH_COUNT_LIMIT> offsets{};
      if (!transfer(fd, offsets.data(), request.offset * sizeof(offsets[0]),
                    false)) {
        connected = false;
        break;
      }
      unsigned char *data = nullptr;
      size_t size = 0;
      bool valid = ct_analysis_lookup_batch(module->second, offsets.data(),
                                            request.offset, text == "arming",
                                            &data, &size);
      std::unique_ptr<unsigned char, decltype(&std::free)> owner(data,
                                                                 std::free);
      uint32_t bytes = size;
      connected = transfer(fd, &valid, sizeof(valid), true) &&
                  transfer(fd, &bytes, sizeof(bytes), true) &&
                  transfer(fd, data, bytes, true);
      break;
    }
    case CT_ANALYSIS_ALLOWED: {
      bool allowed = ct_analysis_source_allowed(module->second, request.offset);
      connected = transfer(fd, &allowed, sizeof(allowed), true);
      break;
    }
    case CT_ANALYSIS_ERROR: {
      const char *error = ct_analysis_source_error(module->second);
      std::string message = error ? error : "";
      uint32_t size = (uint32_t)message.size();
      connected = transfer(fd, &size, sizeof(size), true) &&
                  transfer(fd, message.data(), size, true);
      break;
    }
    case CT_ANALYSIS_FUNCTIONS: {
      std::vector<ct_analysis_function> functions;
      ct_analysis_functions(
          module->second,
          [](uint64_t offset, const char *name, void *context) {
            ct_analysis_function function{};
            function.offset = offset;
            std::snprintf(function.name, sizeof(function.name), "%s", name);
            static_cast<std::vector<ct_analysis_function> *>(context)
                ->push_back(function);
          },
          &functions);
      uint32_t count = (uint32_t)functions.size();
      connected = transfer(fd, &count, sizeof(count), true) &&
                  transfer(fd, functions.data(),
                           count * sizeof(ct_analysis_function), true);
      break;
    }
    case CT_ANALYSIS_INLINE_SCOPES: {
      std::vector<ct_analysis_inline_scope> scopes;
      ct_analysis_inline_scopes(
          module->second,
          [](uint64_t begin, uint64_t end, const char *name, void *context) {
            ct_analysis_inline_scope scope{};
            if (std::strlen(name) >= sizeof(scope.linkage_name))
              return;
            scope.begin_offset = begin;
            scope.end_offset = end;
            std::memcpy(scope.linkage_name, name, std::strlen(name) + 1);
            static_cast<std::vector<ct_analysis_inline_scope> *>(context)
                ->push_back(scope);
          },
          &scopes);
      uint32_t count = (uint32_t)scopes.size();
      connected = transfer(fd, &count, sizeof(count), true) &&
                  transfer(fd, scopes.data(),
                           count * sizeof(ct_analysis_inline_scope), true);
      break;
    }
    case CT_ANALYSIS_OBSERVATION_BOUNDARIES: {
      std::vector<uint64_t> offsets;
      bool complete = ct_analysis_observation_boundaries(
          module->second,
          [](uint64_t offset, void *context) {
            static_cast<std::vector<uint64_t> *>(context)->push_back(offset);
          },
          &offsets);
      if (offsets.size() > (128 * 1024 * 1024) / sizeof(uint64_t))
        complete = false;
      if (!complete)
        offsets.clear();
      uint32_t count = static_cast<uint32_t>(offsets.size());
      connected =
          transfer(fd, &complete, sizeof(complete), true) &&
          transfer(fd, &count, sizeof(count), true) &&
          transfer(fd, offsets.data(), offsets.size() * sizeof(uint64_t), true);
      break;
    }
    case CT_ANALYSIS_FLOW: {
      struct FlowResponse {
        std::vector<ct_analysis_flow_boundary> boundaries;
        std::vector<ct_flow_region> regions;
        std::vector<ct_flow_switch> switches;
      } response;
      ct_flow_range range{};
      ct_analysis_flow_header header{};
      header.valid = ct_analysis_flow(
          module->second, request.offset, &range,
          [](uint64_t offset, uint32_t roles, uint64_t group_offset,
             void *context) {
            ct_analysis_flow_boundary boundary{};
            boundary.offset = offset;
            boundary.group_offset = group_offset;
            boundary.roles = roles;
            static_cast<FlowResponse *>(context)->boundaries.push_back(
                boundary);
          },
          [](const ct_flow_region *region, void *context) {
            static_cast<FlowResponse *>(context)->regions.push_back(*region);
          },
          [](const ct_flow_switch *region, void *context) {
            static_cast<FlowResponse *>(context)->switches.push_back(*region);
          },
          &response);
      header.begin_offset = range.begin_offset;
      header.end_offset = range.end_offset;
      header.complete = range.complete;
      header.bounded = range.bounded;
      header.count = (uint32_t)response.boundaries.size();
      header.region_count = (uint32_t)response.regions.size();
      header.switch_count = (uint32_t)response.switches.size();
      connected =
          transfer(fd, &header, sizeof(header), true) &&
          transfer(fd, response.boundaries.data(),
                   response.boundaries.size() *
                       sizeof(ct_analysis_flow_boundary),
                   true) &&
          transfer(fd, response.regions.data(),
                   response.regions.size() * sizeof(ct_flow_region), true) &&
          transfer(fd, response.switches.data(),
                   response.switches.size() * sizeof(ct_flow_switch), true);
      break;
    }
    case CT_ANALYSIS_CODE_GRAPH: {
      struct CodeGraphResponse {
        std::vector<ct_flow_instruction> instructions;
        std::vector<ct_flow_edge> edges;
      } response;
      ct_analysis_code_graph_header header{};
      header.entry_offset = request.offset;
      header.valid = ct_analysis_code_graph(
          module->second, request.offset, &header.range,
          [](const ct_flow_instruction *instruction, void *context) {
            static_cast<CodeGraphResponse *>(context)->instructions.push_back(
                *instruction);
          },
          [](const ct_flow_edge *edge, void *context) {
            static_cast<CodeGraphResponse *>(context)->edges.push_back(*edge);
          },
          &response);
      if (response.instructions.size() > CT_FLOW_GRAPH_INSTRUCTION_LIMIT ||
          response.edges.size() > CT_FLOW_GRAPH_EDGE_LIMIT)
        header.valid = false;
      if (!header.valid) {
        header.range = {};
        response.instructions.clear();
        response.edges.clear();
      }
      header.instruction_count =
          static_cast<uint32_t>(response.instructions.size());
      header.edge_count = static_cast<uint32_t>(response.edges.size());
      connected =
          transfer(fd, &header, sizeof(header), true) &&
          transfer(fd, response.instructions.data(),
                   response.instructions.size() * sizeof(ct_flow_instruction),
                   true) &&
          transfer(fd, response.edges.data(),
                   response.edges.size() * sizeof(ct_flow_edge), true);
      break;
    }
    case CT_ANALYSIS_CLOSE:
      ct_analysis_close(module->second);
      modules.erase(module);
      break;
    default:
      connected = false;
      break;
    }
  }
  for (const auto &[handle, analysis] : modules)
    ct_analysis_close(analysis);
  close(fd);
}
