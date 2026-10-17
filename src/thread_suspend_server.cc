#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <utility>

#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "thread_suspend_server.h"

// PIDFD_GET_INFO's initial, 64-byte Linux ABI. Using the initial extent avoids
// requiring newer libc headers; a kernel without this proof returns ENOTTY.
struct SuspendPidInfo {
  uint64_t mask, cgroup;
  uint32_t pid, tgid, ppid, credentials[8];
  int32_t exit_code;
};
static_assert(sizeof(SuspendPidInfo) == 64);
static_assert(sizeof(siginfo_t) == DR_THREAD_SUSPEND_PAYLOAD_SIZE);
static_assert(sizeof(dr_thread_suspend_request_t) == 192);
static_assert(sizeof(dr_thread_suspend_reply_t) == 48);

struct ct_thread_suspend_broker::State {
  struct Realm {
    uint32_t signal;
    std::array<unsigned char, DR_THREAD_SUSPEND_PAYLOAD_SIZE> payload;
  };
  struct Task {
    int channel = -1, pidfd = -1, owner = -1, acknowledgment = -1;
    int64_t process = 0;
    uint64_t realm = 0, sequence = 0, pending_signal = 0;
    bool released = false, quiesced = false, invalid = false, departed = false;
    std::optional<dr_thread_suspend_reply_t> barrier_reply;
    void close_routing() {
      invalid = true;
      for (int *fd : {&channel, &acknowledgment})
        if (*fd >= 0)
          close(std::exchange(*fd, -1));
      pending_signal = 0;
      barrier_reply.reset();
    }
    void mark_departed() {
      departed = true;
      quiesced = true;
      close_routing();
      for (int *fd : {&pidfd, &owner})
        if (*fd >= 0)
          close(std::exchange(*fd, -1));
    }
    uint32_t status() {
      if (departed)
        return DR_THREAD_SUSPEND_DEPARTED;
      if (pidfd < 0)
        return DR_THREAD_SUSPEND_UNKNOWN;
      pollfd target{pidfd, POLLIN, 0};
      int result;
      do {
        result = poll(&target, 1, 0);
      } while (result < 0 && errno == EINTR);
      if (result > 0 && (target.revents & POLLIN)) {
        mark_departed();
        return DR_THREAD_SUSPEND_DEPARTED;
      }
      return result == 0 && !released && !invalid && channel >= 0
                 ? DR_THREAD_SUSPEND_LIVE
                 : DR_THREAD_SUSPEND_UNKNOWN;
    }
    ~Task() {
      for (int fd : {channel, pidfd, owner, acknowledgment})
        if (fd >= 0)
          close(fd);
    }
  };
  uint64_t next_realm = 0, next_task = 0, next_signal = 0;
  // An initialized descendant can register after the last registered parent
  // exits. Preserve realm capabilities until the family service itself ends.
  std::map<uint64_t, Realm> realms;
  // Runtime context cleanup explicitly forgets registrations. A closed channel
  // alone cannot retire an exec proof: another CLONE_VM group may still own the
  // old record. Handles are never reused, and final family teardown reclaims
  // all remaining records, including tasks killed without runtime cleanup.
  std::map<uint64_t, std::unique_ptr<Task>> tasks;
};

static bool suspend_reply(int fd, const dr_thread_suspend_reply_t &reply) {
  ssize_t sent;
  do {
    sent = send(fd, &reply, sizeof(reply), MSG_NOSIGNAL | MSG_DONTWAIT);
  } while (sent < 0 && errno == EINTR);
  return sent == sizeof(reply);
}

static bool suspend_pid_info(int fd, SuspendPidInfo &info) {
  info = {};
  info.mask = 3; // PID and credential fields, both required for registration.
  return ioctl(fd, _IOWR(0xff, 11, SuspendPidInfo), &info) == 0 &&
         (info.mask & 3) == 3 && info.pid && info.tgid;
}

static bool suspend_payload_valid(const dr_thread_suspend_request_t &request) {
  if (!request.signal_number || request.signal_number >= NSIG ||
      request.signal_number == SIGKILL || request.signal_number == SIGSTOP ||
      request.payload_size != DR_THREAD_SUSPEND_PAYLOAD_SIZE)
    return false;
  // The Linux nudge overlays si_errno with the marker, version and SUSPEND
  // flag. si_pid/si_uid are rewritten across PID/user namespaces and cannot
  // carry identity. The template's remaining fields start at zero; the broker
  // adds the delivery ticket in si_value when sending a notification.
  uint32_t header[3];
  std::memcpy(header, request.suspend_payload, sizeof(header));
  return header[0] == request.signal_number &&
         header[1] == DR_THREAD_SUSPEND_ERRNO &&
         header[2] == uint32_t(SI_QUEUE) &&
         std::all_of(request.suspend_payload + sizeof(header),
                     request.suspend_payload + sizeof(request.suspend_payload),
                     [](unsigned char value) { return value == 0; });
}

ct_thread_suspend_broker::ct_thread_suspend_broker()
    : state(std::make_unique<State>()) {}
ct_thread_suspend_broker::~ct_thread_suspend_broker() = default;

void ct_thread_suspend_broker::connect(
    const dr_thread_suspend_request_t &request, std::vector<int> files,
    int64_t sender) {
  auto task = std::make_unique<State::Task>();
  if (!files.empty())
    task->channel = std::exchange(files[0], -1);
  if (files.size() > 1)
    task->pidfd = std::exchange(files[1], -1);
  if (files.size() > 2)
    task->acknowledgment = std::exchange(files[2], -1);
  for (int fd : files)
    if (fd >= 0)
      close(fd);
  if (task->channel < 0)
    return;
  dr_thread_suspend_reply_t reply{DR_THREAD_SUSPEND_MAGIC,
                                  DR_THREAD_SUSPEND_VERSION,
                                  DR_THREAD_SUSPEND_INVALID,
                                  request.sequence,
                                  request.realm,
                                  request.task,
                                  EINVAL,
                                  0};
  int type = 0;
  socklen_t size = sizeof(type);
  const bool channel =
      getsockopt(task->channel, SOL_SOCKET, SO_TYPE, &type, &size) == 0 &&
      size == sizeof(type) && type == SOCK_SEQPACKET;
  if (!channel)
    return;
  const auto reject = [&](uint32_t status, int error) {
    reply.status = status;
    reply.system_error = error;
    suspend_reply(task->channel, reply);
  };
  if (files.size() != 3 || task->pidfd < 0 || task->acknowledgment < 0 ||
      sender <= 0 || request.magic != DR_THREAD_SUSPEND_MAGIC ||
      request.version != DR_THREAD_SUSPEND_VERSION ||
      request.operation != DR_THREAD_SUSPEND_REGISTER || !request.sequence ||
      request.task || !request.runtime_id || !request.runtime_group ||
      !suspend_payload_valid(request)) {
    reject(DR_THREAD_SUSPEND_INVALID, EINVAL);
    return;
  }
  // The signal handler writes one ticket to a dedicated, nonsemaphore eventfd.
  // No normal RPC response or socket backpressure can consume that write.
  // Prove the descriptor kind before performing any read on an untrusted FD.
  char path[64], link[64], information[1024];
  std::snprintf(path, sizeof(path), "/proc/self/fd/%d", task->acknowledgment);
  const ssize_t linked = readlink(path, link, sizeof(link));
  const char eventfd_name[] = "anon_inode:[eventfd]";
  const int flags = fcntl(task->acknowledgment, F_GETFL);
  if (linked != sizeof(eventfd_name) - 1 ||
      std::memcmp(link, eventfd_name, sizeof(eventfd_name) - 1) || flags < 0 ||
      !(flags & O_NONBLOCK)) {
    reject(DR_THREAD_SUSPEND_INVALID, EINVAL);
    return;
  }
  std::snprintf(path, sizeof(path), "/proc/self/fdinfo/%d",
                task->acknowledgment);
  const int info = open(path, O_RDONLY | O_CLOEXEC);
  ssize_t count = -1;
  if (info >= 0) {
    do {
      count = read(info, information, sizeof(information) - 1);
    } while (count < 0 && errno == EINTR);
    close(info);
  }
  if (count <= 0) {
    reject(DR_THREAD_SUSPEND_UNAVAILABLE, EOPNOTSUPP);
    return;
  }
  information[count] = 0;
  const char *semaphore = std::strstr(information, "eventfd-semaphore:");
  unsigned value = 1;
  if (!semaphore ||
      std::sscanf(semaphore, "eventfd-semaphore: %u", &value) != 1 || value) {
    reject(DR_THREAD_SUSPEND_INVALID, EINVAL);
    return;
  }
  uint64_t unused;
  do {
    count = read(task->acknowledgment, &unused, sizeof(unused));
  } while (count < 0 && errno == EINTR);
  if (count >= 0 || errno != EAGAIN) {
    reject(DR_THREAD_SUSPEND_INVALID, EINVAL);
    return;
  }
  ucred peer{};
  size = sizeof(peer);
  if (getsockopt(task->channel, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
      size != sizeof(peer) || peer.pid != sender) {
    reject(DR_THREAD_SUSPEND_UNAUTHORIZED, EPERM);
    return;
  }
  size = sizeof(task->owner);
  if (getsockopt(task->channel, SOL_SOCKET, SO_PEERPIDFD, &task->owner,
                 &size) ||
      size != sizeof(task->owner) || task->owner < 0 ||
      fcntl(task->owner, F_SETFD, FD_CLOEXEC) < 0) {
    reject(DR_THREAD_SUSPEND_UNAVAILABLE, errno ? errno : EOPNOTSUPP);
    return;
  }
  SuspendPidInfo owner{}, target{};
  if (!suspend_pid_info(task->owner, owner) ||
      !suspend_pid_info(task->pidfd, target)) {
    reject(DR_THREAD_SUSPEND_UNAVAILABLE, errno ? errno : EOPNOTSUPP);
    return;
  }
  if (owner.tgid != sender || target.tgid != owner.tgid) {
    reject(DR_THREAD_SUSPEND_UNAUTHORIZED, EPERM);
    return;
  }
  pollfd alive[]{{task->pidfd, POLLIN, 0}, {task->owner, POLLIN, 0}};
  int polled;
  do {
    polled = poll(alive, 2, 0);
  } while (polled < 0 && errno == EINTR);
  if (polled != 0) {
    reject(DR_THREAD_SUSPEND_DEAD, ESRCH);
    return;
  }
  int enabled = 1;
  if (setsockopt(task->channel, SOL_SOCKET, SO_PASSCRED, &enabled,
                 sizeof(enabled)) < 0) {
    reject(DR_THREAD_SUSPEND_UNAVAILABLE, errno);
    return;
  }
  auto realm = state->realms.find(request.realm);
  if (request.realm &&
      (realm == state->realms.end() ||
       realm->second.signal != request.signal_number ||
       std::memcmp(realm->second.payload.data(), request.suspend_payload,
                   sizeof(request.suspend_payload)))) {
    reject(DR_THREAD_SUSPEND_UNAUTHORIZED, EPERM);
    return;
  }
  if (state->next_task == UINT64_MAX ||
      (!request.realm && state->next_realm == UINT64_MAX)) {
    reject(DR_THREAD_SUSPEND_UNAVAILABLE, EOVERFLOW);
    return;
  }
  if (!request.realm) {
    State::Realm created{};
    created.signal = request.signal_number;
    std::memcpy(created.payload.data(), request.suspend_payload,
                sizeof(request.suspend_payload));
    realm = state->realms.emplace(++state->next_realm, created).first;
  }
  const uint64_t identity = ++state->next_task;
  task->process = sender;
  task->realm = realm->first;
  task->sequence = request.sequence;
  reply.status = DR_THREAD_SUSPEND_OK;
  reply.system_error = 0;
  reply.realm = task->realm;
  reply.task = identity;
  const auto published = state->tasks.emplace(identity, std::move(task)).first;
  if (!suspend_reply(published->second->channel, reply)) {
    state->tasks.erase(published);
    // No descendant can hold the new realm capability if its first atomic
    // registration reply was never sent. Existing realms retain their lifetime.
    if (!request.realm)
      state->realms.erase(reply.realm);
  }
}

void ct_thread_suspend_broker::append_poll(
    std::vector<pollfd> &descriptors) const {
  for (const auto &[id, task] : state->tasks)
    for (int fd :
         {task->channel, task->owner, task->acknowledgment, task->pidfd})
      if (fd >= 0)
        descriptors.push_back({fd, POLLIN, 0});
}

void ct_thread_suspend_broker::service(const std::vector<pollfd> &descriptors) {
  const auto events = [&](int fd) {
    if (fd < 0)
      return short(0);
    const auto found =
        std::find_if(descriptors.begin(), descriptors.end(),
                     [&](const pollfd &item) { return item.fd == fd; });
    return found == descriptors.end() ? short(0) : found->revents;
  };
  const auto acknowledge = [](State::Task &task) {
    uint64_t ticket;
    ssize_t count;
    do {
      count = read(task.acknowledgment, &ticket, sizeof(ticket));
    } while (count < 0 && errno == EINTR);
    if (count < 0 && errno == EAGAIN)
      return true;
    if (count != sizeof(ticket) || !task.pending_signal ||
        ticket != task.pending_signal) {
      task.invalid = true;
      return false;
    }
    task.pending_signal = 0;
    if (task.barrier_reply) {
      const bool replied = suspend_reply(task.channel, *task.barrier_reply);
      task.barrier_reply.reset();
      if (!replied) {
        task.invalid = true;
        return false;
      }
    }
    return true;
  };
  for (auto position = state->tasks.begin(); position != state->tasks.end();) {
    auto &task = *position->second;
    // POLLIN on the exact thread pidfd is a kernel lifetime proof. Other
    // readiness bits, owner/channel loss and bad ACKs only disable routing.
    if (events(task.pidfd))
      task.status();
    if (task.invalid || events(task.owner) ||
        (events(task.acknowledgment) && !acknowledge(task)) ||
        (events(task.channel) & (POLLERR | POLLHUP | POLLNVAL))) {
      task.close_routing();
      ++position;
      continue;
    }
    if (!(events(task.channel) & POLLIN)) {
      ++position;
      continue;
    }
    dr_thread_suspend_request_t request{};
    iovec vector{&request, sizeof(request)};
    union {
      cmsghdr alignment;
      unsigned char
          bytes[CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(4 * sizeof(int))];
    } ancillary{};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    ssize_t count;
    do {
      count = recvmsg(task.channel, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      ++position;
      continue;
    }
    if (count <= 0) {
      task.close_routing();
      ++position;
      continue;
    }
    bool valid = count == sizeof(request) &&
                 !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    int64_t sender = 0;
    for (auto *header = CMSG_FIRSTHDR(&message); header;
         header = CMSG_NXTHDR(&message, header)) {
      if (header->cmsg_level == SOL_SOCKET &&
          header->cmsg_type == SCM_CREDENTIALS &&
          header->cmsg_len == CMSG_LEN(sizeof(ucred))) {
        ucred peer{};
        std::memcpy(&peer, CMSG_DATA(header), sizeof(peer));
        valid &= sender == 0;
        sender = peer.pid;
      } else {
        valid = false;
        if (header->cmsg_level == SOL_SOCKET &&
            header->cmsg_type == SCM_RIGHTS && header->cmsg_len >= CMSG_LEN(0))
          for (size_t index = 0;
               index < (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
               ++index) {
            int fd;
            std::memcpy(&fd, CMSG_DATA(header) + index * sizeof(fd),
                        sizeof(fd));
            close(fd);
          }
      }
    }
    valid &= request.magic == DR_THREAD_SUSPEND_MAGIC &&
             request.version == DR_THREAD_SUSPEND_VERSION &&
             request.sequence > task.sequence && !request.runtime_id &&
             !request.runtime_group && !request.signal_number &&
             !request.payload_size &&
             std::all_of(std::begin(request.suspend_payload),
                         std::end(request.suspend_payload),
                         [](unsigned char value) { return value == 0; });
    dr_thread_suspend_reply_t reply{DR_THREAD_SUSPEND_MAGIC,
                                    DR_THREAD_SUSPEND_VERSION,
                                    DR_THREAD_SUSPEND_INVALID,
                                    request.sequence,
                                    request.realm,
                                    request.task,
                                    EINVAL,
                                    0};
    bool forget_caller = false;
    if (valid && sender != task.process) {
      reply.status = DR_THREAD_SUSPEND_UNAUTHORIZED;
      reply.system_error = EPERM;
    } else if (valid) {
      task.sequence = request.sequence;
      if (request.realm != task.realm) {
        reply.status = DR_THREAD_SUSPEND_UNAUTHORIZED;
        reply.system_error = EPERM;
      } else if (request.operation == DR_THREAD_SUSPEND_STATUS ||
                 request.operation == DR_THREAD_SUSPEND_FORGET) {
        const auto target = state->tasks.find(request.task);
        if (target != state->tasks.end() &&
            target->second->realm != task.realm) {
          reply.status = DR_THREAD_SUSPEND_UNAUTHORIZED;
          reply.system_error = EPERM;
        } else if (request.operation == DR_THREAD_SUSPEND_STATUS) {
          reply.status = target == state->tasks.end()
                             ? uint32_t(DR_THREAD_SUSPEND_UNKNOWN)
                             : target->second->status();
          reply.system_error = 0;
        } else {
          reply.status = DR_THREAD_SUSPEND_OK;
          reply.system_error = 0;
          if (target == position)
            forget_caller = true;
          else if (target != state->tasks.end())
            state->tasks.erase(target);
        }
      } else if ((request.operation == DR_THREAD_SUSPEND_RELEASE ||
                  (request.operation == DR_THREAD_SUSPEND_QUIESCE &&
                   !task.released)) &&
                 request.task == position->first) {
        task.released |= request.operation == DR_THREAD_SUSPEND_RELEASE;
        task.quiesced = true;
        reply.status = DR_THREAD_SUSPEND_OK;
        reply.system_error = 0;
        // Stop new sends immediately. The reply proves both this exclusion and
        // consumption of any previously queued notification by the handler.
        if (!task.departed && !acknowledge(task)) {
          task.close_routing();
          ++position;
          continue;
        }
        if (task.pending_signal) {
          // A cleanup retry on this caller-owned channel supersedes an older
          // timed-out barrier; it never creates another signal notification.
          task.barrier_reply = reply;
          ++position;
          continue;
        }
      } else if (request.operation == DR_THREAD_SUSPEND_RESUME &&
                 request.task == position->first) {
        if (task.released || task.departed) {
          reply.status = DR_THREAD_SUSPEND_DEAD;
          reply.system_error = ESRCH;
        } else if (task.barrier_reply) {
          reply.status = DR_THREAD_SUSPEND_UNAVAILABLE;
          reply.system_error = EBUSY;
        } else {
          task.quiesced = false;
          reply.status = DR_THREAD_SUSPEND_OK;
          reply.system_error = 0;
        }
      } else if (request.operation == DR_THREAD_SUSPEND_SEND &&
                 !task.released) {
        const auto target = state->tasks.find(request.task);
        if (target == state->tasks.end() || target->second->released ||
            target->second->invalid || target->second->departed) {
          reply.status = DR_THREAD_SUSPEND_DEAD;
          reply.system_error = ESRCH;
        } else if (target->second->realm != task.realm) {
          reply.status = DR_THREAD_SUSPEND_UNAUTHORIZED;
          reply.system_error = EPERM;
        } else if (target->second->quiesced) {
          reply.status = DR_THREAD_SUSPEND_UNAVAILABLE;
          reply.system_error = EBUSY;
        } else {
          // An ACK can arrive after poll took its readiness snapshot. Consume
          // it here as well: coalescing with an already consumed notification
          // would lose a new suspend request.
          auto &recipient = *target->second;
          if (!acknowledge(recipient)) {
            reply.status = DR_THREAD_SUSPEND_UNAVAILABLE;
            reply.system_error = EPROTO;
          } else if (recipient.pending_signal) {
            reply.status = DR_THREAD_SUSPEND_OK;
            reply.system_error = 0;
          } else if (state->next_signal == UINT64_MAX - 1) {
            reply.status = DR_THREAD_SUSPEND_UNAVAILABLE;
            reply.system_error = EOVERFLOW;
          } else {
            const auto &realm = state->realms.at(task.realm);
            siginfo_t payload{};
            std::memcpy(&payload, realm.payload.data(), sizeof(payload));
            const uint64_t ticket = ++state->next_signal;
            // Linux x86-64 si_value; unlike si_pid/si_uid it is not rewritten
            // when delivered across namespace boundaries.
            std::memcpy(reinterpret_cast<unsigned char *>(&payload) + 24,
                        &ticket, sizeof(ticket));
            // Linux PIDFD_SIGNAL_THREAD explicitly prevents group-wide
            // delivery.
            const long delivered =
                syscall(SYS_pidfd_send_signal, target->second->pidfd,
                        realm.signal, &payload, 1u);
            reply.system_error = delivered == 0 ? 0 : errno;
            reply.status = delivered == 0   ? DR_THREAD_SUSPEND_OK
                           : errno == ESRCH ? DR_THREAD_SUSPEND_DEAD
                                            : DR_THREAD_SUSPEND_UNAVAILABLE;
            if (delivered == 0)
              recipient.pending_signal = ticket;
          }
        }
      }
    }
    if (!suspend_reply(task.channel, reply))
      task.close_routing();
    if (forget_caller)
      position = state->tasks.erase(position);
    else
      ++position;
  }
}

void ct_thread_suspend_broker::commit_exec(int64_t sender) {
  for (auto &[id, task] : state->tasks)
    if (task->process == sender)
      task->mark_departed();
}

void ct_thread_suspend_broker::close_for_worker() {
  state->tasks.clear();
  state->realms.clear();
}
