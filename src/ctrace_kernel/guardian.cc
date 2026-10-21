// SPDX-License-Identifier: MIT

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "guardian.hh"
#include "kctrace/contract.h"

static constexpr int guardian_status_interval_ms = 100;

static int guardian_main(int owner, int control,
                         const kctrace_prepare &prepared) {
  // Move descriptors out of the fixed private range before closing inherited
  // state. This also handles a collector that originally occupied fd 3 or 4.
  const int saved_owner = fcntl(owner, F_DUPFD_CLOEXEC, 8);
  const int saved_control = fcntl(control, F_DUPFD_CLOEXEC, 8);
  if (saved_owner < 0 || saved_control < 0) {
    const int failure = errno;
    (void)send(control, &failure, sizeof(failure), MSG_NOSIGNAL);
    return 1;
  }
  if (dup3(saved_owner, 3, O_CLOEXEC) < 0 ||
      dup3(saved_control, 4, O_CLOEXEC) < 0) {
    const int failure = errno;
    (void)send(saved_control, &failure, sizeof(failure), MSG_NOSIGNAL);
    return 1;
  }
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  if (syscall(SYS_close_range, 5u, ~0u, 0) != 0 || setsid() < 0) {
    const int failure = errno;
    (void)send(4, &failure, sizeof(failure), MSG_NOSIGNAL);
    return 1;
  }
  owner = 3;
  control = 4;
  const int observer = open("/dev/kctrace", O_RDONLY | O_CLOEXEC);
  kctrace_observe observed{};
  observed.size = sizeof(observed);
  std::memcpy(observed.contract_sha256, kctrace_contract_hash,
              KCTRACE_HASH_SIZE);
  observed.session_id = prepared.session_id;
  std::memcpy(observed.session_nonce, prepared.session_nonce,
              sizeof(observed.session_nonce));
  int failure = observer < 0 ? errno : 0;
  if (!failure && ioctl(observer, KCTRACE_IOC_OBSERVE, &observed) != 0)
    failure = errno;
  if (!failure && (observed.status.size != sizeof(observed.status) ||
                   std::memcmp(observed.status.contract_sha256,
                               kctrace_contract_hash, KCTRACE_HASH_SIZE) ||
                   observed.status.session_id != prepared.session_id ||
                   observed.status.state != KCTRACE_STATE_PREPARED))
    failure = EPROTO;
  if (send(control, &failure, sizeof(failure), MSG_NOSIGNAL) !=
          sizeof(failure) ||
      failure)
    return 1;

  const std::string path = "/sys/module/" + std::string(prepared.module_name);
  uint64_t generation = 0;
  int identity = -1;
  struct stat original{};
  bool dead = false, waiting = false;
  for (;;) {
    observed.generation = generation;
    if (ioctl(observer, KCTRACE_IOC_OBSERVE, &observed) != 0) {
      if (errno == EINTR)
        continue;
      // Losing the owner before bind, or losing an ownerless bound session
      // after unbind, leaves nothing this guardian may remove by name.
      if (errno != ENOENT)
        dprintf(STDERR_FILENO, "ctrace: guardian cannot observe %s: %s\n",
                prepared.module_name, std::strerror(errno));
      return 0;
    }
    const auto &status = observed.status;
    if (status.size != sizeof(status) ||
        std::memcmp(status.contract_sha256, kctrace_contract_hash,
                    KCTRACE_HASH_SIZE) ||
        status.session_id != prepared.session_id ||
        (generation && generation != status.generation)) {
      dprintf(STDERR_FILENO,
              "ctrace: guardian session identity changed; removal stopped\n");
      return 1;
    }
    if (status.generation)
      generation = status.generation;
    if ((status.flags & KCTRACE_STATUS_BOUND) && identity < 0) {
      identity = open(path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
      if (identity >= 0 && fstat(identity, &original) != 0) {
        close(identity);
        identity = -1;
      }
    }
    if (dead) {
      if (status.state == KCTRACE_STATE_INIT_FAILED ||
          status.state == KCTRACE_STATE_EXIT_COMPLETE ||
          status.state == KCTRACE_STATE_LOAD_ABORTED)
        return 0;
      if (status.state == KCTRACE_STATE_BOUND) {
        if (!waiting) {
          dprintf(STDERR_FILENO,
                  "ctrace: guardian waiting for %s initialization\n",
                  prepared.module_name);
          waiting = true;
        }
      } else if (status.state == KCTRACE_STATE_LIVE &&
                 (status.flags & KCTRACE_STATUS_BOUND)) {
        struct stat current{};
        const int state =
            open((path + "/initstate").c_str(), O_RDONLY | O_CLOEXEC);
        char text[16]{};
        const ssize_t size =
            state < 0 ? -1 : read(state, text, sizeof(text) - 1);
        if (state >= 0)
          close(state);
        if (size > 0 && std::strncmp(text, "going", 5) == 0)
          return 0; // An existing normal unload worker owns completion.
        if (size > 0 && std::strncmp(text, "coming", 6) == 0) {
          // The target wrapper can finish before the kernel loader publishes
          // MODULE_STATE_LIVE. Do not mistake that normal window for a change
          // of identity, or drop protection while initialization completes.
          if (!waiting) {
            dprintf(STDERR_FILENO,
                    "ctrace: guardian waiting for %s initialization\n",
                    prepared.module_name);
            waiting = true;
          }
          (void)poll(nullptr, 0, guardian_status_interval_ms);
          continue;
        }
        if (identity < 0 || stat(path.c_str(), &current) != 0 ||
            current.st_dev != original.st_dev ||
            current.st_ino != original.st_ino || size <= 0 ||
            std::strncmp(text, "live", 4) != 0 ||
            ioctl(observer, KCTRACE_IOC_OBSERVE, &observed) != 0 ||
            observed.status.generation != generation ||
            observed.status.state != KCTRACE_STATE_LIVE ||
            !(observed.status.flags & KCTRACE_STATUS_BOUND)) {
          dprintf(STDERR_FILENO,
                  "ctrace: guardian identity/state changed for %s; "
                  "automatic removal stopped\n",
                  prepared.module_name);
          return 0;
        }
        if (syscall(SYS_delete_module, prepared.module_name, O_NONBLOCK) == 0) {
          dprintf(STDERR_FILENO,
                  "ctrace: guardian removed %s after controller exit\n",
                  prepared.module_name);
        } else {
          dprintf(STDERR_FILENO,
                  "ctrace: guardian cannot remove %s: %s; target remains "
                  "with observation disabled\n",
                  prepared.module_name, std::strerror(errno));
        }
        return 0;
      } else if (status.state != KCTRACE_STATE_PREPARED) {
        return 0;
      }
    }
    pollfd descriptors[] = {{dead ? -1 : owner, POLLIN, 0},
                            {control, POLLIN | POLLHUP, 0}};
    if (poll(descriptors, 2, guardian_status_interval_ms) < 0) {
      if (errno == EINTR)
        continue;
      dprintf(STDERR_FILENO, "ctrace: guardian poll failed: %s\n",
              std::strerror(errno));
      return 1;
    }
    if (descriptors[0].revents & POLLIN)
      dead = true;
    if (control >= 0 && descriptors[1].revents) {
      char command = 0;
      const ssize_t size =
          recv(control, &command, sizeof(command), MSG_DONTWAIT);
      if (size == 1 && command == 'C' && !dead)
        return 0;
      if (!size || (size < 0 && errno != EAGAIN && errno != EINTR)) {
        close(control);
        control = -1; // EOF is not cancellation: keep watching the pidfd.
      }
    }
  }
}

bool ct_kernel_guardian_start(int collector, const kctrace_prepare &prepared,
                              ct_kernel_guardian &guardian,
                              std::string &error) {
  error.clear();
  if (collector < 0 || collector == STDERR_FILENO || guardian.process > 0 ||
      guardian.control >= 0 || prepared.size != sizeof(prepared) ||
      std::memcmp(prepared.contract_sha256, kctrace_contract_hash,
                  KCTRACE_HASH_SIZE) ||
      !prepared.session_id || !prepared.module_name[0] ||
      !std::memchr(prepared.module_name, 0, sizeof(prepared.module_name))) {
    error = "invalid guardian session";
    return false;
  }
  struct sigaction child_signal{};
  if (sigaction(SIGCHLD, nullptr, &child_signal) != 0) {
    error = "cannot inspect guardian child handling: " +
            std::string(std::strerror(errno));
    return false;
  }
  if (child_signal.sa_handler == SIG_IGN ||
      (child_signal.sa_flags & SA_NOCLDWAIT)) {
    error = "guardian requires waitable children; SIGCHLD ignore and "
            "SA_NOCLDWAIT are unsupported";
    return false;
  }
  kctrace_status status{};
  status.size = sizeof(status);
  std::memcpy(status.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE);
  if (ioctl(collector, KCTRACE_IOC_STATUS, &status) != 0 ||
      status.size != sizeof(status) ||
      std::memcmp(status.contract_sha256, kctrace_contract_hash,
                  KCTRACE_HASH_SIZE) ||
      status.session_id != prepared.session_id ||
      status.state != KCTRACE_STATE_PREPARED) {
    error = "guardian requires the collector's prepared session";
    return false;
  }
  const int owner = int(syscall(SYS_pidfd_open, getpid(), 0));
  if (owner < 0) {
    error =
        "cannot open controller pidfd: " + std::string(std::strerror(errno));
    return false;
  }
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
    error =
        "cannot create guardian channel: " + std::string(std::strerror(errno));
    close(owner);
    return false;
  }
  sigset_t signals{}, original{};
  sigfillset(&signals);
  if (sigprocmask(SIG_BLOCK, &signals, &original) != 0) {
    const int failure = errno;
    close(owner);
    close(sockets[0]);
    close(sockets[1]);
    error = "cannot protect guardian startup: " +
            std::string(std::strerror(failure));
    return false;
  }
  const pid_t child = fork();
  if (!child) {
    const int result = guardian_main(owner, sockets[1], prepared);
    _exit(result);
  }
  const int fork_error = errno;
  sigprocmask(SIG_SETMASK, &original, nullptr);
  close(owner);
  close(sockets[1]);
  if (child < 0) {
    close(sockets[0]);
    error = "cannot start guardian: " + std::string(std::strerror(fork_error));
    return false;
  }
  pollfd ready{sockets[0], POLLIN | POLLHUP, 0};
  int available;
  do {
    available = poll(&ready, 1, -1);
  } while (available < 0 && errno == EINTR);
  int failure = available < 0 ? errno : 0;
  const ssize_t size =
      available > 0 ? recv(sockets[0], &failure, sizeof(failure), MSG_DONTWAIT)
                    : -1;
  if (size != sizeof(failure) || failure) {
    error = "guardian initialization failed: " +
            std::string(std::strerror(failure ? failure : EIO));
    close(sockets[0]);
    kill(child, SIGKILL);
    while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
    }
    return false;
  }
  guardian.process = child;
  guardian.control = sockets[0];
  return true;
}

bool ct_kernel_guardian_cancel(ct_kernel_guardian &guardian,
                               std::string &error) {
  error.clear();
  bool success = true;
  if (guardian.control >= 0) {
    const char cancel = 'C';
    if (send(guardian.control, &cancel, sizeof(cancel), MSG_NOSIGNAL) !=
        sizeof(cancel)) {
      error = "cannot cancel guardian: " + std::string(std::strerror(errno));
      success = false;
    }
    close(guardian.control);
    guardian.control = -1;
  }
  if (guardian.process > 0) {
    int status = 0;
    pid_t result;
    do {
      result = waitpid(guardian.process, &status, 0);
    } while (result < 0 && errno == EINTR);
    if (result != guardian.process || !WIFEXITED(status) ||
        WEXITSTATUS(status)) {
      if (error.empty())
        error = "guardian did not exit cleanly";
      success = false;
    }
    guardian.process = -1;
  }
  return success;
}
