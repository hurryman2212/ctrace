#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string_view>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kernel_lifetime.h"

static constexpr unsigned drain_batches = 8;

void ct_kernel_termination_signals(sigset_t &mask) {
  sigemptyset(&mask);
  for (int number : {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE, SIGALRM,
                     SIGUSR1, SIGUSR2, SIGVTALRM, SIGPROF, SIGXCPU, SIGXFSZ,
                     SIGABRT, SIGTRAP, SIGSYS, SIGIO, SIGPWR, SIGSTKFLT})
    sigaddset(&mask, number);
  for (int number = SIGRTMIN; number <= SIGRTMAX; ++number)
    sigaddset(&mask, number);
}

void ct_kernel_consume_sigpipe() {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGPIPE);
  const timespec immediate{};
  sigtimedwait(&mask, nullptr, &immediate);
}

ct_kernel_lifetime_result
ct_kernel_follow(int descriptor, const kctrace_prepare &prepared,
                 const std::function<bool(const kctrace_event &)> &event,
                 const std::function<void(const std::string &)> &notice,
                 ct_kernel_loading *loading) {
  bool output_failed = false;
  const auto finish = [&](ct_kernel_finish reason, int error) {
    output_failed |= std::ferror(stderr) != 0;
    ct_kernel_lifetime_result result{reason, error};
    result.output_failed = output_failed;
    if (output_failed) {
      // The final exit record can fail before the signalfd drain runs. Retire
      // its handled SIGPIPE before restoring the caller's signal mask.
      ct_kernel_consume_sigpipe();
    }
    if (loading && loading->finished) {
      result.load_status = loading->wait_status;
      result.exec_error = loading->exec_error;
    }
    return result;
  };
  if (descriptor < 0 || prepared.size != sizeof(prepared) ||
      prepared.abi != KCTRACE_ABI_VERSION || !prepared.session_id ||
      !prepared.module_name[0] ||
      !std::memchr(prepared.module_name, 0, sizeof(prepared.module_name)))
    return finish(ct_kernel_finish::error, EINVAL);
  sigset_t mask{}, original{};
  ct_kernel_termination_signals(mask);
  if (sigprocmask(SIG_BLOCK, &mask, &original) != 0)
    return finish(ct_kernel_finish::error, errno);
  struct Resources {
    sigset_t original;
    int signal = -1, worker = -1, module = -1;
    int descriptor = -1, flags = -1;
    ~Resources() {
      if (worker >= 0)
        close(worker);
      if (module >= 0)
        close(module);
      if (signal >= 0)
        close(signal);
      if (descriptor >= 0 && flags >= 0)
        fcntl(descriptor, F_SETFL, flags);
      sigprocmask(SIG_SETMASK, &original, nullptr);
    }
  } resources{original};
  resources.signal = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (resources.signal < 0)
    return finish(ct_kernel_finish::error, errno);
  const int flags = fcntl(descriptor, F_GETFL);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0)
    return finish(ct_kernel_finish::error, errno);
  resources.descriptor = descriptor;
  resources.flags = flags;
  const std::string module_path =
      "/sys/module/" + std::string(prepared.module_name);
  struct stat original_module{};
  bool have_module = false;
  std::string diagnostic_pending;
  pid_t worker = -1;
  uint64_t generation = 0;
  bool stopped = false, received_exit = false;
  bool ambiguous = false;
  std::array<unsigned char, sizeof(int)> reply{};
  size_t reply_size = 0;
  int unload_result = -1;
  const auto report = [&](const std::string &message) {
    if (!output_failed) {
      notice(message);
      if (std::ferror(stderr)) {
        output_failed = true;
        stopped = true;
      }
    }
  };

  for (;;) {
    kctrace_status status{};
    status.size = sizeof(status);
    status.abi = KCTRACE_ABI_VERSION;
    if (ioctl(descriptor, KCTRACE_IOC_STATUS, &status) != 0)
      return finish(ct_kernel_finish::error, errno);
    if (status.size != sizeof(status) || status.abi != KCTRACE_ABI_VERSION ||
        status.session_id != prepared.session_id ||
        (generation && status.generation != generation))
      return finish(ct_kernel_finish::error, EPROTO);
    if (!generation)
      generation = status.generation;
    if (!have_module && (status.flags & KCTRACE_STATUS_BOUND)) {
      resources.module =
          open(module_path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
      have_module = resources.module >= 0 &&
                    fstat(resources.module, &original_module) == 0;
      if (!have_module && resources.module >= 0) {
        close(resources.module);
        resources.module = -1;
      }
    }
    const bool load_pending = loading && !loading->finished;
    const bool load_failed =
        loading && loading->finished &&
        (loading->exec_error || !WIFEXITED(loading->wait_status) ||
         WEXITSTATUS(loading->wait_status));

    // Drain records even after an exit callback has disabled the producer.
    bool drained = false;
    for (unsigned batch = 0; batch < drain_batches && !drained; ++batch) {
      std::array<kctrace_event, 32> records;
      const ssize_t count = read(descriptor, records.data(), sizeof(records));
      if (count < 0 && errno == EINTR)
        continue;
      if (!count || (count < 0 && errno == EAGAIN)) {
        drained = true;
        continue;
      }
      if (count < 0)
        return finish(ct_kernel_finish::error, errno);
      if (size_t(count) % sizeof(kctrace_event))
        return finish(ct_kernel_finish::error, EPROTO);
      for (size_t index = 0; index < size_t(count) / sizeof(kctrace_event);
           ++index) {
        const auto &record = records[index];
        if (record.size != sizeof(record) ||
            record.session_id != prepared.session_id ||
            (generation && record.generation != generation))
          return finish(ct_kernel_finish::error, EPROTO);
        if (!output_failed && !event(record)) {
          output_failed = true;
          stopped = true;
          // Do not report through a failed output callback's diagnostic sink:
          // a broken stderr would raise another SIGPIPE.
        }
      }
    }
    if (drained && !load_pending && load_failed &&
        !(status.flags & KCTRACE_STATUS_BOUND))
      return finish(ct_kernel_finish::load_failed, loading->exec_error);
    if (drained && !load_pending &&
        status.state == KCTRACE_STATE_LOAD_ABORTED) {
      // COMING rollback does not carry the loader's errno. Prefer its actual
      // wait status above; an observer without that child reports no guess.
      if (loading)
        return finish(ct_kernel_finish::error, EPROTO);
      return finish(ct_kernel_finish::load_failed, 0);
    }
    if (drained && !load_pending && status.state == KCTRACE_STATE_INIT_FAILED)
      return finish(ct_kernel_finish::init_failed,
                    status.init_result < 0 ? -status.init_result : EINVAL);
    if (loading && loading->finished && !load_failed &&
        status.state == KCTRACE_STATE_PREPARED)
      return finish(ct_kernel_finish::error, EPROTO);
    if (load_failed && (status.flags & KCTRACE_STATUS_BOUND))
      stopped = true;
    received_exit |= status.state == KCTRACE_STATE_EXIT_COMPLETE;
    if (drained && !load_pending && unload_result == 0 && worker < 0 &&
        received_exit)
      return finish(ct_kernel_finish::unloaded, 0);
    if (drained && !load_pending && received_exit && worker < 0) {
      struct stat current{};
      const int found = stat(module_path.c_str(), &current);
      const bool gone = found < 0 && errno == ENOENT;
      const bool replaced = found == 0 && have_module &&
                            (current.st_dev != original_module.st_dev ||
                             current.st_ino != original_module.st_ino);
      if (gone || replaced) {
        report("module exit and disappearance observed; external memory-free "
               "time is unconfirmed");
        return finish(ct_kernel_finish::external_exit, 0);
      }
    }
    if (stopped && !load_pending && worker < 0 && !received_exit &&
        !ambiguous) {
      // Cooperative session identity reduces accidental retries, but this is
      // deliberately not a kernel-atomic check-and-delete operation.
      struct stat current{};
      const bool same = have_module &&
                        stat(module_path.c_str(), &current) == 0 &&
                        current.st_dev == original_module.st_dev &&
                        current.st_ino == original_module.st_ino;
      if (!same || status.state != KCTRACE_STATE_LIVE ||
          !(status.flags & KCTRACE_STATUS_BOUND)) {
        stopped = false;
        report("module identity/state changed; automatic removal stopped");
      } else {
        int descriptors[2];
        if (pipe2(descriptors, O_CLOEXEC) != 0) {
          stopped = false;
          report("cannot create unload worker channel: " +
                 std::string(std::strerror(errno)));
        } else {
          // The child makes only async-signal-safe operations after fork.
          worker = fork();
          if (worker == 0) {
            close(descriptors[0]);
            // The worker must not keep the collector's lease alive if its
            // owner dies while the target exit callback is still running.
            close(descriptor);
            close(resources.signal);
            if (resources.module >= 0)
              close(resources.module);
            const int result =
                syscall(SYS_delete_module, prepared.module_name, O_NONBLOCK) < 0
                    ? errno
                    : 0;
            const auto *bytes =
                reinterpret_cast<const unsigned char *>(&result);
            size_t done = 0;
            while (done < sizeof(result)) {
              const ssize_t count =
                  write(descriptors[1], bytes + done, sizeof(result) - done);
              if (count < 0 && errno == EINTR)
                continue;
              if (count <= 0)
                break;
              done += size_t(count);
            }
            _exit(done == sizeof(result) ? 0 : 1);
          }
          const int failure = errno;
          close(descriptors[1]);
          if (worker < 0) {
            close(descriptors[0]);
            stopped = false;
            report("cannot start unload worker: " +
                   std::string(std::strerror(failure)));
          } else {
            resources.worker = descriptors[0];
            reply_size = 0;
            unload_result = -1;
          }
        }
      }
    }

    // Disabled producers report permanent HUP. Poll only the other channels
    // then, with a modest status retry for externally observed removal.
    pollfd descriptors[] = {
        {(status.flags & KCTRACE_STATUS_DISABLED) ? -1 : descriptor, POLLIN, 0},
        {resources.signal, POLLIN, 0},
        {resources.worker, POLLIN | POLLHUP, 0},
        {load_pending ? loading->process_fd : -1, POLLIN, 0},
        {loading ? loading->diagnostics : -1, POLLIN | POLLHUP, 0}};
    // A continuous producer must not starve termination or unload replies.
    const int timeout = !drained                                   ? 0
                        : (status.flags & KCTRACE_STATUS_DISABLED) ? 100
                                                                   : -1;
    const int ready = poll(descriptors, 5, timeout);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      return finish(ct_kernel_finish::error, errno);
    }
    if (loading && loading->diagnostics >= 0 && descriptors[4].revents) {
      constexpr std::string_view temporary = "/proc/self/fd/3";
      bool ended = false;
      for (unsigned batch = 0; batch < drain_batches && !ended; ++batch) {
        char buffer[4096];
        const ssize_t count =
            read(loading->diagnostics, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR)
          continue;
        if (count < 0 && errno == EAGAIN)
          break;
        if (count <= 0)
          ended = true;
        else
          diagnostic_pending.append(buffer, size_t(count));
        std::string display;
        size_t occurrence;
        while ((occurrence = diagnostic_pending.find(temporary)) !=
               std::string::npos) {
          display.append(diagnostic_pending, 0, occurrence);
          display += loading->original_path;
          diagnostic_pending.erase(0, occurrence + temporary.size());
        }
        const size_t ready =
            ended ? diagnostic_pending.size()
            : diagnostic_pending.size() >= temporary.size()
                ? diagnostic_pending.size() - temporary.size() + 1
                : 0;
        display.append(diagnostic_pending, 0, ready);
        diagnostic_pending.erase(0, ready);
        for (size_t offset = 0; !output_failed && offset < display.size();) {
          const ssize_t written = write(STDERR_FILENO, display.data() + offset,
                                        display.size() - offset);
          if (written < 0 && errno == EINTR)
            continue;
          if (written <= 0) {
            output_failed = true;
            stopped = true;
            break;
          }
          offset += size_t(written);
        }
      }
      if (ended) {
        close(loading->diagnostics);
        loading->diagnostics = -1;
      }
    }
    if (load_pending && descriptors[3].revents && loading->diagnostics < 0) {
      int child_status = 0;
      pid_t waited;
      do {
        waited = waitpid(loading->process, &child_status, WNOHANG);
      } while (waited < 0 && errno == EINTR);
      if (waited < 0)
        return finish(ct_kernel_finish::error, errno);
      if (waited == loading->process) {
        int execution_error = 0;
        ssize_t count;
        do {
          count = read(loading->exec_errors, &execution_error,
                       sizeof(execution_error));
        } while (count < 0 && errno == EINTR);
        if (count != 0 && count != sizeof(execution_error))
          return finish(ct_kernel_finish::error, EPROTO);
        loading->exec_error = execution_error;
        loading->wait_status = child_status;
        loading->finished = true;
        loading->process = -1;
        close(loading->process_fd);
        close(loading->exec_errors);
        loading->process_fd = loading->exec_errors = -1;
      }
    }
    if (descriptors[1].revents & POLLIN) {
      signalfd_siginfo signal{};
      // Signals can be produced while handling another signal (notably a
      // failed diagnostic write). Always return to status and worker replies.
      for (unsigned batch = 0;
           batch < drain_batches &&
           read(resources.signal, &signal, sizeof(signal)) == sizeof(signal);
           ++batch) {
        if (worker >= 0)
          report("module removal is already pending; waiting for its result");
        else if (ambiguous)
          report(
              "previous unload result is unknown; refusing a name-only retry");
        else
          stopped = true;
      }
    }
    if (resources.worker >= 0 && descriptors[2].revents) {
      const ssize_t count =
          reply_size < reply.size()
              ? read(resources.worker, reply.data() + reply_size,
                     reply.size() - reply_size)
              : 0;
      if (count > 0)
        reply_size += size_t(count);
      // The reply may precede the worker's exit. Waiting for pipe HUP keeps
      // the controller responsive even if the worker stops after writing.
      if (descriptors[2].revents & (POLLHUP | POLLERR | POLLNVAL)) {
        int child_status = 0;
        pid_t waited;
        do {
          waited = waitpid(worker, &child_status, 0);
        } while (waited < 0 && errno == EINTR);
        close(resources.worker);
        resources.worker = -1;
        worker = -1;
        stopped = false;
        if (reply_size != reply.size() || waited < 0 ||
            !WIFEXITED(child_status) || WEXITSTATUS(child_status)) {
          ambiguous = true;
          report("unload worker ended without a confirmed result; automatic "
                 "retries disabled");
        } else {
          std::memcpy(&unload_result, reply.data(), sizeof(unload_result));
          if (unload_result != 0)
            report("module removal refused: " +
                   std::string(std::strerror(unload_result)) +
                   "; continuing trace");
        }
      }
    }
  }
}
