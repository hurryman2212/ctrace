// SPDX-License-Identifier: MIT

#include <cerrno>
#include <cstdio>
#include <string>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "guardian.hh"
#include "load.hh"

[[noreturn]] static void loader_failed(int descriptor, int failure) {
  const auto *bytes = reinterpret_cast<const unsigned char *>(&failure);
  size_t sent = 0;
  while (sent < sizeof(failure)) {
    const ssize_t count =
        write(descriptor, bytes + sent, sizeof(failure) - sent);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      break;
    sent += size_t(count);
  }
  _exit(127);
}

ct_kernel_lifetime_result
ct_kernel_load(int collector, const kctrace_prepare &prepared, int module,
               const std::string &original_path,
               const std::vector<std::string> &parameters,
               const std::function<bool(const kctrace_event &)> &event,
               const std::function<void(const std::string &)> &notice) {
  if (module < 0 || fcntl(module, F_GETFD) < 0 || original_path.empty() ||
      original_path.find('\0') != std::string::npos)
    return {ct_kernel_finish::error, EINVAL};
  std::vector<std::string> arguments{"insmod", "--", "/proc/self/fd/3"};
  for (const auto &parameter : parameters) {
    if (parameter.find('\0') != std::string::npos)
      return {ct_kernel_finish::error, EINVAL};
    arguments.push_back(parameter);
  }
  std::vector<char *> argv;
  for (auto &argument : arguments)
    argv.push_back(argument.data());
  argv.push_back(nullptr);

  sigset_t mask{}, original{};
  ct_kernel_termination_signals(mask);
  if (sigprocmask(SIG_BLOCK, &mask, &original) != 0)
    return {ct_kernel_finish::error, errno};
  ct_kernel_loading loading;
  loading.original_path = original_path;
  struct Resources {
    sigset_t original;
    ct_kernel_loading &loading;
    ~Resources() {
      for (int descriptor :
           {loading.process_fd, loading.exec_errors, loading.diagnostics})
        if (descriptor >= 0)
          close(descriptor);
      if (std::ferror(stderr))
        ct_kernel_consume_sigpipe();
      sigprocmask(SIG_SETMASK, &original, nullptr);
    }
  } resources{original, loading};
  ct_kernel_guardian guardian;
  std::string error;
  bool output_failed = false;
  if (!ct_kernel_guardian_start(collector, prepared, guardian, error)) {
    notice(error);
    return {ct_kernel_finish::error, EIO};
  }
  const auto cancel = [&] {
    if (!ct_kernel_guardian_cancel(guardian, error) && !output_failed)
      notice(error);
  };
  const timespec immediate{};
  bool cancelled = false;
  while (sigtimedwait(&mask, nullptr, &immediate) >= 0)
    cancelled = true;
  if (cancelled) {
    cancel();
    notice("module loading cancelled before insmod");
    return {ct_kernel_finish::load_failed, ECANCELED};
  }
  int executions[2], diagnostics[2];
  if (pipe2(executions, O_CLOEXEC) != 0) {
    const int failure = errno;
    cancel();
    return {ct_kernel_finish::error, failure};
  }
  if (pipe2(diagnostics, O_CLOEXEC) != 0) {
    const int failure = errno;
    close(executions[0]);
    close(executions[1]);
    cancel();
    return {ct_kernel_finish::error, failure};
  }
  loading.exec_errors = executions[0];
  loading.diagnostics = diagnostics[0];
  if (fcntl(executions[0], F_SETFL, O_NONBLOCK) != 0 ||
      fcntl(diagnostics[0], F_SETFL, O_NONBLOCK) != 0) {
    const int failure = errno;
    close(executions[1]);
    close(diagnostics[1]);
    cancel();
    return {ct_kernel_finish::error, failure};
  }
  const pid_t child = fork();
  if (!child) {
    // Only fixed-FD setup and exec occur in the child. In particular, no copy
    // of the collector's lease or guardian control channel survives exec.
    const int saved_module = fcntl(module, F_DUPFD_CLOEXEC, 8);
    const int saved_error = fcntl(executions[1], F_DUPFD_CLOEXEC, 8);
    const int saved_diagnostics = fcntl(diagnostics[1], F_DUPFD_CLOEXEC, 8);
    int failure = 0;
    if (saved_module < 0 || saved_error < 0 || saved_diagnostics < 0) {
      failure = errno;
      loader_failed(executions[1], failure);
    }
    if (dup3(saved_module, 3, 0) < 0 || dup3(saved_error, 4, O_CLOEXEC) < 0 ||
        dup3(saved_diagnostics, STDERR_FILENO, 0) < 0) {
      failure = errno;
      loader_failed(saved_error, failure);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    if (syscall(SYS_close_range, 5u, ~0u, 0) != 0) {
      failure = errno;
    } else {
      execvp(argv[0], argv.data());
      failure = errno;
    }
    loader_failed(4, failure);
  }
  const int fork_error = errno;
  close(executions[1]);
  close(diagnostics[1]);
  if (child < 0) {
    cancel();
    return {ct_kernel_finish::error, fork_error};
  }
  loading.process = child;
  loading.process_fd = int(syscall(SYS_pidfd_open, child, 0));
  if (loading.process_fd < 0) {
    const int failure = errno;
    // Do not kill an in-flight module init. Closing this channel is not a
    // guardian cancellation; the caller's fatal exit transfers cleanup.
    close(guardian.control);
    notice(
        "cannot monitor insmod; guardian remains armed until controller exit");
    return {ct_kernel_finish::error, failure};
  }
  auto result = ct_kernel_follow(collector, prepared, event, notice, &loading);
  output_failed = result.output_failed;
  if (result.reason == ct_kernel_finish::error) {
    close(guardian.control);
    if (!output_failed)
      notice("module controller failed; guardian remains armed until "
             "controller exit");
  } else {
    cancel();
  }
  return result;
}
