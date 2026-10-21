// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <type_traits>

#include <sys/ptrace.h>

#include "signal_info.hh"

std::string ct_signal_name(int signal) {
#define SIGNAL_NAME(value)                                                     \
  case value:                                                                  \
    return #value
  switch (signal) {
    SIGNAL_NAME(SIGHUP);
    SIGNAL_NAME(SIGINT);
    SIGNAL_NAME(SIGQUIT);
    SIGNAL_NAME(SIGILL);
    SIGNAL_NAME(SIGTRAP);
    SIGNAL_NAME(SIGABRT);
    SIGNAL_NAME(SIGBUS);
    SIGNAL_NAME(SIGFPE);
    SIGNAL_NAME(SIGKILL);
    SIGNAL_NAME(SIGUSR1);
    SIGNAL_NAME(SIGSEGV);
    SIGNAL_NAME(SIGUSR2);
    SIGNAL_NAME(SIGPIPE);
    SIGNAL_NAME(SIGALRM);
    SIGNAL_NAME(SIGTERM);
    SIGNAL_NAME(SIGSTKFLT);
    SIGNAL_NAME(SIGCHLD);
    SIGNAL_NAME(SIGCONT);
    SIGNAL_NAME(SIGSTOP);
    SIGNAL_NAME(SIGTSTP);
    SIGNAL_NAME(SIGTTIN);
    SIGNAL_NAME(SIGTTOU);
    SIGNAL_NAME(SIGURG);
    SIGNAL_NAME(SIGXCPU);
    SIGNAL_NAME(SIGXFSZ);
    SIGNAL_NAME(SIGVTALRM);
    SIGNAL_NAME(SIGPROF);
    SIGNAL_NAME(SIGWINCH);
    SIGNAL_NAME(SIGIO);
    SIGNAL_NAME(SIGPWR);
    SIGNAL_NAME(SIGSYS);
  default:
    if (signal == SIGRTMIN)
      return "SIGRTMIN";
    if (signal == SIGRTMAX)
      return "SIGRTMAX";
    if (signal > SIGRTMIN && signal < SIGRTMAX)
      return "SIGRTMIN+" + std::to_string(signal - SIGRTMIN);
    return std::to_string(signal);
  }
#undef SIGNAL_NAME
}

enum class SignalLayout {
  Unknown,
  Kernel,
  Sender,
  Queued,
  Timer,
  Fault,
  Bounds,
  ProtectionKey,
  MachineCheck,
  Performance,
  Child,
  Poll,
  Syscall,
};

struct SignalCode {
  int signal, code;
  const char *name;
  SignalLayout layout;
};

// The union layout follows Linux's siginfo_layout(), with additional fields
// enabled only for the si_code that defines them. Unknown codes stay numeric.
static const SignalCode signal_codes[] = {
#define SIGNAL_CODE(signal, code, layout)                                      \
  {signal, code, #code, SignalLayout::layout}
    SIGNAL_CODE(0, SI_USER, Sender),
    SIGNAL_CODE(0, SI_TKILL, Sender),
    SIGNAL_CODE(0, SI_QUEUE, Queued),
    SIGNAL_CODE(0, SI_TIMER, Timer),
    SIGNAL_CODE(0, SI_MESGQ, Queued),
    SIGNAL_CODE(0, SI_ASYNCIO, Queued),
    SIGNAL_CODE(0, SI_SIGIO, Poll),
    SIGNAL_CODE(0, SI_DETHREAD, Sender),
    SIGNAL_CODE(0, SI_ASYNCNL, Queued),
    SIGNAL_CODE(0, SI_KERNEL, Kernel),
    SIGNAL_CODE(SIGILL, ILL_ILLOPC, Fault),
    SIGNAL_CODE(SIGILL, ILL_ILLOPN, Fault),
    SIGNAL_CODE(SIGILL, ILL_ILLADR, Fault),
    SIGNAL_CODE(SIGILL, ILL_ILLTRP, Fault),
    SIGNAL_CODE(SIGILL, ILL_PRVOPC, Fault),
    SIGNAL_CODE(SIGILL, ILL_PRVREG, Fault),
    SIGNAL_CODE(SIGILL, ILL_COPROC, Fault),
    SIGNAL_CODE(SIGILL, ILL_BADSTK, Fault),
#ifdef ILL_BADIADDR
    SIGNAL_CODE(SIGILL, ILL_BADIADDR, Fault),
#endif
    SIGNAL_CODE(SIGFPE, FPE_INTDIV, Fault),
    SIGNAL_CODE(SIGFPE, FPE_INTOVF, Fault),
    SIGNAL_CODE(SIGFPE, FPE_FLTDIV, Fault),
    SIGNAL_CODE(SIGFPE, FPE_FLTOVF, Fault),
    SIGNAL_CODE(SIGFPE, FPE_FLTUND, Fault),
    SIGNAL_CODE(SIGFPE, FPE_FLTRES, Fault),
    SIGNAL_CODE(SIGFPE, FPE_FLTINV, Fault),
    SIGNAL_CODE(SIGFPE, FPE_FLTSUB, Fault),
#ifdef FPE_FLTUNK
    SIGNAL_CODE(SIGFPE, FPE_FLTUNK, Fault),
#endif
#ifdef FPE_CONDTRAP
    SIGNAL_CODE(SIGFPE, FPE_CONDTRAP, Fault),
#endif
    SIGNAL_CODE(SIGSEGV, SEGV_MAPERR, Fault),
    SIGNAL_CODE(SIGSEGV, SEGV_ACCERR, Fault),
#ifdef SEGV_BNDERR
    SIGNAL_CODE(SIGSEGV, SEGV_BNDERR, Bounds),
#endif
#ifdef SEGV_PKUERR
    SIGNAL_CODE(SIGSEGV, SEGV_PKUERR, ProtectionKey),
#endif
#ifdef SEGV_ACCADI
    SIGNAL_CODE(SIGSEGV, SEGV_ACCADI, Fault),
    SIGNAL_CODE(SIGSEGV, SEGV_ADIDERR, Fault),
    SIGNAL_CODE(SIGSEGV, SEGV_ADIPERR, Fault),
#endif
#ifdef SEGV_MTEAERR
    SIGNAL_CODE(SIGSEGV, SEGV_MTEAERR, Fault),
    SIGNAL_CODE(SIGSEGV, SEGV_MTESERR, Fault),
#endif
#ifdef SEGV_CPERR
    SIGNAL_CODE(SIGSEGV, SEGV_CPERR, Fault),
#endif
    SIGNAL_CODE(SIGBUS, BUS_ADRALN, Fault),
    SIGNAL_CODE(SIGBUS, BUS_ADRERR, Fault),
    SIGNAL_CODE(SIGBUS, BUS_OBJERR, Fault),
    SIGNAL_CODE(SIGBUS, BUS_MCEERR_AR, MachineCheck),
    SIGNAL_CODE(SIGBUS, BUS_MCEERR_AO, MachineCheck),
    SIGNAL_CODE(SIGTRAP, TRAP_BRKPT, Fault),
    SIGNAL_CODE(SIGTRAP, TRAP_TRACE, Fault),
    SIGNAL_CODE(SIGTRAP, TRAP_BRANCH, Fault),
    SIGNAL_CODE(SIGTRAP, TRAP_HWBKPT, Fault),
#ifdef TRAP_UNK
    SIGNAL_CODE(SIGTRAP, TRAP_UNK, Fault),
#endif
#ifdef TRAP_PERF
    SIGNAL_CODE(SIGTRAP, TRAP_PERF, Performance),
#endif
    SIGNAL_CODE(SIGCHLD, CLD_EXITED, Child),
    SIGNAL_CODE(SIGCHLD, CLD_KILLED, Child),
    SIGNAL_CODE(SIGCHLD, CLD_DUMPED, Child),
    SIGNAL_CODE(SIGCHLD, CLD_TRAPPED, Child),
    SIGNAL_CODE(SIGCHLD, CLD_STOPPED, Child),
    SIGNAL_CODE(SIGCHLD, CLD_CONTINUED, Child),
    SIGNAL_CODE(SIGIO, POLL_IN, Poll),
    SIGNAL_CODE(SIGIO, POLL_OUT, Poll),
    SIGNAL_CODE(SIGIO, POLL_MSG, Poll),
    SIGNAL_CODE(SIGIO, POLL_ERR, Poll),
    SIGNAL_CODE(SIGIO, POLL_PRI, Poll),
    SIGNAL_CODE(SIGIO, POLL_HUP, Poll),
#ifdef SYS_SECCOMP
    SIGNAL_CODE(SIGSYS, SYS_SECCOMP, Syscall),
#endif
#ifdef SYS_USER_DISPATCH
    SIGNAL_CODE(SIGSYS, SYS_USER_DISPATCH, Syscall),
#endif
#undef SIGNAL_CODE
};

std::string ct_format_signal_info(int signal, const siginfo_t *information) {
  std::ostringstream text;
  const auto number = [&](const char *prefix, auto value) {
    // Keep the declared field width for negative two's-complement values.
    using Unsigned = std::make_unsigned_t<decltype(value)>;
    text << prefix << "0x" << std::hex << static_cast<Unsigned>(value);
  };
  text << "--- " << ct_signal_name(signal) << " {";
  number("si_signo=", information ? information->si_signo : signal);
  text << ", si_code=";
  if (!information) {
    text << "?} ---";
    return text.str();
  }

  const siginfo_t &info = *information;
  SignalLayout layout = SignalLayout::Unknown;
  const char *code_name = nullptr;
  for (const SignalCode &entry : signal_codes) {
    if ((!entry.signal || entry.signal == info.si_signo) &&
        entry.code == info.si_code) {
      code_name = entry.name;
      layout = entry.layout;
      break;
    }
  }
  // F_SETSIG may select a realtime signal for the same POLL_* payload.
  if (!code_name && info.si_signo != SIGILL && info.si_signo != SIGFPE &&
      info.si_signo != SIGSEGV && info.si_signo != SIGBUS &&
      info.si_signo != SIGTRAP && info.si_signo != SIGCHLD &&
      info.si_signo != SIGSYS) {
    for (const SignalCode &entry : signal_codes) {
      if (entry.signal == SIGIO && entry.code == info.si_code) {
        code_name = entry.name;
        layout = entry.layout;
        break;
      }
    }
  }
  if (!code_name && info.si_signo == SIGTRAP &&
      (info.si_code & 0xff) == SIGTRAP) {
    switch (static_cast<unsigned int>(info.si_code) >> 8) {
#define PTRACE_CODE(event)                                                     \
  case event:                                                                  \
    code_name = "SIGTRAP | (" #event " << 8)";                                 \
    break
      PTRACE_CODE(PTRACE_EVENT_FORK);
      PTRACE_CODE(PTRACE_EVENT_VFORK);
      PTRACE_CODE(PTRACE_EVENT_CLONE);
      PTRACE_CODE(PTRACE_EVENT_EXEC);
      PTRACE_CODE(PTRACE_EVENT_VFORK_DONE);
      PTRACE_CODE(PTRACE_EVENT_EXIT);
      PTRACE_CODE(PTRACE_EVENT_SECCOMP);
      PTRACE_CODE(PTRACE_EVENT_STOP);
#undef PTRACE_CODE
    default:
      break;
    }
    if (code_name)
      layout = SignalLayout::Sender;
  }
  number("", info.si_code);
  if (info.si_errno)
    number(", si_errno=", info.si_errno);

  if (layout == SignalLayout::Sender || layout == SignalLayout::Queued ||
      layout == SignalLayout::Child ||
      (layout == SignalLayout::Kernel && (info.si_pid || info.si_uid))) {
    number(", si_pid=", info.si_pid);
    number(", si_uid=", info.si_uid);
  }

  if (layout == SignalLayout::Timer) {
    number(", si_timerid=", info.si_timerid);
    number(", si_overrun=", info.si_overrun);
  }
  if (layout == SignalLayout::Queued || layout == SignalLayout::Timer) {
    number(", si_value={sival_int=", info.si_value.sival_int);
    number(", sival_ptr=",
           reinterpret_cast<uintptr_t>(info.si_value.sival_ptr));
    text << '}';
  }

  if (layout == SignalLayout::Fault || layout == SignalLayout::Bounds ||
      layout == SignalLayout::ProtectionKey ||
      layout == SignalLayout::MachineCheck ||
      layout == SignalLayout::Performance) {
    number(", si_addr=", reinterpret_cast<uintptr_t>(info.si_addr));
    if (layout == SignalLayout::Bounds) {
      number(", si_lower=", reinterpret_cast<uintptr_t>(info.si_lower));
      number(", si_upper=", reinterpret_cast<uintptr_t>(info.si_upper));
    }
    if (layout == SignalLayout::ProtectionKey)
      number(", si_pkey=", info.si_pkey);
    if (layout == SignalLayout::MachineCheck)
      number(", si_addr_lsb=", info.si_addr_lsb);
    if (layout == SignalLayout::Performance) {
      // glibc does not expose these Linux UAPI fields on every version. They
      // occupy the union immediately after si_addr, not the bounds sub-union.
      struct PerformanceInfo {
        unsigned long data;
        uint32_t type, flags;
      } performance{};
      constexpr size_t offset = offsetof(siginfo_t, si_addr) + sizeof(void *);
      static_assert(offset + sizeof(performance) <= sizeof(siginfo_t));
      std::memcpy(&performance,
                  reinterpret_cast<const unsigned char *>(&info) + offset,
                  sizeof(performance));
      number(", si_perf_data=", performance.data);
      number(", si_perf_type=", performance.type);
      number(", si_perf_flags=", performance.flags);
    }
  }
  if (layout == SignalLayout::Child) {
    number(", si_status=", info.si_status);
    number(", si_utime=", info.si_utime);
    number(", si_stime=", info.si_stime);
  }
  if (layout == SignalLayout::Poll) {
    number(", si_band=", info.si_band);
    number(", si_fd=", info.si_fd);
  }
  if (layout == SignalLayout::Syscall) {
    number(", si_call_addr=", reinterpret_cast<uintptr_t>(info.si_call_addr));
    number(", si_syscall=", info.si_syscall);
    number(", si_arch=", info.si_arch);
  }
  text << "} ---";
  return text.str();
}
