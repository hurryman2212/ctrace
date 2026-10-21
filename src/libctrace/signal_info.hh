// SPDX-License-Identifier: MIT

#ifndef CTRACE_SIGNAL_INFO_H
#define CTRACE_SIGNAL_INFO_H

#include <string>

// Public POSIX provider of siginfo_t, declared in an internal glibc header.
#include <csignal> // IWYU pragma: keep

// Standard signal name, a realtime signal offset, or the unknown number.
std::string ct_signal_name(int signal);

// The caller provides a complete native siginfo_t, or nullptr if unavailable.
// Returns the comment body without delimiters or terminal styling.
std::string ct_format_signal_info(int signal, const siginfo_t *information);

#endif
