// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_POLICY_H
#define CTRACE_KERNEL_POLICY_H

#include <cstdint>
#include <string>
#include <vector>

#include "dwarf/kernel_source.hh"
#include "image.hh"
#include "kctrace/policy.h"
#include "rewrite.hh"

struct ct_kernel_policy_options {
  std::vector<std::string> within;
  std::vector<std::string> into, recurse, over;
  bool within_init = false, within_intr = false;
};

struct ct_kernel_policy_function {
  uint32_t section = 0;
  // Physical extents retain separate layouts; proven DWARF fragments share
  // this canonical function ID for selection and execution frames.
  uint32_t logical_function = 0;
  uint64_t source_function = 0;
  uint64_t begin = 0, end = 0, first_probe = 0;
  // Indexes into the original image's symbol vector, not copied names.
  uint32_t first_alias = 0, alias_count = 0;
  kctrace_policy_mode mode = KCTRACE_POLICY_SKIP;
  bool within = false;
  // Complete entry transition for each parent's within/recurse/blocked flags.
  unsigned char states[8]{};
};

struct ct_kernel_policy_inline {
  uint64_t source_block = 0;
  kctrace_policy_mode mode = KCTRACE_POLICY_SKIP;
  bool within = false;
};

struct ct_kernel_policy_path {
  uint32_t parent = 0, scope = 0;
  // Folded inline transitions for each incoming within/recurse/blocked state.
  // A nonempty path does not depend on the incoming physical frame's mode.
  unsigned char states[8]{};
};

struct ct_kernel_policy_site {
  // Canonical logical owner, including every proven disjoint fragment.
  uint32_t function = 0, path = 0;
};

struct ct_kernel_policy {
  // One-based pools; site records retain original probe IDs across copies.
  std::vector<ct_kernel_policy_function> functions{1};
  std::vector<uint32_t> aliases;
  std::vector<ct_kernel_policy_inline> inlines{1};
  // Prefix-interned inline scope paths. Zero is the empty path.
  std::vector<ct_kernel_policy_path> paths{1};
  std::vector<ct_kernel_policy_site> sites;
};

// Compile all patterns before module loading. DWARF inline scopes affect
// policy independently of whether original source or decompiled text is shown.
// Optional scope_sites contains independently proven compiler-gap bridges,
// indexed by original probe ID. Each replacement must remain in the same
// bounded physical function; this check does not replace its caller's CFG
// proof.
bool ct_kernel_compile_policy(
    const ct_kernel_image &image, const std::vector<ct_kernel_site> &sites,
    const ct_kernel_source_metadata *source,
    const ct_kernel_policy_options &options, ct_kernel_policy &policy,
    std::string &error, const std::vector<uint64_t> *scope_sites = nullptr);

#endif
