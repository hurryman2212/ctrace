// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_DECOMPILE_H
#define CTRACE_KERNEL_DECOMPILE_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "decompile_image.hh"
#include "decompile_view.hh"
#include "dwarf/kernel_source.hh"
#include "dwarf/kernel_values.hh"

struct ct_kernel_decompile_function {
  uint32_t section = 0, value_function = 0;
  uint64_t begin = 0, end = 0;
  std::string name, prototype;
  std::vector<uint64_t> parameters;
};

struct ct_kernel_decompile_statement {
  uint32_t function = 0;
  std::string text, declaration_name, declaration_type;
  // Exact original probe identities, in the producer's execution order.
  std::vector<uint64_t> sites;
  std::string assignment;
};

struct ct_kernel_decompile_variable {
  uint64_t variable = 0;
  uint32_t access = 0;
};

struct ct_kernel_decompile_site {
  uint32_t function = 0, statement = 0, index = 0;
  std::vector<ct_kernel_decompile_variable> variables;
  std::string control_text, control_kind;
  uint64_t control_target = 0;
  bool conditional = false, has_target = false;
  std::vector<uint64_t> blocks;
  bool returned = false;
};

struct ct_kernel_decompile_block {
  uint32_t function = 0;
  uint64_t parent = 0;
  std::string header;
  bool loop = false;
  std::vector<uint64_t> sites;
};

struct ct_kernel_decompile_metadata {
  // Pools are one-based; sites use the existing original probe identifiers.
  std::vector<ct_kernel_decompile_function> functions{1};
  std::vector<ct_kernel_decompile_statement> statements{1};
  std::vector<ct_kernel_decompile_site> sites;
  std::vector<ct_kernel_decompile_block> blocks{1};
  ct_kernel_decompile_layout layout;
  // Recoverable per-function/statement failures retain assembly fallbacks.
  std::vector<std::string> warnings;
};

// Identifier tokens only; literals and comments do not reference variables.
bool ct_kernel_decompile_identifier(const std::string &text,
                                    const std::string &name);

// Add a C return only for independently decoded returns with a proven scalar
// return register/width or void ABI. May run again after kernel entry ABI data.
bool ct_kernel_complete_decompile_returns(
    ct_kernel_value_metadata &values, ct_kernel_decompile_metadata &metadata,
    std::string &error);

// The loader maps one FULL function view; its mappings are released after
// normalization. A successful empty view means unavailable decompilation.
// Transport/protocol errors return false. All analysis finishes before insmod.
bool ct_kernel_collect_decompile(
    const ct_kernel_image &image, const std::vector<ct_kernel_site> &sites,
    const ct_kernel_source_metadata &source,
    const ct_kernel_decompile_layout &layout,
    const std::function<bool(uint32_t, uint64_t, ct_decompile_view &,
                             std::string &)> &load_function,
    ct_kernel_value_metadata &values, ct_kernel_decompile_metadata &metadata,
    std::string &error);

#endif
