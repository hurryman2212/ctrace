// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_SOURCE_H
#define CTRACE_KERNEL_SOURCE_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "c_cpp_source.hh"
#include "ctrace_kernel/image.hh"
#include "ctrace_kernel/rewrite.hh"

struct ct_kernel_source_options {
  std::vector<std::pair<std::string, std::string>> maps;
  bool skip_checksum = false;
  // Exact configured kernel build; never substitute userspace Linux headers.
  std::string kernel_build;
  std::vector<std::string> arguments;
  std::function<void(const std::string &)> progress, warning;
};

struct ct_kernel_source_range {
  uint32_t section = 0;
  uint64_t begin = 0, end = 0;
};

struct ct_kernel_line_location {
  uint64_t site = 0;
  std::string file;
  uint32_t line = 0;
};

// Original section-relative DWARF rows without parsing source text. Results
// preserve input order and omit sites whose file cannot be resolved. No LLVM
// metadata survives this offline collection.
bool ct_kernel_collect_line_locations(
    const ct_kernel_image &image, const std::vector<ct_kernel_site> &sites,
    std::vector<ct_kernel_line_location> &locations, std::string &error);

struct ct_kernel_source_file {
  std::string path, error;
  // Explicit checksum bypass permits source use but is not verification.
  bool available = false, verified = false, checksum_skipped = false;
  bool assembly = false;
};

struct ct_kernel_source_presentation {
  bool structural = false;
  std::string statement_function;
  ct_source_expression expression;
  std::vector<ct_source_variable> variables;
  ct_source_declaration declaration;
  std::vector<ct_source_call_info> calls;
  std::vector<ct_source_call_result_info> call_results;
  std::vector<ct_source_highlight> highlights;
};

struct ct_kernel_source_line {
  uint32_t file = 0, line = 0;
  std::string text;
  // Only referenced rows from a successful, stable parse are retained. This
  // contains no Clang AST or duplicate block tree; all tasks share the result.
  std::shared_ptr<const ct_kernel_source_presentation> presentation;
};

struct ct_kernel_source_function {
  uint64_t id = 0;
  uint32_t file = 0, line = 0;
  std::string name, signature;
  std::vector<ct_kernel_source_range> ranges;
  std::vector<ct_source_variable> parameters;
};

enum class ct_kernel_source_block_kind {
  lexical,
  inline_function,
  compound,
  control,
  switch_case,
  statement_expression
};

struct ct_kernel_source_block {
  // Parent is zero when site paths disagree; each site's ordered path is
  // authoritative, including source scopes around compiler inline instances.
  uint64_t id = 0, parent = 0, function = 0;
  uint32_t file = 0, start_line = 0, end_line = 0;
  ct_kernel_source_block_kind kind = ct_kernel_source_block_kind::lexical;
  std::string header;
  // Literal source row(s) for display; header retains its semantic meaning.
  std::string display;
  uint32_t display_line = 0;
  // Exact DWARF inline invocation, distinct from the callee definition row.
  uint32_t call_line = 0, call_column = 0;
  std::string call_function;
  bool loop = false, source_available = false;
  // Disjoint original ELF section ranges. Never a min/max envelope over holes.
  std::vector<ct_kernel_source_range> ranges;
};

struct ct_kernel_source_site {
  uint32_t line = 0, column = 0;
  uint64_t function = 0;
  // Verified declaration/opening-brace row with no body statement on it.
  bool function_opening = false;
  // Proven to perform no separate observable source operation.
  bool compiler_support = false;
  // Exact CFG successor proving the selected source condition's body is not
  // entered.
  uint64_t not_taken_successor = 0;
  // Outer-to-inner IDs. Loop membership includes its header/update/condition.
  std::vector<uint64_t> blocks;
  uint32_t discriminator = 0;
  bool statement = false;
};

struct ct_kernel_source_metadata {
  // Index zero denotes unknown in every vector. Sites use probe IDs directly.
  std::vector<ct_kernel_source_file> files{1};
  std::vector<ct_kernel_source_line> lines{1};
  std::vector<ct_kernel_source_function> functions{1};
  std::vector<ct_kernel_source_block> blocks{1};
  std::vector<ct_kernel_source_site> sites;
};

// Return a usable original C row, with its nearest physical/inline owner.
// A readable file alone does not establish that a particular PC has C source.
uint32_t ct_kernel_source_row(const ct_kernel_source_metadata &metadata,
                              uint64_t site, std::string *owner = nullptr);

// Section-aware, original-ELF DWARF and verified source analysis before load.
// Source positions/structures do not imply evaluation of source expressions.
// Missing or ambiguous metadata remains unknown; fatal malformed ELF/bounds
// errors fail preparation. No LLVM/Clang object or source buffer is retained.
bool ct_kernel_collect_source(const ct_kernel_image &image,
                              const std::vector<ct_kernel_site> &sites,
                              const ct_kernel_source_options &options,
                              ct_kernel_source_metadata &metadata,
                              std::string &error);

#endif
