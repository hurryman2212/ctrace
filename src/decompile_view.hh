// SPDX-License-Identifier: MIT

#ifndef CTRACE_DECOMPILE_VIEW_H
#define CTRACE_DECOMPILE_VIEW_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "analysis.hh"

struct ct_decompile_record;

/* Produce compact pointer-free common and optional full supplements. The full
 * object references the common content digest; it never embeds another copy.
 * Both products are consumed only after sealed catalog publication. */
bool ct_decompile_view_encode(const ct_decompile_record &record,
                              std::vector<unsigned char> &common,
                              std::vector<unsigned char> &full,
                              std::string &error);

class ct_decompile_view {
  struct State;
  std::unique_ptr<State> state;

public:
  ct_decompile_view();
  ~ct_decompile_view();
  ct_decompile_view(const ct_decompile_view &) = delete;
  ct_decompile_view &operator=(const ct_decompile_view &) = delete;
  /* FDs are borrowed and may close after mapping. Caller owns catalog refs.
   * A successful supplement keeps the existing common mapping; a failed
   * upgrade leaves the previous valid view intact. */
  bool map_common(int fd, uint64_t offset, size_t size, std::string &error);
  bool map_full(int fd, uint64_t offset, size_t size, std::string &error);
  uint64_t entry() const;
  const char *identity() const;
  uint32_t level() const;
  bool contains(uint64_t offset) const;
  bool statement(uint64_t offset, ct_decompiled_statement &result) const;
  bool display(uint64_t offset, ct_decompiled_display &result) const;
  bool variables(uint64_t offset, ct_decompiled_variables &result) const;
  bool proof(uint64_t offset, std::vector<unsigned char> &result) const;
};

#endif
