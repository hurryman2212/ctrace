// SPDX-License-Identifier: MIT

#ifndef CTRACE_FILTER_H
#define CTRACE_FILTER_H

#include <memory>
#include <string>
#include <vector>

/* ltrace FILTER EXPRESSIONS; comma-separated chains are alternatives. */
class ct_filter {
  struct Rule;
  std::vector<std::vector<std::unique_ptr<Rule>>> chains;

public:
  ct_filter();
  ~ct_filter();
  ct_filter(const ct_filter &) = delete;
  ct_filter &operator=(const ct_filter &) = delete;
  ct_filter(ct_filter &&) noexcept;
  ct_filter &operator=(ct_filter &&) noexcept;
  bool parse(const std::vector<std::string> &expressions, std::string &error);
  bool matches(const char *symbol, const char *soname, const char *path,
               bool is_main) const;
};

#endif
