// SPDX-License-Identifier: MIT

#include <cstring>
#include <string_view>
#include <utility>

#include <fnmatch.h>
#include <regex.h>

#include "filter.hh"

/* Locate delimiters only; fnmatch/regcomp own pattern syntax and matching. */
static size_t bracket_end(std::string_view text, size_t begin) {
  size_t index = begin + 1;
  if (index < text.size() && (text[index] == '!' || text[index] == '^'))
    ++index;
  if (index < text.size() && text[index] == ']')
    ++index;
  for (; index < text.size(); ++index) {
    if (text[index] == '\\' && index + 1 < text.size()) {
      ++index;
    } else if (text[index] == '[' && index + 1 < text.size() &&
               std::strchr(":.=", text[index + 1])) {
      const std::string close = std::string(1, text[index + 1]) + ']';
      size_t end = text.find(close, index + 2);
      if (end == std::string_view::npos)
        return end;
      index = end + 1;
    } else if (text[index] == ']') {
      return index + 1;
    }
  }
  return std::string_view::npos;
}

struct FilterPattern {
  std::string text;
  bool regular = false;
  bool never = false;
  regex_t regex{};

  ~FilterPattern() {
    if (regular)
      regfree(&regex);
  }

  bool compile(std::string input, bool is_regular, std::string &error) {
    if (input.empty())
      input = is_regular ? ".*" : "*";
    if (is_regular) {
      const int status = regcomp(&regex, input.c_str(), 0); // POSIX basic RE.
      if (status) {
        char message[256];
        regerror(status, &regex, message, sizeof(message));
        error = "invalid filter regex: " + std::string(message);
        return false;
      }
      regular = true;
      return true;
    }
    // fnmatch already anchors the whole name. Handle ltrace's explicit ^/$
    // assertions without replacing the system glob matcher with a parser.
    size_t last_start = std::string::npos, first_end = std::string::npos;
    for (size_t index = 0; index < input.size(); ++index) {
      if (input[index] == '\\' && index + 1 < input.size()) {
        text.append(input, index, 2);
        ++index;
      } else if (input[index] == '[') {
        size_t end = bracket_end(input, index);
        if (end == std::string::npos) {
          error = "unterminated filter character class";
          return false;
        }
        text.append(input, index, end - index);
        index = end - 1;
      } else if (input[index] == '^') {
        last_start = text.size();
      } else if (input[index] == '$') {
        if (first_end == std::string::npos)
          first_end = text.size();
      } else {
        text += input[index];
      }
    }
    if (last_start != std::string::npos &&
        fnmatch(text.substr(0, last_start).c_str(), "", 0))
      never = true;
    if (first_end != std::string::npos &&
        fnmatch(text.substr(first_end).c_str(), "", 0))
      never = true;
    if (last_start != std::string::npos && first_end != std::string::npos &&
        last_start > first_end) {
      never |= fnmatch(text.c_str(), "", 0) != 0;
      text.clear();
    } else {
      const size_t begin = last_start == std::string::npos ? 0 : last_start;
      const size_t end =
          first_end == std::string::npos ? text.size() : first_end;
      text = text.substr(begin, end - begin);
    }
    return true;
  }

  bool matches(const char *name) const {
    if (!name || never)
      return false;
    if (!regular)
      return fnmatch(text.c_str(), name, 0) == 0;
    regmatch_t match;
    return regexec(&regex, name, 1, &match, 0) == 0 && match.rm_so == 0 &&
           (size_t)match.rm_eo == std::strlen(name);
  }
};

struct ct_filter::Rule {
  FilterPattern symbol;
  FilterPattern library;
  bool include = true;
  bool main = false;
  bool path = false;
};

struct PatternText {
  std::string text;
  bool regular = false;
};

static bool read_pattern(const std::string &input, size_t &position,
                         bool library, PatternText &pattern,
                         std::string &error) {
  const size_t begin = position;
  if (position < input.size() && input[position] == '/') {
    for (size_t index = position + 1; index < input.size(); ++index) {
      if (input[index] == '\\' && index + 1 < input.size()) {
        ++index;
      } else if (input[index] == '[') {
        size_t end = bracket_end(input, index);
        if (end == std::string::npos)
          break;
        index = end - 1;
      } else if (input[index] == '/' &&
                 (index + 1 == input.size() ||
                  std::strchr("@+-,", input[index + 1]))) {
        pattern.text = input.substr(begin + 1, index - begin - 1);
        pattern.regular = true;
        position = index + 1;
        return true;
      }
    }
    if (!library) {
      error = "unterminated filter regex";
      return false;
    }
  }
  while (position < input.size()) {
    char byte = input[position];
    if (std::strchr("@+-,", byte))
      break;
    if (byte == '\\') {
      if (++position == input.size()) {
        error = "trailing filter escape";
        return false;
      }
    } else if (byte == '[') {
      size_t end = bracket_end(input, position);
      if (end == std::string::npos) {
        error = "unterminated filter character class";
        return false;
      }
      position = end;
      continue;
    }
    ++position;
  }
  pattern.text = input.substr(begin, position - begin);
  return true;
}

ct_filter::ct_filter() = default;
ct_filter::~ct_filter() = default;
ct_filter::ct_filter(ct_filter &&) noexcept = default;
ct_filter &ct_filter::operator=(ct_filter &&) noexcept = default;

bool ct_filter::parse(const std::vector<std::string> &expressions,
                      std::string &error) {
  chains.clear();
  error.clear();
  for (const std::string &expression : expressions) {
    if (expression.empty()) {
      error = "empty filter expression";
      return false;
    }
    chains.emplace_back();
    size_t position = 0;
    while (position < expression.size()) {
      auto rule = std::make_unique<Rule>();
      if (expression[position] == '+' || expression[position] == '-')
        rule->include = expression[position++] == '+';
      const size_t begin = position;
      PatternText symbol, library;
      if (!read_pattern(expression, position, false, symbol, error))
        return false;
      bool combined = false;
      if (symbol.regular) {
        for (size_t index = 0; index < symbol.text.size(); ++index) {
          if (symbol.text[index] == '\\') {
            ++index;
          } else if (symbol.text[index] == '[') {
            size_t end = bracket_end(symbol.text, index);
            if (end == std::string::npos)
              break;
            index = end - 1;
          } else if (symbol.text[index] == '@') {
            library = {symbol.text.substr(index + 1), true};
            symbol.text.resize(index);
            combined = true;
            break;
          }
        }
      }
      if (!combined && position < expression.size() &&
          expression[position] == '@') {
        ++position;
        if (!read_pattern(expression, position, true, library, error))
          return false;
      }
      if (position == begin || (position < expression.size() &&
                                !std::strchr("+-,", expression[position]))) {
        error = "expected filter symbol[@library] rule";
        return false;
      }
      rule->main = !library.regular && library.text == "MAIN";
      rule->path = !library.text.empty() && library.text.front() == '/';
      if (!rule->symbol.compile(std::move(symbol.text), symbol.regular,
                                error) ||
          !rule->library.compile(std::move(library.text), library.regular,
                                 error))
        return false;
      chains.back().push_back(std::move(rule));
      if (position < expression.size() && expression[position] == ',') {
        if (++position == expression.size()) {
          error = "empty filter expression after comma";
          return false;
        }
        chains.emplace_back();
      }
    }
  }
  return true;
}

bool ct_filter::matches(const char *symbol, const char *soname,
                        const char *path, bool is_main) const {
  if (!symbol)
    return false;
  // An empty name is still eligible for wildcard and module-only rules.
  // Do not invent a symbol for dynamically generated or stripped code.
  if (!soname || !*soname) {
    const char *slash = path ? std::strrchr(path, '/') : nullptr;
    soname = slash ? slash + 1 : path;
  }
  for (const auto &chain : chains) {
    bool selected = !chain.empty() && !chain.front()->include;
    for (const auto &rule : chain) {
      bool library = rule->main
                         ? is_main
                         : rule->library.matches(rule->path ? path : soname);
      if (library && rule->symbol.matches(symbol))
        selected = rule->include;
    }
    if (selected)
      return true;
  }
  return false;
}
