// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <type_traits>
#include <utility>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "analysis_protocol.hh"
#include "contract.hh"
#include "decompile_record.hh"
#include "decompile_view.hh"
#include "flow.hh"
#include "shared_objects_platform.hh"

bool ct_decompile_exceptions_valid(
    const std::vector<ct_decompile_exception> &exceptions,
    const std::vector<ct_decompiled_instruction> &instructions) {
  if (exceptions.empty())
    return true;
  if (exceptions.size() > UINT32_MAX || instructions.empty() ||
      instructions.size() > UINT32_MAX)
    return false;
  std::vector<std::vector<uint32_t>> active(instructions.size());
  std::vector<size_t> coverage(exceptions.size());
  std::set<uint64_t> ids;
  size_t range_count = 0;
  for (size_t index = 0; index < exceptions.size(); ++index) {
    const auto &exception = exceptions[index];
    const auto &scope = exception.scope;
    if (!scope.id || !ids.insert(scope.id).second || exception.ranges.empty() ||
        exception.ranges.size() > UINT32_MAX - range_count)
      return false;
    range_count += exception.ranges.size();
    const std::string &opening = scope.text;
    if (std::any_of(opening.begin(), opening.end(),
                    [](unsigned char ch) { return ch < ' ' || ch == 127; }) ||
        (scope.kind == CT_DECOMPILED_EXCEPTION_TRY
             ? opening != "try {"
             : scope.kind != CT_DECOMPILED_EXCEPTION_CATCH ||
                   opening.size() <= 10 || opening.compare(0, 7, "catch (") ||
                   opening.compare(opening.size() - 3, 3, ") {")))
      return false;
    if (scope.kind == CT_DECOMPILED_EXCEPTION_TRY
            ? scope.entry || scope.selector_register || scope.selector_bytes ||
                  scope.selector_value
            : scope.selector_register > 16 ||
                  (scope.selector_register
                       ? (scope.selector_bytes != 1 &&
                          scope.selector_bytes != 2 &&
                          scope.selector_bytes != 4 &&
                          scope.selector_bytes != 8) ||
                             (scope.selector_bytes < 8 &&
                              (scope.selector_value >>
                               (scope.selector_bytes * 8)))
                       : scope.selector_bytes || scope.selector_value))
      return false;
    bool contains_entry = scope.kind == CT_DECOMPILED_EXCEPTION_TRY;
    uint64_t previous_end = 0;
    for (const auto &range : exception.ranges) {
      if (range.begin >= range.end || range.begin < previous_end)
        return false;
      previous_end = range.end;
      auto instruction = std::lower_bound(
          instructions.begin(), instructions.end(), range.begin,
          [](const auto &item, uint64_t pc) { return item.offset < pc; });
      uint64_t next = range.begin;
      while (instruction != instructions.end() &&
             instruction->offset < range.end) {
        if (instruction->offset != next || !instruction->size ||
            instruction->size > range.end - next)
          return false;
        contains_entry |= instruction->offset == scope.entry;
        auto &membership = active[size_t(instruction - instructions.begin())];
        membership.push_back(uint32_t(index));
        ++coverage[index];
        next += instruction->size;
        ++instruction;
      }
      if (next != range.end)
        return false;
    }
    if (!contains_entry)
      return false;
  }
  // Each scope keeps one parent across its ranges. Mutually exclusive catch
  // alternatives may share instructions without becoming each other's parent.
  std::vector<size_t> parents(exceptions.size(), SIZE_MAX);
  for (const auto &membership : active)
    for (size_t index = 0; index < membership.size(); ++index) {
      const size_t scope = membership[index];
      size_t parent = exceptions.size();
      for (size_t prior = index; prior; --prior) {
        const size_t candidate = membership[prior - 1];
        const auto &left = exceptions[scope];
        const auto &right = exceptions[candidate];
        if (left.scope.kind == CT_DECOMPILED_EXCEPTION_CATCH &&
            right.scope.kind == CT_DECOMPILED_EXCEPTION_CATCH) {
          const bool separate_entries =
              left.scope.entry != right.scope.entry &&
              std::none_of(left.ranges.begin(), left.ranges.end(),
                           [&](const auto &range) {
                             return right.scope.entry >= range.begin &&
                                    right.scope.entry < range.end;
                           }) &&
              std::none_of(right.ranges.begin(), right.ranges.end(),
                           [&](const auto &range) {
                             return left.scope.entry >= range.begin &&
                                    left.scope.entry < range.end;
                           });
          const bool exclusive_selector =
              left.scope.entry == right.scope.entry &&
              left.scope.selector_register &&
              left.scope.selector_register == right.scope.selector_register &&
              left.scope.selector_bytes == right.scope.selector_bytes &&
              left.scope.selector_value != right.scope.selector_value;
          if (separate_entries || exclusive_selector)
            continue;
        }
        parent = candidate;
        break;
      }
      if (parent != exceptions.size() && coverage[parent] <= coverage[scope])
        return false;
      if (parents[scope] != SIZE_MAX && parents[scope] != parent)
        return false;
      parents[scope] = parent;
    }
  return true;
}

struct ViewRange {
  uint64_t offset = 0, count = 0;
};
struct ViewString {
  uint32_t offset = 0, size = 0;
};
struct ViewScalar {
  uint64_t bytes = 0;
  uint32_t kind = 0, reserved = 0;
};
struct ViewType {
  uint64_t bytes = 0;
  ViewScalar scalar;
  uint32_t kind = 0, element_type = 0;
  uint64_t element_count = 0, element_stride = 0, member_count = 0;
  uint32_t first_member = 0, flags = 0;
};
struct ViewStatement {
  uint64_t declaration = 0;
  uint32_t first = 0, count = 0;
  ViewString text, name, type;
};
struct ViewControl {
  uint64_t target = 0;
  uint32_t instruction = 0, flags = 0;
  ViewString text, kind, initializer, update;
};
struct ViewException {
  uint64_t id = 0, entry = 0, selector_value = 0;
  uint32_t kind = 0, first = 0, count = 0, reserved = 0;
  uint32_t selector_register = 0, selector_bytes = 0;
  ViewString opening;
};
struct ViewParameter {
  int64_t stack_offset = 0;
  uint32_t size = 0, kind = 0;
  ViewScalar type;
  ViewString name, spelling, reg;
};
struct ViewVariable {
  uint64_t id = 0, offset = 0;
  int64_t stack_offset = 0;
  uint32_t size = 0, kind = 0, access = 0, type_id = 0, alias = 0, reserved = 0;
  ViewScalar type;
  ViewString name, spelling, reg;
};
struct ViewScope {
  uint64_t offset = 0;
  uint32_t first = 0, count = 0;
};
struct ViewMember {
  uint64_t offset = 0;
  uint32_t type = 0, available = 0;
  ViewString name;
};
struct ViewCommon {
  uint64_t magic = UINT64_C(0x004e4f4d43444354);
  unsigned char contract[32] = CTRACE_CONTRACT_BYTES;
  uint64_t header_size = sizeof(ViewCommon), total_size = 0;
  uint64_t begin = 0, end = 0, entry = 0;
  uint32_t flags = 0, reserved = 0;
  ViewScalar return_type;
  ViewString name, prototype, return_name, return_register;
  ViewRange ranges, instructions, statements, controls, exceptions,
      exception_ranges, parameters, strings;
  char code_identity[65]{};
  char padding[7]{};
  char analysis_identity[65]{};
  char identity_padding[7]{};
};

struct ViewFull {
  uint64_t magic = UINT64_C(0x004c4c5546444354);
  unsigned char contract[32] = CTRACE_CONTRACT_BYTES;
  uint64_t header_size = sizeof(ViewFull), total_size = 0;
  std::array<unsigned char, 32> common_digest{};
  ViewRange globals, scoped, scopes, types, members, strings;
};

static_assert(std::has_unique_object_representations_v<ViewCommon> &&
              std::has_unique_object_representations_v<ViewFull> &&
              std::has_unique_object_representations_v<ViewParameter> &&
              std::has_unique_object_representations_v<ViewVariable> &&
              std::has_unique_object_representations_v<ViewType>);

static ViewScalar view_scalar(const ct_value_type &type) {
  return {type.bytes, uint32_t(type.kind), 0};
}

struct ViewWriter {
  std::vector<unsigned char> &bytes;
  std::vector<unsigned char> strings{0};
  std::map<std::string, ViewString> known{};
  bool valid = true;

  ViewString text(const std::string &value) {
    if (value.empty())
      return {};
    const auto found = known.find(value);
    if (found != known.end())
      return found->second;
    if (value.size() >= UINT32_MAX ||
        strings.size() >= UINT32_MAX - value.size()) {
      valid = false;
      return {};
    }
    ViewString result{uint32_t(strings.size()), uint32_t(value.size())};
    strings.insert(strings.end(), value.begin(), value.end());
    strings.push_back(0);
    known.emplace(value, result);
    return result;
  }

  template <typename T> ViewRange table(const std::vector<T> &values) {
    if (bytes.size() > SIZE_MAX - (alignof(T) - 1)) {
      valid = false;
      return {};
    }
    const size_t offset =
        (bytes.size() + alignof(T) - 1) / alignof(T) * alignof(T);
    if (values.size() > (SIZE_MAX - offset) / sizeof(T)) {
      valid = false;
      return {};
    }
    bytes.resize(offset + values.size() * sizeof(T));
    if (!values.empty())
      std::memcpy(bytes.data() + offset, values.data(),
                  values.size() * sizeof(T));
    return {offset, values.size()};
  }
};

bool ct_decompile_view_encode(const ct_decompile_record &record,
                              std::vector<unsigned char> &common,
                              std::vector<unsigned char> &full,
                              std::string &error) {
  common.clear();
  full.clear();
  error = "invalid decompile record for shared view";
  if ((record.level != CT_DECOMPILE_PERFETTO &&
       record.level != CT_DECOMPILE_FULL) ||
      record.begin >= record.end || record.entry < record.begin ||
      record.entry >= record.end || record.original_instructions.empty() ||
      record.original_instructions.size() > UINT32_MAX ||
      record.parameters.size() > UINT32_MAX)
    return false;
  std::vector<ct_decompiled_range> ranges;
  std::vector<ct_decompiled_instruction> instructions;
  std::map<uint64_t, uint32_t> indices;
  for (const auto &[begin, end] : record.ranges)
    ranges.push_back({begin, end});
  for (const auto &[pc, instruction] : record.original_instructions) {
    indices.emplace(pc, uint32_t(instructions.size()));
    instructions.push_back(instruction);
  }
  std::vector<unsigned char> proof;
  if (!ct_build_code_proof(record.entry, CT_DECOMPILE_PERFETTO, ranges,
                           instructions, proof))
    return false;
  ct_decompiled_proof_header proof_header;
  std::memcpy(&proof_header, proof.data(), sizeof(proof_header));
  ViewCommon header;
  header.begin = record.begin;
  header.end = record.end;
  header.entry = record.entry;
  header.flags =
      (record.return_known ? 1u : 0u) | (record.return_void ? 2u : 0u) |
      (record.return_unsupported ? 4u : 0u) |
      (record.parameters_known ? 8u : 0u) | (record.variadic ? 16u : 0u);
  header.return_type = view_scalar(record.return_type);
  if (!record.identity.empty() &&
      (record.identity.size() != 64 ||
       record.identity.find_first_not_of("0123456789abcdef") !=
           std::string::npos))
    return false;
  std::memcpy(header.analysis_identity, record.identity.data(),
              record.identity.size());
  std::memcpy(header.code_identity, proof_header.code_identity,
              sizeof(header.code_identity));
  common.resize(sizeof(header));
  ViewWriter writer{common};
  header.name = writer.text(record.name);
  header.prototype = writer.text(record.prototype);
  header.return_name = writer.text(record.return_type_name);
  header.return_register = writer.text(record.return_register);
  header.ranges = writer.table(ranges);
  header.instructions = writer.table(instructions);
  std::vector<ViewStatement> statements;
  for (const auto &statement : record.statements) {
    if (!statement.instruction_count ||
        statement.instruction_count != statement.instructions.size())
      return false;
    const auto first = indices.find(statement.instructions[0].offset);
    if (first == indices.end() ||
        statement.instruction_count > instructions.size() - first->second)
      return false;
    for (uint32_t index = 0; index < statement.instruction_count; ++index)
      if (std::memcmp(&statement.instructions[index],
                      &instructions[first->second + index],
                      sizeof(ct_decompiled_instruction)))
        return false;
    statements.push_back(
        {statement.declaration_id, first->second, statement.instruction_count,
         writer.text(statement.text), writer.text(statement.declaration_name),
         writer.text(statement.declaration_type)});
  }
  std::sort(statements.begin(), statements.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  header.statements = writer.table(statements);
  std::vector<ViewControl> controls;
  for (const auto &[pc, control] : record.controls) {
    const auto instruction = indices.find(pc);
    if (instruction == indices.end())
      return false;
    controls.push_back({control.control_target, instruction->second,
                        (control.control_conditional ? 1u : 0u) |
                            (control.control_has_target ? 2u : 0u),
                        writer.text(control.control_text),
                        writer.text(control.control_kind),
                        writer.text(control.control_initializer),
                        writer.text(control.control_update)});
  }
  header.controls = writer.table(controls);
  if (!ct_decompile_exceptions_valid(record.exceptions, instructions))
    return false;
  std::vector<ViewException> exceptions;
  std::vector<ct_decompiled_range> exception_ranges;
  for (const auto &exception : record.exceptions) {
    exceptions.push_back(
        {exception.scope.id, exception.scope.entry,
         exception.scope.selector_value, exception.scope.kind,
         uint32_t(exception_ranges.size()), uint32_t(exception.ranges.size()),
         0, exception.scope.selector_register, exception.scope.selector_bytes,
         writer.text(exception.scope.text)});
    exception_ranges.insert(exception_ranges.end(), exception.ranges.begin(),
                            exception.ranges.end());
  }
  header.exceptions = writer.table(exceptions);
  header.exception_ranges = writer.table(exception_ranges);
  std::vector<ViewParameter> parameters;
  for (const auto &parameter : record.parameters)
    parameters.push_back({parameter.stack_offset, parameter.size,
                          uint32_t(parameter.kind), view_scalar(parameter.type),
                          writer.text(parameter.name),
                          writer.text(parameter.type_name),
                          writer.text(parameter.register_name)});
  header.parameters = writer.table(parameters);
  header.strings = writer.table(writer.strings);
  header.total_size = common.size();
  if (!writer.valid)
    return false;
  std::memcpy(common.data(), &header, sizeof(header));
  if (record.level == CT_DECOMPILE_FULL) {
    ViewFull extra;
    if (!ct_shared_platform_digest(common.data(), common.size(),
                                   extra.common_digest.data()))
      return false;
    full.resize(sizeof(extra));
    ViewWriter output{full};
    const auto variable = [&](const ct_decompiled_variable &item) {
      return ViewVariable{item.id,
                          item.offset,
                          item.stack_offset,
                          item.size,
                          uint32_t(item.kind),
                          item.access,
                          item.type_id,
                          item.register_alias ? 1u : 0u,
                          0,
                          view_scalar(item.type),
                          output.text(item.name),
                          output.text(item.type_name),
                          output.text(item.register_name)};
    };
    std::vector<ViewVariable> globals, scoped;
    std::vector<ViewScope> scopes;
    for (const auto &item : record.variables)
      globals.push_back(variable(item));
    for (const auto &[pc, items] : record.scoped_variables) {
      if (scoped.size() > UINT32_MAX || items.size() > UINT32_MAX)
        return false;
      scopes.push_back({pc, uint32_t(scoped.size()), uint32_t(items.size())});
      for (const auto &item : items)
        scoped.push_back(variable(item));
    }
    std::vector<ViewMember> members;
    for (const auto &member : record.members)
      members.push_back({member.offset, member.type, member.available ? 1u : 0u,
                         output.text(member.name)});
    extra.globals = output.table(globals);
    extra.scoped = output.table(scoped);
    extra.scopes = output.table(scopes);
    std::vector<ViewType> types;
    for (const auto &type : record.types)
      types.push_back({type.bytes, view_scalar(type.scalar),
                       uint32_t(type.kind), type.element_type,
                       type.element_count, type.element_stride,
                       type.member_count, type.first_member,
                       (type.complete ? 1u : 0u) | (type.guarded ? 2u : 0u)});
    extra.types = output.table(types);
    extra.members = output.table(members);
    extra.strings = output.table(output.strings);
    extra.total_size = full.size();
    if (!output.valid)
      return false;
    std::memcpy(full.data(), &extra, sizeof(extra));
  }
  error.clear();
  return true;
}

template <class T> struct ViewTable {
  const T *data = nullptr;
  size_t count = 0;
  const T *begin() const { return data; }
  const T *end() const { return count ? data + count : data; }
  const T &operator[](size_t index) const { return data[index]; }
};

struct ViewMapping {
  unsigned char *data = nullptr;
  size_t size = 0;
  ~ViewMapping() {
    if (data)
      munmap(data, size);
  }
  bool open(int fd, uint64_t offset, size_t length, std::string &error) {
    error = "invalid shared decompile mapping";
    const long page = sysconf(_SC_PAGESIZE);
    struct stat status{};
    const int seals = fcntl(fd, F_GET_SEALS);
    const int required =
        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_EXEC;
    if (page <= 0 || offset % uint64_t(page) || offset > INT64_MAX || !length ||
        seals < 0 || (seals & required) != required ||
        fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & 0111) || status.st_size < 0 ||
        offset > uint64_t(status.st_size) ||
        length > uint64_t(status.st_size) - offset)
      return false;
    void *mapped =
        mmap(nullptr, length, PROT_READ, MAP_SHARED, fd, off_t(offset));
    if (mapped == MAP_FAILED) {
      error =
          "cannot map shared decompile data: " + std::string(strerror(errno));
      return false;
    }
    data = static_cast<unsigned char *>(mapped);
    size = length;
    return true;
  }
};

// Tables are contiguous in encoder order. Requiring that canonical layout also
// rejects overlapping tables, aliases into headers and hidden trailing bytes.
struct ViewReader {
  const ViewMapping &mapping;
  size_t cursor;
  template <class T>
  bool table(ViewRange range, ViewTable<T> &result, size_t maximum = SIZE_MAX) {
    if (cursor > SIZE_MAX - (alignof(T) - 1))
      return false;
    const size_t aligned = (cursor + alignof(T) - 1) / alignof(T) * alignof(T);
    if (aligned > mapping.size || range.offset != aligned ||
        range.count > maximum ||
        range.count > (mapping.size - aligned) / sizeof(T))
      return false;
    result = {reinterpret_cast<const T *>(mapping.data + aligned),
              size_t(range.count)};
    cursor = aligned + result.count * sizeof(T);
    return true;
  }
};

struct ViewText {
  ViewTable<unsigned char> bytes;
  bool valid(ViewString value, bool required = false) const {
    if (!bytes.count || (required && !value.size) ||
        value.offset >= bytes.count ||
        value.size >= bytes.count - value.offset ||
        bytes[value.offset + value.size] ||
        std::memchr(bytes.data + value.offset, 0, value.size))
      return false;
    for (size_t index = 0; index < value.size; ++index)
      if (bytes[value.offset + index] < ' ' ||
          bytes[value.offset + index] == 127)
        return false;
    return true;
  }
  const char *get(ViewString value) const {
    return reinterpret_cast<const char *>(bytes.data + value.offset);
  }
  void copy(ViewString value, std::string &output) const {
    output.assign(get(value), value.size);
  }
};

static bool valid_scalar(const ViewScalar &type) {
  return !type.reserved && type.kind <= CT_VALUE_POINTER &&
         type.bytes <= SIZE_MAX;
}

static bool valid_identifier(const char *name) {
  if (!*name)
    return false;
  for (size_t index = 0; name[index]; ++index) {
    const unsigned char ch = name[index];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' ||
          (index && ch >= '0' && ch <= '9')))
      return false;
  }
  return true;
}

static unsigned argument_register(const char *name, uint32_t size,
                                  bool floating) {
  if (floating)
    return (size == 4 || size == 8) && std::strlen(name) == 4 &&
                   std::strncmp(name, "xmm", 3) == 0 && name[3] >= '0' &&
                   name[3] <= '7'
               ? 7u + unsigned(name[3] - '0')
               : 0;
  static constexpr const char *general[][4] = {
      {"dil", "di", "edi", "rdi"}, {"sil", "si", "esi", "rsi"},
      {"dl", "dx", "edx", "rdx"},  {"cl", "cx", "ecx", "rcx"},
      {"r8b", "r8w", "r8d", "r8"}, {"r9b", "r9w", "r9d", "r9"}};
  for (unsigned family = 0; family < std::size(general); ++family)
    for (unsigned width = 0; width < 4; ++width)
      if (size <= (1u << width) &&
          std::strcmp(name, general[family][width]) == 0)
        return family + 1;
  return 0;
}

static bool valid_register_alias(const char *name, const char *reg,
                                 uint32_t size) {
  if (std::strlen(name) != std::strlen(reg))
    return false;
  for (size_t index = 0; reg[index]; ++index) {
    char lower = name[index];
    if (lower >= 'A' && lower <= 'Z')
      lower += 'a' - 'A';
    if (lower != reg[index])
      return false;
  }
  static constexpr const char *general[][4] = {
      {"al", "ax", "eax", "rax"},      {"cl", "cx", "ecx", "rcx"},
      {"dl", "dx", "edx", "rdx"},      {"bl", "bx", "ebx", "rbx"},
      {"spl", "sp", "esp", "rsp"},     {"bpl", "bp", "ebp", "rbp"},
      {"sil", "si", "esi", "rsi"},     {"dil", "di", "edi", "rdi"},
      {"r8b", "r8w", "r8d", "r8"},     {"r9b", "r9w", "r9d", "r9"},
      {"r10b", "r10w", "r10d", "r10"}, {"r11b", "r11w", "r11d", "r11"},
      {"r12b", "r12w", "r12d", "r12"}, {"r13b", "r13w", "r13d", "r13"},
      {"r14b", "r14w", "r14d", "r14"}, {"r15b", "r15w", "r15d", "r15"}};
  for (const auto &family : general)
    for (unsigned width = 0; width < 4; ++width)
      if (size == (1u << width) && std::strcmp(reg, family[width]) == 0)
        return true;
  return size == 1 &&
         (std::strcmp(reg, "ah") == 0 || std::strcmp(reg, "ch") == 0 ||
          std::strcmp(reg, "dh") == 0 || std::strcmp(reg, "bh") == 0);
}

struct ct_decompile_view::State {
  std::unique_ptr<ViewMapping> common;
  const ViewCommon *header = nullptr;
  std::array<unsigned char, 32> digest{};
  ViewTable<ct_decompiled_range> ranges;
  ViewTable<ct_decompiled_instruction> instructions;
  ViewTable<ViewStatement> statements;
  ViewTable<ViewControl> controls;
  ViewTable<ViewException> exceptions;
  ViewTable<ct_decompiled_range> exception_ranges;
  ViewTable<ViewParameter> parameters;
  ViewText text;
  struct Supplement {
    std::unique_ptr<ViewMapping> mapping;
    ViewTable<ViewVariable> globals, scoped;
    ViewTable<ViewScope> scopes;
    ViewTable<ViewType> types;
    ViewTable<ViewMember> members;
    ViewText text;
  };
  std::unique_ptr<Supplement> full;

  const ct_decompiled_instruction *instruction(uint64_t offset) const {
    const auto found = std::lower_bound(
        instructions.begin(), instructions.end(), offset,
        [](const auto &item, uint64_t pc) { return item.offset < pc; });
    return found != instructions.end() && found->offset == offset ? found
                                                                  : nullptr;
  }

  void proof(std::vector<unsigned char> &result, uint32_t level) const {
    ct_decompiled_proof_header output;
    std::memset(&output, 0, sizeof(output));
    output.function_offset = header->entry;
    output.loaded_level = level;
    output.range_count = uint32_t(ranges.count);
    output.instruction_count = uint32_t(instructions.count);
    std::memcpy(output.code_identity, header->code_identity,
                sizeof(output.code_identity));
    result.resize(sizeof(output) + ranges.count * sizeof(ranges[0]) +
                  instructions.count * sizeof(instructions[0]));
    std::memcpy(result.data(), &output, sizeof(output));
    std::memcpy(result.data() + sizeof(output), ranges.data,
                ranges.count * sizeof(ranges[0]));
    std::memcpy(
        result.data() + sizeof(output) + ranges.count * sizeof(ranges[0]),
        instructions.data, instructions.count * sizeof(instructions[0]));
  }

  bool validate_common(std::string &error) {
    error = "invalid shared decompile common record";
    if (common->size < sizeof(ViewCommon))
      return false;
    header = reinterpret_cast<const ViewCommon *>(common->data);
    const ViewCommon expected;
    if (header->magic != expected.magic ||
        !ct_contract_matches(header->contract) ||
        header->header_size != sizeof(*header) ||
        header->total_size != common->size || header->flags & ~31u ||
        header->reserved || header->begin >= header->end ||
        header->entry < header->begin || header->entry >= header->end ||
        !valid_scalar(header->return_type) ||
        std::any_of(
            std::begin(header->padding), std::end(header->padding),
            [](char value) { return value != 0; }) ||
        std::any_of(
            std::begin(header->identity_padding),
            std::end(header->identity_padding),
            [](char value) { return value != 0; }))
      return false;
    if (header->analysis_identity[64])
      return false;
    for (unsigned index = 0; index < 64; ++index) {
      const char value = header->analysis_identity[index];
      if (header->analysis_identity[0] ? !((value >= '0' && value <= '9') ||
                                           (value >= 'a' && value <= 'f'))
                                       : value != 0)
        return false;
    }
    ViewReader reader{*common, sizeof(*header)};
    if (!reader.table(header->ranges, ranges, UINT32_MAX) ||
        !reader.table(header->instructions, instructions, UINT32_MAX) ||
        !reader.table(header->statements, statements, UINT32_MAX) ||
        !reader.table(header->controls, controls, UINT32_MAX) ||
        !reader.table(header->exceptions, exceptions, UINT32_MAX) ||
        !reader.table(header->exception_ranges, exception_ranges, UINT32_MAX) ||
        !reader.table(header->parameters, parameters, UINT32_MAX) ||
        !reader.table(header->strings, text.bytes) ||
        reader.cursor != common->size || !ranges.count || !instructions.count ||
        !text.bytes.count || text.bytes[0] ||
        header->begin != ranges[0].begin ||
        header->end < ranges[ranges.count - 1].end ||
        !text.valid(header->name) || !text.valid(header->prototype) ||
        !text.valid(header->return_name) ||
        !text.valid(header->return_register))
      return false;
    // Validate both the instruction cover and its stored level-independent
    // digest. The temporary proof is released before the view is published.
    std::vector<unsigned char> original;
    proof(original, CT_DECOMPILE_PERFETTO);
    if (!ct_decompiled_proof_valid(original.data(), original.size()))
      return false;
    ct_decompiled_proof_header identity;
    std::memset(&identity, 0, sizeof(identity));
    identity.function_offset = header->entry;
    identity.range_count = uint32_t(ranges.count);
    identity.instruction_count = uint32_t(instructions.count);
    std::memcpy(original.data(), &identity, sizeof(identity));
    std::array<unsigned char, 32> hash{};
    if (!ct_shared_platform_digest(original.data(), original.size(),
                                   hash.data()))
      return false;
    constexpr char hex[] = "0123456789abcdef";
    for (size_t index = 0; index < hash.size(); ++index)
      if (header->code_identity[2 * index] != hex[hash[index] >> 4] ||
          header->code_identity[2 * index + 1] != hex[hash[index] & 15])
        return false;
    if ((header->flags & 2u) && !(header->flags & 1u))
      return false;
    if ((header->flags & 1u) && (header->flags & 4u))
      return false;
    if (!(header->flags & 8u) && (parameters.count || (header->flags & 16u)))
      return false;
    if (header->flags & 1u) {
      const auto &type = header->return_type;
      const char *reg = text.get(header->return_register);
      if (header->flags & 2u) {
        if (std::strcmp(text.get(header->return_name), "void") || *reg)
          return false;
      } else if (!header->return_name.size ||
                 (type.kind == CT_VALUE_FLOAT
                      ? !(((type.bytes == 4 || type.bytes == 8) &&
                           std::strcmp(reg, "xmm0") == 0) ||
                          (type.bytes == 10 && std::strcmp(reg, "st0") == 0))
                      : !((type.bytes == 1 && std::strcmp(reg, "al") == 0) ||
                          (type.bytes == 2 && std::strcmp(reg, "ax") == 0) ||
                          (type.bytes == 4 && std::strcmp(reg, "eax") == 0) ||
                          (type.bytes == 8 && std::strcmp(reg, "rax") == 0))) ||
                 (type.kind == CT_VALUE_POINTER && type.bytes != 8)) {
        return false;
      }
    }
    size_t previous = 0;
    for (const auto &statement : statements) {
      if (!statement.count || statement.first < previous ||
          statement.first >= instructions.count ||
          statement.count > instructions.count - statement.first ||
          !text.valid(statement.text, true) || !text.valid(statement.name) ||
          !text.valid(statement.type))
        return false;
      for (size_t index = 1; index < statement.count; ++index) {
        const auto &left = instructions[statement.first + index - 1];
        if (left.offset + left.size !=
            instructions[statement.first + index].offset)
          return false;
      }
      previous = statement.first + statement.count;
    }
    previous = 0;
    for (size_t index = 0; index < controls.count; ++index) {
      const auto &control = controls[index];
      if (control.instruction >= instructions.count ||
          (index && control.instruction <= previous) || control.flags & ~3u ||
          !text.valid(control.text, true) || !text.valid(control.kind) ||
          !text.valid(control.initializer) || !text.valid(control.update))
        return false;
      previous = control.instruction;
    }
    if (exceptions.count || exception_ranges.count) {
      std::vector<ct_decompile_exception> decoded;
      size_t next = 0;
      for (const auto &exception : exceptions) {
        if (exception.reserved || exception.first != next ||
            exception.first > exception_ranges.count ||
            exception.count > exception_ranges.count - exception.first ||
            !text.valid(exception.opening, true))
          return false;
        ct_decompile_exception item;
        item.scope.id = exception.id;
        item.scope.entry = exception.entry;
        item.scope.selector_value = exception.selector_value;
        item.scope.kind = exception.kind;
        item.scope.selector_register = exception.selector_register;
        item.scope.selector_bytes = exception.selector_bytes;
        text.copy(exception.opening, item.scope.text);
        item.ranges.assign(exception_ranges.data + exception.first,
                           exception_ranges.data + exception.first +
                               exception.count);
        decoded.push_back(std::move(item));
        next += exception.count;
      }
      if (next != exception_ranges.count ||
          !ct_decompile_exceptions_valid(
              decoded, {instructions.begin(), instructions.end()}))
        return false;
    }
    for (size_t index = 0; index < parameters.count; ++index) {
      const auto &parameter = parameters[index];
      if (!valid_scalar(parameter.type) ||
          parameter.type.bytes != parameter.size ||
          (parameter.size != 1 && parameter.size != 2 && parameter.size != 4 &&
           parameter.size != 8) ||
          (parameter.type.kind == CT_VALUE_POINTER && parameter.size != 8) ||
          (parameter.type.kind == CT_VALUE_FLOAT && parameter.size != 4 &&
           parameter.size != 8) ||
          !text.valid(parameter.name, true) ||
          !valid_identifier(text.get(parameter.name)) ||
          !text.valid(parameter.spelling, true) || !text.valid(parameter.reg))
        return false;
      const unsigned reg =
          argument_register(text.get(parameter.reg), parameter.size,
                            parameter.type.kind == CT_VALUE_FLOAT);
      if (parameter.kind == CT_DECOMPILED_STACK) {
        if (parameter.stack_offset < 8 ||
            parameter.stack_offset > INT64_MAX - parameter.size)
          return false;
      } else if (parameter.kind != CT_DECOMPILED_REGISTER || !reg) {
        return false;
      }
      for (size_t prior = 0; prior < index; ++prior) {
        const auto &old = parameters[prior];
        if (std::strcmp(text.get(old.name), text.get(parameter.name)) == 0 ||
            (parameter.kind == CT_DECOMPILED_REGISTER &&
             old.kind == parameter.kind &&
             argument_register(text.get(old.reg), old.size,
                               old.type.kind == CT_VALUE_FLOAT) == reg) ||
            (parameter.kind == CT_DECOMPILED_STACK &&
             old.kind == parameter.kind &&
             old.stack_offset < parameter.stack_offset + parameter.size &&
             parameter.stack_offset < old.stack_offset + old.size))
          return false;
      }
    }
    return ct_shared_platform_digest(common->data, common->size, digest.data());
  }

  bool add_full(std::unique_ptr<ViewMapping> mapping, std::string &error) {
    error = "invalid shared decompile full supplement";
    if (mapping->size < sizeof(ViewFull))
      return false;
    const auto &header = *reinterpret_cast<const ViewFull *>(mapping->data);
    const ViewFull expected;
    if (header.magic != expected.magic ||
        !ct_contract_matches(header.contract) ||
        header.header_size != sizeof(header) ||
        header.total_size != mapping->size || header.common_digest != digest)
      return false;
    auto loaded = std::make_unique<Supplement>();
    ViewReader reader{*mapping, sizeof(header)};
    if (!reader.table(header.globals, loaded->globals, UINT32_MAX) ||
        !reader.table(header.scoped, loaded->scoped) ||
        !reader.table(header.scopes, loaded->scopes, UINT32_MAX) ||
        !reader.table(header.types, loaded->types, UINT32_MAX) ||
        !reader.table(header.members, loaded->members, UINT32_MAX) ||
        !reader.table(header.strings, loaded->text.bytes) ||
        reader.cursor != mapping->size || !loaded->text.bytes.count ||
        loaded->text.bytes[0])
      return false;
    for (const auto &member : loaded->members)
      if (member.type > loaded->types.count || member.available > 1 ||
          (member.available && !member.type) ||
          !loaded->text.valid(member.name, true))
        return false;
    for (const auto &type : loaded->types) {
      if (!type.bytes || type.bytes > SIZE_MAX ||
          type.kind > CT_LAYOUT_POINTER || !valid_scalar(type.scalar) ||
          type.scalar.bytes != type.bytes || type.flags & ~3u ||
          type.element_type > loaded->types.count ||
          type.first_member > loaded->members.count ||
          type.member_count > loaded->members.count - type.first_member)
        return false;
      if (type.kind == CT_LAYOUT_ARRAY &&
          (!type.element_stride || type.element_stride > SIZE_MAX ||
           type.element_count > type.bytes / type.element_stride ||
           (type.element_type &&
            loaded->types[type.element_type - 1].bytes > type.element_stride)))
        return false;
      if (type.kind == CT_LAYOUT_POINTER &&
          (type.bytes != 8 || type.scalar.kind != CT_VALUE_POINTER))
        return false;
      if (type.kind == CT_LAYOUT_SCALAR &&
          (type.scalar.kind == CT_VALUE_FLOAT
               ? type.bytes != 4 && type.bytes != 8
               : type.bytes != 1 && type.bytes != 2 && type.bytes != 4 &&
                     type.bytes != 8))
        return false;
      if (type.kind == CT_LAYOUT_STRUCT)
        for (size_t index = 0; index < type.member_count; ++index) {
          const auto &member = loaded->members[type.first_member + index];
          if (member.offset > type.bytes ||
              (member.available && loaded->types[member.type - 1].bytes >
                                       type.bytes - member.offset))
            return false;
        }
    }
    const auto valid_variable = [&](const ViewVariable &variable, bool scoped) {
      if (!variable.id || !variable.size ||
          variable.kind > CT_DECOMPILED_REGISTER || !variable.access ||
          variable.access & ~(CT_DECOMPILED_READ | CT_DECOMPILED_WRITE) ||
          variable.type_id > loaded->types.count || variable.alias > 1 ||
          variable.reserved || !valid_scalar(variable.type) ||
          variable.type.bytes != variable.size ||
          (variable.type_id &&
           loaded->types[variable.type_id - 1].bytes != variable.size) ||
          !loaded->text.valid(variable.name, true) ||
          !valid_identifier(loaded->text.get(variable.name)) ||
          !loaded->text.valid(variable.spelling) ||
          !loaded->text.valid(variable.reg))
        return false;
      if (variable.kind == CT_DECOMPILED_REGISTER &&
          (!scoped || !variable.reg.size || variable.size > 64))
        return false;
      if (variable.type.kind != CT_VALUE_UNKNOWN &&
          ((variable.type.kind == CT_VALUE_FLOAT && variable.size != 4 &&
            variable.size != 8 &&
            !(variable.size == 10 && variable.kind == CT_DECOMPILED_REGISTER &&
              variable.reg.size == 3 &&
              std::strncmp(loaded->text.get(variable.reg), "st", 2) == 0 &&
              loaded->text.get(variable.reg)[2] >= '0' &&
              loaded->text.get(variable.reg)[2] <= '7')) ||
           (variable.type.kind == CT_VALUE_POINTER && variable.size != 8) ||
           (variable.type.kind != CT_VALUE_FLOAT && variable.size != 1 &&
            variable.size != 2 && variable.size != 4 && variable.size != 8)))
        return false;
      if (variable.kind == CT_DECOMPILED_REGISTER)
        for (const char *reg = loaded->text.get(variable.reg); *reg; ++reg)
          if (!((*reg >= 'a' && *reg <= 'z') || (*reg >= '0' && *reg <= '9')))
            return false;
      if (variable.kind == CT_DECOMPILED_STACK &&
          variable.stack_offset > INT64_MAX - variable.size)
        return false;
      if (variable.kind == CT_DECOMPILED_GLOBAL &&
          variable.offset > UINT64_MAX - variable.size)
        return false;
      return !variable.alias ||
             (scoped && variable.kind == CT_DECOMPILED_REGISTER &&
              variable.access == CT_DECOMPILED_READ &&
              (variable.type.kind == CT_VALUE_UNKNOWN ||
               variable.type.kind == CT_VALUE_UNSIGNED) &&
              valid_register_alias(loaded->text.get(variable.name),
                                   loaded->text.get(variable.reg),
                                   variable.size));
    };
    for (const auto &variable : loaded->globals)
      if (!valid_variable(variable, false))
        return false;
    size_t next = 0;
    uint64_t previous = 0;
    for (size_t index = 0; index < loaded->scopes.count; ++index) {
      const auto &scope = loaded->scopes[index];
      if ((index && scope.offset <= previous) || !instruction(scope.offset) ||
          scope.first != next || scope.first > loaded->scoped.count ||
          scope.count > loaded->scoped.count - scope.first)
        return false;
      for (size_t item = 0; item < scope.count; ++item)
        if (!valid_variable(loaded->scoped[scope.first + item], true))
          return false;
      next += scope.count;
      previous = scope.offset;
    }
    if (next != loaded->scoped.count)
      return false;
    loaded->mapping = std::move(mapping);
    full = std::move(loaded);
    error.clear();
    return true;
  }
};

ct_decompile_view::ct_decompile_view() = default;
ct_decompile_view::~ct_decompile_view() = default;

bool ct_decompile_view::map_common(int fd, uint64_t offset, size_t size,
                                   std::string &error) {
  auto loaded = std::make_unique<State>();
  loaded->common = std::make_unique<ViewMapping>();
  if (!loaded->common->open(fd, offset, size, error) ||
      !loaded->validate_common(error))
    return false;
  if (!state || state->digest != loaded->digest)
    state = std::move(loaded);
  error.clear();
  return true;
}

bool ct_decompile_view::map_full(int fd, uint64_t offset, size_t size,
                                 std::string &error) {
  error = "shared decompile supplement has no common view";
  if (!state)
    return false;
  auto mapping = std::make_unique<ViewMapping>();
  return mapping->open(fd, offset, size, error) &&
         state->add_full(std::move(mapping), error);
}

uint64_t ct_decompile_view::entry() const {
  return state ? state->header->entry : 0;
}
const char *ct_decompile_view::identity() const {
  return state ? state->header->analysis_identity : "";
}
uint32_t ct_decompile_view::level() const {
  return !state ? 0 : state->full ? CT_DECOMPILE_FULL : CT_DECOMPILE_PERFETTO;
}
bool ct_decompile_view::contains(uint64_t offset) const {
  return state && state->instruction(offset);
}

bool ct_decompile_view::statement(uint64_t offset,
                                  ct_decompiled_statement &result) const {
  result = {};
  const auto *instruction = state ? state->instruction(offset) : nullptr;
  if (!instruction)
    return false;
  const size_t index = instruction - state->instructions.data;
  auto found = std::upper_bound(
      state->statements.begin(), state->statements.end(), index,
      [](size_t value, const auto &item) { return value < item.first; });
  if (found == state->statements.begin())
    return false;
  --found;
  if (index - found->first >= found->count)
    return false;
  result.id = state->instructions[found->first].offset + 1;
  result.function_offset = state->header->entry;
  result.instruction_count = found->count;
  result.instruction_index = uint32_t(index - found->first);
  result.declaration_id = found->declaration;
  state->text.copy(found->text, result.text);
  state->text.copy(found->name, result.declaration_name);
  state->text.copy(found->type, result.declaration_type);
  result.instructions.assign(state->instructions.data + found->first,
                             state->instructions.data + found->first +
                                 found->count);
  return true;
}

bool ct_decompile_view::display(uint64_t offset,
                                ct_decompiled_display &result) const {
  result = {};
  const auto *instruction = state ? state->instruction(offset) : nullptr;
  if (!instruction)
    return false;
  result.function_offset = state->header->entry;
  result.loaded_level = level();
  result.instruction = *instruction;
  state->text.copy(state->header->name, result.function_name);
  state->text.copy(state->header->prototype, result.prototype);
  const size_t index = instruction - state->instructions.data;
  const auto control = std::lower_bound(
      state->controls.begin(), state->controls.end(), index,
      [](const auto &item, size_t value) { return item.instruction < value; });
  if (control != state->controls.end() && control->instruction == index) {
    state->text.copy(control->text, result.control_text);
    state->text.copy(control->kind, result.control_kind);
    state->text.copy(control->initializer, result.control_initializer);
    state->text.copy(control->update, result.control_update);
    result.control_conditional = (control->flags & 1u) != 0;
    result.control_has_target = (control->flags & 2u) != 0;
    result.control_target = control->target;
  }
  for (const auto &exception : state->exceptions) {
    const auto *first = state->exception_ranges.data + exception.first;
    result.exception_boundary |=
        (exception.kind == CT_DECOMPILED_EXCEPTION_CATCH &&
         offset == exception.entry) ||
        std::any_of(first, first + exception.count, [&](const auto &range) {
          return offset == range.begin || offset == range.end;
        });
    if (std::none_of(first, first + exception.count, [&](const auto &range) {
          return offset >= range.begin && offset < range.end;
        }))
      continue;
    auto &output = result.exceptions.emplace_back();
    ++result.exception_count;
    output.id = exception.id;
    output.entry = exception.entry;
    output.selector_value = exception.selector_value;
    output.kind = exception.kind;
    output.selector_register = exception.selector_register;
    output.selector_bytes = exception.selector_bytes;
    state->text.copy(exception.opening, output.text);
  }
  return true;
}

bool ct_decompile_view::variables(uint64_t offset,
                                  ct_decompiled_variables &result) const {
  result = {};
  const auto *instruction = state ? state->instruction(offset) : nullptr;
  if (!instruction)
    return false;
  result.function_offset = state->header->entry;
  result.instruction = *instruction;
  const auto &common = *state->header;
  result.return_known = (common.flags & 1u) != 0;
  result.return_void = (common.flags & 2u) != 0;
  result.return_unsupported = (common.flags & 4u) != 0;
  result.parameters_known = (common.flags & 8u) != 0;
  result.variadic = (common.flags & 16u) != 0;
  result.return_type = {ct_value_kind(common.return_type.kind),
                        size_t(common.return_type.bytes)};
  state->text.copy(common.return_name, result.return_type_name);
  state->text.copy(common.return_register, result.return_register);
  for (const auto &parameter : state->parameters) {
    auto &output = result.parameters.emplace_back();
    ++result.parameter_count;
    output.stack_offset = parameter.stack_offset;
    output.size = parameter.size;
    output.kind = ct_decompiled_storage(parameter.kind);
    output.type = {ct_value_kind(parameter.type.kind),
                   size_t(parameter.type.bytes)};
    state->text.copy(parameter.name, output.name);
    state->text.copy(parameter.spelling, output.type_name);
    state->text.copy(parameter.reg, output.register_name);
  }
  if (!state->full)
    return true;
  const auto &full = *state->full;
  const auto scoped = std::lower_bound(
      full.scopes.begin(), full.scopes.end(), offset,
      [](const auto &item, uint64_t value) { return item.offset < value; });
  const size_t count = scoped != full.scopes.end() && scoped->offset == offset
                           ? scoped->count
                           : 0;
  if (full.globals.count + count > UINT32_MAX) {
    result = {};
    return false;
  }
  const auto variable = [&](const ViewVariable &item) {
    auto &output = result.entries.emplace_back();
    ++result.count;
    output.id = item.id;
    output.offset = item.offset;
    output.stack_offset = item.stack_offset;
    output.size = item.size;
    output.kind = ct_decompiled_storage(item.kind);
    output.access = item.access;
    output.type_id = item.type_id;
    output.register_alias = item.alias != 0;
    output.type = {ct_value_kind(item.type.kind), size_t(item.type.bytes)};
    full.text.copy(item.name, output.name);
    full.text.copy(item.spelling, output.type_name);
    full.text.copy(item.reg, output.register_name);
  };
  for (const auto &item : full.globals)
    variable(item);
  for (size_t index = 0; index < count; ++index)
    variable(full.scoped[scoped->first + index]);
  for (const auto &type : full.types) {
    auto &output = result.types.emplace_back();
    ++result.type_count;
    output.kind = ct_value_layout_kind(type.kind);
    output.scalar = {ct_value_kind(type.scalar.kind),
                     size_t(type.scalar.bytes)};
    output.bytes = size_t(type.bytes);
    output.element_type = type.element_type;
    output.element_count = size_t(type.element_count);
    output.element_stride = size_t(type.element_stride);
    output.first_member = type.first_member;
    output.member_count = size_t(type.member_count);
    output.complete = (type.flags & 1u) != 0;
    output.guarded = (type.flags & 2u) != 0;
  }
  for (const auto &member : full.members) {
    auto &output = result.members.emplace_back();
    ++result.member_count;
    output.type = member.type;
    output.offset = size_t(member.offset);
    output.available = member.available != 0;
    full.text.copy(member.name, output.name);
  }
  return true;
}

bool ct_decompile_view::proof(uint64_t offset,
                              std::vector<unsigned char> &result) const {
  result.clear();
  if (!contains(offset))
    return false;
  state->proof(result, level());
  return true;
}
