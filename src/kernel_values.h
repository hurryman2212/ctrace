#ifndef CTRACE_KERNEL_VALUES_H
#define CTRACE_KERNEL_VALUES_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "uapi/kctrace.h"

#include "kernel_image.h"
#include "kernel_rewrite.h"
#include "values.h"

struct ct_kernel_value_type {
  ct_value_type scalar{};
  std::string name;
  bool guarded = false;
  // Exact scalar storage width, with unknown signedness/semantic type.
  // Aggregates represented by CT_VALUE_UNKNOWN do not establish this proof.
  bool raw_scalar = false;
  // One-based portable shape; shared by all variables of this declared type.
  uint32_t layout_type = 0;
};

struct ct_kernel_value_variable {
  uint64_t id = 0, die = 0, unit = 0, scope = 0, function = 0;
  uint32_t depth = 0, type = 0;
  // Nearest physical/inline subprogram linkage name; globals have no owner.
  std::string name, owner;
  bool global = false, parameter = false;
  bool register_alias = false;
};

struct ct_kernel_value_operation {
  uint8_t opcode = 0;
  uint64_t operand = 0, operand2 = 0;
  // A DW_OP_addr is an original ELF section+offset, never a process-wide bias.
  uint32_t section = UINT32_MAX;
};

struct ct_kernel_value_recipe {
  std::vector<ct_kernel_value_operation> operations;
  std::string error;
  // Exact entry_value(GPR register) + stack_value; DWARF register number.
  uint32_t entry_register = UINT32_MAX;
};

struct ct_kernel_value_binding {
  uint64_t variable = 0;
  uint32_t recipe = 0;
  uint32_t capture_slot = UINT32_MAX;
  // Interned typed leaf-to-slot map; zero means no aggregate capture.
  uint32_t capture_group = 0;
  // Derived semantic input at this C statement start; prioritize its fresh
  // capture over operands which are not displayed in the current statement.
  bool preferred = false;
};

struct ct_kernel_value_capture {
  uint64_t offset = 0;
  uint32_t size = 0, slot = 0;
};

struct ct_kernel_value_function {
  uint64_t die = 0, unit = 0;
  uint32_t return_type = 0;
  bool returns_void = false;
};

struct ct_kernel_value_site {
  std::vector<ct_kernel_value_binding> bindings;
  uint32_t function = 0, frame_recipe = 0, capture_plan = 0;
};

struct ct_kernel_value_metadata {
  // Pools are one-based. Zero denotes unavailable; sites use probe IDs.
  std::vector<ct_kernel_value_type> types{1};
  std::vector<ct_kernel_value_variable> variables{1};
  std::vector<ct_kernel_value_recipe> recipes{1};
  std::vector<ct_kernel_value_function> functions{1};
  std::vector<ct_kernel_value_site> sites;
  // Portable layout IDs index these zero-based arrays as ID - 1.
  std::vector<ct_value_layout_node> layout_types;
  std::vector<ct_value_layout_member> layout_members;
  // Derived capture bindings are prepared once and never copied per frame.
  std::vector<std::vector<ct_kernel_value_capture>> capture_groups{1};
};

struct ct_kernel_value_result {
  std::array<unsigned char, 64> bytes{};
  uint32_t size = 0;
  std::string error;
};

// Resolve names, types, scopes and original section-relative location lists
// before loading. No live LLVM object, DIE or expression byte buffer survives.
// Unavailable locations remain visible bindings with recipe zero or an error.
bool ct_kernel_collect_values(const ct_kernel_image &image,
                              const std::vector<ct_kernel_site> &sites,
                              ct_kernel_value_metadata &metadata,
                              std::string &error, bool *reused = nullptr);

// Evaluate a prepared scalar binding using only this event's valid registers
// and exact captured memory coverage. No kernel/process memory is read here.
// An entry snapshot must belong to this authenticated physical frame. Missing
// entry registers, CFA and unresolved relocated addresses are never guessed.
bool ct_kernel_evaluate_value(const ct_kernel_value_metadata &metadata,
                              const ct_kernel_value_binding &binding,
                              const kctrace_event &event,
                              ct_kernel_value_result &result,
                              const kctrace_event *entry = nullptr);

// Shared presentation for scalar and recursive declared aggregate values.
// Aggregate reads resolve only authenticated captured leaf slots, never a
// kernel address or a pointer target. Uncaptured leaves remain '?'.
std::string ct_kernel_format_value(const ct_kernel_value_metadata &metadata,
                                   const ct_kernel_value_binding &binding,
                                   const kctrace_event &event,
                                   const kctrace_event *entry = nullptr);

#endif
