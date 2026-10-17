#ifndef CTRACE_ASSEMBLY_H
#define CTRACE_ASSEMBLY_H

#include <array>
#include <string>
#include <vector>

#include <dr_api.h>

#include "values.h"

struct ct_asm_operand {
  opnd_t value;
  bool read = false, write = false;
  std::string att, intel;
  bool explicit_operand = false;
};

struct ct_asm_token {
  size_t offset, length;
  size_t operand = std::string::npos;
  bool machine = false;
};

struct ct_instruction {
  app_pc pc = nullptr, next = nullptr;
  bool valid = false, call = false, ret = false, branch = false;
  bool syscall = false, atomic = false, conditional = false;
  bool reads_memory = false, writes_memory = false;
  bool fixed_operands = false;
  bool zeroes_ymmh = false, zeroes_zmmh = false;
  int opcode = OP_INVALID;
  uint eflags = 0;
  std::vector<opnd_t> inputs, outputs;
  std::vector<ct_asm_operand> operands;
  std::array<std::vector<ct_asm_token>, 2> tokens;
  std::string att, intel;
  std::string bytes;
};

/* An observed register copy retains a variable's name and scalar type, not a
 * claim that the register is that variable's storage. Memory origins expire on
 * an overlapping write; all register aliases expire on any overlapping write.
 * State is owned by the tracing thread/frame, never shared globally. */
struct ct_register_origin {
  std::string name;
  std::string source_identity;
  uint64_t symbol_module_id = 0;
  uint64_t symbol_die_offset = 0;
  std::string type_name;
  ct_value_type type{};
  size_t bytes = 0;
  uint64_t address = 0;
  size_t memory_bytes = 0;
  int source_register = -1;
};

struct ct_provenance {
  std::array<ct_register_origin, 33> registers;
};

/* A decompiler variable resolved for this instruction and invocation. Register
 * locations use DWARF numbering; memory locations are effective addresses.
 * Access bits describe proven uses at this PC, not a function-wide alias. */
struct ct_decompiled_operand {
  bool memory = false, read = false, write = false;
  uint64_t location = 0;
  size_t byte_offset = 0, bytes = 0;
  std::string name, type_name, identity;
  ct_value_type type{};
  // Borrowed from the immutable site's decompiler metadata. Scalar bindings
  // can also describe a member of this graph without owning another copy.
  ct_value_layout layout{};
  uint32_t type_id = 0;
  bool subobject = false;
};

/* Require exact storage width and access. Ambiguous identities are rejected. */
const ct_decompiled_operand *
ct_find_decompiled_operand(const std::vector<ct_decompiled_operand> &decompiled,
                           opnd_t operand, const ct_registers &registers,
                           bool read, bool write);

/* A symbolic comparison captured at its instruction, not a reevaluation of
 * application storage. Discard it when flags or operand storage may change. */
struct ct_branch_condition {
  int opcode = OP_INVALID;
  size_t bytes = 0;
  std::string lhs, rhs;
  ct_value_type lhs_type{}, rhs_type{};
};

ct_branch_condition ct_capture_branch_condition(
    const ct_instruction &instruction, const ct_registers &registers,
    ct_values_site *values = nullptr, ct_read_memory read = nullptr,
    void *argument = nullptr, const ct_provenance *provenance = nullptr,
    const std::vector<ct_decompiled_operand> *decompiled = nullptr);
/* Format a proven scalar induction update as type-free pseudocode. This only
 * formats the supplied instruction; it does not establish loop membership.
 * A written variable name requires a current DWARF or decompiler storage
 * match; a copied register's provenance never identifies writable storage. */
std::string ct_format_loop_update(
    const ct_instruction &instruction, const ct_registers &registers,
    ct_values_site *values = nullptr, ct_read_memory read = nullptr,
    void *argument = nullptr,
    const std::vector<ct_decompiled_operand> *decompiled = nullptr);
/* Display a proven immediate initializer, using a declaration only when its
 * instruction's source identity agrees with the local DWARF declaration.
 * Locations are resolved using the supplied current guard context. */
std::string ct_format_loop_initializer(
    const ct_instruction &instruction, const ct_registers &registers,
    ct_values_site *values = nullptr, ct_read_memory read = nullptr,
    void *argument = nullptr, const ct_initializer_source *source = nullptr,
    const std::vector<ct_decompiled_operand> *decompiled = nullptr);
/* Express the selected branch edge. Unsupported comparisons use the actual
 * x86 flags predicate; nonconditional instructions produce an empty string.
 * Typed expressions preserve the compared width and signedness in C output. */
std::string
ct_format_branch_condition(const ct_instruction &instruction,
                           const ct_branch_condition *comparison = nullptr,
                           bool taken = true, bool typed = false);
/* Classify a completed jump: 1 taken, 0 not taken, -1 unproven/non-jump.
 * Conditional decisions use the pre-instruction flags/counter and require
 * agreement with the observed next PC, including a target equal to next. */
int ct_observed_branch_outcome(void *context, const ct_instruction &instruction,
                               const ct_registers &before, app_pc observed_pc);

const ct_register_origin *ct_operand_origin(const ct_provenance &provenance,
                                            opnd_t operand,
                                            const ct_registers &registers);
/* Apply only once an instruction has completed. The supplied registers/site
 * describe its inputs. This follows identity moves, never value equality. */
void ct_update_provenance(
    ct_provenance &provenance, const ct_instruction &instruction,
    ct_values_site *before, const ct_registers &registers, ct_read_memory read,
    void *argument,
    const std::vector<ct_decompiled_operand> *decompiled = nullptr);
/* Invalidate memory-backed aliases in suspended frames for the same executed
 * instruction. This does not change those frames' register contents. */
void ct_invalidate_provenance_memory(ct_provenance &provenance,
                                     const ct_instruction &instruction,
                                     const ct_registers &registers);

/* Uppercase hardware register spelling for generated output. Decoder and
 * lookup code must keep DynamoRIO's canonical names. The pointer is stable. */
const char *ct_register_name(reg_id_t reg);

ct_instruction ct_decode_instruction(void *context, instr_t *instruction);
/* Memory operands return an effective address; registers return their DWARF
 * number and byte offset. Segmented/VSIB addresses require unavailable state.
 */
bool ct_operand_location(opnd_t operand, const ct_registers &registers,
                         uint64_t *location, size_t *byte_offset);
/* Return only the asm statement, retaining known bytes with .byte when the
 * instruction cannot be printed. No bytes and no decoded text produce empty. */
std::string ct_format_assembly(
    const ct_instruction &instruction, ct_values_site *before,
    ct_values_site *after, const ct_registers &registers, ct_read_memory read,
    void *argument, int syntax, const ct_registers *after_registers = nullptr,
    const ct_provenance *provenance = nullptr,
    const char *call_target = nullptr,
    const std::vector<ct_decompiled_operand> *decompiled = nullptr);

/* Render a supported scalar machine operation as C, preserving its storage
 * width. This is a fallback for instructions not covered by a verified
 * decompiler statement. Flags remain in the observed before/after snapshot.
 * Unknown, atomic, vector and control-transfer operations return empty.
 * Writable names require a current storage match, never copy provenance. */
std::string ct_format_decompiled_instruction(
    const ct_instruction &instruction, ct_values_site *before,
    ct_values_site *after, const ct_registers &registers, ct_read_memory read,
    void *argument, const ct_registers *after_registers = nullptr,
    const ct_provenance *provenance = nullptr,
    const std::vector<ct_decompiled_operand> *decompiled = nullptr);

#endif
