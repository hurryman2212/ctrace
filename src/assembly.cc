#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <unordered_map>

#include <dr_api.h>

#include "analysis.h"
#include "assembly.h"
#include "userspace_patch.h"

static std::mutex syntax_mutex;
static const reg_id_t dwarf_registers[] = {
    DR_REG_RAX, DR_REG_RDX, DR_REG_RCX, DR_REG_RBX, DR_REG_RSI, DR_REG_RDI,
    DR_REG_RBP, DR_REG_RSP, DR_REG_R8,  DR_REG_R9,  DR_REG_R10, DR_REG_R11,
    DR_REG_R12, DR_REG_R13, DR_REG_R14, DR_REG_R15};

const char *ct_register_name(reg_id_t reg) {
  static const auto names = [] {
    std::array<std::string, DR_REG_LAST_VALID_ENUM + 1> result;
    for (size_t index = 0; index < result.size(); ++index) {
      const char *name = get_register_name(static_cast<reg_id_t>(index));
      if (!name)
        continue;
      result[index] = name;
      for (char &c : result[index])
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return result;
  }();
  return static_cast<size_t>(reg) < names.size() ? names[reg].c_str() : "?";
}

// Only call this on unresolved machine-operand spelling, before inserting any
// recovered C names or linkage symbols. Decoder text stays canonical so its
// operand offsets and bindings do not depend on the display convention.
static std::string assembly_registers(std::string text) {
  static const auto names = [] {
    std::unordered_map<std::string, std::string> result;
    for (int reg = DR_REG_NULL + 1; reg <= DR_REG_LAST_VALID_ENUM; ++reg) {
      const char *name = get_register_name(static_cast<reg_id_t>(reg));
      if (name && *name)
        result.emplace(name, ct_register_name(static_cast<reg_id_t>(reg)));
    }
    // LLVM uses the architectural byte-register suffix; DR calls these R8L,
    // ..., R15L internally. Keep either spelling recognizable in raw operands.
    for (int index = 8; index <= 15; ++index)
      result.emplace("r" + std::to_string(index) + "b",
                     "R" + std::to_string(index) + "B");
    // These are printed by LLVM although they have no ordinary DR register ID.
    for (const char *name : {"rip", "eip", "rflags", "eflags", "st"}) {
      std::string display = name;
      for (char &c : display)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
      result.emplace(name, std::move(display));
    }
    return result;
  }();
  for (size_t index = 0; index < text.size();) {
    if (!std::isalnum(static_cast<unsigned char>(text[index])) &&
        text[index] != '_') {
      ++index;
      continue;
    }
    const size_t start = index++;
    while (index < text.size() &&
           (std::isalnum(static_cast<unsigned char>(text[index])) ||
            text[index] == '_'))
      ++index;
    const auto found = names.find(text.substr(start, index - start));
    if (found != names.end())
      text.replace(start, index - start, found->second);
  }
  return text;
}

ct_instruction ct_decode_instruction(void *context, instr_t *instruction) {
  ct_instruction result;
  result.pc = instr_get_app_pc(instruction);
  if (!instr_valid(instruction))
    return result;
  result.valid = true;
  size_t original_length = 0;
  const byte *gate_original =
      ct_userspace_patch_original(result.pc, &original_length);
  result.next = gate_original ? result.pc + original_length
                              : decode_next_pc(context, result.pc);
  if (!result.next || result.next <= result.pc ||
      result.next - result.pc > 15) {
    result.valid = false;
    return result;
  }
  result.opcode = instr_get_opcode(instruction);
  result.call = instr_is_call(instruction);
  result.ret = instr_is_return(instruction);
  result.branch = instr_is_cbr(instruction) || instr_is_ubr(instruction) ||
                  instr_is_mbr(instruction);
  result.syscall = instr_is_syscall(instruction);
  result.conditional = instr_is_predicated(instruction);
  result.reads_memory = instr_reads_memory(instruction);
  result.writes_memory = instr_writes_memory(instruction);
  result.fixed_operands = instr_is_string_op(instruction) ||
                          result.opcode == OP_in || result.opcode == OP_out ||
                          result.opcode == OP_xlat;
  result.atomic = instr_get_prefix_flag(instruction, PREFIX_LOCK) ||
                  (result.opcode == OP_xchg && result.writes_memory);
  result.eflags = instr_get_eflags(instruction, DR_QUERY_INCLUDE_ALL);
  result.zeroes_ymmh = instr_zeroes_ymmh(instruction);
  result.zeroes_zmmh = instr_zeroes_zmmh(instruction);
  for (int index = 0; index < instr_num_srcs(instruction); ++index)
    result.inputs.push_back(instr_get_src(instruction, index));
  for (int index = 0; index < instr_num_dsts(instruction); ++index)
    result.outputs.push_back(instr_get_dst(instruction, index));
  for (auto operand : result.outputs)
    result.operands.push_back({operand, false, true, {}, {}});
  for (auto operand : result.inputs) {
    auto existing = std::find_if(result.operands.begin(), result.operands.end(),
                                 [&](const ct_asm_operand &entry) {
                                   return opnd_same(entry.value, operand);
                                 });
    if (existing == result.operands.end())
      result.operands.push_back({operand, true, false, {}, {}});
    else
      existing->read = true;
  }
  // The original bytes go through LLVM's assembler printer. DR's disassembler
  // has diagnostic spellings (including reversed CMP operands and <rel>) that
  // cannot be used as GNU assembler input.
  unsigned char bytes[15];
  size_t length = result.next - result.pc;
  char att[1024] = {}, intel[1024] = {};
  if (length <= sizeof(bytes) &&
      ct_userspace_patch_read_original(result.pc, length, bytes)) {
    for (size_t index = 0; index < length; ++index) {
      char hex[8];
      std::snprintf(hex, sizeof(hex), "%s%02x", index ? " " : "", bytes[index]);
      result.bytes += hex;
    }
    if (ct_analysis_disassemble(reinterpret_cast<uint64_t>(result.pc), bytes,
                                length, att, sizeof(att), intel,
                                sizeof(intel))) {
      result.att = att;
      result.intel = intel;
    }
  }
  // Match explicit operands to whole canonical tokens, never substrings in
  // another operand's address. Reads, writes and locations come exclusively
  // from IR.
  std::lock_guard<std::mutex> lock(syntax_mutex);
  for (int mode = 0; mode != 2; ++mode) {
    disassemble_set_syntax(mode ? DR_DISASM_INTEL : DR_DISASM_ATT);
    char text[1024];
    for (auto &operand : result.operands) {
      opnd_disassemble_to_buffer(context, operand.value, text, sizeof(text));
      (mode ? operand.intel : operand.att) = text;
    }
    const auto &canonical = mode ? result.intel : result.att;
    auto first_comma = canonical.find(',');
    // MCInstPrinter separates mnemonic/prefix fields and operands with tabs.
    auto start = canonical.rfind('\t', first_comma);
    if (start == std::string::npos)
      continue;
    ++start;
    int nesting = 0;
    for (size_t end = start; end <= canonical.size(); ++end) {
      if (end < canonical.size()) {
        char c = canonical[end];
        if (c == '(' || c == '[' || c == '{')
          ++nesting;
        else if (c == ')' || c == ']' || c == '}')
          --nesting;
        if (c != ',' || nesting)
          continue;
      }
      std::string token = canonical.substr(start, end - start);
      auto left = token.find_first_not_of(" \t");
      auto right = token.find_last_not_of(" \t");
      token =
          left == std::string::npos ? "" : token.substr(left, right - left + 1);
      size_t token_start = start + (left == std::string::npos ? 0 : left);
      start = end + 1;
      if (token.empty())
        continue;
      bool machine = token.find_first_of("%([]") != std::string::npos;
      ct_asm_operand *match = nullptr;
      for (auto &operand : result.operands) {
        bool matches = false;
        if (opnd_is_reg(operand.value)) {
          std::string name =
              (mode ? "" : "%") +
              std::string(get_register_name(opnd_get_reg(operand.value)));
          matches = token == name || (!mode && token == "*" + name);
        } else if (opnd_is_pc(operand.value)) {
          matches = result.call || result.branch;
        } else if (opnd_is_memory_reference(operand.value)) {
          bool memory = mode ? token.find('[') != std::string::npos
                             : token.find('(') != std::string::npos;
          if (!memory && !token.empty() && std::isdigit(token.front()))
            memory = !mode;
          matches = memory;
          // Distinguish the two implicit addresses of string operations and
          // stack accesses whenever the printed base/index provides evidence.
          if (matches && opnd_is_base_disp(operand.value)) {
            for (reg_id_t reg : {opnd_get_base(operand.value),
                                 opnd_get_index(operand.value)}) {
              if (reg == DR_REG_NULL)
                continue;
              std::string name =
                  (mode ? "" : "%") + std::string(get_register_name(reg));
              size_t at = token.find(name);
              if (at == std::string::npos ||
                  (at &&
                   std::isalnum(static_cast<unsigned char>(token[at - 1]))) ||
                  (at + name.size() < token.size() &&
                   std::isalnum(
                       static_cast<unsigned char>(token[at + name.size()]))))
                matches = false;
            }
          }
        }
        if (!matches)
          continue;
        if (match) {
          match = nullptr; // Ambiguous bindings remain explicit machine state.
          break;
        }
        match = &operand;
      }
      if (!mode && token.front() == '*') {
        token.erase(0, 1); // Keep GNU's indirect-call marker in the template.
        ++token_start;
      }
      if (match) {
        (mode ? match->intel : match->att) = token;
        match->explicit_operand = true;
      }
      result.tokens[mode].push_back(
          {token_start, token.size(),
           match ? static_cast<size_t>(match - result.operands.data())
                 : std::string::npos,
           machine || match != nullptr});
    }
  }
  return result;
}

bool ct_operand_location(opnd_t operand, const ct_registers &registers,
                         uint64_t *location, size_t *byte_offset) {
  *byte_offset = 0;
  if (opnd_is_reg(operand)) {
    reg_id_t reg = opnd_get_reg(operand);
    if (reg_is_gpr(reg)) {
      if (reg >= DR_REG_AH && reg <= DR_REG_BH)
        *byte_offset = 1;
      reg = reg_resize_to_opsz(reg, OPSZ_8);
      for (size_t index = 0; index < std::size(dwarf_registers); ++index) {
        if (reg == dwarf_registers[index]) {
          *location = index;
          return true;
        }
      }
    }
    if (reg_is_xmm(reg) && reg >= DR_REG_XMM0 && reg <= DR_REG_XMM15) {
      *location = 17 + reg - DR_REG_XMM0;
      return true;
    }
    return false;
  }
  if (!opnd_is_memory_reference(operand))
    return false;
  if (opnd_get_segment(operand) != DR_REG_NULL &&
      opnd_get_segment(operand) != DR_SEG_DS &&
      opnd_get_segment(operand) != DR_SEG_SS)
    return false;
  if (opnd_is_abs_addr(operand) || opnd_is_rel_addr(operand)) {
    *location = reinterpret_cast<uint64_t>(opnd_get_addr(operand));
    return true;
  }
  if (!opnd_is_base_disp(operand) || !registers.have_gpr ||
      (opnd_get_index(operand) != DR_REG_NULL &&
       !reg_is_gpr(opnd_get_index(operand))))
    return false;
  dr_mcontext_t context = {};
  context.size = sizeof(context);
  context.flags =
      static_cast<dr_mcontext_flags_t>(DR_MC_INTEGER | DR_MC_CONTROL);
  for (size_t index = 0; index < std::size(dwarf_registers); ++index)
    reg_set_value(dwarf_registers[index], &context, registers.gpr[index]);
  *location =
      reinterpret_cast<uint64_t>(opnd_compute_address(operand, &context));
  return true;
}

const ct_decompiled_operand *
ct_find_decompiled_operand(const std::vector<ct_decompiled_operand> &decompiled,
                           opnd_t operand, const ct_registers &registers,
                           bool read, bool write) {
  uint64_t location = 0;
  size_t offset = 0;
  if ((!read && !write) ||
      !ct_operand_location(operand, registers, &location, &offset))
    return nullptr;
  const bool memory = opnd_is_memory_reference(operand);
  const size_t bytes = opnd_size_in_bytes(opnd_get_size(operand));
  if (!bytes)
    return nullptr;
  const ct_decompiled_operand *match = nullptr;
  for (const auto &candidate : decompiled) {
    if (candidate.name.empty() || candidate.memory != memory ||
        candidate.location != location || candidate.byte_offset != offset ||
        candidate.bytes != bytes || (read && !candidate.read) ||
        (write && !candidate.write))
      continue;
    if (match && (match->identity != candidate.identity ||
                  match->name != candidate.name ||
                  match->type_name != candidate.type_name ||
                  match->type.kind != candidate.type.kind ||
                  match->type.bytes != candidate.type.bytes))
      return nullptr;
    match = &candidate;
  }
  return match;
}

static std::string
condition_operand(opnd_t operand, std::string text,
                  const ct_registers &registers, ct_values_site *values,
                  ct_read_memory read, void *argument,
                  const ct_provenance *provenance,
                  const std::vector<ct_decompiled_operand> *decompiled,
                  bool input, bool output, ct_value_type *type = nullptr) {
  const bool memory = opnd_is_memory_reference(operand);
  const bool reg = opnd_is_reg(operand) && reg_is_gpr(opnd_get_reg(operand));
  const size_t bytes = opnd_size_in_bytes(opnd_get_size(operand));
  if (type)
    *type = {reg ? CT_VALUE_UNSIGNED : CT_VALUE_UNKNOWN, bytes};
  if (!memory && !reg)
    return {};
  uint64_t address = 0;
  size_t offset = 0;
  const bool located =
      ct_operand_location(operand, registers, &address, &offset);
  char name[256]{};
  if (located && values &&
      ct_values_find_name(values, &registers, read, argument, memory, address,
                          offset, opnd_size_in_bytes(opnd_get_size(operand)),
                          name, sizeof(name))) {
    if (type)
      ct_values_operand_type(values, &registers, read, argument, memory,
                             address, offset, bytes, type);
    return name;
  }
  if (decompiled)
    if (const auto *binding = ct_find_decompiled_operand(
            *decompiled, operand, registers, input, output)) {
      if (type) {
        *type = binding->type;
        if (type->kind == CT_VALUE_UNKNOWN &&
            binding->type_name == "uint" + std::to_string(bytes * 8) + "_t")
          *type = {CT_VALUE_UNSIGNED, bytes};
      }
      return binding->name;
    }
  // Read-only expressions can retain a name through a proven identity copy.
  // Callers formatting an update never supply provenance here.
  if (reg) {
    if (provenance)
      if (const auto *origin =
              ct_operand_origin(*provenance, operand, registers)) {
        if (type)
          *type = origin->type;
        return origin->name;
      }
    return ct_register_name(opnd_get_reg(operand));
  }
  // Reject segmented and VSIB addresses whose required state is absent.
  if (!located)
    return {};
  // RIP-relative operands denote the address at their own instruction, never
  // the different instruction pointer at a later conditional branch.
  if (opnd_is_rel_addr(operand) || opnd_is_abs_addr(operand)) {
    char location[32];
    std::snprintf(location, sizeof(location), "0x%llx",
                  static_cast<unsigned long long>(address));
    text = location;
  } else {
    auto opening = text.find('['), closing = text.rfind(']');
    if (opening == std::string::npos || closing == std::string::npos ||
        closing <= opening)
      return {};
    text = text.substr(opening + 1, closing - opening - 1);
  }
  return "*(" + assembly_registers(text) + ")";
}

ct_branch_condition ct_capture_branch_condition(
    const ct_instruction &instruction, const ct_registers &registers,
    ct_values_site *values, ct_read_memory read, void *argument,
    const ct_provenance *provenance,
    const std::vector<ct_decompiled_operand> *decompiled) {
  ct_branch_condition result;
  if (!instruction.valid ||
      (instruction.opcode != OP_cmp && instruction.opcode != OP_test) ||
      instruction.tokens[1].size() != 2)
    return result;
  for (opnd_t operand : instruction.inputs) {
    if (!opnd_is_reg(operand) && !opnd_is_memory_reference(operand))
      continue;
    if (opnd_is_reg(operand) && !reg_is_gpr(opnd_get_reg(operand)))
      return {};
    size_t bytes = opnd_size_in_bytes(opnd_get_size(operand));
    if ((bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
        (result.bytes && result.bytes != bytes))
      return {};
    result.bytes = bytes;
  }
  if (!result.bytes)
    return {};
  std::string *texts[] = {&result.lhs, &result.rhs};
  ct_value_type *types[] = {&result.lhs_type, &result.rhs_type};
  for (size_t index = 0; index != 2; ++index) {
    const auto &token = instruction.tokens[1][index];
    if (token.offset > instruction.intel.size() ||
        token.length > instruction.intel.size() - token.offset)
      return {};
    std::string text = instruction.intel.substr(token.offset, token.length);
    if (token.operand < instruction.operands.size()) {
      text =
          condition_operand(instruction.operands[token.operand].value,
                            std::move(text), registers, values, read, argument,
                            provenance, decompiled, true, false, types[index]);
    } else {
      // LLVM's Intel operand order supplies lhs/rhs, while DR's immediate
      // supplies the encoded sign extension (e.g. CMP r64, imm8 -1).
      const opnd_t *immediate = nullptr;
      for (const auto &operand : instruction.inputs)
        if (opnd_is_immed_int(operand)) {
          if (immediate)
            return {};
          immediate = &operand;
        }
      if (!immediate)
        return {};
      uint64_t value = static_cast<uint64_t>(opnd_get_immed_int(*immediate));
      if (result.bytes < sizeof(value))
        value &= (uint64_t{1} << (result.bytes * 8)) - 1;
      char number[32];
      std::snprintf(number, sizeof(number), "0x%llx",
                    static_cast<unsigned long long>(value));
      text = number;
      *types[index] = {value <= INT32_MAX ||
                               (value > UINT32_MAX && value <= INT64_MAX)
                           ? CT_VALUE_SIGNED
                           : CT_VALUE_UNSIGNED,
                       value <= UINT32_MAX ? size_t{4} : size_t{8}};
    }
    if (text.empty())
      return {};
    *texts[index] = std::move(text);
  }
  result.opcode = instruction.opcode;
  return result;
}

std::string
ct_format_loop_update(const ct_instruction &instruction,
                      const ct_registers &registers, ct_values_site *values,
                      ct_read_memory read, void *argument,
                      const std::vector<ct_decompiled_operand> *decompiled) {
  const bool unary =
      instruction.opcode == OP_inc || instruction.opcode == OP_dec;
  if (!instruction.valid || instruction.atomic || instruction.conditional ||
      (!unary && instruction.opcode != OP_add &&
       instruction.opcode != OP_sub) ||
      instruction.outputs.size() != 1 || instruction.tokens[1].empty() ||
      instruction.inputs.size() != (unary ? 1 : 2))
    return {};
  const opnd_t output = instruction.outputs.front();
  const size_t bytes = opnd_size_in_bytes(opnd_get_size(output));
  if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
    return {};
  const auto &token = instruction.tokens[1].front();
  if (token.operand >= instruction.operands.size() ||
      !opnd_same(instruction.operands[token.operand].value, output) ||
      token.offset > instruction.intel.size() ||
      token.length > instruction.intel.size() - token.offset)
    return {};
  const std::string lvalue = condition_operand(
      output, instruction.intel.substr(token.offset, token.length), registers,
      values, read, argument, nullptr, decompiled, true, true);
  if (lvalue.empty())
    return {};
  const opnd_t *immediate = nullptr;
  bool reads_output = false;
  for (const auto &operand : instruction.inputs) {
    if (opnd_same(operand, output))
      reads_output = true;
    else if (!unary && opnd_is_immed_int(operand) && !immediate)
      immediate = &operand;
    else
      return {};
  }
  if (!reads_output || (!unary && !immediate))
    return {};
  if (unary)
    return std::string(instruction.opcode == OP_inc ? "++" : "--") + lvalue;
  uint64_t step = static_cast<uint64_t>(opnd_get_immed_int(*immediate));
  if (instruction.opcode == OP_sub)
    step = -step;
  const uint64_t mask =
      bytes == 8 ? UINT64_MAX : (uint64_t{1} << (bytes * 8)) - 1;
  step &= mask;
  if (!step)
    return {};
  const bool subtract = (step & (uint64_t{1} << (bytes * 8 - 1))) != 0;
  const uint64_t magnitude = subtract ? (-step & mask) : step;
  if (magnitude == 1)
    return std::string(subtract ? "--" : "++") + lvalue;
  char amount[32];
  std::snprintf(amount, sizeof(amount), "0x%llx",
                static_cast<unsigned long long>(magnitude));
  return lvalue + (subtract ? " -= " : " += ") + amount;
}

std::string ct_format_loop_initializer(
    const ct_instruction &instruction, const ct_registers &registers,
    ct_values_site *values, ct_read_memory read, void *argument,
    const ct_initializer_source *source,
    const std::vector<ct_decompiled_operand> *decompiled) {
  if (!instruction.valid || instruction.atomic || instruction.conditional ||
      (instruction.opcode != OP_mov_imm && instruction.opcode != OP_mov_st) ||
      instruction.outputs.size() != 1 || instruction.inputs.size() != 1 ||
      !opnd_is_immed_int(instruction.inputs.front()) ||
      instruction.tokens[1].empty())
    return {};
  const opnd_t output = instruction.outputs.front();
  const size_t bytes = opnd_size_in_bytes(opnd_get_size(output));
  if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
    return {};
  const auto &token = instruction.tokens[1].front();
  if (token.operand >= instruction.operands.size() ||
      !opnd_same(instruction.operands[token.operand].value, output) ||
      token.offset > instruction.intel.size() ||
      token.length > instruction.intel.size() - token.offset)
    return {};
  std::string lvalue = condition_operand(
      output, instruction.intel.substr(token.offset, token.length), registers,
      values, read, argument, nullptr, decompiled, false, true);
  if (lvalue.empty())
    return {};
  uint64_t immediate =
      static_cast<uint64_t>(opnd_get_immed_int(instruction.inputs.front()));
  if (bytes < sizeof(immediate))
    immediate &= (uint64_t{1} << (bytes * 8)) - 1;
  uint64_t location = 0;
  size_t byte_offset = 0;
  ct_value_type type{};
  if (values &&
      ct_operand_location(output, registers, &location, &byte_offset)) {
    const bool memory = opnd_is_memory_reference(output);
    ct_values_operand_type(values, &registers, read, argument, memory, location,
                           byte_offset, bytes, &type);
    char declaration[512];
    if (ct_values_initializer_declaration(
            values, &registers, read, argument, memory, location, byte_offset,
            bytes, source, declaration, sizeof(declaration)))
      lvalue = declaration;
  }
  char number[32];
  if (type.kind == CT_VALUE_SIGNED) {
    if (bytes < sizeof(immediate) &&
        (immediate & (uint64_t{1} << (bytes * 8 - 1))))
      immediate |= UINT64_MAX << (bytes * 8);
    std::snprintf(number, sizeof(number), "%lld",
                  static_cast<long long>(immediate));
  } else if (type.kind == CT_VALUE_UNSIGNED || type.kind == CT_VALUE_BOOLEAN) {
    std::snprintf(number, sizeof(number), "%llu",
                  static_cast<unsigned long long>(immediate));
  } else if (!immediate) {
    std::snprintf(number, sizeof(number), "0");
  } else {
    std::snprintf(number, sizeof(number), "0x%llx",
                  static_cast<unsigned long long>(immediate));
  }
  return lvalue + " = " + number;
}

std::string ct_format_branch_condition(const ct_instruction &instruction,
                                       const ct_branch_condition *comparison,
                                       bool taken, bool typed) {
  if (!instruction.valid || !instruction.branch)
    return {};
  int condition = -1;
  if (instruction.opcode >= OP_jo && instruction.opcode <= OP_jnle)
    condition = instruction.opcode - OP_jo;
  else if (instruction.opcode >= OP_jo_short &&
           instruction.opcode <= OP_jnle_short)
    condition = instruction.opcode - OP_jo_short;
  if (condition < 0) {
    if (instruction.opcode != OP_jecxz)
      return {};
    // J[ER]CXZ does not use flags. The IR identifies the counter width.
    for (opnd_t operand : instruction.inputs)
      if (opnd_is_reg(operand) && reg_is_gpr(opnd_get_reg(operand)))
        return std::string(ct_register_name(opnd_get_reg(operand))) +
               (taken ? " == 0" : " != 0");
    return {};
  }
  if (!taken)
    condition ^=
        1; // x86 condition encodings pair each predicate with its inverse.
  bool usable = comparison && !comparison->lhs.empty() &&
                !comparison->rhs.empty() &&
                (comparison->bytes == 1 || comparison->bytes == 2 ||
                 comparison->bytes == 4 || comparison->bytes == 8);
  auto typed_operand = [&](const std::string &text, const ct_value_type &type,
                           bool signed_value) {
    const auto kind = signed_value ? CT_VALUE_SIGNED : CT_VALUE_UNSIGNED;
    if (!typed || (type.kind == kind && type.bytes == comparison->bytes))
      return text;
    // Nonnegative literals already have the requested interpretation when
    // they fit the target range. Their comparison context supplies any usual
    // integer conversion, so no explicit cast is needed.
    if (text.size() > 2 && text[0] == '0' && text[1] == 'x') {
      uint64_t value = 0;
      bool valid = text.size() <= 18;
      for (size_t index = 2; valid && index < text.size(); ++index) {
        const char ch = text[index];
        if (!std::isxdigit(static_cast<unsigned char>(ch)))
          valid = false;
        else
          value =
              value * 16 + (ch <= '9' ? ch - '0' : std::tolower(ch) - 'a' + 10);
      }
      const unsigned bits = comparison->bytes * 8;
      const uint64_t maximum = signed_value ? (uint64_t{1} << (bits - 1)) - 1
                               : bits == 64 ? UINT64_MAX
                                            : (uint64_t{1} << bits) - 1;
      if (valid && value <= maximum)
        return text;
    }
    return "(" + std::string(signed_value ? "int" : "uint") +
           std::to_string(comparison->bytes * 8) + "_t)(" + text + ")";
  };
  if (usable && comparison->opcode == OP_cmp) {
    const char *relation = nullptr;
    switch (condition) {
    case 2:
      relation = " < ";
      break;
    case 3:
      relation = " >= ";
      break;
    case 4:
      relation = " == ";
      break;
    case 5:
      relation = " != ";
      break;
    case 6:
      relation = " <= ";
      break;
    case 7:
      relation = " > ";
      break;
    case 12:
      relation = " < ";
      break;
    case 13:
      relation = " >= ";
      break;
    case 14:
      relation = " <= ";
      break;
    case 15:
      relation = " > ";
      break;
    }
    if (relation && typed) {
      const bool signed_value =
          condition >= 12 || ((condition == 4 || condition == 5) &&
                              comparison->lhs_type.kind == CT_VALUE_SIGNED);
      return typed_operand(comparison->lhs, comparison->lhs_type,
                           signed_value) +
             relation +
             typed_operand(comparison->rhs, comparison->rhs_type, signed_value);
    }
    // Assembly annotations deliberately omit types. C replacements need them
    // above: the same bit pattern can take opposite signed/unsigned branches.
    if (relation)
      return comparison->lhs + relation + comparison->rhs;
  } else if (usable && comparison->opcode == OP_test) {
    const auto bit_operand = [&](const std::string &text,
                                 const ct_value_type &type) {
      if ((type.kind == CT_VALUE_SIGNED || type.kind == CT_VALUE_UNSIGNED) &&
          type.bytes == comparison->bytes)
        return text;
      return typed_operand(text, type, false);
    };
    const std::string lhs = bit_operand(comparison->lhs, comparison->lhs_type);
    const std::string rhs = bit_operand(comparison->rhs, comparison->rhs_type);
    std::string expression = comparison->lhs == comparison->rhs
                                 ? lhs
                                 : "(" + lhs + " & " + rhs + ")";
    if (condition == 4 || condition == 5)
      return expression + (condition == 4 ? " == 0" : " != 0");
    // TEST always clears OF, so signed Jcc predicates reduce to the signed
    // bitwise result. Do not apply this simplification to CMP subtraction.
    const char *relation = nullptr;
    switch (condition) {
    case 8:
    case 12:
      relation = " < 0";
      break;
    case 9:
    case 13:
      relation = " >= 0";
      break;
    case 14:
      relation = " <= 0";
      break;
    case 15:
      relation = " > 0";
      break;
    }
    if (relation && typed) {
      if (comparison->lhs == comparison->rhs)
        expression = typed_operand(comparison->lhs, comparison->lhs_type, true);
      else
        expression = "(int" + std::to_string(comparison->bytes * 8) + "_t)(" +
                     expression + ")";
    }
    if (relation)
      return expression + relation;
  }
  static const char *predicates[] = {"OF == 1",
                                     "OF == 0",
                                     "CF == 1",
                                     "CF == 0",
                                     "ZF == 1",
                                     "ZF == 0",
                                     "CF == 1 || ZF == 1",
                                     "CF == 0 && ZF == 0",
                                     "SF == 1",
                                     "SF == 0",
                                     "PF == 1",
                                     "PF == 0",
                                     "SF != OF",
                                     "SF == OF",
                                     "ZF == 1 || SF != OF",
                                     "ZF == 0 && SF == OF"};
  return predicates[condition];
}

int ct_observed_branch_outcome(void *context, const ct_instruction &instruction,
                               const ct_registers &before, app_pc observed_pc) {
  if (!instruction.valid || !instruction.branch || instruction.call ||
      instruction.ret || instruction.syscall || !observed_pc)
    return -1;
  app_pc target = nullptr;
  for (const auto &operand : instruction.inputs)
    if (opnd_is_pc(operand)) {
      target = opnd_get_pc(operand);
      break;
    }
  if (instruction.opcode == OP_jmp_ind)
    return 1; // The caller supplies the PC observed after completed execution.
  if (instruction.opcode == OP_jmp || instruction.opcode == OP_jmp_short)
    return target && observed_pc == target ? 1 : -1;
  if (!target || !instruction.next || !before.have_gpr)
    return -1;
  bool taken;
  if ((instruction.opcode >= OP_jo && instruction.opcode <= OP_jnle) ||
      (instruction.opcode >= OP_jo_short &&
       instruction.opcode <= OP_jnle_short)) {
    instr_t branch;
    instr_init(context, &branch);
    instr_set_opcode(&branch, instruction.opcode);
    taken = instr_jcc_taken(&branch, before.flags);
    instr_free(context, &branch);
  } else if (instruction.opcode >= OP_loopne &&
             instruction.opcode <= OP_jecxz) {
    size_t bytes = 0;
    for (const auto &operand : instruction.inputs)
      if (opnd_is_reg(operand) &&
          reg_overlap(opnd_get_reg(operand), DR_REG_RCX)) {
        bytes = opnd_size_in_bytes(opnd_get_size(operand));
        break;
      }
    if (bytes != 2 && bytes != 4 && bytes != 8)
      return -1;
    // Address-size overrides select CX/ECX/RCX. LOOP decrements that width
    // before testing it; zero wraps and therefore takes the branch.
    uint64_t counter = before.gpr[2];
    if (bytes < sizeof(counter))
      counter &= (uint64_t{1} << (bytes * 8)) - 1;
    taken = instruction.opcode == OP_jecxz ? counter == 0 : counter != 1;
    if (instruction.opcode == OP_loope)
      taken &= (before.flags & EFLAGS_ZF) != 0;
    else if (instruction.opcode == OP_loopne)
      taken &= (before.flags & EFLAGS_ZF) == 0;
  } else
    return -1;
  return observed_pc == (taken ? target : instruction.next)
             ? static_cast<int>(taken)
             : -1;
}

std::string ct_format_decompiled_instruction(
    const ct_instruction &instruction, ct_values_site *before,
    ct_values_site *after, const ct_registers &registers, ct_read_memory read,
    void *argument, const ct_registers *after_registers,
    const ct_provenance *provenance,
    const std::vector<ct_decompiled_operand> *decompiled) {
  if (!instruction.valid || instruction.atomic || instruction.fixed_operands ||
      instruction.branch || instruction.call || instruction.ret ||
      instruction.syscall)
    return {};
  const int opcode = instruction.opcode;
  if (opcode == OP_leave) {
    // Reject operand-size overrides: LEAVEW restores BP but still uses the
    // stack-address size for its first transfer.
    bool restores_rbp = false;
    bool reads_full_pointer = false;
    for (const auto &operand : instruction.outputs)
      if (opnd_is_reg(operand) && opnd_get_reg(operand) == DR_REG_RBP)
        restores_rbp = true;
    for (const auto &operand : instruction.inputs)
      if (opnd_is_memory_reference(operand) &&
          opnd_size_in_bytes(opnd_get_size(operand)) == 8)
        reads_full_pointer = true;
    return restores_rbp && reads_full_pointer
               ? "RSP = RBP; RBP = *(uint64_t *)RSP; RSP += 8;"
               : std::string{};
  }
  const bool push = opcode == OP_push || opcode == OP_push_imm;
  const bool pop = opcode == OP_pop;
  if (instruction.outputs.size() != (push || pop ? 2 : 1))
    return {};
  const bool conditional_move = opcode >= OP_cmovo && opcode <= OP_cmovnle;
  const bool set_condition = opcode >= OP_seto && opcode <= OP_setnle;
  if (instruction.conditional && !conditional_move)
    return {};
  opnd_t output = instruction.outputs.front();
  if (push || pop) {
    bool stack = false, target = false;
    for (const auto &operand : instruction.outputs) {
      if (opnd_is_reg(operand) && opnd_get_reg(operand) == DR_REG_RSP) {
        stack = true;
        if (push)
          output = operand;
      } else if (push && opnd_is_memory_reference(operand) &&
                 opnd_size_in_bytes(opnd_get_size(operand)) == 8) {
        target = true;
      } else if (pop && opnd_is_reg(operand) &&
                 reg_is_gpr(opnd_get_reg(operand)) &&
                 opnd_size_in_bytes(opnd_get_size(operand)) == 8) {
        output = operand;
        target = true;
      }
    }
    if (!stack || !target)
      return {};
  }
  const bool memory = opnd_is_memory_reference(output);
  const size_t bytes = opnd_size_in_bytes(opnd_get_size(output));
  if ((bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
      (!memory && (!opnd_is_reg(output) || !reg_is_gpr(opnd_get_reg(output)))))
    return {};
  const std::string width = std::to_string(bytes * 8);
  const std::string unsigned_type = "uint" + width + "_t";
  auto address = [&](opnd_t operand) -> std::string {
    if (opnd_is_rel_addr(operand) || opnd_is_abs_addr(operand)) {
      char number[32];
      std::snprintf(number, sizeof(number), "0x%llx",
                    static_cast<unsigned long long>(
                        reinterpret_cast<uint64_t>(opnd_get_addr(operand))));
      return number;
    }
    if (!opnd_is_base_disp(operand))
      return {};
    const reg_id_t base = opnd_get_base(operand);
    const reg_id_t index = opnd_get_index(operand);
    if ((base != DR_REG_NULL && !reg_is_gpr(base)) ||
        (index != DR_REG_NULL && !reg_is_gpr(index)))
      return {};
    std::string expression;
    if (base != DR_REG_NULL)
      expression = ct_register_name(base);
    if (index != DR_REG_NULL) {
      if (!expression.empty())
        expression += " + ";
      expression += ct_register_name(index);
      if (opnd_get_scale(operand) != 1)
        expression += " * " + std::to_string(opnd_get_scale(operand));
    }
    const int64_t displacement = opnd_get_disp(operand);
    if (displacement || expression.empty()) {
      char number[32];
      std::snprintf(number, sizeof(number), "0x%llx",
                    static_cast<unsigned long long>(
                        displacement < 0 ? -displacement : displacement));
      if (!expression.empty())
        expression += displacement < 0 ? " - " : " + ";
      else if (displacement < 0)
        expression += '-';
      expression += number;
    }
    // An address-size override wraps the entire effective address at 32 bits.
    if ((base != DR_REG_NULL && reg_get_size(base) == OPSZ_4) ||
        (index != DR_REG_NULL && reg_get_size(index) == OPSZ_4))
      expression = "(uint32_t)(" + expression + ")";
    return expression;
  };
  auto operand_text = [&](opnd_t operand, bool writing,
                          ct_value_type *rendered_type =
                              nullptr) -> std::string {
    if (rendered_type)
      *rendered_type = {};
    if (opnd_is_immed_int(operand)) {
      uint64_t immediate = static_cast<uint64_t>(opnd_get_immed_int(operand));
      if (bytes < 8)
        immediate &= (uint64_t{1} << (bytes * 8)) - 1;
      char number[32];
      std::snprintf(number, sizeof(number), "0x%llx",
                    static_cast<unsigned long long>(immediate));
      if (rendered_type)
        *rendered_type = {immediate <= INT32_MAX || (immediate > UINT32_MAX &&
                                                     immediate <= INT64_MAX)
                              ? CT_VALUE_SIGNED
                              : CT_VALUE_UNSIGNED,
                          immediate <= UINT32_MAX ? size_t{4} : size_t{8}};
      return number;
    }
    const bool operand_memory = opnd_is_memory_reference(operand);
    if (!operand_memory &&
        (!opnd_is_reg(operand) || !reg_is_gpr(opnd_get_reg(operand))))
      return {};
    const size_t operand_bytes = opnd_size_in_bytes(opnd_get_size(operand));
    if (operand_bytes != 1 && operand_bytes != 2 && operand_bytes != 4 &&
        operand_bytes != 8)
      return {};
    if (rendered_type)
      *rendered_type = {CT_VALUE_UNSIGNED, operand_bytes};
    uint64_t location = 0;
    size_t offset = 0;
    if (!ct_operand_location(operand, registers, &location, &offset))
      return {};
    ct_values_site *site = writing && after ? after : before;
    const ct_registers &state =
        writing && after && after_registers ? *after_registers : registers;
    char name[256]{};
    ct_value_type type{};
    std::string type_name;
    bool named = site && ct_values_find_name(site, &state, read, argument,
                                             operand_memory, location, offset,
                                             operand_bytes, name, sizeof(name));
    if (named) {
      ct_values_operand_type(site, &state, read, argument, operand_memory,
                             location, offset, operand_bytes, &type);
    } else if (decompiled) {
      if (const auto *binding = ct_find_decompiled_operand(
              *decompiled, operand, registers, !writing, writing)) {
        std::snprintf(name, sizeof(name), "%s", binding->name.c_str());
        type = binding->type;
        type_name = binding->type_name;
        named = true;
      }
    }
    if (!named && !writing && provenance)
      if (const auto *origin =
              ct_operand_origin(*provenance, operand, registers)) {
        std::snprintf(name, sizeof(name), "%s", origin->name.c_str());
        type = origin->type;
        type_name = origin->type_name;
        named = true;
      }
    if (named) {
      // Integer instructions can copy floating/aggregate object bits. Avoid
      // turning those bit copies into numeric C conversions.
      const bool untyped_scalar =
          type.kind == CT_VALUE_UNKNOWN &&
          type_name == "uint" + std::to_string(operand_bytes * 8) + "_t";
      if (type.kind == CT_VALUE_FLOAT ||
          (type.kind == CT_VALUE_UNKNOWN && !untyped_scalar))
        return "*(uint" + std::to_string(operand_bytes * 8) + "_t *)&(" + name +
               ")";
      if (type.kind == CT_VALUE_POINTER)
        return writing ? "*(uintptr_t *)&(" + std::string(name) + ")"
                       : "(uintptr_t)(" + std::string(name) + ")";
      if (rendered_type && !untyped_scalar)
        *rendered_type = type;
      return name;
    }
    if (!operand_memory)
      return ct_register_name(opnd_get_reg(operand));
    std::string location_text = address(operand);
    return location_text.empty()
               ? std::string{}
               : "*(uint" + std::to_string(operand_bytes * 8) + "_t *)(" +
                     location_text + ")";
  };
  if (push) {
    // DR lists the pushed value before the implicit old stack pointer.
    // Evaluate and store it before changing RSP, including PUSH RSP.
    if (instruction.inputs.size() != 2 ||
        !opnd_is_reg(instruction.inputs.back()) ||
        opnd_get_reg(instruction.inputs.back()) != DR_REG_RSP)
      return {};
    const std::string source = operand_text(instruction.inputs.front(), false);
    return source.empty()
               ? std::string{}
               : "*(uint64_t *)(RSP - 8) = " + source + "; RSP -= 8;";
  }
  std::string destination = operand_text(output, true);
  if (destination.empty())
    return {};
  if (pop)
    return destination + " = *(uint64_t *)RSP; RSP += 8;";
  const bool raw_register =
      !memory && destination == ct_register_name(opnd_get_reg(output));
  std::string expression;
  ct_value_type expression_type{};
  // Use unsigned arithmetic to retain the machine's modulo semantics without
  // repeatedly casting operands whose displayed types already provide them.
  // Sub-word C operands promote to int; multiplication and left shifts need
  // an unsigned promotion even when their original storage is unsigned.
  auto unsigned_operand = [](std::string text, const ct_value_type &type,
                             size_t width) {
    if (type.kind == CT_VALUE_UNSIGNED && type.bytes == width)
      return text;
    return "(uint" + std::to_string(width * 8) + "_t)(" + text + ")";
  };
  const auto &inputs = instruction.inputs;
  const bool move = opcode == OP_mov_ld || opcode == OP_mov_st ||
                    opcode == OP_mov_imm || opcode == OP_movzx ||
                    opcode == OP_movsx || opcode == OP_movsxd;
  if (move && inputs.size() == 1) {
    expression = operand_text(inputs.front(), false, &expression_type);
    if (expression.empty())
      return {};
    if (opcode == OP_movsx || opcode == OP_movsxd || opcode == OP_movzx) {
      const size_t source_bytes =
          opnd_size_in_bytes(opnd_get_size(inputs.front()));
      if (!source_bytes || source_bytes >= bytes)
        return {};
      const auto required_kind =
          opcode == OP_movzx ? CT_VALUE_UNSIGNED : CT_VALUE_SIGNED;
      if (expression_type.kind != required_kind ||
          expression_type.bytes != source_bytes)
        expression = "(" + std::string(opcode == OP_movzx ? "uint" : "int") +
                     std::to_string(source_bytes * 8) + "_t)(" + expression +
                     ")";
      expression_type = {required_kind, source_bytes};
    }
  } else if (opcode == OP_lea && inputs.size() == 1) {
    expression = address(inputs.front());
    expression_type = {CT_VALUE_UNSIGNED, 8};
    if (opnd_is_base_disp(inputs.front()) &&
        ((opnd_get_base(inputs.front()) != DR_REG_NULL &&
          reg_get_size(opnd_get_base(inputs.front())) == OPSZ_4) ||
         (opnd_get_index(inputs.front()) != DR_REG_NULL &&
          reg_get_size(opnd_get_index(inputs.front())) == OPSZ_4)))
      expression_type.bytes = 4;
  } else if (set_condition && inputs.empty()) {
    ct_instruction branch;
    branch.valid = branch.branch = true;
    branch.opcode = OP_jo + opcode - OP_seto;
    expression = ct_format_branch_condition(branch);
    expression_type = {CT_VALUE_BOOLEAN, 1};
  } else if (conditional_move && inputs.size() == 1) {
    // A memory CMOV reads its source even when the condition is false.
    // A C conditional expression would suppress that access and its faults.
    const opnd_t *source = &inputs.front();
    if (!opnd_is_reg(*source))
      return {};
    ct_value_type source_type{}, previous_type{};
    const std::string source_text = operand_text(*source, false, &source_type);
    const std::string previous = operand_text(output, false, &previous_type);
    if (source_text.empty() || previous.empty())
      return {};
    ct_instruction branch;
    branch.valid = branch.branch = true;
    branch.opcode = OP_jo + opcode - OP_cmovo;
    expression = "(" + ct_format_branch_condition(branch) + ") ? " +
                 source_text + " : " + previous;
    if (source_type.kind == previous_type.kind &&
        source_type.bytes == previous_type.bytes)
      expression_type = source_type;
  } else if ((opcode == OP_inc || opcode == OP_dec || opcode == OP_neg ||
              opcode == OP_not) &&
             inputs.size() == 1 && opnd_same(inputs.front(), output)) {
    ct_value_type previous_type{};
    const std::string previous = operand_text(output, false, &previous_type);
    if (previous.empty())
      return {};
    const size_t arithmetic_bytes = std::max(bytes, size_t{4});
    const auto converted =
        unsigned_operand(previous, previous_type, arithmetic_bytes);
    if (opcode == OP_inc || opcode == OP_dec)
      expression = converted + (opcode == OP_inc ? " + 1" : " - 1");
    else
      expression = std::string(opcode == OP_neg ? "0 - " : "~") + converted;
    expression_type = {CT_VALUE_UNSIGNED, arithmetic_bytes};
  } else if ((opcode == OP_add || opcode == OP_sub || opcode == OP_imul ||
              opcode == OP_and || opcode == OP_or || opcode == OP_xor ||
              opcode == OP_shl || opcode == OP_shr || opcode == OP_sar) &&
             inputs.size() == 2) {
    const opnd_t *left = nullptr, *right = nullptr;
    if (opcode == OP_imul) {
      // Two/three explicit IMUL operands have one low-half destination.
      // Its signed and unsigned products agree modulo that destination width.
      left = &inputs[0];
      right = &inputs[1];
    } else {
      for (const auto &input : inputs)
        if (opnd_same(input, output) && !left)
          left = &input;
        else if (!right)
          right = &input;
    }
    if (!left || !right)
      return {};
    ct_value_type lhs_type{}, rhs_type{};
    std::string lhs = operand_text(*left, false, &lhs_type);
    std::string rhs = operand_text(*right, false, &rhs_type);
    if (lhs.empty() || rhs.empty())
      return {};
    if (opcode == OP_xor && opnd_same(*left, *right)) {
      expression = "0";
      expression_type = {CT_VALUE_BOOLEAN, 1};
    } else if (opcode == OP_shl || opcode == OP_shr || opcode == OP_sar) {
      const std::string count =
          "(" + rhs + " & " + (bytes == 8 ? "63" : "31") + ")";
      if (opcode == OP_sar) {
        // Sign extend before shifting, including byte/word counts larger
        // than their operand width. All x86 counts are below 64.
        if (lhs_type.kind != CT_VALUE_SIGNED || lhs_type.bytes != bytes)
          lhs = "(int" + width + "_t)(" + lhs + ")";
        // Byte/word operands promote to int, whose 32-bit width already
        // covers every masked shift count for those instructions.
        expression_type = {CT_VALUE_SIGNED, std::max(bytes, size_t{4})};
      } else {
        const size_t arithmetic_bytes = std::max(bytes, size_t{4});
        if (bytes < 4 && lhs_type.kind == CT_VALUE_SIGNED)
          lhs = "(" + unsigned_type + ")(" + lhs + ")";
        lhs = unsigned_operand(lhs, lhs_type, arithmetic_bytes);
        expression_type = {CT_VALUE_UNSIGNED, arithmetic_bytes};
      }
      expression = lhs + (opcode == OP_shl ? " << " : " >> ") + count;
    } else {
      const char *operation = opcode == OP_add    ? " + "
                              : opcode == OP_sub  ? " - "
                              : opcode == OP_imul ? " * "
                              : opcode == OP_and  ? " & "
                              : opcode == OP_or   ? " | "
                                                  : " ^ ";
      const size_t arithmetic_bytes = std::max(bytes, size_t{4});
      // One unsigned operand controls the usual arithmetic conversions.
      // The other requires conversion only when wider or of equal-width
      // signed type with greater rank (not present for our fixed-width types).
      if (lhs_type.kind != CT_VALUE_UNSIGNED ||
          lhs_type.bytes != arithmetic_bytes) {
        if (rhs_type.kind != CT_VALUE_UNSIGNED ||
            rhs_type.bytes != arithmetic_bytes)
          lhs = unsigned_operand(lhs, lhs_type, arithmetic_bytes);
      }
      if (rhs_type.bytes > arithmetic_bytes)
        rhs = unsigned_operand(rhs, rhs_type, arithmetic_bytes);
      expression = lhs + operation + rhs;
      expression_type = {CT_VALUE_UNSIGNED, arithmetic_bytes};
    }
  } else
    return {};
  if (expression.empty())
    return {};
  // Assignments already convert to their destination type. Only raw 32-bit
  // register writes (shown through the full register) and partial-register
  // merges need an explicit low-width conversion when the expression has
  // not already acquired that type.
  // MOV immediates have already been masked to the destination width above.
  // Even a signed C literal therefore has a nonnegative, representable value.
  const bool immediate_move =
      move && inputs.size() == 1 && opnd_is_immed_int(inputs.front());
  if (raw_register && bytes < 8 &&
      !(expression_type.kind == CT_VALUE_UNSIGNED &&
        expression_type.bytes <= bytes) &&
      expression_type.kind != CT_VALUE_BOOLEAN && !immediate_move)
    expression = "(" + unsigned_type + ")(" + expression + ")";
  if (raw_register) {
    const reg_id_t reg = opnd_get_reg(output);
    const std::string full = ct_register_name(reg_resize_to_opsz(reg, OPSZ_8));
    if (bytes == 4) {
      // AMD64 32-bit writes clear the high half, unlike byte/word writes.
      destination = full;
    } else if (bytes < 4) {
      const size_t shift = reg >= DR_REG_AH && reg <= DR_REG_BH ? 8 : 0;
      const uint64_t mask = ((uint64_t{1} << (bytes * 8)) - 1) << shift;
      char keep[32];
      std::snprintf(keep, sizeof(keep), "0x%llx",
                    static_cast<unsigned long long>(~mask));
      // The low-width conversion bounds the merged value. A high-byte shift
      // is at most 255 << 8, so integer promotion cannot overflow here.
      expression = "(" + full + " & " + keep + ") | (" +
                   (shift ? "(" + expression + ") << " + std::to_string(shift)
                          : expression) +
                   ")";
      destination = full;
    }
  }
  return destination + " = " + expression + ";";
}

const ct_register_origin *ct_operand_origin(const ct_provenance &provenance,
                                            opnd_t operand,
                                            const ct_registers &registers) {
  uint64_t location = 0;
  size_t offset = 0;
  if (!opnd_is_reg(operand) ||
      !ct_operand_location(operand, registers, &location, &offset) || offset ||
      location >= provenance.registers.size())
    return nullptr;
  const auto &origin = provenance.registers[location];
  if (origin.name.empty() ||
      origin.bytes != opnd_size_in_bytes(opnd_get_size(operand)))
    return nullptr;
  return &origin;
}

void ct_invalidate_provenance_memory(ct_provenance &provenance,
                                     const ct_instruction &instruction,
                                     const ct_registers &registers) {
  if (!instruction.writes_memory)
    return;
  bool found = false;
  for (opnd_t operand : instruction.outputs) {
    if (!opnd_is_memory_reference(operand))
      continue;
    uint64_t address = 0;
    size_t offset = 0;
    size_t bytes = opnd_size_in_bytes(opnd_get_size(operand));
    bool known =
        bytes && ct_operand_location(operand, registers, &address, &offset);
    found = true;
    for (auto &origin : provenance.registers) {
      if (!origin.memory_bytes)
        continue;
      // Subtraction avoids overflow at the top of the application address
      // space. Unknown destinations may alias any originating storage.
      bool overlaps =
          !known || (address <= origin.address
                         ? origin.address - address < bytes
                         : address - origin.address < origin.memory_bytes);
      if (overlaps)
        origin = {};
    }
  }
  if (!found)
    for (auto &origin : provenance.registers)
      if (origin.memory_bytes)
        origin = {};
}

void ct_update_provenance(
    ct_provenance &provenance, const ct_instruction &instruction,
    ct_values_site *before, const ct_registers &registers, ct_read_memory read,
    void *argument, const std::vector<ct_decompiled_operand> *decompiled) {
  if (!instruction.valid) {
    provenance = {};
    return;
  }
  ct_register_origin copied;
  uint64_t destination = provenance.registers.size();
  // Exact scalar/SIMD moves preserve a known low-lane scalar. Extensions,
  // LEA, conditional moves and arithmetic need different proofs.
  bool scalar_simd =
      instruction.opcode == OP_movss || instruction.opcode == OP_movsd;
  bool vector_copy =
      instruction.opcode == OP_movaps || instruction.opcode == OP_movapd ||
      instruction.opcode == OP_movups || instruction.opcode == OP_movupd ||
      instruction.opcode == OP_movdqa || instruction.opcode == OP_movdqu;
  bool move = instruction.valid && !instruction.conditional &&
              (instruction.opcode == OP_mov_ld ||
               instruction.opcode == OP_mov_st || scalar_simd || vector_copy);
  if (move && instruction.inputs.size() == 1 &&
      instruction.outputs.size() == 1 &&
      opnd_is_reg(instruction.outputs.front())) {
    opnd_t source = instruction.inputs.front();
    opnd_t output = instruction.outputs.front();
    size_t bytes = opnd_size_in_bytes(opnd_get_size(source));
    size_t offset = 0;
    uint64_t location = 0;
    size_t output_offset = 0;
    bool memory = opnd_is_memory_reference(source);
    size_t output_bytes = opnd_size_in_bytes(opnd_get_size(output));
    // Legacy scalar loads clear the other XMM lanes, so DR describes their
    // destination as 16 bytes even though only 4/8 source bytes are copied.
    bool scalar_load = scalar_simd && memory && output_bytes == 16 &&
                       reg_is_xmm(opnd_get_reg(output));
    if (bytes && (bytes == output_bytes || scalar_load) &&
        ct_operand_location(output, registers, &destination, &output_offset) &&
        !output_offset && destination < provenance.registers.size() &&
        ct_operand_location(source, registers, &location, &offset)) {
      ct_variable_description description{};
      const auto *binding =
          decompiled ? ct_find_decompiled_operand(*decompiled, source,
                                                  registers, true, false)
                     : nullptr;
      if (ct_values_describe_operand(before, &registers, read, argument, memory,
                                     location, offset, bytes, &description) &&
          ct_values_operand_type(before, &registers, read, argument, memory,
                                 location, offset, bytes, &copied.type)) {
        copied.name = description.name;
        copied.symbol_module_id = description.module_id;
        copied.symbol_die_offset = description.die_offset;
        copied.type_name = description.type;
        copied.bytes = bytes;
        if (memory) {
          copied.address = location;
          copied.memory_bytes = bytes;
        } else
          copied.source_register = static_cast<int>(location);
      } else if (binding) {
        copied.name = binding->name;
        copied.source_identity = binding->identity;
        copied.type_name = binding->type_name;
        copied.type = binding->type;
        copied.bytes = bytes;
        if (memory) {
          copied.address = location;
          copied.memory_bytes = bytes;
        } else
          copied.source_register = static_cast<int>(location);
      } else if (const auto *origin =
                     ct_operand_origin(provenance, source, registers))
        copied = *origin;
      else if (vector_copy && !memory && !offset && bytes == 16 &&
               location >= 17 && location < provenance.registers.size()) {
        const auto &origin = provenance.registers[location];
        // Keep the scalar's original width: a full-vector read must not
        // acquire a scalar name for its otherwise unknown upper lanes.
        if (!origin.name.empty() && origin.bytes && origin.bytes <= bytes)
          copied = origin;
      }
    }
  }
  ct_invalidate_provenance_memory(provenance, instruction, registers);
  for (opnd_t operand : instruction.outputs) {
    if (!opnd_is_reg(operand))
      continue;
    uint64_t location = 0;
    size_t offset = 0;
    // ct_operand_location canonicalizes GPR aliases, so a write to AH, AL,
    // AX or EAX invalidates the entire RAX fact even when bytes happen to
    // match.
    if (ct_operand_location(operand, registers, &location, &offset) &&
        location < provenance.registers.size()) {
      provenance.registers[location] = {};
      for (auto &origin : provenance.registers)
        if (origin.source_register == static_cast<int>(location))
          origin = {};
    } else if (reg_is_simd(opnd_get_reg(operand))) {
      reg_id_t reg = reg_resize_to_opsz(opnd_get_reg(operand), OPSZ_16);
      if (reg >= DR_REG_XMM0 && reg <= DR_REG_XMM15) {
        provenance.registers[17 + reg - DR_REG_XMM0] = {};
        for (auto &origin : provenance.registers)
          if (origin.source_register == 17 + reg - DR_REG_XMM0)
            origin = {};
      }
    }
  }
  if (!copied.name.empty() && destination < provenance.registers.size())
    provenance.registers[destination] = std::move(copied);
}

static std::string asm_escape(const std::string &text) {
  std::string result;
  for (unsigned char byte : text) {
    switch (byte) {
    case '%':
      result += "%%";
      break;
    case '{':
    case '}':
    case '|':
      result += '%';
      result += static_cast<char>(byte);
      break;
    case '\\':
      result += "\\\\";
      break;
    case '"':
      result += "\\\"";
      break;
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += ' ';
      break;
    default:
      if (byte < 32 || byte == 127) {
        char escaped[5];
        std::snprintf(escaped, sizeof(escaped), "\\%03o", byte);
        result += escaped;
      } else
        result += static_cast<char>(byte);
    }
  }
  return result;
}

std::string
ct_format_assembly(const ct_instruction &instruction, ct_values_site *before,
                   ct_values_site *after, const ct_registers &registers,
                   ct_read_memory read, void *argument, int syntax,
                   const ct_registers *after_registers,
                   const ct_provenance *provenance, const char *call_target,
                   const std::vector<ct_decompiled_operand> *decompiled) {
  const std::string normal =
      ct_values_has_scope(before) || ct_values_has_scope(after) ? "\033[33m"
                                                                : "\033[31m";
  const std::string red = "\033[31m";
  const std::string white = "\033[37m";
  if (!instruction.valid || instruction.att.empty() ||
      instruction.intel.empty()) {
    std::string bytes;
    for (size_t offset = 0; offset < instruction.bytes.size();) {
      if (instruction.bytes[offset] == ' ') {
        ++offset;
        continue;
      }
      if (offset + 2 > instruction.bytes.size() ||
          !std::isxdigit(
              static_cast<unsigned char>(instruction.bytes[offset])) ||
          !std::isxdigit(
              static_cast<unsigned char>(instruction.bytes[offset + 1])) ||
          (offset + 2 < instruction.bytes.size() &&
           instruction.bytes[offset + 2] != ' '))
        return {};
      if (!bytes.empty())
        bytes += ", ";
      bytes += "0x" + instruction.bytes.substr(offset, 2);
      offset += 2;
    }
    return bytes.empty() ? bytes
                         : red + "asm (\".byte " + bytes + "\" : );\033[0m";
  }
  struct relation {
    const ct_asm_operand *operand;
    std::string name, placeholder;
    bool known = false;
    bool label = false;
    bool symbol = false;
  };
  std::vector<relation> relations;
  std::vector<std::string> outputs, inputs;
  std::set<std::string> clobbers;
  std::set<std::string> placeholders;
  std::string target_label;
  for (const auto &operand : instruction.operands) {
    if ((instruction.branch || instruction.call) && !instruction.ret &&
        opnd_is_pc(operand.value)) {
      char label[48];
      std::snprintf(label, sizeof(label), "L%llx",
                    static_cast<unsigned long long>(reinterpret_cast<uint64_t>(
                        opnd_get_pc(operand.value))));
      if (instruction.call) {
        std::string name = call_target ? call_target : "";
        bool valid = !name.empty() &&
                     (std::isalpha(static_cast<unsigned char>(name.front())) ||
                      name.front() == '_' || name.front() == '.') &&
                     std::all_of(name.begin(), name.end(), [](unsigned char c) {
                       return c < 128 && (std::isalnum(c) || c == '_' ||
                                          c == '.' || c == '$');
                     });
        // Intel register names are not direct branch symbols. Use an address
        // label for that unusual linkage-name collision.
        if (valid)
          for (int reg = DR_REG_RAX; reg <= DR_REG_STOP_8; ++reg)
            if (name == get_register_name(static_cast<reg_id_t>(reg)))
              valid = false;
        if (valid)
          relations.push_back({&operand, name, name, true, false, true});
        else
          relations.push_back({&operand, {}, label, true, false, true});
      } else {
        target_label = label;
        relations.push_back({&operand, {}, target_label, true, true});
      }
      continue;
    }
    bool memory = opnd_is_memory_reference(operand.value);
    bool reg = opnd_is_reg(operand.value);
    if (!memory && !reg)
      continue;
    uint64_t location = 0;
    size_t offset = 0;
    size_t bytes = opnd_size_in_bytes(opnd_get_size(operand.value));
    char name[256] = {};
    ct_values_site *site = before;
    const ct_registers *state = &registers;
    if (operand.write && after && after_registers) {
      site = after;
      state = after_registers;
    }
    // Compute the accessed address before execution, even if its base register
    // is changed by the instruction. Location expressions use the relevant PC.
    bool mapped =
        ct_operand_location(operand.value, registers, &location, &offset) &&
        ct_values_find_name(site, state, read, argument, memory, location,
                            offset, bytes, name, sizeof(name));
    bool recovered = false;
    if (!mapped && decompiled) {
      if (const auto *binding =
              ct_find_decompiled_operand(*decompiled, operand.value, registers,
                                         operand.read, operand.write)) {
        if (binding->name.size() < sizeof(name)) {
          std::snprintf(name, sizeof(name), "%s", binding->name.c_str());
          mapped = recovered = true;
        }
      }
    }
    // A copied variable is a proven input value, not the destination lvalue.
    // Keep outputs as real registers until DWARF proves a storage relation.
    if (!mapped && reg && operand.read && !operand.write && provenance) {
      if (const auto *origin =
              ct_operand_origin(*provenance, operand.value, registers)) {
        std::snprintf(name, sizeof(name), "%s", origin->name.c_str());
        mapped = true;
      }
    }
    bool explicit_operand = operand.explicit_operand;
    // LEA carries an address expression, not a read of the pointed-to object.
    bool actual_memory = !memory ||
                         (operand.read && instruction.reads_memory) ||
                         (operand.write && instruction.writes_memory);
    relation relation{&operand,
                      name,
                      {},
                      mapped && explicit_operand && actual_memory &&
                          !instruction.fixed_operands};
    if (relation.known && !recovered && operand.read && operand.write &&
        before && after_registers) {
      char input_name[256] = {};
      relation.known = ct_values_find_name(before, &registers, read, argument,
                                           memory, location, offset, bytes,
                                           input_name, sizeof(input_name)) &&
                       relation.name == input_name;
    }
    if (relation.known) {
      // Register operands expose their observed physical name. The symbolic
      // GNU operand name does not force allocation; its C expression is the
      // recovered value. Memory names derive from the recovered expression.
      std::string identifier;
      std::string operand_name =
          reg ? ct_register_name(opnd_get_reg(operand.value)) : relation.name;
      for (unsigned char c : operand_name)
        identifier += c < 128 && (std::isalnum(c) || c == '_')
                          ? static_cast<char>(c)
                          : '_';
      if (identifier.empty() || std::isdigit(identifier.front()))
        identifier.insert(0, "_");
      relation.placeholder = identifier;
      for (size_t suffix = 2; !placeholders.insert(relation.placeholder).second;
           ++suffix)
        relation.placeholder = identifier + "_" + std::to_string(suffix);
      std::string constraint = operand.write ? (operand.read ? "+" : "=") : "";
      constraint += memory                                     ? "m"
                    : reg_is_simd(opnd_get_reg(operand.value)) ? "x"
                                                               : "r";
      std::string entry = white + "[" + relation.placeholder + "] \"" +
                          constraint + "\" (" + relation.name + ")" + normal;
      (operand.write ? outputs : inputs).push_back(entry);
    } else if (operand.write && reg) {
      reg_id_t output = opnd_get_reg(operand.value);
      // GNU asm requires the stack pointer to survive the statement. Observed
      // stack changes belong in before/after, not a forbidden rsp clobber.
      if (!reg_is_gpr(output) ||
          reg_resize_to_opsz(output, OPSZ_8) != DR_REG_RSP) {
        // GCC clobber strings are case-sensitive compiler identifiers, not
        // generated variable names or assembler text.
        const std::string name =
            output == DR_REG_ST0 ? "st"
            : output > DR_REG_ST0 && output <= DR_REG_ST7
                ? "st(" + std::to_string(output - DR_REG_ST0) + ")"
                : get_register_name(output);
        clobbers.insert(name);
      }
    }
    relations.push_back(std::move(relation));
  }
  if (instruction.eflags & EFLAGS_WRITE_ALL)
    clobbers.insert("cc");
  if (instruction.atomic || instruction.call || instruction.ret ||
      instruction.syscall)
    clobbers.insert("memory");
  auto render_template = [&](int mode) {
    const auto &text = mode ? instruction.intel : instruction.att;
    std::string result;
    size_t cursor = 0;
    // Use exact operand spans. A resolved explicit register must never replace
    // a register name inside an unrelated memory operand's address.
    for (const auto &token : instruction.tokens[mode]) {
      result += asm_escape(text.substr(cursor, token.offset - cursor));
      std::string spelling = text.substr(token.offset, token.length);
      const ct_asm_operand *operand =
          token.operand < instruction.operands.size()
              ? &instruction.operands[token.operand]
              : nullptr;
      auto relation = std::find_if(
          relations.begin(), relations.end(),
          [&](const auto &entry) { return entry.operand == operand; });
      if (relation != relations.end() && relation->symbol)
        result += (relation->name.empty() ? red : white) +
                  relation->placeholder + normal;
      else if (relation != relations.end() && relation->known) {
        std::string modifier = relation->label ? "l" : "";
        // GNU's ordinary named memory operand prints the size from its C
        // type in Intel mode. Preserve explicit sizes only on raw operands,
        // whose spelling must carry any width not implied by the instruction.
        result += (relation->label ? red : white) + "%" + modifier + "[" +
                  relation->placeholder + "]" + normal;
      } else
        result += (token.machine ? red : "") +
                  asm_escape(assembly_registers(std::move(spelling))) +
                  (token.machine ? normal : "");
      cursor = token.offset + token.length;
    }
    return result + asm_escape(text.substr(cursor));
  };
  std::string result =
      normal + (target_label.empty() ? "asm (\"" : "asm goto (\"");
  result += render_template(syntax < 0 ? 0 : syntax);
  result += "\" : ";
  for (size_t index = 0; index < outputs.size(); ++index)
    result += (index ? ", " : "") + outputs[index];
  if (!inputs.empty() || !clobbers.empty() || !target_label.empty()) {
    result += " : ";
    for (size_t index = 0; index < inputs.size(); ++index)
      result += (index ? ", " : "") + inputs[index];
  }
  if (!clobbers.empty() || !target_label.empty()) {
    result += " : ";
    for (auto iterator = clobbers.begin(); iterator != clobbers.end();
         ++iterator) {
      if (iterator != clobbers.begin())
        result += ", ";
      bool semantic = *iterator == "cc" || *iterator == "memory";
      result += (semantic ? "" : red) + "\"" + *iterator + "\"" +
                (semantic ? "" : normal);
    }
  }
  if (!target_label.empty())
    result += " : " + red + target_label + normal;
  result += ");";
  return result + "\033[0m";
}
