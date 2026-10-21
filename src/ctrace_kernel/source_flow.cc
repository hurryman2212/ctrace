// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

#include <llvm/BinaryFormat/Dwarf.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <elf.h>

#include "flow.hh"
#include "source_compare.hh"
#include "source_flow.hh"

bool ct_kernel_complete_source(const ct_kernel_image &image,
                               const std::vector<ct_kernel_site> &sites,
                               const ct_kernel_value_metadata &values,
                               ct_kernel_source_metadata &source,
                               std::string &error) {
  error.clear();
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();
  const llvm::Triple triple("x86_64-pc-linux-gnu");
  const auto *target = llvm::TargetRegistry::lookupTarget(triple.str(), error);
  if (!target)
    return false;
  std::unique_ptr<llvm::MCRegisterInfo> registers(
      target->createMCRegInfo(triple.str()));
  if (!registers) {
    error = "source dependency register metadata unavailable";
    return false;
  }
  llvm::MCTargetOptions options;
  std::unique_ptr<llvm::MCAsmInfo> assembly(
      target->createMCAsmInfo(*registers, triple.str(), options));
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget(
      target->createMCSubtargetInfo(triple.str(), "generic", ""));
  std::unique_ptr<llvm::MCInstrInfo> descriptions(target->createMCInstrInfo());
  if (!assembly || !subtarget || !descriptions) {
    error = "source dependency instruction metadata unavailable";
    return false;
  }
  llvm::MCContext context(triple, assembly.get(), registers.get(),
                          subtarget.get());
  std::unique_ptr<llvm::MCDisassembler> decoder(
      target->createMCDisassembler(*subtarget, context));
  std::unique_ptr<llvm::MCInstrAnalysis> analysis(
      target->createMCInstrAnalysis(descriptions.get()));
  if (!decoder || !analysis) {
    error = "source dependency decoder unavailable";
    return false;
  }
  const std::array<const char *, 17> names{
      "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",   "R8",
      "R9",  "R10", "R11", "R12", "R13", "R14", "R15", "EFLAGS"};
  const std::array<const char *, 16> narrow_names{
      "EAX", "ECX", "EDX",  "EBX",  "ESP",  "EBP",  "ESI",  "EDI",
      "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D"};
  static constexpr std::array<unsigned, 16> dwarf_registers{
      0, 2, 1, 3, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15};
  std::array<unsigned, names.size()> canonical{};
  for (unsigned reg = 1; reg < registers->getNumRegs(); ++reg)
    for (size_t index = 0; index < names.size(); ++index)
      if (llvm::StringRef(registers->getName(reg)) == names[index])
        canonical[index] = reg;
  if (std::find(canonical.begin(), canonical.end(), 0) != canonical.end()) {
    error = "source dependency register identities unavailable";
    return false;
  }
  const auto mask = [&](unsigned reg) {
    for (size_t index = 0; reg && index < canonical.size(); ++index)
      if (registers->regsOverlap(reg, canonical[index]))
        return uint32_t(1) << index;
    return uint32_t(0);
  };
  const auto full_write = [&](unsigned reg) {
    const llvm::StringRef name = reg ? registers->getName(reg) : "";
    for (size_t index = 0; index < canonical.size(); ++index)
      if (reg == canonical[index] ||
          (index < narrow_names.size() && name == narrow_names[index]))
        return uint32_t(1) << index;
    return uint32_t(0);
  };
  struct Node {
    const ct_kernel_site *site;
    uint32_t reads = 0, writes = 0, kills = 0;
    uint32_t constant_register = 0;
    std::optional<uint64_t> constant;
    std::optional<std::pair<uint32_t, uint64_t>> address;
    uint32_t address_register = 0;
    std::optional<int64_t> stack_offset;
    size_t stack_bytes = 0;
    std::optional<int64_t> stack_adjust = 0, guard_slot, store_slot;
    std::string guard, called;
    uint32_t guard_register = 0, store_register = 0, compared_register = 0;
    std::vector<uint64_t> next, previous;
    bool candidate = false, returned = false, frontier = false, load = false,
         unknown_call = false, pure_register = false, not_equal = false,
         call = false, imported_call = false, dead = false;
    bool originally_unmapped = false;
  };
  std::map<uint64_t, Node> nodes;
  std::map<uint64_t, std::set<uint32_t>> value_functions;
  std::map<std::pair<uint32_t, uint64_t>, uint64_t> addresses;
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  for (const auto &symbol : image.symbols)
    symbols[{symbol.table, symbol.index}] = &symbol;
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_relocation *>
      relocations;
  for (const auto &relocation : image.relocations)
    relocations[{relocation.section, relocation.offset}] = &relocation;
  for (const auto &site : sites) {
    if (!site.id || site.id >= source.sites.size() ||
        !source.sites[site.id].function)
      continue;
    addresses.emplace(std::make_pair(site.section, site.offset), site.id);
    if (site.id < values.sites.size() && values.sites[site.id].function)
      value_functions[source.sites[site.id].function].insert(
          values.sites[site.id].function);
  }
  const auto source_row = [&](uint64_t id) {
    return ct_kernel_source_row(source, id);
  };
  for (const auto &site : sites) {
    if (!addresses.count({site.section, site.offset}))
      continue;
    if (site.section >= image.sections.size()) {
      error = "source dependency section is absent";
      return false;
    }
    const auto &section = image.sections[site.section];
    if (section.offset > image.bytes.size() ||
        section.size > image.bytes.size() - section.offset ||
        site.offset > section.size ||
        site.original_size > section.size - site.offset) {
      error = "source dependency instruction exceeds original section";
      return false;
    }
    const llvm::ArrayRef<unsigned char> code(
        image.bytes.data() + section.offset + site.offset, site.original_size);
    llvm::MCInst instruction;
    uint64_t size = 0;
    do {
      uint64_t part = 0;
      if (decoder->getInstruction(instruction, part, code.drop_front(size),
                                  site.offset + size, llvm::nulls()) !=
              llvm::MCDisassembler::Success ||
          !part || part > code.size() - size)
        break;
      size += part;
    } while (
        size < code.size() &&
        descriptions->getName(instruction.getOpcode()).ends_with("_PREFIX"));
    if (size != code.size())
      continue;
    const auto &description = descriptions->get(instruction.getOpcode());
    const auto opcode = descriptions->getName(instruction.getOpcode());
    Node node{};
    node.site = &site;
    node.originally_unmapped = !source.sites[site.id].line;
    for (unsigned index = 0; index < instruction.getNumOperands(); ++index) {
      const auto &operand = instruction.getOperand(index);
      if (!operand.isReg())
        continue;
      if (index < description.getNumDefs()) {
        node.writes |= mask(operand.getReg());
        node.kills |= full_write(operand.getReg());
      } else
        node.reads |= mask(operand.getReg());
    }
    for (unsigned reg : description.implicit_defs()) {
      node.writes |= mask(reg);
      node.kills |= full_write(reg);
    }
    for (unsigned reg : description.implicit_uses())
      node.reads |= mask(reg);
    const auto reg = [&](unsigned index) {
      return index < instruction.getNumOperands() &&
                     instruction.getOperand(index).isReg()
                 ? unsigned(instruction.getOperand(index).getReg())
                 : 0;
    };
    node.call = description.isCall();
    if (node.writes & (1U << 4))
      node.stack_adjust.reset();
    if (opcode.starts_with("PUSH64"))
      node.stack_adjust = -8;
    else if (opcode.starts_with("POP64") && mask(reg(0)) != (1U << 4))
      node.stack_adjust = 8;
    else if ((opcode == "ADD64ri8" || opcode == "ADD64ri32" ||
              opcode == "SUB64ri8" || opcode == "SUB64ri32") &&
             reg(0) == canonical[4] && reg(1) == canonical[4] &&
             instruction.getNumOperands() == 3 &&
             instruction.getOperand(2).isImm())
      node.stack_adjust = opcode.starts_with("SUB")
                              ? -instruction.getOperand(2).getImm()
                              : instruction.getOperand(2).getImm();
    else if (opcode.starts_with("CALL64")) {
      node.stack_adjust = 0;
      const auto field = relocations.lower_bound({site.section, site.offset});
      uint64_t destination = 0;
      if ((field == relocations.end() || field->first.first != site.section ||
           field->first.second >= site.offset + size) &&
          analysis->evaluateBranch(instruction, site.offset, size,
                                   destination) &&
          destination == site.offset + size)
        node.stack_adjust = -8;
    }
    if (description.isConditionalBranch() &&
        instruction.getNumOperands() == 2 &&
        instruction.getOperand(1).isImm() &&
        instruction.getOperand(1).getImm() == 5)
      node.not_equal = true;
    const auto stack_operand = [&](unsigned first) {
      return instruction.getNumOperands() >= first + 5 &&
             reg(first) == canonical[4] &&
             instruction.getOperand(first + 1).isImm() &&
             instruction.getOperand(first + 1).getImm() == 1 &&
             instruction.getOperand(first + 2).isReg() && !reg(first + 2) &&
             instruction.getOperand(first + 3).isImm() &&
             instruction.getOperand(first + 4).isReg() && !reg(first + 4);
    };
    if (opcode == "CMP64rm" && stack_operand(1)) {
      node.guard_slot = instruction.getOperand(4).getImm();
      node.compared_register = mask(reg(0));
    }
    if (opcode == "MOV64mr" && stack_operand(0) && reg(5)) {
      node.store_slot = instruction.getOperand(3).getImm();
      node.store_register = mask(reg(5));
    }
    if (opcode == "MOV64rm" && instruction.getNumOperands() == 6 && reg(0) &&
        instruction.getOperand(2).isImm() &&
        instruction.getOperand(2).getImm() == 1 &&
        instruction.getOperand(3).isReg() && !reg(3) &&
        instruction.getOperand(4).isImm() && reg(5) &&
        llvm::StringRef(registers->getName(reg(5))) == "GS" &&
        (!reg(1) || llvm::StringRef(registers->getName(reg(1))) == "RIP")) {
      node.guard_register = mask(reg(0));
      node.guard = std::to_string(reg(1)) + ':' +
                   std::to_string(instruction.getOperand(4).getImm());
      unsigned guard_relocations = 0;
      bool guard_relocation_valid = true;
      for (auto field = relocations.lower_bound({site.section, site.offset});
           field != relocations.end() && field->first.first == site.section &&
           field->first.second < site.offset + size;
           ++field) {
        const auto &fixup = *field->second;
        ++guard_relocations;
        guard_relocation_valid &=
            fixup.offset == site.offset + size - 4 &&
            (fixup.type == R_X86_64_PC32 ||
             (!reg(1) &&
              (fixup.type == R_X86_64_32 || fixup.type == R_X86_64_32S))) &&
            symbols.count({fixup.symbol_table, fixup.symbol});
        node.guard += ':' + std::to_string(fixup.type) + ':' +
                      std::to_string(fixup.symbol_table) + ':' +
                      std::to_string(fixup.symbol) + ':' +
                      std::to_string(fixup.addend);
      }
      // Equal RIP displacements at different PCs do not identify one guard.
      // Relocated loads require the exact shared symbol/addend identity.
      if (!guard_relocation_valid || guard_relocations > 1 ||
          (reg(1) && guard_relocations != 1))
        node.guard.clear();
    }
    const bool zero = (opcode == "XOR32rr" || opcode == "XOR64rr") && reg(0) &&
                      reg(0) == reg(1) && reg(1) == reg(2);
    // INC/DEC and similar instructions preserve condition bits (e.g. CF).
    // Only these complete arithmetic flag definitions terminate flag liveness.
    if (!(opcode.starts_with("ADD") || opcode.starts_with("SUB") ||
          opcode.starts_with("CMP") || opcode.starts_with("TEST") ||
          opcode.starts_with("AND") || opcode.starts_with("OR") ||
          opcode.starts_with("XOR") || opcode == "POPF64"))
      node.kills &= ~(1U << 16);
    if (zero)
      node.reads &= ~mask(reg(0));
    if (zero) {
      node.constant_register = mask(reg(0));
      node.constant = 0;
    } else if ((opcode == "MOV32ri" || opcode == "MOV64ri" ||
                opcode == "MOV64ri32") &&
               reg(0) && instruction.getNumOperands() == 2 &&
               instruction.getOperand(1).isImm()) {
      node.constant_register = mask(reg(0));
      node.constant = uint64_t(instruction.getOperand(1).getImm());
      // A relocated immediate is an address, not this encoded zero/addend.
      const auto relocation =
          relocations.lower_bound({site.section, site.offset});
      if (relocation != relocations.end() &&
          relocation->first.first == site.section &&
          relocation->first.second < site.offset + size)
        node.constant.reset();
    }
    if ((opcode == "MOV64ri" || opcode == "MOV64ri32") && reg(0)) {
      auto field = relocations.lower_bound({site.section, site.offset});
      if (field != relocations.end() && field->first.first == site.section &&
          field->first.second < site.offset + size) {
        const auto &fixup = *field->second;
        const auto symbol = symbols.find({fixup.symbol_table, fixup.symbol});
        const auto next = std::next(field);
        const unsigned width = opcode == "MOV64ri" ? 8 : 4;
        if ((next == relocations.end() || next->first.first != site.section ||
             next->first.second >= site.offset + size) &&
            fixup.offset == site.offset + size - width &&
            fixup.type == (width == 8 ? R_X86_64_64 : R_X86_64_32S) &&
            symbol != symbols.end() && symbol->second->section &&
            symbol->second->section < image.sections.size()) {
          const __int128 offset =
              __int128(symbol->second->offset) + fixup.addend;
          if (offset >= 0 &&
              offset < image.sections[symbol->second->section].size) {
            node.address = {symbol->second->section, uint64_t(offset)};
            node.address_register = mask(reg(0));
          }
        }
      }
    }
    node.load = description.mayLoad();
    if ((opcode == "MOV32rm" || opcode == "MOV64rm") &&
        instruction.getNumOperands() == 6 && reg(1) == canonical[4] &&
        instruction.getOperand(2).isImm() &&
        instruction.getOperand(2).getImm() == 1 &&
        instruction.getOperand(3).isReg() && !reg(3) &&
        instruction.getOperand(4).isImm() &&
        instruction.getOperand(5).isReg() && !reg(5)) {
      node.stack_offset = instruction.getOperand(4).getImm();
      node.stack_bytes = opcode == "MOV32rm" ? 4 : 8;
    }
    node.pure_register = zero || opcode == "MOV64rr" || opcode == "MOV32rr" ||
                         opcode == "MOV32ri" || opcode == "MOV64ri" ||
                         opcode == "MOV64ri32" || opcode == "LEA64r" ||
                         opcode == "LEA32r";
    if (!source.sites[site.id].line && opcode.starts_with("NOOP"))
      source.sites[site.id].compiler_support = true;
    node.candidate = !source.sites[site.id].line && !description.mayStore() &&
                     !description.isCall() && !description.isBranch() &&
                     !description.isReturn() &&
                     !description.hasUnmodeledSideEffects() && node.writes &&
                     node.writes == node.kills && !(node.writes & (1U << 4));
    if (node.candidate && site.id < values.sites.size()) {
      for (const auto &binding : values.sites[site.id].bindings) {
        if (!binding.variable || binding.variable >= values.variables.size() ||
            !values.variables[binding.variable].global || !binding.recipe ||
            binding.recipe >= values.recipes.size())
          continue;
        // Fixed-register globals are observable storage beyond call arguments.
        // Their definitions are never merely compiler bookkeeping.
        for (const auto &operation :
             values.recipes[binding.recipe].operations) {
          uint64_t reg = UINT64_MAX;
          if (operation.opcode >= llvm::dwarf::DW_OP_reg0 &&
              operation.opcode <= llvm::dwarf::DW_OP_reg15)
            reg = operation.opcode - llvm::dwarf::DW_OP_reg0;
          else if (operation.opcode >= llvm::dwarf::DW_OP_breg0 &&
                   operation.opcode <= llvm::dwarf::DW_OP_breg15)
            reg = operation.opcode - llvm::dwarf::DW_OP_breg0;
          else if (operation.opcode == llvm::dwarf::DW_OP_regx ||
                   operation.opcode == llvm::dwarf::DW_OP_bregx)
            reg = operation.operand;
          if (reg < dwarf_registers.size() &&
              (node.writes & (1U << dwarf_registers[reg])))
            node.candidate = false;
        }
      }
    }
    const auto connect = [&](uint64_t offset) {
      const auto found = addresses.find({site.section, offset});
      if (found == addresses.end() || source.sites[found->second].function !=
                                          source.sites[site.id].function)
        node.frontier = true;
      else
        node.next.push_back(found->second);
    };
    node.returned = description.isReturn();
    if (description.isBranch()) {
      uint64_t destination = 0;
      bool known =
          analysis->evaluateBranch(instruction, site.offset, size, destination);
      for (auto relocation =
               relocations.lower_bound({site.section, site.offset});
           relocation != relocations.end() &&
           relocation->first.first == site.section &&
           relocation->first.second < site.offset + size;
           ++relocation) {
        const auto &fixup = *relocation->second;
        const auto symbol = symbols.find({fixup.symbol_table, fixup.symbol});
        known = false;
        if (symbol == symbols.end() ||
            (fixup.type != R_X86_64_PC32 && fixup.type != R_X86_64_PLT32) ||
            fixup.offset != site.offset + size - 4)
          continue;
        if (symbol->second->section == SHN_UNDEF &&
            symbol->second->name == "__x86_return_thunk" &&
            fixup.addend == -4 && description.isUnconditionalBranch())
          node.returned = true;
        const __int128 offset =
            __int128(symbol->second->offset) + fixup.addend + 4;
        if (symbol->second->section == site.section && offset >= 0 &&
            offset < section.size) {
          destination = uint64_t(offset);
          known = true;
        }
      }
      if (known && !node.returned)
        connect(destination);
      else if (!node.returned)
        node.frontier = true;
    }
    if (node.returned) {
      // Return preserves the callee-saved registers even without C references.
      node.reads |= (1U << 3) | (1U << 4) | (1U << 5) | (15U << 12);
      uint32_t return_registers = (1U << 0) | (1U << 2);
      const auto &matches = value_functions[source.sites[site.id].function];
      if (matches.size() == 1) {
        const auto function = *matches.begin();
        if (function && function < values.functions.size()) {
          const auto &description = values.functions[function];
          if (description.returns_void)
            return_registers = 0;
          else if (description.return_type &&
                   description.return_type < values.types.size()) {
            const auto &type = values.types[description.return_type].scalar;
            if (type.kind != CT_VALUE_UNKNOWN && type.kind != CT_VALUE_FLOAT &&
                type.bytes && type.bytes <= 8)
              return_registers = 1;
          }
        }
      }
      node.reads |= return_registers;
    } else if (!description.isBranch() || description.isConditionalBranch()) {
      connect(site.offset + size);
    }
    // The original line-zero edge connects already observed basic blocks.
    // Keep the branch and its scope events without inventing a C statement.
    if (!source.sites[site.id].line && description.isUnconditionalBranch() &&
        !node.returned && !node.frontier && node.next.size() == 1)
      source.sites[site.id].compiler_support = true;
    if (description.isCall()) {
      // Calls consume their proven scalar ABI inputs, and clobber volatile
      // registers. A missing signature is a frontier for value attribution.
      static constexpr std::array<unsigned, 6> argument_registers{7, 6, 2,
                                                                  1, 8, 9};
      bool signature = false;
      bool abi_known = false;
      auto &called = node.called;
      if (size >= 4 && opcode == "CALL64pcrel32") {
        const auto field =
            relocations.find({site.section, site.offset + size - 4});
        if (field != relocations.end()) {
          const auto &fixup = *field->second;
          const auto symbol = symbols.find({fixup.symbol_table, fixup.symbol});
          if (symbol != symbols.end() &&
              (fixup.type == R_X86_64_PC32 || fixup.type == R_X86_64_PLT32)) {
            if (symbol->second->section == SHN_UNDEF && fixup.addend == -4) {
              called = symbol->second->name;
              node.imported_call = true;
            } else if (symbol->second->section &&
                       symbol->second->section < image.sections.size()) {
              const __int128 offset =
                  __int128(symbol->second->offset) + fixup.addend + 4;
              std::set<std::string> callees;
              if (offset >= 0 &&
                  offset < image.sections[symbol->second->section].size)
                for (const auto &candidate : image.symbols)
                  if (candidate.section == symbol->second->section &&
                      candidate.offset == offset &&
                      candidate.type == STT_FUNC && !candidate.name.empty())
                    callees.insert(candidate.name);
              if (callees.size() == 1)
                called = *callees.begin();
              else if (!callees.empty()) {
                const auto line = source_row(site.id);
                if (line && source.lines[line].presentation)
                  for (const auto &contract :
                       source.lines[line].presentation->calls)
                    if (callees.count(contract.callee)) {
                      if (!called.empty() && called != contract.callee) {
                        called.clear();
                        break;
                      }
                      called = contract.callee;
                    }
              }
            }
          }
        }
      }
      const auto line = source_row(site.id);
      if (line && source.lines[line].presentation) {
        const auto &calls = source.lines[line].presentation->calls;
        abi_known =
            !called.empty() &&
            std::any_of(calls.begin(), calls.end(), [&](const auto &call) {
              return call.callee == called;
            });
        if (calls.size() == 1 && calls.front().callee == called &&
            !called.empty() && !calls.front().variadic &&
            calls.front().parameters.size() <= argument_registers.size()) {
          signature = true;
          for (size_t index = 0; index < calls.front().parameters.size();
               ++index) {
            const auto &type = calls.front().parameters[index].type;
            if (!type.bytes || type.bytes > 8 || type.kind == CT_VALUE_FLOAT ||
                type.kind == CT_VALUE_UNKNOWN) {
              signature = false;
              break;
            }
            node.reads |= 1U << argument_registers[index];
          }
        }
      }
      if (!signature) {
        // Arithmetic condition flags are call-clobbered, not ABI inputs.
        // Keep every GPR live when the actual argument contract is unknown.
        node.reads = abi_known
                         ? ((1U << 0) | (1U << 1) | (1U << 2) | (1U << 4) |
                            (1U << 6) | (1U << 7) | (15U << 8))
                         : (1U << 16) - 1;
        node.unknown_call = true;
      }
      const uint32_t volatile_registers = (1U << 0) | (1U << 1) | (1U << 2) |
                                          (1U << 6) | (1U << 7) | (15U << 8) |
                                          (1U << 16);
      node.writes |= volatile_registers;
      node.kills |= volatile_registers;
    }
    nodes.emplace(site.id, std::move(node));
  }
  for (auto &[id, node] : nodes)
    for (const auto next : node.next)
      if (const auto found = nodes.find(next); found != nodes.end())
        found->second.previous.push_back(id);
      else
        node.frontier = true;
  // Tail merging can give several identical source calls one line-zero machine
  // call. Keep their exact common C statement with an unknown line number,
  // after proving the callee, scalar contract and every file-global address.
  static constexpr std::array<unsigned, 6> argument_registers{7, 6, 2, 1, 8, 9};
  for (auto &[id, node] : nodes) {
    if (!node.call || node.called.empty() || source.sites[id].line)
      continue;
    uint32_t chosen = 0;
    bool ambiguous = false;
    std::string statement, declaration;
    std::vector<std::string> argument_objects;
    std::vector<uint32_t> candidates;
    for (uint32_t row = 1; row < source.lines.size(); ++row) {
      const auto &line = source.lines[row];
      if (!line.presentation ||
          line.presentation->expression.kind != CT_EXPRESSION_CALL ||
          line.presentation->call_results.size() != 1)
        continue;
      const auto &call = line.presentation->call_results.front();
      if (node.called != call.result.callee ||
          call.argument_addresses.empty() ||
          call.argument_addresses.size() > argument_registers.size() ||
          std::any_of(call.argument_addresses.begin(),
                      call.argument_addresses.end(),
                      [](const auto &name) { return name.empty(); }))
        continue;
      const auto old = source.sites[id].line;
      source.sites[id].line = row;
      const auto owned = source_row(id);
      source.sites[id].line = old;
      if (!owned)
        continue;
      const auto contract =
          std::find_if(line.presentation->calls.begin(),
                       line.presentation->calls.end(), [&](const auto &entry) {
                         return entry.callee == node.called &&
                                entry.function == call.function;
                       });
      if (contract == line.presentation->calls.end() || contract->variadic ||
          contract->parameters.size() != call.argument_addresses.size() ||
          std::any_of(contract->parameters.begin(), contract->parameters.end(),
                      [](const auto &parameter) {
                        return parameter.type.kind != CT_VALUE_POINTER ||
                               parameter.type.bytes != 8;
                      }))
        continue;
      if (chosen &&
          (statement != line.text || declaration != contract->declaration ||
           argument_objects != call.argument_addresses ||
           source.lines[chosen].file != line.file))
        ambiguous = true;
      chosen = row;
      statement = line.text;
      declaration = contract->declaration;
      argument_objects = call.argument_addresses;
      candidates.push_back(row);
    }
    if (!chosen || ambiguous)
      continue;
    bool proved = true;
    for (size_t argument = 0; argument < argument_objects.size() && proved;
         ++argument) {
      std::optional<std::pair<uint32_t, uint64_t>> expected;
      for (const auto &symbol : image.symbols)
        if (symbol.name == argument_objects[argument] &&
            symbol.type == STT_OBJECT && symbol.section &&
            symbol.section < image.sections.size()) {
          const auto address = std::make_pair(symbol.section, symbol.offset);
          if (expected && expected != address)
            proved = false;
          expected = address;
        }
      bool declared = false;
      if (expected && id < values.sites.size())
        for (const auto &binding : values.sites[id].bindings) {
          if (!binding.variable ||
              binding.variable >= values.variables.size() ||
              !values.variables[binding.variable].global || !binding.recipe ||
              binding.recipe >= values.recipes.size())
            continue;
          const auto &recipe = values.recipes[binding.recipe];
          declared |=
              recipe.error.empty() && recipe.operations.size() == 1 &&
              recipe.operations.front().opcode == llvm::dwarf::DW_OP_addr &&
              std::make_pair(recipe.operations.front().section,
                             recipe.operations.front().operand) == *expected;
        }
      if (!declared) {
        proved = false;
        break;
      }
      const uint32_t wanted = 1U << argument_registers[argument];
      std::vector<uint64_t> pending = node.previous;
      std::set<uint64_t> visited;
      if (pending.empty())
        proved = false;
      while (!pending.empty() && proved) {
        const auto current = pending.back();
        pending.pop_back();
        if (!visited.insert(current).second)
          continue;
        const auto &definition = nodes.at(current);
        if (definition.writes & wanted) {
          proved = definition.address &&
                   definition.address_register == wanted &&
                   definition.address == expected;
          continue;
        }
        if (definition.previous.empty() || definition.call) {
          proved = false;
          break;
        }
        pending.insert(pending.end(), definition.previous.begin(),
                       definition.previous.end());
      }
      if (!pending.empty())
        proved = false;
    }
    if (!proved)
      continue;
    if (candidates.size() > 1) {
      auto common = source.lines[chosen];
      common.line = 0;
      chosen = source.lines.size();
      source.lines.push_back(std::move(common));
    }
    source.sites[id].line = chosen;
    source.sites[id].statement = false;
    node.unknown_call = false;
    node.reads = 1U << 4;
    for (size_t index = 0; index < argument_objects.size(); ++index)
      node.reads |= 1U << argument_registers[index];
  }
  std::map<uint64_t, int64_t> protected_stack;
  // Recognize the complete compiler stack-protector sequence, not its imported
  // function name alone: a prologue saves the same GS guard into an allocated
  // local slot; every predecessor of the failure call tests that slot with
  // CMP/JNE. All paths between save and comparison preserve the allocated SP.
  for (auto &[id, failure] : nodes) {
    if (source.sites[id].line || !failure.imported_call ||
        failure.called != "__stack_chk_fail" || failure.previous.empty())
      continue;
    bool valid = true;
    std::map<uint64_t, int64_t> proved;
    for (const auto branch_id : failure.previous) {
      const auto &branch = nodes.at(branch_id);
      if (!branch.not_equal || branch.previous.size() != 1 ||
          branch.next.size() != 2 ||
          branch.site->offset + branch.site->original_size ==
              failure.site->offset) {
        valid = false;
        break;
      }
      const auto &compare = nodes.at(branch.previous.front());
      if (!compare.guard_slot || compare.previous.size() != 1) {
        valid = false;
        break;
      }
      const auto &guard = nodes.at(compare.previous.front());
      if (guard.guard.empty() ||
          guard.guard_register != compare.compared_register) {
        valid = false;
        break;
      }
      const auto function = source.sites[id].function;
      if (!function || function >= source.functions.size() ||
          source.functions[function].ranges.size() != 1) {
        valid = false;
        break;
      }
      const auto &range = source.functions[function].ranges.front();
      auto entry = addresses.lower_bound({range.section, range.begin});
      if (entry == addresses.end() || entry->first.first != range.section ||
          entry->first.second >= range.end) {
        valid = false;
        break;
      }
      const auto prefix = entry->first.second - range.begin;
      const auto *bytes = image.bytes.data() +
                          image.sections[range.section].offset + range.begin;
      if (prefix && (prefix != 4 || bytes[0] != 0xf3 || bytes[1] != 0x0f ||
                     bytes[2] != 0x1e || bytes[3] != 0xfa)) {
        valid = false;
        break;
      }
      uint64_t cursor = entry->second, save = 0;
      int64_t sp = 0, saved_sp = 0;
      uint32_t live_guard = 0;
      std::set<uint64_t> prefix_nodes;
      while (nodes.count(cursor) &&

             prefix_nodes.insert(cursor).second) {
        const auto &part = nodes.at(cursor);
        if (part.store_slot == compare.guard_slot && live_guard &&
            part.store_register == live_guard && sp < 0 &&
            *part.store_slot >= 0 &&
            __int128(*part.store_slot) + 8 <= -__int128(sp)) {
          save = cursor;
          saved_sp = sp;
          break;
        }
        live_guard &= ~part.writes;
        if (part.guard == guard.guard)
          live_guard = part.guard_register;
        if (part.call || !part.stack_adjust || part.next.size() != 1 ||
            part.frontier)
          break;
        const __int128 after = __int128(sp) + *part.stack_adjust;
        if (after < INT64_MIN || after > 0)
          break;
        sp = int64_t(after);
        cursor = part.next.front();
      }
      if (!save) {
        valid = false;
        break;
      }
      std::vector<uint64_t> pending{branch.previous.front()};
      std::set<uint64_t> visited;
      while (!pending.empty() && valid) {
        const auto current = pending.back();
        pending.pop_back();
        if (current == save || !visited.insert(current).second)
          continue;
        const auto &part = nodes.at(current);
        if (!part.stack_adjust || *part.stack_adjust || part.previous.empty()) {
          valid = false;
          break;
        }
        pending.insert(pending.end(), part.previous.begin(),
                       part.previous.end());
      }
      if (!pending.empty())
        valid = false;
      if (valid)
        for (const auto site : visited)
          proved.emplace(site, saved_sp);
    }
    if (!valid)
      continue;
    source.sites[id].compiler_support = true;
    failure.reads = 1U << 4;
    failure.kills = failure.writes = (1U << 17) - 1;
    failure.unknown_call = false;
    failure.frontier = false;
    failure.next.clear();
    protected_stack.insert(proved.begin(), proved.end());
  }
  // The optimizer can emit a source constant assignment with line zero. Its
  // exact destination location and declared value identify the C statement;
  // adjacency to an unrelated line does not.
  for (auto &[id, node] : nodes) {
    if (!node.candidate || !node.constant || node.next.size() != 1 ||
        node.next.front() >= values.sites.size())
      continue;
    uint32_t row = 0;
    bool conflict = false;
    for (const auto &binding : values.sites[node.next.front()].bindings) {
      if (!binding.variable || binding.variable >= values.variables.size() ||
          !binding.recipe || binding.recipe >= values.recipes.size())
        continue;
      const auto &variable = values.variables[binding.variable];
      if (variable.global || !variable.type ||
          variable.type >= values.types.size())
        continue;
      // AST spelling alone cannot distinguish shadowed lexical variables.
      // Repeated instances of the same abstract declaration are harmless.
      if (std::any_of(values.variables.begin(), values.variables.end(),
                      [&](const auto &other) {
                        return other.name == variable.name &&
                               (other.global ||
                                other.owner == variable.owner) &&
                               (other.unit != variable.unit ||
                                other.die != variable.die);
                      }))
        continue;
      const auto &type = values.types[variable.type];
      if (type.guarded || !type.scalar.bytes || type.scalar.bytes > 8 ||
          (type.scalar.kind != CT_VALUE_SIGNED &&
           type.scalar.kind != CT_VALUE_UNSIGNED &&
           type.scalar.kind != CT_VALUE_BOOLEAN))
        continue;
      const auto &recipe = values.recipes[binding.recipe];
      if (!recipe.error.empty() || recipe.operations.size() != 1)
        continue;
      const auto &operation = recipe.operations.front();
      uint64_t reg = UINT64_MAX;
      if (operation.opcode >= llvm::dwarf::DW_OP_reg0 &&
          operation.opcode <= llvm::dwarf::DW_OP_reg15)
        reg = operation.opcode - llvm::dwarf::DW_OP_reg0;
      else if (operation.opcode == llvm::dwarf::DW_OP_regx)
        reg = operation.operand;
      if (reg >= dwarf_registers.size() ||
          (1U << dwarf_registers[reg]) != node.constant_register)
        continue;
      const auto bits = type.scalar.bytes * 8;
      const uint64_t truncate =
          bits == 64 ? UINT64_MAX : (uint64_t(1) << bits) - 1;
      for (uint32_t line = 1; line < source.lines.size(); ++line) {
        const auto &presentation = source.lines[line].presentation;
        if (!presentation)
          continue;
        const auto &expression = presentation->expression;
        if (expression.constant && expression.assignment == variable.name &&
            expression.function == variable.owner &&
            (expression.constant_value & truncate) ==
                (*node.constant & truncate)) {
          if (row && row != line)
            conflict = true;
          row = line;
        }
      }
    }
    if (row && !conflict) {
      source.sites[id].line = row;
      source.sites[id].statement = false;
    }
  }
  // Several moves can intervene before the next source instruction. Resolve
  // only when every live use establishes the same already-authenticated row.
  const auto owned_row = [&](uint64_t producer, uint64_t consumer,
                             uint32_t row) {
    if (!row)
      return uint32_t(0);
    auto &site = source.sites[producer];
    const auto saved = site.line;
    site.line = row;
    auto selected = source_row(producer);
    if (!selected) {
      // Argument preparation may precede the inline body range. Its consumer
      // still proves the exact caller expression through the DWARF call row.
      for (auto block = source.sites[consumer].blocks.rbegin();
           block != source.sites[consumer].blocks.rend() && !selected;
           ++block) {
        if (!*block || *block >= source.blocks.size() ||
            source.blocks[*block].kind !=
                ct_kernel_source_block_kind::inline_function)
          continue;
        site.line = source.blocks[*block].call_line;
        selected = source_row(producer);
      }
    }
    site.line = saved;
    return selected;
  };
  bool changed = true;
  std::map<uint64_t, std::map<uint64_t, ct_kernel_stack_location>> stack_proofs;
  while (changed) {
    changed = false;
    for (auto &[id, node] : nodes) {
      if (!node.candidate || source.sites[id].line ||
          source.sites[id].compiler_support)
        continue;
      uint32_t row = 0;
      bool conflict = node.frontier, multiple_rows = false;
      std::vector<std::pair<uint64_t, uint32_t>> pending;
      for (const auto next : node.next)
        pending.emplace_back(next, node.writes);
      std::set<std::pair<uint64_t, uint32_t>> seen;
      while (!pending.empty() && !conflict) {
        const auto current = pending.back();
        pending.pop_back();
        if (!current.second || !seen.insert(current).second)
          continue;
        const auto found = nodes.find(current.first);
        if (found == nodes.end()) {
          conflict = true;
          break;
        }
        const auto &use = found->second;
        auto live = current.second;
        const auto used = use.dead ? 0 : live & use.reads;
        if (used) {
          const auto selected =
              owned_row(id, current.first, source_row(current.first));
          if (use.unknown_call || !selected) {
            conflict = true;
            break;
          }
          multiple_rows |= row && row != selected;
          row = selected;
          // A source row accounts for the value. Further uses can belong to
          // later C statements and do not redefine its initial attribution.
          live &= ~used;
        }
        if (live & use.writes & ~use.kills)
          conflict = true;
        live &= ~use.kills;
        if (live && use.frontier)
          conflict = true;
        for (const auto next : use.next)
          pending.emplace_back(next, live);
      }
      if (!pending.empty())
        conflict = true;
      if (multiple_rows && (!node.pure_register || node.load))
        conflict = true;
      bool return_support = false;
      if (!conflict && row &&
          source.lines[row].text.find('}') != std::string::npos &&
          source.lines[row].text.find_first_not_of(" \t\r\n}") ==
              std::string::npos) {
        uint32_t returned_row = 0;
        bool ambiguous = false;
        if (node.constant)
          for (uint32_t line = 1; line < source.lines.size(); ++line) {
            const auto &presentation = source.lines[line].presentation;
            if (!presentation)
              continue;
            const auto &expression = presentation->expression;
            const auto bytes = expression.constant_type.bytes;
            if (!expression.constant || !bytes || bytes > 8 ||
                expression.constant_type.kind == CT_VALUE_FLOAT)
              continue;
            const uint64_t bits =
                bytes == 8 ? UINT64_MAX : (uint64_t(1) << (bytes * 8)) - 1;
            if ((expression.constant_value & bits) != (*node.constant & bits))
              continue;
            const auto saved = source.sites[id].line;
            source.sites[id].line = line;
            const auto selected = source_row(id);
            source.sites[id].line = saved;
            if (selected) {
              // A same-valued assignment in this scope can feed a later
              // `return variable`. Constant equality cannot choose a distinct
              // early-return statement instead of that assignment.
              if (expression.kind != CT_EXPRESSION_RETURN)
                ambiguous = true;
              else {
                ambiguous |= returned_row && returned_row != line;
                returned_row = line;
              }
            }
          }
        if (returned_row && !ambiguous)
          row = returned_row;
        else if (node.pure_register && !node.load)
          return_support = true;
      }
      bool local_read = false;
      if (!conflict && !row && node.stack_offset && *node.stack_offset >= 0 &&
          id < values.sites.size()) {
        const auto function_id = source.sites[id].function;
        auto [proof, fresh] = stack_proofs.try_emplace(function_id);
        if (fresh && function_id && function_id < source.functions.size()) {
          const auto &function = source.functions[function_id];
          // Multiple disconnected extents need a joint CFG proof. Do not
          // treat a cold extent as a fresh stack at offset zero.
          if (function.ranges.size() == 1) {
            const auto &range = function.ranges.front();
            std::vector<ct_kernel_flow_region> regions;
            std::vector<ct_kernel_stack_location> stack;
            std::string reason;
            if (ct_kernel_source_flow(image, sites, range.section, range.begin,
                                      range.end, regions, reason, &stack))
              for (const auto &location : stack)
                proof->second.emplace(location.probe, location);
          }
        }
        const auto location = proof->second.find(id);
        std::optional<int64_t> rsp;
        if (location != proof->second.end() && location->second.rsp_known)
          rsp = location->second.rsp_offset;
        else if (const auto protected_location = protected_stack.find(id);
                 protected_location != protected_stack.end())
          rsp = protected_location->second;
        if (rsp && *rsp <= 0 &&
            __int128(*node.stack_offset) + node.stack_bytes <=
                -__int128(*rsp)) {
          const auto &site = values.sites[id];
          auto bindings = site.bindings;
          if (node.next.size() == 1 && node.next.front() < values.sites.size())
            for (const auto &binding :
                 values.sites[node.next.front()].bindings) {
              if (!binding.variable ||
                  binding.variable >= values.variables.size() ||
                  !binding.recipe || binding.recipe >= values.recipes.size())
                continue;
              const auto &variable = values.variables[binding.variable];
              const auto &recipe = values.recipes[binding.recipe];
              if (variable.global || variable.scope != variable.function ||
                  !recipe.error.empty() || recipe.operations.size() != 1)
                continue;
              const auto &operation = recipe.operations.front();
              const auto reg =
                  operation.opcode >= llvm::dwarf::DW_OP_reg0 &&
                          operation.opcode <= llvm::dwarf::DW_OP_reg15
                      ? uint64_t(operation.opcode - llvm::dwarf::DW_OP_reg0)
                  : operation.opcode == llvm::dwarf::DW_OP_regx
                      ? operation.operand
                      : UINT64_MAX;
              if (reg >= dwarf_registers.size() ||
                  (1U << dwarf_registers[reg]) != node.writes)
                continue;
              // Optimized debug locations can have a hole before a final
              // load and resume in its destination register. Recover only
              // the same whole-function local's proven stack slot, not its
              // old value. The actual instruction still performs the read.
              for (const auto &[previous, state] : nodes) {
                if (state.site->section != node.site->section ||
                    state.site->offset >= node.site->offset ||
                    source.sites[previous].function != function_id ||
                    previous >= values.sites.size() ||
                    !protected_stack.count(previous) ||
                    protected_stack.at(previous) != *rsp)
                  continue;
                for (const auto &old : values.sites[previous].bindings)
                  if (old.variable == binding.variable && old.recipe &&
                      old.recipe < values.recipes.size() &&
                      values.recipes[old.recipe].error.empty() &&
                      values.recipes[old.recipe].operations.size() == 1 &&
                      values.recipes[old.recipe].operations.front().opcode ==
                          llvm::dwarf::DW_OP_breg7 &&
                      int64_t(values.recipes[old.recipe]
                                  .operations.front()
                                  .operand) == *node.stack_offset)
                    bindings.push_back(old);
              }
            }
          for (const auto &binding : bindings) {
            if (!binding.variable ||
                binding.variable >= values.variables.size() ||
                !binding.recipe || binding.recipe >= values.recipes.size())
              continue;
            const auto &variable = values.variables[binding.variable];
            if (variable.global || !variable.type ||
                variable.type >= values.types.size())
              continue;
            const auto &type = values.types[variable.type];
            const auto &recipe = values.recipes[binding.recipe];
            if (type.guarded || type.scalar.bytes != node.stack_bytes ||
                type.scalar.kind == CT_VALUE_UNKNOWN || !recipe.error.empty() ||
                recipe.operations.size() != 1)
              continue;
            const auto &operation = recipe.operations.front();
            if (operation.opcode == llvm::dwarf::DW_OP_breg7 &&
                int64_t(operation.operand) == *node.stack_offset)
              local_read = true;
            if (operation.opcode == llvm::dwarf::DW_OP_fbreg &&
                int64_t(operation.operand) == *node.stack_offset &&
                site.frame_recipe &&
                site.frame_recipe < values.recipes.size()) {
              const auto &frame = values.recipes[site.frame_recipe];
              local_read |=
                  frame.error.empty() && frame.operations.size() == 1 &&
                  frame.operations.front().opcode == llvm::dwarf::DW_OP_reg7;
            }
          }
        }
      }
      if (!conflict && (return_support ||
                        (multiple_rows && node.pure_register && !node.load))) {
        source.sites[id].compiler_support = true;
        changed = true;
      } else if (!conflict && !row &&
                 ((node.pure_register && !node.load) || local_read) &&
                 !node.next.empty()) {
        source.sites[id].compiler_support = true;
        node.dead = node.pure_register && !node.load;
        changed = true;
      } else if (!conflict && row) {
        source.sites[id].line = row;
        source.sites[id].statement = false;
        source.sites[id].column = 0;
        changed = true;
      }
    }
  }
  // A cached address/register copy can be hoisted above another C statement.
  // Showing its later call/return here would announce that operation before
  // the intervening statement. Its actual C row still owns the operation,
  // while this register-only preparation remains observed bookkeeping.
  for (auto &[id, node] : nodes) {
    const auto row = source_row(id);
    if (!node.candidate || !node.pure_register || node.load || !row ||
        !source.lines[row].presentation ||
        (source.lines[row].presentation->call_results.empty() &&
         source.lines[row].presentation->expression.kind !=
             CT_EXPRESSION_RETURN))
      continue;
    if (source.lines[row].presentation->expression.kind ==
        CT_EXPRESSION_RETURN) {
      // Keep the only recovered return statement. Suppression requires a
      // native DWARF row in the same function and execution scope to display
      // that exact statement later.
      const bool survives =
          std::any_of(nodes.begin(), nodes.end(), [&](const auto &entry) {
            const auto &[other, original] = entry;
            return !original.originally_unmapped &&
                   source.sites[other].function == source.sites[id].function &&
                   source.sites[other].blocks == source.sites[id].blocks &&
                   source_row(other) == row;
          });
      if (!survives)
        continue;
    }
    bool interleaved = false, incomplete = false;
    std::vector<std::pair<uint64_t, uint32_t>> pending;
    for (const auto next : node.next)
      pending.emplace_back(next, node.writes);
    std::set<std::pair<uint64_t, uint32_t>> seen;
    while (!pending.empty() && !interleaved && !incomplete) {
      const auto current = pending.back();
      pending.pop_back();
      if (!current.second || !seen.insert(current).second)
        continue;
      const auto found = nodes.find(current.first);
      if (found == nodes.end()) {
        incomplete = true;
        break;
      }
      const auto &use = found->second;
      const auto consumed = use.dead ? 0 : current.second & use.reads;
      const auto visible = source_row(current.first);
      if (visible == row)
        continue;
      const bool closing =
          visible && source.lines[visible].presentation &&
          source.lines[visible].presentation->structural &&
          source.lines[visible].text.find('}') != std::string::npos &&
          source.lines[visible].text.find_first_not_of(" \t\r\n}") ==
              std::string::npos;
      interleaved = !consumed && visible && !closing;
      const auto live = current.second & ~consumed & ~use.kills;
      incomplete |=
          bool(live & use.writes & ~use.kills) || (live && use.frontier);
      for (const auto next : use.next)
        pending.emplace_back(next, live);
    }
    if (interleaved && !incomplete) {
      source.sites[id].line = 0;
      source.sites[id].compiler_support = true;
    }
  }
  // A condition eliminated to an unconditional edge can still be proven from
  // its exact DWARF constant location. Never use an old register/memory value
  // or a global initialized value to infer the branch outcome.
  for (const auto &[id, node] : nodes) {
    const auto row = source_row(id);
    if (!row || node.call || node.returned || node.frontier ||
        node.next.size() != 1 ||
        node.site->offset + node.site->original_size ==
            nodes.at(node.next.front()).site->offset ||
        source.sites[id].not_taken_successor ||
        !source.lines[row].presentation || id >= values.sites.size())
      continue;
    const auto &expression = source.lines[row].presentation->expression;
    const auto &comparison = expression.comparison;
    if (expression.kind != CT_EXPRESSION_NONE ||
        comparison.kind == CT_SOURCE_COMPARE_NONE || comparison.types.empty())
      continue;
    const ct_kernel_value_binding *selected = nullptr;
    uint32_t depth = 0;
    bool ambiguous = false;
    for (const auto &binding : values.sites[id].bindings) {
      if (!binding.variable || binding.variable >= values.variables.size())
        continue;
      const auto &variable = values.variables[binding.variable];
      if (variable.global || variable.name != comparison.variable ||
          variable.owner != expression.function)
        continue;
      if (!selected || variable.depth > depth) {
        selected = &binding;
        depth = variable.depth;
        ambiguous = false;
      } else if (variable.depth == depth && variable.id != selected->variable) {
        ambiguous = true;
      }
    }
    if (!selected || ambiguous || !selected->recipe ||
        selected->recipe >= values.recipes.size())
      continue;
    const auto &recipe = values.recipes[selected->recipe];
    if (!recipe.error.empty() || recipe.operations.size() != 2 ||
        recipe.operations.back().opcode != llvm::dwarf::DW_OP_stack_value)
      continue;
    const auto opcode = recipe.operations.front().opcode;
    if (!((opcode >= llvm::dwarf::DW_OP_lit0 &&
           opcode <= llvm::dwarf::DW_OP_lit31) ||
          (opcode >= llvm::dwarf::DW_OP_const1u &&
           opcode <= llvm::dwarf::DW_OP_consts)))
      continue;
    ct_kernel_observation event;
    event.size = sizeof(kctrace_event);
    event.site_id = id;
    ct_kernel_value_result observed;
    if (!ct_kernel_evaluate_value(values, *selected, event, observed) ||
        !observed.size || observed.size > sizeof(uint64_t))
      continue;
    uint64_t value = 0;
    std::memcpy(&value, observed.bytes.data(), observed.size);
    const auto &type = values.types[values.variables[selected->variable].type];
    const auto outcome =
        ct_source_compare_value(comparison, type.scalar, value);
    if (outcome && !*outcome)
      source.sites[id].not_taken_successor = node.next.front();
  }
  // A missing line row inside one straight basic block does not leave the
  // surrounding source scopes. Retain only the common, already-proven path
  // of both endpoints; do not infer an inline frame or cross another entry.
  std::map<uint64_t, std::vector<uint64_t>> retained_scopes;
  const auto straight = [&](const Node &before, const Node &after,
                            bool returned_call = false) {
    return (!before.call || returned_call) && !before.returned &&
           !before.frontier && before.next.size() == 1 &&
           after.previous.size() == 1 &&
           before.next.front() == after.site->id &&
           after.previous.front() == before.site->id &&
           before.site->section == after.site->section &&
           before.site->offset + before.site->original_size ==
               after.site->offset &&
           source.sites[before.site->id].function ==
               source.sites[after.site->id].function;
  };
  for (const auto &[id, node] : nodes) {
    if (!node.originally_unmapped || !source.sites[id].blocks.empty() ||
        node.previous.size() != 1)
      continue;
    const auto &before = nodes.at(node.previous.front());
    const auto &prefix = source.sites[before.site->id].blocks;
    // A scope resumes at an actual call's normal continuation. Executing that
    // instruction proves return; this transfers no call-clobbered values.
    if (prefix.empty() || !straight(before, node, true))
      continue;
    std::vector<uint64_t> gap;
    const Node *after = &node;
    while (after->originally_unmapped &&
           source.sites[after->site->id].blocks.empty()) {
      gap.push_back(after->site->id);
      if (after->next.size() != 1) {
        after = nullptr;
        break;
      }
      const auto next = nodes.find(after->next.front());
      if (next == nodes.end() || !straight(*after, next->second)) {
        after = nullptr;
        break;
      }
      after = &next->second;
    }
    if (!after)
      continue;
    const auto &following = source.sites[after->site->id].blocks;
    size_t common = 0;
    while (common < prefix.size() && common < following.size() &&
           prefix[common] == following[common] &&
           source.blocks[prefix[common]].kind !=
               ct_kernel_source_block_kind::inline_function)
      ++common;
    if (!common)
      continue;
    for (const auto missing : gap)
      retained_scopes.emplace(
          missing,
          std::vector<uint64_t>(prefix.begin(), prefix.begin() + common));
  }
  // Publish only after all bounded searches succeed. These ranges fill real
  // instruction gaps and never connect disjoint addresses by an envelope.
  std::set<uint64_t> changed_scopes;
  for (auto &[id, blocks] : retained_scopes) {
    const auto &site = *nodes.at(id).site;
    for (const auto block : blocks) {
      source.blocks[block].ranges.push_back(
          {site.section, site.offset, site.offset + site.original_size});
      changed_scopes.insert(block);
    }
    source.sites[id].blocks = std::move(blocks);
  }
  for (const auto block : changed_scopes) {
    auto &ranges = source.blocks[block].ranges;
    std::sort(ranges.begin(), ranges.end(), [](const auto &a, const auto &b) {
      return std::tie(a.section, a.begin, a.end) <
             std::tie(b.section, b.begin, b.end);
    });
    size_t used = 0;
    for (const auto &range : ranges) {
      if (used && ranges[used - 1].section == range.section &&
          range.begin <= ranges[used - 1].end)
        ranges[used - 1].end = std::max(ranges[used - 1].end, range.end);
      else
        ranges[used++] = range;
    }
    ranges.resize(used);
  }
  return true;
}
