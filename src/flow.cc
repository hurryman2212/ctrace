// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <llvm/ADT/EquivalenceClasses.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include "analysis.hh"
#include "analysis_protocol.hh"
#include "flow.hh"

struct FlowDecoder {
  llvm::Triple triple{"x86_64-pc-linux-gnu"};
  std::unique_ptr<llvm::MCRegisterInfo> registers;
  std::unique_ptr<llvm::MCAsmInfo> info;
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget;
  std::unique_ptr<llvm::MCInstrInfo> instructions;
  std::unique_ptr<llvm::MCContext> context;
  std::unique_ptr<llvm::MCDisassembler> decoder;
  std::unique_ptr<llvm::MCInstrAnalysis> analysis;

  FlowDecoder() {
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetDisassembler();
    std::string error;
    const auto *target =
        llvm::TargetRegistry::lookupTarget(triple.str(), error);
    if (!target)
      return;
    registers.reset(target->createMCRegInfo(triple.str()));
    if (!registers)
      return;
    llvm::MCTargetOptions options;
    info.reset(target->createMCAsmInfo(*registers, triple.str(), options));
    subtarget.reset(target->createMCSubtargetInfo(triple.str(), "generic", ""));
    instructions.reset(target->createMCInstrInfo());
    if (!info || !subtarget || !instructions)
      return;
    context = std::make_unique<llvm::MCContext>(
        triple, info.get(), registers.get(), subtarget.get());
    decoder.reset(target->createMCDisassembler(*subtarget, *context));
    analysis.reset(target->createMCInstrAnalysis(instructions.get()));
  }
};

static FlowDecoder &flow_decoder() {
  static FlowDecoder state;
  return state;
}

bool ct_decode_code_range(
    llvm::ArrayRef<unsigned char> bytes, uint64_t offset,
    std::vector<ct_decompiled_instruction> &instructions) {
  instructions.clear();
  if (bytes.empty() || bytes.size() > UINT64_MAX - offset)
    return false;
  FlowDecoder &state = flow_decoder();
  if (!state.decoder || !state.instructions)
    return false;
  size_t position = 0;
  while (position < bytes.size()) {
    if (instructions.size() == UINT32_MAX)
      return false;
    llvm::MCInst instruction;
    uint64_t size = 0;
    bool decoded = false;
    while (size < bytes.size() - position && size < 15) {
      uint64_t part = 0;
      if (state.decoder->getInstruction(
              instruction, part, bytes.drop_front(position + size),
              offset + position + size,
              llvm::nulls()) != llvm::MCDisassembler::Success ||
          !part || part > bytes.size() - position - size || part > 15 - size)
        break;
      size += part;
      if (!state.instructions->getName(instruction.getOpcode())
               .ends_with("_PREFIX")) {
        decoded = true;
        break;
      }
    }
    if (!decoded)
      return false;
    ct_decompiled_instruction original{};
    original.offset = offset + position;
    original.size = static_cast<uint8_t>(size);
    std::memcpy(original.bytes, bytes.data() + position, size);
    instructions.push_back(original);
    position += size;
  }
  return true;
}

bool ct_build_code_proof(
    uint64_t function_offset, uint32_t loaded_level,
    const std::vector<ct_decompiled_range> &ranges,
    const std::vector<ct_decompiled_instruction> &instructions,
    std::vector<unsigned char> &proof) {
  proof.clear();
  if (ranges.size() > UINT32_MAX || instructions.size() > UINT32_MAX ||
      loaded_level > CT_DECOMPILE_FULL)
    return false;
  ct_decompiled_proof_header header;
  std::memset(&header, 0, sizeof(header));
  header.function_offset = function_offset;
  header.range_count = ranges.size();
  header.instruction_count = instructions.size();
  const size_t size = sizeof(header) + ranges.size() * sizeof(ranges[0]) +
                      instructions.size() * sizeof(instructions[0]);
  proof.resize(size);
  std::memcpy(proof.data(), &header, sizeof(header));
  size_t position = sizeof(header);
  if (!ranges.empty())
    std::memcpy(proof.data() + position, ranges.data(),
                ranges.size() * sizeof(ranges[0]));
  position += ranges.size() * sizeof(ranges[0]);
  if (!instructions.empty())
    std::memcpy(proof.data() + position, instructions.data(),
                instructions.size() * sizeof(instructions[0]));
  // The byte identity does not depend on the consumer's information level.
  const auto digest = llvm::SHA256::hash(proof);
  const char hexadecimal[] = "0123456789abcdef";
  for (size_t index = 0; index < digest.size(); ++index) {
    header.code_identity[index * 2] = hexadecimal[digest[index] >> 4];
    header.code_identity[index * 2 + 1] = hexadecimal[digest[index] & 15];
  }
  header.loaded_level = loaded_level;
  std::memcpy(proof.data(), &header, sizeof(header));
  if (!ct_decompiled_proof_valid(proof.data(), proof.size())) {
    proof.clear();
    return false;
  }
  return true;
}

struct FlowNode {
  uint64_t size = 0;
  std::vector<uint64_t> successors;
  std::vector<uint64_t> code_successors;
  bool conditional = false;
  llvm::MCInst instruction;
};

struct FlowSwitch {
  ct_flow_switch region{};
  std::vector<uint64_t> path;
  std::vector<uint64_t> bootstrap;
};

enum class FlowStorageKind { Comparison, Update, Initializer };

// Compare exact-width architectural storage, including all memory-address
// components. RIP-relative displacements are normalized to their target VA.
// A register merely holding a loaded memory value is deliberately not an alias.
static std::vector<std::vector<uint64_t>>
flow_storage(const FlowDecoder &decoder, const FlowNode &node, uint64_t pc,
             FlowStorageKind kind) {
  const auto &instruction = node.instruction;
  auto name = decoder.instructions->getName(instruction.getOpcode());
  const bool update = kind == FlowStorageKind::Update;
  const bool initializer = kind == FlowStorageKind::Initializer;
  const bool unary = name.starts_with("INC") || name.starts_with("DEC");
  if (initializer ? !name.starts_with("MOV")
      : update ? !(unary || name.starts_with("ADD") || name.starts_with("SUB"))
               : !(name.starts_with("CMP") || name.starts_with("TEST")))
    return {};
  name = name.drop_front(name.starts_with("TEST") ? 4 : 3);
  unsigned width = 0;
  while (!name.empty() && name.front() >= '0' && name.front() <= '9') {
    width = width * 10 + name.front() - '0';
    name = name.drop_front();
  }
  if (width != 8 && width != 16 && width != 32 && width != 64)
    return {};
  if (initializer &&
      (!(name.starts_with("ri") || name.starts_with("mi")) ||
       instruction.getNumOperands() == 0 ||
       !instruction.getOperand(instruction.getNumOperands() - 1).isImm()))
    return {};
  if (update && !unary &&
      (instruction.getNumOperands() == 0 ||
       !instruction.getOperand(instruction.getNumOperands() - 1).isImm() ||
       instruction.getOperand(instruction.getNumOperands() - 1).getImm() == 0))
    return {};
  std::vector<std::vector<uint64_t>> storage;
  auto add_register = [&](unsigned index) {
    if (index < instruction.getNumOperands() &&
        instruction.getOperand(index).isReg())
      storage.push_back({width, 0, instruction.getOperand(index).getReg()});
  };
  auto add_memory = [&](unsigned index) {
    if (index + 4 >= instruction.getNumOperands())
      return;
    const auto &base = instruction.getOperand(index);
    const auto &scale = instruction.getOperand(index + 1);
    const auto &subscript = instruction.getOperand(index + 2);
    const auto &displacement = instruction.getOperand(index + 3);
    const auto &segment = instruction.getOperand(index + 4);
    if (!base.isReg() || !scale.isImm() || !subscript.isReg() ||
        !displacement.isImm() || !segment.isReg())
      return;
    uint64_t base_register = base.getReg();
    uint64_t offset = displacement.getImm();
    if (base_register &&
        llvm::StringRef(decoder.registers->getName(base_register)) == "RIP") {
      base_register = 0;
      offset += pc + node.size;
    }
    storage.push_back({width, 1, base_register,
                       static_cast<uint64_t>(scale.getImm()),
                       subscript.getReg(), offset, segment.getReg()});
  };
  if (name == "r" || name.starts_with("ri")) {
    add_register(0);
  } else if (name == "rr" && !update) {
    add_register(0);
    add_register(1);
  } else if (name == "m" || name.starts_with("mi")) {
    add_memory(0);
  } else if (name == "mr" && !update) {
    add_memory(0);
    add_register(5);
  } else if (name == "rm" && !update) {
    add_register(0);
    add_memory(1);
  } else if (name.starts_with("i")) {
    // The accumulator-immediate encodings omit the register from MC operands.
    const char *accumulator = width == 8    ? "AL"
                              : width == 16 ? "AX"
                              : width == 32 ? "EAX"
                                            : "RAX";
    for (unsigned reg = 1; reg < decoder.registers->getNumRegs(); ++reg)
      if (llvm::StringRef(decoder.registers->getName(reg)) == accumulator) {
        storage.push_back({width, 0, reg});
        break;
      }
  }
  return storage;
}

// Recognize bounded table dispatch through a deliberately small symbolic
// language. Values are affine in the checked selector, or signed table loads;
// no instruction is executed and no writable table is trusted.
static bool flow_switch(
    const FlowDecoder &decoder, const std::map<uint64_t, FlowNode> &nodes,
    uint64_t pc, const FlowNode &dispatch,
    const std::function<bool(uint64_t, size_t, std::vector<unsigned char> &)>
        &read,
    FlowSwitch &result) {
  if (!read)
    return false;
  uint64_t cursor = pc;
  std::vector<uint64_t> path;
  const FlowNode *guard = nullptr;
  uint64_t guard_pc = 0;
  while (true) {
    auto previous = nodes.lower_bound(cursor);
    if (previous == nodes.begin())
      return false;
    --previous;
    const auto &[address, node] = *previous;
    if (address + node.size != cursor)
      return false;
    if (node.conditional) {
      if (node.successors.size() != 2 || node.successors[1] != cursor)
        return false;
      guard = &node;
      guard_pc = address;
      break;
    }
    if (node.successors.size() != 1 || node.successors[0] != cursor ||
        decoder.analysis->isCall(node.instruction))
      return false;
    path.push_back(address);
    cursor = address;
  }
  if (!guard || guard->instruction.getNumOperands() != 2 ||
      !guard->instruction.getOperand(1).isImm())
    return false;
  // x86 condition codes 7 (A) and 3 (AE) reject an unsigned out-of-range index.
  const auto condition = guard->instruction.getOperand(1).getImm();
  if (condition != 7 && condition != 3)
    return false;
  auto comparison = nodes.find(guard_pc);
  if (comparison == nodes.begin())
    return false;
  --comparison;
  const auto &[compare_pc, compare_node] = *comparison;
  if (compare_pc + compare_node.size != guard_pc ||
      !decoder.instructions->getName(compare_node.instruction.getOpcode())
           .starts_with("CMP") ||
      !compare_node.instruction.getNumOperands())
    return false;
  const auto &bound_operand = compare_node.instruction.getOperand(
      compare_node.instruction.getNumOperands() - 1);
  if (!bound_operand.isImm() || bound_operand.getImm() < 0)
    return false;
  const uint64_t count =
      uint64_t(bound_operand.getImm()) + (condition == 7 ? 1 : 0);
  const auto storage = flow_storage(decoder, compare_node, compare_pc,
                                    FlowStorageKind::Comparison);
  if (count < 3 || count > UINT32_MAX || storage.size() != 1 ||
      (storage[0][0] != 32 && storage[0][0] != 64))
    return false;
  std::reverse(path.begin(), path.end());
  enum class Kind { Unknown, Affine, UnsignedEntry, SignedEntry, Target };
  struct Value {
    Kind kind = Kind::Unknown;
    uint64_t constant = 0;
    uint64_t scale = 0;
    unsigned width = 0;
  };
  std::map<unsigned, Value> values;
  auto width = [&](unsigned reg) -> unsigned {
    const llvm::StringRef name(decoder.registers->getName(reg));
    if (name.starts_with("E") || name.ends_with("D"))
      return 32;
    if (name.starts_with("R") && !name.ends_with("B") && !name.ends_with("W"))
      return 64;
    return 0;
  };
  auto reg_value = [&](unsigned reg) -> Value {
    if (!reg)
      return {Kind::Affine, 0, 0, 64};
    for (const auto &[known, value] : values)
      if (decoder.registers->regsOverlap(known, reg) && width(reg) &&
          width(reg) <= value.width)
        return value;
    return {};
  };
  auto set_register = [&](unsigned reg, Value value) {
    for (auto current = values.begin(); current != values.end();)
      if (decoder.registers->regsOverlap(current->first, reg))
        current = values.erase(current);
      else
        ++current;
    // A 32-bit write zero-extends the architectural 64-bit GPR. Table pointer
    // values, however, cannot survive a truncating write.
    if (width(reg) == 32 &&
        (value.kind != Kind::Affine || value.constant > UINT32_MAX ||
         value.scale > (UINT32_MAX - value.constant) / (count - 1)))
      value = {};
    value.width = width(reg) ? 64 : 0;
    values[reg] = value;
  };
  if (storage[0][1] == 0) {
    const unsigned reg = storage[0][2];
    unsigned known_width = storage[0][0];
    // A nearby proven 32-bit definition establishes zero-extended high bits.
    // Without it, a 32-bit bounds test does not constrain a 64-bit table index.
    auto previous = comparison;
    uint64_t next = compare_pc;
    std::vector<uint64_t> bootstrap{compare_pc};
    while (previous != nodes.begin()) {
      --previous;
      if (previous->first + previous->second.size != next ||
          previous->second.successors.size() != 1 ||
          previous->second.successors[0] != next ||
          decoder.analysis->isCall(previous->second.instruction))
        break;
      const auto &instruction = previous->second.instruction;
      const auto &descriptor =
          decoder.instructions->get(instruction.getOpcode());
      bool defined = false;
      bool zero_extended = false;
      for (unsigned operand = 0; operand < descriptor.getNumDefs() &&
                                 operand < instruction.getNumOperands();
           ++operand)
        if (instruction.getOperand(operand).isReg() &&
            decoder.registers->regsOverlap(
                instruction.getOperand(operand).getReg(), reg)) {
          zero_extended = width(instruction.getOperand(operand).getReg()) == 32;
          defined = true;
        }
      for (const auto implicit : descriptor.implicit_defs())
        if (decoder.registers->regsOverlap(implicit, reg)) {
          zero_extended = width(implicit) == 32;
          defined = true;
        }
      bootstrap.push_back(previous->first);
      if (defined) {
        if (known_width == 32 && zero_extended) {
          known_width = 64;
          std::reverse(bootstrap.begin(), bootstrap.end());
          result.bootstrap = std::move(bootstrap);
        }
        break;
      }
      next = previous->first;
    }
    values[reg] = {Kind::Affine, 0, 1, known_width};
    std::snprintf(result.region.selector_register,
                  sizeof(result.region.selector_register), "%s",
                  decoder.registers->getName(reg));
  }
  auto memory = [&](const llvm::MCInst &instruction, unsigned index,
                    uint64_t address, uint64_t size) -> Value {
    if (index + 4 >= instruction.getNumOperands())
      return {};
    const auto &base = instruction.getOperand(index);
    const auto &scale = instruction.getOperand(index + 1);
    const auto &subscript = instruction.getOperand(index + 2);
    const auto &offset = instruction.getOperand(index + 3);
    const auto &segment = instruction.getOperand(index + 4);
    if (!base.isReg() || !scale.isImm() || !subscript.isReg() ||
        !offset.isImm() || !segment.isReg() || segment.getReg())
      return {};
    Value left = reg_value(base.getReg());
    if (base.getReg() &&
        llvm::StringRef(decoder.registers->getName(base.getReg())) == "RIP")
      left = {Kind::Affine, address + size, 0, 64};
    const Value right = reg_value(subscript.getReg());
    if (left.kind != Kind::Affine || right.kind != Kind::Affine ||
        (scale.getImm() != 1 && scale.getImm() != 2 && scale.getImm() != 4 &&
         scale.getImm() != 8))
      return {};
    return {Kind::Affine,
            left.constant + right.constant * scale.getImm() + offset.getImm(),
            left.scale + right.scale * scale.getImm(), 64};
  };
  auto matches_selector = [&](const llvm::MCInst &instruction, unsigned index,
                              unsigned bits, uint64_t address, uint64_t size) {
    if (storage[0][1] != 1 || bits != storage[0][0] ||
        index + 4 >= instruction.getNumOperands())
      return false;
    std::vector<uint64_t> location{bits, 1};
    for (unsigned operand = 0; operand < 5; ++operand) {
      const auto &value = instruction.getOperand(index + operand);
      if (operand % 2 == 0) {
        if (!value.isReg())
          return false;
        location.push_back(value.getReg());
      } else {
        if (!value.isImm())
          return false;
        location.push_back(value.getImm());
      }
    }
    if (location[2] &&
        llvm::StringRef(decoder.registers->getName(location[2])) == "RIP") {
      location[2] = 0;
      location[5] += address + size;
    }
    return location == storage[0];
  };
  for (const uint64_t address : path) {
    const auto &node = nodes.at(address);
    const auto &instruction = node.instruction;
    const auto opcode = decoder.instructions->getName(instruction.getOpcode());
    if (opcode.starts_with("NOOP"))
      continue;
    if (opcode == "CDQE") {
      unsigned eax = 0, rax = 0;
      for (unsigned reg = 1; reg < decoder.registers->getNumRegs(); ++reg) {
        const llvm::StringRef name(decoder.registers->getName(reg));
        if (name == "EAX")
          eax = reg;
        if (name == "RAX")
          rax = reg;
      }
      Value value = reg_value(eax);
      if (value.kind != Kind::UnsignedEntry)
        return false;
      value.kind = Kind::SignedEntry;
      set_register(rax, value);
      continue;
    }
    if (!instruction.getNumOperands() || !instruction.getOperand(0).isReg())
      return false;
    const unsigned destination = instruction.getOperand(0).getReg();
    Value value;
    if ((opcode == "MOV32rr" || opcode == "MOV64rr") &&
        instruction.getNumOperands() == 2 &&
        instruction.getOperand(1).isReg()) {
      value = reg_value(instruction.getOperand(1).getReg());
    } else if ((opcode == "MOV32ri" || opcode == "MOV64ri" ||
                opcode == "MOV64ri32") &&
               instruction.getNumOperands() == 2 &&
               instruction.getOperand(1).isImm()) {
      value = {Kind::Affine,
               static_cast<uint64_t>(instruction.getOperand(1).getImm()), 0,
               64};
    } else if (opcode == "LEA64r") {
      value = memory(instruction, 1, address, node.size);
    } else if (opcode == "MOV32rm" || opcode == "MOV64rm" ||
               opcode == "MOVSX64rm32") {
      const unsigned bits = opcode == "MOV64rm" ? 64 : 32;
      if (matches_selector(instruction, 1, bits, address, node.size)) {
        value = {Kind::Affine, 0, 1, 64};
      } else {
        value = memory(instruction, 1, address, node.size);
        if (value.kind != Kind::Affine ||
            value.scale != (opcode == "MOV64rm" ? 8 : 4))
          return false;
        value.kind = opcode == "MOV64rm"       ? Kind::Target
                     : opcode == "MOVSX64rm32" ? Kind::SignedEntry
                                               : Kind::UnsignedEntry;
      }
    } else if (opcode == "MOVSX64rr32" && instruction.getNumOperands() == 2 &&
               instruction.getOperand(1).isReg()) {
      value = reg_value(instruction.getOperand(1).getReg());
      if (value.kind == Kind::UnsignedEntry)
        value.kind = Kind::SignedEntry;
      else if (value.kind != Kind::Affine || value.constant > INT32_MAX ||
               value.scale > (INT32_MAX - value.constant) / (count - 1))
        return false;
    } else if (opcode == "ADD64rr" && instruction.getNumOperands() == 3 &&
               instruction.getOperand(1).isReg() &&
               instruction.getOperand(2).isReg()) {
      const auto left = reg_value(instruction.getOperand(1).getReg());
      const auto right = reg_value(instruction.getOperand(2).getReg());
      if (left.kind == Kind::Affine && right.kind == Kind::Affine)
        value = {Kind::Affine, left.constant + right.constant,
                 left.scale + right.scale, 64};
      else if (left.kind == Kind::SignedEntry && right.kind == Kind::Affine &&
               right.scale == 0 && right.constant == left.constant)
        value = {Kind::Target, left.constant, 4, 64};
      else if (right.kind == Kind::SignedEntry && left.kind == Kind::Affine &&
               left.scale == 0 && left.constant == right.constant)
        value = {Kind::Target, right.constant, 4, 64};
    } else {
      return false;
    }
    if (value.kind == Kind::Unknown)
      return false;
    // A selector stored in memory cannot be reread through a modified address
    // register and still be treated as the value checked by the guard.
    if (storage[0][1] == 1)
      for (const size_t index : {size_t{2}, size_t{4}, size_t{6}})
        if (storage[0][index] &&
            decoder.registers->regsOverlap(destination, storage[0][index]))
          return false;
    // A 32-bit table load is intentionally retained until CDQE/MOVSXD.
    if (value.kind == Kind::UnsignedEntry) {
      set_register(destination, {});
      value.width = 32;
      values[destination] = value;
    } else {
      set_register(destination, value);
    }
  }
  const auto opcode =
      decoder.instructions->getName(dispatch.instruction.getOpcode());
  Value table;
  if (opcode == "JMP64m") {
    table = memory(dispatch.instruction, 0, pc, dispatch.size);
    if (table.kind != Kind::Affine || table.scale != 8)
      return false;
    table.kind = Kind::Target;
  } else if (opcode == "JMP64r" && dispatch.instruction.getNumOperands() == 1 &&
             dispatch.instruction.getOperand(0).isReg()) {
    table = reg_value(dispatch.instruction.getOperand(0).getReg());
  }
  if (table.kind != Kind::Target || (table.scale != 4 && table.scale != 8))
    return false;
  std::vector<unsigned char> contents;
  if (!read(table.constant, count * table.scale, contents) ||
      contents.size() != count * table.scale)
    return false;
  result.region.guard_offset = guard_pc;
  result.region.dispatch_offset = pc;
  result.region.selector_offset = compare_pc;
  result.region.default_offset = guard->successors[0];
  result.region.cases.resize(count);
  for (uint64_t index = 0; index < count; ++index) {
    uint64_t target = 0;
    for (uint64_t byte = 0; byte < table.scale; ++byte)
      target |= uint64_t(contents[index * table.scale + byte]) << (byte * 8);
    if (table.scale == 4)
      target = table.constant + static_cast<int32_t>(target);
    result.region.cases[index] = {static_cast<int64_t>(index), target};
  }
  result.path = std::move(path);
  return true;
}

ct_flow_analysis ct_analyze_flow(
    llvm::ArrayRef<unsigned char> bytes, uint64_t begin, uint64_t entry,
    const std::function<bool(uint64_t, size_t, std::vector<unsigned char> &)>
        &read) {
  ct_flow_analysis result;
  if (bytes.empty() || entry < begin || entry - begin >= bytes.size() ||
      bytes.size() > UINT64_MAX - begin)
    return result;
  // The helper serializes requests, including initialization and MC access.
  FlowDecoder &state = flow_decoder();
  if (!state.decoder || !state.analysis)
    return result;
  const uint64_t end = begin + bytes.size();
  std::map<uint64_t, FlowNode> nodes;
  std::set<uint64_t> failed;
  std::vector<uint64_t> pending{entry};
  std::map<uint64_t, FlowSwitch> switches;
  bool complete = true;
  while (!pending.empty()) {
    const uint64_t pc = pending.back();
    pending.pop_back();
    if (nodes.count(pc) || failed.count(pc))
      continue;
    llvm::MCInst instruction;
    uint64_t size = 0;
    bool decoded = false;
    while (size < end - pc && size < 15) {
      uint64_t part = 0;
      if (state.decoder->getInstruction(
              instruction, part, bytes.drop_front(pc - begin + size), pc + size,
              llvm::nulls()) != llvm::MCDisassembler::Success ||
          !part || part > end - pc - size || part > 15 - size)
        break;
      size += part;
      // LLVM exposes LOCK and similar prefixes as pseudo-instructions. Their
      // following opcode belongs to the same architectural instruction/PC.
      if (!state.instructions->getName(instruction.getOpcode())
               .ends_with("_PREFIX")) {
        decoded = true;
        break;
      }
    }
    if (!decoded) {
      failed.insert(pc);
      complete = false;
      continue;
    }
    auto following = nodes.lower_bound(pc);
    if ((following != nodes.end() && following->first < pc + size) ||
        (following != nodes.begin() &&
         std::prev(following)->first + std::prev(following)->second.size >
             pc)) {
      failed.insert(pc);
      complete = false;
      continue;
    }
    FlowNode node;
    node.size = size;
    node.instruction = instruction;
    auto successor = [&](uint64_t target) {
      node.code_successors.push_back(target);
      if (target >= begin && target < end) {
        node.successors.push_back(target);
        pending.push_back(target);
      } else {
        node.successors.push_back(UINT64_MAX);
        // Symbol bounds alone cannot distinguish a tail call from a cold
        // fragment that rejoins this routine. The unexamined edge is unknown.
        complete = false;
      }
    };
    if (state.analysis->isReturn(instruction)) {
      // Return destinations belong to the caller and are observed at runtime.
    } else if (state.analysis->isCall(instruction)) {
      // Calls can return here; their targets belong to separately prepared
      // functions, even when a direct callee lies inside the supplied bytes.
      successor(pc + size);
    } else if (state.analysis->isBranch(instruction)) {
      uint64_t target = 0;
      node.conditional = state.analysis->isConditionalBranch(instruction);
      if (!state.analysis->isIndirectBranch(instruction) &&
          state.analysis->evaluateBranch(instruction, pc, size, target))
        successor(target);
      else {
        FlowSwitch table;
        if (!node.conditional &&
            flow_switch(state, nodes, pc, node, read, table) &&
            table.region.default_offset >= begin &&
            table.region.default_offset < end &&
            std::all_of(
                table.region.cases.begin(), table.region.cases.end(),
                [&](const auto &item) {
                  return item.target_offset >= begin &&
                         item.target_offset < end;
                })) {
          std::set<uint64_t> targets;
          for (const auto &item : table.region.cases)
            targets.insert(item.target_offset);
          for (const uint64_t destination : targets)
            successor(destination);
          switches.emplace(pc, std::move(table));
        } else {
          node.code_successors.push_back(UINT64_MAX);
          complete = false;
        }
      }
      if (node.conditional)
        successor(pc + size);
    } else if (state.analysis->isTerminator(instruction)) {
      node.code_successors.push_back(UINT64_MAX);
      complete = false;
    } else {
      successor(pc + size);
    }
    nodes.emplace(pc, std::move(node));
  }
  for (const auto &[pc, node] : nodes)
    for (const auto target : node.successors)
      if (target != UINT64_MAX && !nodes.count(target))
        complete = false;
  // Export the actual decoded cover before the structured-region analysis can
  // return early. Gaps and known frontier PCs are retained, never linearly
  // decoded as instructions or replaced by a fictitious function exit.
  for (const auto &[pc, node] : nodes) {
    ct_flow_instruction exported{};
    exported.offset = pc;
    exported.size = static_cast<uint8_t>(node.size);
    std::memcpy(exported.bytes, bytes.data() + (pc - begin), node.size);
    const auto &instruction = node.instruction;
    const bool call = state.analysis->isCall(instruction);
    const bool branch = state.analysis->isBranch(instruction);
    uint64_t destination = 0;
    const auto opcode = state.instructions->getName(instruction.getOpcode());
    const bool syscall =
        opcode == "SYSCALL" || opcode == "SYSENTER" ||
        (opcode == "INT" && instruction.getNumOperands() == 1 &&
         instruction.getOperand(0).isImm() &&
         instruction.getOperand(0).getImm() == 0x80);
    exported.flags =
        (call ? unsigned(CT_FLOW_CALL) : 0u) |
        (branch ? unsigned(CT_FLOW_BRANCH) : 0u) |
        (state.analysis->isReturn(instruction) ? unsigned(CT_FLOW_RETURN)
                                               : 0u) |
        (node.conditional ? unsigned(CT_FLOW_CONDITIONAL) : 0u) |
        (syscall ? unsigned(CT_FLOW_SYSCALL) : 0u);
    if ((call || branch) && !state.analysis->evaluateBranch(
                                instruction, pc, node.size, destination))
      exported.flags |= CT_FLOW_INDIRECT;
    auto successors = node.code_successors;
    std::sort(successors.begin(), successors.end());
    successors.erase(std::unique(successors.begin(), successors.end()),
                     successors.end());
    for (const uint64_t target : successors) {
      result.edges.push_back({pc, target});
      if (!nodes.count(target))
        exported.flags |= CT_FLOW_FRONTIER;
    }
    result.instructions.push_back(exported);
  }
  if (!switches.empty()) {
    std::map<uint64_t, std::set<uint64_t>> predecessors;
    for (const auto &[pc, node] : nodes)
      for (const uint64_t target : node.successors)
        predecessors[target].insert(pc);
    for (const auto &[dispatch, table] : switches) {
      for (size_t index = 1; index < table.bootstrap.size(); ++index)
        if (predecessors[table.bootstrap[index]] !=
            std::set<uint64_t>{table.bootstrap[index - 1]})
          complete = false;
      uint64_t previous = table.region.guard_offset;
      if (predecessors[previous] !=
          std::set<uint64_t>{table.region.selector_offset})
        complete = false;
      for (const uint64_t pc : table.path) {
        if (predecessors[pc] != std::set<uint64_t>{previous})
          complete = false;
        previous = pc;
      }
      if (predecessors[dispatch] != std::set<uint64_t>{previous})
        complete = false;
    }
  }
  llvm::EquivalenceClasses<uint64_t> groups;
  auto group_boundaries = [&](const std::vector<uint64_t> &boundaries) {
    if (!boundaries.empty())
      for (const auto address : boundaries)
        groups.unionSets(boundaries.front(), address);
  };
  auto finish_groups = [&] {
    // roles is ordered, so the first member encountered is the canonical
    // minimum address, independent of LLVM's union leader selection.
    std::map<uint64_t, uint64_t> representatives;
    for (const auto &[address, role] : result.roles) {
      const auto [representative, inserted] =
          representatives.try_emplace(groups.getLeaderValue(address), address);
      result.groups.emplace(address, representative->second);
    }
  };
  if (!complete) {
    // Direct conditional successors are known basic-block entry addresses.
    // Without the complete graph, do not claim a join or a loop exit.
    for (const auto &[pc, node] : nodes)
      if (node.conditional) {
        std::vector<uint64_t> boundaries;
        for (const auto target : node.successors)
          if (target != UINT64_MAX) {
            result.roles[target] |= CT_FLOW_ENTRY;
            boundaries.push_back(target);
          }
        group_boundaries(boundaries);
      }
    finish_groups();
    return result;
  }
  llvm::LLVMContext context;
  llvm::Module module("ctrace.flow", context);
  auto *function = llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), false),
      llvm::GlobalValue::InternalLinkage, "flow", module);
  auto *synthetic_entry = llvm::BasicBlock::Create(context, "entry", function);
  std::map<uint64_t, llvm::BasicBlock *> blocks;
  std::map<llvm::BasicBlock *, uint64_t> addresses;
  for (const auto &[pc, node] : nodes) {
    auto *block = llvm::BasicBlock::Create(context, "", function);
    blocks.emplace(pc, block);
    addresses.emplace(block, pc);
  }
  auto *outside = llvm::BasicBlock::Create(context, "outside", function);
  llvm::ReturnInst::Create(context, outside);
  llvm::BranchInst::Create(blocks.at(entry), synthetic_entry);
  for (const auto &[pc, node] : nodes) {
    auto *block = blocks.at(pc);
    const auto &successors = node.successors;
    auto target = [&](size_t index) {
      return successors[index] == UINT64_MAX ? outside
                                             : blocks.at(successors[index]);
    };
    if (successors.empty())
      llvm::ReturnInst::Create(context, block);
    else if (successors.size() == 1)
      llvm::BranchInst::Create(target(0), block);
    else if (successors.size() == 2 && node.conditional)
      llvm::BranchInst::Create(
          target(0), target(1),
          llvm::UndefValue::get(llvm::Type::getInt1Ty(context)), block);
    else {
      auto *branch = llvm::SwitchInst::Create(
          llvm::UndefValue::get(llvm::Type::getInt32Ty(context)), target(0),
          successors.size() - 1, block);
      for (size_t index = 1; index < successors.size(); ++index)
        branch->addCase(
            llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), index),
            target(index));
    }
  }
  llvm::DominatorTree dominators(*function);
  llvm::LoopInfo loops(dominators);
  for (const auto *loop : loops.getLoopsInPreorder()) {
    std::vector<uint64_t> boundaries;
    if (auto header = addresses.find(loop->getHeader());
        header != addresses.end()) {
      result.roles[header->second] |= CT_FLOW_ENTRY;
      boundaries.push_back(header->second);
    }
    llvm::SmallVector<llvm::BasicBlock *, 8> exits;
    loop->getExitBlocks(exits);
    for (auto *exit : exits)
      if (auto address = addresses.find(exit); address != addresses.end()) {
        result.roles[address->second] |= CT_FLOW_EXIT;
        boundaries.push_back(address->second);
      }
    group_boundaries(boundaries);
  }
  llvm::PostDominatorTree postdominators(*function);
  for (auto &[dispatch, table] : switches) {
    const auto *node =
        postdominators.getNode(blocks.at(table.region.guard_offset));
    const auto *parent = node ? node->getIDom() : nullptr;
    auto *join = parent ? parent->getBlock() : nullptr;
    if (!join || !addresses.count(join) ||
        !dominators.dominates(blocks.at(table.region.guard_offset),
                              blocks.at(dispatch)))
      continue;
    table.region.join_offset = addresses.at(join);
    result.switches.push_back(table.region);
  }
  for (const auto &[pc, node] : nodes) {
    if (!node.conditional || node.successors.size() != 2 ||
        node.successors[0] == node.successors[1])
      continue;
    const auto *dominator = postdominators.getNode(blocks.at(pc));
    const auto *parent = dominator ? dominator->getIDom() : nullptr;
    auto *join = parent ? parent->getBlock() : nullptr;
    std::vector<uint64_t> boundaries;
    for (const auto target : node.successors)
      if (target != UINT64_MAX && blocks.at(target) != join) {
        result.roles[target] |= CT_FLOW_ENTRY;
        boundaries.push_back(target);
      }
    if (join)
      if (auto address = addresses.find(join); address != addresses.end()) {
        result.roles[address->second] |= CT_FLOW_EXIT;
        boundaries.push_back(address->second);
      }
    group_boundaries(boundaries);
    const auto join_address = addresses.find(join);
    if (join_address == addresses.end())
      continue;
    ct_flow_region region{};
    region.branch_offset = pc;
    region.taken_offset = node.successors[0];
    region.fallthrough_offset = node.successors[1];
    region.join_offset = join_address->second;
    region.kind = CT_FLOW_IF;
    if (const auto *loop = loops.getLoopFor(blocks.at(pc))) {
      const bool taken_inside = loop->contains(blocks.at(node.successors[0]));
      const bool fallthrough_inside =
          loop->contains(blocks.at(node.successors[1]));
      if (!taken_inside || !fallthrough_inside) {
        // Restrict iteration annotations to a unique pretest exit. A nested
        // break or a latch/do-while test must not masquerade as the loop guard.
        if (taken_inside == fallthrough_inside ||
            loop->getUniqueExitBlock() != join)
          continue;
        auto *body = blocks.at(node.successors[taken_inside ? 0 : 1]);
        auto *exit = blocks.at(node.successors[taken_inside ? 1 : 0]);
        if (body == loop->getHeader() || exit != join)
          continue;
        const uint64_t header = addresses.at(loop->getHeader());
        uint64_t cursor = header;
        std::set<uint64_t> prefix;
        while (cursor != pc && prefix.insert(cursor).second) {
          const auto &prefix_node = nodes.at(cursor);
          if (prefix_node.successors.size() != 1 ||
              !loop->contains(blocks.at(prefix_node.successors.front())))
            break;
          cursor = prefix_node.successors.front();
        }
        if (cursor != pc)
          continue;
        region.kind = CT_FLOW_LOOP;
        region.loop_header_offset = header;
        region.taken_is_body = taken_inside;
        // Only a unique, unconditional tail can become the for increment.
        // A conditional increment, alternate latch, or intervening effect
        // remains a while body rather than being moved into the annotation.
        auto *latch = loop->getLoopLatch();
        auto *condition = blocks.at(pc)->getSinglePredecessor();
        if (latch && condition && addresses.count(condition)) {
          uint64_t update = addresses.at(latch);
          std::set<uint64_t> suffix;
          while (suffix.insert(update).second) {
            const auto &tail = nodes.at(update);
            const auto opcode =
                state.instructions->getName(tail.instruction.getOpcode());
            if (!opcode.starts_with("NOOP") &&
                !state.analysis->isUnconditionalBranch(tail.instruction))
              break;
            auto *previous = blocks.at(update)->getSinglePredecessor();
            if (!previous || !loop->contains(previous) ||
                !addresses.count(previous)) {
              update = UINT64_MAX;
              break;
            }
            update = addresses.at(previous);
          }
          if (update != UINT64_MAX && update != header &&
              dominators.dominates(blocks.at(update), latch)) {
            const auto updated = flow_storage(state, nodes.at(update), update,
                                              FlowStorageKind::Update);
            const auto compared = flow_storage(
                state, nodes.at(addresses.at(condition)),
                addresses.at(condition), FlowStorageKind::Comparison);
            // Require the guard prefix after the backedge to contain only
            // its comparison and no-op instructions. Otherwise an address
            // register or compared value might change before the test.
            bool unchanged = !updated.empty() && !compared.empty();
            for (const auto prefix_pc : prefix)
              if (prefix_pc != addresses.at(condition) &&
                  !state.instructions
                       ->getName(nodes.at(prefix_pc).instruction.getOpcode())
                       .starts_with("NOOP"))
                unchanged = false;
            if (unchanged && std::find(compared.begin(), compared.end(),
                                       updated.front()) != compared.end()) {
              region.has_update = true;
              region.update_offset = update;
              // A real initializer must execute on the sole incoming path
              // from outside the loop. Only an independent immediate GPR
              // move, no-op, or jump can intervene: other work might change
              // the counter or the registers forming its address.
              auto *preheader = loop->getLoopPreheader();
              std::set<uint64_t> incoming;
              while (preheader && addresses.count(preheader) &&
                     !loop->contains(preheader)) {
                const uint64_t initializer = addresses.at(preheader);
                if (!incoming.insert(initializer).second)
                  break;
                const auto &initial_node = nodes.at(initializer);
                if (initial_node.successors.size() != 1)
                  break;
                const auto initialized =
                    flow_storage(state, initial_node, initializer,
                                 FlowStorageKind::Initializer);
                if (!initialized.empty() &&
                    initialized.front() == updated.front()) {
                  region.has_initializer = true;
                  region.initializer_offset = initializer;
                  break;
                }
                const auto opcode = state.instructions->getName(
                    initial_node.instruction.getOpcode());
                bool independent_move =
                    initialized.size() == 1 && initialized.front()[1] == 0;
                if (independent_move) {
                  const auto destination = initialized.front()[2];
                  const auto &counter = updated.front();
                  for (size_t reg = 2; reg < counter.size(); reg += 2)
                    if (counter[reg] &&
                        state.registers->regsOverlap(destination, counter[reg]))
                      independent_move = false;
                }
                if (!independent_move && !opcode.starts_with("NOOP") &&
                    !state.analysis->isUnconditionalBranch(
                        initial_node.instruction))
                  break;
                preheader = preheader->getSinglePredecessor();
              }
            }
          }
        }
      }
    }
    result.regions.push_back(region);
  }
  finish_groups();
  result.complete = true;
  return result;
}
