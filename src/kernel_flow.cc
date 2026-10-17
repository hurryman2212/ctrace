#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

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
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <elf.h>

#include "flow.h"
#include "kernel_flow.h"

static bool
kernel_flow(const ct_kernel_image &original,
            const std::vector<ct_kernel_site> &sites,
            const ct_kernel_decompile_layout &layout, uint32_t section,
            uint64_t entry_offset,
            const std::vector<ct_decompiled_instruction> &instructions,
            std::vector<ct_kernel_flow_region> &regions, std::string &error,
            std::vector<ct_kernel_stack_location> *stack, bool original_flow) {
  regions.clear();
  if (stack)
    stack->clear();
  error.clear();
  const auto fail = [&](const std::string &reason) {
    regions.clear();
    if (stack)
      stack->clear();
    error = "kernel control scopes unavailable: " + reason;
    return false;
  };
  if (instructions.size() > CT_FLOW_GRAPH_INSTRUCTION_LIMIT ||
      !ct_kernel_validate_decompile_proof(original, sites, layout, instructions,
                                          error))
    return fail(error.empty() ? "function exceeds CFG bound" : error);
  const auto mapping =
      std::find_if(layout.regions.begin(), layout.regions.end(),
                   [&](const auto &item) { return item.section == section; });
  if (mapping == layout.regions.end() || entry_offset >= mapping->size)
    return fail("function entry has no original section mapping");
  const uint64_t entry = mapping->address - layout.image_base + entry_offset;
  auto ordered = instructions;
  std::sort(ordered.begin(), ordered.end(),
            [](const auto &a, const auto &b) { return a.offset < b.offset; });
  std::vector<unsigned char> bytes;
  for (const auto &instruction : ordered) {
    if (instruction.offset != ordered.front().offset + bytes.size())
      return fail(
          "discontiguous instruction proof is not a linear code buffer");
    bytes.insert(bytes.end(), instruction.bytes,
                 instruction.bytes + instruction.size);
  }
  const auto decoded = ct_analyze_flow(bytes, ordered.front().offset, entry);
  if (decoded.instructions.empty())
    return fail("function entry could not be decoded");
  struct Node {
    const ct_flow_instruction *instruction;
    const ct_kernel_site *site;
    std::vector<uint64_t> successors;
    bool returned = false;
  };
  std::map<uint64_t, const ct_kernel_site *> originals;
  for (const auto &site : sites) {
    const auto mapped = std::find_if(
        layout.regions.begin(), layout.regions.end(),
        [&](const auto &item) { return item.section == site.section; });
    if (mapped != layout.regions.end())
      originals.emplace(mapped->address - layout.image_base + site.offset,
                        &site);
  }
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  for (const auto &symbol : original.symbols)
    symbols[{symbol.table, symbol.index}] = &symbol;
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_relocation *>
      relocations;
  for (const auto &relocation : original.relocations)
    relocations[{relocation.section, relocation.offset}] = &relocation;
  std::map<uint64_t, Node> nodes;
  for (const auto &instruction : decoded.instructions) {
    const auto proof = std::lower_bound(
        ordered.begin(), ordered.end(), instruction.offset,
        [](const auto &item, uint64_t pc) { return item.offset < pc; });
    const auto original_site = originals.find(instruction.offset);
    if (proof == ordered.end() || proof->offset != instruction.offset ||
        proof->size != instruction.size ||
        std::memcmp(proof->bytes, instruction.bytes, instruction.size) ||
        original_site == originals.end())
      return fail("decoded CFG left its proven original instructions");
    Node node{&instruction,
              original_site->second,
              {},
              bool(instruction.flags & CT_FLOW_RETURN)};
    // This exact undefined symbol denotes the kernel x86 return thunk. A
    // same-named function defined by the target is not an ABI return proof.
    if ((instruction.flags & CT_FLOW_BRANCH) &&
        !(instruction.flags & (CT_FLOW_CONDITIONAL | CT_FLOW_INDIRECT)) &&
        node.site->original_size >= 4) {
      const auto field =
          relocations.find({node.site->section,
                            node.site->offset + node.site->original_size - 4});
      if (field != relocations.end()) {
        const auto &relocation = *field->second;
        const auto symbol =
            symbols.find({relocation.symbol_table, relocation.symbol});
        node.returned |= symbol != symbols.end() &&
                         symbol->second->section == SHN_UNDEF &&
                         symbol->second->name == "__x86_return_thunk" &&
                         relocation.addend == -4 &&
                         (relocation.type == R_X86_64_PC32 ||
                          relocation.type == R_X86_64_PLT32);
      }
    }
    if (original_flow && !node.returned &&
        (instruction.flags & CT_FLOW_BRANCH)) {
      for (const auto &relocation : original.relocations) {
        if (relocation.section != node.site->section ||
            relocation.offset < node.site->offset ||
            relocation.offset - node.site->offset >= node.site->original_size)
          continue;
        if (std::none_of(layout.fixups.begin(), layout.fixups.end(),
                         [&](const auto &fixup) {
                           return fixup.proven &&
                                  fixup.section == relocation.section &&
                                  fixup.offset == relocation.offset;
                         }))
          return fail("unresolved original branch relocation");
      }
    }
    nodes.emplace(instruction.offset, std::move(node));
  }
  for (const auto &edge : decoded.edges) {
    const auto from = nodes.find(edge.from_offset);
    if (from == nodes.end())
      return fail("CFG edge has no proven source");
    if (from->second.returned)
      continue;
    if (!nodes.count(edge.to_offset))
      return fail("unresolved control-flow frontier");
    from->second.successors.push_back(edge.to_offset);
  }
  for (const auto &[pc, node] : nodes)
    if ((!node.returned && node.successors.empty()) ||
        (node.successors.size() > 1 &&
         !(node.instruction->flags & CT_FLOW_CONDITIONAL)) ||
        node.successors.size() > 2)
      return fail("unknown or unsupported successor set");

  if (stack) {
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetDisassembler();
    const llvm::Triple triple("x86_64-pc-linux-gnu");
    const auto *target =
        llvm::TargetRegistry::lookupTarget(triple.str(), error);
    if (!target)
      return fail("stack decoder target unavailable");
    std::unique_ptr<llvm::MCRegisterInfo> registers(
        target->createMCRegInfo(triple.str()));
    if (!registers)
      return fail("stack register metadata unavailable");
    llvm::MCTargetOptions options;
    std::unique_ptr<llvm::MCAsmInfo> assembly(
        target->createMCAsmInfo(*registers, triple.str(), options));
    std::unique_ptr<llvm::MCSubtargetInfo> subtarget(
        target->createMCSubtargetInfo(triple.str(), "generic", ""));
    std::unique_ptr<llvm::MCInstrInfo> descriptions(
        target->createMCInstrInfo());
    if (!assembly || !subtarget || !descriptions)
      return fail("stack instruction metadata unavailable");
    llvm::MCContext context(triple, assembly.get(), registers.get(),
                            subtarget.get());
    std::unique_ptr<llvm::MCDisassembler> decoder(
        target->createMCDisassembler(*subtarget, context));
    std::unique_ptr<llvm::MCInstrAnalysis> analysis(
        target->createMCInstrAnalysis(descriptions.get()));
    if (!decoder || !analysis)
      return fail("stack decoder unavailable");
    unsigned tracked[2] = {};
    for (unsigned reg = 1; reg < registers->getNumRegs(); ++reg) {
      const llvm::StringRef name = registers->getName(reg);
      if (name == "RSP")
        tracked[0] = reg;
      else if (name == "RBP")
        tracked[1] = reg;
    }
    if (!tracked[0] || !tracked[1])
      return fail("stack register identity unavailable");
    struct Rule {
      int base = -1;
      int64_t offset = 0;
    };
    std::map<uint64_t, std::array<Rule, 2>> rules;
    for (const auto &[pc, node] : nodes) {
      llvm::MCInst instruction;
      uint64_t size = 0;
      const llvm::ArrayRef<unsigned char> code(node.instruction->bytes,
                                               node.instruction->size);
      do {
        uint64_t part = 0;
        if (decoder->getInstruction(instruction, part, code.drop_front(size),
                                    pc + size, llvm::nulls()) !=
                llvm::MCDisassembler::Success ||
            !part || part > code.size() - size)
          return fail("stack instruction could not be decoded");
        size += part;
      } while (
          size < code.size() &&
          descriptions->getName(instruction.getOpcode()).ends_with("_PREFIX"));
      if (size != code.size())
        return fail("stack decoder instruction boundaries disagree");
      const auto &description = descriptions->get(instruction.getOpcode());
      const llvm::StringRef opcode =
          descriptions->getName(instruction.getOpcode());
      bool word_operand = false;
      for (unsigned char byte : code) {
        if (byte == 0x66)
          word_operand = true;
        else if (byte != 0xf0 && byte != 0xf2 && byte != 0xf3 && byte != 0x2e &&
                 byte != 0x36 && byte != 0x3e && byte != 0x26 && byte != 0x64 &&
                 byte != 0x65 && byte != 0x67 && (byte < 0x40 || byte > 0x4f))
          break;
      }
      auto &rule = rules[pc];
      rule = {{{0, 0}, {1, 0}}};
      const auto invalidate = [&](unsigned reg) {
        for (unsigned index = 0; index < 2; ++index)
          if (registers->regsOverlap(reg, tracked[index]))
            rule[index] = {};
      };
      for (unsigned index = 0; index < description.getNumDefs() &&
                               index < instruction.getNumOperands();
           ++index)
        if (instruction.getOperand(index).isReg())
          invalidate(instruction.getOperand(index).getReg());
      for (unsigned reg : description.implicit_defs())
        invalidate(reg);
      const auto reg = [&](unsigned index) -> unsigned {
        return index < instruction.getNumOperands() &&
                       instruction.getOperand(index).isReg()
                   ? unsigned(instruction.getOperand(index).getReg())
                   : 0;
      };
      const auto immediate = [&](unsigned index) {
        return index < instruction.getNumOperands() &&
               instruction.getOperand(index).isImm();
      };
      const auto base = [&](unsigned source) {
        return source == tracked[0] ? 0 : source == tracked[1] ? 1 : -1;
      };
      const int destination = base(reg(0));
      if (opcode.starts_with("PUSH64") || opcode == "PUSHF64")
        rule[0] = {0, -8};
      else if (opcode.starts_with("PUSH16") || opcode == "PUSHF16")
        rule[0] = {0, -2};
      else if (opcode.starts_with("POP64") || opcode == "POPF64" ||
               opcode.starts_with("POP16") || opcode == "POPF16") {
        // POP RSP/SP loads its new value from memory, rather than merely
        // undoing a push. Partial writes to BP likewise lose its proof.
        const bool writes_sp = description.getNumDefs() && reg(0) &&
                               registers->regsOverlap(reg(0), tracked[0]);
        if (!writes_sp)
          rule[0] = {0, opcode.contains("16") ? 2 : 8};
      } else if (opcode == "MOV64rr" && destination >= 0)
        rule[destination] = {base(reg(1)), 0};
      else if ((opcode == "ADD64ri8" || opcode == "ADD64ri32" ||
                opcode == "SUB64ri8" || opcode == "SUB64ri32") &&
               destination >= 0 && immediate(2)) {
        const int64_t value = instruction.getOperand(2).getImm();
        rule[destination] = {base(reg(1)),
                             opcode.starts_with("SUB") ? -value : value};
      } else if (opcode == "LEA64r" && destination >= 0 &&
                 instruction.getNumOperands() == 6 && immediate(2) &&
                 instruction.getOperand(2).getImm() == 1 &&
                 instruction.getOperand(3).isReg() && !reg(3) && immediate(4) &&
                 instruction.getOperand(5).isReg() && !reg(5))
        rule[destination] = {base(reg(1)), instruction.getOperand(4).getImm()};
      else if (opcode == "LEAVE64" && !word_operand) {
        rule[0] = {1, 8};
        rule[1] = {};
      } else if (opcode.starts_with("ENTER") || opcode.starts_with("LEAVE")) {
        // LLVM's ENTER description omits its RSP update, and its decoder
        // names 66 C9 LEAVE64. Neither case proves an ordinary 64-bit frame
        // restore, so do not retain the incoming stack/frame relationship.
        rule = {};
      } else if (node.instruction->flags & CT_FLOW_CALL) {
        // A returning x86-64 kernel ABI call preserves RSP and callee-saved
        // RBP, including recursion. CALL next-PC is instead the call/pop
        // address idiom: its fallthrough observes the pushed return address.
        uint64_t called = 0;
        if (opcode.starts_with("CALL64")) {
          rule = {{{0, 0}, {1, 0}}};
          if (analysis->evaluateBranch(instruction, pc, size, called) &&
              called == pc + size)
            rule[0] = {0, -8};
        } else
          rule = {};
      }
    }
    using State = std::array<std::optional<int64_t>, 2>;
    std::map<uint64_t, State> states;
    states[entry][0] = 0;
    std::deque<uint64_t> pending{entry};
    std::set<uint64_t> queued{entry};
    while (!pending.empty()) {
      const uint64_t pc = pending.front();
      pending.pop_front();
      queued.erase(pc);
      State after;
      const auto &before = states.at(pc);
      for (unsigned index = 0; index < 2; ++index) {
        const auto &rule = rules.at(pc)[index];
        int64_t value = 0;
        if (rule.base >= 0 && before[rule.base] &&
            !__builtin_add_overflow(*before[rule.base], rule.offset, &value))
          after[index] = value;
      }
      for (uint64_t successor : nodes.at(pc).successors) {
        auto [state, inserted] = states.emplace(successor, after);
        bool changed = inserted;
        if (!inserted)
          for (unsigned index = 0; index < 2; ++index)
            if (state->second[index] && state->second[index] != after[index]) {
              state->second[index].reset();
              changed = true;
            }
        if (changed && queued.insert(successor).second)
          pending.push_back(successor);
      }
    }
    for (const auto &[pc, state] : states)
      if (nodes.at(pc).site->id)
        stack->push_back({nodes.at(pc).site->id, bool(state[0]), bool(state[1]),
                          state[0].value_or(0), state[1].value_or(0)});
  }

  llvm::LLVMContext context;
  llvm::Module module("ctrace.kernel.flow", context);
  auto *function = llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), false),
      llvm::GlobalValue::InternalLinkage, "flow", module);
  std::map<uint64_t, llvm::BasicBlock *> blocks;
  std::map<const llvm::BasicBlock *, uint64_t> addresses;
  const auto add_block = [&](uint64_t pc) {
    auto *block = llvm::BasicBlock::Create(context, "", function);
    blocks[pc] = block;
    addresses[block] = pc;
  };
  add_block(entry);
  for (const auto &[pc, node] : nodes)
    if (pc != entry)
      add_block(pc);
  for (const auto &[pc, node] : nodes) {
    auto *block = blocks.at(pc);
    if (node.successors.empty())
      llvm::ReturnInst::Create(context, block);
    else if (node.successors.size() == 1)
      llvm::BranchInst::Create(blocks.at(node.successors[0]), block);
    else
      llvm::BranchInst::Create(
          blocks.at(node.successors[0]), blocks.at(node.successors[1]),
          llvm::UndefValue::get(llvm::Type::getInt1Ty(context)), block);
  }
  llvm::DominatorTree dominators(*function);
  llvm::LoopInfo loops(dominators);
  llvm::PostDominatorTree postdominators(*function);
  std::set<uint64_t> loop_tests;
  const auto probe = [&](uint64_t pc) { return nodes.at(pc).site->id; };
  for (const auto *loop : loops.getLoopsInPreorder()) {
    ct_kernel_flow_region region;
    region.loop = true;
    region.header = probe(addresses.at(loop->getHeader()));
    if (const auto *exit = loop->getUniqueExitBlock())
      region.join = probe(addresses.at(exit));
    unsigned preferred_tests = 0;
    for (const auto *block : loop->blocks()) {
      const uint64_t pc = addresses.at(block);
      const auto &node = nodes.at(pc);
      if (node.site->id)
        region.members.push_back(node.site->id);
      if (node.successors.size() != 2)
        continue;
      const bool first = loop->contains(blocks.at(node.successors[0]));
      const bool second = loop->contains(blocks.at(node.successors[1]));
      if (first == second)
        continue;
      loop_tests.insert(pc);
      const bool header_test = block == loop->getHeader();
      const bool latch_test = std::any_of(
          node.successors.begin(), node.successors.end(), [&](uint64_t target) {
            return blocks.at(target) == loop->getHeader();
          });
      if (header_test || latch_test) {
        ++preferred_tests;
        region.branch = node.site->id;
      }
    }
    if (preferred_tests > 1)
      region.branch = 0;
    // Header prefixes can contain ordinary condition preparation. Prefer the
    // unique exiting test when no header/latch instruction itself is a test.
    if (!region.branch) {
      unsigned candidates = 0;
      for (uint64_t pc : loop_tests)
        if (loop->contains(blocks.at(pc)) &&
            loops.getLoopFor(blocks.at(pc)) == loop) {
          region.branch = probe(pc);
          ++candidates;
        }
      if (candidates != 1)
        region.branch = 0;
    }
    std::sort(region.members.begin(), region.members.end());
    if (!region.members.empty())
      regions.push_back(std::move(region));
  }
  for (const auto &[pc, node] : nodes) {
    if (node.successors.size() != 2 || loop_tests.count(pc))
      continue;
    const auto *postdom = postdominators.getNode(blocks.at(pc));
    const auto *parent = postdom ? postdom->getIDom() : nullptr;
    const auto *join = parent ? parent->getBlock() : nullptr;
    if (!join || !addresses.count(join))
      continue;
    const uint64_t joined = addresses.at(join);
    const uint64_t following = pc + node.instruction->size;
    const uint64_t taken = node.successors[0] == following ? node.successors[1]
                                                           : node.successors[0];
    if (std::find(node.successors.begin(), node.successors.end(), following) ==
        node.successors.end())
      continue;
    ct_kernel_flow_region region;
    region.branch = probe(pc);
    region.taken = probe(taken);
    region.fallthrough = probe(following);
    region.join = probe(joined);
    bool valid = true;
    std::set<uint64_t> arms[2];
    for (unsigned side = 0; side < 2; ++side) {
      std::vector<uint64_t> pending{side ? following : taken};
      while (!pending.empty()) {
        const uint64_t current = pending.back();
        pending.pop_back();
        if (current == joined || !arms[side].insert(current).second)
          continue;
        if (current == pc ||
            !dominators.dominates(blocks.at(pc), blocks.at(current))) {
          valid = false;
          break;
        }
        const auto &child = nodes.at(current);
        pending.insert(pending.end(), child.successors.begin(),
                       child.successors.end());
      }
    }
    for (uint64_t member : arms[0])
      valid &= !arms[1].count(member);
    if (!valid)
      continue;
    for (uint64_t member : arms[0])
      if (probe(member))
        region.taken_members.push_back(probe(member));
    for (uint64_t member : arms[1])
      if (probe(member))
        region.fallthrough_members.push_back(probe(member));
    if (!region.taken_members.empty() || !region.fallthrough_members.empty())
      regions.push_back(std::move(region));
  }
  return true;
}

bool ct_kernel_decompile_flow(
    const ct_kernel_image &original, const std::vector<ct_kernel_site> &sites,
    const ct_kernel_decompile_layout &layout, uint32_t section,
    uint64_t entry_offset,
    const std::vector<ct_decompiled_instruction> &instructions,
    std::vector<ct_kernel_flow_region> &regions, std::string &error,
    std::vector<ct_kernel_stack_location> *stack) {
  return kernel_flow(original, sites, layout, section, entry_offset,
                     instructions, regions, error, stack, false);
}

bool ct_kernel_source_flow(const ct_kernel_image &original,
                           const std::vector<ct_kernel_site> &sites,
                           uint32_t section, uint64_t begin, uint64_t end,
                           std::vector<ct_kernel_flow_region> &regions,
                           std::string &error) {
  regions.clear();
  error.clear();
  if (section >= original.sections.size() || begin >= end) {
    error = "invalid original source CFG range";
    return false;
  }
  const auto &code = original.sections[section];
  if (!(code.flags & SHF_EXECINSTR) || end > code.size ||
      code.offset > original.bytes.size() ||
      code.size > original.bytes.size() - code.offset) {
    error = "original source CFG exceeds executable bytes";
    return false;
  }
  ct_kernel_decompile_layout layout;
  layout.regions.push_back({section, 0, code.size});
  std::vector<unsigned char> bytes(original.bytes.begin() + code.offset + begin,
                                   original.bytes.begin() + code.offset + end);
  for (const auto &relocation : original.relocations) {
    if (relocation.section != section || relocation.offset < begin ||
        relocation.offset >= end || end - relocation.offset < 4 ||
        (relocation.type != R_X86_64_PC32 && relocation.type != R_X86_64_PLT32))
      continue;
    const auto symbol =
        std::find_if(original.symbols.begin(), original.symbols.end(),
                     [&](const auto &candidate) {
                       return candidate.table == relocation.symbol_table &&
                              candidate.index == relocation.symbol;
                     });
    if (symbol == original.symbols.end() || symbol->section != section)
      continue;
    const __int128 displacement =
        __int128(symbol->offset) + relocation.addend - relocation.offset;
    if (displacement < INT32_MIN || displacement > INT32_MAX)
      continue;
    ct_kernel_decompile_fixup fixup;
    fixup.section = section;
    fixup.offset = relocation.offset;
    fixup.width = 4;
    fixup.value = uint32_t(int32_t(displacement));
    fixup.proven = true;
    layout.fixups.push_back(fixup);
    for (unsigned byte = 0; byte < 4; ++byte)
      bytes[relocation.offset - begin + byte] = fixup.value >> (8 * byte);
  }
  std::vector<ct_decompiled_instruction> instructions;
  if (!ct_decode_code_range(bytes, begin, instructions)) {
    error = "original source CFG instruction decoding failed";
    return false;
  }
  return kernel_flow(original, sites, layout, section, begin, instructions,
                     regions, error, nullptr, true);
}
