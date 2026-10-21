// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <set>

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/MemoryBufferRef.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <elf.h>

#include "analysis_cache.hh"
#include "cache.hh"
#include "interrupt.hh"
#include "kctrace/interrupt.h"

bool ct_kernel_interrupt_extract(
    const std::vector<unsigned char> &vmlinux,
    const std::string &expected_build_id,
    const ct_kernel_interrupt_layout &layout, ct_kernel_interrupt_proof &proof,
    std::string &error, const std::vector<unsigned char> &boot_relocations) {
  proof = {};
  error.clear();
  const auto fail = [&](const std::string &reason) {
    proof = {};
    error = "kernel interrupt dispatch proof: " + reason;
    return false;
  };
  if (vmlinux.size() < sizeof(Elf64_Ehdr) || expected_build_id.empty() ||
      expected_build_id.size() > 128 || expected_build_id.size() % 2 ||
      expected_build_id.find_first_not_of("0123456789abcdef") !=
          std::string::npos)
    return fail("missing bounded image or canonical running build ID");
  Elf64_Ehdr header{};
  std::memcpy(&header, vmlinux.data(), sizeof(header));
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 ||
      header.e_type != ET_EXEC)
    return fail("expected a little-endian x86-64 vmlinux ELF executable");
  const llvm::MemoryBufferRef memory(
      {reinterpret_cast<const char *>(vmlinux.data()), vmlinux.size()},
      "selected-vmlinux");
  auto parsed = llvm::object::ObjectFile::createObjectFile(memory);
  if (!parsed)
    return fail(llvm::toString(parsed.takeError()));
  const auto *object =
      llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(parsed->get());
  if (!object)
    return fail("unsupported ELF object representation");
  struct Section {
    uint64_t address = 0;
    llvm::StringRef bytes;
    bool executable = false;
  };
  std::map<uint64_t, Section> sections;
  std::map<std::string, uint64_t> named_sections;
  std::vector<ct_kernel_interrupt_jump> jumps;
  const auto hex = [](llvm::ArrayRef<uint8_t> bytes) {
    std::string result;
    for (unsigned char byte : bytes) {
      result += "0123456789abcdef"[byte >> 4];
      result += "0123456789abcdef"[byte & 15];
    }
    return result;
  };
  for (const auto &section : object->sections()) {
    auto content = section.getContents();
    auto section_name = section.getName();
    if (!content) {
      if (!section_name)
        llvm::consumeError(section_name.takeError());
      return fail(llvm::toString(content.takeError()));
    }
    if (!section_name)
      return fail(llvm::toString(section_name.takeError()));
    const llvm::object::ELFSectionRef elf(section);
    const auto flags = elf.getFlags();
    if (content->size() > UINT64_MAX - section.getAddress())
      return fail("kernel section address range overflows");
    if (flags & SHF_EXECINSTR) {
      if (!(flags & SHF_ALLOC))
        return fail("invalid executable section");
    }
    sections.emplace(section.getIndex(), Section{section.getAddress(), *content,
                                                 bool((flags & SHF_EXECINSTR) &&
                                                      !(flags & SHF_WRITE))});
    if (!section_name->empty() &&
        !named_sections.emplace(section_name->str(), section.getIndex()).second)
      return fail("duplicate kernel section name");
    if (elf.getType() != SHT_NOTE)
      continue;
    size_t offset = 0;
    while (offset < content->size()) {
      if (content->size() - offset < sizeof(Elf64_Nhdr))
        return fail("truncated kernel note");
      Elf64_Nhdr note{};
      std::memcpy(&note, content->data() + offset, sizeof(note));
      offset += sizeof(note);
      const uint64_t name_size = (uint64_t(note.n_namesz) + 3) & ~UINT64_C(3);
      const uint64_t data_size = (uint64_t(note.n_descsz) + 3) & ~UINT64_C(3);
      if (name_size > content->size() - offset ||
          data_size > content->size() - offset - name_size)
        return fail("kernel note exceeds its section");
      if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
          !std::memcmp(content->data() + offset, "GNU", 4)) {
        if (!proof.build_id.empty() || !note.n_descsz || note.n_descsz > 64)
          return fail("ambiguous or invalid GNU build ID");
        proof.build_id = hex({reinterpret_cast<const uint8_t *>(
                                  content->data() + offset + name_size),
                              note.n_descsz});
      }
      offset += name_size + data_size;
    }
  }
  if (proof.build_id != expected_build_id)
    return fail("vmlinux build ID differs from the running kernel");
  proof.image_digest = hex(llvm::SHA256::hash(vmlinux));
  struct Symbol {
    uint64_t address = 0, size = 0, section = 0;
    unsigned type = 0;
  };
  std::map<std::string, Symbol> symbols;
  std::set<uint64_t> function_addresses;
  std::set<uint64_t> indirect_thunks;
  for (const auto &symbol : object->symbols()) {
    auto name = symbol.getName();
    auto address = symbol.getAddress();
    auto section = symbol.getSection();
    if (!name || !address || !section) {
      if (!name)
        llvm::consumeError(name.takeError());
      if (!address)
        llvm::consumeError(address.takeError());
      if (!section)
        llvm::consumeError(section.takeError());
      return fail("invalid kernel symbol table");
    }
    if (name->empty() || *section == object->section_end())
      continue;
    const llvm::object::ELFSymbolRef elf(symbol);
    const Symbol value{*address, elf.getSize(), (*section)->getIndex(),
                       elf.getELFType()};
    const auto contents = sections.find(value.section);
    const bool executable = contents != sections.end() &&
                            contents->second.executable &&
                            value.address >= contents->second.address &&
                            value.address - contents->second.address <
                                contents->second.bytes.size();
    if (executable && (value.type == STT_FUNC || *name == "__x86_return_thunk"))
      function_addresses.insert(value.address);
    if (executable && name->starts_with("__x86_indirect_thunk_"))
      indirect_thunks.insert(value.address);
    if (*name != "_text" && *name != "hrtimer_start_range_ns" &&
        *name != "__x86_return_thunk" && *name != "__WARN_trap" &&
        *name != "__start_static_call_sites" &&
        *name != "__stop_static_call_sites" &&
        !name->starts_with("__SCK__tp_func_") &&
        !name->starts_with("__SCT__tp_func_") &&
        !name->starts_with("__traceiter_") && *name != "__SCK__WARN_trap" &&
        *name != "__SCT__WARN_trap" && *name != "__start___jump_table" &&
        *name != "__stop___jump_table" && *name != "__x86_indirect_thunk_rax" &&
        *name != "__x86_indirect_thunk_r13" &&
        *name != "__x86_indirect_thunk_r12" &&
        *name != "__x86_indirect_thunk_rdx" &&
        *name != "__x86_indirect_thunk_rbp" &&
        *name != "_raw_spin_unlock_irqrestore" &&
        *name != "__hrtimer_run_queues" &&
        *name != "__hrtimer_run_queues.cold" &&
        *name != "__handle_irq_event_percpu" &&
        *name != "__handle_irq_event_percpu.cold" && *name != "irq_thread_fn" &&
        *name != "irq_thread_fn.cold" && *name != "call_timer_fn" &&
        *name != "call_timer_fn.cold" && *name != "tasklet_action_common" &&
        *name != "tasklet_action_common.cold")
      continue;
    auto [position, inserted] = symbols.emplace(name->str(), value);
    if (!inserted && (position->second.address != value.address ||
                      position->second.size != value.size))
      return fail("ambiguous kernel symbol " + name->str());
  }
  if (symbols.count("__start___jump_table") !=
      symbols.count("__stop___jump_table"))
    return fail("incomplete kernel jump-label bounds");
  if (symbols.count("__start___jump_table")) {
    const auto &begin = symbols.at("__start___jump_table");
    const auto &end = symbols.at("__stop___jump_table");
    const auto &section = sections.at(begin.section);
    if (begin.section != end.section || begin.address > end.address ||
        begin.address < section.address ||
        end.address - section.address > section.bytes.size() ||
        (end.address - begin.address) % 16)
      return fail("unsupported x86 jump-label table layout");
    for (uint64_t pc = begin.address; pc < end.address; pc += 16) {
      int32_t relative[2];
      std::memcpy(relative, section.bytes.data() + pc - section.address,
                  sizeof(relative));
      const __int128 instruction = __int128(pc) + relative[0];
      const __int128 destination = __int128(pc) + 4 + relative[1];
      if (instruction <= 0 || instruction > UINT64_MAX || destination <= 0 ||
          destination > UINT64_MAX)
        return fail("overflow in kernel jump-label table");
      jumps.push_back({uint64_t(instruction), uint64_t(destination)});
    }
  }
  const auto text = symbols.find("_text");
  if (text == symbols.end() || !text->second.address ||
      !sections.at(text->second.section).executable ||
      text->second.address != sections.at(text->second.section).address)
    return fail("kernel text anchor unavailable");
  proof.text_address = text->second.address;
  const auto anchor = symbols.find("hrtimer_start_range_ns");
  if (anchor == symbols.end() || anchor->second.type != STT_FUNC ||
      !function_addresses.count(anchor->second.address))
    return fail("public hrtimer_start_range_ns anchor unavailable");
  proof.anchor_address = anchor->second.address;
  for (const char *name :
       {"__x86_indirect_thunk_rax", "__x86_indirect_thunk_rbp",
        "_raw_spin_unlock_irqrestore"})
    if (!symbols.count(name) || !symbols.at(name).address)
      return fail(std::string("required kernel symbol unavailable: ") + name);
    else if (!sections.at(symbols.at(name).section).executable ||
             symbols.at(name).address <
                 sections.at(symbols.at(name).section).address ||
             symbols.at(name).address -
                     sections.at(symbols.at(name).section).address >=
                 sections.at(symbols.at(name).section).bytes.size())
      return fail(std::string("required kernel symbol is not executable: ") +
                  name);
  if (layout.irq_desc_action % 8 || layout.irqaction_handler % 8 ||
      layout.irqaction_next % 8 || layout.irqaction_thread_fn % 8 ||
      layout.hrtimer_function % 8 || !layout.irq_desc_action ||
      !layout.irqaction_next || !layout.irqaction_thread_fn ||
      !layout.hrtimer_function ||
      layout.irqaction_handler == layout.irqaction_next ||
      layout.irqaction_handler == layout.irqaction_thread_fn ||
      layout.irqaction_next == layout.irqaction_thread_fn)
    return fail("invalid selected-Kbuild callback layout");
  const bool tasklets = layout.tasklet_function || layout.tasklet_data;
  if (tasklets && (!layout.tasklet_function || !layout.tasklet_data ||
                   layout.tasklet_function % 8 || layout.tasklet_data % 8 ||
                   layout.tasklet_function == layout.tasklet_data ||
                   !symbols.count("__x86_indirect_thunk_rdx") ||
                   !symbols.count("__SCT__tp_func_tasklet_entry") ||
                   !symbols.count("__SCT__tp_func_tasklet_exit")))
    return fail("invalid selected-Kbuild tasklet layout or tracepoints");

  const auto image_bytes = [&](uint64_t address, uint64_t size) {
    for (const auto &[index, section] : sections)
      if (address >= section.address &&
          address - section.address <= section.bytes.size() &&
          size <= section.bytes.size() - (address - section.address))
        return section.bytes.substr(address - section.address, size);
    return llvm::StringRef{};
  };
  const auto relative_address = [](uint64_t pc, int32_t offset) {
    const __int128 result = __int128(pc) + offset;
    return result > 0 && result <= UINT64_MAX ? uint64_t(result) : 0;
  };
  std::map<uint64_t, ct_kernel_interrupt_window> patches;
  for (const auto &[name, kind] :
       {std::pair{".retpoline_sites",
                  ct_kernel_interrupt_window_kind::indirect_call},
        std::pair{".return_sites",
                  ct_kernel_interrupt_window_kind::return_thunk},
        std::pair{".ibt_endbr_seal",
                  ct_kernel_interrupt_window_kind::endbr_seal}}) {
    const auto section = named_sections.find(name);
    if (section == named_sections.end())
      continue;
    const auto &contents = sections.at(section->second);
    if (contents.bytes.size() % 4)
      return fail(std::string("malformed patch-site table: ") + name);
    for (size_t offset = 0; offset < contents.bytes.size(); offset += 4) {
      int32_t displacement;
      std::memcpy(&displacement, contents.bytes.data() + offset, 4);
      const auto pc = relative_address(contents.address + offset, displacement);
      if (!pc ||
          !patches.emplace(pc, ct_kernel_interrupt_window{kind, pc}).second)
        return fail("overlapping or invalid kernel patch-site metadata");
    }
  }
  if (symbols.count("__start_static_call_sites") !=
      symbols.count("__stop_static_call_sites"))
    return fail("incomplete kernel static-call bounds");
  if (symbols.count("__start_static_call_sites")) {
    const auto begin = symbols.at("__start_static_call_sites").address;
    const auto end = symbols.at("__stop_static_call_sites").address;
    const auto bytes =
        end >= begin ? image_bytes(begin, end - begin) : llvm::StringRef{};
    if (bytes.empty() || bytes.size() % 8)
      return fail("unsupported kernel static-call table layout");
    for (size_t offset = 0; offset < bytes.size(); offset += 8) {
      int32_t relative[2];
      std::memcpy(relative, bytes.data() + offset, sizeof(relative));
      const uint64_t pc = relative_address(begin + offset, relative[0]);
      const uint64_t key = relative_address(begin + offset + 4, relative[1]);
      if (!pc || !key ||
          !patches
               .emplace(pc,
                        ct_kernel_interrupt_window{
                            ct_kernel_interrupt_window_kind::tracepoint_call,
                            pc, 0, key})
               .second)
        return fail("overlapping or invalid kernel static-call metadata");
    }
  }
  // The selected x86-64 boot code processes this exact two-list format
  // backwards: add the KASLR delta to 32-bit fields, then 64-bit fields.
  // Site words are signed 32-bit virtual addresses, not image file offsets.
  if (!boot_relocations.empty()) {
    if (boot_relocations.size() < 8 || boot_relocations.size() % 4)
      return fail("invalid selected-Kbuild boot relocation size");
    unsigned group = 0;
    uint64_t previous = 0;
    for (size_t offset = 0; offset < boot_relocations.size(); offset += 4) {
      int32_t word;
      std::memcpy(&word, boot_relocations.data() + offset, 4);
      if (!word) {
        if (++group > 2)
          return fail("unsupported boot relocation list format");
        previous = 0;
        continue;
      }
      const auto pc = uint64_t(int64_t(word));
      if (!group || word >= 0 || (previous && pc <= previous))
        return fail("unordered or noncanonical boot relocation site");
      previous = pc;
      ct_kernel_interrupt_window patch{
          group == 1 ? ct_kernel_interrupt_window_kind::relocate64
                     : ct_kernel_interrupt_window_kind::relocate32,
          pc};
      patch.size = group == 1 ? 8 : 4;
      if (!patches.emplace(pc, patch).second)
        return fail("boot relocation overlaps another kernel patch site");
    }
    if (group != 2)
      return fail("incomplete boot relocation lists");
    proof.relocation_digest = hex(llvm::SHA256::hash(boot_relocations));
  }

  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();
  llvm::Triple triple("x86_64-pc-linux-gnu");
  const auto *target = llvm::TargetRegistry::lookupTarget(triple.str(), error);
  if (!target)
    return fail(error);
  llvm::MCTargetOptions options;
  std::unique_ptr<llvm::MCRegisterInfo> registers(
      target->createMCRegInfo(triple.str()));
  std::unique_ptr<llvm::MCInstrInfo> descriptions(target->createMCInstrInfo());
  if (!registers || !descriptions)
    return fail("x86 instruction metadata unavailable");
  std::unique_ptr<llvm::MCAsmInfo> assembly(
      target->createMCAsmInfo(*registers, triple.str(), options));
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget(
      target->createMCSubtargetInfo(triple.str(), "generic", ""));
  if (!assembly || !subtarget)
    return fail("x86 decoder metadata unavailable");
  llvm::MCContext context(triple, assembly.get(), registers.get(),
                          subtarget.get());
  std::unique_ptr<llvm::MCDisassembler> decoder(
      target->createMCDisassembler(*subtarget, context));
  std::unique_ptr<llvm::MCInstrAnalysis> analysis(
      target->createMCInstrAnalysis(descriptions.get()));
  if (!decoder || !analysis)
    return fail("x86 decoder unavailable");
  const std::array<const char *, 16> names{
      {"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9",
       "R10", "R11", "R12", "R13", "R14", "R15"}};
  std::array<unsigned, 16> tracked{};
  for (unsigned reg = 1; reg < registers->getNumRegs(); ++reg)
    for (size_t index = 0; index < names.size(); ++index)
      if (llvm::StringRef(registers->getName(reg)) == names[index])
        tracked[index] = reg;
  if (std::any_of(tracked.begin(), tracked.end(),
                  [](unsigned reg) { return !reg; }))
    return fail("x86 GPR identities unavailable");
  enum Value : unsigned char {
    unknown,
    descriptor,
    action,
    handler,
    thread,
    timer_function,
    timer_object,
    timer_data
  };
  using State = std::array<Value, 16>;
  struct Instruction {
    llvm::MCInst decoded;
    uint64_t pc = 0, size = 0, destination = 0;
    uint64_t static_destination = 0;
    bool call = false, branch = false, conditional = false, returns = false,
         direct = false;
    llvm::StringRef bytes;
  };
  for (const auto &[name, kind] :
       {std::pair{"__hrtimer_run_queues", ct_kernel_interrupt_kind::hrtimer},
        std::pair{"__handle_irq_event_percpu",
                  ct_kernel_interrupt_kind::hard_irq},
        std::pair{"irq_thread_fn", ct_kernel_interrupt_kind::threaded_irq},
        std::pair{"call_timer_fn", ct_kernel_interrupt_kind::timer_list},
        std::pair{"tasklet_action_common",
                  ct_kernel_interrupt_kind::tasklet}}) {
    if (kind == ct_kernel_interrupt_kind::tasklet && !tasklets)
      continue;
    const auto entry = symbols.find(name);
    if (entry == symbols.end() || entry->second.type != STT_FUNC)
      return fail(std::string("dispatcher unavailable: ") + name);
    std::map<uint64_t, Instruction> code;
    for (const auto &[symbol_name, symbol] : symbols) {
      if (symbol_name != name && symbol_name != std::string(name) + ".cold")
        continue;
      const auto section = sections.find(symbol.section);
      if (symbol.type != STT_FUNC || !symbol.size ||
          symbol.size > uint64_t(UINT32_MAX) || section == sections.end() ||
          !section->second.executable ||
          symbol.address < section->second.address ||
          symbol.address - section->second.address >
              section->second.bytes.size() ||
          symbol.size > section->second.bytes.size() -
                            (symbol.address - section->second.address))
        return fail(std::string("invalid dispatcher extent: ") + name);
      const auto bytes = section->second.bytes.substr(
          symbol.address - section->second.address, symbol.size);
      proof.code.push_back(
          {symbol.address, {bytes.bytes_begin(), bytes.bytes_end()}});
      for (uint64_t offset = 0; offset < symbol.size;) {
        Instruction instruction;
        instruction.pc = symbol.address + offset;
        do {
          uint64_t part = 0;
          const llvm::ArrayRef<uint8_t> remaining(
              reinterpret_cast<const uint8_t *>(bytes.data() + offset +
                                                instruction.size),
              bytes.size() - offset - instruction.size);
          if (decoder->getInstruction(instruction.decoded, part, remaining,
                                      instruction.pc + instruction.size,
                                      llvm::nulls()) !=
                  llvm::MCDisassembler::Success ||
              !part || part > remaining.size())
            return fail(std::string("undecodable dispatcher: ") + name);
          instruction.size += part;
          if (instruction.size > 15)
            return fail(std::string("oversized x86 dispatcher instruction: ") +
                        name);
        } while (instruction.size < symbol.size - offset &&
                 descriptions->getName(instruction.decoded.getOpcode())
                     .ends_with("_PREFIX"));
        instruction.bytes = bytes.substr(offset, instruction.size);
        instruction.call = analysis->isCall(instruction.decoded);
        instruction.branch = analysis->isBranch(instruction.decoded);
        instruction.conditional =
            analysis->isConditionalBranch(instruction.decoded);
        instruction.returns =
            analysis->isReturn(instruction.decoded) ||
            descriptions->get(instruction.decoded.getOpcode()).isTrap();
        instruction.direct =
            (instruction.call || instruction.branch) &&
            analysis->evaluateBranch(instruction.decoded, instruction.pc,
                                     instruction.size, instruction.destination);
        if (!code.emplace(instruction.pc, std::move(instruction)).second ||
            code.size() > uint64_t(UINT32_MAX))
          return fail(std::string("overlapping or excessive dispatcher: ") +
                      name);
        offset += instruction.size;
      }
    }
    for (const auto &jump : jumps) {
      const auto at = code.find(jump.pc);
      if (at == code.end()) {
        const auto after = code.upper_bound(jump.pc);
        if (after != code.begin()) {
          const auto &before = std::prev(after)->second;
          if (jump.pc < before.pc + before.size)
            return fail(
                std::string("jump label splits a dispatcher instruction: ") +
                name);
        }
        continue;
      }
      const auto opcode = descriptions->getName(at->second.decoded.getOpcode());
      const __int128 displacement =
          __int128(jump.target) - jump.pc - at->second.size;
      if ((at->second.size != 2 && at->second.size != 5) ||
          at->second.static_destination || !code.count(jump.target) ||
          (at->second.size == 2 &&
           (displacement < INT8_MIN || displacement > INT8_MAX)) ||
          (at->second.size == 5 &&
           (displacement < INT32_MIN || displacement > INT32_MAX)) ||
          !(opcode.starts_with("NOOP") ||
            (at->second.branch && at->second.direct &&
             !at->second.conditional && at->second.destination == jump.target)))
        return fail(std::string("unsupported dispatcher jump label: ") + name);
      at->second.static_destination = jump.target;
      proof.jumps.push_back({jump.pc, jump.target, uint8_t(at->second.size)});
      proof.windows.push_back({ct_kernel_interrupt_window_kind::jump_label,
                               jump.pc, jump.target, 0,
                               uint8_t(at->second.size)});
    }
    for (const auto &[pc, metadata] : patches) {
      auto instruction = code.upper_bound(pc);
      if (instruction == code.begin())
        continue;
      --instruction;
      const auto &at = instruction->second;
      if (pc >= at.pc + at.size)
        continue;
      auto window = metadata;
      const bool relocation =
          window.kind == ct_kernel_interrupt_window_kind::relocate32 ||
          window.kind == ct_kernel_interrupt_window_kind::relocate64;
      if (relocation) {
        if (pc == at.pc || window.size > at.pc + at.size - pc)
          return fail(
              "boot relocation overlaps a dispatcher instruction boundary");
      } else {
        if (pc != at.pc)
          return fail("kernel patch metadata splits a dispatcher instruction");
        window.size = at.size;
      }
      switch (window.kind) {
      case ct_kernel_interrupt_window_kind::indirect_call: {
        if (!at.call || !at.direct || (at.size != 5 && at.size != 6) ||
            uint8_t(at.bytes[at.size - 5]) != 0xe8 ||
            (at.size == 6 && uint8_t(at.bytes[0]) != 0x2e))
          return fail("unsupported dispatcher retpoline patch encoding");
        bool found = false;
        for (const auto &[thunk, reg] :
             {std::pair{"__x86_indirect_thunk_rax", 0},
              std::pair{"__x86_indirect_thunk_rbp", 5},
              std::pair{"__x86_indirect_thunk_r13", 13},
              std::pair{"__x86_indirect_thunk_r12", 12},
              std::pair{"__x86_indirect_thunk_rdx", 2}})
          if (symbols.count(thunk) &&
              at.destination == symbols.at(thunk).address) {
            window.reg = reg;
            found = true;
          }
        if (!found)
          return fail("unsupported dispatcher retpoline register");
        window.target = at.destination;
        break;
      }
      case ct_kernel_interrupt_window_kind::return_thunk:
        if (!at.branch || !at.direct || at.conditional || at.size != 5 ||
            uint8_t(at.bytes[0]) != 0xe9 ||
            !symbols.count("__x86_return_thunk") ||
            at.destination != symbols.at("__x86_return_thunk").address)
          return fail("unsupported dispatcher return-thunk patch encoding");
        window.target = at.destination;
        break;
      case ct_kernel_interrupt_window_kind::endbr_seal:
        if (at.bytes != llvm::StringRef("\xf3\x0f\x1e\xfa", 4))
          return fail("unsupported dispatcher ENDBR seal encoding");
        break;
      case ct_kernel_interrupt_window_kind::tracepoint_call: {
        if (!at.call || !at.direct || at.size != 5 ||
            uint8_t(at.bytes[0]) != 0xe8 || (window.key & 1))
          return fail("unsupported dispatcher static-call instruction");
        window.key &= ~UINT64_C(3);
        const auto key = std::find_if(
            symbols.begin(), symbols.end(), [&](const auto &symbol) {
              return symbol.second.address == window.key &&
                     llvm::StringRef(symbol.first).starts_with("__SCK__");
            });
        if (key == symbols.end() || key->second.type != STT_OBJECT ||
            key->second.size < sizeof(uint64_t))
          return fail("unproved dispatcher static-call key");
        const auto suffix = key->first.substr(7);
        const auto trampoline = symbols.find("__SCT__" + suffix);
        const auto initial = image_bytes(window.key, 8);
        if (trampoline == symbols.end() ||
            trampoline->second.type != STT_FUNC ||
            trampoline->second.address != at.destination || initial.size() != 8)
          return fail("unproved dispatcher static-call trampoline");
        std::memcpy(&window.target, initial.data(), 8);
        const auto expected = symbols.find(
            suffix == "WARN_trap" ? "__WARN_trap"
                                  : "__traceiter_" + suffix.substr(8));
        if ((suffix != "WARN_trap" &&
             !llvm::StringRef(suffix).starts_with("tp_func_")) ||
            expected == symbols.end() || expected->second.type != STT_FUNC ||
            expected->second.address != window.target)
          return fail("unproved dispatcher static-call initial target");
        if (suffix == "WARN_trap")
          window.kind = ct_kernel_interrupt_window_kind::warning_call;
        break;
      }
      case ct_kernel_interrupt_window_kind::relocate32:
      case ct_kernel_interrupt_window_kind::relocate64:
        break;
      default:
        return fail("unexpected dispatcher patch metadata kind");
      }
      proof.windows.push_back(window);
    }
    for (const auto &[pc, instruction] : code) {
      if ((instruction.branch || instruction.call) && !instruction.direct)
        return fail(std::string("unproved indirect dispatcher branch: ") +
                    name);
      if (instruction.branch && instruction.direct &&
          !code.count(instruction.destination) &&
          !function_addresses.count(instruction.destination))
        return fail(
            std::string("branch escapes proved dispatcher boundaries: ") +
            name);
    }
    const auto reg = [&](const llvm::MCInst &instruction, unsigned operand) {
      return operand < instruction.getNumOperands() &&
                     instruction.getOperand(operand).isReg()
                 ? unsigned(instruction.getOperand(operand).getReg())
                 : 0;
    };
    const auto load = [&](const Instruction &instruction, unsigned destination,
                          unsigned base, uint32_t displacement) {
      const auto &decoded = instruction.decoded;
      return descriptions->getName(decoded.getOpcode()) == "MOV64rm" &&
             decoded.getNumOperands() == 6 &&
             reg(decoded, 0) == tracked[destination] &&
             reg(decoded, 1) == tracked[base] &&
             decoded.getOperand(2).isImm() &&
             decoded.getOperand(2).getImm() == 1 && !reg(decoded, 3) &&
             decoded.getOperand(4).isImm() &&
             decoded.getOperand(4).getImm() == displacement && !reg(decoded, 5);
    };
    unsigned hrtimer_target = 13, hrtimer_object = 3;
    if (kind == ct_kernel_interrupt_kind::hrtimer) {
      unsigned matches = 0;
      for (const auto &[pc, instruction] : code)
        for (const auto &[target_reg, object_reg] :
             {std::pair{13U, 3U}, std::pair{12U, 14U}})
          if (load(instruction, target_reg, object_reg,
                   layout.hrtimer_function) &&
              code.count(pc + instruction.size) &&
              code.at(pc + instruction.size).call &&
              code.at(pc + instruction.size).direct &&
              code.at(pc + instruction.size).destination ==
                  symbols.at("_raw_spin_unlock_irqrestore").address) {
            hrtimer_target = target_reg;
            hrtimer_object = object_reg;
            ++matches;
          }
      if (matches != 1)
        return fail("unproved or ambiguous hrtimer saved-target registers");
      const auto thunk =
          symbols.find(hrtimer_target == 12 ? "__x86_indirect_thunk_r12"
                                            : "__x86_indirect_thunk_r13");
      if (thunk == symbols.end() || !thunk->second.address ||
          !sections.count(thunk->second.section))
        return fail("required hrtimer thunk is unavailable");
      const auto &section = sections.at(thunk->second.section);
      if (!section.executable || thunk->second.address < section.address ||
          thunk->second.address - section.address >= section.bytes.size())
        return fail("required hrtimer thunk is not executable");
    }
    std::map<uint64_t, State> states;
    State initial{};
    if (kind == ct_kernel_interrupt_kind::hard_irq)
      initial[7] = descriptor;
    if (kind == ct_kernel_interrupt_kind::threaded_irq)
      initial[6] = action;
    if (kind == ct_kernel_interrupt_kind::timer_list) {
      initial[6] = timer_function;
      initial[7] = timer_object;
    }
    states.emplace(entry->second.address, initial);
    std::deque<uint64_t> pending{entry->second.address};
    while (!pending.empty()) {
      const auto pc = pending.front();
      pending.pop_front();
      const auto &instruction = code.at(pc);
      const auto &decoded = instruction.decoded;
      const auto &description = descriptions->get(decoded.getOpcode());
      const auto before = states.at(pc);
      auto after = before;
      const auto invalidate = [&](unsigned changed) {
        for (size_t index = 0; index < tracked.size(); ++index)
          if (registers->regsOverlap(changed, tracked[index]))
            after[index] = unknown;
      };
      for (unsigned index = 0;
           index < description.getNumDefs() && index < decoded.getNumOperands();
           ++index)
        if (reg(decoded, index))
          invalidate(reg(decoded, index));
      for (unsigned changed : description.implicit_defs())
        invalidate(changed);
      if (descriptions->getName(decoded.getOpcode()) == "MOV64rr")
        for (size_t destination = 0; destination < tracked.size();
             ++destination)
          for (size_t source = 0; source < tracked.size(); ++source)
            if (reg(decoded, 0) == tracked[destination] &&
                reg(decoded, 1) == tracked[source])
              after[destination] = before[source];
      for (size_t destination = 0; destination < tracked.size(); ++destination)
        for (size_t base = 0; base < tracked.size(); ++base) {
          if (before[base] == descriptor &&
              load(instruction, destination, base, layout.irq_desc_action))
            after[destination] = action;
          if (before[base] != action)
            continue;
          if (load(instruction, destination, base, layout.irqaction_next))
            after[destination] = action;
          else if (load(instruction, destination, base,
                        layout.irqaction_handler))
            after[destination] = handler;
          else if (load(instruction, destination, base,
                        layout.irqaction_thread_fn))
            after[destination] = thread;
        }
      if (kind == ct_kernel_interrupt_kind::hrtimer &&
          load(instruction, hrtimer_target, hrtimer_object,
               layout.hrtimer_function)) {
        after[hrtimer_target] = timer_function;
        after[hrtimer_object] = timer_object;
      }
      if (kind == ct_kernel_interrupt_kind::tasklet) {
        if (load(instruction, 2, 3, layout.tasklet_function)) {
          after[2] = timer_function;
          after[3] = timer_object;
        }
        if (before[3] == timer_object &&
            load(instruction, 7, 3, layout.tasklet_data))
          after[7] = timer_data;
      }
      if (instruction.call)
        for (unsigned index : {0, 1, 2, 6, 7, 8, 9, 10, 11})
          after[index] = unknown;
      const auto propagate = [&](uint64_t successor) {
        if (!code.count(successor))
          return;
        auto [found, inserted] = states.emplace(successor, after);
        bool changed = inserted;
        if (!inserted)
          for (size_t index = 0; index < after.size(); ++index)
            if (found->second[index] != after[index] &&
                found->second[index] != unknown) {
              found->second[index] = unknown;
              changed = true;
            }
        if (changed)
          pending.push_back(successor);
      };
      if (instruction.branch && instruction.direct)
        propagate(instruction.destination);
      if (instruction.static_destination)
        propagate(instruction.static_destination);
      if (!instruction.returns &&
          (!instruction.branch || instruction.conditional ||
           instruction.static_destination))
        propagate(pc + instruction.size);
    }
    size_t matches = 0;
    bool tasklet_entry = false, tasklet_exit = false;
    for (const auto &[pc, instruction] : code) {
      if (!instruction.call || !instruction.direct)
        continue;
      if (kind == ct_kernel_interrupt_kind::tasklet) {
        const bool entering =
            instruction.destination ==
            symbols.at("__SCT__tp_func_tasklet_entry").address;
        const bool exiting = instruction.destination ==
                             symbols.at("__SCT__tp_func_tasklet_exit").address;
        if (entering || exiting) {
          if (!states.count(pc) || states.at(pc)[3] != timer_object ||
              states.at(pc)[6] != timer_object ||
              states.at(pc)[2] != timer_function)
            return fail("unproved tasklet tracepoint arguments");
          tasklet_entry |= entering;
          tasklet_exit |= exiting;
        }
      }
      const auto thunk =
          symbols
              .at(kind == ct_kernel_interrupt_kind::hrtimer
                      ? (hrtimer_target == 12 ? "__x86_indirect_thunk_r12"
                                              : "__x86_indirect_thunk_r13")
                  : kind == ct_kernel_interrupt_kind::timer_list
                      ? "__x86_indirect_thunk_rbp"
                  : kind == ct_kernel_interrupt_kind::tasklet
                      ? "__x86_indirect_thunk_rdx"
                      : "__x86_indirect_thunk_rax")
              .address;
      if (indirect_thunks.count(instruction.destination) &&
          instruction.destination != thunk)
        return fail(std::string("unsupported callback target register: ") +
                    name);
      if ((kind == ct_kernel_interrupt_kind::hard_irq ||
           kind == ct_kernel_interrupt_kind::threaded_irq) &&
          states.count(pc) &&
          states.at(pc)[0] ==
              (kind == ct_kernel_interrupt_kind::hard_irq ? handler : thread) &&
          instruction.destination != thunk)
        return fail(
            std::string(
                "callback target is not invoked by the proved thunk: ") +
            name);
      if (instruction.destination != thunk)
        continue;
      if ((instruction.size != 5 && instruction.size != 6) ||
          static_cast<unsigned char>(instruction.bytes[instruction.size - 5]) !=
              0xe8 ||
          (instruction.size == 6 &&
           static_cast<unsigned char>(instruction.bytes[0]) != 0x2e))
        return fail(std::string("unsupported callback CALL encoding: ") + name);
      if (!states.count(pc))
        return fail(std::string("unreachable callback candidate: ") + name);
      ct_kernel_interrupt_dispatch dispatch{};
      dispatch.kind = kind;
      dispatch.call_pc = pc;
      dispatch.return_pc = pc + instruction.size;
      dispatch.witness_pc = pc;
      if (kind == ct_kernel_interrupt_kind::hrtimer) {
        // Both alternatives of each jump label must retain the callback
        // target and object across the unlock and optional tracing calls.
        const auto &state = states.at(pc);
        const Instruction *loaded = nullptr;
        for (const auto &[address, candidate] : code)
          if (load(candidate, hrtimer_target, hrtimer_object,
                   layout.hrtimer_function)) {
            if (loaded)
              return fail("ambiguous hrtimer callback loads");
            loaded = &candidate;
          }
        if (!loaded || state[hrtimer_target] != timer_function ||
            state[hrtimer_object] != timer_object || state[7] != timer_object ||
            !code.count(loaded->pc + loaded->size) ||
            !code.at(loaded->pc + loaded->size).call ||
            !code.at(loaded->pc + loaded->size).direct ||
            code.at(loaded->pc + loaded->size).destination !=
                symbols.at("_raw_spin_unlock_irqrestore").address)
          return fail("unsupported hrtimer saved-target sequence");
        dispatch.target = ct_kernel_interrupt_target::saved_register;
        dispatch.reg = hrtimer_target == 12 ? ct_kernel_interrupt_register::r12
                                            : ct_kernel_interrupt_register::r13;
        dispatch.witness_pc = loaded->pc;
      } else if (kind == ct_kernel_interrupt_kind::timer_list) {
        // call_timer_fn receives a captured callback separately from the
        // timer object. Preserve that exact value through every static-branch
        // alternative: the callback may change or free the timer before a
        // tail transfer reaches another canonical entry.
        const auto &state = states.at(pc);
        if (state[5] != timer_function || state[7] != timer_object)
          return fail("unsupported timer_list saved-target sequence");
        dispatch.target = ct_kernel_interrupt_target::saved_register;
        dispatch.reg = ct_kernel_interrupt_register::rbp;
        dispatch.witness_pc = entry->second.address;
      } else if (kind == ct_kernel_interrupt_kind::tasklet) {
        const auto &state = states.at(pc);
        if (state[3] != timer_object || state[2] != timer_function ||
            (state[7] != timer_object && state[7] != timer_data))
          return fail("unproved tasklet callback target or argument");
        dispatch.target = ct_kernel_interrupt_target::tasklet_token;
        dispatch.reg = ct_kernel_interrupt_register::rdx;
        dispatch.witness_pc = entry->second.address;
      } else {
        const auto &state = states.at(pc);
        const Value wanted =
            kind == ct_kernel_interrupt_kind::hard_irq ? handler : thread;
        if (state[3] != action || state[0] != wanted)
          return fail(std::string("unproved irqaction target provenance: ") +
                      name);
        dispatch.target = ct_kernel_interrupt_target::saved_register_word;
        dispatch.reg = ct_kernel_interrupt_register::rbx;
        dispatch.word_offset = kind == ct_kernel_interrupt_kind::hard_irq
                                   ? layout.irqaction_handler
                                   : layout.irqaction_thread_fn;
        // Bind the loaded target to this exact saved RBX, not just to any
        // irqaction value. No intervening write, call or branch entry may
        // replace either register after the callback word was loaded.
        auto loaded = code.find(pc);
        bool argument = false, contiguous = true;
        while (loaded != code.begin()) {
          const auto next = loaded;
          --loaded;
          if (loaded->first + loaded->second.size != next->first) {
            contiguous = false;
            break;
          }
          const auto &decoded = loaded->second.decoded;
          const auto opcode = descriptions->getName(decoded.getOpcode());
          if (opcode.starts_with("NOOP"))
            continue;
          if (!argument && kind == ct_kernel_interrupt_kind::hard_irq &&
              opcode == "MOV32rr" &&
              llvm::StringRef(registers->getName(reg(decoded, 0))) == "EDI" &&
              llvm::StringRef(registers->getName(reg(decoded, 1))) == "R13D") {
            argument = true;
            continue;
          }
          break;
        }
        if (!contiguous || !load(loaded->second, 0, 3, dispatch.word_offset))
          return fail(std::string("callback word is not loaded at the call: ") +
                      name);
        for (const auto &[address, edge] : code) {
          if ((edge.branch && edge.direct && edge.destination > loaded->first &&
               edge.destination <= pc) ||
              (edge.static_destination > loaded->first &&
               edge.static_destination <= pc))
            return fail(
                std::string("control flow bypasses the callback load: ") +
                name);
        }
        dispatch.witness_pc = loaded->first;
      }
      const auto section = sections.at(entry->second.section);
      if (dispatch.witness_pc < section.address ||
          dispatch.return_pc < dispatch.witness_pc ||
          dispatch.return_pc - section.address > section.bytes.size())
        return fail(std::string("callback witness leaves its code section: ") +
                    name);
      const auto witness =
          section.bytes.substr(dispatch.witness_pc - section.address,
                               dispatch.return_pc - dispatch.witness_pc);
      dispatch.witness.assign(witness.bytes_begin(), witness.bytes_end());
      proof.dispatches.push_back(std::move(dispatch));
      ++matches;
    }
    if (kind == ct_kernel_interrupt_kind::tasklet &&
        (matches != 2 || !tasklet_entry || !tasklet_exit))
      return fail("missing tasklet callback or entry/exit tracepoint proof");
    if (!matches || ((kind == ct_kernel_interrupt_kind::hrtimer ||
                      kind == ct_kernel_interrupt_kind::timer_list) &&
                     matches != 1))
      return fail(
          std::string("missing or ambiguous supported callback dispatch: ") +
          name);
  }
  std::sort(proof.dispatches.begin(), proof.dispatches.end(),
            [](const auto &left, const auto &right) {
              return left.return_pc < right.return_pc;
            });
  std::sort(
      proof.windows.begin(), proof.windows.end(),
      [](const auto &left, const auto &right) { return left.pc < right.pc; });
  for (size_t index = 1; index < proof.windows.size(); ++index)
    if (proof.windows[index].pc - proof.windows[index - 1].pc <
        proof.windows[index - 1].size)
      return fail("overlapping live-code binding windows");
  return true;
}

static bool interrupt_archive(ct_kernel_interrupt_proof &proof,
                              std::vector<unsigned char> &bytes, bool reading,
                              const std::string &key) {
  ct_analysis_archive archive{bytes, reading};
  const auto text = [&](std::string &value, size_t bound) {
    uint32_t size = value.size();
    archive.field(size);
    if (!archive.valid || size > bound ||
        (reading && size > bytes.size() - archive.offset)) {
      archive.valid = false;
      return;
    }
    if (reading) {
      value.assign(
          reinterpret_cast<const char *>(bytes.data() + archive.offset), size);
      archive.offset += size;
    } else {
      bytes.insert(bytes.end(), value.begin(), value.end());
    }
  };
  std::string identity = key;
  text(identity, 64);
  if (!archive.valid || identity != key)
    return false;
  text(proof.build_id, 128);
  text(proof.image_digest, 64);
  text(proof.relocation_digest, 64);
  archive.fields(proof.text_address, proof.anchor_address);
  const auto pool = [&](auto &items, size_t maximum, auto fields) {
    if (items.size() > UINT32_MAX) {
      archive.valid = false;
      return;
    }
    uint32_t count = items.size();
    archive.field(count);
    if (!archive.valid || count > maximum ||
        (reading && count > bytes.size() - archive.offset)) {
      archive.valid = false;
      return;
    }
    if (reading)
      items.resize(count);
    for (auto &item : items) {
      if (!archive.valid)
        break;
      fields(item);
    }
  };
  size_t total = 0;
  pool(proof.code, uint64_t(UINT32_MAX), [&](auto &range) {
    archive.field(range.address);
    if (range.bytes.size() > UINT32_MAX) {
      archive.valid = false;
      return;
    }
    uint32_t count = range.bytes.size();
    archive.field(count);
    if (!archive.valid || count > SIZE_MAX - total ||
        (reading && count > bytes.size() - archive.offset)) {
      archive.valid = false;
      return;
    }
    total += count;
    if (reading) {
      range.bytes.assign(bytes.begin() + archive.offset,
                         bytes.begin() + archive.offset + count);
      archive.offset += count;
    } else {
      bytes.insert(bytes.end(), range.bytes.begin(), range.bytes.end());
    }
  });
  pool(proof.windows, uint64_t(UINT32_MAX), [&](auto &window) {
    uint32_t kind = uint32_t(window.kind);
    archive.fields(kind, window.pc, window.target, window.key, window.size,
                   window.reg);
    if (kind > uint32_t(ct_kernel_interrupt_window_kind::relocate64))
      archive.valid = false;
    if (reading)
      window.kind = ct_kernel_interrupt_window_kind(kind);
  });
  pool(proof.jumps, uint64_t(UINT32_MAX),
       [&](auto &jump) { archive.fields(jump.pc, jump.target, jump.size); });
  pool(proof.dispatches, uint64_t(UINT32_MAX), [&](auto &dispatch) {
    uint32_t kind = uint32_t(dispatch.kind), target = uint32_t(dispatch.target);
    uint32_t reg = uint32_t(dispatch.reg);
    archive.fields(kind, target, reg, dispatch.word_offset, dispatch.call_pc,
                   dispatch.return_pc, dispatch.witness_pc);
    if (kind > uint32_t(ct_kernel_interrupt_kind::tasklet) ||
        target > uint32_t(ct_kernel_interrupt_target::tasklet_token) ||
        reg > uint32_t(ct_kernel_interrupt_register::r12))
      archive.valid = false;
    if (reading) {
      dispatch.kind = ct_kernel_interrupt_kind(kind);
      dispatch.target = ct_kernel_interrupt_target(target);
      dispatch.reg = ct_kernel_interrupt_register(reg);
      dispatch.witness.clear();
    }
  });
  return archive.complete();
}

static bool
interrupt_restored_valid(const std::vector<unsigned char> &image,
                         const ct_kernel_interrupt_layout &layout,
                         const std::vector<unsigned char> &relocations,
                         ct_kernel_interrupt_proof &proof) {
  if (image.size() < sizeof(Elf64_Ehdr) || proof.code.empty() ||
      proof.code.size() > uint64_t(UINT32_MAX) || proof.windows.empty() ||
      proof.windows.size() > uint64_t(UINT32_MAX) || proof.dispatches.empty() ||
      proof.dispatches.size() > uint64_t(UINT32_MAX))
    return false;
  Elf64_Ehdr header;
  std::memcpy(&header, image.data(), sizeof(header));
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 ||
      header.e_type != ET_EXEC || !header.e_shnum ||
      header.e_shentsize != sizeof(Elf64_Shdr) ||
      header.e_shoff > image.size() ||
      header.e_shnum > (image.size() - header.e_shoff) / sizeof(Elf64_Shdr) ||
      header.e_shstrndx >= header.e_shnum)
    return false;
  std::vector<Elf64_Shdr> sections(header.e_shnum);
  std::memcpy(sections.data(), image.data() + header.e_shoff,
              sections.size() * sizeof(Elf64_Shdr));
  for (const auto &section : sections)
    if (section.sh_size > UINT64_MAX - section.sh_addr ||
        (section.sh_type != SHT_NOBITS &&
         (section.sh_offset > image.size() ||
          section.sh_size > image.size() - section.sh_offset)))
      return false;
  const auto &names = sections[header.e_shstrndx];
  if (names.sh_type != SHT_STRTAB)
    return false;
  const auto string = [&](const Elf64_Shdr &table,
                          uint64_t offset) -> const char * {
    if (table.sh_type != SHT_STRTAB || offset >= table.sh_size)
      return nullptr;
    const char *text =
        reinterpret_cast<const char *>(image.data() + table.sh_offset + offset);
    return std::memchr(text, 0, table.sh_size - offset) ? text : nullptr;
  };
  std::map<std::string, const Elf64_Shdr *> named;
  std::map<std::string, Elf64_Sym> symbols;
  std::string build_id;
  const auto data = [&](uint64_t address,
                        uint64_t size) -> const unsigned char * {
    for (const auto &section : sections)
      if (section.sh_type != SHT_NOBITS && address >= section.sh_addr &&
          address - section.sh_addr <= section.sh_size &&
          size <= section.sh_size - (address - section.sh_addr))
        return image.data() + section.sh_offset + address - section.sh_addr;
    return nullptr;
  };
  for (const auto &section : sections) {
    const char *name = string(names, section.sh_name);
    if (!name || (*name && !named.emplace(name, &section).second))
      return false;
    if (section.sh_type == SHT_NOTE) {
      uint64_t offset = 0;
      while (offset < section.sh_size) {
        if (sizeof(Elf64_Nhdr) > section.sh_size - offset)
          return false;
        Elf64_Nhdr note;
        std::memcpy(&note, image.data() + section.sh_offset + offset,
                    sizeof(note));
        offset += sizeof(note);
        const uint64_t name_size = (uint64_t(note.n_namesz) + 3) & ~UINT64_C(3);
        const uint64_t data_size = (uint64_t(note.n_descsz) + 3) & ~UINT64_C(3);
        if (name_size > section.sh_size - offset ||
            data_size > section.sh_size - offset - name_size)
          return false;
        const auto *bytes = image.data() + section.sh_offset + offset;
        if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
            !std::memcmp(bytes, "GNU", 4)) {
          if (!build_id.empty() || !note.n_descsz || note.n_descsz > 64)
            return false;
          for (unsigned index = 0; index < note.n_descsz; ++index) {
            const auto value = bytes[name_size + index];
            build_id += "0123456789abcdef"[value >> 4];
            build_id += "0123456789abcdef"[value & 15];
          }
        }
        offset += name_size + data_size;
      }
    }
    if (section.sh_type != SHT_SYMTAB)
      continue;
    if (section.sh_entsize != sizeof(Elf64_Sym) ||
        section.sh_size % sizeof(Elf64_Sym) ||
        section.sh_link >= sections.size())
      return false;
    for (uint64_t offset = 0; offset < section.sh_size;
         offset += sizeof(Elf64_Sym)) {
      Elf64_Sym symbol;
      std::memcpy(&symbol, image.data() + section.sh_offset + offset,
                  sizeof(symbol));
      const char *spelling = string(sections[section.sh_link], symbol.st_name);
      if (!spelling)
        return false;
      const std::string_view label(spelling);
      if (label != "_text" && label != "hrtimer_start_range_ns" &&
          label != "__x86_return_thunk" && label != "__WARN_trap" &&
          label != "__start_static_call_sites" &&
          label != "__stop_static_call_sites" &&
          label != "__start___jump_table" && label != "__stop___jump_table" &&
          label.rfind("__x86_indirect_thunk_", 0) &&
          label.rfind("__SCK__", 0) && label.rfind("__SCT__", 0) &&
          label.rfind("__traceiter_", 0) &&
          label.rfind("__hrtimer_run_queues", 0) &&
          label.rfind("__handle_irq_event_percpu", 0) &&
          label.rfind("irq_thread_fn", 0) && label.rfind("call_timer_fn", 0) &&
          label.rfind("tasklet_action_common", 0))
        continue;
      if (symbol.st_shndx == SHN_UNDEF)
        continue;
      const auto [position, inserted] = symbols.emplace(spelling, symbol);
      if (!inserted && (position->second.st_value != symbol.st_value ||
                        position->second.st_size != symbol.st_size))
        return false;
    }
  }
  const auto symbol_address = [&](const std::string &name) {
    const auto found = symbols.find(name);
    return found == symbols.end() ? uint64_t(0) : found->second.st_value;
  };
  if (build_id != proof.build_id || !proof.text_address ||
      proof.text_address != symbol_address("_text") || !proof.anchor_address ||
      proof.anchor_address != symbol_address("hrtimer_start_range_ns"))
    return false;
  const bool tasklets = layout.tasklet_function || layout.tasklet_data;
  const char *owners[] = {"__hrtimer_run_queues", "__handle_irq_event_percpu",
                          "irq_thread_fn", "call_timer_fn",
                          "tasklet_action_common"};
  std::map<uint64_t, std::pair<uint64_t, unsigned>> extents;
  for (unsigned kind = 0; kind < (tasklets ? 5U : 4U); ++kind) {
    for (const char *suffix : {"", ".cold"}) {
      const auto found = symbols.find(std::string(owners[kind]) + suffix);
      if (found == symbols.end()) {
        if (!*suffix)
          return false;
        continue;
      }
      const auto &symbol = found->second;
      if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC || !symbol.st_size ||
          symbol.st_shndx >= sections.size() ||
          !(sections[symbol.st_shndx].sh_flags & SHF_EXECINSTR) ||
          (sections[symbol.st_shndx].sh_flags & SHF_WRITE) ||
          !data(symbol.st_value, symbol.st_size) ||
          !extents
               .emplace(symbol.st_value, std::make_pair(symbol.st_size, kind))
               .second)
        return false;
    }
  }
  if (extents.size() != proof.code.size())
    return false;
  size_t total = 0;
  std::set<uint64_t> seen_ranges;
  for (const auto &range : proof.code) {
    const auto found = extents.find(range.address);
    if (found == extents.end() || found->second.first != range.bytes.size() ||
        range.bytes.size() > SIZE_MAX - total ||
        !seen_ranges.insert(range.address).second ||
        std::memcmp(range.bytes.data(), data(range.address, range.bytes.size()),
                    range.bytes.size()))
      return false;
    total += range.bytes.size();
  }
  const auto contained = [&](uint64_t address, uint64_t size) {
    const auto next = extents.upper_bound(address);
    if (next == extents.begin())
      return false;
    const auto &range = *std::prev(next);
    return address - range.first < range.second.first &&
           size <= range.second.first - (address - range.first);
  };
  std::map<uint64_t, std::pair<unsigned, uint64_t>> expected;
  for (const auto &[name, kind] : {std::pair{".retpoline_sites", 0U},
                                   {".return_sites", 1U},
                                   {".ibt_endbr_seal", 2U}}) {
    const auto found = named.find(name);
    if (found == named.end())
      continue;
    const auto &section = *found->second;
    if (section.sh_size % 4)
      return false;
    for (uint64_t offset = 0; offset < section.sh_size; offset += 4) {
      int32_t relative;
      std::memcpy(&relative, image.data() + section.sh_offset + offset, 4);
      const uint64_t pc = section.sh_addr + offset + int64_t(relative);
      if (contained(pc, 1) &&
          !expected.emplace(pc, std::make_pair(kind, 0)).second)
        return false;
    }
  }
  for (bool jumps : {false, true}) {
    const auto begin = symbol_address(jumps ? "__start___jump_table"
                                            : "__start_static_call_sites");
    const auto end = symbol_address(jumps ? "__stop___jump_table"
                                          : "__stop_static_call_sites");
    const unsigned size = jumps ? 16 : 8;
    if (!begin && !end)
      continue;
    const auto *bytes = end >= begin ? data(begin, end - begin) : nullptr;
    if (!bytes || (end - begin) % size)
      return false;
    for (uint64_t offset = 0; offset < end - begin; offset += size) {
      int32_t relative[2];
      std::memcpy(relative, bytes + offset, sizeof(relative));
      const uint64_t pc = begin + offset + int64_t(relative[0]);
      uint64_t target = begin + offset + 4 + int64_t(relative[1]);
      if (!jumps)
        target &= ~UINT64_C(3);
      if (contained(pc, 1) &&
          !expected.emplace(pc, std::make_pair(jumps ? 5U : 3U, target)).second)
        return false;
    }
  }
  unsigned group = 0;
  for (size_t offset = 0; offset < relocations.size(); offset += 4) {
    int32_t field;
    std::memcpy(&field, relocations.data() + offset, 4);
    if (!field) {
      ++group;
      continue;
    }
    const uint64_t pc = uint64_t(int64_t(field));
    if ((group != 1 && group != 2) || field >= 0)
      return false;
    if (contained(pc, 1) &&
        !expected.emplace(pc, std::make_pair(group == 1 ? 7U : 6U, 0)).second)
      return false;
  }
  if (group != 2 || expected.size() != proof.windows.size())
    return false;
  uint64_t end = 0;
  std::map<uint64_t, const ct_kernel_interrupt_window *> calls;
  std::map<uint64_t, const ct_kernel_interrupt_window *> jumps;
  for (const auto &window : proof.windows) {
    const auto found = expected.find(window.pc);
    const unsigned kind = unsigned(window.kind);
    if (found == expected.end() || window.pc < end || !window.size ||
        !contained(window.pc, window.size) ||
        (kind == 4 ? found->second.first != 3 : kind != found->second.first))
      return false;
    const auto *bytes = data(window.pc, window.size);
    if (kind == 0) {
      const char *reg = window.reg == 0    ? "rax"
                        : window.reg == 2  ? "rdx"
                        : window.reg == 5  ? "rbp"
                        : window.reg == 12 ? "r12"
                        : window.reg == 13 ? "r13"
                                           : "";
      if (!*reg ||
          window.target !=
              symbol_address(std::string("__x86_indirect_thunk_") + reg))
        return false;
      calls.emplace(window.pc + window.size, &window);
    } else if (kind == 1 &&
               window.target != symbol_address("__x86_return_thunk")) {
      return false;
    } else if (kind == 3 || kind == 4) {
      if (window.key != found->second.second)
        return false;
      const auto key =
          std::find_if(symbols.begin(), symbols.end(), [&](const auto &item) {
            return item.second.st_value == window.key &&
                   item.first.rfind("__SCK__", 0) == 0;
          });
      if (key == symbols.end() ||
          ELF64_ST_TYPE(key->second.st_info) != STT_OBJECT ||
          key->second.st_size < 8)
        return false;
      const auto suffix = key->first.substr(7);
      const auto *value = data(window.key, 8);
      if (!value || window.size != 5 || bytes[0] != 0xe8 ||
          kctrace_interrupt_word(value, 8) != window.target ||
          window.pc + 5 + kctrace_interrupt_relative(bytes + 1) !=
              symbol_address("__SCT__" + suffix) ||
          (kind == 4 ? suffix != "WARN_trap" ||
                           window.target != symbol_address("__WARN_trap")
                     : suffix.rfind("tp_func_", 0) ||
                           window.target != symbol_address("__traceiter_" +
                                                           suffix.substr(8))))
        return false;
    } else if (kind == 5) {
      if (window.target != found->second.second || !contained(window.target, 1))
        return false;
      jumps.emplace(window.pc, &window);
    }
    const kctrace_interrupt_patch patch{window.pc,   window.target,
                                        window.key,  uint8_t(kind),
                                        window.size, window.reg};
    if (!kctrace_interrupt_patch_matches(&patch, bytes, bytes, window.size, 0,
                                         window.target, 0))
      return false;
    end = window.pc + window.size;
  }
  if (jumps.size() != proof.jumps.size())
    return false;
  for (const auto &jump : proof.jumps) {
    const auto found = jumps.find(jump.pc);
    if (found == jumps.end() || found->second->target != jump.target ||
        found->second->size != jump.size)
      return false;
    jumps.erase(found);
  }
  std::array<unsigned, 5> counts{};
  end = 0;
  for (auto &dispatch : proof.dispatches) {
    const unsigned kind = unsigned(dispatch.kind);
    const auto call = calls.find(dispatch.return_pc);
    if (kind >= (tasklets ? 5U : 4U) || dispatch.return_pc <= end ||
        call == calls.end() || call->second->pc != dispatch.call_pc ||
        dispatch.witness_pc > dispatch.call_pc ||
        !contained(dispatch.witness_pc,
                   dispatch.return_pc - dispatch.witness_pc))
      return false;
    const auto owner = std::prev(extents.upper_bound(dispatch.call_pc));
    if (owner->second.second != kind)
      return false;
    const auto expected_reg =
        kind == 0
            ? (call->second->reg == 12 ? ct_kernel_interrupt_register::r12
                                       : ct_kernel_interrupt_register::r13)
        : kind == 3 ? ct_kernel_interrupt_register::rbp
        : kind == 4 ? ct_kernel_interrupt_register::rdx
                    : ct_kernel_interrupt_register::rbx;
    const auto expected_target =
        kind == 4 ? ct_kernel_interrupt_target::tasklet_token
        : kind == 1 || kind == 2
            ? ct_kernel_interrupt_target::saved_register_word
            : ct_kernel_interrupt_target::saved_register;
    if (dispatch.reg != expected_reg || dispatch.target != expected_target ||
        dispatch.word_offset != (kind == 1   ? layout.irqaction_handler
                                 : kind == 2 ? layout.irqaction_thread_fn
                                             : 0) ||
        call->second->reg !=
            (kind == 0
                 ? (dispatch.reg == ct_kernel_interrupt_register::r12 ? 12U
                                                                      : 13U)
             : kind == 3 ? 5U
             : kind == 4 ? 2U
                         : 0U))
      return false;
    const auto *witness =
        data(dispatch.witness_pc, dispatch.return_pc - dispatch.witness_pc);
    if (!witness)
      return false;
    dispatch.witness.assign(witness,
                            witness + dispatch.return_pc - dispatch.witness_pc);
    calls.erase(call);
    ++counts[kind];
    end = dispatch.return_pc;
  }
  return calls.empty() && counts[0] == 1 && counts[1] && counts[2] &&
         counts[3] == 1 && counts[4] == (tasklets ? 2U : 0U);
}

bool ct_kernel_interrupt_prepare(
    const std::vector<unsigned char> &vmlinux,
    const std::string &expected_build_id,
    const ct_kernel_interrupt_layout &layout,
    const std::vector<unsigned char> &boot_relocations,
    const std::string &relocator_identity,
    const std::function<bool(std::string &)> &verify_relocations,
    ct_kernel_interrupt_proof &proof, std::string &error, bool *reused) {
  proof = {};
  error.clear();
  if (reused)
    *reused = false;
  if (vmlinux.size() < sizeof(Elf64_Ehdr) || boot_relocations.size() < 8 ||
      boot_relocations.size() % 4 || relocator_identity.empty() ||
      !verify_relocations || expected_build_id.empty() ||
      expected_build_id.size() > 128 || expected_build_id.size() % 2 ||
      expected_build_id.find_first_not_of("0123456789abcdef") !=
          std::string::npos) {
    error = "kernel interrupt cache requires exact bounded image and tool "
            "identities";
    return false;
  }
  const auto digest = [](const std::vector<unsigned char> &bytes) {
    std::string result;
    for (unsigned char value : llvm::SHA256::hash(bytes)) {
      result += "0123456789abcdef"[value >> 4];
      result += "0123456789abcdef"[value & 15];
    }
    return result;
  };
  const auto image_digest = digest(vmlinux),
             relocation_digest = digest(boot_relocations);
  const std::string shape = std::to_string(layout.irq_desc_action) + ':' +
                            std::to_string(layout.irqaction_handler) + ':' +
                            std::to_string(layout.irqaction_next) + ':' +
                            std::to_string(layout.irqaction_thread_fn) + ':' +
                            std::to_string(layout.hrtimer_function) + ':' +
                            std::to_string(layout.tasklet_function) + ':' +
                            std::to_string(layout.tasklet_data);
  const auto key =
      ct_cache_key({"kernel-interrupt", image_digest, relocation_digest,
                    expected_build_id, shape, relocator_identity});
  std::vector<unsigned char> cached;
  if (ct_cache_read("kernel-interrupt", key, cached)) {
    ct_kernel_interrupt_proof restored;
    if (interrupt_archive(restored, cached, true, key) &&
        restored.build_id == expected_build_id &&
        restored.image_digest == image_digest &&
        restored.relocation_digest == relocation_digest &&
        interrupt_restored_valid(vmlinux, layout, boot_relocations, restored)) {
      proof = std::move(restored);
      if (reused)
        *reused = true;
      return true;
    }
  }
  std::vector<unsigned char>().swap(cached);
  if (!verify_relocations(error) ||
      !ct_kernel_interrupt_extract(vmlinux, expected_build_id, layout, proof,
                                   error, boot_relocations))
    return false;
  if (interrupt_restored_valid(vmlinux, layout, boot_relocations, proof) &&
      interrupt_archive(proof, cached, false, key))
    ct_cache_write("kernel-interrupt", key, cached);
  return true;
}
