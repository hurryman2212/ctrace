// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <memory>

#include <gelf.h>
#include <libelf.h>

#include "compiler_hooks.hh"
#include "userspace_patch.hh"

bool ct_compiler_hooks_read(int descriptor, app_pc module_base,
                            ct_compiler_hooks &catalog) {
  catalog = {};
  if (descriptor < 0 || elf_version(EV_CURRENT) == EV_NONE)
    return false;
  std::unique_ptr<Elf, decltype(&elf_end)> elf(
      elf_begin(descriptor, ELF_C_READ, nullptr), elf_end);
  GElf_Ehdr header{};
  if (!elf || !gelf_getehdr(elf.get(), &header) ||
      gelf_getclass(elf.get()) != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 ||
      (header.e_type != ET_EXEC && header.e_type != ET_DYN))
    return false;
  size_t count = 0;
  if (elf_getphdrnum(elf.get(), &count) != 0 || count > INT_MAX)
    return false;
  std::vector<GElf_Phdr> loads;
  uint64_t link_base = UINT64_MAX;
  for (size_t index = 0; index < count; ++index) {
    GElf_Phdr segment{};
    if (!gelf_getphdr(elf.get(), int(index), &segment))
      return false;
    if (segment.p_type != PT_LOAD)
      continue;
    if (segment.p_memsz > UINT64_MAX - segment.p_vaddr)
      return false;
    link_base = std::min(link_base, uint64_t(segment.p_vaddr));
    loads.push_back(segment);
  }
  if (loads.empty())
    return false;
  // Match the module-relative coordinates used by the analysis service.
  link_base &= ~UINT64_C(4095);
  const auto mapped = [&](uint64_t address, uint64_t size, bool executable) {
    if (address < link_base || size > UINT64_MAX - address ||
        address - link_base > UINTPTR_MAX - uintptr_t(module_base) ||
        size > UINTPTR_MAX - uintptr_t(module_base) - (address - link_base))
      return static_cast<app_pc>(nullptr);
    const bool covered =
        std::any_of(loads.begin(), loads.end(), [&](const auto &load) {
          return address >= load.p_vaddr &&
                 address + size <= load.p_vaddr + load.p_memsz &&
                 (!executable || (load.p_flags & PF_X));
        });
    return covered ? module_base + (address - link_base) : nullptr;
  };
  const auto kind_of = [](const char *name) {
    if (name && std::strcmp(name, "__cyg_profile_func_enter") == 0)
      return ct_compiler_hook_kind::Enter;
    if (name && std::strcmp(name, "__cyg_profile_func_exit") == 0)
      return ct_compiler_hook_kind::Exit;
    return ct_compiler_hook_kind::None;
  };
  const auto record = [](auto &entries, app_pc address,
                         ct_compiler_hook_kind kind) {
    const auto [entry, inserted] = entries.emplace(address, kind);
    if (!inserted && entry->second != kind)
      entry->second = ct_compiler_hook_kind::None;
  };
  size_t names = 0;
  if (elf_getshdrstrndx(elf.get(), &names) != 0)
    return false;
  ct_compiler_hooks result;
  for (Elf_Scn *section = nullptr;
       (section = elf_nextscn(elf.get(), section)) != nullptr;) {
    GElf_Shdr shdr{};
    if (!gelf_getshdr(section, &shdr))
      return false;
    const char *name = elf_strptr(elf.get(), names, shdr.sh_name);
    if ((shdr.sh_flags & SHF_EXECINSTR) && shdr.sh_size && name &&
        (std::strcmp(name, ".plt") == 0 || std::strcmp(name, ".plt.sec") == 0 ||
         std::strcmp(name, ".plt.got") == 0 ||
         std::strcmp(name, ".iplt") == 0)) {
      if (app_pc begin = mapped(shdr.sh_addr, shdr.sh_size, true))
        result.linkage.emplace_back(begin, begin + shdr.sh_size);
    }
    if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM &&
        shdr.sh_type != SHT_RELA)
      continue;
    const bool relocations = shdr.sh_type == SHT_RELA;
    const size_t entry_size =
        relocations ? sizeof(Elf64_Rela) : sizeof(Elf64_Sym);
    if (shdr.sh_entsize != entry_size || shdr.sh_size % entry_size ||
        shdr.sh_size / entry_size > INT_MAX)
      return false;
    Elf_Data *data = elf_getdata(section, nullptr);
    if (!data || data->d_size != shdr.sh_size)
      return false;
    Elf_Data *symbols = data;
    GElf_Shdr symtab = shdr;
    if (relocations) {
      Elf_Scn *symbol_section = elf_getscn(elf.get(), shdr.sh_link);
      if (!symbol_section || !gelf_getshdr(symbol_section, &symtab) ||
          (symtab.sh_type != SHT_SYMTAB && symtab.sh_type != SHT_DYNSYM) ||
          symtab.sh_entsize != sizeof(Elf64_Sym) ||
          !(symbols = elf_getdata(symbol_section, nullptr)) ||
          symbols->d_size != symtab.sh_size)
        return false;
    }
    for (size_t index = 0; index < shdr.sh_size / entry_size; ++index) {
      GElf_Sym symbol{};
      GElf_Rela relocation{};
      size_t symbol_index = index;
      if (relocations) {
        if (!gelf_getrela(data, int(index), &relocation))
          return false;
        if ((GELF_R_TYPE(relocation.r_info) != R_X86_64_JUMP_SLOT &&
             GELF_R_TYPE(relocation.r_info) != R_X86_64_GLOB_DAT) ||
            relocation.r_addend)
          continue;
        symbol_index = GELF_R_SYM(relocation.r_info);
      }
      if (symbol_index >= symtab.sh_size / sizeof(Elf64_Sym) ||
          symbol_index > INT_MAX ||
          !gelf_getsym(symbols, int(symbol_index), &symbol))
        return false;
      const auto kind =
          kind_of(elf_strptr(elf.get(), symtab.sh_link, symbol.st_name));
      if (kind == ct_compiler_hook_kind::None)
        continue;
      if (relocations) {
        if (app_pc address =
                mapped(relocation.r_offset, sizeof(uintptr_t), false))
          record(result.slots, address, kind);
      } else if (symbol.st_shndx != SHN_UNDEF &&
                 symbol.st_shndx < SHN_LORESERVE &&
                 (GELF_ST_TYPE(symbol.st_info) == STT_FUNC ||
                  GELF_ST_TYPE(symbol.st_info) == STT_NOTYPE)) {
        if (app_pc address = mapped(symbol.st_value, 1, true))
          record(result.symbols, address, kind);
      }
    }
  }
  catalog = std::move(result);
  return true;
}

ct_compiler_hook_kind ct_compiler_hook_at(void *context,
                                          const ct_compiler_hooks &catalog,
                                          instr_t *instruction) {
  if (!instr_valid(instruction) ||
      (!instr_is_call(instruction) && !instr_is_ubr(instruction) &&
       (!instr_is_mbr(instruction) || instr_is_return(instruction))) ||
      instr_is_far_cti(instruction))
    return ct_compiler_hook_kind::None;
  opnd_t target = instr_get_target(instruction);
  if (opnd_is_pc(target)) {
    app_pc pc = opnd_get_pc(target);
    if (const auto known = catalog.symbols.find(pc);
        known != catalog.symbols.end())
      return known->second;
    if (catalog.slots.empty())
      return ct_compiler_hook_kind::None;
    const auto linkage = std::find_if(
        catalog.linkage.begin(), catalog.linkage.end(), [&](const auto &range) {
          return pc >= range.first && pc < range.second;
        });
    if (linkage == catalog.linkage.end())
      return ct_compiler_hook_kind::None;
    // A normal PLT entry begins with the GOT jump; CET adds one ENDBR64.
    // No resolver, register-indirect trampoline or arbitrary body is followed.
    for (unsigned index = 0; index < 2; ++index) {
      byte bytes[15]{};
      const size_t available =
          std::min(sizeof(bytes), size_t(linkage->second - pc));
      if (!available || !ct_userspace_patch_read_original(pc, available, bytes))
        return ct_compiler_hook_kind::None;
      instr_t stub;
      instr_init(context, &stub);
      byte *next = decode_from_copy(context, bytes, pc, &stub);
      const bool valid = next && next > bytes && next <= bytes + available &&
                         instr_valid(&stub);
      const bool landing =
          valid && !index && instr_get_opcode(&stub) == OP_endbr64;
      const bool jump = valid && instr_is_mbr(&stub) && !instr_is_call(&stub) &&
                        !instr_is_return(&stub) && !instr_is_far_cti(&stub);
      if (jump)
        target = instr_get_target(&stub);
      if (landing)
        pc += next - bytes;
      instr_free(context, &stub);
      if (jump)
        break;
      if (!landing)
        return ct_compiler_hook_kind::None;
    }
  }
  if (opnd_is_rel_addr(target) && opnd_get_segment(target) != DR_SEG_FS &&
      opnd_get_segment(target) != DR_SEG_GS) {
    const auto slot =
        catalog.slots.find(static_cast<app_pc>(opnd_get_addr(target)));
    if (slot != catalog.slots.end())
      return slot->second;
  }
  return ct_compiler_hook_kind::None;
}

static bool compiler_hook_epilogue_step(instr_t &instruction) {
  if (instr_is_nop(&instruction))
    return true;
  const int opcode = instr_get_opcode(&instruction);
  const bool move =
      opcode == OP_mov_ld || opcode == OP_mov_st || opcode == OP_mov_imm;
  const bool arithmetic = opcode == OP_add || opcode == OP_sub;
  if (!move && !arithmetic && opcode != OP_lea && opcode != OP_xor &&
      opcode != OP_pop && opcode != OP_leave)
    return false;
  for (int index = 0; index < instr_num_dsts(&instruction); ++index) {
    const opnd_t destination = instr_get_dst(&instruction, index);
    if (!opnd_is_reg(destination) || !reg_is_gpr(opnd_get_reg(destination)))
      return false;
    const reg_id_t reg = opnd_get_reg(destination);
    if (!reg_overlap(reg, DR_REG_RSP))
      continue;
    if (reg != DR_REG_RSP)
      return false;
    if (opcode == OP_leave)
      continue;
    if (opcode == OP_pop) {
      if (index == 0)
        return false; // POP RSP has an explicit, unknown stack destination.
      continue;
    }
    if ((move || opcode == OP_lea) && instr_num_srcs(&instruction) == 1) {
      const opnd_t source = instr_get_src(&instruction, 0);
      if (move && opnd_is_reg(source) && opnd_get_reg(source) == DR_REG_RBP)
        continue;
      if (opcode == OP_lea && opnd_is_base_disp(source) &&
          (opnd_get_base(source) == DR_REG_RSP ||
           opnd_get_base(source) == DR_REG_RBP) &&
          opnd_get_index(source) == DR_REG_NULL &&
          opnd_get_segment(source) == DR_REG_NULL)
        continue;
    }
    if (arithmetic && instr_num_srcs(&instruction) == 2) {
      const opnd_t first = instr_get_src(&instruction, 0);
      const opnd_t second = instr_get_src(&instruction, 1);
      const opnd_t immediate = opnd_is_immed_int(first) ? first : second;
      const opnd_t original = opnd_is_immed_int(first) ? second : first;
      if (opnd_is_immed_int(immediate) && opnd_is_reg(original) &&
          opnd_get_reg(original) == DR_REG_RSP) {
        const int64_t value = opnd_get_immed_int(immediate);
        if ((opcode == OP_add && value >= 0 && value <= INT32_MAX) ||
            (opcode == OP_sub && value <= 0 && value >= INT32_MIN))
          continue;
      }
    }
    return false;
  }
  // A suffix can restore saved registers or produce the ABI return value.
  // Other memory reads can be source-level work, so retain the normal backend.
  for (int index = 0; index < instr_num_srcs(&instruction); ++index) {
    const opnd_t source = instr_get_src(&instruction, index);
    if (!opnd_is_memory_reference(source) || opcode == OP_lea)
      continue;
    if (!opnd_is_base_disp(source) ||
        (opnd_get_base(source) != DR_REG_RSP &&
         opnd_get_base(source) != DR_REG_RBP) ||
        opnd_get_index(source) != DR_REG_NULL ||
        opnd_get_segment(source) != DR_REG_NULL)
      return false;
  }
  return true;
}

bool ct_compiler_hooks_function(
    void *context, const ct_compiler_hooks &catalog, app_pc module_base,
    app_pc function, const std::vector<ct_flow_instruction> &instructions,
    ct_compiler_hook_function &proof) {
  proof = {};
  if (function < module_base || instructions.empty())
    return false;
  struct Register {
    enum Kind { Unknown, Constant, Stack } kind = Unknown;
    uint64_t value = 0;
    int64_t offset = 0;
  };
  std::array<Register, 16> registers{};
  registers[DR_REG_RSP - DR_REG_RAX].kind = Register::Stack;
  const auto read_register = [&](reg_id_t reg) {
    Register value;
    if (!reg_is_gpr(reg))
      return value;
    const reg_id_t full = reg_to_pointer_sized(reg);
    if (full < DR_REG_RAX || full > DR_REG_R15)
      return value;
    value = registers[full - DR_REG_RAX];
    if (reg != full) {
      if (reg_get_size(reg) == OPSZ_4 && value.kind == Register::Constant)
        value.value = uint32_t(value.value);
      else
        value = {};
    }
    return value;
  };
  const auto add_offset = [](int64_t value, int64_t delta, int64_t &result) {
    if ((delta > 0 && value > INT64_MAX - delta) ||
        (delta < 0 && value < INT64_MIN - delta))
      return false;
    result = value + delta;
    return true;
  };
  const auto address_of = [&](opnd_t operand) {
    Register address;
    if (opnd_is_rel_addr(operand) || opnd_is_abs_addr(operand)) {
      address.kind = Register::Constant;
      address.value = reinterpret_cast<uintptr_t>(opnd_get_addr(operand));
    } else if (opnd_is_base_disp(operand) &&
               opnd_get_index(operand) == DR_REG_NULL &&
               opnd_get_segment(operand) == DR_REG_NULL) {
      address = read_register(opnd_get_base(operand));
      const int64_t displacement = opnd_get_disp(operand);
      if (address.kind == Register::Constant)
        address.value += uint64_t(displacement);
      else if (address.kind == Register::Stack &&
               !add_offset(address.offset, displacement, address.offset))
        address = {};
    }
    return address;
  };
  ct_compiler_hook_function result;
  enum { EpilogueStep = 1, Return = 2, ExitCall = 4, ExitTail = 8 };
  std::vector<unsigned char> suffixes;
  suffixes.reserve(instructions.size());
  app_pc expected = function;
  uint64_t previous_end = 0;
  for (const auto &item : instructions) {
    if (!item.size || item.size > sizeof(item.bytes) ||
        item.offset < previous_end || item.size > UINT64_MAX - item.offset ||
        item.offset > UINTPTR_MAX - uintptr_t(module_base) ||
        item.size > UINTPTR_MAX - uintptr_t(module_base) - item.offset)
      return false;
    previous_end = item.offset + item.size;
    app_pc pc = module_base + item.offset;
    instr_t instruction;
    instr_init(context, &instruction);
    byte bytes[15]{};
    std::memcpy(bytes, item.bytes, item.size);
    byte *next = decode_from_copy(context, bytes, pc, &instruction);
    if (!next || next != bytes + item.size || !instr_valid(&instruction)) {
      instr_free(context, &instruction);
      return false;
    }
    const auto kind = ct_compiler_hook_at(context, catalog, &instruction);
    unsigned char suffix = instr_get_opcode(&instruction) == OP_ret ? Return
                           : compiler_hook_epilogue_step(instruction)
                               ? EpilogueStep
                               : 0;
    if (kind == ct_compiler_hook_kind::Exit)
      suffix |= instr_is_call(&instruction) ? ExitCall : ExitTail;
    suffixes.push_back(suffix);
    const bool valid_prefix = [&]() {
      if (result.entry || pc < function)
        return true;
      if (pc != expected)
        return false;
      const Register stack = read_register(DR_REG_RSP);
      if (stack.kind != Register::Stack || stack.offset > 0)
        return false;
      if (instr_is_call(&instruction)) {
        const Register argument = read_register(DR_REG_RDI);
        if (kind != ct_compiler_hook_kind::Enter ||
            argument.kind != Register::Constant ||
            argument.value != reinterpret_cast<uintptr_t>(function))
          return false;
        result.entry = pc;
        result.entry_stack_delta = stack.offset;
        return true;
      }
      expected = pc + item.size;
      const int opcode = instr_get_opcode(&instruction);
      if (instr_is_nop(&instruction) || opcode == OP_endbr64)
        return true;
      const bool push = opcode == OP_push || opcode == OP_push_imm;
      const bool pop = opcode == OP_pop;
      const bool move =
          opcode == OP_mov_ld || opcode == OP_mov_st || opcode == OP_mov_imm;
      const bool arithmetic = opcode == OP_add || opcode == OP_sub;
      if (!push && !pop && !move && !arithmetic && opcode != OP_lea &&
          opcode != OP_xor)
        return false;
      int64_t next_stack = stack.offset;
      if ((push || pop) && !add_offset(next_stack, push ? -8 : 8, next_stack))
        return false;
      if (next_stack > 0)
        return false;
      for (int index = 0;
           index < instr_num_srcs(&instruction) + instr_num_dsts(&instruction);
           ++index) {
        const bool write = index >= instr_num_srcs(&instruction);
        const opnd_t operand =
            write ? instr_get_dst(&instruction,
                                  index - instr_num_srcs(&instruction))
                  : instr_get_src(&instruction, index);
        if (!opnd_is_memory_reference(operand) || opcode == OP_lea)
          continue;
        const Register address = address_of(operand);
        const size_t size = opnd_size_in_bytes(opnd_get_size(operand));
        int64_t end = 0;
        if (address.kind != Register::Stack || !size || size > INT64_MAX ||
            !add_offset(address.offset, int64_t(size), end) ||
            (write && (address.offset < (push ? next_stack : stack.offset) ||
                       end > 0)) ||
            ((push || pop) && size != 8))
          return false;
      }
      Register value;
      opnd_t destination = opnd_create_null();
      if (move || opcode == OP_lea) {
        if (instr_num_dsts(&instruction) != 1 ||
            instr_num_srcs(&instruction) != 1)
          return false;
        destination = instr_get_dst(&instruction, 0);
        const opnd_t source = instr_get_src(&instruction, 0);
        if (opcode == OP_lea)
          value = address_of(source);
        else if (opnd_is_reg(source))
          value = read_register(opnd_get_reg(source));
        else if (opnd_is_immed_int(source)) {
          value.kind = Register::Constant;
          value.value = uint64_t(opnd_get_immed_int(source));
        }
      } else if (arithmetic || opcode == OP_xor) {
        if (instr_num_dsts(&instruction) != 1 ||
            instr_num_srcs(&instruction) != 2)
          return false;
        destination = instr_get_dst(&instruction, 0);
        if (!opnd_is_reg(destination))
          return false;
        const reg_id_t reg = opnd_get_reg(destination);
        const opnd_t first = instr_get_src(&instruction, 0);
        const opnd_t second = instr_get_src(&instruction, 1);
        if (opcode == OP_xor) {
          if (opnd_is_reg(first) && opnd_is_reg(second) &&
              opnd_get_reg(first) == reg && opnd_get_reg(second) == reg) {
            value.kind = Register::Constant;
            value.value = 0;
          }
        } else {
          const opnd_t immediate = opnd_is_immed_int(first) ? first : second;
          const opnd_t original = opnd_is_immed_int(first) ? second : first;
          if (!opnd_is_immed_int(immediate) || !opnd_is_reg(original) ||
              opnd_get_reg(original) != reg)
            return false;
          const int64_t number = opnd_get_immed_int(immediate);
          if (number < INT32_MIN || number > INT32_MAX)
            return false;
          const int64_t delta = opcode == OP_add ? number : -number;
          value = read_register(reg);
          if (value.kind == Register::Constant)
            value.value += uint64_t(delta);
          else if (value.kind == Register::Stack &&
                   !add_offset(value.offset, delta, value.offset))
            return false;
        }
      }
      for (int index = 0; index < instr_num_dsts(&instruction); ++index) {
        const opnd_t operand = instr_get_dst(&instruction, index);
        if (!opnd_is_reg(operand))
          continue;
        const reg_id_t reg = opnd_get_reg(operand);
        if (!reg_is_gpr(reg))
          return false;
        const reg_id_t full = reg_to_pointer_sized(reg);
        if (full < DR_REG_RAX || full > DR_REG_R15 ||
            (pop && full == DR_REG_RSP && reg != DR_REG_RSP))
          return false;
        Register replacement;
        if (opnd_is_reg(destination) && opnd_get_reg(destination) == reg)
          replacement = value;
        if (full == DR_REG_RSP && (push || pop)) {
          // POP RSP has both an explicit destination and an implicit update.
          if (pop && index == 0)
            return false;
          replacement.kind = Register::Stack;
          replacement.offset = next_stack;
        } else if (reg != full) {
          if (reg_get_size(reg) == OPSZ_4 &&
              replacement.kind == Register::Constant)
            replacement.value = uint32_t(replacement.value);
          else
            replacement = {};
        }
        registers[full - DR_REG_RAX] = replacement;
      }
      const Register changed_stack = read_register(DR_REG_RSP);
      return changed_stack.kind == Register::Stack && changed_stack.offset <= 0;
    }();
    instr_free(context, &instruction);
    if (!valid_prefix)
      return false;
  }
  bool epilogue = false;
  for (size_t index = instructions.size(); index-- > 0;) {
    const auto &item = instructions[index];
    const bool contiguous =
        index + 1 < instructions.size() &&
        item.offset + item.size == instructions[index + 1].offset;
    if ((suffixes[index] & ExitTail) ||
        ((suffixes[index] & ExitCall) && contiguous && epilogue))
      result.exits.push_back(module_base + item.offset);
    epilogue = (suffixes[index] & Return) ||
               ((suffixes[index] & EpilogueStep) && contiguous && epilogue);
  }
  if (!result.entry || result.exits.empty())
    return false;
  std::reverse(result.exits.begin(), result.exits.end());
  proof = std::move(result);
  return true;
}
