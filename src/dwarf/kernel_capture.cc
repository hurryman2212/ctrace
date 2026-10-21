// SPDX-License-Identifier: MIT

#include <algorithm>
#include <tuple>
#include <utility>

#include <llvm/ADT/SmallVector.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDataExtractor.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugFrame.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBufferRef.h>

#include <elf.h>

#include "dwarf/kernel_capture.hh"

bool ct_kernel_collect_cfa(
    const ct_kernel_image &image,
    std::map<uint32_t, std::vector<ct_kernel_cfa_range>> &ranges,
    std::string &error) {
  auto object = llvm::object::ObjectFile::createObjectFile(
      llvm::MemoryBufferRef({reinterpret_cast<const char *>(image.bytes.data()),
                             image.bytes.size()},
                            image.path));
  if (!object) {
    error = llvm::toString(object.takeError());
    return false;
  }
  const auto diagnostic = [&](llvm::Error issue) {
    auto message = llvm::toString(std::move(issue));
    if (error.empty())
      error = "kernel capture unwind metadata: " + message;
  };
  auto context = llvm::DWARFContext::create(
      **object, llvm::DWARFContext::ProcessDebugRelocations::Process, nullptr,
      "", diagnostic, diagnostic);
  auto frame = context->getDebugFrame();
  if (!frame) {
    error = llvm::toString(frame.takeError());
    return false;
  }
  if (!*frame)
    return error.empty();
  const auto &dwarf_object = context->getDWARFObj();
  const auto &section = dwarf_object.getFrameSection();
  const llvm::DWARFDataExtractor data(dwarf_object, section, true, 8);
  for (const auto &entry : (*frame)->entries()) {
    const auto *fde = llvm::dyn_cast<llvm::dwarf::FDE>(&entry);
    if (!fde || !fde->getLinkedCIE())
      continue;
    const auto *cie = fde->getLinkedCIE();
    if (!cie->getAugmentationString().empty() ||
        (cie->getVersion() != 1 && cie->getVersion() != 3 &&
         cie->getVersion() != 4))
      continue;
    llvm::Error issue = llvm::Error::success();
    if (cie->getVersion() == 4) {
      uint64_t offset = cie->getOffset();
      const auto length = data.getInitialLength(&offset, &issue);
      (void)data.getUnsigned(
          &offset, length.second == llvm::dwarf::DWARF64 ? 8 : 4, &issue);
      (void)data.getU8(&offset, &issue);
      (void)data.getCStrRef(&offset, &issue);
      const auto address_size = data.getU8(&offset, &issue);
      const auto segment_size = data.getU8(&offset, &issue);
      if (issue) {
        error = llvm::toString(std::move(issue));
        return false;
      }
      if (address_size != 8 || segment_size)
        continue;
    }
    uint64_t offset = fde->getOffset();
    const auto length = data.getInitialLength(&offset, &issue);
    (void)data.getUnsigned(
        &offset, length.second == llvm::dwarf::DWARF64 ? 8 : 4, &issue);
    const auto relocation = dwarf_object.find(section, offset);
    uint64_t code_section = llvm::object::SectionedAddress::UndefSection;
    const uint64_t begin =
        data.getRelocatedValue(8, &offset, &code_section, &issue);
    if (issue) {
      error = llvm::toString(std::move(issue));
      return false;
    }
    // Numeric initial PCs overlap across .text/.init.text/.exit.text in ET_REL.
    // Only an exact relocation proves which original code section owns an FDE.
    if (!relocation || relocation->Reloc2 ||
        relocation->Reloc.getType() != R_X86_64_64 ||
        code_section >= image.sections.size() ||
        !(image.sections[code_section].flags & SHF_EXECINSTR) ||
        begin != fde->getInitialLocation() ||
        begin > image.sections[code_section].size || !fde->getAddressRange() ||
        fde->getAddressRange() > image.sections[code_section].size - begin)
      continue;
    const auto absolute_row = [](const auto &program) {
      return std::any_of(program.begin(), program.end(), [](const auto &op) {
        return op.Opcode == llvm::dwarf::DW_CFA_set_loc;
      });
    };
    // Parsed set_loc operands no longer retain their relocation section.
    if (absolute_row(cie->cfis()) || absolute_row(fde->cfis())) {
      ranges[code_section].push_back({uint32_t(code_section),
                                      begin,
                                      begin + fde->getAddressRange(),
                                      0,
                                      {}});
      continue;
    }
    auto table = llvm::dwarf::createUnwindTable(fde);
    if (!table) {
      error = llvm::toString(table.takeError());
      return false;
    }
    const uint64_t end = begin + fde->getAddressRange();
    for (size_t index = 0; index < table->size(); ++index) {
      const auto &row = (*table)[index];
      const auto finish = index + 1 == table->size() ? end
                          : (*table)[index + 1].hasAddress()
                              ? (*table)[index + 1].getAddress()
                              : 0;
      if (!row.hasAddress() || row.getAddress() < begin ||
          row.getAddress() > finish || finish > end) {
        error = "kernel capture CFA row exceeds its original FDE";
        return false;
      }
      const auto &cfa = row.getCFAValue();
      if (row.getAddress() == finish)
        continue;
      ct_kernel_dwarf_address address;
      if (cfa.getLocation() == llvm::dwarf::UnwindLocation::RegPlusOffset &&
          !cfa.getDereference() && !cfa.hasAddressSpace() &&
          (cfa.getRegister() == 6 || cfa.getRegister() == 7))
        address = {
            KCTRACE_CAPTURE_STACK,
            uint8_t(cfa.getRegister() == 6 ? KCTRACE_REG_RBP : KCTRACE_REG_RSP),
            UINT32_MAX, cfa.getOffset()};
      ranges[code_section].push_back(
          {uint32_t(code_section), row.getAddress(), finish, 0, address});
    }
  }
  for (auto &[section_index, entries] : ranges) {
    std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
      return std::tie(a.begin, a.end, a.address.reg, a.address.offset) <
             std::tie(b.begin, b.end, b.address.reg, b.address.offset);
    });
    uint64_t end = 0;
    for (auto &range : entries)
      range.prefix_end = end = std::max(end, range.end);
  }
  return error.empty();
}

std::optional<ct_kernel_dwarf_address> ct_kernel_resolve_capture_address(
    const ct_kernel_value_recipe &recipe,
    const std::optional<ct_kernel_dwarf_address> &frame,
    const std::optional<ct_kernel_dwarf_address> &cfa, size_t bytes,
    bool frame_base) {
  if (!recipe.error.empty() || recipe.operations.empty())
    return {};
  llvm::SmallVector<ct_kernel_dwarf_address, 64> stack(
      recipe.operations.size());
  size_t depth = 0;
  bool complete = false;
  for (const auto &op : recipe.operations) {
    using namespace llvm::dwarf;
    if (complete && op.opcode != DW_OP_nop)
      return {};
    ct_kernel_dwarf_address value;
    bool push = true;
    if ((op.opcode >= DW_OP_breg0 && op.opcode <= DW_OP_breg31) ||
        op.opcode == DW_OP_bregx) {
      const auto reg =
          op.opcode == DW_OP_bregx ? op.operand : op.opcode - DW_OP_breg0;
      if (reg != 6 && reg != 7)
        return {};
      value.kind = KCTRACE_CAPTURE_STACK;
      value.reg = reg == 6 ? KCTRACE_REG_RBP : KCTRACE_REG_RSP;
      value.offset =
          int64_t(op.opcode == DW_OP_bregx ? op.operand2 : op.operand);
    } else if ((op.opcode >= DW_OP_reg0 && op.opcode <= DW_OP_reg31) ||
               op.opcode == DW_OP_regx) {
      const auto reg =
          op.opcode == DW_OP_regx ? op.operand : op.opcode - DW_OP_reg0;
      if (!frame_base || depth || (reg != 6 && reg != 7))
        return {};
      value.kind = KCTRACE_CAPTURE_STACK;
      value.reg = reg == 6 ? KCTRACE_REG_RBP : KCTRACE_REG_RSP;
      complete = true;
    } else if (op.opcode >= DW_OP_lit0 && op.opcode <= DW_OP_lit31) {
      value.offset = op.opcode - DW_OP_lit0;
    } else if (op.opcode >= DW_OP_const1u && op.opcode <= DW_OP_consts) {
      const bool signed_value =
          op.opcode == DW_OP_const1s || op.opcode == DW_OP_const2s ||
          op.opcode == DW_OP_const4s || op.opcode == DW_OP_const8s ||
          op.opcode == DW_OP_consts;
      value.offset =
          signed_value ? __int128(int64_t(op.operand)) : __int128(op.operand);
    } else {
      switch (op.opcode) {
      case DW_OP_addr:
        if (op.section == UINT32_MAX)
          return {};
        value.kind = KCTRACE_CAPTURE_OBJECT;
        value.section = op.section;
        value.offset = op.operand;
        break;
      case DW_OP_fbreg:
        if (!frame)
          return {};
        value = *frame;
        value.offset += int64_t(op.operand);
        break;
      case DW_OP_call_frame_cfa:
        if (!cfa)
          return {};
        value = *cfa;
        break;
      case DW_OP_plus_uconst:
        if (!depth)
          return {};
        stack[depth - 1].offset += op.operand;
        push = false;
        break;
      case DW_OP_plus:
      case DW_OP_minus:
        if (depth < 2)
          return {};
        value = stack[--depth];
        if (op.opcode == DW_OP_plus &&
            stack[depth - 1].kind == KCTRACE_CAPTURE_NONE)
          std::swap(value, stack[depth - 1]);
        if (value.kind != KCTRACE_CAPTURE_NONE)
          return {};
        stack[depth - 1].offset +=
            op.opcode == DW_OP_plus ? value.offset : -value.offset;
        push = false;
        break;
      case DW_OP_piece:
        if (frame_base || depth != 1 || op.operand != bytes)
          return {};
        complete = true;
        push = false;
        break;
      case DW_OP_nop:
        push = false;
        break;
      default:
        // stack_value is a computed value, not a memory capture request.
        // Dereferences, entry values and pointer arithmetic from other GPRs
        // are deliberately not converted into kernel reads.
        return {};
      }
    }
    if (push) {
      if (depth == stack.size())
        return {};
      stack[depth++] = value;
    }
    if (depth && (stack[depth - 1].offset < INT64_MIN ||
                  stack[depth - 1].offset > INT64_MAX))
      return {};
  }
  if (depth != 1 || stack[0].kind == KCTRACE_CAPTURE_NONE)
    return {};
  return stack[0];
}

bool ct_kernel_resolve_capture_register(const ct_kernel_value_recipe &recipe,
                                        size_t bytes, kctrace_capture &capture,
                                        bool &direct) {
  using namespace llvm::dwarf;
  if (!recipe.error.empty() ||
      (recipe.operations.size() != 1 &&
       (recipe.operations.size() != 2 ||
        recipe.operations.back().opcode != DW_OP_stack_value)))
    return false;
  const auto &operation = recipe.operations.front();
  const bool indirect =
      operation.opcode == DW_OP_bregx ||
      (operation.opcode >= DW_OP_breg0 && operation.opcode <= DW_OP_breg31);
  const auto reg =
      operation.opcode == DW_OP_regx || operation.opcode == DW_OP_bregx
          ? operation.operand
      : indirect ? operation.opcode - DW_OP_breg0
      : operation.opcode >= DW_OP_reg0 && operation.opcode <= DW_OP_reg31
          ? operation.opcode - DW_OP_reg0
          : UINT64_MAX;
  static constexpr unsigned registers[] = {
      KCTRACE_REG_RAX, KCTRACE_REG_RDX, KCTRACE_REG_RCX, KCTRACE_REG_RBX,
      KCTRACE_REG_RSI, KCTRACE_REG_RDI, KCTRACE_REG_RBP, KCTRACE_REG_RSP,
      KCTRACE_REG_R8,  KCTRACE_REG_R9,  KCTRACE_REG_R10, KCTRACE_REG_R11,
      KCTRACE_REG_R12, KCTRACE_REG_R13, KCTRACE_REG_R14, KCTRACE_REG_R15};
  if (reg >= std::size(registers) || bytes > 8)
    return false;
  kctrace_capture result{};
  result.kind = KCTRACE_CAPTURE_GPR;
  result.reg = registers[reg];
  direct = !indirect || recipe.operations.size() == 2;
  result.reserved = direct ? KCTRACE_CAPTURE_ADDRESS : 0;
  if (indirect)
    result.offset =
        int64_t(operation.opcode == DW_OP_bregx ? operation.operand2
                                                : operation.operand);
  result.size = 8;
  capture = result;
  return true;
}
