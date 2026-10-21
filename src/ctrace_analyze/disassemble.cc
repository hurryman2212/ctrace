// SPDX-License-Identifier: MIT

#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCParser/MCAsmParser.h>
#include <llvm/MC/MCParser/MCTargetAsmParser.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCStreamer.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include "analysis.hh"
#include "cache.hh"

class InstructionIdentity : public llvm::MCStreamer {
public:
  std::string identity;
  bool unsupported = false;
  explicit InstructionIdentity(llvm::MCContext &context)
      : MCStreamer(context) {}
  void emitInstruction(const llvm::MCInst &instruction,
                       const llvm::MCSubtargetInfo &) override {
    llvm::raw_string_ostream output(identity);
    output << instruction.getOpcode() << ':' << instruction.getFlags() << ':';
    for (const auto &operand : instruction) {
      if (operand.isReg())
        output << 'r' << operand.getReg().id() << ',';
      else if (operand.isImm())
        output << 'i' << operand.getImm() << ',';
      else
        unsupported = true;
    }
    output << ';';
  }
  bool emitSymbolAttribute(llvm::MCSymbol *, llvm::MCSymbolAttr) override {
    unsupported = true;
    return false;
  }
  void emitCommonSymbol(llvm::MCSymbol *, uint64_t, llvm::Align) override {
    unsupported = true;
  }
};

struct Disassembler {
  llvm::Triple triple{"x86_64-pc-linux-gnu"};
  const llvm::Target *target = nullptr;
  std::unique_ptr<llvm::MCRegisterInfo> registers;
  std::unique_ptr<llvm::MCAsmInfo> info;
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget;
  std::unique_ptr<llvm::MCInstrInfo> instructions;
  std::unique_ptr<llvm::MCInstrAnalysis> analysis;
  std::unique_ptr<llvm::MCContext> context;
  std::unique_ptr<llvm::MCDisassembler> decoder;
  std::unique_ptr<llvm::MCInstPrinter> printers[2];

  Disassembler() {
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetDisassembler();
    llvm::InitializeNativeTargetAsmParser();
    std::string error;
    target = llvm::TargetRegistry::lookupTarget(triple.str(), error);
    if (!target)
      return;
    llvm::MCTargetOptions options;
    registers.reset(target->createMCRegInfo(triple.str()));
    if (!registers)
      return;
    info.reset(target->createMCAsmInfo(*registers, triple.str(), options));
    subtarget.reset(target->createMCSubtargetInfo(triple.str(), "generic", ""));
    instructions.reset(target->createMCInstrInfo());
    if (!info || !subtarget || !instructions)
      return;
    analysis.reset(target->createMCInstrAnalysis(instructions.get()));
    context = std::make_unique<llvm::MCContext>(
        triple, info.get(), registers.get(), subtarget.get());
    decoder.reset(target->createMCDisassembler(*subtarget, *context));
    for (int syntax = 0; syntax != 2; ++syntax) {
      printers[syntax].reset(target->createMCInstPrinter(
          triple, syntax, *info, *instructions, *registers));
      if (printers[syntax]) {
        printers[syntax]->setPrintImmHex(true);
        printers[syntax]->setPrintBranchImmAsAddress(true);
      }
    }
  }

  std::optional<std::string> identity(const std::string &assembly) const {
    llvm::SourceMgr sources;
    bool diagnosed = false;
    sources.setDiagHandler(
        [](const llvm::SMDiagnostic &, void *context) {
          *static_cast<bool *>(context) = true;
        },
        &diagnosed);
    sources.AddNewSourceBuffer(
        llvm::MemoryBuffer::getMemBufferCopy(assembly + '\n'), llvm::SMLoc());
    llvm::MCContext parse_context(triple, info.get(), registers.get(),
                                  subtarget.get(), &sources);
    std::unique_ptr<llvm::MCObjectFileInfo> object_info(
        target->createMCObjectFileInfo(parse_context, false));
    parse_context.setObjectFileInfo(object_info.get());
    InstructionIdentity streamer(parse_context);
    std::unique_ptr<llvm::MCAsmParser> parser(
        llvm::createMCAsmParser(sources, parse_context, streamer, *info));
    llvm::MCTargetOptions options;
    std::unique_ptr<llvm::MCTargetAsmParser> machine_parser(
        target->createMCAsmParser(*subtarget, *parser, *instructions, options));
    if (!machine_parser)
      return std::nullopt;
    parser->setTargetParser(*machine_parser);
    parser->setAssemblerDialect(1);
    if (parser->Run(false) || diagnosed || streamer.unsupported ||
        streamer.identity.empty())
      return std::nullopt;
    return streamer.identity;
  }
};

bool ct_analysis_disassemble(uint64_t pc, const unsigned char *bytes,
                             size_t size, char *att, size_t att_capacity,
                             char *intel, size_t intel_capacity) {
  if (!bytes || !size || size > 15 || !att || !att_capacity || !intel ||
      !intel_capacity)
    return false;
  att[0] = intel[0] = '\0';
  struct CachedInstruction {
    uint64_t relative_target = 0;
    char att[1024]{}, intel[1024]{};
  } cached;
  const std::string key = ct_cache_key(
      {"disassembly", {reinterpret_cast<const char *>(bytes), size}});
  const auto copy_text = [&]() {
    std::string text[2] = {cached.att, cached.intel};
    char target[32];
    std::snprintf(target, sizeof(target), "0x%llx",
                  static_cast<unsigned long long>(pc + cached.relative_target));
    for (auto &item : text)
      if (const size_t offset = item.find("@TARGET@");
          offset != std::string::npos)
        item.replace(offset, 8, target);
    if (text[0].size() >= att_capacity || text[1].size() >= intel_capacity)
      return false;
    std::memcpy(att, text[0].c_str(), text[0].size() + 1);
    std::memcpy(intel, text[1].c_str(), text[1].size() + 1);
    return true;
  };
  std::vector<unsigned char> saved;
  if (ct_cache_read("disassembly", key, saved) &&
      saved.size() == sizeof(cached)) {
    std::memcpy(&cached, saved.data(), sizeof(cached));
    if (std::memchr(cached.att, 0, sizeof(cached.att)) && cached.att[0] &&
        std::memchr(cached.intel, 0, sizeof(cached.intel)) && cached.intel[0])
      return copy_text();
    cached = {};
  }
  // Requests are serialized by the helper's socket loop; retain MC state once.
  static Disassembler state;
  if (!state.decoder || !state.printers[0] || !state.printers[1])
    return false;
  std::string rendered[2];
  // A fixed printing address keeps relative branch operands independent of
  // ASLR. Only an MC-proven branch target becomes a runtime placeholder.
  constexpr uint64_t print_base = UINT64_C(1) << 32;
  size_t consumed = 0;
  while (consumed < size) {
    llvm::MCInst instruction;
    uint64_t decoded = 0;
    if (state.decoder->getInstruction(instruction, decoded,
                                      {bytes + consumed, size - consumed},
                                      print_base + consumed, llvm::nulls()) !=
            llvm::MCDisassembler::Success ||
        !decoded || decoded > size - consumed)
      return false;
    uint64_t target = 0;
    const bool relative =
        state.analysis &&
        state.analysis->evaluateBranch(instruction, print_base + consumed,
                                       decoded, target);
    consumed += decoded;
    // LLVM emits standalone prefix pseudo-instructions such as LOCK_PREFIX.
    // Join those to the instruction, but reject two actual instructions.
    bool prefix = state.instructions->getName(instruction.getOpcode())
                      .ends_with("_PREFIX");
    if (prefix == (consumed == size))
      return false;
    for (int syntax = 0; syntax != 2; ++syntax) {
      std::string piece;
      llvm::raw_string_ostream output(piece);
      // MCInstPrinter expects the next PC for x86 relative branch operands.
      state.printers[syntax]->printInst(&instruction, print_base + consumed, "",
                                        *state.subtarget, output);
      output.flush();
      if (relative) {
        char address[32];
        std::snprintf(address, sizeof(address), "0x%llx",
                      static_cast<unsigned long long>(target));
        const size_t position = piece.find(address);
        if (position == std::string::npos)
          return false;
        piece.replace(position, std::strlen(address), "@TARGET@");
        cached.relative_target = target - print_base;
      }
      rendered[syntax] += llvm::StringRef(piece).trim().str();
      if (prefix)
        rendered[syntax] += ' ';
    }
  }
  if (rendered[1].find(" ptr ") != std::string::npos) {
    // LLVM decides whether the remaining operands still determine exactly
    // the same instruction. In particular, a register need not imply the
    // memory width for extensions, scalar SIMD operations or CL shifts.
    const auto original = state.identity(rendered[1]);
    if (original) {
      size_t offset = 0;
      while ((offset = rendered[1].find(" ptr ", offset)) !=
             std::string::npos) {
        size_t begin = rendered[1].find_last_of(" \t", offset - 1);
        begin = begin == std::string::npos ? 0 : begin + 1;
        std::string candidate = rendered[1];
        candidate.erase(begin, offset + 5 - begin);
        if (state.identity(candidate) == original) {
          rendered[1] = std::move(candidate);
          offset = begin;
        } else {
          offset += 5;
        }
      }
    }
  }
  if (rendered[0].empty() || rendered[1].empty() ||
      rendered[0].size() >= att_capacity ||
      rendered[1].size() >= intel_capacity)
    return false;
  if (rendered[0].size() >= sizeof(cached.att) ||
      rendered[1].size() >= sizeof(cached.intel))
    return false;
  std::memcpy(cached.att, rendered[0].c_str(), rendered[0].size() + 1);
  std::memcpy(cached.intel, rendered[1].c_str(), rendered[1].size() + 1);
  saved.resize(sizeof(cached));
  std::memcpy(saved.data(), &cached, sizeof(cached));
  ct_cache_write("disassembly", key, saved);
  return copy_text();
}
