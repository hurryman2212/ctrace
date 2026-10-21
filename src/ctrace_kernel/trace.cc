// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <utility>

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCCodeEmitter.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCExpr.h>
#include <llvm/MC/MCFixup.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <elf.h>

#include "c_cpp_access.hh"
#include "dwarf/kernel_source.hh"
#include "dwarf/kernel_values.hh"
#include "kctrace/policy.h"
#include "source_compare.hh"
#include "trace.hh"

struct ct_kernel_trace::Data {
  using Mode = kctrace_policy_mode;
  using Selection = kctrace_policy_state;
  static constexpr Mode skip = KCTRACE_POLICY_SKIP;
  static constexpr Mode over = KCTRACE_POLICY_OVER;
  static constexpr Mode into = KCTRACE_POLICY_INTO;
  static constexpr Mode recurse = KCTRACE_POLICY_RECURSE;
  struct Register {
    std::string name;
    unsigned slot = 0, bits = 64, shift = 0;
    // Transfer-only kinds: 13 raw component, 14 tile, 15 configuration,
    // 16 logical x87, 17/18 unmasked FX raw/x87, 19 standard-form MXCSR.
    // They reuse number/shift for component or register index/byte offset.
    unsigned xstate = 0, number = 0;
    bool read = false, write = false;
  };
  struct Function {
    uint32_t section = 0;
    uint64_t begin = 0, end = 0, first = 0, parameter_site = 0;
    std::string name;
    Mode mode = skip;
    bool within = false, indirect = false;
  };
  struct Site {
    struct MemoryOperand {
      uint32_t section = UINT32_MAX;
      uint64_t target = 0;
      int64_t displacement = 0;
      unsigned reg = KCTRACE_REGISTER_COUNT, size = 0;
    } store, memory_operand;
    struct IndexedMemory {
      unsigned base, index, scale;
      int64_t displacement;
    };
    std::unique_ptr<IndexedMemory> indexed_memory;
    ct_kernel_site original;
    size_t function = 0;
    uint64_t next = 0, observation_next = 0, branch_target = 0, scope_site = 0;
    std::string assembly, assembly_note, original_assembly, display_function;
    std::string source_owner, call_name, store_object;
    uint32_t source_line = 0;
    uint64_t source_assignment = 0;
    struct StoredAssignment {
      ct_value_type type{};
      std::string name;
      uint64_t member_offset = 0;
      bool indirect = false;
    };
    std::unique_ptr<StoredAssignment> stored_assignment;
    uint64_t store_immediate = 0;
    unsigned store_register = KCTRACE_REGISTER_COUNT, store_shift = 0;
    bool store_literal = false;
    unsigned memory_value_width = 0,
             memory_value_register = KCTRACE_REGISTER_COUNT;
    unsigned memory_value_shift = 0;
    uint64_t memory_value_immediate = 0;
    bool memory_value_literal = false;
    bool memory_assignment = false;
    bool source_opening = false;
    unsigned line = 0, file = 0;
    std::vector<Register> registers;
    bool call = false, ret = false, branch = false, conditional = false;
    bool memory = false, memory_read = false, memory_write = false;
    bool writes_stack = false, stack_save = false, entry_padding = false;
    bool coalescible = false;
    bool dwarf_scope = false;
    bool compiler_support = false;
  };
  struct SourceValue {
    uint64_t variable = 0;
    uint32_t access = 0;
    std::string name, type, before = "?";
    bool declared = false, global = false, address = false;
    bool read_before = true;
  };
  struct InlineResult {
    std::string text;
    ct_value_type type{};
    uint64_t scalar = 0;
    bool known = false;
  };
  struct SourceRow {
    uint32_t line = 0;
    std::string owner;
    std::shared_ptr<bool> inline_prefix_seen;
    ct_kernel_observation before{}, after{};
    std::vector<SourceValue> inputs;
    struct CallResult {
      const ct_source_call_result_info *call = nullptr;
      std::string value;
      InlineResult returned;
      bool display = true;
    };
    std::vector<CallResult> results;
    std::vector<const ct_source_call_result_info *> entered_calls;
    uint64_t assigned = 0, buffered_sequence = 0;
    std::string assigned_name, assigned_value;
    std::vector<ct_kernel_trace_record> fallback, stores;
    InlineResult returned;
    bool call_bearing = false, call_seen = false, assembly = false;
    bool printed = false, call_reported = false, call_completed = false;
    bool assignment_returned = false;
    int condition_outcome = -1;
    bool forward_checked = false;
  };
  struct DecompileRow {
    uint32_t statement = 0;
    size_t next = 0;
    ct_kernel_observation before{}, last{};
    std::vector<SourceValue> inputs;
    std::vector<uint64_t> writes;
    std::vector<ct_kernel_trace_record> fallback;
    bool printed = false;
  };
  struct Frame : Selection {
    struct Scope : Selection {
      uint64_t token = 0, parent = 0, begin = 0, block = 0, pc = 0;
      bool decompiled = false;
      std::shared_ptr<bool> inline_prefix_seen;
    };
    size_t function = 0;
    uint64_t stack = 0, return_site = 0;
    uint64_t execution_id = 0, execution_parent = 0, incoming_call = 0;
    uint64_t call_cookie = 0, call_site = 0, resumed_site = 0;
    uint64_t guard_site = 0;
    unsigned char execution_state = 0, execution_level = KCTRACE_LEVEL_FULL;
    bool call_unpaired = false, call_observed = false, call_reported = false;
    bool call_skipped = false;
    const ct_source_call_result_info *pending_source = nullptr;
    InlineResult call_return;
    ct_kernel_observation entry{};
    Scope scope{};
    std::vector<Scope> blocks;
    SourceRow row;
    struct InlineRow {
      uint64_t block = 0;
      SourceRow caller;
      const ct_source_call_result_info *call = nullptr;
      bool awaiting_snapshot = false;
      InlineResult returned;
      bool return_observed = false;
    };
    std::vector<InlineRow> inline_rows;
    DecompileRow decompiled;
    std::unique_ptr<SourceRow> deferred_assignment;
    std::unique_ptr<SourceRow> deferred_return;
    std::string source_function;
    std::string entry_invocation;
    std::string call_decompile;
    std::set<std::string> introduced;
    const ct_source_call_result_info *call_source = nullptr;
    bool source_entry = false;
    bool decompile_entry = false;
  };
  struct Task {
    std::vector<Frame> frames;
    ct_kernel_observation pending{};
    bool selected = false;
    bool execution = false, execution_unknown = false;
    uint64_t execution_serial = 0;
    uint64_t sequence = 0, timestamp = 0;
  };
  using TaskKey = std::tuple<uint32_t, uint32_t, uint64_t, uint16_t, uint32_t,
                             uint16_t, uint16_t, bool>;
  std::vector<Site> sites;
  std::vector<Function> functions;
  ct_kernel_policy policy;
  std::vector<uint64_t> timing_sites;
  std::vector<uint8_t> observation_sites;
  std::vector<std::string> files{std::string()};
  std::map<TaskKey, Task> tasks;
  std::map<std::tuple<uint32_t, uint16_t, uint16_t>, TaskKey> irq_contexts;
  std::shared_ptr<const ct_kernel_source_metadata> source;
  std::shared_ptr<const ct_kernel_decompile_metadata> decompile;
  std::shared_ptr<const ct_kernel_value_metadata> values;
  std::shared_ptr<const std::vector<ct_kernel_capture_plan>> captures;
  std::vector<std::pair<Mode, bool>> block_filters;
  std::set<std::string> introduced;
  std::set<std::string> introduced_globals;
  std::set<std::string> introduced_functions;
  std::map<uint32_t, uint64_t> section_bases;
  std::map<uint64_t, uint64_t> decompile_addresses;
  uint64_t session = 0, generation = 0, dropped = 0;
  uint64_t next_token = 1;
  bool prepared = false, terminal = true, within_filter = false;
  bool within_intr = false;

  bool inline_owner(uint64_t site, const std::string &owner) const {
    if (!source || site >= sites.size())
      return false;
    site = sites[site].scope_site ? sites[site].scope_site : site;
    if (site >= source->sites.size())
      return false;
    return std::any_of(
        source->sites[site].blocks.begin(), source->sites[site].blocks.end(),
        [&](uint64_t block) {
          return block && block < source->blocks.size() &&
                 source->blocks[block].kind ==
                     ct_kernel_source_block_kind::inline_function &&
                 source->blocks[block].header == owner;
        });
  }

  std::shared_ptr<bool> inline_prefix(const Frame &frame, uint64_t site,
                                      const std::string &owner) const {
    if (!source || site >= sites.size())
      return {};
    site = sites[site].scope_site ? sites[site].scope_site : site;
    if (site >= source->sites.size())
      return {};
    const auto &members = source->sites[site].blocks;
    for (auto scope = frame.blocks.rbegin(); scope != frame.blocks.rend();
         ++scope)
      if (!scope->decompiled && scope->inline_prefix_seen &&
          source->blocks[scope->block].header == owner &&
          std::find(members.begin(), members.end(), scope->block) !=
              members.end())
        return scope->inline_prefix_seen;
    return {};
  }

  ct_kernel_trace_record
  base_record(const ct_kernel_observation &before) const {
    const Site &site = sites[before.site_id];
    const Function &function = functions[site.function];
    ct_kernel_trace_record record;
    record.site_id = before.site_id;
    record.pc = before.pc;
    record.original_offset = site.original.offset;
    record.monotonic_ns = before.monotonic_ns;
    record.task_start_ns = before.task_start_ns;
    record.section = site.original.section;
    record.tid = before.tid;
    record.tgid = before.tgid;
    record.cpu = before.cpu;
    record.context = before.context;
    record.hardirq_depth = before.hardirq_depth;
    record.softirq_depth = before.softirq_depth;
    record.line = site.line;
    record.function =
        site.display_function.empty() ? function.name : site.display_function;
    record.inlined = inline_owner(before.site_id, record.function);
    record.file = files[site.file];
    return record;
  }

  void assembly_record(ct_kernel_trace_record &record, const Site &site,
                       const ct_kernel_observation &before,
                       const ct_kernel_observation *after) const {
    if (!site.original_assembly.empty()) {
      record.text = site.original_assembly;
      return;
    }
    record.inline_assembly = true;
    record.dwarf_scope = site.dwarf_scope;
    const auto append = [&](std::string_view text,
                            ct_kernel_code_color color =
                                ct_kernel_code_color::normal) {
      const size_t begin = record.text.size();
      record.text += text;
      if (!text.empty())
        record.assembly_styles.push_back({begin, record.text.size(), color});
    };
    const auto escape = [](std::string_view text) {
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
          result += char(byte);
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
            result += char(byte);
        }
      }
      return result;
    };
    const auto trim = [](std::string text) {
      const auto begin = text.find_first_not_of(" \t");
      return begin == std::string::npos
                 ? std::string{}
                 : text.substr(begin, text.find_last_not_of(" \t") - begin + 1);
    };
    size_t operand_begin = 0;
    for (;;) {
      const auto end = site.assembly.find_first_of(" \t", operand_begin);
      if (end == std::string::npos) {
        operand_begin = site.assembly.size();
        break;
      }
      const auto word =
          site.assembly.substr(operand_begin, end - operand_begin);
      operand_begin = site.assembly.find_first_not_of(" \t", end);
      if (operand_begin == std::string::npos) {
        operand_begin = site.assembly.size();
        break;
      }
      if (word != "lock" && word != "rep" && word != "repne" &&
          word != "repe" && word != "repz" && word != "repnz" && word != "CS" &&
          word != "DS" && word != "ES" && word != "SS" && word != "FS" &&
          word != "GS")
        break;
    }
    std::vector<std::string> operands;
    size_t start = operand_begin;
    unsigned depth = 0;
    for (size_t pos = start; pos <= site.assembly.size(); ++pos) {
      const char ch = pos < site.assembly.size() ? site.assembly[pos] : ',';
      if (ch == '(' || ch == '[')
        ++depth;
      if ((ch == ')' || ch == ']') && depth)
        --depth;
      if (ch == ',' && !depth) {
        if (pos > start)
          operands.push_back(trim(site.assembly.substr(start, pos - start)));
        start = pos + 1;
      }
    }
    const bool jump =
        site.branch && !site.ret && site.branch_target && operands.size() == 1;
    const std::string label =
        jump
            ? "L" + std::to_string(sites[site.branch_target].original.section) +
                  "_" +
                  std::to_string(sites[site.branch_target].original.offset)
            : std::string{};
    std::vector<std::string> outputs, inputs;
    std::set<std::string> clobbers, resolved_registers, placeholders;
    append(jump ? "asm goto (\"" : "asm (\"");
    record.assembly_begin = record.text.size();
    append(escape(trim(site.assembly.substr(0, operand_begin))));
    for (size_t index = 0; index < operands.size(); ++index) {
      append(index ? ", " : " ");
      const auto &operand = operands[index];
      if (jump) {
        append("%l[" + label + "]", ct_kernel_code_color::machine);
        continue;
      }
      std::string reg_name = operand;
      const bool indirect = !reg_name.empty() && reg_name.front() == '*';
      if (indirect)
        reg_name.erase(0, 1);
      if (!reg_name.empty() && reg_name.front() == '%')
        reg_name.erase(0, 1);
      const auto reg = std::find_if(
          site.registers.begin(), site.registers.end(),
          [&](const auto &entry) { return entry.name == reg_name; });
      const bool memory = reg == site.registers.end() &&
                          operand.find_first_of("([") != std::string::npos &&
                          site.memory_operand.size;
      const bool write = memory ? site.store.size != 0
                                : reg != site.registers.end() && reg->write;
      const bool read =
          memory ? site.memory_read : reg != site.registers.end() && reg->read;
      const auto *event = write && after ? after : &before;
      const ct_kernel_value_variable *variable = nullptr;
      bool ambiguous = false;
      const bool repeated_register =
          reg != site.registers.end() &&
          std::count_if(operands.begin(), operands.end(),
                        [&](std::string text) {
                          if (!text.empty() && text.front() == '*')
                            text.erase(0, 1);
                          if (!text.empty() && text.front() == '%')
                            text.erase(0, 1);
                          return text == reg->name;
                        }) > 1;
      if (!repeated_register && (reg != site.registers.end() || memory) &&
          values && event->site_id < values->sites.size())
        for (const auto &location : values->sites[event->site_id].bindings) {
          const auto &candidate = values->variables[location.variable];
          if (!candidate.type || candidate.name.empty())
            continue;
          const auto &type = values->types[candidate.type];
          bool match = false;
          if (!memory) {
            match = reg->bits && reg->slot < KCTRACE_REGISTER_COUNT &&
                    !reg->shift && reg->bits == type.scalar.bytes * 8 &&
                    location_register(&location) == reg->slot;
            if (match && read && write)
              match = location_register(
                          binding(candidate.id, before.site_id)) == reg->slot;
          } else {
            const auto matches_memory = [&](const ct_kernel_observation
                                                &observed) {
              unsigned slot = 0;
              const auto *storage =
                  capture(candidate.id, observed.site_id, slot);
              if (!storage ||
                  storage->capture.size != site.memory_operand.size ||
                  type.scalar.bytes != site.memory_operand.size)
                return false;
              const auto &address = storage->capture;
              if (address.kind == KCTRACE_CAPTURE_OBJECT)
                return storage->section == site.memory_operand.section &&
                       __int128(storage->object_offset) + address.offset ==
                           site.memory_operand.target;
              if (address.kind == KCTRACE_CAPTURE_STACK &&
                  address.reg < KCTRACE_REGISTER_COUNT &&
                  site.memory_operand.reg < KCTRACE_REGISTER_COUNT &&
                  (observed.valid_registers & (UINT64_C(1) << address.reg)) &&
                  (before.valid_registers &
                   (UINT64_C(1) << site.memory_operand.reg))) {
                const __int128 location =
                    __int128(observed.registers[address.reg]) + address.offset;
                return location >= 0 && location <= UINT64_MAX &&
                       location ==
                           __int128(before.registers[site.memory_operand.reg]) +
                               site.memory_operand.displacement;
              }
              return false;
            };
            match = matches_memory(*event) &&
                    (!read || !write || matches_memory(before));
          }
          if (!match || type.guarded)
            continue;
          if (variable && variable->id != candidate.id)
            ambiguous = true;
          variable = &candidate;
        }
      if (variable && !ambiguous) {
        std::string name = memory ? variable->name : reg->name;
        for (char &byte : name)
          if (!std::isalnum(static_cast<unsigned char>(byte)) && byte != '_')
            byte = '_';
        if (std::isdigit(static_cast<unsigned char>(name.front())))
          name.insert(0, "_");
        const auto base = name;
        for (unsigned suffix = 2; !placeholders.insert(name).second; ++suffix)
          name = base + '_' + std::to_string(suffix);
        if (indirect)
          append("*", ct_kernel_code_color::machine);
        append("%[" + name + "]", ct_kernel_code_color::resolved);
        const std::string constraint =
            (write ? (read ? "+" : "=") : "") + std::string(memory ? "m" : "r");
        (write ? outputs : inputs)
            .push_back("[" + name + "] \"" + constraint + "\" (" +
                       variable->name + ")");
        if (!memory)
          resolved_registers.insert(reg->name);
      } else {
        const bool symbol =
            (site.call || site.branch) && !indirect &&
            reg == site.registers.end() &&
            operand.find_first_of("%([]") == std::string::npos &&
            !operand.empty() &&
            (std::isalpha(static_cast<unsigned char>(operand.front())) ||
             operand.front() == '_');
        const bool machine =
            reg != site.registers.end() ||
            operand.find_first_of("%([]") != std::string::npos || site.branch ||
            site.call;
        append(escape(operand), symbol    ? ct_kernel_code_color::resolved
                                : machine ? ct_kernel_code_color::machine
                                          : ct_kernel_code_color::normal);
        if (memory && write)
          clobbers.insert("memory");
      }
    }
    record.assembly_end = record.text.size();
    for (const auto &reg : site.registers) {
      if (!reg.write || resolved_registers.count(reg.name))
        continue;
      if (reg.xstate >= 13) {
        // State-transfer descriptors name observed state, not GCC clobbers.
        clobbers.insert("memory");
        continue;
      }
      if (reg.xstate == 10) {
        for (unsigned tile = 0; tile < 8; ++tile)
          clobbers.insert("tmm" + std::to_string(tile));
        clobbers.insert("memory");
        // TILECFG is observable control state, not a GCC asm clobber name.
        continue;
      }
      if (reg.slot == KCTRACE_REG_RFLAGS)
        clobbers.insert("cc");
      else if (reg.slot != KCTRACE_REG_RSP && reg.slot != KCTRACE_REG_RIP) {
        std::string name = reg.name;
        if (!reg.bits) {
          // Register capture only covers GPRs, but the compiler still needs
          // explicit vector/x87 writes in the asm clobber list. LLVM's other
          // implicit registers (for example SSP/FPSW) are not GCC clobbers.
          const auto first = name.find_first_of("0123456789");
          if (first == std::string::npos || name.size() - first > 2 ||
              name.find_first_not_of("0123456789", first) != std::string::npos)
            continue;
          const auto prefix = name.substr(0, first);
          unsigned number = 0;
          for (size_t index = first; index < name.size(); ++index)
            number = number * 10 + unsigned(name[index] - '0');
          const bool vector =
              prefix == "XMM" || prefix == "YMM" || prefix == "ZMM";
          if ((vector && number >= 32) ||
              (!vector && (number >= 8 || (prefix != "MM" && prefix != "K" &&
                                           prefix != "ST"))))
            continue;
          if (prefix == "ST")
            name = number ? "st(" + std::to_string(number) + ')' : "st";
        }
        for (char &byte : name)
          byte = std::tolower(static_cast<unsigned char>(byte));
        clobbers.insert(std::move(name));
      }
    }
    if (site.call || site.ret || site.memory_write ||
        site.assembly.rfind("lock", 0) == 0)
      clobbers.insert("memory");
    append("\" : ");
    for (size_t index = 0; index < outputs.size(); ++index) {
      if (index)
        append(", ");
      append(outputs[index], ct_kernel_code_color::resolved);
    }
    if (!inputs.empty() || !clobbers.empty() || jump) {
      append(" : ");
      for (size_t index = 0; index < inputs.size(); ++index) {
        if (index)
          append(", ");
        append(inputs[index], ct_kernel_code_color::resolved);
      }
    }
    if (!clobbers.empty() || jump) {
      append(" : ");
      size_t index = 0;
      for (const auto &name : clobbers) {
        if (index++)
          append(", ");
        append('"' + name + '"', name == "cc" || name == "memory"
                                     ? ct_kernel_code_color::normal
                                     : ct_kernel_code_color::machine);
      }
    }
    if (jump) {
      append(" : ");
      append(label, ct_kernel_code_color::machine);
      if (after && site.branch_target != site.next) {
        if (after->site_id == site.branch_target)
          record.branch_outcome = 1;
        else if (site.conditional && after->site_id == site.next)
          record.branch_outcome = 0;
      }
    }
    append(");");
    append(site.assembly_note);
  }

  ct_kernel_trace_record render(const ct_kernel_observation &before,
                                const ct_kernel_observation *after,
                                const Frame *frame = nullptr) const {
    const Site &site = sites[before.site_id];
    auto record = base_record(before);
    if (frame && record.inlined)
      record.inline_prefix_seen =
          inline_prefix(*frame, before.site_id, record.function);
    assembly_record(record, site, before, after);
    record.end_monotonic_ns = after ? after->monotonic_ns : 0;
    record.stage = after ? ct_kernel_trace_stage::completed
                         : ct_kernel_trace_stage::before;
    std::string inputs, outputs;
    std::vector<ct_kernel_trace_value_span> input_values, output_values;
    for (const auto &reg : site.registers) {
      if (reg.xstate >= 13 && reg.xstate != 17 && reg.xstate != 18) {
        const uint64_t mask_registers =
            (UINT64_C(1) << KCTRACE_REG_RAX) | (UINT64_C(1) << KCTRACE_REG_RDX);
        const unsigned component = (reg.xstate == 13 || reg.xstate == 19)
                                       ? reg.number
                                   : reg.xstate == 14 ? 18
                                   : reg.xstate == 16 ? 0
                                                      : 17;
        const uint64_t requested =
            (UINT64_C(1) << component) | (reg.xstate == 19 ? 4 : 0);
        if ((before.valid_registers & mask_registers) != mask_registers ||
            !((uint32_t(before.registers[KCTRACE_REG_RAX]) |
               (uint64_t(uint32_t(before.registers[KCTRACE_REG_RDX])) << 32)) &
              requested))
          continue;
      }
      const auto value = [&](const ct_kernel_observation &event) {
        if (reg.xstate) {
          if (!values || !captures || event.site_id >= values->sites.size())
            return std::string("?");
          const auto plan = values->sites[event.site_id].capture_plan;
          if (!plan || plan >= captures->size() || event.capture_plan != plan)
            return std::string("?");
          if (reg.xstate == 14)
            return ct_kernel_tile_value((*captures)[plan], event, reg.number,
                                        false, true);
          if (reg.xstate == 9 || reg.xstate == 11 || reg.xstate == 12) {
            // A successful configuration/reset instruction clears tile data.
            // Fault/fixup is not completion and cannot prove that result.
            const bool initialized = reg.xstate == 11 && &event == after &&
                                     event.site_id == site.next;
            return ct_kernel_tile_value((*captures)[plan], event, reg.number,
                                        initialized);
          }
          std::array<unsigned char, 64> bytes{};
          const auto read = [&](unsigned component, uint64_t offset, void *out,
                                size_t size) {
            return ct_kernel_xstate_bytes((*captures)[plan], event, component,
                                          offset, out, size);
          };
          bool valid = false;
          const unsigned size = (reg.bits + 7) / 8;
          if (reg.xstate == 1) {
            if (reg.number >= 16) {
              valid = read(7, (reg.number - 16) * 64, bytes.data(), size);
            } else {
              valid = read(1, 160 + reg.number * 16, bytes.data(), 16);
              if (size >= 32)
                valid =
                    valid && read(2, reg.number * 16, bytes.data() + 16, 16);
              if (size == 64)
                valid =
                    valid && read(6, reg.number * 32, bytes.data() + 32, 32);
            }
          } else if (reg.xstate == 2 || reg.xstate == 3 || reg.xstate == 16 ||
                     reg.xstate == 18) {
            unsigned char tag = 0;
            uint16_t status = 0;
            valid = read(0, 4, &tag, 1) && read(0, 2, &status, 2);
            const unsigned physical = reg.xstate != 3
                                          ? ((status >> 11) + reg.number) % 8
                                          : reg.number;
            const unsigned logical =
                reg.xstate != 3 ? reg.number
                                : (reg.number + 8 - ((status >> 11) & 7)) % 8;
            valid = valid && (reg.xstate == 3 || (tag & (1U << physical))) &&
                    read(0, 32 + logical * 16, bytes.data(), size);
          } else if (reg.xstate == 4) {
            valid = read(5, reg.number * 8, bytes.data(), 8);
          } else if (reg.xstate == 10 || reg.xstate == 15) {
            valid = read(17, 0, bytes.data(), bytes.size());
          } else if (reg.xstate == 13 || reg.xstate == 17 || reg.xstate == 19) {
            valid = read(reg.number, reg.shift, bytes.data(), size);
          } else {
            const unsigned component = reg.xstate == 7 ? 1 : 0;
            const unsigned offset = reg.xstate == 5   ? 0
                                    : reg.xstate == 6 ? 2
                                    : reg.xstate == 7 ? 24
                                                      : 4;
            valid = read(component, offset, bytes.data(), size);
          }
          if (!valid)
            return std::string("?");
          std::string rendered = "0x";
          for (unsigned byte = size; byte-- > 0;) {
            rendered += "0123456789abcdef"[bytes[byte] >> 4];
            rendered += "0123456789abcdef"[bytes[byte] & 15];
          }
          return rendered;
        }
        if (!(event.valid_registers & (UINT64_C(1) << reg.slot)))
          return std::string("?");
        const uint64_t mask =
            reg.bits == 64 ? UINT64_MAX : (UINT64_C(1) << reg.bits) - 1;
        return llvm::formatv("0x{0:x-}",
                             (event.registers[reg.slot] >> reg.shift) & mask)
            .str();
      };
      if (reg.read || (reg.write && reg.xstate != 11 && reg.xstate != 12)) {
        if (!inputs.empty())
          inputs += ' ';
        const size_t begin = inputs.size();
        const auto rendered = value(before);
        inputs += '%' + reg.name + '=' + rendered;
        input_values.push_back({begin, inputs.size() - begin, reg.name,
                                reg.bits, false, rendered == "?"});
      }
      if (reg.write && after) {
        if (!outputs.empty())
          outputs += ' ';
        const size_t begin = outputs.size();
        const auto rendered = value(*after);
        outputs += '%' + reg.name + '=' + rendered;
        output_values.push_back({begin, outputs.size() - begin, reg.name,
                                 reg.bits, false, rendered == "?"});
      }
    }
    // Source access metadata names precisely the selected object or member.
    // An assembly operand touching part of an aggregate does not justify
    // dumping that aggregate's unrelated fields.
    if (frame && source && site.source_line &&
        site.source_line < source->lines.size() &&
        source->lines[site.source_line].presentation) {
      const auto observed =
          source_values(source->lines[site.source_line].presentation->variables,
                        site.source_owner, before, *frame);
      for (const auto &value : observed) {
        if (!value.access)
          continue;
        if (!inputs.empty())
          inputs += ' ';
        const size_t begin = inputs.size();
        inputs += value.name + '=' + value.before;
        ct_kernel_trace_value_span span{
            begin, inputs.size() - begin, value.name,    0,
            false, value.before == "?",   value.variable};
        span.type = value.type;
        span.address = value.address;
        input_values.push_back(std::move(span));
      }
    }
    if (site.memory) {
      std::string memory_name = "[?]", address = "?";
      const auto &operand = site.memory_operand;
      const ct_kernel_value_variable *memory_variable = nullptr;
      bool ambiguous = false;
      if (operand.size && values && before.site_id < values->sites.size())
        for (const auto &binding : values->sites[before.site_id].bindings) {
          const auto &variable = values->variables[binding.variable];
          if (!variable.type || variable.name.empty())
            continue;
          const auto &type = values->types[variable.type];
          unsigned slot = 0;
          const auto *storage = capture(variable.id, before.site_id, slot);
          if (!storage || type.guarded || type.scalar.bytes != operand.size ||
              storage->capture.size != operand.size)
            continue;
          const auto &descriptor = storage->capture;
          bool matched = descriptor.kind == KCTRACE_CAPTURE_OBJECT &&
                         storage->section == operand.section &&
                         __int128(storage->object_offset) + descriptor.offset ==
                             operand.target;
          if (descriptor.kind == KCTRACE_CAPTURE_STACK &&
              descriptor.reg < KCTRACE_REGISTER_COUNT &&
              operand.reg < KCTRACE_REGISTER_COUNT &&
              (before.valid_registers & (UINT64_C(1) << descriptor.reg)) &&
              (before.valid_registers & (UINT64_C(1) << operand.reg)))
            matched =
                __int128(before.registers[descriptor.reg]) +
                    descriptor.offset ==
                __int128(before.registers[operand.reg]) + operand.displacement;
          if (matched) {
            ambiguous |= memory_variable && memory_variable->id != variable.id;
            memory_variable = &variable;
          }
        }
      if (ambiguous)
        memory_variable = nullptr;
      if (operand.size && operand.reg < KCTRACE_REGISTER_COUNT) {
        const auto reg =
            std::find_if(site.registers.begin(), site.registers.end(),
                         [&](const auto &candidate) {
                           return candidate.slot == operand.reg &&
                                  candidate.bits == 64 && !candidate.shift;
                         });
        if (reg != site.registers.end()) {
          memory_name = "[%" + reg->name;
          if (operand.displacement)
            memory_name +=
                llvm::formatv("{0}0x{1:x-}",
                              operand.displacement < 0 ? "-" : "+",
                              operand.displacement < 0
                                  ? uint64_t(0) - uint64_t(operand.displacement)
                                  : uint64_t(operand.displacement))
                    .str();
          memory_name += ']';
        }
        if (before.valid_registers & (UINT64_C(1) << operand.reg)) {
          const __int128 effective =
              __int128(before.registers[operand.reg]) + operand.displacement;
          if (effective >= 0 && effective <= UINT64_MAX)
            address = llvm::formatv("0x{0:x-}", uint64_t(effective)).str();
        }
      }
      if ((before.flags & KCTRACE_EVENT_HAVE_MEMORY) &&
          !(before.flags & KCTRACE_EVENT_HAVE_VALUES) && before.memory_size)
        address = llvm::formatv("0x{0:x-}", before.memory_address).str();
      if (site.indexed_memory) {
        const auto &operand = *site.indexed_memory;
        const auto name = [&](unsigned slot) {
          const auto found = std::find_if(
              site.registers.begin(), site.registers.end(),
              [&](const auto &reg) {
                return reg.slot == slot && reg.bits == 64 && !reg.shift;
              });
          return found == site.registers.end() ? std::string("?")
                                               : '%' + found->name;
        };
        memory_name = '[' + name(operand.base) + '+' + name(operand.index) +
                      llvm::formatv("*0x{0:x-}", operand.scale).str();
        if (operand.displacement)
          memory_name +=
              llvm::formatv("{0}0x{1:x-}", operand.displacement < 0 ? "-" : "+",
                            operand.displacement < 0
                                ? uint64_t(0) - uint64_t(operand.displacement)
                                : uint64_t(operand.displacement))
                  .str();
        memory_name += ']';
        if ((before.valid_registers & (UINT64_C(1) << operand.base)) &&
            (before.valid_registers & (UINT64_C(1) << operand.index))) {
          const uint64_t effective =
              before.registers[operand.base] +
              before.registers[operand.index] * operand.scale +
              uint64_t(operand.displacement);
          address = llvm::formatv("0x{0:x-}", effective).str();
        }
      }
      if (memory_name == "[?]" && address != "?")
        memory_name = '[' + address + ']';
      if (memory_variable)
        memory_name = memory_variable->name;
      if (!inputs.empty())
        inputs += ' ';
      const size_t address_begin = inputs.size();
      inputs += '&' + memory_name + '=' + address;
      input_values.push_back({address_begin,
                              inputs.size() - address_begin,
                              {},
                              0,
                              false,
                              address == "?"});
      if (!inputs.empty())
        inputs += ' ';
      if ((before.flags & KCTRACE_EVENT_HAVE_MEMORY) &&
          !(before.flags & KCTRACE_EVENT_HAVE_VALUES) && before.memory_size) {
        inputs += memory_name + "=[";
        for (uint32_t index = 0; index < before.memory_size; ++index) {
          if (index)
            inputs += ' ';
          inputs += llvm::formatv("0x{0:x-2}", before.memory[index]).str();
        }
        inputs += ']';
      } else {
        const bool completed =
            after && site.next == after->site_id &&
            before.execution.frame_id == after->execution.frame_id;
        const bool load = site.memory_read && !site.memory_write;
        const auto *observed = load ? after : &before;
        const bool known =
            completed && site.memory_value_width &&
            (site.memory_value_literal ||
             (observed && site.memory_value_register < KCTRACE_REGISTER_COUNT &&
              (observed->valid_registers &
               (UINT64_C(1) << site.memory_value_register))));
        std::string value = "?";
        if (known) {
          const uint64_t raw =
              site.memory_value_literal
                  ? site.memory_value_immediate
                  : observed->registers[site.memory_value_register] >>
                        site.memory_value_shift;
          const auto bits = site.memory_value_width * 8;
          const auto mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
          value =
              memory_variable
                  ? scalar_value(values->types[memory_variable->type].scalar,
                                 reinterpret_cast<const unsigned char *>(&raw),
                                 site.memory_value_width)
                  : llvm::formatv("0x{0:x-}", raw & mask).str();
        }
        const size_t begin = inputs.size();
        inputs += memory_name + '=' + (load ? value : std::string("?"));
        input_values.push_back({begin, inputs.size() - begin,
                                memory_variable ? memory_name : std::string{},
                                0, false, !load || !known,
                                memory_variable ? memory_variable->id : 0});
        if (!load && known) {
          if (!outputs.empty())
            outputs += ' ';
          const size_t output_begin = outputs.size();
          outputs += memory_name + '=' + value;
          output_values.push_back({output_begin,
                                   outputs.size() - output_begin,
                                   {},
                                   0,
                                   false,
                                   false});
        }
      }
    }
    if (!inputs.empty() || !outputs.empty()) {
      record.comment_offset = record.text.size() + 1;
      record.text += " #";
      if (!inputs.empty()) {
        record.text += ' ';
        for (auto span : input_values) {
          span.offset += record.text.size();
          record.values.push_back(std::move(span));
        }
        record.text += inputs;
      }
      if (!outputs.empty()) {
        record.text += " -> ";
        for (auto span : output_values) {
          span.offset += record.text.size();
          record.values.push_back(std::move(span));
        }
        record.text += outputs;
      }
    }
    return record;
  }

  ct_kernel_trace_record summarize(const Frame &frame,
                                   const ct_kernel_observation *after) const {
    auto record = render(frame.entry, after);
    record.values.clear();
    record.inline_assembly = false;
    record.assembly_styles.clear();
    record.function_summary = true;
    record.text = record.function + "(...); #";
    record.comment_offset = record.text.size() - 1;
    if (after) {
      record.text += " completed";
      // A scalar return type has not been established; expose the captured
      // register without asserting that every function returns its contents.
      if (after->valid_registers & (UINT64_C(1) << KCTRACE_REG_RAX)) {
        record.text += ' ';
        const size_t begin = record.text.size();
        record.text +=
            llvm::formatv("%RAX=0x{0:x-}", after->registers[KCTRACE_REG_RAX])
                .str();
        record.values.push_back({begin, record.text.size() - begin, "RAX", 64});
      }
    } else {
      record.text += ' ';
      const size_t begin = record.text.size();
      record.text += "completion=?";
      record.values.push_back(
          {begin, record.text.size() - begin, {}, 0, false, true});
    }
    return record;
  }

  void emit(ct_kernel_trace_record record,
            std::vector<ct_kernel_trace_record> &records,
            Frame *frame = nullptr) {
    size_t inserted = 0;
    for (auto &span : record.values) {
      span.offset += inserted;
      if (span.bits && introduced.insert(span.name).second) {
        const std::string type = "(uint" + std::to_string(span.bits) + "_t)";
        record.text.insert(span.offset + span.name.size() + 2, type);
        span.length += type.size();
        inserted += type.size();
        span.introduction = true;
      } else if (span.variable && values && frame &&
                 span.variable < values->variables.size()) {
        const auto &variable = values->variables[span.variable];
        const auto identity = std::to_string(variable.id) + ':' + span.name +
                              (span.address ? ":address" : "");
        const bool first = variable.global
                               ? introduced_globals.insert(identity).second
                               : frame->introduced.insert(identity).second;
        if (first && variable.type && variable.type < values->types.size()) {
          const auto &name =
              span.type.empty() ? values->types[variable.type].name : span.type;
          if (!name.empty() && !span.address) {
            const std::string type = '(' + name + ')';
            record.text.insert(span.offset + span.name.size() + 1, type);
            span.length += type.size();
            inserted += type.size();
          }
          span.introduction = true;
        }
      }
    }
    records.push_back(std::move(record));
  }

  static std::string scalar_value(const ct_value_type &type,
                                  const unsigned char *bytes, size_t size) {
    char output[128];
    const int length =
        ct_values_format_scalar(&type, bytes, size, output, sizeof(output));
    return length >= 0 && size_t(length) < sizeof(output)
               ? std::string(output, size_t(length))
               : "?";
  }

  const ct_kernel_value_binding *binding(uint64_t variable,
                                         uint64_t site) const {
    if (!values || !variable || site >= values->sites.size())
      return nullptr;
    const auto &bindings = values->sites[site].bindings;
    const auto found = std::find_if(
        bindings.begin(), bindings.end(),
        [&](const auto &candidate) { return candidate.variable == variable; });
    return found == bindings.end() ? nullptr : &*found;
  }

  std::string variable_value(uint64_t variable,
                             const ct_kernel_observation &event,
                             const Frame &frame) const {
    const auto *location = binding(variable, event.site_id);
    if (!location)
      return "?";
    return ct_kernel_format_value(*values, *location, event, &frame.entry);
  }

  std::string source_value(const SourceValue &value,
                           const ct_kernel_observation &event,
                           const Frame &frame) const {
    if (!value.access)
      return variable_value(value.variable, event, frame);
    if (!values || event.site_id >= values->sites.size() ||
        value.access >= values->accesses.size())
      return "?";
    const auto &access = values->accesses[value.access];
    const auto &bindings = values->sites[event.site_id].accesses;
    const auto selected = std::find_if(
        bindings.begin(), bindings.end(),
        [&](const auto &binding) { return binding.access == value.access; });
    std::string result =
        selected == bindings.end()
            ? "?"
            : ct_kernel_format_access(*values, *selected, event);
    // An entry-value recipe can prove the pointer itself without authorizing
    // a new read through it. Do not apply that fallback to any selected leaf.
    if (result == "?" && !access.address && access.variable &&
        access.variable < values->variables.size() &&
        access.name == values->variables[access.variable].name &&
        access.layout_type &&
        access.layout_type <= values->layout_types.size() &&
        values->layout_types[access.layout_type - 1].kind == CT_LAYOUT_POINTER)
      result = variable_value(access.variable, event, frame);
    return result;
  }

  const ct_kernel_value_variable *
  named_variable(const std::string &name, const std::string &owner,
                 uint64_t site, bool parameters = false) const {
    if (!values || site >= values->sites.size())
      return nullptr;
    const ct_kernel_value_variable *selected = nullptr;
    bool ambiguous = false;
    for (const auto &location : values->sites[site].bindings) {
      const auto &candidate = values->variables[location.variable];
      if (candidate.name != name ||
          (!candidate.global && candidate.owner != owner) ||
          (parameters && !candidate.parameter))
        continue;
      if (!selected || (parameters ? candidate.depth < selected->depth
                                   : candidate.depth > selected->depth)) {
        selected = &candidate;
        ambiguous = false;
      } else if (candidate.depth == selected->depth &&
                 candidate.id != selected->id) {
        ambiguous = true;
      }
    }
    return ambiguous ? nullptr : selected;
  }

  struct Member {
    uint64_t variable, offset;
    ct_value_type type;
  };

  std::optional<Member> source_member(llvm::StringRef path,
                                      const std::string &owner,
                                      uint64_t site) const {
    if (!values)
      return std::nullopt;
    const auto identifier = [&]() {
      path = path.ltrim();
      size_t length = 0;
      while (length < path.size() &&
             (std::isalnum(static_cast<unsigned char>(path[length])) ||
              path[length] == '_'))
        ++length;
      if (!length || std::isdigit(static_cast<unsigned char>(path.front())))
        return std::string();
      const auto name = path.take_front(length).str();
      path = path.drop_front(length).ltrim();
      return name;
    };
    const auto name = identifier();
    if (name.empty() || !path.consume_front("->"))
      return std::nullopt;
    const auto *base = named_variable(name, owner, site);
    if (!base || !base->type || base->type >= values->types.size())
      return std::nullopt;
    const auto &type = values->types[base->type];
    if (type.guarded || type.scalar.kind != CT_VALUE_POINTER ||
        type.scalar.bytes != 8 || !type.pointee_layout_type)
      return std::nullopt;
    uint32_t layout = type.pointee_layout_type;
    uint64_t offset = 0;
    for (;;) {
      const auto field = identifier();
      if (field.empty() || !layout || layout > values->layout_types.size())
        return std::nullopt;
      const auto &parent = values->layout_types[layout - 1];
      if ((parent.kind != CT_LAYOUT_STRUCT && parent.kind != CT_LAYOUT_UNION) ||
          parent.guarded ||
          parent.first_member > values->layout_members.size() ||
          parent.member_count >
              values->layout_members.size() - parent.first_member)
        return std::nullopt;
      const ct_value_layout_member *member = nullptr;
      for (size_t index = 0; index < parent.member_count; ++index) {
        const auto &candidate =
            values->layout_members[parent.first_member + index];
        if (candidate.name != field)
          continue;
        if (member)
          return std::nullopt;
        member = &candidate;
      }
      if (!member || !member->available || !member->type ||
          member->type > values->layout_types.size() ||
          member->offset > parent.bytes ||
          values->layout_types[member->type - 1].bytes >
              parent.bytes - member->offset ||
          member->offset > UINT64_MAX - offset)
        return std::nullopt;
      layout = member->type;
      offset += member->offset;
      if (!path.consume_front("."))
        break;
    }
    if (!path.empty())
      return std::nullopt;
    const auto &member = values->layout_types[layout - 1];
    ct_value_type scalar = member.scalar;
    if (member.kind == CT_LAYOUT_POINTER && member.bytes == 8)
      scalar = {CT_VALUE_POINTER, 8};
    if (member.guarded ||
        (member.kind != CT_LAYOUT_SCALAR && member.kind != CT_LAYOUT_POINTER) ||
        scalar.kind == CT_VALUE_UNKNOWN || !scalar.bytes || scalar.bytes > 8)
      return std::nullopt;
    return Member{base->id, offset, scalar};
  }

  std::vector<SourceValue>
  source_values(const std::vector<ct_source_variable> &references,
                const std::string &owner, const ct_kernel_observation &event,
                const Frame &frame, bool parameters = false) const {
    std::vector<SourceValue> result;
    for (const auto &reference : references) {
      if (reference.function != owner || reference.name.empty())
        continue;
      const auto append = [&](SourceValue value) {
        const auto previous =
            std::find_if(result.begin(), result.end(), [&](const auto &item) {
              return item.name == value.name && item.address == value.address;
            });
        if (previous == result.end())
          result.push_back(std::move(value));
        else {
          const bool declared = previous->declared || value.declared;
          const bool read_before = previous->read_before || value.read_before;
          if (!previous->variable && value.variable)
            *previous = std::move(value);
          previous->declared = declared;
          previous->read_before = read_before;
        }
      };
      const auto *selected =
          named_variable(reference.name, owner, event.site_id, parameters);
      if (!parameters && !reference.access.empty()) {
        bool found = false;
        if (selected && event.site_id < values->sites.size())
          for (const auto &binding : values->sites[event.site_id].accesses) {
            if (!binding.access || binding.access >= values->accesses.size())
              continue;
            const auto &access = values->accesses[binding.access];
            if (access.variable != selected->id ||
                access.expression != reference.access)
              continue;
            SourceValue value;
            value.variable = selected->id;
            value.access = binding.access;
            value.name = access.name;
            value.address = access.address;
            value.global = selected->global;
            if (!access.address && access.layout_type &&
                access.layout_type <= values->layout_names.size())
              value.type = values->layout_names[access.layout_type - 1];
            value.before = source_value(value, event, frame);
            append(std::move(value));
            found = true;
          }
        if (!found) {
          // Preserve the requested labels when DWARF cannot identify the
          // object. In particular, do not substitute a whole parent object.
          ct_source_access access;
          if (ct_parse_source_access(reference.access, access)) {
            bool dereferenced = false;
            for (const auto &step : access.steps) {
              if (dereferenced && step.kind == ct_source_access_kind::member) {
                dereferenced = false;
                continue;
              }
              SourceValue base;
              base.name = step.base;
              base.address = step.kind == ct_source_access_kind::member;
              append(std::move(base));
              dereferenced = step.kind == ct_source_access_kind::dereference;
            }
            SourceValue leaf;
            leaf.name = access.text;
            append(std::move(leaf));
          }
        }
        continue;
      }
      SourceValue value;
      value.name = reference.name;
      value.declared = reference.declaration || parameters;
      value.read_before = !reference.declaration || parameters;
      if (selected) {
        value.variable = selected->id;
        value.global = selected->global;
        if (selected->type)
          value.type = values->types[selected->type].name;
        value.before = variable_value(value.variable, event, frame);
      }
      if (parameters && value.before == "?" &&
          frame.function < functions.size()) {
        const auto site = functions[frame.function].parameter_site;
        if (site && site != event.site_id) {
          auto entry = event;
          entry.site_id = site;
          const auto *variable = named_variable(value.name, owner, site, true);
          const auto *location =
              variable ? binding(variable->id, site) : nullptr;
          if (location && location->recipe &&
              location->recipe < values->recipes.size()) {
            const auto &recipe = values->recipes[location->recipe];
            if (ct_kernel_recipe_register(recipe)) {
              value.variable = variable->id;
              value.type = values->types[variable->type].name;
              value.before = variable_value(variable->id, entry, frame);
            }
          }
        }
      }
      append(std::move(value));
    }
    return result;
  }

  void source_field(ct_kernel_trace_record &record, Frame &frame,
                    const SourceValue &value, const std::string &text,
                    bool first) {
    bool introduced = false;
    if (first) {
      const std::string identity = std::to_string(value.variable) + ':' +
                                   value.name +
                                   (value.address ? ":address" : "");
      const bool register_alias =
          values && value.variable &&
          value.variable < values->variables.size() &&
          values->variables[value.variable].register_alias;
      introduced = register_alias ? this->introduced.insert(value.name).second
                   : value.global ? introduced_globals.insert(identity).second
                                  : frame.introduced.insert(identity).second;
    }
    // A declaration introduces its type in the source, but does not read its
    // destination's old storage. Keep the value for the assignment's after
    // snapshot and for an explicit initializer reference to the same object.
    if (first && !value.read_before)
      return;
    if (record.comment_offset == std::string::npos) {
      record.text += ' ';
      record.comment_offset = record.text.size();
      record.text += '#';
    }
    record.text += ' ';
    const size_t begin = record.text.size();
    record.text += value.name + '=';
    introduced &= !value.declared;
    // Selected access layouts are derived from the declared root type. The
    // displayed root already carries that type, so its dereference/member
    // does not introduce a new one. Missing layouts never establish this.
    if (introduced && value.access && values && value.variable &&
        value.variable < values->variables.size() &&
        value.access < values->accesses.size()) {
      const auto &variable = values->variables[value.variable];
      const auto &access = values->accesses[value.access];
      if (variable.type && variable.type < values->types.size() &&
          !values->types[variable.type].name.empty() && access.layout_type &&
          access.layout_type <= values->layout_types.size() &&
          access.name != variable.name)
        introduced = false;
    }
    if (introduced && !value.type.empty())
      record.text += '(' + value.type + ')';
    record.text += text;
    record.values.push_back({begin, record.text.size() - begin, value.name, 0,
                             introduced, text == "?"});
  }

  void source_result(ct_kernel_trace_record &record, const std::string &name,
                     const std::string &value, bool first,
                     bool introduction = false) {
    if (record.comment_offset == std::string::npos) {
      record.text += ' ';
      record.comment_offset = record.text.size();
      record.text += '#';
    }
    record.text += first ? " -> " : " ";
    const size_t begin = record.text.size();
    record.text += name + '=' + value;
    record.values.push_back(
        {begin, record.text.size() - begin, {}, 0, introduction, value == "?"});
  }

  std::string decompile_text(const std::string &text) const {
    std::string rendered;
    size_t begin = 0;
    while (begin < text.size()) {
      if (text[begin] == '"' || text[begin] == '\'') {
        const auto start = begin;
        const auto quote = text[begin++];
        while (begin < text.size()) {
          const auto character = text[begin++];
          if (character == '\\' && begin < text.size())
            ++begin;
          else if (character == quote)
            break;
        }
        rendered += text.substr(start, begin - start);
        continue;
      }
      if (text.compare(begin, 2, "@L") != 0) {
        rendered += text[begin++];
        continue;
      }
      const auto marker = begin;
      const auto end = text.find('@', marker + 2);
      if (end == std::string::npos) {
        rendered += "?";
        break;
      }
      uint64_t address = 0;
      const auto parsed = std::from_chars(text.data() + marker + 2,
                                          text.data() + end, address, 16);
      bool resolved = false;
      if (parsed.ec == std::errc() && parsed.ptr == text.data() + end) {
        const auto target = decompile_addresses.find(address);
        if (target != decompile_addresses.end()) {
          const auto &site = sites[target->second];
          const auto base = section_bases.find(site.original.section);
          if (base != section_bases.end() &&
              site.original.operation <= UINT64_MAX - base->second) {
            rendered +=
                llvm::formatv("L{0:x-}", base->second + site.original.operation)
                    .str();
            resolved = true;
          }
        }
        if (!resolved) {
          const auto external =
              decompile->layout.external_symbols.find(address);
          if (external != decompile->layout.external_symbols.end()) {
            rendered += external->second;
            resolved = true;
          }
        }
        if (!resolved && address <= UINT64_MAX - decompile->layout.image_base)
          for (const auto &region : decompile->layout.regions) {
            const auto absolute = address + decompile->layout.image_base;
            if (absolute >= region.address &&
                absolute - region.address < region.size) {
              rendered += llvm::formatv("Lsection{0}_{1:x-}", region.section,
                                        absolute - region.address)
                              .str();
              resolved = true;
              break;
            }
          }
      }
      if (!resolved)
        rendered += "?";
      begin = end + 1;
    }
    return rendered;
  }

  void flush_decompile(Frame &frame,
                       std::vector<ct_kernel_trace_record> &records,
                       const ct_kernel_observation *after = nullptr,
                       bool continuing = false, bool unknown_call = false) {
    auto &row = frame.decompiled;
    if (!row.statement)
      return;
    const auto &statement = decompile->statements[row.statement];
    if (!after && !continuing) {
      if (row.last.site_id && (row.fallback.empty() ||
                               row.fallback.back().site_id != row.last.site_id))
        row.fallback.push_back(render(row.last, nullptr, &frame));
      for (auto &record : row.fallback)
        emit(std::move(record), records, &frame);
      row = {};
      return;
    }
    auto record = base_record(row.before);
    record.source = true;
    record.text = decompile_text(statement.text);
    record.stage = after ? ct_kernel_trace_stage::completed
                         : ct_kernel_trace_stage::before;
    record.end_monotonic_ns = after ? after->monotonic_ns : 0;
    const bool global_assignment = std::any_of(
        row.inputs.begin(), row.inputs.end(), [&](const auto &value) {
          return value.global && value.name == statement.declaration_name;
        });
    if (!statement.declaration_name.empty() &&
        !statement.declaration_type.empty() && !global_assignment) {
      const auto key = "declaration:" + statement.declaration_name;
      const auto prefix = statement.declaration_type + " ";
      const bool first_declaration = frame.introduced.insert(key).second;
      if (first_declaration &&
          record.text.compare(0, prefix.size(), prefix) != 0)
        record.text.insert(0, prefix);
      else if (!first_declaration &&
               record.text.compare(0, prefix.size(), prefix) == 0)
        record.text.erase(0, prefix.size());
    }
    for (const auto &value : row.inputs)
      source_field(record, frame, value, value.before, true);
    bool first = true;
    if (after)
      for (const auto variable : row.writes) {
        const auto &definition = values->variables[variable];
        source_result(record, definition.name,
                      variable_value(variable, *after, frame), first);
        first = false;
      }
    const auto &last = sites[row.last.site_id];
    if (after && last.call && row.writes.empty()) {
      std::string invocation = decompile_text(statement.text);
      if (const auto semicolon = invocation.rfind(';');
          semicolon != std::string::npos)
        invocation.erase(semicolon);
      if (!statement.assignment.empty()) {
        const auto equal = invocation.find('=');
        if (equal != std::string::npos)
          invocation.erase(0, invocation.find_first_not_of(" \t", equal + 1));
      }
      ct_value_type type{};
      bool returns_void = false;
      if (values)
        for (const auto &function : decompile->functions)
          if (function.name == last.call_name && function.value_function &&
              function.value_function < values->functions.size()) {
            const auto &returned = values->functions[function.value_function];
            returns_void = returned.returns_void;
            if (returned.return_type)
              type = values->types[returned.return_type].scalar;
            break;
          }
      if (!returns_void)
        source_result(record, invocation,
                      unknown_call ? "?" : returned_scalar(type, *after),
                      first);
    } else if (after && last.ret && !returns_void(frame)) {
      source_result(record,
                    frame.call_source ? frame.call_source->result.text
                    : frame.call_decompile.empty()
                        ? (frame.source_function.empty()
                               ? functions[frame.function].name
                               : frame.source_function) +
                              "(...)"
                        : frame.call_decompile,
                    return_value(frame, *after), first);
    }
    if (after && last.conditional) {
      const auto &control = decompile->sites[row.last.site_id];
      if (control.has_target && (control.control_target == last.branch_target ||
                                 control.control_target == last.next)) {
        if (record.comment_offset == std::string::npos) {
          record.text += " #";
          record.comment_offset = record.text.size() - 1;
        }
        record.text += first ? " -> " : " ";
        record.text += after->site_id == control.control_target ? "0x1" : "0x0";
      }
    }
    if (continuing) {
      if (record.comment_offset == std::string::npos) {
        record.text += " #";
        record.comment_offset = record.text.size() - 1;
      }
      record.text += " -> ...";
      record.call_entry = true;
      row.printed = true;
    }
    records.push_back(std::move(record));
    if (!continuing) {
      row = {};
    }
  }

  void decompile_completed(Frame &frame, const ct_kernel_observation &before,
                           const ct_kernel_observation *after,
                           std::vector<ct_kernel_trace_record> &records) {
    auto &row = frame.decompiled;
    if (!row.statement || row.last.site_id != before.site_id ||
        row.last.sequence != before.sequence)
      return;
    // Sparse statement continuity is not an instruction-after snapshot.
    const auto &operation = sites[before.site_id];
    const auto *completed =
        after && (operation.next == after->site_id ||
                  (operation.branch && !operation.ret &&
                   operation.branch_target == after->site_id))
            ? after
            : nullptr;
    row.fallback.push_back(render(before, completed, &frame));
    const auto &statement = decompile->statements[row.statement];
    if (after && row.next == statement.sites.size())
      flush_decompile(frame, records, after);
    else if (!after && !sites[before.site_id].call &&
             !sites[before.site_id].ret)
      flush_decompile(frame, records);
  }

  void decompile_entry(Frame &frame, const ct_kernel_observation &event,
                       std::vector<ct_kernel_trace_record> &records) {
    if (!decompile || event.site_id >= decompile->sites.size() ||
        sites[event.site_id].source_line)
      return;
    const auto &site = decompile->sites[event.site_id];
    if (!frame.decompile_entry && !frame.source_entry && site.function &&
        site.function < decompile->functions.size()) {
      const auto &function = decompile->functions[site.function];
      if (!function.prototype.empty() && function.prototype.front() != '?') {
        auto record = base_record(event);
        record.source = record.entry = true;
        record.inlined = false;
        record.text = function.prototype + " {";
        frame.entry_invocation = function.name + '(';
        for (size_t index = 0; index < function.parameters.size(); ++index) {
          if (index)
            frame.entry_invocation += ", ";
          const auto variable = function.parameters[index];
          if (values && variable && variable < values->variables.size()) {
            const auto &definition = values->variables[variable];
            SourceValue value;
            value.variable = variable;
            value.name = definition.name;
            value.declared = true;
            frame.introduced.insert("declaration:" + value.name);
            const auto observed = variable_value(variable, frame.entry, frame);
            frame.entry_invocation += observed;
            source_field(record, frame, value, observed, true);
          } else {
            frame.entry_invocation += '?';
          }
        }
        if (function.prototype.find("...") != std::string::npos)
          frame.entry_invocation +=
              function.parameters.empty() ? "..." : ", ...";
        frame.entry_invocation += ')';
        records.push_back(std::move(record));
        frame.decompile_entry = true;
      }
    }
  }

  std::string decompile_call(const Frame &caller) const {
    const auto &row = caller.decompiled;
    if (!decompile || !row.statement ||
        row.next != decompile->statements[row.statement].sites.size() ||
        (caller.execution_id && row.last.site_id != caller.call_site))
      return {};
    const auto &statement = decompile->statements[row.statement];
    auto text = decompile_text(statement.text);
    if (const auto semicolon = text.rfind(';'); semicolon != std::string::npos)
      text.erase(semicolon);
    if (!statement.assignment.empty()) {
      const auto equal = text.find('=');
      if (equal != std::string::npos)
        text.erase(0, text.find_first_not_of(" \t", equal + 1));
    }
    return text;
  }

  bool decompile_observation(Frame &frame, const ct_kernel_observation &event,
                             std::vector<ct_kernel_trace_record> &records) {
    if (!decompile || event.site_id >= decompile->sites.size())
      return false;
    if (sites[event.site_id].source_line)
      return false;
    const auto &site = decompile->sites[event.site_id];
    auto &row = frame.decompiled;
    if (row.statement && row.statement == site.statement) {
      const auto &statement = decompile->statements[row.statement];
      while (row.next < site.index && row.next < statement.sites.size() &&
             !observation_sites[statement.sites[row.next]])
        ++row.next;
    }
    if (row.statement &&
        (row.statement != site.statement || row.next != site.index))
      flush_decompile(frame, records);
    decompile_entry(frame, event, records);
    if (!site.statement || (site.index && !row.statement))
      return false;
    const auto &statement = decompile->statements[site.statement];
    if (!row.statement) {
      row.statement = site.statement;
      row.before = event;
    }
    row.last = event;
    row.next = site.index + 1;
    for (const auto &reference : site.variables) {
      if (!values || !reference.variable ||
          reference.variable >= values->variables.size())
        continue;
      const auto &definition = values->variables[reference.variable];
      if (!ct_kernel_decompile_identifier(statement.text, definition.name))
        continue;
      if (std::none_of(row.inputs.begin(), row.inputs.end(),
                       [&](const auto &value) {
                         return value.variable == reference.variable;
                       })) {
        SourceValue value;
        value.variable = reference.variable;
        value.name = definition.name;
        value.type = values->types[definition.type].name;
        value.global = definition.global;
        value.declared = value.name == statement.declaration_name;
        value.before = variable_value(value.variable, event, frame);
        row.inputs.push_back(std::move(value));
      } else {
        auto known = std::find_if(row.inputs.begin(), row.inputs.end(),
                                  [&](const auto &value) {
                                    return value.variable == reference.variable;
                                  });
        if (known->before == "?")
          known->before = variable_value(reference.variable, event, frame);
      }
      if ((reference.access & CT_DECOMPILED_WRITE) &&
          std::find(row.writes.begin(), row.writes.end(), reference.variable) ==
              row.writes.end())
        row.writes.push_back(reference.variable);
    }
    return true;
  }

  unsigned location_register(const ct_kernel_value_binding *location) const {
    if (!location || !location->recipe ||
        !values->recipes[location->recipe].error.empty())
      return KCTRACE_REGISTER_COUNT;
    const auto type = values->variables[location->variable].type;
    if (!type)
      return KCTRACE_REGISTER_COUNT;
    const uint64_t number =
        ct_kernel_recipe_register(values->recipes[location->recipe],
                                  values->types[type].scalar.bytes)
            .value_or(UINT64_MAX);
    static constexpr unsigned slots[] = {
        KCTRACE_REG_RAX, KCTRACE_REG_RDX, KCTRACE_REG_RCX, KCTRACE_REG_RBX,
        KCTRACE_REG_RSI, KCTRACE_REG_RDI, KCTRACE_REG_RBP, KCTRACE_REG_RSP,
        KCTRACE_REG_R8,  KCTRACE_REG_R9,  KCTRACE_REG_R10, KCTRACE_REG_R11,
        KCTRACE_REG_R12, KCTRACE_REG_R13, KCTRACE_REG_R14, KCTRACE_REG_R15,
        KCTRACE_REG_RIP};
    return number < std::size(slots) ? slots[number] : KCTRACE_REGISTER_COUNT;
  }

  const ct_kernel_capture_slot *capture(uint64_t variable, uint64_t site,
                                        unsigned &slot) const {
    const auto *location = binding(variable, site);
    if (!location || !captures || site >= values->sites.size())
      return nullptr;
    const auto plan = values->sites[site].capture_plan;
    slot = location->capture_slot;
    return plan && plan < captures->size() &&
                   slot < (*captures)[plan].slots.size()
               ? &(*captures)[plan].slots[slot]
               : nullptr;
  }

  bool memory_completed(const Site &site, const ct_kernel_observation &before,
                        const ct_kernel_observation &after) const {
    unsigned slot = 0;
    const auto *captured = capture(site.source_assignment, after.site_id, slot);
    if (!captured || !(after.flags & KCTRACE_EVENT_HAVE_VALUES) ||
        after.capture_plan != values->sites[after.site_id].capture_plan ||
        !after.capture_data(slot))
      return false;
    const auto &descriptor = captured->capture;
    if (descriptor.kind == KCTRACE_CAPTURE_OBJECT)
      return true; // Exact section, object offset and width checked offline.
    if (descriptor.kind != KCTRACE_CAPTURE_STACK ||
        site.store.reg >= KCTRACE_REGISTER_COUNT ||
        descriptor.reg >= KCTRACE_REGISTER_COUNT ||
        !(before.valid_registers & (UINT64_C(1) << site.store.reg)) ||
        !(after.valid_registers & (UINT64_C(1) << descriptor.reg)))
      return false;
    const __int128 written =
        __int128(before.registers[site.store.reg]) + site.store.displacement;
    const __int128 observed =
        __int128(after.registers[descriptor.reg]) + descriptor.offset;
    return written >= 0 && written <= UINT64_MAX && written == observed;
  }

  void complete_assignment(Frame &frame, const Site &site,
                           const ct_kernel_observation &before,
                           const ct_kernel_observation &after) const {
    auto &row = frame.row;
    if (!site.source_assignment || !row.line ||
        (row.call_bearing && !row.call_seen) || site.source_line != row.line ||
        site.source_owner != row.owner)
      return;
    if (site.stored_assignment) {
      const auto &assignment = *site.stored_assignment;
      bool matched = false;
      if (assignment.indirect) {
        const auto *location = binding(site.source_assignment, before.site_id);
        ct_kernel_value_result pointer;
        if (location &&
            ct_kernel_evaluate_value(*values, *location, before, pointer,
                                     &frame.entry) &&
            pointer.size == sizeof(uint64_t) &&
            site.store.reg < KCTRACE_REGISTER_COUNT &&
            (before.valid_registers & (UINT64_C(1) << site.store.reg))) {
          uint64_t address = 0;
          std::memcpy(&address, pointer.bytes.data(), sizeof(address));
          const __int128 expected =
              __int128(address) + assignment.member_offset;
          const __int128 written = __int128(before.registers[site.store.reg]) +
                                   site.store.displacement;
          matched = address && expected <= UINT64_MAX && expected == written;
        }
      } else {
        // A completed MOV supplies the bytes it stored, including when the
        // successor has no DWARF location/capture. The storage identity must
        // still match this instruction; no pointer is read speculatively.
        for (const auto *observed : {&before, &after}) {
          unsigned slot = 0;
          const auto *storage =
              capture(site.source_assignment, observed->site_id, slot);
          if (!storage || storage->capture.size != site.store.size)
            continue;
          const auto &descriptor = storage->capture;
          if (descriptor.kind == KCTRACE_CAPTURE_OBJECT) {
            matched = storage->section == site.store.section &&
                      __int128(storage->object_offset) + descriptor.offset ==
                          site.store.target;
          } else if (descriptor.kind == KCTRACE_CAPTURE_STACK &&
                     site.store.reg < KCTRACE_REGISTER_COUNT &&
                     descriptor.reg < KCTRACE_REGISTER_COUNT &&
                     (before.valid_registers &
                      (UINT64_C(1) << site.store.reg)) &&
                     (observed->valid_registers &
                      (UINT64_C(1) << descriptor.reg))) {
            const __int128 written =
                __int128(before.registers[site.store.reg]) +
                site.store.displacement;
            const __int128 expected =
                __int128(observed->registers[descriptor.reg]) +
                descriptor.offset;
            matched =
                written >= 0 && written <= UINT64_MAX && written == expected;
          }
          if (matched)
            break;
        }
      }
      if (!matched ||
          (!site.store_literal &&
           (site.store_register >= KCTRACE_REGISTER_COUNT ||
            !(before.valid_registers & (UINT64_C(1) << site.store_register)))))
        return;
      const uint64_t value =
          site.store_literal
              ? site.store_immediate
              : before.registers[site.store_register] >> site.store_shift;
      row.assigned_name = assignment.name;
      row.assigned_value = scalar_value(
          assignment.type, reinterpret_cast<const unsigned char *>(&value),
          assignment.type.bytes);
    } else if (site.memory_assignment &&
               !memory_completed(site, before, after)) {
      return;
    }
    row.after = after;
    row.assigned = site.source_assignment;
  }

  void source_condition(Frame &frame, const ct_kernel_observation &before,
                        const ct_kernel_observation &after) const {
    if (!source || before.site_id >= source->sites.size() || !frame.row.line)
      return;
    const auto &site = sites[before.site_id];
    const auto successor = source->sites[before.site_id].not_taken_successor;
    if (!site.branch || site.ret || site.source_line != frame.row.line ||
        site.source_owner != frame.row.owner)
      return;
    if (successor &&
        (site.branch_target == after.site_id || site.next == after.site_id)) {
      frame.row.condition_outcome = successor != after.site_id;
      return;
    }
    if (!site.conditional || !values ||
        (site.branch_target != after.site_id && site.next != after.site_id))
      return;
    const auto &expression =
        source->lines[frame.row.line].presentation->expression;
    if (expression.kind != CT_EXPRESSION_NONE ||
        expression.function != frame.row.owner ||
        expression.comparison.kind == CT_SOURCE_COMPARE_NONE)
      return;
    const auto *variable = named_variable(expression.comparison.variable,
                                          frame.row.owner, before.site_id);
    if (!variable || variable->global || !variable->type ||
        variable->type >= values->types.size())
      return;
    const auto &type = values->types[variable->type];
    const auto reg = location_register(binding(variable->id, before.site_id));
    if (type.guarded || reg >= KCTRACE_REGISTER_COUNT ||
        !(before.valid_registers & (UINT64_C(1) << reg)))
      return;
    // Only a pure AST comparison of a live local register is evaluated here.
    // A captured global/memory value could have changed before the branch.
    const auto result = ct_source_compare_value(
        expression.comparison, type.scalar, before.registers[reg]);
    if (result)
      frame.row.condition_outcome = *result;
  }

  const ct_source_call_result_info *source_call(const Frame &frame,
                                                const std::string &name) const {
    if (!frame.row.line || name.empty())
      return nullptr;
    const ct_source_call_result_info *selected = nullptr;
    for (const auto &call :
         source->lines[frame.row.line].presentation->call_results)
      if (call.function == frame.row.owner && name == call.result.callee) {
        if (selected)
          return nullptr;
        selected = &call;
      }
    return selected;
  }

  void source_arguments(Frame &frame,
                        const ct_kernel_observation &event) const {
    auto &row = frame.row;
    const auto *call = source_call(frame, sites[event.site_id].call_name);
    if (!call ||
        (call->argument_variables.empty() && call->argument_calls.empty()) ||
        !source || !values)
      return;
    const auto &presentation = *source->lines[row.line].presentation;
    const ct_source_call_info *contract = nullptr;
    for (const auto &candidate : presentation.calls) {
      if (candidate.function != row.owner ||
          candidate.callee != call->result.callee)
        continue;
      if (contract)
        return;
      contract = &candidate;
    }
    static constexpr unsigned registers[] = {KCTRACE_REG_RDI, KCTRACE_REG_RSI,
                                             KCTRACE_REG_RDX, KCTRACE_REG_RCX,
                                             KCTRACE_REG_R8,  KCTRACE_REG_R9};
    if (!contract ||
        (contract->parameters.size() != call->argument_variables.size() &&
         contract->parameters.size() != call->argument_calls.size()) ||
        contract->parameters.size() > std::size(registers))
      return;
    // Hidden aggregate return pointers and non-integer argument classes alter
    // this ABI layout. Use only the fixed scalar declaration verified by Clang.
    const auto &returned = call->result.return_type;
    if ((returned.kind == CT_VALUE_UNKNOWN &&
         contract->declaration.rfind("void ", 0) != 0) ||
        returned.kind == CT_VALUE_FLOAT || returned.bytes > sizeof(uint64_t))
      return;
    for (const auto &parameter : contract->parameters)
      if (!parameter.type.bytes || parameter.type.bytes > sizeof(uint64_t) ||
          (parameter.type.kind != CT_VALUE_POINTER &&
           parameter.type.kind != CT_VALUE_BOOLEAN &&
           parameter.type.kind != CT_VALUE_SIGNED &&
           parameter.type.kind != CT_VALUE_UNSIGNED))
        return;
    for (size_t index = 0; index < contract->parameters.size(); ++index) {
      if (!(event.valid_registers & (UINT64_C(1) << registers[index])))
        continue;
      const auto &argument = contract->parameters[index].type;
      if (index < call->argument_calls.size() &&
          !call->argument_calls[index].empty()) {
        const auto &callee = call->argument_calls[index];
        SourceRow::CallResult *selected = nullptr;
        for (auto &result : row.results) {
          if (result.call->result.callee != callee)
            continue;
          if (selected) {
            selected = nullptr;
            break;
          }
          selected = &result;
        }
        if (selected && selected->value == "?") {
          const auto &type = selected->call->result.return_type;
          const bool pointer = type.kind == CT_VALUE_POINTER;
          const bool integer = type.kind == CT_VALUE_SIGNED ||
                               type.kind == CT_VALUE_UNSIGNED ||
                               type.kind == CT_VALUE_BOOLEAN;
          if (type.bytes && type.bytes <= argument.bytes &&
              ((pointer && argument.kind == CT_VALUE_POINTER) ||
               (integer && argument.kind != CT_VALUE_POINTER &&
                (argument.kind != CT_VALUE_BOOLEAN ||
                 type.kind == CT_VALUE_BOOLEAN)))) {
            auto &returned = selected->returned;
            returned.type = type;
            returned.scalar = event.registers[registers[index]];
            returned.known = true;
            returned.text = scalar_value(
                type, reinterpret_cast<const unsigned char *>(&returned.scalar),
                type.bytes);
            selected->value = returned.text;
          }
        }
      }
      if (index >= call->argument_variables.size() ||
          call->argument_variables[index].empty())
        continue;
      const auto &name = call->argument_variables[index];
      const auto variable = named_variable(name, row.owner, event.site_id);
      if (!variable || variable->global || !variable->type ||
          variable->type >= values->types.size())
        continue;
      const auto &type = values->types[variable->type];
      if (type.guarded || type.scalar.kind != argument.kind ||
          type.scalar.bytes != argument.bytes)
        continue;
      for (auto &input : row.inputs)
        if (input.variable == variable->id && input.name == variable->name &&
            !input.address && input.before == "?")
          input.before = scalar_value(type.scalar,
                                      reinterpret_cast<const unsigned char *>(
                                          &event.registers[registers[index]]),
                                      type.scalar.bytes);
    }
  }

  static std::string returned_scalar(const ct_value_type &type,
                                     const ct_kernel_observation &event) {
    if (!type.bytes || type.bytes > sizeof(uint64_t) ||
        type.kind == CT_VALUE_FLOAT || type.kind == CT_VALUE_UNKNOWN ||
        !(event.valid_registers & (UINT64_C(1) << KCTRACE_REG_RAX)))
      return "?";
    return scalar_value(type,
                        reinterpret_cast<const unsigned char *>(
                            &event.registers[KCTRACE_REG_RAX]),
                        type.bytes);
  }

  void release_fallback(std::vector<ct_kernel_trace_record> &fallback,
                        std::vector<ct_kernel_trace_record> *records = nullptr,
                        Frame *frame = nullptr) {
    if (records)
      for (auto &record : fallback)
        emit(std::move(record), *records, frame);
    fallback.clear();
  }

  void source_assembly(Frame &frame, const ct_kernel_observation &before,
                       const ct_kernel_observation *after,
                       std::vector<ct_kernel_trace_record> &records) {
    auto &row = frame.row;
    const auto &site = sites[before.site_id];
    if (!row.line || !row.call_bearing ||
        row.buffered_sequence >= before.sequence ||
        row.line != site.source_line || row.owner != site.source_owner)
      return;
    const bool store = row.call_seen && !row.assembly;
    if (store) {
      const auto &expression = source->lines[row.line].presentation->expression;
      if (!site.memory_write || site.call || site.ret || site.branch ||
          site.writes_stack || expression.function != row.owner ||
          expression.assignment.empty())
        return;
    }
    row.buffered_sequence = before.sequence;
    auto record = render(before, after, &frame);
    if (row.assembly) {
      emit(std::move(record), records, &frame);
    } else {
      (store ? row.stores : row.fallback).push_back(std::move(record));
    }
  }

  static InlineResult convert_result(InlineResult result,
                                     const ct_value_type &expected) {
    const auto integer = [](ct_value_kind kind) {
      return kind == CT_VALUE_SIGNED || kind == CT_VALUE_UNSIGNED ||
             kind == CT_VALUE_BOOLEAN;
    };
    const auto mask = [](unsigned bytes) {
      return bytes == 8 ? UINT64_MAX : (UINT64_C(1) << (bytes * 8)) - 1;
    };
    if (!result.type.bytes || result.type.bytes > 8 || !expected.bytes ||
        expected.bytes > 8 ||
        (!(integer(result.type.kind) && integer(expected.kind)) &&
         !(result.type.kind == CT_VALUE_POINTER &&
           expected.kind == CT_VALUE_POINTER)))
      result.known = false;
    if (result.known) {
      result.scalar &= mask(result.type.bytes);
      if (result.type.kind == CT_VALUE_SIGNED &&
          (result.scalar & (UINT64_C(1) << (result.type.bytes * 8 - 1))))
        result.scalar |= ~mask(result.type.bytes);
      result.scalar = expected.kind == CT_VALUE_BOOLEAN
                          ? result.scalar != 0
                          : result.scalar & mask(expected.bytes);
      result.type = expected;
      result.text = scalar_value(
          expected, reinterpret_cast<const unsigned char *>(&result.scalar),
          expected.bytes);
    } else
      result.text = "?";
    return result;
  }

  void source_returned(Frame &frame, const ct_source_call_result_info &call,
                       const ct_kernel_observation &event, bool reported,
                       bool unknown_call = false,
                       const InlineResult *inline_result = nullptr) {
    auto &row = frame.row;
    if (!row.line)
      return;
    row.after = event;
    row.call_seen = true;
    release_fallback(row.fallback);
    const auto &expression = source->lines[row.line].presentation->expression;
    const bool root_call = expression.function == row.owner &&
                           expression.is_call &&
                           expression.callee == call.result.callee;
    row.call_completed |= root_call;
    // Compound updates such as a += f() are not AST root CALL expressions.
    // The sole observed call dependency can still be retained until a proven
    // destination write. Nested/multiple-call expressions require the root
    // call's return so an inner argument cannot finish their invocation.
    if (expression.function == row.owner && !expression.assignment.empty()) {
      const auto &calls = source->lines[row.line].presentation->call_results;
      row.assignment_returned |=
          root_call ||
          std::count_if(calls.begin(), calls.end(), [&](const auto &candidate) {
            return candidate.function == row.owner;
          }) == 1;
    }
    bool void_call = false;
    for (const auto &contract : source->lines[row.line].presentation->calls) {
      if (contract.function != row.owner ||
          contract.callee != call.result.callee)
        continue;
      const std::string name = call.result.display_name;
      const auto position = contract.declaration.find(name + "(");
      void_call |= !name.empty() && position != std::string::npos &&
                   contract.declaration.substr(0, position) == "void ";
    }
    row.call_reported |= root_call && (reported || (row.printed && void_call));
    const bool assigned_call = root_call && !expression.assignment.empty();
    if (!void_call) {
      const auto &expected = call.result.return_type;
      InlineResult observed;
      if (inline_result && inline_result->known)
        observed = *inline_result;
      else if (!unknown_call &&
               (event.valid_registers & (UINT64_C(1) << KCTRACE_REG_RAX))) {
        observed.scalar = event.registers[KCTRACE_REG_RAX];
        observed.type = expected;
        observed.known = true;
      }
      observed = convert_result(std::move(observed), expected);
      const bool display =
          !reported &&
          (!assigned_call || (inline_result && inline_result->known));
      row.results.push_back(
          {&call, observed.text, std::move(observed), display});
    }
    if (assigned_call) {
      const auto value = std::find_if(
          row.inputs.begin(), row.inputs.end(),
          [&](const auto &item) { return item.name == expression.assignment; });
      if (value != row.inputs.end() && !value->access &&
          location_register(binding(value->variable, event.site_id)) ==
              KCTRACE_REG_RAX)
        row.assigned = value->variable;
    }
  }

  bool returns_void(const Frame &frame) const {
    if (!values || frame.entry.site_id >= values->sites.size())
      return false;
    const auto function = values->sites[frame.entry.site_id].function;
    return function && values->functions[function].returns_void;
  }

  InlineResult constant_return(const Frame &frame) const {
    const auto &row = frame.row;
    if (!source || !values || !row.line || row.assembly ||
        row.line >= source->lines.size() ||
        row.owner != frame.source_function ||
        inline_owner(row.before.site_id, row.owner) ||
        !source->lines[row.line].presentation)
      return {};
    const auto &expression = source->lines[row.line].presentation->expression;
    if (expression.kind != CT_EXPRESSION_RETURN ||
        expression.function != row.owner || !expression.constant ||
        !expression.constant_type.bytes || expression.constant_type.bytes > 8)
      return {};
    ct_value_type type{};
    if (frame.entry.site_id < values->sites.size()) {
      const auto function = values->sites[frame.entry.site_id].function;
      if (function && values->functions[function].return_type) {
        const auto &returned =
            values->types[values->functions[function].return_type];
        if (returned.guarded)
          return {};
        type = returned.scalar;
      }
    }
    if (!type.bytes && frame.call_source)
      type = frame.call_source->result.return_type;
    return convert_result(
        {{}, expression.constant_type, expression.constant_value, true}, type);
  }

  std::string return_value(const Frame &frame,
                           const ct_kernel_observation &event) const {
    // Private compiler calling conventions can materialize a constant result
    // in the caller, leaving an unrelated RAX at the physical return.
    if (const auto observed = constant_return(frame); observed.known)
      return observed.text;
    ct_value_type type{};
    if (values && frame.entry.site_id < values->sites.size()) {
      const auto function = values->sites[frame.entry.site_id].function;
      if (function && values->functions[function].return_type) {
        const auto &result =
            values->types[values->functions[function].return_type];
        if (result.guarded || result.scalar.kind == CT_VALUE_UNKNOWN)
          return "?";
        type = result.scalar;
        if (type.kind == CT_VALUE_FLOAT) {
          const auto reg = values->functions[function].return_register;
          if (event.site_id >= values->sites.size() ||
              !((reg == 17 && (type.bytes == 4 || type.bytes == 8)) ||
                (reg == 33 && type.bytes == 10)))
            return "?";
          for (const auto &binding : values->sites[event.site_id].bindings) {
            const auto &variable = values->variables[binding.variable];
            if (variable.type != values->functions[function].return_type ||
                !binding.recipe ||
                ct_kernel_recipe_register(values->recipes[binding.recipe],
                                          type.bytes) != reg)
              continue;
            return ct_kernel_format_value(*values, binding, event);
          }
          return "?";
        }
      }
    }
    if (!type.bytes && frame.call_source)
      type = frame.call_source->result.return_type;
    return returned_scalar(type, event);
  }

  std::string typed_source_call(const SourceRow &row,
                                const ct_source_call_result_info &call) {
    if (introduced_functions.count(call.result.callee))
      return {};
    const std::string display = call.result.display_name;
    const std::string expression = call.result.text;
    if (display.empty() || expression.rfind(display + "(", 0) != 0)
      return {};
    for (const auto &contract : source->lines[row.line].presentation->calls) {
      if (contract.function != row.owner ||
          contract.callee != call.result.callee)
        continue;
      const auto name = contract.declaration.find(display + "(");
      if (name == std::string::npos || !name)
        continue;
      std::string result = contract.declaration.substr(0, name);
      const auto last = result.find_last_not_of(" \t");
      if (last == std::string::npos || result.find("::") != std::string::npos)
        continue;
      result.resize(last + 1);
      const auto parameters =
          contract.declaration.substr(name + display.size());
      if (parameters.empty() || parameters.back() != ')')
        continue;
      introduced_functions.insert(call.result.callee);
      return "((" + result + " (*)" + parameters + ")" + display + ")" +
             expression.substr(display.size());
    }
    return {};
  }

  static std::vector<size_t> call_positions(const std::string &text,
                                            const std::string &call) {
    std::vector<size_t> positions;
    if (call.empty())
      return positions;
    char quote = 0;
    bool comment = false;
    for (size_t index = 0; index < text.size(); ++index) {
      if (quote) {
        if (text[index] == '\\')
          ++index;
        else if (text[index] == quote)
          quote = 0;
      } else if (comment) {
        if (text.compare(index, 2, "*/") == 0) {
          comment = false;
          ++index;
        }
      } else if (text.compare(index, 2, "//") == 0) {
        break;
      } else if (text.compare(index, 2, "/*") == 0) {
        comment = true;
        ++index;
      } else if (text[index] == '\'' || text[index] == '"') {
        quote = text[index];
      } else if (text.compare(index, call.size(), call) == 0 &&
                 (!index ||
                  (!std::isalnum(static_cast<unsigned char>(text[index - 1])) &&
                   text[index - 1] != '_'))) {
        positions.push_back(index);
      }
    }
    return positions;
  }

  static void
  highlight_calls(ct_kernel_trace_record &record, const SourceRow &row,
                  const ct_kernel_source_presentation &presentation) {
    for (const auto *call : row.entered_calls) {
      const std::string spelling = call->result.text;
      const auto positions = call_positions(record.text, spelling);
      size_t begin = std::string::npos;
      if (positions.size() == 1) {
        begin = positions.front();
      } else if (!positions.empty() && call->result.begin_column &&
                 call->result.end_column >= call->result.begin_column &&
                 call->result.end_column - call->result.begin_column ==
                     spelling.size()) {
        // A unique peer on the same source row anchors stripped indentation.
        // Reject multiline/ambiguous spellings instead of coloring an
        // identical invocation that was not actually entered.
        size_t indentation = std::string::npos;
        bool conflict = false;
        for (const auto &peer : presentation.call_results) {
          const std::string text = peer.result.text;
          if (peer.function != row.owner || !peer.result.begin_column ||
              peer.result.end_column < peer.result.begin_column ||
              peer.result.end_column - peer.result.begin_column != text.size())
            continue;
          const auto anchors = call_positions(record.text, text);
          if (anchors.size() != 1 ||
              anchors.front() >= peer.result.begin_column)
            continue;
          const size_t offset = peer.result.begin_column - 1 - anchors.front();
          conflict |= indentation != std::string::npos && indentation != offset;
          indentation = offset;
        }
        if (!conflict && indentation != std::string::npos &&
            indentation < call->result.begin_column) {
          const size_t candidate = call->result.begin_column - 1 - indentation;
          if (std::find(positions.begin(), positions.end(), candidate) !=
              positions.end())
            begin = candidate;
        }
      }
      if (begin != std::string::npos)
        record.code_highlights.push_back(
            {uint32_t(begin), uint32_t(begin + spelling.size())});
    }
    std::sort(record.code_highlights.begin(), record.code_highlights.end(),
              [](const auto &left, const auto &right) {
                return std::tie(left.begin, left.end) <
                       std::tie(right.begin, right.end);
              });
    size_t count = 0;
    for (const auto span : record.code_highlights) {
      if (count && span.begin <= record.code_highlights[count - 1].end)
        record.code_highlights[count - 1].end =
            std::max(record.code_highlights[count - 1].end, span.end);
      else
        record.code_highlights[count++] = span;
    }
    record.code_highlights.resize(count);
  }

  void flush_source(Frame &frame, std::vector<ct_kernel_trace_record> &records,
                    bool continuing = false,
                    const ct_kernel_observation *returned = nullptr) {
    auto &row = frame.row;
    if (!row.line)
      return;
    if (row.assembly || (row.call_bearing && !row.call_seen)) {
      release_fallback(row.fallback, &records, &frame);
      release_fallback(row.stores, &records, &frame);
      if (continuing)
        row.assembly = true;
      else
        row = {};
      return;
    }
    const auto &line = source->lines[row.line];
    const auto &presentation = *line.presentation;
    if (!continuing && !row.forward_checked && row.call_seen &&
        row.owner == frame.source_function) {
      SourceRow::CallResult *forwarded = nullptr;
      for (auto &result : row.results) {
        if (!result.returned.known && result.call->return_forwarded &&
            result.call->function == frame.source_function) {
          if (forwarded) {
            forwarded = nullptr;
            break;
          }
          forwarded = &result;
        }
      }
      if (forwarded && !returned && !frame.deferred_return) {
        // The AST proves that this invocation is forwarded without an
        // intervening operation or lossy conversion. Wait for this physical
        // frame's authenticated return, never an arbitrary inline-exit RAX.
        frame.deferred_return = std::make_unique<SourceRow>(std::move(row));
        row = {};
        return;
      }
      if (forwarded && returned) {
        forwarded->value =
            returned_scalar(forwarded->call->result.return_type, *returned);
        forwarded->display = true;
      }
    }
    if (!frame.inline_rows.empty() &&
        source->blocks[frame.inline_rows.back().block].header == row.owner) {
      const auto result = inline_result(frame, row);
      if (presentation.expression.kind == CT_EXPRESSION_RETURN)
        frame.inline_rows.back().returned = result;
    }
    const bool returning =
        presentation.expression.kind == CT_EXPRESSION_RETURN &&
        presentation.expression.function == row.owner &&
        row.owner == frame.source_function;
    const bool call_only = presentation.expression.kind == CT_EXPRESSION_CALL &&
                           presentation.expression.function == row.owner;
    if (!(row.printed && call_only && row.call_reported && !continuing)) {
      auto record = base_record(row.before);
      record.source = true;
      record.function = row.owner;
      record.inlined = inline_owner(row.before.site_id, row.owner);
      record.inline_prefix_seen = row.inline_prefix_seen;
      record.file = source->files[line.file].path;
      record.line = line.line;
      record.text = line.text;
      record.code_highlights = presentation.highlights;
      highlight_calls(record, row, presentation);
      record.call_entry = continuing;
      if (row.condition_outcome >= 0) {
        record.condition_outcome = row.condition_outcome;
        for (const auto &highlight : presentation.highlights) {
          if (highlight.end == highlight.begin + 1 &&
              highlight.end <= record.text.size() &&
              record.text[highlight.begin] == '{') {
            if (record.condition_brace != std::string::npos) {
              record.condition_brace = std::string::npos;
              break;
            }
            record.condition_brace = highlight.begin;
          }
        }
        record.text += ' ';
        record.comment_offset = record.text.size();
        record.text +=
            row.condition_outcome ? "# /* taken */" : "# /* not taken */";
      }
      for (const auto &value : row.inputs) {
        std::string observed = value.before;
        // An exact `return variable;` consumes that scalar value. At the
        // authenticated return boundary its ABI result remains evidence even
        // if an optimized epilogue has ended the variable's DWARF location.
        // Do not apply this to conversions, expressions or unknown types.
        if (returning && returned && observed == "?" && values &&
            !value.access && value.variable &&
            value.variable < values->variables.size() &&
            llvm::StringRef(presentation.expression.text).trim() ==
                value.name &&
            frame.entry.site_id < values->sites.size()) {
          const auto type = values->variables[value.variable].type;
          const auto function = values->sites[frame.entry.site_id].function;
          const auto result = function && function < values->functions.size()
                                  ? values->functions[function].return_type
                                  : 0;
          if (type && result && type < values->types.size() &&
              result < values->types.size() && !values->types[type].guarded &&
              !values->types[result].guarded &&
              values->types[type].scalar.kind ==
                  values->types[result].scalar.kind &&
              values->types[type].scalar.bytes ==
                  values->types[result].scalar.bytes)
            observed = returned_scalar(values->types[type].scalar, *returned);
        }
        source_field(record, frame, value, observed, true);
      }
      bool result = false;
      if (returning && returned && !returns_void(frame)) {
        const std::string invocation =
            frame.call_source ? frame.call_source->result.text
                              : (frame.source_function.empty()
                                     ? functions[frame.function].name
                                     : frame.source_function) +
                                    "(...)";
        source_result(record, invocation, return_value(frame, *returned), true);
        result = true;
      } else {
        for (const auto &call : row.results) {
          if (!call.display)
            continue;
          const auto typed = typed_source_call(row, *call.call);
          source_result(record, typed.empty() ? call.call->result.text : typed,
                        call.value, !result, !typed.empty());
          result = true;
        }
        if (row.after.site_id && !row.assigned_value.empty()) {
          source_result(record, row.assigned_name, row.assigned_value, !result);
          result = true;
        } else if (row.after.site_id && row.assigned) {
          const auto value = std::find_if(
              row.inputs.begin(), row.inputs.end(), [&](const auto &item) {
                return item.variable == row.assigned &&
                       item.name == values->variables[row.assigned].name;
              });
          if (value != row.inputs.end()) {
            if (!result) {
              if (record.comment_offset == std::string::npos) {
                record.text += ' ';
                record.comment_offset = record.text.size();
                record.text += '#';
              }
              record.text += " ->";
            }
            source_field(record, frame, *value,
                         source_value(*value, row.after, frame), false);
            result = true;
          }
        }
      }
      if (continuing) {
        if (record.comment_offset == std::string::npos) {
          record.text += ' ';
          record.comment_offset = record.text.size();
          record.text += '#';
        }
        record.text += result ? " ..." : " -> ...";
      }
      if ((returning && returned) || row.assigned ||
          (call_only && row.call_completed)) {
        record.stage = ct_kernel_trace_stage::completed;
        record.end_monotonic_ns =
            returned ? returned->monotonic_ns : row.after.monotonic_ns;
      }
      records.push_back(std::move(record));
    }
    if (continuing) {
      row.printed = true;
      row.results.clear();
    } else {
      // A known invocation does not prove an unresolved destination write.
      // Keep its actual store observation when no typed assignment accounts
      // for the bytes, including compiler-split array objects.
      release_fallback(row.stores,
                       row.assigned || !row.assigned_value.empty() ? nullptr
                                                                   : &records,
                       &frame);
      release_fallback(row.fallback);
      row = {};
    }
  }

  void source_entry(Frame &frame,
                    std::vector<ct_kernel_trace_record> &records) {
    if (!terminal || !source || !frame.within || frame.mode != into ||
        frame.source_entry || frame.entry.site_id >= source->sites.size())
      return;
    const auto index = source->sites[frame.entry.site_id].function;
    if (!index || source->functions[index].signature.empty())
      return;
    const auto &definition = source->functions[index];
    auto record = base_record(frame.entry);
    record.source = record.entry = true;
    record.inlined = false;
    record.function = definition.name;
    record.file = source->files[definition.file].path;
    record.line = definition.line;
    record.text = definition.signature;
    const auto parameters = source_values(
        definition.parameters, definition.name, frame.entry, frame, true);
    frame.entry_invocation = definition.name + '(';
    for (const auto &value : parameters) {
      if (&value != &parameters.front())
        frame.entry_invocation += ", ";
      frame.entry_invocation += value.before;
      source_field(record, frame, value, value.before, true);
    }
    bool unknown_arguments =
        definition.parameters.size() != parameters.size() ||
        definition.signature.find("...") != std::string::npos;
    if (parameters.empty()) {
      const auto name = definition.signature.find(definition.name);
      const auto opening =
          name == std::string::npos
              ? name
              : definition.signature.find('(', name + definition.name.size());
      const auto closing = opening == std::string::npos
                               ? opening
                               : definition.signature.find(')', opening + 1);
      const auto declaration = closing == std::string::npos
                                   ? llvm::StringRef("?")
                                   : llvm::StringRef(definition.signature)
                                         .slice(opening + 1, closing)
                                         .trim();
      unknown_arguments |= !declaration.empty() && declaration != "void";
    }
    if (unknown_arguments)
      frame.entry_invocation += parameters.empty() ? "..." : ", ...";
    frame.entry_invocation += ')';
    records.push_back(std::move(record));
    frame.source_entry = true;
    introduced_functions.insert(definition.name);
    introduced_functions.insert(functions[frame.function].name);
    if (frame.call_source)
      introduced_functions.insert(frame.call_source->result.callee);
  }

  void flush_deferred(Frame &frame,
                      std::vector<ct_kernel_trace_record> &records) {
    if (!frame.deferred_assignment)
      return;
    std::swap(frame.row, *frame.deferred_assignment);
    flush_source(frame, records);
    frame.row = std::move(*frame.deferred_assignment);
    frame.deferred_assignment.reset();
  }

  void flush_forwarded(Frame &frame,
                       std::vector<ct_kernel_trace_record> &records,
                       const ct_kernel_observation *returned = nullptr) {
    if (!frame.deferred_return)
      return;
    std::swap(frame.row, *frame.deferred_return);
    // A scope/observation gap discards the proof rather than parking again.
    frame.row.forward_checked = !returned;
    flush_source(frame, records, false, returned);
    frame.row = std::move(*frame.deferred_return);
    frame.deferred_return.reset();
  }

  void flush_inline_rows(Frame &frame,
                         std::vector<ct_kernel_trace_record> &records) {
    // Frame loss or an unobserved boundary does not prove that the inlined
    // invocation returned. Preserve its observed source without a result.
    while (!frame.inline_rows.empty()) {
      flush_deferred(frame, records);
      flush_source(frame, records);
      frame.row = std::move(frame.inline_rows.back().caller);
      frame.inline_rows.pop_back();
    }
  }

  bool source_observation(Frame &frame, const ct_kernel_observation &event,
                          std::vector<ct_kernel_trace_record> &records,
                          bool repeated, bool sequential) {
    const auto &site = sites[event.site_id];
    source_entry(frame, records);
    if (repeated && !frame.inline_rows.empty())
      frame.inline_rows.back().returned = {};
    if (site.compiler_support)
      return true;
    // A returned call can have its destination store scheduled after another
    // source row. Retain that exact invocation only across a proven straight
    // line in the same owner; a branch, another call, loss, or scope change
    // cannot lend old CALL evidence to a later execution of the same line.
    if (frame.deferred_assignment) {
      if (!sequential || site.call || site.branch || site.ret ||
          site.source_owner != frame.deferred_assignment->owner) {
        flush_deferred(frame, records);
      } else if (site.source_line == frame.deferred_assignment->line) {
        flush_source(frame, records);
        frame.row = std::move(*frame.deferred_assignment);
        frame.deferred_assignment.reset();
      }
    }
    if (frame.row.line && frame.row.assignment_returned &&
        !frame.row.assigned &&
        !source->lines[frame.row.line]
             .presentation->expression.assignment.empty()) {
      // The first caller observation after a proven return is not sequential
      // with the callee's RET. Every later observation must be sequential even
      // when a branch retains the same source line and no row was parked yet.
      const bool returned_here = frame.row.after.site_id == event.site_id &&
                                 frame.row.after.sequence == event.sequence;
      if ((!sequential && !returned_here) || site.call || site.branch ||
          site.ret || frame.row.owner != site.source_owner)
        flush_source(frame, records);
    }
    // The offline CFG proof already assigned this compiler callee-save PUSH
    // to its adjacent scope. Do not split the same pending C operation at its
    // declaration-line DWARF hole; real caller statements still flush below.
    if (frame.source_entry && site.source_opening && site.stack_save &&
        site.scope_site && site.scope_site != site.original.id &&
        (!frame.row.line ||
         (sites[site.scope_site].source_line == frame.row.line &&
          sites[site.scope_site].source_owner == frame.row.owner)))
      return true;
    if (frame.row.line) {
      const auto &expression =
          source->lines[frame.row.line].presentation->expression;
      if (expression.kind == CT_EXPRESSION_RETURN &&
          expression.function == frame.row.owner &&
          frame.row.owner == frame.source_function &&
          (site.ret || site.source_line == frame.row.line ||
           (site.source_line && source->lines[site.source_line].text == "}")))
        return true;
      if (repeated || frame.row.line != site.source_line ||
          frame.row.owner != site.source_owner) {
        if (!repeated && !site.call && !site.branch && !site.ret &&
            frame.row.owner == site.source_owner &&
            frame.row.assignment_returned && !frame.row.assigned &&
            !expression.assignment.empty() &&
            expression.function == frame.row.owner) {
          flush_deferred(frame, records);
          frame.deferred_assignment =
              std::make_unique<SourceRow>(std::move(frame.row));
          frame.row = {};
        } else {
          flush_source(frame, records);
        }
      }
    }
    if (site.source_opening && frame.source_entry)
      return true;
    if (!site.source_line)
      return false;
    if (!frame.row.line) {
      if (!frame.inline_rows.empty() &&
          source->blocks[frame.inline_rows.back().block].header ==
              site.source_owner &&
          !source->lines[site.source_line].presentation->structural)
        frame.inline_rows.back().returned = {};
      frame.row.line = site.source_line;
      frame.row.owner = site.source_owner;
      frame.row.inline_prefix_seen =
          inline_prefix(frame, event.site_id, site.source_owner);
      frame.row.before = event;
      const auto &presentation = *source->lines[site.source_line].presentation;
      frame.row.call_bearing =
          (presentation.expression.function == site.source_owner &&
           presentation.expression.is_call) ||
          std::any_of(presentation.call_results.begin(),
                      presentation.call_results.end(), [&](const auto &call) {
                        return call.function == site.source_owner;
                      });
      frame.row.inputs =
          source_values(source->lines[site.source_line].presentation->variables,
                        site.source_owner, event, frame);
    }
    return true;
  }

  void transition(const Frame &frame, const Frame::Scope &scope,
                  ct_kernel_trace_phase phase, uint64_t timestamp,
                  const char *status,
                  std::vector<ct_kernel_trace_transition> *output) const {
    if (!output || !scope.token)
      return;
    ct_kernel_trace_transition event;
    event.token = scope.token;
    event.parent = scope.parent;
    event.phase = phase;
    event.monotonic_ns = std::max(timestamp, scope.begin);
    event.task_start_ns = frame.entry.task_start_ns;
    event.pc = scope.pc;
    event.tid = frame.entry.tid;
    event.tgid = frame.entry.tgid;
    event.cpu = frame.entry.cpu;
    event.context = frame.entry.context;
    event.hardirq_depth = frame.entry.hardirq_depth;
    event.softirq_depth = frame.entry.softirq_depth;
    event.has_execution = frame.execution_id != 0;
    event.status = status;
    const auto &site = sites[frame.entry.site_id];
    event.name = frame.source_function.empty() ? functions[frame.function].name
                                               : frame.source_function;
    event.file = files[site.file];
    event.line = site.line;
    event.origin = "assembly";
    if (decompile && frame.entry.site_id < decompile->sites.size() &&
        decompile->sites[frame.entry.site_id].function)
      event.origin = "decompile";
    if (scope.block) {
      if (scope.decompiled) {
        event.kind = ct_kernel_trace_kind::block;
        event.name = decompile_text(decompile->blocks[scope.block].header);
        event.origin = "decompile";
        output->push_back(std::move(event));
        return;
      }
      const auto &block = source->blocks[scope.block];
      event.kind = block.kind == ct_kernel_source_block_kind::inline_function
                       ? ct_kernel_trace_kind::function
                       : ct_kernel_trace_kind::block;
      event.name = !block.display.empty() ? block.display
                   : block.header.empty() ? "{"
                                          : block.header;
      event.file = source->files[block.file].path;
      event.line =
          block.display.empty() ? block.start_line : block.display_line;
      event.origin = block.source_available ? "source" : "dwarf";
    } else if (source && frame.entry.site_id < source->sites.size()) {
      const auto function = source->sites[frame.entry.site_id].function;
      if (function && function < source->functions.size()) {
        const auto &definition = source->functions[function];
        event.file = source->files[definition.file].path;
        event.line = definition.line;
        if (source->files[definition.file].available)
          event.origin = "source";
        else if (event.origin != "decompile")
          event.origin = "dwarf";
      }
    }
    output->push_back(std::move(event));
  }

  static void append_invocation(ct_kernel_trace_record &record,
                                const Frame &frame) {
    if (frame.entry_invocation.empty())
      return;
    record.closing_context = frame.entry_invocation;
    if (record.comment_offset == std::string::npos) {
      record.text += ' ';
      record.comment_offset = record.text.size();
      record.text += '#';
    } else {
      record.text += ';';
    }
    record.text += " /* " + frame.entry_invocation + " */";
  }

  void close_frame(Task &task, uint64_t timestamp, const char *status,
                   const ct_kernel_observation *returned,
                   std::vector<ct_kernel_trace_record> &records,
                   std::vector<ct_kernel_trace_transition> *output,
                   bool complete_caller = true) {
    auto &frame = task.frames.back();
    const auto *call_source = frame.call_source;
    const bool source_return_reported =
        returned && frame.row.line && !frame.row.assembly &&
        (!frame.row.call_bearing || frame.row.call_seen) &&
        frame.row.owner == frame.source_function &&
        source->lines[frame.row.line].presentation->expression.kind ==
            CT_EXPRESSION_RETURN;
    const bool decompile_return_reported =
        returned && frame.decompiled.statement &&
        frame.decompiled.last.site_id &&
        sites[frame.decompiled.last.site_id].ret;
    const bool return_reported =
        source_return_reported || decompile_return_reported;
    const auto known_return =
        returned ? constant_return(frame) : InlineResult{};
    if (frame.source_entry && frame.row.line &&
        source->lines[frame.row.line].text == "}")
      frame.row = {};
    flush_inline_rows(frame, records);
    flush_deferred(frame, records);
    flush_forwarded(frame, records, returned);
    flush_source(frame, records, false, returned);
    flush_forwarded(frame, records, returned);
    const auto return_boundary =
        frame.decompiled.last.site_id ? frame.decompiled.last : frame.entry;
    flush_decompile(frame, records,
                    returned && frame.decompiled.last.site_id &&
                            sites[frame.decompiled.last.site_id].ret
                        ? returned
                        : nullptr);
    if (returned && frame.decompile_entry && !frame.source_entry) {
      auto record = base_record(return_boundary);
      record.source = true;
      record.inlined = false;
      record.text = "}";
      record.stage = ct_kernel_trace_stage::completed;
      record.end_monotonic_ns = returned->monotonic_ns;
      if (!return_reported && !returns_void(frame))
        source_result(record,
                      frame.call_source ? frame.call_source->result.text
                      : frame.call_decompile.empty()
                          ? (frame.source_function.empty()
                                 ? functions[frame.function].name
                                 : frame.source_function) +
                                "(...)"
                          : frame.call_decompile,
                      return_value(frame, *returned), true);
      append_invocation(record, frame);
      records.push_back(std::move(record));
    }
    if (returned && frame.source_entry) {
      const ct_kernel_observation *boundary = &frame.entry;
      if (task.pending.site_id &&
          sites[task.pending.site_id].function == frame.function)
        boundary = &task.pending;
      else if (returned->site_id && returned->site_id < sites.size() &&
               sites[returned->site_id].function == frame.function)
        boundary = returned;
      auto record = base_record(*boundary);
      record.source = true;
      record.inlined = false;
      record.function = frame.source_function;
      record.text = "}";
      record.code_highlights.push_back({0, 1});
      record.stage = ct_kernel_trace_stage::completed;
      record.end_monotonic_ns = returned->monotonic_ns;
      if (!return_reported && !returns_void(frame)) {
        const std::string invocation = call_source
                                           ? call_source->result.text
                                           : frame.source_function + "(...)";
        source_result(record, invocation, return_value(frame, *returned), true);
      }
      append_invocation(record, frame);
      records.push_back(std::move(record));
    }
    const bool source_exit =
        returned && (frame.source_entry || frame.decompile_entry);
    const bool decompile_call_reported =
        !frame.call_decompile.empty() && (return_reported || source_exit);
    const uint64_t incoming_call = frame.incoming_call;
    const bool skipped_call = frame.mode == skip;
    for (auto block = frame.blocks.rbegin(); block != frame.blocks.rend();
         ++block)
      transition(frame, *block, ct_kernel_trace_phase::end, timestamp, status,
                 output);
    transition(frame, frame.scope, ct_kernel_trace_phase::end, timestamp,
               status, output);
    if (terminal && frame.within && frame.mode == over && !frame.call_source &&
        frame.call_decompile.empty())
      emit(summarize(frame, returned), records);
    task.frames.pop_back();
    if (!complete_caller) {
      if (returned && incoming_call && !task.frames.empty() &&
          task.frames.back().call_cookie == incoming_call) {
        task.frames.back().call_reported |= return_reported || source_exit;
        task.frames.back().call_return = known_return;
      }
      return;
    }
    if (returned && call_source && !task.frames.empty())
      source_returned(task.frames.back(), *call_source, *returned,
                      return_reported || source_exit, skipped_call,
                      known_return.known ? &known_return : nullptr);
    if (returned && decompile && !task.frames.empty()) {
      auto &caller = task.frames.back();
      if (caller.decompiled.statement && caller.decompiled.last.site_id &&
          sites[caller.decompiled.last.site_id].call &&
          caller.decompiled.next ==
              decompile->statements[caller.decompiled.statement].sites.size()) {
        if (caller.decompiled.printed && decompile_call_reported &&
            decompile->statements[caller.decompiled.statement]
                .assignment.empty()) {
          caller.decompiled = {};
        } else {
          flush_decompile(caller, records, returned, false, skipped_call);
        }
      }
    }
  }

  void close_task(Task &task, uint64_t timestamp, const char *status,
                  std::vector<ct_kernel_trace_record> &records,
                  std::vector<ct_kernel_trace_transition> *output) {
    if (task.pending.site_id && task.selected)
      emit(render(task.pending, nullptr,
                  task.frames.empty() ? nullptr : &task.frames.back()),
           records, task.frames.empty() ? nullptr : &task.frames.back());
    else if (task.pending.site_id && !task.frames.empty())
      source_assembly(task.frames.back(), task.pending, nullptr, records);
    timestamp = std::max(timestamp, task.timestamp);
    if (task.pending.site_id && std::strcmp(status, "returned")) {
      const auto &site = sites[task.pending.site_id];
      if (site.ret ||
          (site.branch && !site.conditional && !site.branch_target)) {
        timestamp = task.pending.monotonic_ns;
        if (std::strcmp(status, "lost") &&
            std::strcmp(status, "out-of-order") &&
            std::strcmp(status, "load-aborted"))
          status =
              site.ret ? "unobserved-return" : "unobserved-control-transfer";
      }
    }
    auto returned = task.pending;
    const bool proven_return = !std::strcmp(status, "returned") &&
                               returned.site_id && sites[returned.site_id].ret;
    returned.monotonic_ns = timestamp;
    task.pending = {};
    task.selected = false;
    while (!task.frames.empty())
      close_frame(task, timestamp ? timestamp : task.timestamp, status,
                  proven_return && task.frames.back().function ==
                                       sites[returned.site_id].function
                      ? &returned
                      : nullptr,
                  records, output);
  }

  static const Selection &selection(const Frame &frame) {
    return frame.blocks.empty() ? static_cast<const Selection &>(frame)
                                : frame.blocks.back();
  }

  static uint64_t parent_token(const Frame &frame) {
    for (auto scope = frame.blocks.rbegin(); scope != frame.blocks.rend();
         ++scope)
      if (scope->token)
        return scope->token;
    return frame.scope.token;
  }

  const std::vector<uint64_t> *block_membership(uint64_t site_id,
                                                bool &generated) const {
    const auto scope_site = sites[site_id].scope_site;
    const auto function =
        source && scope_site ? source->sites[scope_site].function : 0;
    const bool original_source =
        function && source->files[source->functions[function].file].available;
    generated =
        !original_source && decompile && site_id < decompile->sites.size();
    if (!generated && (!source || !scope_site))
      return nullptr;
    return generated ? &decompile->sites[site_id].blocks
                     : &source->sites[scope_site].blocks;
  }

  InlineResult inline_result(const Frame &frame, const SourceRow &row) const {
    if (!source || !values || !row.line || row.line >= source->lines.size() ||
        !source->lines[row.line].presentation)
      return {};
    const auto &expression = source->lines[row.line].presentation->expression;
    if (expression.kind != CT_EXPRESSION_RETURN ||
        expression.function != row.owner)
      return {};
    if (row.returned.known)
      return row.returned;
    if (expression.constant && expression.constant_type.bytes &&
        expression.constant_type.bytes <= sizeof(expression.constant_value))
      return {scalar_value(expression.constant_type,
                           reinterpret_cast<const unsigned char *>(
                               &expression.constant_value),
                           expression.constant_type.bytes),
              expression.constant_type, expression.constant_value, true};
    // An inline wrapper can forward a real call's observed result. The
    // result belongs to this source invocation; the scope-exit registers may
    // already contain unrelated values and are never used as its return ABI.
    if (expression.is_call) {
      const SourceRow::CallResult *returned = nullptr;
      for (const auto &result : row.results) {
        if (result.call->result.callee != expression.callee)
          continue;
        if (returned)
          return {};
        returned = &result;
      }
      if (returned && returned->value != "?") {
        auto result = returned->returned;
        if (expression.result_casts.size() > 16)
          return {};
        for (const auto &type : expression.result_casts)
          result = convert_result(std::move(result), type);
        return result;
      }
    }
    const auto &comparison = expression.comparison;
    if (comparison.kind == CT_SOURCE_COMPARE_NONE) {
      const std::string name = llvm::StringRef(expression.text).trim().str();
      const auto *variable =
          named_variable(name, row.owner, row.before.site_id);
      if (!variable || !variable->type ||
          variable->type >= values->types.size())
        return {};
      const auto &type = values->types[variable->type];
      const auto *location = binding(variable->id, row.before.site_id);
      ct_kernel_value_result observed;
      if (type.guarded || !location ||
          !ct_kernel_evaluate_value(*values, *location, row.before, observed,
                                    &frame.entry))
        return {};
      const auto text =
          scalar_value(type.scalar, observed.bytes.data(), observed.size);
      uint64_t scalar = 0;
      if (observed.size <= sizeof(scalar))
        std::memcpy(&scalar, observed.bytes.data(), observed.size);
      return text == "?" || observed.size > sizeof(scalar)
                 ? InlineResult{}
                 : InlineResult{text, type.scalar, scalar, true};
    }
    if (comparison.types.empty() || comparison.types.size() > 16)
      return {};
    const auto *variable =
        named_variable(comparison.variable, row.owner, row.before.site_id);
    if (!variable || !variable->type || variable->type >= values->types.size())
      return {};
    const auto &type = values->types[variable->type];
    if (type.guarded || type.scalar.kind != comparison.types.front().kind ||
        type.scalar.bytes != comparison.types.front().bytes)
      return {};
    const auto *location = binding(variable->id, row.before.site_id);
    ct_kernel_value_result observed;
    if (!location ||
        !ct_kernel_evaluate_value(*values, *location, row.before, observed,
                                  &frame.entry) ||
        !observed.size || observed.size > sizeof(uint64_t))
      return {};
    uint64_t value = 0;
    std::memcpy(&value, observed.bytes.data(), observed.size);
    const auto result = ct_source_compare_value(comparison, type.scalar, value);
    if (!result)
      return {};
    ct_value_type result_type{};
    result_type.kind = CT_VALUE_BOOLEAN;
    result_type.bytes = 1;
    return {*result ? "0x1" : "0x0", result_type, *result ? 1u : 0u, true};
  }

  bool update_blocks(Frame &frame, const ct_kernel_observation &event,
                     std::vector<ct_kernel_trace_record> &records,
                     std::vector<ct_kernel_trace_transition> *output,
                     std::string &error) {
    for (auto &pending : frame.inline_rows) {
      if (!pending.awaiting_snapshot)
        continue;
      auto &row = pending.caller;
      const auto &before = row.before;
      const bool matching =
          event.site_id == before.site_id &&
          event.session_id == before.session_id &&
          event.generation == before.generation &&
          event.level == KCTRACE_LEVEL_FULL &&
          (event.flags & KCTRACE_EVENT_HAVE_EXECUTION) &&
          event.execution.frame_id == before.execution.frame_id &&
          event.execution.frame_id == frame.execution_id;
      const bool instruction =
          event.type == KCTRACE_EVENT_INSTRUCTION_BEFORE ||
          (event.execution.flags & KCTRACE_EXEC_INSTRUCTION);
      if (matching && instruction && event.level == KCTRACE_LEVEL_FULL) {
        // SCOPE gates carry only control state. The following full snapshot
        // is still before this exact original instruction, in the same frame.
        // Its registers remain usable without a memory capture plan. Never
        // backfill the caller from a later instruction or loop visit.
        row.before = event;
        row.inputs =
            source_values(source->lines[row.line].presentation->variables,
                          row.owner, event, frame);
      }
      if (!matching || instruction || event.type != KCTRACE_EVENT_EXECUTION ||
          (event.execution.kind != KCTRACE_BOUNDARY_SCOPE &&
           event.execution.kind != KCTRACE_BOUNDARY_CALL &&
           event.execution.kind != KCTRACE_BOUNDARY_CALL_UNPAIRED))
        pending.awaiting_snapshot = false;
    }
    bool generated = false;
    const auto *members = block_membership(event.site_id, generated);
    if (!members)
      return true;
    const auto &membership = *members;
    size_t common = 0;
    while (common < membership.size() && common < frame.blocks.size() &&
           membership[common] == frame.blocks[common].block &&
           frame.blocks[common].decompiled == generated)
      ++common;
    while (frame.blocks.size() > common) {
      if (!frame.inline_rows.empty() &&
          frame.inline_rows.back().block == frame.blocks.back().block &&
          !frame.blocks.back().decompiled) {
        auto result = inline_result(frame, frame.row);
        if (!result.known)
          result = frame.inline_rows.back().returned;
        flush_deferred(frame, records);
        flush_source(frame, records);
        const auto *call = frame.inline_rows.back().call;
        frame.row = std::move(frame.inline_rows.back().caller);
        frame.inline_rows.pop_back();
        // DWARF scope exit proves completion, but an inline result has no
        // fixed ABI register. Only a later observed destination write can
        // supply its assignment value; do not borrow an unrelated RAX.
        source_returned(frame, *call, event, false, true, &result);
        frame.row.assigned = 0;
      }
      transition(frame, frame.blocks.back(), ct_kernel_trace_phase::end,
                 event.monotonic_ns, "complete", output);
      frame.blocks.pop_back();
    }
    for (; common < membership.size(); ++common) {
      Frame::Scope block{};
      static_cast<Selection &>(block) = selection(frame);
      block.block = membership[common];
      block.decompiled = generated;
      const bool inlined =
          !generated && source->blocks[block.block].kind ==
                            ct_kernel_source_block_kind::inline_function;
      if (inlined) {
        const auto &definition = source->blocks[block.block];
        if (terminal && block.within && block.mode == into &&
            definition.call_line &&
            definition.call_line < source->lines.size()) {
          const auto &line = source->lines[definition.call_line];
          const ct_source_call_result_info *call = nullptr;
          if (line.presentation) {
            for (const auto &candidate : line.presentation->call_results) {
              if (candidate.function != definition.call_function ||
                  (definition.header != candidate.result.callee &&
                   definition.header != candidate.result.display_name) ||
                  (definition.call_column &&
                   (definition.call_column < candidate.result.begin_column ||
                    definition.call_column >= candidate.result.end_column)))
                continue;
              if (call) {
                call = nullptr;
                break;
              }
              call = &candidate;
            }
          }
          if (call) {
            flush_deferred(frame, records);
            if (frame.row.line != definition.call_line ||
                frame.row.owner != definition.call_function)
              flush_source(frame, records);
            if (!frame.row.line) {
              frame.row.line = definition.call_line;
              frame.row.owner = definition.call_function;
              frame.row.inline_prefix_seen =
                  inline_prefix(frame, event.site_id, definition.call_function);
              frame.row.before = event;
              frame.row.call_bearing = true;
              frame.row.inputs =
                  source_values(line.presentation->variables,
                                definition.call_function, event, frame);
            }
            frame.row.call_seen = true;
            release_fallback(frame.row.fallback);
            const auto &before = frame.row.before;
            const bool awaiting =
                before.type == KCTRACE_EVENT_EXECUTION &&
                before.level == KCTRACE_LEVEL_FULL &&
                (before.flags & KCTRACE_EVENT_HAVE_EXECUTION) &&
                !(before.flags & KCTRACE_EVENT_HAVE_VALUES) &&
                !(before.execution.flags & KCTRACE_EXEC_INSTRUCTION) &&
                (before.execution.kind == KCTRACE_BOUNDARY_ENTER ||
                 before.execution.kind == KCTRACE_BOUNDARY_SCOPE);
            frame.inline_rows.push_back(
                {block.block, std::move(frame.row), call, awaiting, {}});
            frame.row = {};
          }
        }
        const auto [mode, within] = block_filters[block.block];
        static_cast<Selection &>(block) =
            kctrace_policy_enter(block, mode, within);
        if (terminal && block.within && block.mode == into)
          block.inline_prefix_seen = std::make_shared<bool>(false);
        if (block.within && block.mode == into && !frame.inline_rows.empty() &&
            frame.inline_rows.back().block == block.block) {
          auto &row = frame.inline_rows.back();
          if (std::find(row.caller.entered_calls.begin(),
                        row.caller.entered_calls.end(),
                        row.call) == row.caller.entered_calls.end())
            row.caller.entered_calls.push_back(row.call);
        }
      }
      // Retain invisible lexical/inline membership as policy state. In
      // particular a within match in an inline body ends when that body ends,
      // and only calls made inside it inherit that active match.
      const bool visible = generated || inlined ||
                           source->blocks[block.block].kind !=
                               ct_kernel_source_block_kind::lexical ||
                           !source->blocks[block.block].header.empty();
      if (visible && block.within &&
          (block.mode == into || (inlined && block.mode == over))) {
        block.token = next_token++;
        block.parent = parent_token(frame);
        block.begin = event.monotonic_ns;
        block.pc = event.pc;
      }
      frame.blocks.push_back(block);
      transition(frame, block, ct_kernel_trace_phase::begin, event.monotonic_ns,
                 "", output);
    }
    return true;
  }

  bool
  finish_execution_instruction(Task &task, const ct_kernel_observation *after,
                               std::vector<ct_kernel_trace_record> &records) {
    if (!task.pending.site_id || task.frames.empty())
      return false;
    auto &frame = task.frames.back();
    const auto &before = task.pending;
    const auto &previous = sites[before.site_id];
    const bool same =
        after && before.execution.frame_id == after->execution.frame_id &&
        before.level == KCTRACE_LEVEL_FULL &&
        after->level == KCTRACE_LEVEL_FULL &&
        before.registers[KCTRACE_REG_RSP] == after->registers[KCTRACE_REG_RSP];
    const bool completed = same && previous.next == after->site_id &&
                           !previous.call && !previous.ret &&
                           !previous.branch && !previous.writes_stack;
    const bool sequential =
        same && previous.observation_next == after->site_id && !previous.call &&
        !previous.ret && !previous.branch && !previous.writes_stack;
    const bool branch =
        same && previous.branch && !previous.ret &&
        (previous.branch_target == after->site_id ||
         (previous.conditional && previous.next == after->site_id));
    if (branch)
      source_condition(frame, before, *after);
    source_assembly(frame, before, completed || branch ? after : nullptr,
                    records);
    if (completed && source && values && frame.row.line &&
        previous.source_line == frame.row.line &&
        previous.source_owner == frame.row.owner && previous.memory_read &&
        !previous.memory_write &&
        previous.memory_value_register < KCTRACE_REGISTER_COUNT &&
        previous.memory_operand.reg < KCTRACE_REGISTER_COUNT &&
        (after->valid_registers &
         (UINT64_C(1) << previous.memory_value_register)) &&
        (before.valid_registers &
         (UINT64_C(1) << previous.memory_operand.reg))) {
      const auto &expression =
          source->lines[frame.row.line].presentation->expression;
      if (expression.kind == CT_EXPRESSION_RETURN &&
          expression.function == frame.row.owner &&
          !expression.read_path.empty()) {
        const auto member = source_member(expression.read_path, frame.row.owner,
                                          before.site_id);
        const auto *location =
            member ? binding(member->variable, before.site_id) : nullptr;
        ct_kernel_value_result pointer;
        if (member && location &&
            member->type.kind == expression.value_type.kind &&
            member->type.bytes == expression.value_type.bytes &&
            member->type.bytes == previous.memory_value_width &&
            ct_kernel_evaluate_value(*values, *location, before, pointer,
                                     &frame.entry) &&
            pointer.size == sizeof(uint64_t)) {
          uint64_t base = 0;
          std::memcpy(&base, pointer.bytes.data(), sizeof(base));
          const __int128 expected = __int128(base) + member->offset;
          const __int128 accessed =
              __int128(before.registers[previous.memory_operand.reg]) +
              previous.memory_operand.displacement;
          if (base && expected <= UINT64_MAX && expected == accessed) {
            auto &result = frame.row.returned;
            result.type = member->type;
            result.scalar = after->registers[previous.memory_value_register] >>
                            previous.memory_value_shift;
            result.text = scalar_value(
                result.type,
                reinterpret_cast<const unsigned char *>(&result.scalar),
                result.type.bytes);
            result.known = true;
          }
        }
      }
    }
    if (completed)
      complete_assignment(frame, previous, before, *after);
    if (completed && source && frame.row.line &&
        previous.source_line == frame.row.line &&
        previous.source_owner == frame.row.owner &&
        !previous.store_object.empty() &&
        previous.memory_value_register < KCTRACE_REGISTER_COUNT &&
        (before.valid_registers &
         (UINT64_C(1) << previous.memory_value_register))) {
      const auto &expression =
          source->lines[frame.row.line].presentation->expression;
      if (expression.function == frame.row.owner && expression.is_call &&
          expression.assignment_object == previous.store_object &&
          expression.assignment_type.bytes == previous.memory_value_width) {
        if (const auto *call = source_call(frame, expression.callee)) {
          // This completed scalar store consumes the exact AST RHS call.
          // Its lossless assignment conversion preserves the callee value,
          // including paths where the compiler folded away the inline RET.
          for (auto &result : frame.row.results) {
            if (result.call != call || result.returned.known)
              continue;
            InlineResult observed;
            observed.scalar =
                before.registers[previous.memory_value_register] >>
                previous.memory_value_shift;
            observed.type = expression.assignment_type;
            observed.known = true;
            observed =
                convert_result(std::move(observed), call->result.return_type);
            if (observed.known) {
              result.value = observed.text;
              result.returned = std::move(observed);
              result.display = true;
            }
          }
        }
      }
    }
    decompile_completed(frame, before,
                        completed || sequential || branch ? after : nullptr,
                        records);
    if (task.selected)
      emit(render(before, completed || branch ? after : nullptr, &frame),
           records, &frame);
    task.pending = {};
    task.selected = false;
    return completed || sequential;
  }

  void execution_gap(Task &task, const ct_kernel_observation &event,
                     const char *reason,
                     std::vector<ct_kernel_trace_record> &records,
                     std::vector<ct_kernel_trace_transition> *output) {
    close_task(task, event.monotonic_ns, reason, records, output);
    if (!task.execution_unknown) {
      ct_kernel_trace_record gap;
      gap.monotonic_ns = event.monotonic_ns;
      gap.stage = ct_kernel_trace_stage::discontinuity;
      gap.text = std::string("kernel execution context is unknown: ") + reason;
      records.push_back(std::move(gap));
    }
    task.execution_unknown = true;
  }

  bool consume_execution(Task &task, const ct_kernel_observation &event,
                         std::vector<ct_kernel_trace_record> &records,
                         std::vector<ct_kernel_trace_transition> *output,
                         std::string &error) {
    const auto &execution = event.execution;
    const auto &site = sites[event.site_id];
    const auto &function = functions[site.function];
    const auto gap = [&](const char *reason) {
      execution_gap(task, event, reason, records, output);
      return true;
    };
    if (!task.execution && !task.frames.empty())
      return gap("mixed dense and explicit observations");
    task.execution = true;
    if (execution.flags & (KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY))
      return gap("runtime state discontinuity");
    if (!execution.frame_id)
      return gap("missing frame cookie");
    if (task.execution_unknown &&
        (execution.kind != KCTRACE_BOUNDARY_ENTER || execution.parent_frame_id))
      return true;

    if (execution.kind == KCTRACE_BOUNDARY_ENTER) {
      if (event.site_id != function.first ||
          execution.frame_id <= task.execution_serial ||
          execution.parent_frame_id !=
              (task.frames.empty() ? 0 : task.frames.back().execution_id) ||
          (task.frames.empty() &&
           (execution.call_id || (execution.flags & KCTRACE_EXEC_CALLBACK))) ||
          (!task.frames.empty() &&
           (!task.frames.back().call_cookie ||
            (execution.call_id
                 ? execution.call_id != task.frames.back().call_cookie ||
                       (execution.flags & KCTRACE_EXEC_CALLBACK)
                 : !(execution.flags & KCTRACE_EXEC_CALLBACK)))))
        return gap("unproven frame entry");
      finish_execution_instruction(task, nullptr, records);
      Frame frame{};
      const unsigned char incoming =
          task.frames.empty()
              ? bool(execution.inheritance & KCTRACE_INHERIT_WITHIN)
              : task.frames.back().execution_state;
      auto base = policy.functions[execution.function].states[incoming & 7];
      if (execution.flags & KCTRACE_EXEC_HANDLER_CRITERION)
        base |= 1;
      const auto state =
          execution.path ? policy.paths[execution.path].states[base & 7] : base;
      if (state != execution.state)
        return gap("entry policy differs from prepared state");
      static_cast<Selection &>(frame) = kctrace_policy_decode(base);
      frame.execution_id = execution.frame_id;
      frame.execution_parent = execution.parent_frame_id;
      frame.incoming_call = execution.call_id;
      frame.execution_state = execution.state;
      frame.execution_level = event.level;
      frame.function = site.function;
      frame.entry = event;
      frame.stack = event.registers[KCTRACE_REG_RSP];
      frame.source_function = function.name;
      if (source && event.site_id < source->sites.size()) {
        const auto index = source->sites[event.site_id].function;
        if (index)
          frame.source_function = source->functions[index].name;
      }
      if (execution.call_id && !task.frames.empty()) {
        auto &caller = task.frames.back();
        caller.call_skipped |= frame.mode == skip;
        frame.call_source = source_call(caller, function.name);
        frame.call_decompile = decompile_call(caller);
        if (frame.call_source) {
          caller.pending_source = frame.call_source;
          caller.row.call_seen = true;
          release_fallback(caller.row.fallback);
        }
        const auto selected = kctrace_policy_decode(execution.state);
        if (selected.within && selected.mode == into) {
          if (frame.call_source &&
              std::find(caller.row.entered_calls.begin(),
                        caller.row.entered_calls.end(),
                        frame.call_source) == caller.row.entered_calls.end())
            caller.row.entered_calls.push_back(frame.call_source);
          if (caller.row.line && !caller.row.printed)
            flush_source(caller, records, true);
          if (caller.decompiled.statement && !caller.decompiled.printed)
            flush_decompile(caller, records, nullptr, true);
        }
      }
      if (frame.within && frame.mode != skip) {
        frame.scope.token = next_token++;
        frame.scope.begin = event.monotonic_ns;
        frame.scope.pc = event.pc;
        for (auto parent = task.frames.rbegin(); parent != task.frames.rend();
             ++parent)
          if (const auto token = parent_token(*parent)) {
            frame.scope.parent = token;
            break;
          }
        transition(frame, frame.scope, ct_kernel_trace_phase::begin,
                   event.monotonic_ns, "", output);
      }
      task.frames.push_back(std::move(frame));
      task.execution_serial = execution.frame_id;
      task.execution_unknown = false;
      auto &entered = task.frames.back();
      if (!update_blocks(entered, event, records, output, error))
        return false;
      const auto selected = kctrace_policy_decode(execution.state);
      if (terminal && selected.within && selected.mode == into &&
          (execution.flags & KCTRACE_EXEC_ENTRY_VALUES)) {
        source_entry(entered, records);
        decompile_entry(entered, event, records);
      }
      return true;
    }

    if (task.frames.empty() ||
        task.frames.back().execution_id != execution.frame_id ||
        task.frames.back().execution_parent != execution.parent_frame_id ||
        task.frames.back().function != site.function)
      return gap("boundary does not match the active frame");
    auto &frame = task.frames.back();
    const bool calling = execution.kind == KCTRACE_BOUNDARY_CALL ||
                         execution.kind == KCTRACE_BOUNDARY_CALL_UNPAIRED;
    const bool returned = execution.kind == KCTRACE_BOUNDARY_AFTER_CALL;
    const auto base = kctrace_policy_encode(frame);
    const auto state =
        execution.path ? policy.paths[execution.path].states[base & 7] : base;
    if (state != execution.state ||
        (!calling && !returned && execution.call_id != frame.incoming_call) ||
        execution.previous_level != frame.execution_level)
      return gap("boundary policy or call identity changed without evidence");
    if (execution.kind == KCTRACE_BOUNDARY_POINT &&
        (event.level != frame.execution_level ||
         execution.state != frame.execution_state ||
         (frame.call_cookie &&
          (frame.call_site != event.site_id || frame.call_observed))))
      return gap("body point crosses an unobserved boundary");
    if (execution.kind == KCTRACE_BOUNDARY_POINT &&
        event.site_id == frame.guard_site)
      return gap("body point duplicates a control guard observation");
    if (calling && (!site.call || !execution.call_id || frame.call_cookie ||
                    execution.call_id <= task.execution_serial))
      return gap("invalid pending call cookie");
    if (returned && (!frame.call_cookie || frame.call_unpaired ||
                     execution.call_id != frame.call_cookie ||
                     sites[frame.call_site].next != event.site_id))
      return gap("caller completion does not match its pending call");
    if (!calling && !returned && execution.kind != KCTRACE_BOUNDARY_POINT &&
        frame.call_cookie)
      return gap("suspended caller reached an ordinary boundary");

    const bool level_changed = event.level != frame.execution_level;
    const auto previous_selection =
        kctrace_policy_decode(frame.execution_state);
    const auto selected = kctrace_policy_decode(execution.state);
    const bool previous_detailed =
        terminal && frame.execution_level == KCTRACE_LEVEL_FULL &&
        previous_selection.within && previous_selection.mode == into;
    const bool detailed = terminal && event.level == KCTRACE_LEVEL_FULL &&
                          selected.within && selected.mode == into;
    // A single FULL body still has policy gaps. Physical snapshots from a
    // hidden interval must not complete a selected row or deferred assignment.
    const bool observation_changed =
        level_changed || previous_detailed != detailed;
    const bool exiting = execution.kind == KCTRACE_BOUNDARY_EXIT;
    const bool tail = execution.kind == KCTRACE_BOUNDARY_TAIL;
    const bool instruction = execution.flags & KCTRACE_EXEC_INSTRUCTION;
    const bool body = event.type == KCTRACE_EVENT_INSTRUCTION_BEFORE ||
                      exiting || tail || instruction;
    const bool resumed =
        body && !observation_changed && frame.resumed_site == event.site_id;
    const bool repeated =
        body && task.pending.site_id &&
        task.pending.execution.frame_id == execution.frame_id &&
        sites[task.pending.site_id].branch &&
        sites[task.pending.site_id].function == site.function &&
        site.original.offset <= sites[task.pending.site_id].original.offset &&
        (sites[task.pending.site_id].branch_target == event.site_id ||
         (sites[task.pending.site_id].conditional &&
          sites[task.pending.site_id].next == event.site_id));
    if (body || observation_changed || frame.resumed_site != event.site_id)
      frame.resumed_site = 0;
    bool completed = false;
    if (observation_changed && !returned) {
      flush_forwarded(frame, records);
      if (previous_detailed && task.pending.site_id &&
          task.pending.execution.frame_id == execution.frame_id &&
          (event.valid_registers & (UINT64_C(1) << KCTRACE_REG_RSP)) &&
          (task.pending.valid_registers & (UINT64_C(1) << KCTRACE_REG_RSP)) &&
          task.pending.registers[KCTRACE_REG_RSP] ==
              event.registers[KCTRACE_REG_RSP]) {
        const auto &previous = sites[task.pending.site_id];
        if (previous.next == event.site_id && previous.stored_assignment &&
            !previous.call && !previous.ret && !previous.branch &&
            !previous.writes_stack)
          complete_assignment(frame, previous, task.pending, event);
        if (previous.branch && !previous.ret &&
            (previous.branch_target == event.site_id ||
             (previous.conditional && previous.next == event.site_id)))
          source_condition(frame, task.pending, event);
      }
      finish_execution_instruction(task, nullptr, records);
    } else if (body && detailed) {
      completed = finish_execution_instruction(task, &event, records);
    } else if (event.type == KCTRACE_EVENT_BLOCK_POINT) {
      finish_execution_instruction(task, nullptr, records);
    }
    frame.execution_state = execution.state;
    frame.execution_level = event.level;

    if (calling) {
      frame.call_cookie = execution.call_id;
      frame.call_site = event.site_id;
      frame.call_unpaired = execution.kind == KCTRACE_BOUNDARY_CALL_UNPAIRED;
      frame.call_observed = frame.call_reported = frame.call_skipped = false;
      frame.pending_source = nullptr;
      frame.call_return = {};
      task.execution_serial = execution.call_id;
    }
    if (returned) {
      finish_execution_instruction(task, nullptr, records);
      if (terminal && (execution.flags & KCTRACE_EXEC_RETURN_VALUE)) {
        const auto *call = frame.pending_source;
        if (!call)
          call = source_call(frame, sites[frame.call_site].call_name);
        if (call)
          source_returned(
              frame, *call, event, frame.call_reported, frame.call_skipped,
              frame.call_return.known ? &frame.call_return : nullptr);
        if (decompile && frame.decompiled.statement &&
            frame.decompiled.last.site_id == frame.call_site &&
            frame.decompiled.next ==
                decompile->statements[frame.decompiled.statement]
                    .sites.size()) {
          if (frame.decompiled.printed && frame.call_reported &&
              decompile->statements[frame.decompiled.statement]
                  .assignment.empty()) {
            frame.decompiled = {};
          } else {
            flush_decompile(frame, records, &event, false, frame.call_skipped);
          }
        }
      }
      frame.call_cookie = frame.call_site = 0;
      frame.call_unpaired = frame.call_observed = frame.call_reported = false;
      frame.call_skipped = false;
      frame.pending_source = nullptr;
      frame.call_return = {};
      if (!observation_changed && detailed &&
          (execution.flags & KCTRACE_EXEC_RETURN_VALUE))
        frame.resumed_site = event.site_id;
    }
    // SCOPE contains selector state, not the full register/value snapshot.
    // Finish the old instruction using the following body observation before
    // entering an inline scope that can flush its pending source row.
    const bool defer_scope = execution.kind == KCTRACE_BOUNDARY_SCOPE &&
                             !instruction && detailed && !observation_changed;
    const auto previous_inline =
        frame.inline_rows.empty() ? 0 : frame.inline_rows.back().block;
    if (!defer_scope && !update_blocks(frame, event, records, output, error))
      return false;
    // An authenticated inline exit restores the selected caller's unfinished
    // expression. Its destination store or condition still belongs to that
    // invocation, even though the hidden body changed the observation policy.
    const bool inline_resumed =
        detailed && previous_inline && frame.row.line && frame.row.call_seen &&
        frame.row.after.site_id == event.site_id &&
        frame.row.after.sequence == event.sequence &&
        std::none_of(
            frame.inline_rows.begin(), frame.inline_rows.end(),
            [&](const auto &row) { return row.block == previous_inline; });
    if (inline_resumed && !body)
      frame.resumed_site = event.site_id;
    if ((observation_changed && !inline_resumed) ||
        event.type == KCTRACE_EVENT_BLOCK_POINT) {
      flush_deferred(frame, records);
      flush_source(frame, records);
      flush_decompile(frame, records);
    }
    if (event.site_id != frame.guard_site)
      frame.guard_site = 0;
    if (instruction)
      frame.guard_site = event.site_id;
    if (body) {
      if (!detailed && terminal && selected.within && selected.mode == over &&
          event.level == KCTRACE_LEVEL_FULL && source && values &&
          site.source_line && site.source_line < source->lines.size() &&
          source->lines[site.source_line].presentation &&
          !frame.inline_rows.empty()) {
        auto &inlined = frame.inline_rows.back();
        const auto &expression =
            source->lines[site.source_line].presentation->expression;
        if (!inlined.return_observed &&
            source->blocks[inlined.block].header == site.source_owner &&
            expression.kind == CT_EXPRESSION_RETURN &&
            expression.function == site.source_owner) {
          inlined.return_observed = true;
          // Retain only a pure scalar return's existing, exact input snapshot.
          // Step-over has no displayed body row and must not infer intermediate
          // values, read new memory, or use an arbitrary inline-exit RAX.
          const auto name = expression.comparison.kind != CT_SOURCE_COMPARE_NONE
                                ? expression.comparison.variable
                                : llvm::StringRef(expression.text).trim().str();
          const auto *variable =
              named_variable(name, site.source_owner, event.site_id);
          if (expression.constant ||
              (variable && !variable->global &&
               location_register(binding(variable->id, event.site_id)) <
                   KCTRACE_REGISTER_COUNT)) {
            SourceRow result;
            result.line = site.source_line;
            result.owner = site.source_owner;
            result.before = event;
            inlined.returned = inline_result(frame, result);
          }
        }
      }
      task.selected = detailed;
      if (task.selected) {
        if (source_observation(frame, event, records, repeated,
                               completed || resumed || inline_resumed) ||
            decompile_observation(frame, event, records))
          task.selected = false;
      }
      task.pending = detailed ? event : ct_kernel_observation{};
      if (frame.call_cookie && frame.call_site == event.site_id) {
        frame.call_observed = true;
        source_arguments(frame, event);
        frame.pending_source = source_call(frame, site.call_name);
      }
    }
    if (tail && detailed && source_call(frame, site.call_name)) {
      // A tail jump proves invocation, but its result belongs to the caller's
      // eventual return. Render the original C call without inventing a value.
      source_arguments(frame, event);
      frame.row.call_seen = true;
      release_fallback(frame.row.fallback);
    }
    if (exiting || tail) {
      finish_execution_instruction(task, nullptr, records);
      close_frame(
          task, event.monotonic_ns, exiting ? "result-ready" : "tail-call",
          exiting && (execution.flags & KCTRACE_EXEC_RETURN_VALUE) ? &event
                                                                   : nullptr,
          records, output, false);
    }
    return true;
  }
};

ct_kernel_trace::ct_kernel_trace() : data(std::make_unique<Data>()) {}
ct_kernel_trace::~ct_kernel_trace() = default;

const ct_kernel_policy &ct_kernel_trace::prepared_policy() const {
  return data->policy;
}

const std::vector<uint64_t> &ct_kernel_trace::timing_sites() const {
  return data->timing_sites;
}

const std::vector<uint8_t> &ct_kernel_trace::observation_sites() const {
  return data->observation_sites;
}

bool ct_kernel_trace::prepare(const ct_kernel_image &image,
                              const std::vector<ct_kernel_site> &sites,
                              const ct_kernel_trace_options &options,
                              std::string &error) {
  error.clear();
  if (data->prepared || sites.empty() || sites.size() > uint64_t(UINT32_MAX)) {
    error = "invalid or repeated kernel trace preparation";
    return false;
  }
  auto prepared = std::make_unique<Data>();
  prepared->terminal = options.emit_terminal;
  prepared->within_filter =
      !options.within.empty() || options.within_init || options.within_intr;
  prepared->within_intr = options.within_intr;
  prepared->source = options.source;
  prepared->decompile = options.decompile;
  prepared->values = options.values;
  prepared->captures = options.captures;
  if (prepared->decompile) {
    const auto &decompile = *prepared->decompile;
    if (decompile.functions.empty() || decompile.statements.empty() ||
        decompile.blocks.empty() ||
        decompile.sites.size() > uint64_t(UINT32_MAX) + 1) {
      error = "invalid kernel decompile metadata pools";
      return false;
    }
    for (size_t id = 1; id < decompile.statements.size(); ++id) {
      const auto &statement = decompile.statements[id];
      if (!statement.function ||
          statement.function >= decompile.functions.size() ||
          statement.sites.empty()) {
        error = "invalid kernel decompile statement proof";
        return false;
      }
      for (size_t index = 0; index < statement.sites.size(); ++index) {
        const auto site = statement.sites[index];
        if (!site || site >= decompile.sites.size() ||
            decompile.sites[site].statement != id ||
            decompile.sites[site].index != index ||
            decompile.sites[site].function != statement.function) {
          error = "inconsistent kernel decompile statement membership";
          return false;
        }
      }
    }
    for (const auto &site : decompile.sites) {
      if (site.function >= decompile.functions.size() ||
          site.statement >= decompile.statements.size()) {
        error = "invalid kernel decompile site metadata";
        return false;
      }
      for (const auto &reference : site.variables)
        if (!reference.variable ||
            (prepared->values &&
             reference.variable >= prepared->values->variables.size())) {
          error = "invalid kernel decompile variable identity";
          return false;
        }
      uint64_t parent = 0;
      for (const auto block : site.blocks) {
        if (!block || block >= decompile.blocks.size() ||
            decompile.blocks[block].parent != parent ||
            decompile.blocks[block].function != site.function) {
          error = "invalid kernel decompile block ancestry";
          return false;
        }
        parent = block;
      }
    }
  }
  if (prepared->source) {
    const auto &source = *prepared->source;
    if (source.files.empty() || source.lines.empty() ||
        source.functions.empty() || source.blocks.empty()) {
      error = "kernel source metadata has no unknown sentinels";
      return false;
    }
    for (const auto &line : source.lines)
      if (line.file >= source.files.size()) {
        error = "kernel source line has an invalid file";
        return false;
      }
    for (size_t index = 0; index < source.functions.size(); ++index)
      if (source.functions[index].id != index ||
          source.functions[index].file >= source.files.size()) {
        error = "kernel source function has an invalid file";
        return false;
      }
    for (size_t index = 1; index < source.blocks.size(); ++index) {
      const auto &block = source.blocks[index];
      if (block.id != index || block.file >= source.files.size() ||
          block.parent >= source.blocks.size() ||
          block.function >= source.functions.size()) {
        error = "kernel source block has an invalid identity";
        return false;
      }
      for (const auto &range : block.ranges)
        if (range.section >= image.sections.size() ||
            range.begin >= range.end ||
            range.end > image.sections[range.section].size) {
          error = "kernel source block exceeds its original section";
          return false;
        }
    }
    for (const auto &site : source.sites) {
      if (site.line >= source.lines.size() ||
          site.function >= source.functions.size() ||
          site.not_taken_successor >= source.sites.size() ||
          site.blocks.size() > uint64_t(UINT32_MAX)) {
        error = "kernel source site has invalid metadata";
        return false;
      }
      std::set<uint64_t> seen;
      for (const auto block : site.blocks)
        if (!block || block >= source.blocks.size() ||
            !seen.insert(block).second) {
          error = "kernel source block membership is invalid";
          return false;
        }
    }
  }
  if (prepared->values) {
    const auto &values = *prepared->values;
    if (values.variables.empty() || values.types.empty() ||
        values.recipes.empty() || values.functions.empty() ||
        values.accesses.empty() ||
        values.sites.size() > uint64_t(UINT32_MAX) + 1) {
      error = "invalid kernel value metadata pools";
      return false;
    }
    for (size_t index = 0; index < values.variables.size(); ++index)
      if (values.variables[index].id != index ||
          values.variables[index].type >= values.types.size()) {
        error = "invalid kernel variable identity or type";
        return false;
      }
    for (const auto &function : values.functions)
      if (function.return_type >= values.types.size() ||
          (function.return_register != UINT32_MAX &&
           (!function.return_type || function.returns_void ||
            (function.return_register == 0
                 ? values.types[function.return_type].scalar.kind ==
                       CT_VALUE_FLOAT
                 : !((function.return_register == 17 &&
                      values.types[function.return_type].scalar.kind ==
                          CT_VALUE_FLOAT &&
                      (values.types[function.return_type].scalar.bytes == 4 ||
                       values.types[function.return_type].scalar.bytes == 8)) ||
                     (function.return_register == 33 &&
                      values.types[function.return_type].scalar.kind ==
                          CT_VALUE_FLOAT &&
                      values.types[function.return_type].scalar.bytes ==
                          10)))))) {
        error = "invalid kernel function return type";
        return false;
      }
    for (size_t index = 1; index < values.accesses.size(); ++index) {
      const auto &access = values.accesses[index];
      if (!access.variable || access.variable >= values.variables.size() ||
          access.layout_type > values.layout_types.size() ||
          access.expression.empty() || access.name.empty()) {
        error = "invalid kernel selected access identity";
        return false;
      }
    }
    for (const auto &site : values.sites) {
      if (site.function >= values.functions.size()) {
        error = "invalid kernel value function identity";
        return false;
      }
      std::set<uint64_t> seen;
      for (const auto &binding : site.bindings)
        if (!binding.variable || binding.variable >= values.variables.size() ||
            binding.recipe >= values.recipes.size() ||
            !seen.insert(binding.variable).second) {
          error = "invalid kernel variable binding";
          return false;
        }
      std::set<uint32_t> accesses;
      for (const auto &binding : site.accesses)
        if (!binding.access || binding.access >= values.accesses.size() ||
            !accesses.insert(binding.access).second) {
          error = "invalid kernel selected access binding";
          return false;
        }
    }
  }
  const ct_kernel_policy_options policy_options{
      options.within, options.into,        options.recurse,
      options.over,   options.within_init, options.within_intr};
  if (!ct_kernel_compile_policy(image, sites, prepared->source.get(),
                                policy_options, prepared->policy, error))
    return false;
  if (prepared->source) {
    prepared->block_filters.resize(prepared->source->blocks.size());
    for (const auto &scope : prepared->policy.inlines)
      if (scope.source_block)
        prepared->block_filters[scope.source_block] = {scope.mode,
                                                       scope.within};
  }
  std::map<std::pair<uint32_t, uint64_t>, size_t> function_index;
  prepared->functions.emplace_back(); // Match the one-based policy IDs.
  for (const auto &policy : prepared->policy.functions) {
    if (!policy.alias_count)
      continue;
    function_index.emplace(std::make_pair(policy.section, policy.begin),
                           prepared->functions.size());
    Data::Function function;
    function.section = policy.section;
    function.begin = policy.begin;
    function.end = policy.end;
    function.name =
        image.symbols[prepared->policy.aliases[policy.first_alias]].name;
    if (prepared->source && policy.source_function &&
        policy.source_function < prepared->source->functions.size())
      function.name = prepared->source->functions[policy.source_function].name;
    function.mode = policy.mode;
    function.within = policy.within;
    prepared->functions.push_back(std::move(function));
  }
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetDisassembler();
  const llvm::Triple triple("x86_64-pc-linux-gnu");
  const auto *target = llvm::TargetRegistry::lookupTarget(triple.str(), error);
  if (!target)
    return false;
  llvm::MCTargetOptions target_options;
  std::unique_ptr<llvm::MCRegisterInfo> registers(
      target->createMCRegInfo(triple.str()));
  if (!registers) {
    error = "kernel register metadata unavailable";
    return false;
  }
  std::unique_ptr<llvm::MCAsmInfo> assembly(
      target->createMCAsmInfo(*registers, triple.str(), target_options));
  std::unique_ptr<llvm::MCSubtargetInfo> subtarget(
      target->createMCSubtargetInfo(triple.str(), "generic", ""));
  std::unique_ptr<llvm::MCInstrInfo> instructions(target->createMCInstrInfo());
  if (!assembly || !subtarget || !instructions) {
    error = "kernel instruction metadata unavailable";
    return false;
  }
  llvm::MCContext context(triple, assembly.get(), registers.get(),
                          subtarget.get());
  std::unique_ptr<llvm::MCDisassembler> decoder(
      target->createMCDisassembler(*subtarget, context));
  std::unique_ptr<llvm::MCInstPrinter> printer(target->createMCInstPrinter(
      triple, options.intel ? 1 : 0, *assembly, *instructions, *registers));
  std::unique_ptr<llvm::MCInstrAnalysis> instruction_analysis(
      target->createMCInstrAnalysis(instructions.get()));
  std::unique_ptr<llvm::MCCodeEmitter> encoder(
      target->createMCCodeEmitter(*instructions, context));
  if (!decoder || !printer || !instruction_analysis || !encoder) {
    error = "kernel disassembler unavailable";
    return false;
  }
  printer->setPrintImmHex(true);
  printer->setPrintBranchImmAsAddress(true);
  const auto *memory_symbol = llvm::MCSymbolRefExpr::create(
      context.getOrCreateSymbol("ctrace_memory"), context);
  std::map<std::string, Data::Register> register_names;
  const char *families[][5] = {{"RAX", "EAX", "AX", "AL", "AH"},
                               {"RBX", "EBX", "BX", "BL", "BH"},
                               {"RCX", "ECX", "CX", "CL", "CH"},
                               {"RDX", "EDX", "DX", "DL", "DH"},
                               {"RSI", "ESI", "SI", "SIL", nullptr},
                               {"RDI", "EDI", "DI", "DIL", nullptr},
                               {"RBP", "EBP", "BP", "BPL", nullptr},
                               {"RSP", "ESP", "SP", "SPL", nullptr},
                               {"R8", "R8D", "R8W", "R8B", nullptr},
                               {"R9", "R9D", "R9W", "R9B", nullptr},
                               {"R10", "R10D", "R10W", "R10B", nullptr},
                               {"R11", "R11D", "R11W", "R11B", nullptr},
                               {"R12", "R12D", "R12W", "R12B", nullptr},
                               {"R13", "R13D", "R13W", "R13B", nullptr},
                               {"R14", "R14D", "R14W", "R14B", nullptr},
                               {"R15", "R15D", "R15W", "R15B", nullptr},
                               {"RFLAGS", "EFLAGS", nullptr, nullptr, nullptr},
                               {"RIP", "EIP", "IP", nullptr, nullptr}};
  const unsigned widths[] = {64, 32, 16, 8, 8};
  llvm::MCRegister x87_top;
  for (unsigned index = 1; index < registers->getNumRegs(); ++index) {
    Data::Register reg;
    reg.name = registers->getName(index);
    if (reg.name == "ST0")
      x87_top = index;
    reg.slot = KCTRACE_REGISTER_COUNT;
    reg.bits = 0;
    const std::string_view name = reg.name;
    size_t prefix = 0;
    if (name.starts_with("XMM") || name.starts_with("YMM") ||
        name.starts_with("ZMM")) {
      reg.xstate = 1;
      reg.bits = name.front() == 'X' ? 128 : name.front() == 'Y' ? 256 : 512;
      prefix = 3;
    } else if (name.starts_with("TMM")) {
      reg.xstate = 9;
      reg.bits = 8192;
      prefix = 3;
    } else if (name.starts_with("ST") ||
               (name.starts_with("FP") && name.size() == 3 &&
                std::isdigit(name.back()))) {
      reg.xstate = 2;
      reg.bits = 80;
      prefix = 2;
    } else if (name.starts_with("MM")) {
      reg.xstate = 3;
      reg.bits = 64;
      prefix = 2;
    } else if (name.size() == 2 && name.front() == 'K' &&
               std::isdigit(name.back())) {
      reg.xstate = 4;
      reg.bits = 64;
      prefix = 1;
    } else if (name == "FPCW" || name == "FPSW" || name == "MXCSR" ||
               name == "FPTAG") {
      reg.xstate = name == "FPCW"    ? 5
                   : name == "FPSW"  ? 6
                   : name == "MXCSR" ? 7
                                     : 8;
      reg.bits = name == "MXCSR" ? 32 : name == "FPTAG" ? 8 : 16;
    }
    if (prefix) {
      const auto parsed = std::from_chars(
          name.data() + prefix, name.data() + name.size(), reg.number);
      if (parsed.ec != std::errc{} || parsed.ptr != name.data() + name.size() ||
          reg.number >= (reg.xstate == 1 ? 32 : 8)) {
        reg.xstate = 0;
        reg.bits = 0;
      }
    }
    register_names.emplace(reg.name, std::move(reg));
  }
  for (unsigned slot = 0; slot < KCTRACE_REGISTER_COUNT; ++slot)
    for (unsigned alias = 0; alias < 5; ++alias)
      if (families[slot][alias]) {
        Data::Register reg;
        reg.name = families[slot][alias];
        reg.slot = slot;
        reg.bits = widths[alias];
        reg.shift = alias == 4 ? 8 : 0;
        register_names[reg.name] = std::move(reg);
      }
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_relocation *>
      relocations;
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_symbol *> objects;
  std::map<std::string, size_t> object_names;
  for (const auto &relocation : image.relocations)
    relocations.emplace(std::make_pair(relocation.section, relocation.offset),
                        &relocation);
  for (const auto &symbol : image.symbols) {
    symbols.emplace(std::make_pair(symbol.table, symbol.index), &symbol);
    if (symbol.type == STT_OBJECT) {
      ++object_names[symbol.name];
      const auto [it, inserted] = objects.emplace(
          std::make_pair(symbol.section, symbol.offset), &symbol);
      if (!inserted)
        it->second = nullptr;
    }
  }
  // A fixup can resume at the ordinary next instruction. Observing that PC
  // alone cannot prove that a preceding configuration reset succeeded.
  std::set<
      std::pair<std::pair<uint32_t, uint64_t>, std::pair<uint32_t, uint64_t>>>
      fault_transfers;
  for (const auto &field : image.relocations) {
    if (image.sections[field.section].name != "__ex_table" || field.offset % 12)
      continue;
    const auto fixup = relocations.find({field.section, field.offset + 4});
    const auto fault_symbol = symbols.find({field.symbol_table, field.symbol});
    if (fixup == relocations.end() || fault_symbol == symbols.end()) {
      error = "kernel trace exception entry has no fault/fixup pair";
      return false;
    }
    const auto &target = *fixup->second;
    const auto fixup_symbol =
        symbols.find({target.symbol_table, target.symbol});
    if (fixup_symbol == symbols.end() || field.type != R_X86_64_PC32 ||
        target.type != R_X86_64_PC32) {
      error = "kernel trace exception entry has invalid relocation";
      return false;
    }
    const auto resolve = [&](const ct_kernel_symbol &symbol, int64_t addend,
                             std::pair<uint32_t, uint64_t> &address) {
      const __int128 offset = __int128(symbol.offset) + addend;
      if (symbol.section >= image.sections.size() || offset < 0 ||
          offset >= image.sections[symbol.section].size)
        return false;
      address = {symbol.section, uint64_t(offset)};
      return true;
    };
    std::pair<uint32_t, uint64_t> from, to;
    if (!resolve(*fault_symbol->second, field.addend, from) ||
        !resolve(*fixup_symbol->second, target.addend, to)) {
      error = "kernel trace exception entry leaves its section";
      return false;
    }
    fault_transfers.emplace(from, to);
  }
  uint64_t max_site = 0;
  for (const auto &site : sites)
    if (site.probe)
      max_site = std::max(max_site, site.id);
  if (!max_site || max_site > uint64_t(UINT32_MAX)) {
    error = "kernel trace site identifiers exceed limit";
    return false;
  }
  prepared->sites.resize(max_site + 1);
  std::map<std::pair<uint32_t, uint64_t>, uint64_t> site_index;
  std::map<uint64_t, std::pair<uint32_t, uint64_t>> branch_destinations;
  std::vector<std::tuple<uint32_t, uint64_t, uint64_t>> protected_entries;
  std::map<std::string, unsigned> source_files;
  if (!prepared->source) {
    std::vector<ct_kernel_line_location> locations;
    if (!ct_kernel_collect_line_locations(image, sites, locations, error))
      return false;
    for (const auto &location : locations) {
      const auto [file, inserted] =
          source_files.emplace(location.file, prepared->files.size());
      if (inserted)
        prepared->files.push_back(location.file);
      auto &site = prepared->sites[location.site];
      site.file = file->second;
      site.line = location.line;
    }
  }
  for (const auto &source : sites) {
    if (!source.probe)
      continue;
    if (!source.id || source.id >= prepared->sites.size() ||
        prepared->sites[source.id].original.id ||
        source.section >= image.sections.size()) {
      error = "invalid kernel site identity";
      return false;
    }
    const auto &section = image.sections[source.section];
    if (!source.original_size || source.original_size > 15 ||
        source.offset > section.size ||
        source.original_size > section.size - source.offset ||
        section.offset > image.bytes.size() ||
        section.size > image.bytes.size() - section.offset) {
      error = "kernel trace site exceeds original section";
      return false;
    }
    auto function = function_index.upper_bound({source.section, source.offset});
    if (function == function_index.begin() ||
        (--function)->first.first != source.section ||
        prepared->functions[function->second].end <= source.offset) {
      error = "kernel trace site has no bounded original function";
      return false;
    }
    auto &site = prepared->sites[source.id];
    site.original = source;
    site.compiler_support = prepared->source &&
                            source.id < prepared->source->sites.size() &&
                            prepared->source->sites[source.id].compiler_support;
    if (prepared->decompile)
      for (const auto &region : prepared->decompile->layout.regions)
        if (region.section == source.section && source.offset < region.size &&
            region.address >= prepared->decompile->layout.image_base &&
            source.offset <= UINT64_MAX - region.address)
          prepared->decompile_addresses.emplace(
              region.address - prepared->decompile->layout.image_base +
                  source.offset,
              source.id);
    if (prepared->source && source.id < prepared->source->sites.size())
      site.scope_site = source.id;
    site.function = prepared->policy.sites[source.id].function;
    auto &owner = prepared->functions[site.function];
    auto &physical = prepared->functions[function->second];
    if (!physical.first ||
        source.offset < prepared->sites[physical.first].original.offset)
      physical.first = source.id;
    if (!site_index
             .emplace(std::make_pair(source.section, source.offset), source.id)
             .second) {
      error = "duplicate kernel instruction site";
      return false;
    }
    if (prepared->source && source.id < prepared->source->sites.size()) {
      const auto &metadata = prepared->source->sites[source.id];
      if (metadata.function &&
          metadata.function < prepared->source->functions.size()) {
        site.display_function =
            prepared->source->functions[metadata.function].name;
        site.dwarf_scope = true;
      }
      const auto line_id = prepared->source->sites[source.id].line;
      if (line_id) {
        const auto &line = prepared->source->lines[line_id];
        const auto &source_file = prepared->source->files[line.file];
        const auto &path = source_file.path;
        if (source_file.available && source_file.assembly)
          site.original_assembly = line.text;
        const auto [file, inserted] =
            source_files.emplace(path, prepared->files.size());
        if (inserted)
          prepared->files.push_back(path);
        site.file = file->second;
        site.line = line.line;
      }
    }
    if (prepared->values && source.id < prepared->values->sites.size() &&
        prepared->values->sites[source.id].function)
      site.dwarf_scope = true;
    if (prepared->terminal && prepared->source &&
        source.id < prepared->source->sites.size()) {
      const auto &metadata = prepared->source->sites[source.id];
      site.source_line = ct_kernel_source_row(*prepared->source, source.id,
                                              &site.source_owner);
      site.source_opening = site.source_line && metadata.function_opening;
    }

    size_t consumed = 0;
    while (consumed < source.original_size) {
      llvm::MCInst instruction;
      uint64_t length = 0;
      if (decoder->getInstruction(
              instruction, length,
              {image.bytes.data() + section.offset + source.offset + consumed,
               source.original_size - consumed},
              source.offset + consumed,
              llvm::nulls()) != llvm::MCDisassembler::Success ||
          !length || length > source.original_size - consumed) {
        error = "cannot prepare original kernel instruction";
        return false;
      }
      const auto &description = instructions->get(instruction.getOpcode());
      const bool prefix =
          instructions->getName(instruction.getOpcode()).ends_with("_PREFIX");
      consumed += length;
      if (prefix == (consumed == source.original_size)) {
        error = "kernel site contains an incomplete prefix or multiple "
                "instructions";
        return false;
      }
      std::string text;
      llvm::raw_string_ostream output(text);
      printer->printInst(&instruction, source.offset + consumed, "", *subtarget,
                         output);
      // Uppercase only generated register spelling, before inserting any
      // source/linkage symbol whose name might itself look like a register.
      for (size_t offset = 0; offset < text.size();) {
        if (!std::isalpha(static_cast<unsigned char>(text[offset]))) {
          ++offset;
          continue;
        }
        const size_t begin = offset;
        while (offset < text.size() &&
               std::isalnum(static_cast<unsigned char>(text[offset])))
          ++offset;
        std::string token = text.substr(begin, offset - begin);
        for (char &byte : token)
          byte = std::toupper(static_cast<unsigned char>(byte));
        if (register_names.count(token))
          text.replace(begin, token.size(), token);
      }
      uint64_t destination = 0;
      if (!prefix && instruction_analysis->evaluateBranch(
                         instruction, source.offset + consumed - length, length,
                         destination)) {
        uint32_t target_section = source.section;
        uint64_t target_offset = destination;
        bool target_known = destination < section.size;
        std::string name = section.name;
        int64_t displacement = int64_t(destination);
        const auto field = relocations.find(
            {source.section, source.offset + source.original_size - 4});
        if (source.original_size >= 4 && field != relocations.end() &&
            (field->second->type == R_X86_64_PC32 ||
             field->second->type == R_X86_64_PLT32)) {
          const auto symbol = symbols.find(
              {field->second->symbol_table, field->second->symbol});
          if (symbol == symbols.end() ||
              field->second->addend > INT64_MAX - 4) {
            error = "invalid kernel branch relocation identity";
            return false;
          }
          name = symbol->second->name;
          if (name == "__x86_return_thunk" &&
              symbol->second->section == SHN_UNDEF &&
              description.isUnconditionalBranch() && length >= 5 &&
              consumed == source.original_size &&
              image.bytes[section.offset + source.offset + consumed - 5] ==
                  0xe9 &&
              field->second->offset == source.offset + consumed - 4 &&
              field->second->addend == -4)
            site.ret = true;
          displacement = field->second->addend + 4;
          target_known = symbol->second->section != SHN_UNDEF &&
                         symbol->second->section < SHN_LORESERVE &&
                         symbol->second->section < image.sections.size();
          if (target_known) {
            const __int128 value =
                __int128(symbol->second->offset) + displacement;
            target_section = symbol->second->section;
            target_known =
                value >= 0 && value < image.sections[target_section].size;
            if (target_known)
              target_offset = uint64_t(value);
          }
          if (name.empty() && symbol->second->section < image.sections.size()) {
            name = image.sections[symbol->second->section].name;
            const __int128 value =
                __int128(displacement) + symbol->second->offset;
            if (value < INT64_MIN || value > INT64_MAX) {
              error = "kernel branch relocation offset overflows";
              return false;
            }
            displacement = int64_t(value);
          }
        }
        if (name.empty()) {
          error = "kernel branch relocation has no printable identity";
          return false;
        }
        std::string operand = name;
        if (displacement > 0)
          operand += llvm::formatv("+0x{0:x-}", uint64_t(displacement)).str();
        else if (displacement < 0)
          operand +=
              llvm::formatv("-0x{0:x-}", UINT64_C(0) - uint64_t(displacement))
                  .str();
        const size_t target_begin = text.find_last_of(" \t");
        if (target_begin == std::string::npos) {
          error = "kernel branch rendering has no target operand";
          return false;
        }
        text.replace(target_begin + 1, std::string::npos, operand);
        if (description.isCall() || description.isUnconditionalBranch()) {
          const auto callee =
              function_index.find({target_section, target_offset});
          site.call_name = target_known && callee != function_index.end()
                               ? prepared->functions[callee->second].name
                               : name;
        }
        if (target_known)
          protected_entries.emplace_back(target_section, target_offset,
                                         target_offset + 1);
        if (description.isBranch() && target_known)
          branch_destinations.emplace(
              source.id, std::make_pair(target_section, target_offset));
      }
      site.assembly += text;
      if (prefix)
        continue;
      owner.indirect |= (description.isBranch() || description.isCall()) &&
                        !instruction_analysis->evaluateBranch(
                            instruction, source.offset + consumed - length,
                            length, destination);
      if (instructions->getName(instruction.getOpcode()) == "PUSH64r" &&
          instruction.getNumOperands() == 1 &&
          instruction.getOperand(0).isReg()) {
        const llvm::StringRef reg =
            registers->getName(instruction.getOperand(0).getReg());
        site.stack_save = reg == "RBX" || reg == "RBP" || reg == "R12" ||
                          reg == "R13" || reg == "R14" || reg == "R15";
      }
      const auto mnemonic = instructions->getName(instruction.getOpcode());
      site.entry_padding =
          mnemonic.starts_with("NOOP") || mnemonic == "ENDBR64";
      site.call = description.isCall();
      site.ret |= description.isReturn();
      site.branch = description.isBranch();
      site.conditional = description.isConditionalBranch();
      site.memory = description.mayLoad() || description.mayStore();
      site.memory_read = description.mayLoad();
      site.memory_write = description.mayStore();
      // Only ordinary nonfaulting integer work may disappear between source
      // observations. Memory, control, system, vector and stack operations
      // retain their original instruction snapshots.
      auto integer_opcode = mnemonic;
      bool integer_work = false;
      for (const llvm::StringRef name :
           {"MOV", "LEA", "ADD", "SUB",  "ADC",  "SBB",  "AND", "OR",
            "XOR", "SHL", "SHR", "SAR",  "SAL",  "IMUL", "INC", "DEC",
            "NEG", "NOT", "CMP", "TEST", "CMOV", "SET"})
        if (integer_opcode.consume_front(name)) {
          integer_work = !integer_opcode.empty() &&
                         (std::isdigit(integer_opcode.front()) ||
                          name == "SET" || name == "CMOV");
          break;
        }
      site.coalescible = integer_work && !site.memory && !site.call &&
                         !site.branch && !site.ret &&
                         !description.hasUnmodeledSideEffects();
      if (prepared->captures &&
          (description.mayStore() || description.mayLoad())) {
        // Prove an explicit integer memory operand for aggregate display. Only
        // unconditional destinations also establish C assignment completion;
        // a load must never become a write witness.
        auto opcode = instructions->getName(instruction.getOpcode());
        const bool move = opcode.consume_front("MOV");
        bool binary = false, unary = false;
        if (!move)
          for (const llvm::StringRef name :
               {"ADD", "SUB", "AND", "OR", "XOR", "ADC", "SBB"})
            if (opcode.consume_front(name)) {
              binary = true;
              break;
            }
        if (!move && !binary)
          for (const llvm::StringRef name : {"INC", "DEC", "NEG", "NOT"})
            if (opcode.consume_front(name)) {
              unary = true;
              break;
            }
        unsigned width = 0;
        if (move || binary || unary)
          for (const unsigned bits : {8, 16, 32, 64})
            if (opcode.consume_front(std::to_string(bits))) {
              width = bits / 8;
              break;
            }
        const bool store = description.mayStore() && width &&
                           ((unary && opcode == "m") ||
                            (!unary && (opcode == "mr" || opcode == "mi" ||
                                        opcode == "mi8" || opcode == "mi32")));
        const bool load = description.mayLoad() && width && (move || binary) &&
                          opcode == "rm" && description.getNumDefs() == 1;
        const unsigned memory_index = load ? (binary ? 2 : 1) : 0;
        if ((store || load) &&
            instruction.getNumOperands() >= memory_index + 5 &&
            instruction.getOperand(memory_index).isReg() &&
            instruction.getOperand(memory_index + 1).isImm() &&
            instruction.getOperand(memory_index + 2).isReg() &&
            instruction.getOperand(memory_index + 2).getReg() &&
            instruction.getOperand(memory_index + 3).isImm() &&
            instruction.getOperand(memory_index + 4).isReg() &&
            !instruction.getOperand(memory_index + 4).getReg()) {
          const auto base = register_names.find(registers->getName(
              instruction.getOperand(memory_index).getReg()));
          const auto index = register_names.find(registers->getName(
              instruction.getOperand(memory_index + 2).getReg()));
          const auto scale = instruction.getOperand(memory_index + 1).getImm();
          const auto field =
              relocations.lower_bound({source.section, source.offset});
          if (base != register_names.end() && index != register_names.end() &&
              base->second.bits == 64 && index->second.bits == 64 &&
              base->second.slot < KCTRACE_REG_RFLAGS &&
              index->second.slot < KCTRACE_REG_RFLAGS &&
              (scale == 1 || scale == 2 || scale == 4 || scale == 8) &&
              (field == relocations.end() ||
               field->first.first != source.section ||
               field->first.second >= source.offset + source.original_size)) {
            // This address is display evidence only. It does not authorize a
            // memory read or imply a source-level array identity.
            site.indexed_memory = std::make_unique<Data::Site::IndexedMemory>(
                Data::Site::IndexedMemory{
                    base->second.slot, index->second.slot, unsigned(scale),
                    instruction.getOperand(memory_index + 3).getImm()});
          }
        }
        if ((store || load) &&
            instruction.getNumOperands() >= memory_index + 5 &&
            (!load || !binary ||
             (instruction.getOperand(0).isReg() &&
              instruction.getOperand(1).isReg() &&
              instruction.getOperand(0).getReg() ==
                  instruction.getOperand(1).getReg())) &&
            instruction.getOperand(memory_index).isReg() &&
            instruction.getOperand(memory_index + 1).isImm() &&
            instruction.getOperand(memory_index + 1).getImm() == 1 &&
            instruction.getOperand(memory_index + 2).isReg() &&
            !instruction.getOperand(memory_index + 2).getReg() &&
            instruction.getOperand(memory_index + 3).isImm() &&
            instruction.getOperand(memory_index + 4).isReg() &&
            !instruction.getOperand(memory_index + 4).getReg()) {
          const llvm::StringRef base =
              registers->getName(instruction.getOperand(memory_index).getReg());
          const auto base_register = register_names.find(base.str());
          if (base_register != register_names.end() &&
              base_register->second.bits == 64 &&
              base_register->second.slot != KCTRACE_REG_RIP &&
              !base_register->second.shift) {
            // A register address is compared only with already established
            // capture storage; it never authorizes a new read or dereference.
            // A relocated displacement is not a literal displacement.
            const auto field =
                relocations.lower_bound({source.section, source.offset});
            if (field == relocations.end() ||
                field->first.first != source.section ||
                field->first.second >= source.offset + source.original_size) {
              site.memory_operand.reg = base_register->second.slot;
              site.memory_operand.displacement =
                  instruction.getOperand(memory_index + 3).getImm();
              site.memory_operand.size = width;
            }
          } else if (base == "RIP") {
            llvm::MCInst symbolic = instruction;
            symbolic.getOperand(memory_index + 3) =
                llvm::MCOperand::createExpr(memory_symbol);
            llvm::SmallVector<char, 16> encoded;
            llvm::SmallVector<llvm::MCFixup, 1> fixups;
            encoder->encodeInstruction(symbolic, encoded, fixups, *subtarget);
            const size_t prefix_size = consumed - length;
            bool proven = encoded.size() == length && fixups.size() == 1 &&
                          fixups[0].getOffset() <= encoded.size() &&
                          encoded.size() - fixups[0].getOffset() >= 4;
            if (proven) {
              const auto field = fixups[0].getOffset();
              for (size_t byte = 0; byte < encoded.size(); ++byte)
                if ((byte < field || byte >= field + 4) &&
                    uint8_t(encoded[byte]) !=
                        image.bytes[section.offset + source.offset +
                                    prefix_size + byte])
                  proven = false;
              const auto relocation = relocations.find(
                  {source.section, source.offset + prefix_size + field});
              if (proven && relocation != relocations.end() &&
                  relocation->second->type == R_X86_64_PC32) {
                const auto &rel = *relocation->second;
                const auto symbol =
                    symbols.find({rel.symbol_table, rel.symbol});
                if (symbol != symbols.end() &&
                    symbol->second->section != SHN_UNDEF &&
                    symbol->second->section < SHN_LORESERVE &&
                    symbol->second->section < image.sections.size()) {
                  const auto &target = image.sections[symbol->second->section];
                  // RIP names the end of the instruction, including any
                  // trailing immediate; the relocation field's bias is not
                  // necessarily the CALL-specific four bytes.
                  const __int128 address = __int128(symbol->second->offset) +
                                           rel.addend + source.offset +
                                           source.original_size - rel.offset;
                  if ((target.flags & SHF_ALLOC) &&
                      !(target.flags & SHF_EXECINSTR) && address >= 0 &&
                      address + width <= target.size) {
                    site.memory_operand.section = symbol->second->section;
                    site.memory_operand.target = uint64_t(address);
                    site.memory_operand.size = width;
                  }
                }
              }
            }
          }
        }
        if (move && width && instruction.getNumOperands() == 6 &&
            (store || load)) {
          const auto &operand = instruction.getOperand(store ? 5 : 0);
          if (operand.isReg()) {
            const auto reg =
                register_names.find(registers->getName(operand.getReg()));
            if (reg != register_names.end() && reg->second.bits == width * 8 &&
                reg->second.slot < KCTRACE_REGISTER_COUNT) {
              site.memory_value_width = width;
              site.memory_value_register = reg->second.slot;
              site.memory_value_shift = reg->second.shift;
            }
          } else if (store && operand.isImm()) {
            const auto first =
                relocations.lower_bound({source.section, source.offset});
            unsigned count = 0;
            for (auto field = first;
                 field != relocations.end() &&
                 field->first.first == source.section &&
                 field->first.second < source.offset + source.original_size;
                 ++field)
              ++count;
            const bool literal =
                count == unsigned(site.memory_operand.section != UINT32_MAX);
            if (literal) {
              site.memory_value_width = width;
              site.memory_value_literal = true;
              site.memory_value_immediate = uint64_t(operand.getImm());
            }
          }
        }
        if (store)
          site.store = site.memory_operand;
        if (store && move &&
            site.memory_value_register < KCTRACE_REGISTER_COUNT &&
            instruction.getNumOperands() == 6 &&
            instruction.getOperand(3).isImm() &&
            instruction.getOperand(4).isReg() &&
            !instruction.getOperand(4).getReg()) {
          // Match the displacement relocation, including indexed array
          // stores. Never interpret the relocation placeholder as an address.
          llvm::MCInst symbolic = instruction;
          symbolic.getOperand(3) = llvm::MCOperand::createExpr(memory_symbol);
          llvm::SmallVector<char, 16> encoded;
          llvm::SmallVector<llvm::MCFixup, 1> fixups;
          encoder->encodeInstruction(symbolic, encoded, fixups, *subtarget);
          const size_t prefix_size = consumed - length;
          bool proven = encoded.size() == length && fixups.size() == 1 &&
                        fixups[0].getOffset() <= encoded.size() &&
                        encoded.size() - fixups[0].getOffset() >= 4;
          if (proven) {
            const auto field = fixups[0].getOffset();
            for (size_t byte = 0; byte < encoded.size(); ++byte)
              if ((byte < field || byte >= field + 4) &&
                  uint8_t(encoded[byte]) !=
                      image.bytes[section.offset + source.offset + prefix_size +
                                  byte])
                proven = false;
            const auto relocation = relocations.find(
                {source.section, source.offset + prefix_size + field});
            const bool relative =
                instruction.getOperand(0).isReg() &&
                llvm::StringRef(registers->getName(
                    instruction.getOperand(0).getReg())) == "RIP";
            if (proven && relocation != relocations.end() &&
                (relative ? relocation->second->type == R_X86_64_PC32
                          : relocation->second->type == R_X86_64_32S ||
                                relocation->second->type == R_X86_64_32)) {
              const auto &rel = *relocation->second;
              const auto symbol = symbols.find({rel.symbol_table, rel.symbol});
              if (symbol != symbols.end() &&
                  symbol->second->section != SHN_UNDEF &&
                  symbol->second->section < image.sections.size()) {
                const auto &target = image.sections[symbol->second->section];
                const __int128 address =
                    __int128(symbol->second->offset) + rel.addend +
                    (relative
                         ? source.offset + source.original_size - rel.offset
                         : 0);
                if ((target.flags & SHF_ALLOC) &&
                    !(target.flags & (SHF_EXECINSTR | SHF_TLS)) &&
                    address >= 0 && address <= UINT64_MAX) {
                  const auto object = objects.find(
                      {symbol->second->section, uint64_t(address)});
                  if (object != objects.end() && object->second &&
                      object->second->size >= width &&
                      !object->second->name.empty() &&
                      object_names.at(object->second->name) == 1)
                    site.store_object = object->second->name;
                }
              }
            }
          }
        }
        if (store && move && site.store.size &&
            instruction.getNumOperands() == 6) {
          auto relocation =
              relocations.lower_bound({source.section, source.offset});
          unsigned relocation_count = 0;
          for (;
               relocation != relocations.end() &&
               relocation->first.first == source.section &&
               relocation->first.second < source.offset + source.original_size;
               ++relocation)
            ++relocation_count;
          // Only the already-validated RIP displacement may be relocated.
          // In particular, a zero placeholder in an immediate is not a value.
          if (relocation_count == unsigned(site.store.section != UINT32_MAX)) {
            const auto &value = instruction.getOperand(5);
            if (value.isImm()) {
              site.store_literal = true;
              site.store_immediate = uint64_t(value.getImm());
            } else if (value.isReg()) {
              const auto reg =
                  register_names.find(registers->getName(value.getReg()));
              if (reg != register_names.end() &&
                  reg->second.bits == width * 8) {
                site.store_register = reg->second.slot;
                site.store_shift = reg->second.shift;
              }
            }
          }
        }
      }
      const auto opcode = instructions->getName(instruction.getOpcode());
      const auto add_register = [&](llvm::MCRegister value, bool read,
                                    bool write, bool explicit_operand) {
        if (!value)
          return;
        const auto known = register_names.find(registers->getName(value));
        if (known == register_names.end() ||
            known->second.slot >= KCTRACE_REGISTER_COUNT ||
            (write && (known->second.slot == KCTRACE_REG_RSP ||
                       known->second.slot == KCTRACE_REG_RBP ||
                       known->second.slot == KCTRACE_REG_RIP)))
          site.coalescible = false;
        if (known == register_names.end() ||
            (!explicit_operand &&
             known->second.slot >= KCTRACE_REGISTER_COUNT &&
             !known->second.xstate))
          return;
        if (known->second.xstate == 9)
          site.compiler_support = false;
        auto existing = std::find_if(
            site.registers.begin(), site.registers.end(),
            [&](const auto &reg) { return reg.name == known->first; });
        if (existing == site.registers.end()) {
          site.registers.push_back(known->second);
          existing = site.registers.end() - 1;
        }
        existing->read |= read;
        existing->write |= write;
        if (existing->xstate == 9 && !explicit_operand && write &&
            (opcode == "LDTILECFG" || opcode == "TILERELEASE"))
          existing->xstate =
              fault_transfers.count(
                  {{source.section, source.offset},
                   {source.section, source.offset + source.original_size}})
                  ? 12
                  : 11;
        site.writes_stack |= write && existing->slot == KCTRACE_REG_RSP;
      };
      for (unsigned index = 0; index < instruction.getNumOperands(); ++index)
        if (instruction.getOperand(index).isReg())
          add_register(instruction.getOperand(index).getReg(),
                       index >= description.getNumDefs(),
                       index < description.getNumDefs(), true);
      for (const auto reg : description.implicit_uses())
        add_register(reg, true, false, false);
      for (const auto reg : description.implicit_defs())
        add_register(reg, false, true, false);
      if (opcode == "LDTILECFG" || opcode == "STTILECFG" ||
          opcode == "TILERELEASE") {
        Data::Register config;
        config.name = "TILECFG";
        config.slot = KCTRACE_REGISTER_COUNT;
        config.bits = 512;
        config.xstate = 10;
        config.read = true;
        config.write = opcode != "STTILECFG";
        site.registers.push_back(std::move(config));
        site.coalescible = false;
        site.compiler_support = false;
        if (opcode == "TILERELEASE")
          site.memory = site.memory_read = site.memory_write = false;
      }
      const bool legacy_transfer =
          opcode.starts_with("FXSAVE") || opcode.starts_with("FXRSTOR");
      if (legacy_transfer || opcode.starts_with("XSAVE") ||
          opcode.starts_with("XRSTOR")) {
        uint32_t components = 0;
        if (prepared->values && prepared->captures &&
            source.id < prepared->values->sites.size()) {
          const auto plan = prepared->values->sites[source.id].capture_plan;
          if (plan < prepared->captures->size())
            for (const auto &slot : (*prepared->captures)[plan].slots)
              if (slot.capture.kind == KCTRACE_CAPTURE_XSTATE &&
                  slot.capture.reg < 32)
                components |= 1U << slot.capture.reg;
        }
        if (legacy_transfer)
          components &= 3;
        const bool restore =
            opcode.starts_with("XRSTOR") || opcode.starts_with("FXRSTOR");
        const unsigned raw = legacy_transfer ? 17 : 13;
        const auto state = [&](const char *name, unsigned kind,
                               unsigned component, unsigned bits,
                               unsigned offset = 0) {
          Data::Register reg;
          reg.name = name;
          reg.slot = KCTRACE_REGISTER_COUNT;
          reg.xstate = kind;
          reg.number = component;
          reg.bits = bits;
          reg.shift = offset;
          reg.read = true;
          reg.write = restore;
          site.registers.push_back(std::move(reg));
        };
        if (components & 1) {
          state("FPCW", raw, 0, 16);
          state("FPSW", raw, 0, 16, 2);
          state("FPTAG", raw, 0, 8, 4);
          state("FOP", raw, 0, 16, 6);
          state("FIP", raw, 0, 64, 8);
          state("FDP", raw, 0, 64, 16);
          for (unsigned reg = 0; reg < 8; ++reg)
            state(("ST" + std::to_string(reg)).c_str(),
                  legacy_transfer ? 18 : 16, reg, 80);
        }
        if (components & 2) {
          // Standard transfers also handle MXCSR when only AVX is selected.
          // XRSTOR may consume either layout, so retain the real value for
          // both; compacted C/S forms require the SSE request bit.
          const bool standard = !opcode.starts_with("XSAVEC") &&
                                !opcode.starts_with("XSAVES") &&
                                !opcode.starts_with("XRSTORS");
          state("MXCSR", legacy_transfer ? raw : standard ? 19 : 13, 1, 32, 24);
          for (unsigned reg = 0; reg < 16; ++reg)
            state(("XMM" + std::to_string(reg)).c_str(), raw, 1, 128,
                  160 + reg * 16);
        }
        // A transfer can request upper lanes without their lower component.
        // Display those exact slices instead of inventing a complete vector.
        for (unsigned component : {2U, 5U, 6U, 7U})
          if (components & (1U << component)) {
            const unsigned bits = component == 2   ? 128
                                  : component == 5 ? 64
                                  : component == 6 ? 256
                                                   : 512;
            for (unsigned reg = 0; reg < (component == 5 ? 8U : 16U); ++reg) {
              const auto name =
                  component == 5   ? "K" + std::to_string(reg)
                  : component == 7 ? "ZMM" + std::to_string(reg + 16)
                  : component == 2 ? "YMM" + std::to_string(reg) + "[255:128]"
                                   : "ZMM" + std::to_string(reg) + "[511:256]";
              state(name.c_str(), 13, component, bits, reg * (bits / 8));
            }
          }
        if (components & (1U << 9))
          state("PKRU", 13, 9, 32);
        if (components & (1U << 10))
          state("IA32_PASID", 13, 10, 64);
        if (components & (1U << 11)) {
          state("IA32_U_CET", 13, 11, 64);
          state("IA32_PL3_SSP", 13, 11, 64, 8);
        }
        if (components & (1U << 12)) {
          state("IA32_PL0_SSP", 13, 12, 64);
          state("IA32_PL1_SSP", 13, 12, 64, 8);
          state("IA32_PL2_SSP", 13, 12, 64, 16);
        }
        if (components & (1U << 13))
          state("IA32_PM_CTL1", 13, 13, 64);
        if (components & (1U << 16))
          state("IA32_HWP_REQUEST", 13, 16, 64);
        if (components & (1U << 17))
          state("TILECFG", 15, 17, 512);
        if (components & (1U << 18))
          for (unsigned tile = 0; tile < 8; ++tile)
            state(("TMM" + std::to_string(tile)).c_str(), 14, tile, 8192);
        site.coalescible = false;
        site.compiler_support = false;
      }
      const auto x87_destination =
          ct_kernel_x87_destination({opcode.data(), opcode.size()},
                                    instruction.getNumOperands() == 1 &&
                                        instruction.getOperand(0).isReg());
      if (x87_destination == ct_kernel_x87_write::top)
        add_register(x87_top, true, true, false);
      else if (x87_destination == ct_kernel_x87_write::operand) {
        add_register(x87_top, true, false, false);
        add_register(instruction.getOperand(0).getReg(), true, true, true);
      }
      // ET_REL bytes contain unresolved data operands. Preserve their exact
      // relocation identity instead of presenting zero displacement as the
      // final loaded address. Branch operands were symbolized above.
      if (!instruction_analysis->evaluateBranch(
              instruction, source.offset + consumed - length, length,
              destination)) {
        auto relocation =
            relocations.lower_bound({source.section, source.offset});
        for (; relocation != relocations.end() &&
               relocation->first.first == source.section &&
               relocation->first.second < source.offset + source.original_size;
             ++relocation) {
          const auto &field = *relocation->second;
          const auto symbol = symbols.find({field.symbol_table, field.symbol});
          if (symbol == symbols.end()) {
            error = "kernel data relocation has no symbol";
            return false;
          }
          std::string name = symbol->second->name;
          if (name.empty() && symbol->second->section < image.sections.size())
            name = image.sections[symbol->second->section].name;
          site.assembly_note +=
              llvm::formatv(
                  " /* relocation +0x{0:x-}: {1}, type={2}, addend={3} */",
                  field.offset - source.offset, name, field.type, field.addend)
                  .str();
        }
      }
    }
    const size_t begin = site.assembly.find_first_not_of(" \t");
    if (begin != std::string::npos)
      site.assembly.erase(0, begin);
  }
  for (auto &site : prepared->sites) {
    if (!site.original.id)
      continue;
    auto next =
        site_index.find({site.original.section,
                         site.original.offset + site.original.original_size});
    if (next != site_index.end())
      site.next = next->second;
    const auto destination = branch_destinations.find(site.original.id);
    if (destination != branch_destinations.end()) {
      const auto target = site_index.find(destination->second);
      if (target != site_index.end()) {
        site.branch_target = target->second;
      } else {
        // A function entry's ENDBR/padding precedes its first observed
        // instruction without application state effects.
        const auto function = function_index.find(destination->second);
        if (function != function_index.end())
          site.branch_target = prepared->functions[function->second].first;
      }
    }
  }
  // DWARF parameter locations can start after ENDBR/NOP entry padding. Those
  // exact instructions preserve all registers and the stack; only register
  // locations may borrow the authenticated entry snapshot at the later PC.
  for (auto &function : prepared->functions) {
    uint64_t site = function.first;
    while (site && prepared->sites[site].entry_padding &&
           prepared->sites[site].next &&
           prepared->sites[prepared->sites[site].next].function ==
               prepared->sites[site].function)
      site = prepared->sites[site].next;
    function.parameter_site = site;
  }
  if (prepared->values && prepared->source && prepared->terminal) {
    std::map<std::tuple<size_t, uint32_t, uint64_t>, std::vector<uint64_t>>
        writes;
    for (auto &site : prepared->sites) {
      if (!site.source_line || !site.next || site.call || site.branch ||
          site.ret || site.writes_stack)
        continue;
      const auto &expression =
          prepared->source->lines[site.source_line].presentation->expression;
      if ((expression.kind != CT_EXPRESSION_ASSIGNMENT &&
           expression.kind != CT_EXPRESSION_UPDATE) ||
          expression.function != site.source_owner ||
          expression.assignment.empty() ||
          site.next >= prepared->values->sites.size())
        continue;
      const bool stored_value =
          site.store.size &&
          (site.store_literal || site.store_register < KCTRACE_REGISTER_COUNT);
      if (stored_value) {
        const auto member = prepared->source_member(
            expression.assignment, site.source_owner, site.original.id);
        if (member && member->type.bytes == site.store.size) {
          site.stored_assignment =
              std::make_unique<Data::Site::StoredAssignment>(
                  Data::Site::StoredAssignment{member->type,
                                               expression.assignment,
                                               member->offset, true});
          writes[{site.function, site.source_line, member->variable}].push_back(
              site.original.id);
          continue;
        }
      }
      const auto *variable = prepared->named_variable(
          expression.assignment, site.source_owner, site.next);
      if (!variable)
        variable = prepared->named_variable(
            expression.assignment, site.source_owner, site.original.id);
      if (variable && variable->type) {
        const auto *location = prepared->binding(variable->id, site.next);
        const auto slot = prepared->location_register(location);
        const auto &type = prepared->values->types[variable->type];
        const auto size = type.scalar.bytes;
        const bool extended = type.scalar.kind == CT_VALUE_FLOAT && size == 16;
        if (type.guarded || type.scalar.kind == CT_VALUE_UNKNOWN || !size ||
            (size > 8 && !extended))
          continue;
        const auto dwarf_register =
            location && location->recipe
                ? ct_kernel_recipe_register(
                      prepared->values->recipes[location->recipe], size)
                : std::nullopt;
        for (const auto location_site : {site.original.id, site.next}) {
          unsigned capture_slot = 0;
          if (const auto *captured =
                  prepared->capture(variable->id, location_site, capture_slot);
              captured && site.store.size == size &&
              captured->capture.size == size && !captured->capture.reserved &&
              !captured->capture.reserved2) {
            const auto &descriptor = captured->capture;
            if (descriptor.kind == KCTRACE_CAPTURE_STACK &&
                (descriptor.reg == KCTRACE_REG_RSP ||
                 descriptor.reg == KCTRACE_REG_RBP) &&
                site.store.reg != KCTRACE_REGISTER_COUNT)
              site.memory_assignment =
                  descriptor.reg != site.store.reg ||
                  descriptor.offset == site.store.displacement;
            else if (descriptor.kind == KCTRACE_CAPTURE_OBJECT &&
                     captured->section == site.store.section &&
                     descriptor.offset >= 0 &&
                     uint64_t(descriptor.offset) <= descriptor.object_size &&
                     size <= descriptor.object_size - descriptor.offset)
              site.memory_assignment =
                  __int128(captured->object_offset) + descriptor.offset ==
                  site.store.target;
          }
          if (site.memory_assignment)
            break;
        }
        if (site.memory_assignment && stored_value)
          site.stored_assignment =
              std::make_unique<Data::Site::StoredAssignment>(
                  Data::Site::StoredAssignment{type.scalar,
                                               expression.assignment});
        if (site.memory_assignment ||
            std::any_of(site.registers.begin(), site.registers.end(),
                        [&](const auto &reg) {
                          if (!reg.write || reg.shift)
                            return false;
                          if (slot < KCTRACE_REGISTER_COUNT)
                            return reg.slot == slot && reg.bits >= 8 * size;
                          if (!dwarf_register ||
                              type.scalar.kind != CT_VALUE_FLOAT)
                            return false;
                          const auto number = *dwarf_register;
                          if (extended)
                            return number >= 33 && number <= 40 &&
                                   reg.xstate == 2 && reg.bits == 80 &&
                                   reg.number == number - 33;
                          return reg.xstate == 1 && reg.bits >= 8 * size &&
                                 ((number >= 17 && number <= 32 &&
                                   reg.number == number - 17) ||
                                  (number >= 67 && number <= 82 &&
                                   reg.number == number - 67 + 16));
                        }))
          writes[{site.function, site.source_line, variable->id}].push_back(
              site.original.id);
      }
    }
    for (const auto &[key, sites] : writes)
      if (sites.size() == 1)
        prepared->sites[sites.front()].source_assignment = std::get<2>(key);
  }
  if (prepared->source) {
    for (const auto &symbol : image.symbols)
      if (symbol.section < image.sections.size() &&
          symbol.section != SHN_UNDEF && symbol.section < SHN_LORESERVE &&
          (image.sections[symbol.section].flags & SHF_EXECINSTR) &&
          symbol.offset < image.sections[symbol.section].size)
        protected_entries.emplace_back(symbol.section, symbol.offset,
                                       symbol.offset + 1);
    for (const auto &relocation : image.relocations) {
      const auto found =
          symbols.find({relocation.symbol_table, relocation.symbol});
      if (found == symbols.end())
        continue;
      const auto &symbol = *found->second;
      if (symbol.section == SHN_UNDEF || symbol.section >= SHN_LORESERVE ||
          symbol.section >= image.sections.size() ||
          !(image.sections[symbol.section].flags & SHF_EXECINSTR))
        continue;
      const __int128 address = __int128(symbol.offset) + relocation.addend;
      // A PC-relative instruction field may be followed by an immediate. Cover
      // every possible next-PC bias within x86's 15-byte instruction limit,
      // rather than assuming that every relocation uses the CALL -4 bias.
      const bool instruction_relative =
          relocation.section < image.sections.size() &&
          (image.sections[relocation.section].flags & SHF_EXECINSTR) &&
          (relocation.type == R_X86_64_PC32 ||
           relocation.type == R_X86_64_PLT32 ||
           relocation.type == R_X86_64_PC64);
      const uint64_t extent = instruction_relative ? 16 : 1;
      const __int128 end = std::min(
          address + extent, __int128(image.sections[symbol.section].size));
      if (end > 0 && address < end)
        protected_entries.emplace_back(symbol.section,
                                       uint64_t(std::max(address, __int128(0))),
                                       uint64_t(end));
    }
    std::sort(protected_entries.begin(), protected_entries.end());
    size_t count = 0;
    for (const auto &entry : protected_entries) {
      if (count &&
          std::get<0>(protected_entries[count - 1]) == std::get<0>(entry) &&
          std::get<2>(protected_entries[count - 1]) >= std::get<1>(entry)) {
        std::get<2>(protected_entries[count - 1]) = std::max(
            std::get<2>(protected_entries[count - 1]), std::get<2>(entry));
      } else {
        protected_entries[count++] = entry;
      }
    }
    protected_entries.resize(count);
    for (auto current = site_index.begin(); current != site_index.end();
         ++current) {
      auto &site = prepared->sites[current->second];
      if (!site.scope_site || !site.stack_save ||
          prepared->functions[site.function].indirect ||
          !prepared->source->sites[site.scope_site].function_opening ||
          !prepared->source->sites[site.scope_site].blocks.empty() ||
          current == site_index.begin() || !site.next)
        continue;
      const auto &before = prepared->sites[std::prev(current)->second];
      const auto &after = prepared->sites[site.next];
      if (before.next != site.original.id || before.call || before.branch ||
          before.ret || before.function != site.function ||
          after.function != site.function || !before.scope_site ||
          !after.scope_site)
        continue;
      const auto &membership =
          prepared->source->sites[before.scope_site].blocks;
      if (membership.empty() ||
          membership != prepared->source->sites[after.scope_site].blocks)
        continue;
      auto entry = std::lower_bound(
          protected_entries.begin(), protected_entries.end(),
          std::make_tuple(site.original.section,
                          site.original.offset + site.original.original_size,
                          UINT64_C(0)));
      if (entry != protected_entries.begin() &&
          std::get<0>(*std::prev(entry)) == site.original.section &&
          std::get<2>(*std::prev(entry)) > site.original.offset)
        continue;
      // A compiler callee-save PUSH scheduled between two observations in the
      // same scope is not a C scope exit. This one-instruction CFG proof does
      // not join disjoint ranges across branches or arbitrary missing source.
      site.scope_site = before.scope_site;
      prepared->policy.sites[site.original.id].path =
          prepared->policy.sites[before.scope_site].path;
    }
  }
  const std::vector<uint64_t> empty;
  const std::vector<uint64_t> *previous_members = &empty;
  size_t previous_function = SIZE_MAX;
  bool previous_generated = false;
  for (const auto &[address, id] : site_index) {
    bool generated = false;
    const auto *members = prepared->block_membership(id, generated);
    if (!members)
      members = &empty;
    const auto function = prepared->sites[id].function;
    if (function != previous_function || *members != *previous_members ||
        (generated != previous_generated && !members->empty()))
      prepared->timing_sites.push_back(id);
    previous_function = function;
    previous_generated = generated;
    previous_members = members;
  }
  std::sort(prepared->timing_sites.begin(), prepared->timing_sites.end());
  auto &observations = prepared->observation_sites;
  observations.resize(prepared->sites.size());
  // Extended-state operands, displayed values and their result endpoints are
  // selected offline. Preserve those snapshots across source coalescing; no
  // special per-site flag or state is added to unrelated trace records.
  std::set<uint32_t> xstate_plans;
  if (prepared->captures)
    for (uint32_t plan = 1; plan < prepared->captures->size(); ++plan)
      if (std::any_of((*prepared->captures)[plan].slots.begin(),
                      (*prepared->captures)[plan].slots.end(),
                      [](const auto &slot) {
                        return slot.capture.kind == KCTRACE_CAPTURE_XSTATE;
                      }))
        xstate_plans.insert(plan);
  // Without terminal output, the copy emitter's Perfetto block/scope points
  // suffice. No source-row or intermediate value observation is requested.
  for (const auto &[address, id] : site_index)
    observations[id] = prepared->terminal;
  std::vector<uint8_t> reaches_call(observations.size());
  for (auto position = site_index.rbegin(); position != site_index.rend();
       ++position) {
    const auto id = position->second;
    const auto &site = prepared->sites[id];
    if (!prepared->terminal)
      break;
    if (!site.source_line)
      continue;
    if (site.call) {
      const auto &calls =
          prepared->source->lines[site.source_line].presentation->call_results;
      reaches_call[id] =
          std::count_if(calls.begin(), calls.end(), [&](const auto &call) {
            return call.function == site.source_owner &&
                   call.result.callee == site.call_name;
          }) == 1;
    } else if (site.coalescible && site.next) {
      const auto &after = prepared->sites[site.next];
      if (site.function == after.function &&
          site.source_line == after.source_line &&
          site.source_owner == after.source_owner &&
          prepared->policy.sites[id].path ==
              prepared->policy.sites[site.next].path)
        reaches_call[id] = reaches_call[site.next];
    }
  }
  for (auto position = site_index.begin(); position != site_index.end();
       ++position) {
    if (!prepared->terminal)
      break;
    const auto id = position->second;
    const auto &site = prepared->sites[id];
    if (!xstate_plans.empty() && prepared->values &&
        id < prepared->values->sites.size() &&
        xstate_plans.count(prepared->values->sites[id].capture_plan))
      continue;
    if (position == site_index.begin() || !site.next ||
        prepared->functions[site.function].indirect)
      continue;
    const auto &before = prepared->sites[std::prev(position)->second];
    const auto &after = prepared->sites[site.next];
    if (before.next != id || before.function != site.function ||
        after.function != site.function || before.call || before.branch ||
        before.ret || site.call || site.branch || site.ret ||
        prepared->policy.sites[before.original.id].path !=
            prepared->policy.sites[id].path ||
        prepared->policy.sites[site.next].path !=
            prepared->policy.sites[id].path)
      continue;
    const auto entry = std::lower_bound(
        protected_entries.begin(), protected_entries.end(),
        std::make_tuple(site.original.section,
                        site.original.offset + site.original.original_size,
                        UINT64_C(0)));
    if (entry != protected_entries.begin() &&
        std::get<0>(*std::prev(entry)) == site.original.section &&
        std::get<2>(*std::prev(entry)) > site.original.offset)
      continue;
    const bool compiler_support = site.compiler_support;
    if ((!site.coalescible && !compiler_support) || site.source_assignment ||
        site.stored_assignment)
      continue;
    if (compiler_support) {
      observations[id] = 0;
    } else if (site.source_line && before.source_line == site.source_line &&
               after.source_line == site.source_line &&
               before.source_owner == site.source_owner &&
               after.source_owner == site.source_owner) {
      const auto &presentation =
          *prepared->source->lines[site.source_line].presentation;
      // A pure straight-line suffix ending at the exact source CALL needs
      // only its argument snapshot. Unmatched/conditional source calls retain
      // complete instruction evidence for their assembly fallback.
      if ((presentation.expression.is_call ||
           !presentation.call_results.empty()) &&
          !reaches_call[id])
        continue;
      observations[id] = 0;
    } else if (prepared->decompile && id < prepared->decompile->sites.size() &&
               before.original.id < prepared->decompile->sites.size() &&
               site.next < prepared->decompile->sites.size()) {
      const auto &current = prepared->decompile->sites[id];
      const auto &previous = prepared->decompile->sites[before.original.id];
      const auto &next = prepared->decompile->sites[site.next];
      const bool displayed_value =
          current.statement &&
          std::any_of(
              current.variables.begin(), current.variables.end(),
              [&](const auto &reference) {
                if (!prepared->values || !reference.variable ||
                    reference.variable >= prepared->values->variables.size())
                  return true;
                const auto &statement =
                    prepared->decompile->statements[current.statement];
                const auto &variable =
                    prepared->values->variables[reference.variable];
                if (!ct_kernel_decompile_identifier(statement.text,
                                                    variable.name))
                  return false;
                if ((reference.access & CT_DECOMPILED_WRITE) ||
                    statement.sites.empty() || !variable.type)
                  return true;
                const auto first = statement.sites.front();
                const auto *initial =
                    prepared->binding(reference.variable, first);
                const auto *binding = prepared->binding(reference.variable, id);
                const auto &type = prepared->values->types[variable.type];
                if (type.guarded || !type.scalar.bytes ||
                    type.scalar.bytes > 8 ||
                    type.scalar.kind == CT_VALUE_UNKNOWN ||
                    std::none_of(
                        prepared->decompile->sites[first].variables.begin(),
                        prepared->decompile->sites[first].variables.end(),
                        [&](const auto &input) {
                          return input.variable == reference.variable;
                        }))
                  return true;
                // Function-wide references with no location cannot improve
                // the input already introduced at statement entry. Retain
                // the later real load where its location becomes available.
                if (!binding || (!binding->recipe && !binding->capture_group &&
                                 binding->capture_slot == UINT32_MAX))
                  return false;
                if (!initial || !initial->recipe ||
                    initial->recipe != binding->recipe)
                  return true;
                unsigned capture_slot = 0;
                const auto *captured =
                    prepared->capture(reference.variable, first, capture_slot);
                if (!captured || captured->capture.size != type.scalar.bytes)
                  return true;
                // The statement's first snapshot already supplies this fixed
                // scalar storage. A pure register instruction neither reads
                // nor changes it; keep the actual memory operation instead.
                if (captured->capture.kind == KCTRACE_CAPTURE_OBJECT)
                  return false;
                if (captured->capture.kind != KCTRACE_CAPTURE_STACK ||
                    prepared->values->sites[first].frame_recipe !=
                        prepared->values->sites[id].frame_recipe)
                  return true;
                return std::any_of(
                    statement.sites.begin(),
                    statement.sites.begin() + current.index,
                    [&](uint64_t predecessor) {
                      return !prepared->sites[predecessor].coalescible;
                    });
              });
      if (!site.source_line && !before.source_line && !after.source_line &&
          current.statement && !displayed_value &&
          previous.statement == current.statement &&
          next.statement == current.statement &&
          previous.index + 1 == current.index &&
          current.index + 1 == next.index)
        observations[id] = 0;
    }
  }
  // Exact instruction before/after pairs are still required for stores,
  // observed loads, assignment completion, branch outcomes and fallback
  // assembly. A statement boundary alone cannot replace those witnesses.
  if (prepared->terminal)
    for (const auto &[address, id] : site_index) {
      const auto &site = prepared->sites[id];
      const bool compiler_support = site.compiler_support;
      if ((!site.coalescible && !compiler_support) || site.source_assignment ||
          site.stored_assignment || site.call || site.branch || site.ret) {
        observations[id] = 1;
        if (site.next)
          observations[site.next] = 1;
      }
    }
  if (prepared->terminal) {
    for (uint64_t id : prepared->timing_sites)
      observations[id] = 1;
    for (const auto &site : prepared->sites) {
      if (site.branch_target)
        observations[site.branch_target] = 1;
      if ((site.call || site.branch || site.ret) && site.next)
        observations[site.next] = 1;
    }
  }
  // Keep immediate instruction adjacency separate from statement continuity.
  // Only this prepared straight-line chain may connect two sparse snapshots;
  // it never supplies an intermediate instruction's after-register values.
  for (auto position = site_index.rbegin(); position != site_index.rend();
       ++position) {
    auto &site = prepared->sites[position->second];
    site.observation_next = site.next;
    if (site.next && !observations[site.next])
      site.observation_next = prepared->sites[site.next].writes_stack
                                  ? 0
                                  : prepared->sites[site.next].observation_next;
  }
  prepared->prepared = true;
  data = std::move(prepared);
  return true;
}

bool ct_kernel_trace::consume_event(
    const ct_kernel_observation &event,
    std::vector<ct_kernel_trace_record> &records,
    std::vector<ct_kernel_trace_transition> *transitions, std::string &error) {
  error.clear();
  const bool execution = event.flags & KCTRACE_EVENT_HAVE_EXECUTION;
  const kctrace_execution_record no_execution{};
  const auto &observed = event.execution;
  if (!data->prepared || event.size != sizeof(kctrace_event) ||
      event.context > KCTRACE_CONTEXT_HARDIRQ ||
      event.level > KCTRACE_LEVEL_FULL ||
      (!execution && event.level != KCTRACE_LEVEL_FULL) ||
      event.valid_registers >> KCTRACE_REGISTER_COUNT ||
      ((event.flags & KCTRACE_EVENT_HAVE_MEMORY) &&
       (event.memory_size > KCTRACE_MEMORY_SIZE ||
        (event.flags & KCTRACE_EVENT_HAVE_VALUES))) ||
      ((event.flags & KCTRACE_EVENT_HAVE_VALUES) &&
       (!event.capture_plan || event.capture_plan > UINT32_MAX ||
        event.capture_valid >> KCTRACE_VALUE_SLOTS)) ||
      (event.reserved2 && !(event.flags & KCTRACE_EVENT_HAVE_VALUES)) ||
      (event.reserved2 > 1 &&
       (!event.extra_values ||
        event.extra_values->size() + 1 != event.reserved2)) ||
      !event.sequence || !event.session_id || !event.generation ||
      event.softirq_depth > 1 ||
      event.hardirq_depth > (KCTRACE_INHERIT_SOURCE_MAX - 2) / 2 ||
      (event.context == KCTRACE_CONTEXT_TASK &&
       (event.hardirq_depth || event.softirq_depth)) ||
      (event.context == KCTRACE_CONTEXT_SOFTIRQ &&
       (event.hardirq_depth || !event.softirq_depth)) ||
      (event.context == KCTRACE_CONTEXT_HARDIRQ && !event.hardirq_depth)) {
    error = "invalid or unsupported kernel trace event context";
    return false;
  }
  if ((!execution && (std::memcmp(&observed, &no_execution, sizeof(observed)) ||
                      event.type == KCTRACE_EVENT_EXECUTION ||
                      event.type == KCTRACE_EVENT_BLOCK_POINT)) ||
      (execution &&
       (observed.reserved || observed.state > 31 ||
        observed.previous_level > KCTRACE_LEVEL_FULL ||
        observed.failure > KCTRACE_FAILURE_INHERITED_UNKNOWN ||
        (observed.flags &
         ~(KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY |
           KCTRACE_EXEC_CALLBACK | KCTRACE_EXEC_LEVEL_CHANGED |
           KCTRACE_EXEC_ENTRY_VALUES | KCTRACE_EXEC_RETURN_VALUE |
           KCTRACE_EXEC_RECOVERED | KCTRACE_EXEC_INSTRUCTION |
           KCTRACE_EXEC_HANDLER_CRITERION)) ||
        (observed.failure && !(observed.flags & KCTRACE_EXEC_UNKNOWN)) ||
        (event.type == KCTRACE_EVENT_EXECUTION
             ? observed.kind > KCTRACE_BOUNDARY_CALL_UNPAIRED
             : ((event.type != KCTRACE_EVENT_INSTRUCTION_BEFORE &&
                 event.type != KCTRACE_EVENT_BLOCK_POINT) ||
                observed.kind != KCTRACE_BOUNDARY_POINT)) ||
        (event.type == KCTRACE_EVENT_INSTRUCTION_BEFORE &&
         event.level != KCTRACE_LEVEL_FULL) ||
        (event.type == KCTRACE_EVENT_BLOCK_POINT &&
         event.level != KCTRACE_LEVEL_PERFETTO)))) {
    error = "invalid kernel execution record";
    return false;
  }
  if (execution && (observed.flags & KCTRACE_EXEC_HANDLER_CRITERION) &&
      (!data->within_intr || event.type != KCTRACE_EVENT_EXECUTION ||
       observed.kind != KCTRACE_BOUNDARY_ENTER ||
       (observed.flags & (KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY |
                          KCTRACE_EXEC_RECOVERED | KCTRACE_EXEC_RETURN_VALUE |
                          KCTRACE_EXEC_INSTRUCTION)))) {
    error = "invalid kernel interrupt-handler criterion";
    return false;
  }
  if (execution) {
    const uint32_t inheritance = observed.inheritance;
    const bool root_irq = event.context != KCTRACE_CONTEXT_TASK &&
                          observed.kind == KCTRACE_BOUNDARY_ENTER &&
                          !observed.parent_frame_id;
    const auto source = (inheritance & KCTRACE_INHERIT_SOURCE_MASK) >>
                        KCTRACE_INHERIT_SOURCE_SHIFT;
    const bool active = inheritance & KCTRACE_INHERIT_WITHIN;
    const bool unknown = inheritance & KCTRACE_INHERIT_UNKNOWN;
    bool valid_source = source == KCTRACE_INHERIT_SOURCE_NONE ||
                        source == KCTRACE_INHERIT_SOURCE_TASK;
    if (source == KCTRACE_INHERIT_SOURCE_SOFTIRQ)
      valid_source =
          event.context == KCTRACE_CONTEXT_HARDIRQ && event.softirq_depth;
    else if (source >= KCTRACE_INHERIT_SOURCE_HARDIRQ) {
      const auto lane = source - KCTRACE_INHERIT_SOURCE_HARDIRQ;
      valid_source = event.context == KCTRACE_CONTEXT_HARDIRQ &&
                     lane / 2 + 1 < event.hardirq_depth &&
                     (lane & 1) == event.softirq_depth;
    }
    if ((inheritance &&
         (!root_irq || !(inheritance & KCTRACE_INHERIT_VALID) ||
          (inheritance &
           ~(KCTRACE_INHERIT_VALID | KCTRACE_INHERIT_WITHIN |
             KCTRACE_INHERIT_UNKNOWN | KCTRACE_INHERIT_SOURCE_MASK)) ||
          !valid_source || source > KCTRACE_INHERIT_SOURCE_MAX ||
          (active && unknown) ||
          ((active || unknown) != (source != KCTRACE_INHERIT_SOURCE_NONE)) ||
          (unknown &&
           ((observed.flags &
             (KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY)) !=
                (KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY) ||
            !observed.failure)) ||
          (!data->within_filter && inheritance != KCTRACE_INHERIT_VALID))) ||
        (root_irq && !(observed.flags & KCTRACE_EXEC_UNKNOWN) &&
         !inheritance)) {
      error = "invalid kernel within inheritance evidence";
      return false;
    }
  }
  if (!data->session) {
    data->session = event.session_id;
    data->generation = event.generation;
  } else if (data->session != event.session_id ||
             data->generation != event.generation) {
    error = "kernel trace event belongs to another load";
    return false;
  }
  if (event.dropped_total > data->dropped) {
    finish_events(records, transitions, event.monotonic_ns, "lost");
    data->tasks.clear();
    data->irq_contexts.clear();
    data->dropped = event.dropped_total;
    ct_kernel_trace_record gap;
    gap.monotonic_ns = event.monotonic_ns;
    gap.stage = ct_kernel_trace_stage::discontinuity;
    gap.text =
        "kernel events lost; pending completion and call stacks discarded";
    records.push_back(std::move(gap));
  }
  const bool irq_lane = execution && event.context != KCTRACE_CONTEXT_TASK;
  const Data::TaskKey key{
      irq_lane ? 0 : event.tgid,
      irq_lane ? 0 : event.tid,
      irq_lane ? 0 : event.task_start_ns,
      event.context,
      event.context == KCTRACE_CONTEXT_TASK && event.tid ? 0 : event.cpu,
      event.hardirq_depth,
      event.softirq_depth,
      irq_lane};
  if (event.type != KCTRACE_EVENT_INSTRUCTION_BEFORE && !execution) {
    if (event.type == KCTRACE_EVENT_INIT_COMPLETE ||
        event.type == KCTRACE_EVENT_INIT_FAILED ||
        event.type == KCTRACE_EVENT_EXIT_COMPLETE ||
        event.type == KCTRACE_EVENT_LOAD_ABORTED) {
      const auto task = data->tasks.find(key);
      if (task != data->tasks.end()) {
        auto &state = task->second;
        const bool stale = event.sequence <= state.sequence ||
                           event.monotonic_ns < state.timestamp;
        data->close_task(state, event.monotonic_ns,
                         stale ? "out-of-order"
                         : event.type == KCTRACE_EVENT_LOAD_ABORTED
                             ? "load-aborted"
                             : "returned",
                         records, transitions);
        if (stale) {
          ct_kernel_trace_record gap;
          gap.monotonic_ns = event.monotonic_ns;
          gap.stage = ct_kernel_trace_stage::discontinuity;
          gap.text = "kernel lifecycle event arrived out of order; uncertain "
                     "call stack closed";
          records.push_back(std::move(gap));
        } else {
          state.sequence = event.sequence;
          state.timestamp = event.monotonic_ns;
        }
      }
    }
    return true;
  }
  if (!event.site_id || event.site_id >= data->sites.size() ||
      !data->sites[event.site_id].original.id ||
      !(event.valid_registers & (UINT64_C(1) << KCTRACE_REG_RSP)) ||
      ((event.valid_registers & (UINT64_C(1) << KCTRACE_REG_RIP)) &&
       event.pc != event.registers[KCTRACE_REG_RIP])) {
    error =
        "kernel instruction event has an unknown site or missing stack pointer";
    return false;
  }
  if (execution &&
      (!observed.function ||
       observed.function >= data->policy.functions.size() ||
       observed.path >= data->policy.paths.size() ||
       data->policy.sites[event.site_id].function != observed.function ||
       data->policy.sites[event.site_id].path != observed.path)) {
    error = "kernel execution record differs from prepared site policy";
    return false;
  }
  if (execution && (observed.flags & KCTRACE_EXEC_INSTRUCTION)) {
    const auto &site = data->sites[event.site_id];
    const auto unknown =
        observed.flags & (KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY);
    if (event.type != KCTRACE_EVENT_EXECUTION ||
        (observed.kind != KCTRACE_BOUNDARY_SCOPE &&
         observed.kind != KCTRACE_BOUNDARY_TAIL) ||
        event.level != KCTRACE_LEVEL_FULL || !site.branch || site.call ||
        site.ret ||
        (observed.flags &
         (KCTRACE_EXEC_LEVEL_CHANGED | KCTRACE_EXEC_ENTRY_VALUES |
          KCTRACE_EXEC_RETURN_VALUE | KCTRACE_EXEC_CALLBACK)) ||
        (unknown &&
         (unknown != (KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY) ||
          !observed.failure)) ||
        ((observed.flags & KCTRACE_EXEC_RECOVERED) &&
         (!unknown || observed.kind != KCTRACE_BOUNDARY_TAIL)) ||
        ((site.conditional || site.memory) &&
         (observed.kind != KCTRACE_BOUNDARY_SCOPE || !unknown))) {
      error = "invalid kernel control guard observation";
      return false;
    }
  }
  auto &task = data->tasks[key];
  if (event.sequence <= task.sequence || event.monotonic_ns < task.timestamp) {
    data->close_task(task, task.timestamp, "out-of-order", records,
                     transitions);
    ct_kernel_trace_record gap;
    gap.monotonic_ns = event.monotonic_ns;
    gap.stage = ct_kernel_trace_stage::discontinuity;
    gap.values.clear();
    gap.text = "kernel event arrived out of order; uncertain call stack closed";
    records.push_back(std::move(gap));
    return true;
  }
  // A lower observed interrupt depth proves that the deeper context is no
  // longer running on this CPU. Its last return may have left the target, so
  // retain an explicit unobserved-return status instead of extending a function
  // slice across unrelated kernel work or idle time.
  for (auto context = data->irq_contexts.lower_bound({event.cpu, 0, 0});
       context != data->irq_contexts.end() &&
       std::get<0>(context->first) == event.cpu;) {
    const bool resumed = std::get<1>(context->first) > event.hardirq_depth ||
                         std::get<2>(context->first) > event.softirq_depth;
    const bool replaced = std::get<1>(context->first) == event.hardirq_depth &&
                          std::get<2>(context->first) == event.softirq_depth &&
                          context->second != key;
    auto &previous = data->tasks.at(context->second);
    if ((resumed || replaced) && previous.timestamp <= event.monotonic_ns) {
      data->close_task(previous, event.monotonic_ns, "context-ended", records,
                       transitions);
      context = data->irq_contexts.erase(context);
    } else {
      ++context;
    }
  }
  if (event.context != KCTRACE_CONTEXT_TASK)
    data->irq_contexts[{event.cpu, event.hardirq_depth, event.softirq_depth}] =
        key;
  task.sequence = event.sequence;
  task.timestamp = event.monotonic_ns;
  if (execution)
    return data->consume_execution(task, event, records, transitions, error);
  if (task.execution) {
    data->execution_gap(task, event, "missing execution identity", records,
                        transitions);
    return true;
  }
  const auto &site = data->sites[event.site_id];
  if (event.pc >= site.original.operation)
    data->section_bases[site.original.section] =
        event.pc - site.original.operation;
  const auto &function = data->functions[site.function];
  const uint64_t stack = event.registers[KCTRACE_REG_RSP];
  bool completed = false, nested_call = false, internal_branch = false;
  bool tail_call = false;
  uint64_t return_site = 0;
  if (task.pending.site_id) {
    const auto &previous = data->sites[task.pending.site_id];
    completed = previous.next == event.site_id && !previous.call &&
                !previous.ret && !previous.branch && !previous.writes_stack &&
                task.pending.registers[KCTRACE_REG_RSP] == stack;
    nested_call = previous.call && event.site_id == function.first &&
                  task.pending.registers[KCTRACE_REG_RSP] >= 8 &&
                  task.pending.registers[KCTRACE_REG_RSP] - 8 == stack;
    internal_branch =
        previous.branch && !previous.ret &&
        previous.function == site.function &&
        (previous.branch_target == event.site_id ||
         (previous.conditional && previous.next == event.site_id)) &&
        task.pending.registers[KCTRACE_REG_RSP] == stack;
    tail_call = previous.branch && !previous.ret &&
                previous.branch_target == event.site_id &&
                previous.function != site.function &&
                event.site_id == function.first && !task.frames.empty() &&
                task.frames.back().stack == stack;
    if (nested_call)
      return_site = previous.next;
    if (!task.frames.empty() && task.frames.back().row.line) {
      auto &frame = task.frames.back();
      data->source_assembly(frame, task.pending,
                            completed || internal_branch ? &event : nullptr,
                            records);
      if (completed)
        data->complete_assignment(frame, previous, task.pending, event);
      if (internal_branch)
        data->source_condition(frame, task.pending, event);
      if (previous.call && previous.next == event.site_id &&
          task.pending.registers[KCTRACE_REG_RSP] == stack) {
        if (const auto *call = data->source_call(frame, previous.call_name))
          data->source_returned(frame, *call, event, false);
      }
      if (nested_call) {
        if (data->source_call(frame, function.name)) {
          frame.row.call_seen = true;
          data->release_fallback(frame.row.fallback);
        }
        const auto selected = kctrace_policy_enter(
            Data::selection(frame), function.mode, function.within);
        if (selected.within && selected.mode == Data::into &&
            !frame.row.printed) {
          const auto *call = data->source_call(frame, function.name);
          if (call && std::find(frame.row.entered_calls.begin(),
                                frame.row.entered_calls.end(),
                                call) == frame.row.entered_calls.end())
            frame.row.entered_calls.push_back(call);
          data->flush_source(frame, records, true);
        }
      }
    }
    if (!task.frames.empty() && task.frames.back().decompiled.statement) {
      auto &frame = task.frames.back();
      const bool external_return =
          previous.call && previous.next == event.site_id &&
          task.pending.registers[KCTRACE_REG_RSP] == stack;
      data->decompile_completed(
          frame, task.pending,
          completed || internal_branch || external_return ? &event : nullptr,
          records);
      if (nested_call && frame.decompiled.statement &&
          !frame.decompiled.printed) {
        const auto selected = kctrace_policy_enter(
            Data::selection(frame), function.mode, function.within);
        if (selected.within && selected.mode == Data::into)
          data->flush_decompile(frame, records, nullptr, true);
      }
    }
    if (task.selected)
      data->emit(
          data->render(task.pending,
                       completed || internal_branch ? &event : nullptr,
                       task.frames.empty() ? nullptr : &task.frames.back()),
          records, task.frames.empty() ? nullptr : &task.frames.back());
    task.selected = false;
  }
  if (!task.frames.empty() && task.frames.back().return_site == event.site_id &&
      task.frames.back().stack <= UINT64_MAX - 8 &&
      stack == task.frames.back().stack + 8) {
    data->close_frame(task, event.monotonic_ns, "returned", &event, records,
                      transitions);
  } else if (tail_call) {
    return_site = task.frames.back().return_site;
    data->close_frame(task, event.monotonic_ns, "tail-call", nullptr, records,
                      transitions);
  }
  if (!task.frames.empty() && !nested_call && !tail_call &&
      (task.frames.back().function != site.function ||
       (event.site_id == function.first && !internal_branch))) {
    // The pending row was already emitted above, but still identifies whether
    // the previous function ended with an unobserved return to kernel code.
    data->close_task(task, event.monotonic_ns, "unobserved-boundary", records,
                     transitions);
  }
  if (task.frames.empty() || nested_call || tail_call) {
    Data::Frame frame{};
    if (!task.frames.empty())
      static_cast<Data::Selection &>(frame) =
          Data::selection(task.frames.back());
    if (!task.frames.empty())
      frame.call_source = data->source_call(task.frames.back(), function.name);
    if (nested_call && !task.frames.empty())
      frame.call_decompile = data->decompile_call(task.frames.back());
    frame.function = site.function;
    frame.source_function = function.name;
    if (data->source && event.site_id < data->source->sites.size()) {
      const auto index = data->source->sites[event.site_id].function;
      if (index)
        frame.source_function = data->source->functions[index].name;
    }
    frame.entry = event;
    frame.stack = stack;
    frame.return_site = return_site;
    static_cast<Data::Selection &>(frame) =
        kctrace_policy_enter(frame, function.mode, function.within);
    if (frame.within && frame.mode != Data::skip) {
      frame.scope.token = data->next_token++;
      frame.scope.begin = event.monotonic_ns;
      frame.scope.pc = event.pc;
      for (auto parent = task.frames.rbegin(); parent != task.frames.rend();
           ++parent)
        if (const auto token = Data::parent_token(*parent)) {
          frame.scope.parent = token;
          break;
        }
      data->transition(frame, frame.scope, ct_kernel_trace_phase::begin,
                       event.monotonic_ns, "", transitions);
    }
    task.frames.push_back(std::move(frame));
  }
  if (!data->update_blocks(task.frames.back(), event, records, transitions,
                           error))
    return false;
  const auto &selection = Data::selection(task.frames.back());
  task.selected =
      data->terminal && selection.within && selection.mode == Data::into;
  if (task.selected) {
    const bool repeated = internal_branch && task.pending.site_id &&
                          site.original.offset <=
                              data->sites[task.pending.site_id].original.offset;
    if (data->source_observation(task.frames.back(), event, records, repeated,
                                 completed))
      task.selected = false;
    else if (data->decompile_observation(task.frames.back(), event, records))
      task.selected = false;
  } else if (data->terminal) {
    data->flush_deferred(task.frames.back(), records);
    data->flush_source(task.frames.back(), records);
    data->flush_decompile(task.frames.back(), records);
  }
  task.pending = event;
  return true;
}

bool ct_kernel_trace::consume(const ct_kernel_observation &event,
                              std::vector<ct_kernel_trace_record> &records,
                              std::string &error) {
  return consume_event(event, records, nullptr, error);
}

bool ct_kernel_trace::consume(
    const ct_kernel_observation &event,
    std::vector<ct_kernel_trace_record> &records,
    std::vector<ct_kernel_trace_transition> &transitions, std::string &error) {
  return consume_event(event, records, &transitions, error);
}

void ct_kernel_trace::finish_events(
    std::vector<ct_kernel_trace_record> &records,
    std::vector<ct_kernel_trace_transition> *transitions, uint64_t timestamp,
    const char *status) {
  for (auto &[key, task] : data->tasks)
    data->close_task(task, timestamp, status, records, transitions);
  data->irq_contexts.clear();
}

void ct_kernel_trace::finish(std::vector<ct_kernel_trace_record> &records) {
  finish_events(records, nullptr, 0, "incomplete");
}

void ct_kernel_trace::finish(
    std::vector<ct_kernel_trace_record> &records,
    std::vector<ct_kernel_trace_transition> &transitions, uint64_t timestamp,
    const char *status) {
  finish_events(records, &transitions, timestamp, status);
}
