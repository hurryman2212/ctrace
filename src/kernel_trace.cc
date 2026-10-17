#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <tuple>
#include <utility>

#include <llvm/BinaryFormat/Dwarf.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
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
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/MemoryBufferRef.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>

#include <elf.h>

#include "kctrace_policy.h"
#include "kernel_trace.h"

static constexpr size_t kernel_trace_site_limit = 1000000;
static constexpr size_t kernel_trace_task_limit = 65536;
static constexpr size_t kernel_trace_frame_limit = 4096;
static constexpr size_t kernel_trace_total_frame_limit = 65536;
static constexpr size_t kernel_trace_fallback_limit = 4096;
static constexpr size_t kernel_trace_row_limit = 256;

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
    bool read = false, write = false;
  };
  struct Function {
    uint32_t section = 0;
    uint64_t begin = 0, end = 0, first = 0;
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
    ct_kernel_site original;
    size_t function = 0;
    uint64_t next = 0, branch_target = 0, scope_site = 0;
    std::string assembly, source_owner, call_name;
    uint32_t source_line = 0;
    uint64_t source_assignment = 0;
    bool memory_assignment = false;
    bool source_opening = false;
    unsigned line = 0, file = 0;
    std::vector<Register> registers;
    bool call = false, ret = false, branch = false, conditional = false;
    bool memory = false, writes_stack = false, stack_save = false;
  };
  struct SourceValue {
    uint64_t variable = 0;
    std::string name, type, before = "?";
    bool declared = false, global = false;
  };
  struct SourceRow {
    uint32_t line = 0;
    std::string owner;
    kctrace_event before{}, after{};
    std::vector<SourceValue> inputs;
    struct CallResult {
      const ct_source_call_result_info *call = nullptr;
      std::string value;
    };
    std::vector<CallResult> results;
    uint64_t assigned = 0, buffered_sequence = 0;
    std::vector<ct_kernel_trace_record> fallback;
    bool call_bearing = false, call_seen = false, assembly = false;
    bool printed = false, call_reported = false, call_completed = false;
    bool assignment_returned = false;
  };
  struct DecompileRow {
    uint32_t statement = 0;
    size_t next = 0;
    kctrace_event before{}, last{};
    std::vector<SourceValue> inputs;
    std::vector<uint64_t> writes;
    std::vector<ct_kernel_trace_record> fallback;
    bool printed = false;
  };
  struct Frame : Selection {
    struct Scope : Selection {
      uint64_t token = 0, parent = 0, begin = 0, block = 0, pc = 0;
      bool decompiled = false;
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
    kctrace_event entry{};
    Scope scope{};
    std::vector<Scope> blocks;
    SourceRow row;
    DecompileRow decompiled;
    std::unique_ptr<SourceRow> deferred_assignment;
    std::string source_function;
    std::string call_decompile;
    std::set<std::string> introduced;
    const ct_source_call_result_info *call_source = nullptr;
    bool source_entry = false;
    bool decompile_entry = false;
  };
  struct Task {
    std::vector<Frame> frames;
    kctrace_event pending{};
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
  std::vector<std::string> files{std::string()};
  std::map<TaskKey, Task> tasks;
  std::map<std::tuple<uint32_t, uint16_t, uint16_t>, TaskKey> irq_contexts;
  std::shared_ptr<const ct_kernel_source_metadata> source;
  std::shared_ptr<const ct_kernel_decompile_metadata> decompile;
  std::shared_ptr<const ct_kernel_value_metadata> values;
  std::shared_ptr<const std::vector<ct_kernel_capture_plan>> captures;
  std::vector<std::pair<Mode, bool>> block_filters;
  std::set<std::string> introduced;
  std::set<uint64_t> introduced_globals;
  std::set<std::string> introduced_functions;
  std::map<uint32_t, uint64_t> section_bases;
  std::map<uint64_t, uint64_t> decompile_addresses;
  uint64_t session = 0, generation = 0, dropped = 0;
  size_t frame_count = 0, block_count = 0, fallback_count = 0;
  uint64_t next_token = 1;
  bool prepared = false, terminal = true, within_filter = false;
  bool within_intr = false;

  ct_kernel_trace_record base_record(const kctrace_event &before) const {
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
    record.function = function.name;
    record.file = files[site.file];
    return record;
  }

  bool aggregate_operand(const Site &site, const kctrace_event &event,
                         const ct_kernel_value_binding &binding) const {
    if (!captures || !values || !binding.variable ||
        binding.variable >= values->variables.size() ||
        !binding.capture_group ||
        binding.capture_group >= values->capture_groups.size() ||
        event.site_id >= values->sites.size() || !site.memory_operand.size)
      return false;
    const auto type = values->variables[binding.variable].type;
    if (!type || type >= values->types.size())
      return false;
    const auto layout = values->types[type].layout_type;
    if (!layout || layout > values->layout_types.size())
      return false;
    const auto kind = values->layout_types[layout - 1].kind;
    if (kind != CT_LAYOUT_STRUCT && kind != CT_LAYOUT_ARRAY)
      return false;
    const auto plan = values->sites[event.site_id].capture_plan;
    if (!plan || plan >= captures->size())
      return false;
    const auto &operand = site.memory_operand;
    for (const auto &part : values->capture_groups[binding.capture_group]) {
      if (part.slot >= KCTRACE_VALUE_SLOTS)
        continue;
      const auto &slot = (*captures)[plan].slots[part.slot];
      const auto &capture = slot.capture;
      __int128 observed = -1, accessed = -1;
      if (capture.kind == KCTRACE_CAPTURE_STACK &&
          capture.reg < KCTRACE_REGISTER_COUNT &&
          operand.reg < KCTRACE_REGISTER_COUNT &&
          (event.valid_registers & (UINT64_C(1) << capture.reg)) &&
          (event.valid_registers & (UINT64_C(1) << operand.reg))) {
        observed = __int128(event.registers[capture.reg]) + capture.offset;
        accessed =
            __int128(event.registers[operand.reg]) + operand.displacement;
      } else if (capture.kind == KCTRACE_CAPTURE_OBJECT &&
                 operand.section != UINT32_MAX &&
                 slot.section == operand.section) {
        observed = __int128(slot.object_offset) + capture.offset;
        accessed = operand.target;
      }
      if (observed >= 0 && accessed >= 0 && observed <= UINT64_MAX &&
          accessed <= UINT64_MAX && observed < accessed + operand.size &&
          accessed < observed + part.size)
        return true;
    }
    return false;
  }

  ct_kernel_trace_record render(const kctrace_event &before,
                                const kctrace_event *after,
                                const Frame *frame = nullptr) const {
    const Site &site = sites[before.site_id];
    auto record = base_record(before);
    record.text = site.assembly;
    record.end_monotonic_ns = after ? after->monotonic_ns : 0;
    record.stage = after ? ct_kernel_trace_stage::completed
                         : ct_kernel_trace_stage::before;
    std::string inputs, outputs;
    std::vector<ct_kernel_trace_value_span> input_values, output_values;
    for (const auto &reg : site.registers) {
      const auto value = [&](const kctrace_event &event) {
        if (!(event.valid_registers & (UINT64_C(1) << reg.slot)))
          return std::string("?");
        const uint64_t mask =
            reg.bits == 64 ? UINT64_MAX : (UINT64_C(1) << reg.bits) - 1;
        return llvm::formatv("0x{0:x-}",
                             (event.registers[reg.slot] >> reg.shift) & mask)
            .str();
      };
      if (reg.read || reg.write) {
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
    bool aggregate = false;
    if (site.memory_operand.size && values &&
        before.site_id < values->sites.size())
      for (const auto &binding : values->sites[before.site_id].bindings) {
        if (!aggregate_operand(site, before, binding))
          continue;
        aggregate = true;
        const auto &variable = values->variables[binding.variable];
        const auto append = [&](std::string &text,
                                std::vector<ct_kernel_trace_value_span> &spans,
                                const ct_kernel_value_binding &location,
                                const kctrace_event &event) {
          if (!text.empty())
            text += ' ';
          const size_t begin = text.size();
          const auto value = ct_kernel_format_value(
              *values, location, event, frame ? &frame->entry : nullptr);
          text += variable.name + '=' + value;
          spans.push_back({begin, text.size() - begin, variable.name, 0, false,
                           value == "?", variable.id});
        };
        append(inputs, input_values, binding, before);
        if (after && site.store.size)
          if (const auto *next = this->binding(variable.id, after->site_id);
              next && aggregate_operand(site, *after, *next))
            append(outputs, output_values, *next, *after);
      }
    if (site.memory && !aggregate) {
      if (!inputs.empty())
        inputs += ' ';
      if ((before.flags & KCTRACE_EVENT_HAVE_MEMORY) &&
          !(before.flags & KCTRACE_EVENT_HAVE_VALUES) && before.memory_size) {
        inputs += llvm::formatv("[0x{0:x-}]=[", before.memory_address).str();
        for (uint32_t index = 0; index < before.memory_size; ++index) {
          if (index)
            inputs += ' ';
          inputs += llvm::formatv("0x{0:x-2}", before.memory[index]).str();
        }
        inputs += ']';
      } else {
        const size_t begin = inputs.size();
        inputs += "memory=?";
        input_values.push_back(
            {begin, inputs.size() - begin, {}, 0, false, true});
      }
    }
    if (!inputs.empty() || !outputs.empty()) {
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
                                   const kctrace_event *after) const {
    auto record = render(frame.entry, after);
    record.values.clear();
    record.function_summary = true;
    record.text = record.function + "(...); #";
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
        const auto identity = std::to_string(variable.id) + ':' + variable.name;
        const bool first = variable.global
                               ? introduced_globals.insert(variable.id).second
                               : frame->introduced.insert(identity).second;
        if (first && variable.type && variable.type < values->types.size()) {
          const auto &name = values->types[variable.type].name;
          if (!name.empty()) {
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

  std::string variable_value(uint64_t variable, const kctrace_event &event,
                             const Frame &frame) const {
    const auto *location = binding(variable, event.site_id);
    if (!location)
      return "?";
    return ct_kernel_format_value(*values, *location, event, &frame.entry);
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

  std::vector<SourceValue>
  source_values(const std::vector<ct_source_variable> &references,
                const std::string &owner, const kctrace_event &event,
                const Frame &frame, bool parameters = false) const {
    std::vector<SourceValue> result;
    for (const auto &reference : references) {
      if (reference.function != owner || reference.name.empty() ||
          std::any_of(result.begin(), result.end(), [&](const auto &item) {
            return item.name == reference.name;
          }))
        continue;
      SourceValue value;
      value.name = reference.name;
      value.declared = reference.declaration || parameters;
      if (const auto *selected =
              named_variable(value.name, owner, event.site_id, parameters)) {
        value.variable = selected->id;
        value.global = selected->global;
        if (selected->type)
          value.type = values->types[selected->type].name;
        value.before = variable_value(value.variable, event, frame);
      }
      result.push_back(std::move(value));
    }
    return result;
  }

  void source_field(ct_kernel_trace_record &record, Frame &frame,
                    const SourceValue &value, const std::string &text,
                    bool first) {
    if (record.comment_offset == std::string::npos) {
      record.text += ' ';
      record.comment_offset = record.text.size();
      record.text += '#';
    }
    record.text += ' ';
    const size_t begin = record.text.size();
    bool introduced = false;
    if (first) {
      const std::string identity =
          std::to_string(value.variable) + ':' + value.name;
      const bool register_alias =
          values && value.variable &&
          value.variable < values->variables.size() &&
          values->variables[value.variable].register_alias;
      introduced = register_alias ? this->introduced.insert(value.name).second
                   : value.global
                       ? introduced_globals.insert(value.variable).second
                       : frame.introduced.insert(identity).second;
    }
    record.text += value.name + '=';
    introduced &= !value.declared;
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
                       const kctrace_event *after = nullptr,
                       bool continuing = false, bool unknown_call = false) {
    auto &row = frame.decompiled;
    if (!row.statement)
      return;
    const auto &statement = decompile->statements[row.statement];
    if (!after && !continuing) {
      fallback_count -= row.fallback.size();
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
                        ? functions[frame.function].name + "(...)"
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
        record.text +=
            after->site_id == control.control_target ? "true" : "false";
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
      fallback_count -= row.fallback.size();
      row = {};
    }
  }

  void decompile_completed(Frame &frame, const kctrace_event &before,
                           const kctrace_event *after,
                           std::vector<ct_kernel_trace_record> &records) {
    auto &row = frame.decompiled;
    if (!row.statement || row.last.site_id != before.site_id ||
        row.last.sequence != before.sequence)
      return;
    if (fallback_count >= kernel_trace_fallback_limit ||
        row.fallback.size() >= CT_DECOMPILED_INSTRUCTION_LIMIT) {
      flush_decompile(frame, records);
      return;
    }
    row.fallback.push_back(render(before, after, &frame));
    ++fallback_count;
    const auto &statement = decompile->statements[row.statement];
    if (after && row.next == statement.sites.size())
      flush_decompile(frame, records, after);
    else if (!after && !sites[before.site_id].call &&
             !sites[before.site_id].ret)
      flush_decompile(frame, records);
  }

  void decompile_entry(Frame &frame, const kctrace_event &event,
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
        record.text = function.prototype + " {";
        if (values)
          for (const auto variable : function.parameters) {
            if (!variable || variable >= values->variables.size())
              continue;
            const auto &definition = values->variables[variable];
            SourceValue value;
            value.variable = variable;
            value.name = definition.name;
            value.declared = true;
            frame.introduced.insert("declaration:" + value.name);
            source_field(record, frame, value,
                         variable_value(variable, frame.entry, frame), true);
          }
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

  bool decompile_observation(Frame &frame, const kctrace_event &event,
                             std::vector<ct_kernel_trace_record> &records) {
    if (!decompile || event.site_id >= decompile->sites.size())
      return false;
    if (sites[event.site_id].source_line)
      return false;
    const auto &site = decompile->sites[event.site_id];
    auto &row = frame.decompiled;
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
    const auto &operations = values->recipes[location->recipe].operations;
    const auto type = values->variables[location->variable].type;
    if (operations.empty() || operations.size() > 2 || !type ||
        (operations.size() == 2 &&
         (operations[1].opcode != llvm::dwarf::DW_OP_piece ||
          operations[1].operand != values->types[type].scalar.bytes)))
      return KCTRACE_REGISTER_COUNT;
    uint64_t number = UINT64_MAX;
    const auto &operation = operations.front();
    if (operation.opcode >= llvm::dwarf::DW_OP_reg0 &&
        operation.opcode <= llvm::dwarf::DW_OP_reg31)
      number = operation.opcode - llvm::dwarf::DW_OP_reg0;
    else if (operation.opcode == llvm::dwarf::DW_OP_regx)
      number = operation.operand;
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
    return plan && plan < captures->size() && slot < KCTRACE_VALUE_SLOTS
               ? &(*captures)[plan].slots[slot]
               : nullptr;
  }

  bool memory_completed(const Site &site, const kctrace_event &before,
                        const kctrace_event &after) const {
    unsigned slot = 0;
    const auto *captured = capture(site.source_assignment, after.site_id, slot);
    if (!captured || !(after.flags & KCTRACE_EVENT_HAVE_VALUES) ||
        after.capture_plan != values->sites[after.site_id].capture_plan ||
        !(after.capture_valid & (UINT32_C(1) << slot)))
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

  static std::string returned_scalar(const ct_value_type &type,
                                     const kctrace_event &event) {
    if (!type.bytes || type.bytes > sizeof(uint64_t) ||
        type.kind == CT_VALUE_FLOAT || type.kind == CT_VALUE_UNKNOWN ||
        !(event.valid_registers & (UINT64_C(1) << KCTRACE_REG_RAX)))
      return "?";
    return scalar_value(type,
                        reinterpret_cast<const unsigned char *>(
                            &event.registers[KCTRACE_REG_RAX]),
                        type.bytes);
  }

  void release_fallback(SourceRow &row,
                        std::vector<ct_kernel_trace_record> *records = nullptr,
                        Frame *frame = nullptr) {
    if (records)
      for (auto &record : row.fallback)
        emit(std::move(record), *records, frame);
    fallback_count -= row.fallback.size();
    row.fallback.clear();
  }

  void source_assembly(Frame &frame, const kctrace_event &before,
                       const kctrace_event *after,
                       std::vector<ct_kernel_trace_record> &records) {
    auto &row = frame.row;
    const auto &site = sites[before.site_id];
    if (!row.line || !row.call_bearing || (row.call_seen && !row.assembly) ||
        row.buffered_sequence >= before.sequence ||
        row.line != site.source_line || row.owner != site.source_owner)
      return;
    row.buffered_sequence = before.sequence;
    if (row.fallback.size() >= kernel_trace_row_limit ||
        fallback_count >= kernel_trace_fallback_limit) {
      release_fallback(row, &records, &frame);
      row.assembly = true;
    }
    auto record = render(before, after, &frame);
    if (row.assembly) {
      emit(std::move(record), records, &frame);
    } else {
      row.fallback.push_back(std::move(record));
      ++fallback_count;
    }
  }

  void source_returned(Frame &frame, const ct_source_call_result_info &call,
                       const kctrace_event &event, bool reported,
                       bool unknown_call = false) {
    auto &row = frame.row;
    if (!row.line)
      return;
    row.after = event;
    row.call_seen = true;
    release_fallback(row);
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
    if (!reported && !assigned_call && !void_call)
      row.results.push_back(
          {&call, unknown_call
                      ? "?"
                      : returned_scalar(call.result.return_type, event)});
    if (assigned_call) {
      const auto value = std::find_if(
          row.inputs.begin(), row.inputs.end(),
          [&](const auto &item) { return item.name == expression.assignment; });
      if (value != row.inputs.end() &&
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

  std::string return_value(const Frame &frame,
                           const kctrace_event &event) const {
    ct_value_type type{};
    if (values && frame.entry.site_id < values->sites.size()) {
      const auto function = values->sites[frame.entry.site_id].function;
      if (function && values->functions[function].return_type) {
        const auto &result =
            values->types[values->functions[function].return_type];
        if (result.guarded || result.scalar.kind == CT_VALUE_UNKNOWN)
          return "?";
        type = result.scalar;
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

  void flush_source(Frame &frame, std::vector<ct_kernel_trace_record> &records,
                    bool continuing = false,
                    const kctrace_event *returned = nullptr) {
    auto &row = frame.row;
    if (!row.line)
      return;
    if (row.assembly || (row.call_bearing && !row.call_seen)) {
      release_fallback(row, &records, &frame);
      if (continuing)
        row.assembly = true;
      else
        row = {};
      return;
    }
    const auto &line = source->lines[row.line];
    const auto &presentation = *line.presentation;
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
      record.text = line.text;
      record.code_highlights = presentation.highlights;
      record.call_entry = continuing;
      for (const auto &value : row.inputs)
        source_field(record, frame, value, value.before, true);
      bool result = false;
      if (returning && returned && !returns_void(frame)) {
        const std::string invocation =
            frame.call_source ? frame.call_source->result.text
                              : functions[frame.function].name + "(...)";
        source_result(record, invocation, return_value(frame, *returned), true);
        result = true;
      } else {
        for (const auto &call : row.results) {
          const auto typed = typed_source_call(row, *call.call);
          source_result(record, typed.empty() ? call.call->result.text : typed,
                        call.value, !result, !typed.empty());
          result = true;
        }
        if (row.after.site_id && row.assigned) {
          const auto value = std::find_if(
              row.inputs.begin(), row.inputs.end(),
              [&](const auto &item) { return item.variable == row.assigned; });
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
                         variable_value(value->variable, row.after, frame),
                         false);
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
    record.function = definition.name;
    record.file = source->files[definition.file].path;
    record.line = definition.line;
    record.text = definition.signature;
    const auto parameters = source_values(
        definition.parameters, definition.name, frame.entry, frame, true);
    for (const auto &value : parameters)
      source_field(record, frame, value, value.before, true);
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

  bool source_observation(Frame &frame, const kctrace_event &event,
                          std::vector<ct_kernel_trace_record> &records,
                          bool repeated, bool sequential) {
    const auto &site = sites[event.site_id];
    source_entry(frame, records);
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
      frame.row.line = site.source_line;
      frame.row.owner = site.source_owner;
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
    event.name = functions[frame.function].name;
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
      event.name = block.header.empty() ? "{" : block.header;
      event.file = source->files[block.file].path;
      event.line = block.start_line;
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

  void close_frame(Task &task, uint64_t timestamp, const char *status,
                   const kctrace_event *returned,
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
    if (frame.source_entry && frame.row.line &&
        source->lines[frame.row.line].text == "}")
      frame.row = {};
    flush_deferred(frame, records);
    flush_source(frame, records, false, returned);
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
      record.text = "}";
      record.stage = ct_kernel_trace_stage::completed;
      record.end_monotonic_ns = returned->monotonic_ns;
      if (!return_reported && !returns_void(frame))
        source_result(record,
                      frame.call_source ? frame.call_source->result.text
                      : frame.call_decompile.empty()
                          ? functions[frame.function].name + "(...)"
                          : frame.call_decompile,
                      return_value(frame, *returned), true);
      records.push_back(std::move(record));
    }
    if (returned && frame.source_entry) {
      const kctrace_event *boundary = &frame.entry;
      if (task.pending.site_id &&
          sites[task.pending.site_id].function == frame.function)
        boundary = &task.pending;
      else if (returned->site_id && returned->site_id < sites.size() &&
               sites[returned->site_id].function == frame.function)
        boundary = returned;
      auto record = base_record(*boundary);
      record.source = true;
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
    block_count -= frame.blocks.size();
    task.frames.pop_back();
    --frame_count;
    if (!complete_caller) {
      if (returned && incoming_call && !task.frames.empty() &&
          task.frames.back().call_cookie == incoming_call)
        task.frames.back().call_reported |= return_reported || source_exit;
      return;
    }
    if (returned && call_source && !task.frames.empty())
      source_returned(task.frames.back(), *call_source, *returned,
                      return_reported || source_exit, skipped_call);
    if (returned && decompile && !task.frames.empty()) {
      auto &caller = task.frames.back();
      if (caller.decompiled.statement && caller.decompiled.last.site_id &&
          sites[caller.decompiled.last.site_id].call &&
          caller.decompiled.next ==
              decompile->statements[caller.decompiled.statement].sites.size()) {
        if (caller.decompiled.printed && decompile_call_reported &&
            decompile->statements[caller.decompiled.statement]
                .assignment.empty()) {
          fallback_count -= caller.decompiled.fallback.size();
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

  bool update_blocks(Frame &frame, const kctrace_event &event,
                     std::vector<ct_kernel_trace_transition> *output,
                     std::string &error) {
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
      transition(frame, frame.blocks.back(), ct_kernel_trace_phase::end,
                 event.monotonic_ns, "complete", output);
      frame.blocks.pop_back();
      --block_count;
    }
    if (membership.size() - common >
        kernel_trace_total_frame_limit - block_count) {
      error = "kernel trace active source scopes exceed limit";
      return false;
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
        const auto [mode, within] = block_filters[block.block];
        static_cast<Selection &>(block) =
            kctrace_policy_enter(block, mode, within);
      }
      // Retain invisible lexical/inline membership as policy state. In
      // particular a within match in an inline body ends when that body ends,
      // and only calls made inside it inherit that active match.
      if (block.within &&
          (block.mode == into || (inlined && block.mode == over))) {
        block.token = next_token++;
        block.parent = parent_token(frame);
        block.begin = event.monotonic_ns;
        block.pc = event.pc;
      }
      frame.blocks.push_back(block);
      ++block_count;
      transition(frame, block, ct_kernel_trace_phase::begin, event.monotonic_ns,
                 "", output);
    }
    return true;
  }

  bool
  finish_execution_instruction(Task &task, const kctrace_event *after,
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
    const bool branch =
        same && previous.branch && !previous.ret &&
        (previous.branch_target == after->site_id ||
         (previous.conditional && previous.next == after->site_id));
    source_assembly(frame, before, completed ? after : nullptr, records);
    if (completed && previous.source_assignment && frame.row.line &&
        (!frame.row.call_bearing || frame.row.call_seen) &&
        previous.source_line == frame.row.line &&
        previous.source_owner == frame.row.owner &&
        (!previous.memory_assignment ||
         memory_completed(previous, before, *after))) {
      frame.row.after = *after;
      frame.row.assigned = previous.source_assignment;
    }
    decompile_completed(frame, before, completed || branch ? after : nullptr,
                        records);
    if (task.selected)
      emit(render(before, completed ? after : nullptr, &frame), records,
           &frame);
    task.pending = {};
    task.selected = false;
    return completed;
  }

  void execution_gap(Task &task, const kctrace_event &event, const char *reason,
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

  bool consume_execution(Task &task, const kctrace_event &event,
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
      if (task.frames.size() >= kernel_trace_frame_limit ||
          frame_count >= kernel_trace_total_frame_limit) {
        error = "kernel trace call depth exceeds limit";
        return false;
      }
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
          release_fallback(caller.row);
        }
        const auto selected = kctrace_policy_decode(execution.state);
        if (selected.within && selected.mode == into) {
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
      ++frame_count;
      task.execution_serial = execution.frame_id;
      task.execution_unknown = false;
      auto &entered = task.frames.back();
      if (!update_blocks(entered, event, output, error))
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
      finish_execution_instruction(task, nullptr, records);
      flush_deferred(frame, records);
      flush_source(frame, records);
      flush_decompile(frame, records);
    } else if (body && detailed) {
      completed = finish_execution_instruction(task, &event, records);
    } else if (event.type == KCTRACE_EVENT_BLOCK_POINT) {
      finish_execution_instruction(task, nullptr, records);
      flush_deferred(frame, records);
      flush_source(frame, records);
      flush_decompile(frame, records);
    }
    frame.execution_state = execution.state;
    frame.execution_level = event.level;

    if (calling) {
      frame.call_cookie = execution.call_id;
      frame.call_site = event.site_id;
      frame.call_unpaired = execution.kind == KCTRACE_BOUNDARY_CALL_UNPAIRED;
      frame.call_observed = frame.call_reported = frame.call_skipped = false;
      frame.pending_source = nullptr;
      task.execution_serial = execution.call_id;
    }
    if (returned) {
      finish_execution_instruction(task, nullptr, records);
      if (terminal && (execution.flags & KCTRACE_EXEC_RETURN_VALUE)) {
        const auto *call = frame.pending_source;
        if (!call)
          call = source_call(frame, sites[frame.call_site].call_name);
        if (call)
          source_returned(frame, *call, event, frame.call_reported,
                          frame.call_skipped);
        if (decompile && frame.decompiled.statement &&
            frame.decompiled.last.site_id == frame.call_site &&
            frame.decompiled.next ==
                decompile->statements[frame.decompiled.statement]
                    .sites.size()) {
          if (frame.decompiled.printed && frame.call_reported &&
              decompile->statements[frame.decompiled.statement]
                  .assignment.empty()) {
            fallback_count -= frame.decompiled.fallback.size();
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
      if (!observation_changed && detailed &&
          (execution.flags & KCTRACE_EXEC_RETURN_VALUE))
        frame.resumed_site = event.site_id;
      if (observation_changed) {
        flush_deferred(frame, records);
        flush_source(frame, records);
        flush_decompile(frame, records);
      }
    }
    if (!update_blocks(frame, event, output, error))
      return false;
    if (event.site_id != frame.guard_site)
      frame.guard_site = 0;
    if (instruction)
      frame.guard_site = event.site_id;
    if (body) {
      task.selected = detailed;
      if (task.selected) {
        if (source_observation(frame, event, records, repeated,
                               completed || resumed) ||
            decompile_observation(frame, event, records))
          task.selected = false;
      }
      task.pending = detailed ? event : kctrace_event{};
      if (frame.call_cookie && frame.call_site == event.site_id) {
        frame.call_observed = true;
        frame.pending_source = source_call(frame, site.call_name);
      }
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

bool ct_kernel_trace::prepare(const ct_kernel_image &image,
                              const std::vector<ct_kernel_site> &sites,
                              const ct_kernel_trace_options &options,
                              std::string &error) {
  error.clear();
  if (data->prepared || sites.empty() ||
      sites.size() > kernel_trace_site_limit) {
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
        decompile.sites.size() > kernel_trace_site_limit + 1) {
      error = "invalid kernel decompile metadata pools";
      return false;
    }
    for (size_t id = 1; id < decompile.statements.size(); ++id) {
      const auto &statement = decompile.statements[id];
      if (!statement.function ||
          statement.function >= decompile.functions.size() ||
          statement.sites.empty() ||
          statement.sites.size() > CT_DECOMPILED_INSTRUCTION_LIMIT) {
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
          site.blocks.size() > kernel_trace_frame_limit) {
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
        values.sites.size() > kernel_trace_site_limit + 1) {
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
      if (function.return_type >= values.types.size()) {
        error = "invalid kernel function return type";
        return false;
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
  const llvm::MemoryBufferRef bytes(
      {reinterpret_cast<const char *>(image.bytes.data()), image.bytes.size()},
      image.path);
  std::unique_ptr<llvm::object::ObjectFile> object;
  std::unique_ptr<llvm::DWARFContext> dwarf;
  if (!prepared->source) {
    auto parsed = llvm::object::ObjectFile::createObjectFile(bytes);
    if (!parsed) {
      error = llvm::toString(parsed.takeError());
      return false;
    }
    object = std::move(*parsed);
    dwarf = llvm::DWARFContext::create(*object);
  }
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
  for (unsigned index = 1; index < registers->getNumRegs(); ++index) {
    Data::Register reg;
    reg.name = registers->getName(index);
    reg.slot = KCTRACE_REGISTER_COUNT;
    reg.bits = 0;
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
  for (const auto &relocation : image.relocations)
    relocations.emplace(std::make_pair(relocation.section, relocation.offset),
                        &relocation);
  for (const auto &symbol : image.symbols)
    symbols.emplace(std::make_pair(symbol.table, symbol.index), &symbol);
  uint64_t max_site = 0;
  for (const auto &site : sites)
    if (site.probe)
      max_site = std::max(max_site, site.id);
  if (!max_site || max_site > kernel_trace_site_limit) {
    error = "kernel trace site identifiers exceed limit";
    return false;
  }
  prepared->sites.resize(max_site + 1);
  std::map<std::pair<uint32_t, uint64_t>, uint64_t> site_index;
  std::map<uint64_t, std::pair<uint32_t, uint64_t>> branch_destinations;
  std::vector<std::tuple<uint32_t, uint64_t, uint64_t>> protected_entries;
  std::map<std::string, unsigned> source_files;
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
    site.function = function->second;
    auto &owner = prepared->functions[site.function];
    if (!owner.first ||
        source.offset < prepared->sites[owner.first].original.offset)
      owner.first = source.id;
    if (!site_index
             .emplace(std::make_pair(source.section, source.offset), source.id)
             .second) {
      error = "duplicate kernel instruction site";
      return false;
    }
    if (dwarf) {
      const llvm::DILineInfoSpecifier source_specification(
          llvm::DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
          llvm::DILineInfoSpecifier::FunctionNameKind::LinkageName);
      const auto location = dwarf->getLineInfoForAddress(
          {source.offset, source.section}, source_specification);
      if (location && location->FileName != llvm::DILineInfo::BadString) {
        const auto [file, inserted] =
            source_files.emplace(location->FileName, prepared->files.size());
        if (inserted)
          prepared->files.push_back(location->FileName);
        site.file = file->second;
        site.line = location->Line;
      }
    }
    if (prepared->source && source.id < prepared->source->sites.size()) {
      const auto line_id = prepared->source->sites[source.id].line;
      if (line_id) {
        const auto &line = prepared->source->lines[line_id];
        const auto &path = prepared->source->files[line.file].path;
        const auto [file, inserted] =
            source_files.emplace(path, prepared->files.size());
        if (inserted)
          prepared->files.push_back(path);
        site.file = file->second;
        site.line = line.line;
      }
    }
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
              description.isUnconditionalBranch() &&
              source.original_size == 5 && length == 5 &&
              image.bytes[section.offset + source.offset] == 0xe9 &&
              field->second->offset == source.offset + 1 &&
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
        if (description.isCall()) {
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
      site.call = description.isCall();
      site.ret |= description.isReturn();
      site.branch = description.isBranch();
      site.conditional = description.isConditionalBranch();
      site.memory = description.mayLoad() || description.mayStore();
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
        if (store)
          site.store = site.memory_operand;
      }
      const auto add_register = [&](llvm::MCRegister value, bool read,
                                    bool write) {
        if (!value)
          return;
        const auto known = register_names.find(registers->getName(value));
        if (known == register_names.end())
          return;
        auto existing = std::find_if(
            site.registers.begin(), site.registers.end(),
            [&](const auto &reg) { return reg.name == known->first; });
        if (existing == site.registers.end()) {
          site.registers.push_back(known->second);
          existing = site.registers.end() - 1;
        }
        existing->read |= read;
        existing->write |= write;
        site.writes_stack |= write && existing->slot == KCTRACE_REG_RSP;
      };
      for (unsigned index = 0; index < instruction.getNumOperands(); ++index)
        if (instruction.getOperand(index).isReg())
          add_register(instruction.getOperand(index).getReg(),
                       index >= description.getNumDefs(),
                       index < description.getNumDefs());
      for (const auto reg : description.implicit_uses())
        add_register(reg, true, false);
      for (const auto reg : description.implicit_defs())
        add_register(reg, false, true);
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
          site.assembly +=
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
      if (const auto *variable = prepared->named_variable(
              expression.assignment, site.source_owner, site.next);
          variable && variable->type) {
        const auto slot = prepared->location_register(
            prepared->binding(variable->id, site.next));
        const auto &type = prepared->values->types[variable->type];
        const auto size = type.scalar.bytes;
        if (type.guarded || type.scalar.kind == CT_VALUE_UNKNOWN || !size ||
            size > 8)
          continue;
        unsigned capture_slot = 0;
        if (const auto *captured =
                prepared->capture(variable->id, site.next, capture_slot);
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
        if (site.memory_assignment ||
            std::any_of(site.registers.begin(), site.registers.end(),
                        [&](const auto &reg) {
                          return reg.write && !reg.shift && reg.slot == slot &&
                                 reg.bits >= 8 * size;
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
  prepared->prepared = true;
  data = std::move(prepared);
  return true;
}

bool ct_kernel_trace::consume_event(
    const kctrace_event &event, std::vector<ct_kernel_trace_record> &records,
    std::vector<ct_kernel_trace_transition> *transitions, std::string &error) {
  error.clear();
  const bool execution = event.flags & KCTRACE_EVENT_HAVE_EXECUTION;
  const kctrace_execution_record no_execution{};
  const auto &observed = event.execution;
  if (!data->prepared || event.size != sizeof(event) ||
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
      event.reserved2 || !event.sequence || !event.session_id ||
      !event.generation || event.softirq_depth > 1 ||
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
  if (!data->tasks.count(key) &&
      data->tasks.size() >= kernel_trace_task_limit) {
    error = "kernel trace task state exceeds limit";
    return false;
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
      data->source_assembly(frame, task.pending, completed ? &event : nullptr,
                            records);
      if (completed && previous.source_assignment &&
          (!frame.row.call_bearing || frame.row.call_seen) &&
          previous.source_line == frame.row.line &&
          previous.source_owner == frame.row.owner &&
          (!previous.memory_assignment ||
           data->memory_completed(previous, task.pending, event))) {
        frame.row.after = event;
        frame.row.assigned = previous.source_assignment;
      }
      if (previous.call && previous.next == event.site_id &&
          task.pending.registers[KCTRACE_REG_RSP] == stack) {
        if (const auto *call = data->source_call(frame, previous.call_name))
          data->source_returned(frame, *call, event, false);
      }
      if (nested_call) {
        if (data->source_call(frame, function.name)) {
          frame.row.call_seen = true;
          data->release_fallback(frame.row);
        }
        const auto selected = kctrace_policy_enter(
            Data::selection(frame), function.mode, function.within);
        if (selected.within && selected.mode == Data::into &&
            !frame.row.printed)
          data->flush_source(frame, records, true);
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
          data->render(task.pending, completed ? &event : nullptr,
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
    if (task.frames.size() >= kernel_trace_frame_limit ||
        data->frame_count >= kernel_trace_total_frame_limit) {
      error = "kernel trace call depth exceeds limit";
      return false;
    }
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
    ++data->frame_count;
  }
  if (!data->update_blocks(task.frames.back(), event, transitions, error))
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

bool ct_kernel_trace::consume(const kctrace_event &event,
                              std::vector<ct_kernel_trace_record> &records,
                              std::string &error) {
  return consume_event(event, records, nullptr, error);
}

bool ct_kernel_trace::consume(
    const kctrace_event &event, std::vector<ct_kernel_trace_record> &records,
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
