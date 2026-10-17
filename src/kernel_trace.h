#ifndef CTRACE_KERNEL_TRACE_H
#define CTRACE_KERNEL_TRACE_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <uapi/kctrace.h>

#include "kernel_capture.h"
#include "kernel_decompile.h"
#include "kernel_image.h"
#include "kernel_policy.h"
#include "kernel_rewrite.h"
#include "kernel_source.h"
#include "kernel_values.h"

struct ct_kernel_trace_options {
  bool intel = false, emit_terminal = true;
  bool within_init = false, within_intr = false;
  std::vector<std::string> within;
  std::vector<std::string> into, recurse, over;
  std::shared_ptr<const ct_kernel_source_metadata> source;
  std::shared_ptr<const ct_kernel_decompile_metadata> decompile;
  std::shared_ptr<const ct_kernel_value_metadata> values;
  std::shared_ptr<const std::vector<ct_kernel_capture_plan>> captures;
};

enum class ct_kernel_trace_stage { before, completed, discontinuity };
enum class ct_kernel_trace_phase { begin, end };
enum class ct_kernel_trace_kind { function, block };

// Tokens are unique across task/context tracks. BEGIN refers to its nearest
// visible parent; END is emitted inner-first. Proven exits use the successor
// event timestamp. Without a proven successor, an observed RET ends at that
// last observation with status "unobserved-return", never at unload time.
struct ct_kernel_trace_transition {
  uint64_t token = 0, parent = 0, monotonic_ns = 0, task_start_ns = 0, pc = 0;
  uint32_t tid = 0, tgid = 0, cpu = 0, context = 0, line = 0;
  uint16_t hardirq_depth = 0, softirq_depth = 0;
  // Explicit IRQ cookies belong to a persistent CPU/depth lane; current task
  // fields remain attribution and do not identify that lane.
  bool has_execution = false;
  ct_kernel_trace_phase phase = ct_kernel_trace_phase::begin;
  ct_kernel_trace_kind kind = ct_kernel_trace_kind::function;
  std::string name, file, origin, status;
};

struct ct_kernel_trace_value_span {
  size_t offset = 0, length = 0;
  std::string name;
  unsigned bits = 0;
  bool introduction = false, unknown = false;
  // Assembly aggregate introductions are resolved only when a buffered row
  // is actually emitted, using its physical frame's existing value scope.
  uint64_t variable = 0;
};

struct ct_kernel_trace_record {
  uint64_t site_id = 0, pc = 0, original_offset = 0, monotonic_ns = 0;
  uint64_t end_monotonic_ns = 0;
  uint64_t task_start_ns = 0;
  uint32_t section = 0, tid = 0, tgid = 0, cpu = 0, context = 0, line = 0;
  uint16_t hardirq_depth = 0, softirq_depth = 0;
  std::string function, file, text;
  // Byte spans include the first visible type spelling. No ANSI sequences are
  // embedded; the controller chooses introduction/unknown-value styling.
  std::vector<ct_kernel_trace_value_span> values;
  ct_kernel_trace_stage stage = ct_kernel_trace_stage::before;
  bool function_summary = false, source = false, entry = false;
  bool call_entry = false;
  size_t comment_offset = std::string::npos;
  std::vector<ct_source_highlight> code_highlights;
};

// Offline assembly/value rendering. Source positions are section-aware DWARF
// locations, not a claim that original-source expressions have been evaluated.
// HAVE_EXECUTION observations use authoritative frame/call cookies and prepared
// numeric policy. Sparse points never bridge value snapshots across levels.
// With within_intr enabled, a runtime-proved ENTER may select that physical
// frame's within scope; context/depth alone never changes the step filters.
// Copy PCs stay actual addresses; legacy section-base inference applies only
// to dense observations without execution records.
// prepare owns all display data and releases LLVM objects before returning.
// consume/finish never disassemble, analyze source, or read target memory.
class ct_kernel_trace {
  struct Data;
  std::unique_ptr<Data> data;
  bool consume_event(const kctrace_event &event,
                     std::vector<ct_kernel_trace_record> &records,
                     std::vector<ct_kernel_trace_transition> *transitions,
                     std::string &error);
  void finish_events(std::vector<ct_kernel_trace_record> &records,
                     std::vector<ct_kernel_trace_transition> *transitions,
                     uint64_t timestamp, const char *status);

public:
  ct_kernel_trace();
  ~ct_kernel_trace();
  ct_kernel_trace(const ct_kernel_trace &) = delete;
  ct_kernel_trace &operator=(const ct_kernel_trace &) = delete;

  bool prepare(const ct_kernel_image &image,
               const std::vector<ct_kernel_site> &sites,
               const ct_kernel_trace_options &options, std::string &error);
  // Valid after prepare(); includes independently proven scope-gap bridges.
  // Original IDs and numeric decisions are independent of emitted copy PCs.
  const ct_kernel_policy &prepared_policy() const;
  // Additional original sites where straight-line execution changes display
  // block membership. Copy emitters also observe basic-block leaders.
  const std::vector<uint64_t> &timing_sites() const;
  bool consume(const kctrace_event &event,
               std::vector<ct_kernel_trace_record> &records,
               std::string &error);
  bool consume(const kctrace_event &event,
               std::vector<ct_kernel_trace_record> &records,
               std::vector<ct_kernel_trace_transition> &transitions,
               std::string &error);
  // Pending instructions without a proven successor remain before-only.
  void finish(std::vector<ct_kernel_trace_record> &records);
  void finish(std::vector<ct_kernel_trace_record> &records,
              std::vector<ct_kernel_trace_transition> &transitions,
              uint64_t timestamp, const char *status = "incomplete");
};

#endif
