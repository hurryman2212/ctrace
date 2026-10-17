#ifndef CTRACE_PERFETTO_SCOPE_H
#define CTRACE_PERFETTO_SCOPE_H

#include <cstdint>
#include <string>
#include <vector>

#include "decompiled_record.h"
#include "location_record.h"

// Perfetto keeps a loop's complete statement (including its header and trailing
// condition) open across iterations; other blocks use lexical body membership.
// Pointers remain owned by the supplied location record.
std::vector<const ct_source_block *>
ct_perfetto_source_scopes(const ct_location_view &location, bool source);

struct ct_perfetto_flow_scope {
  bool valid = false;
  bool loop = false;
  bool body = false;
  bool has_else = false;
  bool open = false;
  uint64_t join = 0;
  uint64_t repeat = 0;
};

// Offsets remain relative to the containing module. A branch opens a body only
// after its actual successor proves that the body ran. branch_outcome is -1
// when only the successor is known, otherwise 0/1 means not-taken/taken.
ct_perfetto_flow_scope ct_perfetto_recovered_scope(const ct_flow_region &region,
                                                   uint64_t destination,
                                                   int branch_outcome,
                                                   bool counted_loop);

struct ct_perfetto_flow_label {
  std::string text;
  const char *origin = "recovered";
};

// A common, value-free display label for both collectors. The caller validates
// the display instruction's original bytes before supplying it. Predicate
// polarity is checked against the actual CFG successors here. Loop fields from
// different naming schemes are never combined into the same header.
ct_perfetto_flow_label
ct_perfetto_recovered_label(const ct_flow_region &region, bool body,
                            const std::string &fallback_condition,
                            const std::string &fallback_initializer,
                            const std::string &fallback_update,
                            const ct_decompiled_display_view &display);
ct_perfetto_flow_label
ct_perfetto_switch_label(const std::string &fallback_selector,
                         const ct_decompiled_display_view &display);

// Existing raw-query callers borrow the protocol buffer for this call only.
ct_perfetto_flow_label
ct_perfetto_recovered_label(const ct_flow_region &region, bool body,
                            const std::string &fallback_condition,
                            const std::string &fallback_initializer,
                            const std::string &fallback_update,
                            const ct_decompiled_display *display);
ct_perfetto_flow_label
ct_perfetto_switch_label(const std::string &fallback_selector,
                         const ct_decompiled_display *display);

#endif
