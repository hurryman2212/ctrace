#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "perfetto_scope.h"

std::vector<const ct_source_block *>
ct_perfetto_source_scopes(const ct_location_view &location, bool source) {
  std::vector<const ct_source_block *> result;
  if (!source)
    return result;
  const size_t count = std::min<size_t>(location.source_block_count,
                                        location.source_blocks.size());
  for (size_t index = 0; index < count; ++index) {
    const auto &block = location.source_blocks[index];
    if (block.loop_end_line) {
      // A loop is one activation, including its initializer, condition and
      // update. Returning to the header does not leave this scope; do/while
      // also retains its trailing condition after the body's closing brace.
      const bool after_start =
          location.line > block.start_line ||
          (location.line == block.start_line &&
           (!location.column || location.column >= block.loop_start_column));
      const bool before_end =
          location.line < block.loop_end_line ||
          (location.line == block.loop_end_line &&
           (!location.column || location.column < block.loop_end_column));
      if (after_start && before_end)
        result.push_back(&block);
      continue;
    }
    // Header/brace metadata describes a scope; it does not prove execution of
    // that scope's interior. An absent column cannot prove same-line entry.
    const bool after_open =
        location.line > block.opening_line ||
        (location.line == block.opening_line && location.column &&
         location.column > block.opening_column);
    const bool before_close =
        location.line < block.closing_line ||
        (location.line == block.closing_line && location.column &&
         location.column < block.closing_column);
    if (after_open && before_close)
      result.push_back(&block);
  }
  // A statement-expression in a loop header has an earlier opening brace
  // than the loop body, but must remain a child of the complete loop scope.
  std::stable_sort(
      result.begin(), result.end(), [](const auto *left, const auto *right) {
        const auto left_line =
            left->loop_end_line ? left->start_line : left->opening_line;
        const auto right_line =
            right->loop_end_line ? right->start_line : right->opening_line;
        if (left_line != right_line)
          return left_line < right_line;
        const auto left_column = left->loop_end_line ? left->loop_start_column
                                                     : left->opening_column;
        const auto right_column = right->loop_end_line
                                      ? right->loop_start_column
                                      : right->opening_column;
        return left_column < right_column;
      });
  return result;
}

ct_perfetto_flow_scope ct_perfetto_recovered_scope(const ct_flow_region &region,
                                                   uint64_t destination,
                                                   int branch_outcome,
                                                   bool counted_loop) {
  ct_perfetto_flow_scope result;
  if ((region.kind != CT_FLOW_IF && region.kind != CT_FLOW_LOOP) ||
      (destination != region.taken_offset &&
       destination != region.fallthrough_offset) ||
      branch_outcome < -1 || branch_outcome > 1)
    return result;
  result.valid = true;
  result.loop = region.kind == CT_FLOW_LOOP;
  const bool taken = branch_outcome >= 0 ? branch_outcome == 1
                                         : destination == region.taken_offset;
  result.has_else = !result.loop && region.taken_offset != region.join_offset &&
                    region.fallthrough_offset != region.join_offset;
  // Match the rendered control-flow orientation: for a two-arm if, its
  // fallthrough is the first arm. No original-source orientation is inferred.
  const bool body_taken = result.loop
                              ? region.taken_is_body
                              : region.fallthrough_offset == region.join_offset;
  result.body = taken == body_taken;
  result.open = result.body || result.has_else;
  result.join = region.join_offset;
  if (result.loop)
    result.repeat =
        counted_loop ? region.update_offset : region.loop_header_offset;
  return result;
}

ct_perfetto_flow_label
ct_perfetto_recovered_label(const ct_flow_region &region, bool body,
                            const std::string &fallback_condition,
                            const std::string &fallback_initializer,
                            const std::string &fallback_update,
                            const ct_decompiled_display_view &display) {
  ct_perfetto_flow_label label;
  if ((region.kind != CT_FLOW_IF && region.kind != CT_FLOW_LOOP) ||
      region.taken_offset == region.fallthrough_offset)
    return label;
  const bool loop = region.kind == CT_FLOW_LOOP;
  const bool body_taken = loop
                              ? region.taken_is_body
                              : region.fallthrough_offset == region.join_offset;
  const uint64_t body_target =
      body_taken ? region.taken_offset : region.fallthrough_offset;
  const bool compatible =
      (!display.control_kind[0] ||
       (loop ? std::strcmp(display.control_kind, "for") == 0 ||
                   std::strcmp(display.control_kind, "while") == 0
             : std::strcmp(display.control_kind, "if") == 0));
  const bool proven = compatible &&
                      display.instruction.offset == region.branch_offset &&
                      display.control_conditional &&
                      display.control_has_target && display.control_text[0] &&
                      (display.control_target == region.taken_offset ||
                       display.control_target == region.fallthrough_offset);
  std::string condition = fallback_condition;
  std::string initializer = fallback_initializer, update = fallback_update;
  if (proven) {
    label.origin = "decompiled";
    condition = display.control_text;
    if (display.control_target != body_target)
      condition = "!(" + condition + ")";
    // A recovered machine initializer such as EAX=0 cannot initialize a
    // Ghidra induction variable named local_10. Keep the whole header within
    // one naming scheme, falling back to while when only its predicate exists.
    initializer.clear();
    update.clear();
    if (loop && std::strcmp(display.control_kind, "for") == 0 &&
        display.control_initializer[0] && display.control_update[0]) {
      initializer = display.control_initializer;
      update = display.control_update;
    }
  }
  const bool has_else = !loop && region.taken_offset != region.join_offset &&
                        region.fallthrough_offset != region.join_offset;
  if (!body && has_else) {
    label.text = "else {";
  } else if (!condition.empty()) {
    if (loop && !update.empty())
      label.text =
          "for (" + initializer + "; " + condition + "; " + update + ") {";
    else
      label.text = std::string(loop ? "while (" : "if (") + condition + ") {";
  }
  return label;
}

ct_perfetto_flow_label
ct_perfetto_switch_label(const std::string &fallback_selector,
                         const ct_decompiled_display_view &display) {
  ct_perfetto_flow_label label;
  std::string selector = fallback_selector;
  if (!display.control_conditional &&
      std::strcmp(display.control_kind, "switch") == 0 &&
      display.control_text[0]) {
    selector = display.control_text;
    label.origin = "decompiled";
  }
  if (!selector.empty())
    label.text = "switch (" + selector + ") {";
  return label;
}

ct_perfetto_flow_label
ct_perfetto_recovered_label(const ct_flow_region &region, bool body,
                            const std::string &fallback_condition,
                            const std::string &fallback_initializer,
                            const std::string &fallback_update,
                            const ct_decompiled_display *display) {
  return ct_perfetto_recovered_label(
      region, body, fallback_condition, fallback_initializer, fallback_update,
      display ? ct_decompiled_display_view(*display)
              : ct_decompiled_display_view{});
}

ct_perfetto_flow_label
ct_perfetto_switch_label(const std::string &fallback_selector,
                         const ct_decompiled_display *display) {
  return ct_perfetto_switch_label(fallback_selector,
                                  display ? ct_decompiled_display_view(*display)
                                          : ct_decompiled_display_view{});
}
