#ifndef CTRACE_INSTRUMENTATION_H
#define CTRACE_INSTRUMENTATION_H

#include <cstdint>

// Initial preparation is separate from the active execution requirement.
// Only a detailed filter hit selects full; Perfetto covers the other scopes.
enum class ct_instrument_level : uint8_t { arm, perfetto, full };

inline const char *ct_instrument_level_name(ct_instrument_level level) {
  switch (level) {
  case ct_instrument_level::arm:
    return "arm";
  case ct_instrument_level::perfetto:
    return "perfetto";
  case ct_instrument_level::full:
    return "full";
  }
  return "?";
}

inline ct_instrument_level ct_required_instrumentation(bool record_perfetto,
                                                       bool step_into) {
  return step_into         ? ct_instrument_level::full
         : record_perfetto ? ct_instrument_level::perfetto
                           : ct_instrument_level::arm;
}

#endif
