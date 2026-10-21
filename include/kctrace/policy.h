/* SPDX-License-Identifier: MIT */
#ifndef KCTRACE_POLICY_H
#define KCTRACE_POLICY_H

/* Shared selection implementation; this enum/state struct is private. */
enum kctrace_policy_mode {
  KCTRACE_POLICY_SKIP = 0,
  KCTRACE_POLICY_OVER = 1,
  KCTRACE_POLICY_INTO = 2,
  KCTRACE_POLICY_RECURSE = 3,
};

/* Flags are Boolean values. Zero initialization gives an out-of-scope root. */
struct kctrace_policy_state {
  enum kctrace_policy_mode mode;
  unsigned char within;
  unsigned char recurse;
  unsigned char blocked;
};

/* Encodes the state byte documented in the UAPI execution record.
 * Flags occupy bits 0..2 and mode occupies bits 3..4.
 * The low three bits index decisions that do not depend on the incoming mode.
 */
#ifdef __cplusplus
extern "C" {
#endif

static inline unsigned char
kctrace_policy_encode(struct kctrace_policy_state state) {
  return (state.mode << 3) | state.within | (state.recurse << 1) |
         (state.blocked << 2);
}

static inline struct kctrace_policy_state
kctrace_policy_decode(unsigned char encoded) {
  struct kctrace_policy_state state;

  state.mode = (enum kctrace_policy_mode)((encoded >> 3) & 3);
  state.within = encoded & 1;
  state.recurse = (encoded >> 1) & 1;
  state.blocked = (encoded >> 2) & 1;
  return state;
}

static inline struct kctrace_policy_state
kctrace_policy_enter(struct kctrace_policy_state state,
                     enum kctrace_policy_mode mode, unsigned char within) {
  /* Ancestors outside within have not entered the trace policy. */
  if (!state.within) {
    state.recurse = 0;
    state.blocked = 0;
  }
  state.within = state.within || within;
  if (mode == KCTRACE_POLICY_RECURSE) {
    state.mode = KCTRACE_POLICY_INTO;
    state.recurse = 1;
    state.blocked = 0;
  } else if (mode == KCTRACE_POLICY_INTO) {
    state.mode = KCTRACE_POLICY_INTO;
  } else if (mode == KCTRACE_POLICY_OVER) {
    state.mode = state.blocked ? KCTRACE_POLICY_SKIP : KCTRACE_POLICY_OVER;
    state.recurse = 0;
    state.blocked = 1;
  } else {
    state.mode = state.recurse && !state.blocked ? KCTRACE_POLICY_INTO
                                                 : KCTRACE_POLICY_SKIP;
  }
  return state;
}

#ifdef __cplusplus
}
#endif

#endif
