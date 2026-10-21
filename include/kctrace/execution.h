/* SPDX-License-Identifier: MIT */
#ifndef KCTRACE_EXECUTION_H
#define KCTRACE_EXECUTION_H

#include "kctrace/policy.h"

/* Shared bounded execution state, not a serialized ABI. Array indexes are
 * one-based; counts include the unused zero element. Tables are immutable.
 * Callers own context lookup, synchronization, storage, and event emission.
 * A context pointer is always required and its storage starts zeroed.
 */
struct kctrace_execution_function {
  unsigned char states[8];
  unsigned char minimum_level;
};

struct kctrace_execution_path {
  unsigned char states[8];
};

struct kctrace_execution_tables {
  const struct kctrace_execution_function *functions;
  const struct kctrace_execution_path *paths;
  unsigned int function_count;
  unsigned int path_count;
};

enum kctrace_execution_kind {
  KCTRACE_EXECUTION_ENTER,
  KCTRACE_EXECUTION_SCOPE,
  KCTRACE_EXECUTION_CALL,
  KCTRACE_EXECUTION_AFTER_CALL,
  KCTRACE_EXECUTION_EXIT,
  KCTRACE_EXECUTION_TAIL,
  /* A terminal CALL without an AFTER_CALL site. This does not itself
   * prove noreturn; offline validation must establish that separately.
   */
  KCTRACE_EXECUTION_CALL_UNPAIRED,
};

enum kctrace_execution_level {
  KCTRACE_EXECUTION_ARM,
  KCTRACE_EXECUTION_PERFETTO,
  KCTRACE_EXECUTION_FULL,
};

enum kctrace_execution_flag {
  KCTRACE_EXECUTION_UNKNOWN = 1U << 0,
  KCTRACE_EXECUTION_DISCONTINUITY = 1U << 1,
  KCTRACE_EXECUTION_CALLBACK = 1U << 2,
  KCTRACE_EXECUTION_LEVEL_CHANGED = 1U << 3,
  KCTRACE_EXECUTION_ENTRY_VALUES = 1U << 4,
  KCTRACE_EXECUTION_RETURN_VALUE = 1U << 5,
  KCTRACE_EXECUTION_RECOVERED = 1U << 6,
  /* Successful ENTER of a runtime-proved interrupt handler only. */
  KCTRACE_EXECUTION_HANDLER_CRITERION = 1U << 8,
};

enum kctrace_execution_failure {
  KCTRACE_EXECUTION_OK,
  KCTRACE_EXECUTION_OVERFLOW,
  KCTRACE_EXECUTION_BAD_BOUNDARY,
  KCTRACE_EXECUTION_COOKIE_EXHAUSTED,
  KCTRACE_EXECUTION_REENTRANT,
  /* Values 5 and 6 belong to the owner's context lookup failures. */
  KCTRACE_EXECUTION_INHERITED_UNKNOWN = 7,
};

enum kctrace_execution_within {
  KCTRACE_EXECUTION_WITHIN_OUTSIDE,
  KCTRACE_EXECUTION_WITHIN_ACTIVE,
  KCTRACE_EXECUTION_WITHIN_UNKNOWN,
};

enum kctrace_execution_handler {
  KCTRACE_EXECUTION_HANDLER_NONE,
  KCTRACE_EXECUTION_HANDLER_PROVED,
  KCTRACE_EXECUTION_HANDLER_UNKNOWN,
};

struct kctrace_execution_boundary {
  unsigned long long site_id;
  unsigned long long stack;
  /* ENTER: original [RSP], or zero when unavailable. */
  unsigned long long return_pc;
  /* CALL kinds: exact hardware continuation for each outgoing copy. A
   * paired CALL resumes before its AFTER_CALL gate. Selection can change
   * at this CALL boundary itself.
   */
  unsigned long long call_returns[3];
  /* CALL: original site reached after completion. CALL_UNPAIRED: zero.
   * AFTER_CALL: original CALL site. These remain independent of relocated
   * copy addresses.
   */
  unsigned long long related_site_id;
  unsigned int function;
  unsigned int path;
  enum kctrace_execution_kind kind;
  /* Empty-context ENTER only; never carries recurse/blocked state. */
  unsigned char root_within;
  /* ENTER only: owner-proved handler identity and enabled within-intr.
   * Context/depth alone never establishes this criterion. It selects this
   * frame's within scope, not its step mode, independently of inheritance.
   * UNKNOWN preserves only a proved canonical function/entry-stack anchor;
   * its matching EXIT/TAIL ends uncertainty without inventing within policy.
   */
  unsigned char handler_within;
};

struct kctrace_execution_frame {
  unsigned long long id;
  unsigned long long parent_id;
  /* Only an exact return-address and stack match links the incoming call.
   * A callback has a parent frame but no incoming call cookie.
   */
  unsigned long long incoming_call;
  unsigned long long entry_stack;
  unsigned long long call_id;
  unsigned long long call_site;
  unsigned long long call_stack;
  unsigned long long call_return_pc;
  unsigned long long return_site;
  unsigned int function;
  unsigned int path;
  unsigned char base_state;
  unsigned char state;
  unsigned char level;
};

struct kctrace_execution_context {
  struct kctrace_execution_frame *frames;
  unsigned int capacity;
  unsigned int depth;
  /* Shared monotonically increasing frame/call cookies within this
   * context. The owner must also identify the context incarnation in
   * every event.
   */
  unsigned long long serial;
  enum kctrace_execution_failure failure;
  /* Immutable owner configuration; keep publication in a separate byte. */
  unsigned char terminal : 1;
  unsigned char perfetto : 1;
  unsigned char within_enabled : 1;
  unsigned char minimum_level : 2;
  /* The owner publishes this summary atomically after complete dispatch.
   * Nested contexts must never inspect the mutable frame array instead.
   * These fields do not participate in the pure engine's dispatch logic.
   */
  unsigned char published_within;
};

struct kctrace_execution_result {
  unsigned long long frame_id;
  unsigned long long parent_frame_id;
  unsigned long long call_id;
  unsigned int flags;
  enum kctrace_execution_failure failure;
  unsigned char state;
  unsigned char level;
  /* This frame's selected level before dispatch. At canonical ENTER use
   * the surviving parent's level, or the physical floor at a new root. EXIT
   * does not change the suspended caller's copy; its own AFTER_CALL can do so.
   */
  unsigned char previous_level;
};

#ifdef __cplusplus
extern "C" {
#endif

static inline unsigned char
kctrace_execution_level(const struct kctrace_execution_context *context,
                        unsigned char state) {
  const struct kctrace_policy_state policy = kctrace_policy_decode(state);

  unsigned char level = KCTRACE_EXECUTION_ARM;
  if (policy.within && policy.mode == KCTRACE_POLICY_INTO)
    level = context->terminal   ? KCTRACE_EXECUTION_FULL
            : context->perfetto ? KCTRACE_EXECUTION_PERFETTO
                                : KCTRACE_EXECUTION_ARM;
  return level < context->minimum_level ? context->minimum_level : level;
}

/* The owner uses this when reentrant instrumentation skipped a boundary.
 * Preserve all known frames; never turn a damaged context into a new root.
 */
static inline void
kctrace_execution_poison(struct kctrace_execution_context *context,
                         enum kctrace_execution_failure failure) {
  if (failure != KCTRACE_EXECUTION_OK &&
      context->failure == KCTRACE_EXECUTION_OK)
    context->failure = failure;
}

/* No allocation, instruction analysis, memory reads, or event publication.
 * EXIT is immediately before the original RET: its result is ready, but only
 * AFTER_CALL proves the caller resumed. TAIL closes the departing frame and
 * the next ENTER inherits its surviving parent's policy, as a normal sibling.
 */
static inline __attribute__((__always_inline__)) struct kctrace_execution_result
kctrace_execution_dispatch(struct kctrace_execution_context *context,
                           const struct kctrace_execution_tables *tables,
                           const struct kctrace_execution_boundary *boundary) {
#ifdef __cplusplus
  struct kctrace_execution_result result = {};
  const struct kctrace_execution_frame empty = {};
#else
  struct kctrace_execution_result result = {0};
  const struct kctrace_execution_frame empty = {0};
#endif
  struct kctrace_execution_frame *frame = 0;
  unsigned char incoming = 0;
  unsigned char outgoing_state, outgoing_level;
  unsigned int index;

  result.level = KCTRACE_EXECUTION_FULL;
  if (context->depth && context->frames && context->depth <= context->capacity)
    frame = &context->frames[context->depth - 1];
  if (!tables || !tables->functions || !tables->paths || !boundary ||
      !boundary->site_id || !boundary->stack || !boundary->function ||
      boundary->function >= tables->function_count ||
      boundary->path >= tables->path_count ||
      boundary->kind < KCTRACE_EXECUTION_ENTER ||
      boundary->kind > KCTRACE_EXECUTION_CALL_UNPAIRED ||
      boundary->handler_within > KCTRACE_EXECUTION_HANDLER_UNKNOWN ||
      (boundary->handler_within && boundary->kind != KCTRACE_EXECUTION_ENTER) ||
      boundary->root_within > KCTRACE_EXECUTION_WITHIN_UNKNOWN ||
      (boundary->root_within &&
       (boundary->kind != KCTRACE_EXECUTION_ENTER || context->depth)) ||
      context->depth > context->capacity ||
      (context->capacity && !context->frames)) {
    kctrace_execution_poison(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
    goto unknown;
  }
  if (context->failure != KCTRACE_EXECUTION_OK)
    goto recover;
  result.previous_level = context->minimum_level;
  if (frame)
    result.previous_level = frame->level;
  if (boundary->kind == KCTRACE_EXECUTION_ENTER) {
    /* Every physical CALL has a boundary. A child without a waiting
     * caller, or an upward/same-stack entry, is an unobserved unwind.
     * Interrupt stacks belong to separate contexts owned by the caller.
     */
    if (frame && (!frame->call_id || frame->call_stack < 8 ||
                  boundary->stack >= frame->entry_stack ||
                  boundary->stack > frame->call_stack - 8)) {
      kctrace_execution_poison(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
      goto unknown;
    }
    if (context->depth == context->capacity) {
      kctrace_execution_poison(context, KCTRACE_EXECUTION_OVERFLOW);
      goto unknown;
    }
    if (context->serial == ~0ULL) {
      kctrace_execution_poison(context, KCTRACE_EXECUTION_COOKIE_EXHAUSTED);
      goto unknown;
    }
    if (frame) {
      incoming = frame->state;
      result.parent_frame_id = frame->id;
      if (frame->call_id && boundary->return_pc &&
          boundary->return_pc == frame->call_return_pc &&
          boundary->stack <= ~0ULL - 8 &&
          boundary->stack + 8 == frame->call_stack)
        result.call_id = frame->call_id;
      else
        result.flags |= KCTRACE_EXECUTION_CALLBACK;
    } else if (boundary->root_within == KCTRACE_EXECUTION_WITHIN_ACTIVE) {
      incoming = 1;
    }
    frame = &context->frames[context->depth++];
    *frame = empty;
    frame->id = ++context->serial;
    frame->parent_id = result.parent_frame_id;
    frame->incoming_call = result.call_id;
    frame->entry_stack = boundary->stack;
    frame->function = boundary->function;
    if (boundary->root_within == KCTRACE_EXECUTION_WITHIN_UNKNOWN) {
      /* Preserve a bounded physical root anchor, without inventing
       * policy. Its known EXIT/TAIL can end this temporary uncertainty.
       */
      result.frame_id = frame->id;
      kctrace_execution_poison(context, KCTRACE_EXECUTION_INHERITED_UNKNOWN);
      goto unknown;
    }
    frame->base_state =
        tables->functions[boundary->function].states[incoming & 7];
    if (boundary->handler_within == KCTRACE_EXECUTION_HANDLER_UNKNOWN &&
        !(frame->base_state & 1)) {
      result.frame_id = frame->id;
      kctrace_execution_poison(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
      goto unknown;
    }
    if (boundary->handler_within == KCTRACE_EXECUTION_HANDLER_PROVED) {
      frame->base_state |= 1;
      result.flags |= KCTRACE_EXECUTION_HANDLER_CRITERION;
    }
    frame->state = frame->base_state;
    frame->level = kctrace_execution_level(context, frame->state);
    if (frame->level < tables->functions[frame->function].minimum_level)
      frame->level = tables->functions[frame->function].minimum_level;
  } else if (!frame || frame->function != boundary->function ||
             boundary->stack > frame->entry_stack) {
    kctrace_execution_poison(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
    goto unknown;
  }
  result.frame_id = frame->id;
  result.parent_frame_id = frame->parent_id;
  result.call_id = frame->incoming_call;
  outgoing_state =
      boundary->path
          ? tables->paths[boundary->path].states[frame->base_state & 7]
          : frame->base_state;
  outgoing_level = kctrace_execution_level(context, outgoing_state);
  if (outgoing_level < tables->functions[frame->function].minimum_level)
    outgoing_level = tables->functions[frame->function].minimum_level;
  if (boundary->kind == KCTRACE_EXECUTION_EXIT ||
      boundary->kind == KCTRACE_EXECUTION_TAIL) {
    if (boundary->stack != frame->entry_stack || frame->call_id) {
      kctrace_execution_poison(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
      goto unknown;
    }
    if (boundary->kind == KCTRACE_EXECUTION_EXIT && context->terminal &&
        kctrace_policy_decode(frame->base_state).within &&
        kctrace_policy_decode(frame->base_state).mode != KCTRACE_POLICY_SKIP)
      result.flags |= KCTRACE_EXECUTION_RETURN_VALUE;
    context->depth--;
  } else {
    if (boundary->kind == KCTRACE_EXECUTION_CALL ||
        boundary->kind == KCTRACE_EXECUTION_CALL_UNPAIRED) {
      if (frame->call_id || boundary->stack < 8 ||
          (boundary->kind == KCTRACE_EXECUTION_CALL
               ? !boundary->related_site_id
               : boundary->related_site_id != 0) ||
          !boundary->call_returns[outgoing_level] || context->serial == ~0ULL) {
        kctrace_execution_poison(context,
                                 context->serial == ~0ULL
                                     ? KCTRACE_EXECUTION_COOKIE_EXHAUSTED
                                     : KCTRACE_EXECUTION_BAD_BOUNDARY);
        goto unknown;
      }
      frame->call_id = ++context->serial;
      frame->call_site = boundary->site_id;
      frame->call_stack = boundary->stack;
      frame->call_return_pc = boundary->call_returns[outgoing_level];
      frame->return_site = boundary->related_site_id;
      result.call_id = frame->call_id;
    } else if (boundary->kind == KCTRACE_EXECUTION_AFTER_CALL) {
      if (!frame->call_id || frame->call_site != boundary->related_site_id ||
          frame->return_site != boundary->site_id ||
          frame->call_stack != boundary->stack) {
        kctrace_execution_poison(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
        goto unknown;
      }
      result.call_id = frame->call_id;
      frame->call_id = 0;
      if (context->terminal && kctrace_policy_decode(frame->state).within &&
          kctrace_policy_decode(frame->state).mode == KCTRACE_POLICY_INTO)
        result.flags |= KCTRACE_EXECUTION_RETURN_VALUE;
    } else if (frame->call_id) {
      /* A suspended caller cannot execute another ordinary boundary.
       */
      kctrace_execution_poison(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
      goto unknown;
    }
    frame->path = boundary->path;
    frame->state = outgoing_state;
    frame->level = outgoing_level;
    if (boundary->kind == KCTRACE_EXECUTION_ENTER && context->terminal &&
        kctrace_policy_decode(frame->base_state).within &&
        kctrace_policy_decode(frame->base_state).mode != KCTRACE_POLICY_SKIP)
      result.flags |= KCTRACE_EXECUTION_ENTRY_VALUES;
  }
  result.state = frame->state;
  result.level = frame->level;
  if (result.level != result.previous_level)
    result.flags |= KCTRACE_EXECUTION_LEVEL_CHANGED;
  return result;

recover:
  /* Unknown frames have no fabricated identity or policy. Only a known
   * saved call boundary or entry stack can recover a bounded stack
   * prefix. Stay in FULL until that known root has actually reached
   * EXIT/TAIL.
   */
  for (index = context->depth; index; index--) {
    frame = &context->frames[index - 1];
    if (frame->function != boundary->function)
      continue;
    if (boundary->kind == KCTRACE_EXECUTION_AFTER_CALL && frame->call_id &&
        frame->call_site == boundary->related_site_id &&
        frame->return_site == boundary->site_id &&
        frame->call_stack == boundary->stack) {
      result.frame_id = frame->id;
      result.parent_frame_id = frame->parent_id;
      result.call_id = frame->call_id;
      frame->call_id = 0;
      context->depth = index;
      break;
    }
    if ((boundary->kind == KCTRACE_EXECUTION_EXIT ||
         boundary->kind == KCTRACE_EXECUTION_TAIL) &&
        frame->entry_stack == boundary->stack) {
      result.frame_id = frame->id;
      result.parent_frame_id = frame->parent_id;
      result.call_id = frame->incoming_call;
      context->depth = index - 1;
      if (!context->depth &&
          context->failure != KCTRACE_EXECUTION_COOKIE_EXHAUSTED) {
        result.failure = context->failure;
        context->failure = KCTRACE_EXECUTION_OK;
        result.flags |= KCTRACE_EXECUTION_RECOVERED;
      }
      break;
    }
  }
unknown:
  result.flags |= KCTRACE_EXECUTION_UNKNOWN;
  if (!result.failure)
    result.failure = context->failure;
  if (result.failure)
    result.flags |= KCTRACE_EXECUTION_DISCONTINUITY;
  result.level = KCTRACE_EXECUTION_FULL;
  result.state = 0;
  return result;
}

#ifdef __cplusplus
}
#endif

#endif
