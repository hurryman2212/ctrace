/* SPDX-License-Identifier: MIT */
#ifndef KCTRACE_PROBE_H
#define KCTRACE_PROBE_H

/* Private ABI for PUSHFQ; CALL kctrace_probe; POPFQ instrumentation. */
#define KCTRACE_PROBE_RBP_OFFSET	112
#define KCTRACE_PROBE_FRAME_SIZE	136

/* Selector gate: PUSHFQ; PUSH RAX; CALL; select arm; POP RAX; POPFQ; JMP. */
#define KCTRACE_SELECT_RBP_OFFSET	112
#define KCTRACE_SELECT_FRAME_SIZE	144

/* Perfetto boundary: PUSHFQ; CALL kctrace_perfetto_probe; POPFQ. */
#define KCTRACE_PERFETTO_RBP_OFFSET	72
#define KCTRACE_PERFETTO_FRAME_SIZE	96

#ifndef __ASSEMBLER__
#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>

struct kctrace_probe_frame {
	u64 r15, r14, r13, r12, r11, r10, r9, r8;
	u64 rdi, rsi, rdx, rcx, rbx, rax, rbp, return_pc, flags;
};

static_assert(sizeof(struct kctrace_probe_frame) == KCTRACE_PROBE_FRAME_SIZE);
static_assert(offsetof(struct kctrace_probe_frame, rbp) == KCTRACE_PROBE_RBP_OFFSET);
static_assert(offsetof(struct kctrace_probe_frame, return_pc) ==
	      KCTRACE_PROBE_FRAME_SIZE - 2 * sizeof(u64));
static_assert(offsetof(struct kctrace_probe_frame, flags) ==
	      KCTRACE_PROBE_FRAME_SIZE - sizeof(u64));

/* Only call through the seven-byte boundary sequence documented above. */
void kctrace_probe(void);
/* The frame is valid only during this call. Original RSP is frame + 1. */
void kctrace_probe_saved(const struct kctrace_probe_frame *frame);

struct kctrace_select_frame {
	u64 r15, r14, r13, r12, r11, r10, r9, r8;
	u64 rdi, rsi, rdx, rcx, rbx, rax, rbp, return_pc, original_rax, flags;
};

static_assert(sizeof(struct kctrace_select_frame) == KCTRACE_SELECT_FRAME_SIZE);
static_assert(offsetof(struct kctrace_select_frame, rbp) ==
	      KCTRACE_SELECT_RBP_OFFSET);
static_assert(offsetof(struct kctrace_select_frame, return_pc) ==
	      KCTRACE_SELECT_FRAME_SIZE - 3 * sizeof(u64));
static_assert(offsetof(struct kctrace_select_frame, original_rax) ==
	      KCTRACE_SELECT_FRAME_SIZE - 2 * sizeof(u64));
static_assert(offsetof(struct kctrace_select_frame, flags) ==
	      KCTRACE_SELECT_FRAME_SIZE - sizeof(u64));

/* Only call through the selector gate. Its outer saved RAX remains intact. */
unsigned int kctrace_select(void);
/* Frame lifetime is this call; original RSP is frame + 1. Return level in EAX. */
unsigned int kctrace_select_saved(const struct kctrace_select_frame *frame);

struct kctrace_perfetto_frame {
	u64 r11, r10, r9, r8, rdi, rsi, rdx, rcx, rax, rbp, return_pc, flags;
};

static_assert(sizeof(struct kctrace_perfetto_frame) ==
	      KCTRACE_PERFETTO_FRAME_SIZE);
static_assert(offsetof(struct kctrace_perfetto_frame, rbp) ==
	      KCTRACE_PERFETTO_RBP_OFFSET);
static_assert(offsetof(struct kctrace_perfetto_frame, return_pc) ==
	      KCTRACE_PERFETTO_FRAME_SIZE - 2 * sizeof(u64));
static_assert(offsetof(struct kctrace_perfetto_frame, flags) ==
	      KCTRACE_PERFETTO_FRAME_SIZE - sizeof(u64));

/* Timing-only boundary: this frame has no callee-saved value snapshot. */
void kctrace_perfetto_probe(void);
/* The frame is valid only during this call. Original RSP is frame + 1. */
void kctrace_perfetto_saved(const struct kctrace_perfetto_frame *frame);
#endif
#endif
