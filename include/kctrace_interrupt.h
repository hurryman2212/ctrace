/* SPDX-License-Identifier: MIT */
#ifndef KCTRACE_INTERRUPT_H
#define KCTRACE_INTERRUPT_H

/* Private shared validation contract, not a serialized ABI. The caller proves
 * metadata ownership, window bounds/nonoverlap and the original CFG offline.
 * Runtime binding supplies bounded byte snapshots and a nofault static-key
 * value. No allocation, kernel memory access or instruction decoding here.
 */
enum kctrace_interrupt_patch_kind {
	KCTRACE_INTERRUPT_INDIRECT_CALL,
	KCTRACE_INTERRUPT_RETURN_THUNK,
	KCTRACE_INTERRUPT_ENDBR_SEAL,
	KCTRACE_INTERRUPT_TRACEPOINT_CALL,
	KCTRACE_INTERRUPT_WARNING_CALL,
	KCTRACE_INTERRUPT_JUMP_LABEL,
	KCTRACE_INTERRUPT_RELOCATE32,
	KCTRACE_INTERRUPT_RELOCATE64,
};

struct kctrace_interrupt_patch {
	unsigned long long pc;
	/* Thunk, exact jump target, or the static key's initial function. */
	unsigned long long target;
	unsigned long long key;
	unsigned char kind;
	unsigned char size;
	unsigned char reg;
};

/* One non-RT serving-softirq lane. Nested or unbalanced notifications cannot
 * authorize a callback; a registration epoch prevents stale reuse after the
 * last binding detaches. The caller excludes hard IRQ/NMI and CPU migration.
 */
struct kctrace_interrupt_token {
	unsigned long long epoch;
	unsigned long long object;
	unsigned long long target;
	unsigned int depth;
	unsigned int valid;
	unsigned int consumed;
};

static inline void kctrace_interrupt_token_enter(struct kctrace_interrupt_token *token,
						 unsigned long long epoch,
						 unsigned long long object,
						 unsigned long long target)
{
	if (token->epoch != epoch) {
		token->epoch = epoch;
		token->depth = 0;
	}
	token->valid = 0;
	token->consumed = 0;
	if (!epoch || token->depth == ~0U)
		return;
	if (token->depth++ || !object || !target)
		return;
	token->object = object;
	token->target = target;
	token->valid = 1;
}

static inline void kctrace_interrupt_token_exit(struct kctrace_interrupt_token *token,
						unsigned long long epoch, unsigned long long object)
{
	if (!epoch || token->epoch != epoch || !token->depth || token->depth == ~0U)
		return;
	token->valid = 0;
	if (token->depth > 1 || token->object == object)
		token->depth--;
}

/* Invoke only after the dispatcher's exact CALL-end return PC was matched.
 * Even a filtered callback consumes its token, so H -> tail G cannot reuse it.
 * Return -1 for an unproved invocation, 0 for an already consumed invocation,
 * and 1 for its exact callback entry. Unknown never establishes a within root.
 */
static inline int kctrace_interrupt_token_consume(struct kctrace_interrupt_token *token,
						  unsigned long long epoch,
						  unsigned long long object,
						  unsigned long long target,
						  unsigned long long canonical)
{
	if (!epoch || token->epoch != epoch || token->depth != 1)
		return -1;
	if (token->consumed)
		return 0;
	if (!token->valid || !canonical || object != token->object || target != token->target ||
	    canonical != target) {
		/* A changed payload cannot later become a match after a tail call. */
		token->valid = 0;
		return -1;
	}
	token->valid = 0;
	token->consumed = 1;
	return 1;
}

static inline unsigned long long
kctrace_interrupt_word(const unsigned char *bytes, unsigned int count)
{
	unsigned long long result = 0;
	unsigned int index;

	for (index = 0; index < count; index++)
		result |= (unsigned long long)bytes[index] << (index * 8);
	return result;
}

static inline int kctrace_interrupt_equal(const unsigned char *left,
					  const unsigned char *right,
					  unsigned int count)
{
	unsigned int index;

	for (index = 0; index < count; index++)
		if (left[index] != right[index])
			return 0;
	return 1;
}

/* Read a signed rel32 without unaligned access or implementation-defined casts.
 */
static inline unsigned long long
kctrace_interrupt_relative(const unsigned char *field)
{
	unsigned long long value = kctrace_interrupt_word(field, 4);

	return value & 0x80000000ULL ? value | 0xffffffff00000000ULL : value;
}

/* All addresses are unsigned x86-64 addresses. Original PCs/targets are link
 * addresses; key_function and return_zero are live addresses. The latter must
 * be the separately proved __static_call_return0, not an arbitrary caller
 * supplied target. Set it to zero if that alternative was not proved.
 * A key/code disagreement or an in-progress INT3 update rejects this binding.
 */
static inline int
kctrace_interrupt_patch_matches(const struct kctrace_interrupt_patch *patch,
				const unsigned char *original, const unsigned char *live,
				unsigned int available, unsigned long long slide,
				unsigned long long key_function, unsigned long long return_zero)
{
	static const unsigned char endbr[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	static const unsigned char sealed[] = { 0x0f, 0x1f, 0x40, 0xd6 };
	static const unsigned char ret[] = { 0xc3, 0xcc, 0xcc, 0xcc, 0xcc };
	static const unsigned char nop2[] = { 0x66, 0x90 };
	static const unsigned char nop5[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	static const unsigned char xor5[] = { 0x2e, 0x2e, 0x2e, 0x31, 0xc0 };
	static const unsigned char warn5[] = { 0x67, 0x48, 0x0f, 0xb9, 0x3a };
	unsigned long long target, trampoline;
	unsigned int index, prefix, size;

	if (!patch || !original || !live || !patch->pc || !patch->size ||
	    patch->size > available || patch->size > 8 ||
	    patch->kind > KCTRACE_INTERRUPT_RELOCATE64)
		return 0;
	size = patch->size;
	if (patch->kind != KCTRACE_INTERRUPT_INDIRECT_CALL && patch->reg)
		return 0;
	if (patch->kind != KCTRACE_INTERRUPT_TRACEPOINT_CALL &&
	    patch->kind != KCTRACE_INTERRUPT_WARNING_CALL && patch->key)
		return 0;
	switch (patch->kind) {
	case KCTRACE_INTERRUPT_INDIRECT_CALL:
		if ((size != 5 && size != 6) || patch->reg > 15 ||
		    patch->reg == 4 || !patch->target)
			return 0;
		prefix = size - 5;
		if ((prefix && original[0] != 0x2e) ||
		    original[prefix] != 0xe8 ||
		    patch->pc + size +
				    kctrace_interrupt_relative(original +
							       prefix + 1) !=
			    patch->target)
			return 0;
		if (kctrace_interrupt_equal(original, live, size))
			return 1;
		index = 0;
		/* Supported LFENCE and CS padding forms preserve the original CALL end. */
		if (live[0] == 0x0f && live[1] == 0xae && live[2] == 0xe8)
			index = 3;
		while (index < size && live[index] == 0x2e)
			index++;
		if (patch->reg >= 8) {
			if (index >= size || live[index++] != 0x41)
				return 0;
		}
		return index + 2 == size && live[index] == 0xff &&
		       live[index + 1] == 0xd0 + (patch->reg & 7);
	case KCTRACE_INTERRUPT_RETURN_THUNK:
		return size == 5 && patch->target && original[0] == 0xe9 &&
		       patch->pc + 5 +
				       kctrace_interrupt_relative(original +
								  1) ==
			       patch->target &&
		       (kctrace_interrupt_equal(original, live, size) ||
			kctrace_interrupt_equal(ret, live, size));
	case KCTRACE_INTERRUPT_ENDBR_SEAL:
		return size == 4 && !patch->target &&
		       kctrace_interrupt_equal(original, endbr, size) &&
		       (kctrace_interrupt_equal(endbr, live, size) ||
			kctrace_interrupt_equal(sealed, live, size));
	case KCTRACE_INTERRUPT_TRACEPOINT_CALL:
	case KCTRACE_INTERRUPT_WARNING_CALL:
		if (size != 5 || !patch->key || !patch->target ||
		    original[0] != 0xe8)
			return 0;
		trampoline = patch->pc + 5 +
			     kctrace_interrupt_relative(original + 1) + slide;
		if (patch->kind == KCTRACE_INTERRUPT_WARNING_CALL) {
			if (key_function != patch->target + slide)
				return 0;
			if (kctrace_interrupt_equal(warn5, live, size))
				return 1;
		} else {
			if (!key_function &&
			    kctrace_interrupt_equal(nop5, live, size))
				return 1;
			if (return_zero && key_function == return_zero &&
			    kctrace_interrupt_equal(xor5, live, size))
				return 1;
		}
		if (live[0] != 0xe8)
			return 0;
		target = patch->pc + slide + 5 +
			 kctrace_interrupt_relative(live + 1);
		return target == trampoline ||
		       (key_function && target == key_function);
	case KCTRACE_INTERRUPT_JUMP_LABEL:
		if ((size != 2 && size != 5) || !patch->target)
			return 0;
		if (size == 2) {
			if (!kctrace_interrupt_equal(original, nop2, size) &&
			    (original[0] != 0xeb ||
			     patch->pc + 2 +
					     ((unsigned long long)original[1] |
					      (original[1] & 0x80 ? ~0xffULL :
								    0)) !=
				     patch->target))
				return 0;
			return kctrace_interrupt_equal(live, nop2, size) ||
			       (live[0] == 0xeb &&
				patch->pc + 2 +
						((unsigned long long)live[1] |
						 (live[1] & 0x80 ? ~0xffULL :
								   0)) ==
					patch->target);
		}
		if (!kctrace_interrupt_equal(original, nop5, size) &&
		    (original[0] != 0xe9 ||
		     patch->pc + 5 + kctrace_interrupt_relative(original + 1) !=
			     patch->target))
			return 0;
		return kctrace_interrupt_equal(live, nop5, size) ||
		       (live[0] == 0xe9 &&
			patch->pc + 5 + kctrace_interrupt_relative(live + 1) ==
				patch->target);
	case KCTRACE_INTERRUPT_RELOCATE32:
		return size == 4 && !patch->target &&
		       kctrace_interrupt_word(live, 4) ==
			       ((kctrace_interrupt_word(original, 4) + slide) &
				0xffffffffULL);
	case KCTRACE_INTERRUPT_RELOCATE64:
		return size == 8 && !patch->target &&
		       kctrace_interrupt_word(live, 8) ==
			       kctrace_interrupt_word(original, 8) + slide;
	}
	return 0;
}

#endif
