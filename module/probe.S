/* SPDX-License-Identifier: MIT */
#include <linux/linkage.h>
#include <asm/ibt.h>

#include "probe.h"

/*
 * Supported callers have a valid kernel stack and the normal DF=0/AC=0 ABI.
 * The offline verifier excludes unsupported flag, stack and FPU transitions.
 * The caller saves flags before CALL and restores them after return. Keeping
 * both operations outside this function also contains call/return thunks which
 * alter flags before entry or after return state has been restored.
 */
.macro KCTRACE_FULL_ENTRY name, handler, selector=0
SYM_FUNC_START(\name)
	ENDBR
	pushq %rbp
	movq %rsp, %rbp
	pushq %rax
	pushq %rbx
	pushq %rcx
	pushq %rdx
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	movq %rsp, %rdi
	andq $-16, %rsp
	call \handler
	leaq -KCTRACE_PROBE_RBP_OFFSET(%rbp), %rsp
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rdi
	popq %rsi
	popq %rdx
	popq %rcx
	popq %rbx
	.if \selector
	leaq 8(%rsp), %rsp
	.else
	popq %rax
	.endif
	popq %rbp
	RET
SYM_FUNC_END(\name)
.endm

KCTRACE_FULL_ENTRY kctrace_probe, kctrace_probe_saved
KCTRACE_FULL_ENTRY kctrace_probe_fpu, kctrace_probe_fpu_saved
KCTRACE_FULL_ENTRY kctrace_probe_amx, kctrace_probe_amx_saved
KCTRACE_FULL_ENTRY kctrace_probe_extended, kctrace_probe_extended_saved
/* Selector keeps returned EAX; the outer gate restores original RAX. */
KCTRACE_FULL_ENTRY kctrace_select, kctrace_select_saved, 1
KCTRACE_FULL_ENTRY kctrace_select_fpu, kctrace_select_fpu_saved, 1
KCTRACE_FULL_ENTRY kctrace_select_amx, kctrace_select_amx_saved, 1
KCTRACE_FULL_ENTRY kctrace_select_extended, kctrace_select_extended_saved, 1

/* The C helper preserves RBX and R12-R15 through the ordinary kernel ABI. */
SYM_FUNC_START(kctrace_perfetto_probe)
	ENDBR
	pushq %rbp
	movq %rsp, %rbp
	pushq %rax
	pushq %rcx
	pushq %rdx
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	movq %rsp, %rdi
	andq $-16, %rsp
	call kctrace_perfetto_saved
	leaq -KCTRACE_PERFETTO_RBP_OFFSET(%rbp), %rsp
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rdi
	popq %rsi
	popq %rdx
	popq %rcx
	popq %rax
	popq %rbp
	RET
SYM_FUNC_END(kctrace_perfetto_probe)
