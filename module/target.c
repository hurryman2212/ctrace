// SPDX-License-Identifier: MIT
#include <linux/bug.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/objtool_types.h>
#define INCLUDE_VERMAGIC
#include <linux/vermagic.h>

#include <asm/orc_types.h>

#include "kctrace/contract.h"
#include "target.h"

/* annotations.S emits this selected-kernel hint layout for external labels. */
static_assert(sizeof(struct unwind_hint) == 12);
static_assert(offsetof(struct unwind_hint, ip) == 0);
static_assert(offsetof(struct unwind_hint, sp_offset) == 4);
static_assert(offsetof(struct unwind_hint, sp_reg) == 6);
static_assert(offsetof(struct unwind_hint, type) == 7);
static_assert(offsetof(struct unwind_hint, signal) == 8);

/*
 * Compare original ORC bytes with compiler-produced bitfields, not a guessed
 * layout. This build-only witness is discarded by the final module linker.
 */
const struct orc_entry __ctrace_entry_unwind __used __section(".discard.ctrace_entry_unwind") = {
	.sp_offset = 8,
	.sp_reg = ORC_REG_SP,
	.bp_reg = ORC_REG_UNDEFINED,
	.type = ORC_TYPE_CALL,
};

const struct kctrace_manifest
	__ctrace_manifest __used __section(".init.rodata.ctrace_manifest") = {};
const __u64 __ctrace_layout[] __used __section(".init.rodata.ctrace_layout") = {
	sizeof(struct module),
	offsetof(struct module, init),
	offsetof(struct module, exit),
};

const __u64 __ctrace_param_layout[] __used __section(".init.rodata.ctrace_param_layout") = {
	sizeof(struct kernel_param),
	offsetof(struct kernel_param, ops),
	sizeof(const struct kernel_param_ops),
	offsetof(const struct kernel_param_ops, free),
};

/* Offline dispatch proofs use the selected Kbuild's actual callback fields. */
const __u64 __ctrace_interrupt_layout[] __used __section(".discard.ctrace_interrupt_layout") = {
	offsetof(struct irq_desc, action),  offsetof(struct irqaction, handler),
	offsetof(struct irqaction, next),   offsetof(struct irqaction, thread_fn),
	offsetof(struct hrtimer, function),
	offsetof(struct tasklet_struct, func),
	offsetof(struct tasklet_struct, data),
};

/* WARN reachability must use this kernel's flags field, not a guessed ABI. */
const __u64 __ctrace_bug_layout[4] __used __section(".discard.ctrace_bug_layout") = {
#ifdef CONFIG_GENERIC_BUG
	sizeof(struct bug_entry),
	offsetof(struct bug_entry, flags),
	sizeof(((struct bug_entry *)0)->flags),
	BUGFLAG_WARNING,
#endif
};

struct kctrace_binding *__ctrace_binding __section(".bss.ctrace_binding");
const struct kctrace_bootstrap
	__ctrace_bootstrap __used __section(".init.rodata.ctrace_bootstrap") = {
	.size = sizeof(struct kctrace_bootstrap),
	.contract_sha256 = KCTRACE_CONTRACT_BYTES,
	.manifest = (unsigned long)&__ctrace_manifest,
	.program = (unsigned long)&__ctrace_program,
	.site_count_address = (unsigned long)&__ctrace_site_count,
	.capture_plans = (unsigned long)__ctrace_capture_plans,
	.capture_plan_count_address = (unsigned long)&__ctrace_capture_plan_count,
	.binding_slot = (unsigned long)&__ctrace_binding,
};

const char __ctrace_vermagic[] __used __section(".init.rodata.ctrace_vermagic") = VERMAGIC_STRING;

int __init __ctrace_init(void)
{
	struct kctrace_binding *binding;
	int result;

	/* Pairs with COMING's release after immutable tables are registered. */
	binding = smp_load_acquire(&__ctrace_binding);
	if (!binding)
		return -ENXIO;
	result = init_module();
	kctrace_initialized(binding, result);
	return result;
}

void __exit __ctrace_exit(void)
{
	cleanup_module();
}
