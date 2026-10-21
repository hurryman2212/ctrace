// SPDX-License-Identifier: MIT
/*
 * Pre-generated probes: no decoding, code generation or rendering.
 */
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/buildid.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/irq_work.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/min_heap.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/overflow.h>
#include <linux/percpu.h>
#include <linux/poll.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include <asm/cpufeature.h>
#include <asm/cpuid/api.h>
#include <asm/fpu/xcr.h>
#include <asm/msr.h>
#include <asm/pgtable_64_types.h>
#include <asm/special_insns.h>
#include <trace/events/irq.h>

#include "kctrace/contract.h"
#include "kctrace/execution.h"
#include "kctrace/interrupt.h"
#include "kctrace/runtime.h"
#include "probe.h"

/* Absorb short mixed task/IRQ bursts while bounding per-session memory. */
static const unsigned int default_events_per_cpu = 512;
static const unsigned int execution_task_count = 256;
static const unsigned int execution_frame_count = 128;
static const unsigned int execution_irq_frame_count = 32;

/* Standard XSAVE layout, restricted to validated user FPU components. */
static u64 xstate_mask;
static u64 xstate_fpu_mask;
static u64 scalar_mask;
static unsigned int xstate_bytes, amx_bytes;
static unsigned int xstate_offsets[19], xstate_sizes[19];
static DEFINE_PER_CPU(void *, xstate_storage);
static DEFINE_PER_CPU(void *, amx_storage);
static bool amx_ready;

/* These bytes belong to our private snapshot, never an XRSTOR input. They
 * occupy the XSAVE software area and reserved header bytes after XSAVE has
 * finished, preserving the ordinary FPU/AMX buffer sizes.
 */
static const struct {
	u8 component, count;
	u16 offset;
	u32 msrs[3];
} supervisor_components[] = {
	{ 10, 1, 464, { MSR_IA32_PASID } },
	{ 11, 2, 472, { MSR_IA32_U_CET, MSR_IA32_PL3_SSP } },
	{ 12, 3, 488, { MSR_IA32_PL0_SSP, MSR_IA32_PL1_SSP, MSR_IA32_PL2_SSP } },
	{ 13, 1, 528, { 0xdb1 } }, /* IA32_PM_CTL1 */
	{ 16, 1, 536, { MSR_HWP_REQUEST } },
};

enum kctrace_capture_mode {
	KCTRACE_CAPTURE_INTEGER,
	KCTRACE_CAPTURE_FPU,
	KCTRACE_CAPTURE_AMX,
	KCTRACE_CAPTURE_EXTENDED,
};

static bool kctrace_xstate_range(const struct kctrace_capture *capture)
{
	u64 offset = capture->offset;

	if (capture->reg >= ARRAY_SIZE(xstate_sizes) ||
	    !((xstate_mask | scalar_mask) & BIT_ULL(capture->reg)) || capture->offset < 0 ||
	    !capture->size || capture->size > 8)
		return false;
	if (!capture->reg)
		return (offset < 24 && capture->size <= 24 - offset) ||
		       (offset >= 32 && offset < 160 && capture->size <= 16 - (offset - 32) % 16);
	if (capture->reg == 1)
		return (offset >= 24 && offset < 28 && capture->size <= 28 - offset) ||
		       (offset >= 160 && offset < 416 && capture->size <= 416 - offset);
	return offset < xstate_sizes[capture->reg] &&
	       capture->size <= xstate_sizes[capture->reg] - offset;
}

static void kctrace_free_xstate(void)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		kfree(per_cpu(xstate_storage, cpu));
		per_cpu(xstate_storage, cpu) = NULL;
		kfree(per_cpu(amx_storage, cpu));
		per_cpu(amx_storage, cpu) = NULL;
	}
}

/* Called with sessions_lock before any xstate-bearing binding is published. */
static int kctrace_prepare_xstate(struct kctrace_capture_plan *plans, unsigned int count)
{
	unsigned int index, cpu;
	u64 required = 0;
	bool fpu = false, amx = false;

	/* Generated next IDs increase, so every suffix mask is ready on this pass. */
	for (index = count; index; index--) {
		struct kctrace_capture_plan *plan = &plans[index - 1];

		if (plan->next)
			plan->xstate_mask |= plans[plan->next - 1].xstate_mask;
		required |= plan->xstate_mask;
		amx |= !!(plan->xstate_mask & KCTRACE_XSTATE_AMX);
		fpu |= plan->xstate_mask && !(plan->xstate_mask & KCTRACE_XSTATE_AMX);
	}
	if (!required)
		return 0;
	if (required & ~(xstate_mask | scalar_mask))
		return -EOPNOTSUPP;
	for_each_possible_cpu(cpu) {
		if (fpu && !per_cpu(xstate_storage, cpu)) {
			per_cpu(xstate_storage, cpu) = kzalloc(xstate_bytes + 63, GFP_KERNEL);
			if (!per_cpu(xstate_storage, cpu)) {
				unsigned int rollback;

				/* The pool is first published only after all CPUs
				 * have storage; a later successful pool never grows.
				 */
				for_each_possible_cpu(rollback) {
					kfree(per_cpu(xstate_storage, rollback));
					per_cpu(xstate_storage, rollback) = NULL;
				}
				return -ENOMEM;
			}
		}
	}
	if (amx && !amx_ready) {
		for_each_possible_cpu(cpu) {
			per_cpu(amx_storage, cpu) = kzalloc(amx_bytes + 63, GFP_KERNEL);
			if (!per_cpu(amx_storage, cpu)) {
				unsigned int rollback;

				for_each_possible_cpu(rollback) {
					kfree(per_cpu(amx_storage, rollback));
					per_cpu(amx_storage, rollback) = NULL;
				}
				return -ENOMEM;
			}
		}
		amx_ready = true;
	}
	return 0;
}

/* One softirq lane and both softirq states for every hardirq nesting value. */
#define KCTRACE_IRQ_LANES	(1 + 2 * ((1U << HARDIRQ_BITS) - 1))

struct kctrace_landing {
	u64 pc;
	u32 function;
	u32 kind;
};

struct kctrace_program_table {
	struct kctrace_copy_probe *probes;
	struct kctrace_gate_site *gates;
	struct kctrace_execution_function *functions;
	struct kctrace_execution_path *paths;
	struct kctrace_capture_plan *plans;
	struct kctrace_landing *landings;
	struct kctrace_interrupt_dispatch *handlers;
	u64 *handler_entries;
	struct kctrace_execution_tables policy;
	unsigned int probe_count;
	unsigned int gate_count;
	unsigned int plan_count;
	unsigned int landing_count;
	unsigned int handler_count;
	u32 flags;
	u32 minimum_level;
};

struct kctrace_task_state {
	struct task_struct *task;
	u64 start_ns;
	struct kctrace_execution_context execution;
};

struct kctrace_irq_state {
	struct kctrace_execution_context lanes[KCTRACE_IRQ_LANES];
	struct kctrace_execution_frame *frames;
};

static void kctrace_free_irqs(struct kctrace_irq_state __percpu *irqs)
{
	unsigned int cpu;

	if (!irqs)
		return;
	for_each_possible_cpu(cpu)
		kvfree(per_cpu_ptr(irqs, cpu)->frames);
	free_percpu(irqs);
}

static void kctrace_free_program(struct kctrace_program_table *table)
{
	if (!table)
		return;
	kvfree(table->probes);
	kvfree(table->gates);
	kvfree(table->functions);
	kvfree(table->paths);
	kvfree(table->plans);
	kvfree(table->landings);
	kvfree(table->handlers);
	kvfree(table->handler_entries);
	kfree(table);
}

struct kctrace_probe_table {
	unsigned int count;
	unsigned int plan_count;
	struct kctrace_capture_plan *plans;
	struct kctrace_probe_site sites[];
};

static void kctrace_free_table(struct kctrace_probe_table *table)
{
	if (table) {
		kvfree(table->plans);
		kvfree(table);
	}
}

struct kctrace_ring {
	raw_spinlock_t lock;
	struct kctrace_event *events;
	unsigned int head;
	unsigned int tail;
	unsigned int used;
};

struct kctrace_head {
	u64 sequence;
	unsigned int cpu;
};

DEFINE_MIN_HEAP(struct kctrace_head, kctrace_heads);

struct kctrace_binding {
	struct list_head link;
	struct list_head probe_link;
	struct kref refs;
	struct mutex consume; /* Serializes readers of all per-CPU rings. */
	wait_queue_head_t readable;
	wait_queue_head_t drained;
	struct irq_work wakeup;
	struct kctrace_ring __percpu *rings;
	struct kctrace_prepare prepared;
	struct module *target;
	struct kctrace_binding **target_slot;
	struct kctrace_probe_table __rcu *probe_table;
	struct kctrace_probe_table *core_table;
	struct kctrace_program_table __rcu *program;
	struct kctrace_program_table *core_program;
	struct kctrace_task_state *tasks;
	struct kctrace_execution_frame *frames;
	struct kctrace_irq_state __percpu *irqs;
	raw_spinlock_t task_lock;
	atomic64_t sequence;
	atomic64_t produced;
	atomic64_t dropped;
	atomic64_t buffered;
	atomic_t active;
	u64 session_id;
	u64 generation;
	u32 state;
	u32 levels;
	int init_result;
	bool enabled;
	bool bound;
	bool owner_present;
	bool tasklet_hooks;
};

static LIST_HEAD(sessions);
static LIST_HEAD(probe_bindings);
static DEFINE_MUTEX(sessions_lock);
static atomic64_t next_session = ATOMIC64_INIT(0);
static atomic64_t next_generation = ATOMIC64_INIT(0);
struct kctrace_recorder_state {
	unsigned int depth;
	unsigned int domain;
};

static DEFINE_PER_CPU(struct kctrace_recorder_state, recorder_state);

static DEFINE_PER_CPU(struct kctrace_interrupt_token, tasklet_token);
static u64 tasklet_epoch;

#ifdef CONFIG_TRACEPOINTS
struct kctrace_tasklet_tracepoints {
	struct tracepoint *entry;
	struct tracepoint *exit;
	bool duplicate;
};

static struct kctrace_tasklet_tracepoints tasklet_points;
static unsigned int tasklet_users;
static u64 next_tasklet_epoch;
static bool tasklet_entry_registered;
static bool tasklet_exit_registered;
static bool tasklet_pinned;
#endif

static unsigned int notrace kctrace_current_domain(void)
{
	unsigned int hardirq = hardirq_count() >> HARDIRQ_SHIFT;
	unsigned int softirq = !!in_serving_softirq();

	if (hardirq)
		return 2 + 2 * (hardirq - 1) + softirq;
	return softirq;
}

#ifdef CONFIG_TRACEPOINTS
static void notrace kctrace_tasklet_entry(void *unused, struct tasklet_struct *tasklet,
					  void *function)
{
	if (in_nmi() || kctrace_current_domain() != 1)
		return;
	kctrace_interrupt_token_enter(this_cpu_ptr(&tasklet_token), READ_ONCE(tasklet_epoch),
				      (unsigned long)tasklet, (unsigned long)function);
}

static void notrace kctrace_tasklet_exit(void *unused, struct tasklet_struct *tasklet,
					 void *function)
{
	if (in_nmi() || kctrace_current_domain() != 1)
		return;
	/* The callback may have replaced its function field before this event. */
	kctrace_interrupt_token_exit(this_cpu_ptr(&tasklet_token), READ_ONCE(tasklet_epoch),
				     (unsigned long)tasklet);
}

static void kctrace_find_tasklet_tracepoint(struct tracepoint *point, void *data)
{
	struct kctrace_tasklet_tracepoints *points = data;
	struct tracepoint **slot;

	if (!strcmp(point->name, "tasklet_entry"))
		slot = &points->entry;
	else if (!strcmp(point->name, "tasklet_exit"))
		slot = &points->exit;
	else
		return;
	if (*slot || tracepoint_is_faultable(point))
		points->duplicate = true;
	*slot = point;
}

/* A failed removal retains the module reference and disabled callbacks. A
 * later registration may retry cleanup; module exit can never free a live
 * callback address. All callers hold sessions_lock in process context.
 */
static bool kctrace_tasklet_remove_hooks(void)
{
	int result;

	if (tasklet_entry_registered) {
		result = tracepoint_probe_unregister(tasklet_points.entry,
						     (void *)kctrace_tasklet_entry, NULL);
		if (!result || result == -ENOENT)
			tasklet_entry_registered = false;
	}
	if (tasklet_exit_registered) {
		result = tracepoint_probe_unregister(tasklet_points.exit,
						     (void *)kctrace_tasklet_exit, NULL);
		if (!result || result == -ENOENT)
			tasklet_exit_registered = false;
	}
	tracepoint_synchronize_unregister();
	if (tasklet_entry_registered || tasklet_exit_registered) {
		pr_warn("kctrace: tasklet hook removal failed; runtime remains pinned\n");
		return false;
	}
	memset(&tasklet_points, 0, sizeof(tasklet_points));
	if (tasklet_pinned) {
		tasklet_pinned = false;
		module_put(THIS_MODULE);
	}
	return true;
}

static int kctrace_tasklet_get_hooks(void)
{
	int result;

	lockdep_assert_held(&sessions_lock);
	if (tasklet_users == UINT_MAX)
		return -EOVERFLOW;
	if (tasklet_users) {
		tasklet_users++;
		return 0;
	}
	if (next_tasklet_epoch == U64_MAX)
		return -EOVERFLOW;
	if (tasklet_pinned && !kctrace_tasklet_remove_hooks())
		return -EIO;
	for_each_kernel_tracepoint(kctrace_find_tasklet_tracepoint, &tasklet_points);
	if (!tasklet_points.entry || !tasklet_points.exit || tasklet_points.duplicate) {
		memset(&tasklet_points, 0, sizeof(tasklet_points));
		return -EOPNOTSUPP;
	}
	__module_get(THIS_MODULE);
	tasklet_pinned = true;
	check_trace_callback_type_tasklet_entry(kctrace_tasklet_entry);
	check_trace_callback_type_tasklet_exit(kctrace_tasklet_exit);
	result = tracepoint_probe_register(tasklet_points.exit, (void *)kctrace_tasklet_exit, NULL);
	if (result)
		goto failed;
	tasklet_exit_registered = true;
	result = tracepoint_probe_register(tasklet_points.entry, (void *)kctrace_tasklet_entry,
					   NULL);
	if (result)
		goto failed;
	tasklet_entry_registered = true;
	WRITE_ONCE(tasklet_epoch, ++next_tasklet_epoch);
	tasklet_users = 1;
	return 0;
failed:
	kctrace_tasklet_remove_hooks();
	return result;
}

static void kctrace_tasklet_put_hooks(void)
{
	lockdep_assert_held(&sessions_lock);
	if (WARN_ON_ONCE(!tasklet_users) || --tasklet_users)
		return;
	WRITE_ONCE(tasklet_epoch, 0);
	kctrace_tasklet_remove_hooks();
}
#else
static int kctrace_tasklet_get_hooks(void)
{
	return -EOPNOTSUPP;
}

static void kctrace_tasklet_put_hooks(void)
{
}
#endif

static int notrace kctrace_tasklet_handler(const struct kctrace_probe_frame *saved, u64 canonical)
{
	struct kctrace_interrupt_token *token = this_cpu_ptr(&tasklet_token);

	if (in_nmi() || kctrace_current_domain() != 1)
		return -1;
	return kctrace_interrupt_token_consume(token, READ_ONCE(tasklet_epoch), saved->rbx,
					       saved->rdx, canonical);
}

/* A successful entry retains preemption disabling until the matching leave.
 * Internal emission/wakeup inherits a same-domain recorder's ownership, while
 * a genuinely nested IRQ gets an independent owner and restores it on exit.
 */
static bool notrace kctrace_recorder_enter(struct kctrace_recorder_state *previous, bool internal)
{
	struct kctrace_recorder_state *state;
	unsigned int domain;
	unsigned long flags;

	preempt_disable_notrace();
	/* Guard bookkeeping itself must not invoke IRQ-flag tracing callbacks. */
	raw_local_irq_save(flags);
	state = this_cpu_ptr(&recorder_state);
	*previous = *state;
	domain = kctrace_current_domain();
	if (!internal && state->depth && state->domain == domain) {
		raw_local_irq_restore(flags);
		preempt_enable_notrace();
		return false;
	}
	state->domain = domain;
	state->depth++;
	raw_local_irq_restore(flags);
	return true;
}

static void notrace kctrace_recorder_leave(const struct kctrace_recorder_state *previous)
{
	unsigned long flags;

	raw_local_irq_save(flags);
	*this_cpu_ptr(&recorder_state) = *previous;
	raw_local_irq_restore(flags);
	preempt_enable_notrace();
}

static struct kctrace_execution_context *notrace
kctrace_irq_context(struct kctrace_binding *binding)
{
	unsigned int domain = kctrace_current_domain();

	if (!binding->irqs || !domain || domain > KCTRACE_IRQ_LANES || in_nmi())
		return NULL;
	return &this_cpu_ptr(binding->irqs)->lanes[domain - 1];
}

/* Slots are never evicted: a task denied a slot cannot later become a new
 * policy root merely because another task finished. Only lookup/claim needs
 * the lock; task execution itself is serialized by the scheduler.
 */
static struct kctrace_execution_context *notrace
kctrace_current_context(struct kctrace_binding *binding,
			const struct kctrace_program_table *program, bool create)
{
	struct kctrace_execution_context *context = NULL;
	unsigned int first, offset;
	unsigned long flags;

	if (!in_task())
		return kctrace_irq_context(binding);
	if (!binding->tasks)
		return NULL;
	first = hash_long((unsigned long)current ^ current->start_boottime, 8);
	raw_spin_lock_irqsave(&binding->task_lock, flags);
	for (offset = 0; offset < execution_task_count; offset++) {
		unsigned int index = (first + offset) % execution_task_count;
		struct kctrace_task_state *slot = &binding->tasks[index];

		if (slot->task == current && slot->start_ns == current->start_boottime) {
			context = &slot->execution;
			break;
		}
		if (slot->task)
			continue;
		if (create) {
			slot->start_ns = current->start_boottime;
			context = &slot->execution;
			context->frames = &binding->frames[index * execution_frame_count];
			context->capacity = execution_frame_count;
			context->terminal = !!(program->flags & KCTRACE_PROGRAM_TERMINAL);
			context->perfetto = !!(program->flags & KCTRACE_PROGRAM_PERFETTO);
			context->within_enabled =
				!!(program->flags & KCTRACE_PROGRAM_WITHIN_FILTER);
			context->minimum_level = program->minimum_level;
			/* The recursion-loss path may inspect existing slots without
			 * taking the task lock interrupted by that same recorder.
			 */
			smp_store_release(&slot->task, current);
		}
		break;
	}
	raw_spin_unlock_irqrestore(&binding->task_lock, flags);
	return context;
}

static void notrace kctrace_publish_within(struct kctrace_execution_context *context)
{
	unsigned char within = KCTRACE_EXECUTION_WITHIN_OUTSIDE;

	if (context->failure)
		within = KCTRACE_EXECUTION_WITHIN_UNKNOWN;
	else if (context->within_enabled && context->depth)
		within = context->frames[context->depth - 1].state & 1;
	/* A single published byte is the selector-boundary linearization point.
	 * An interrupt sees the old or new complete policy, never partial frames.
	 */
	smp_store_release(&context->published_within, within);
}

static void notrace kctrace_poison_context(struct kctrace_execution_context *context,
					   enum kctrace_execution_failure failure)
{
	kctrace_execution_poison(context, failure);
	kctrace_publish_within(context);
}

static __always_inline u32 kctrace_inherited_within(struct kctrace_binding *binding)
{
	unsigned int first, offset, domain, current_domain = kctrace_current_domain();
	unsigned int softirq = !!in_serving_softirq();
	unsigned int source = KCTRACE_INHERIT_SOURCE_TASK;
	unsigned char within = KCTRACE_EXECUTION_WITHIN_UNKNOWN;

	/* The interrupted task may hold task_lock. Permanent slots and their
	 * release publication permit a bounded, allocation-free lookup here.
	 * An unclaimed slot proves no prior tracked frame; a full table does not.
	 */
	first = hash_long((unsigned long)current ^ current->start_boottime, 8);
	for (offset = 0; offset < execution_task_count; offset++) {
		struct kctrace_task_state *slot =
			&binding->tasks[(first + offset) % execution_task_count];
		struct task_struct *task;

		/* Pair with complete task-slot initialization before publication. */
		task = smp_load_acquire(&slot->task);
		if (!task) {
			within = KCTRACE_EXECUTION_WITHIN_OUTSIDE;
			break;
		}
		if (task == current && slot->start_ns == current->start_boottime) {
			/* Read only the interrupted task's committed selector summary. */
			within = smp_load_acquire(&slot->execution.published_within);
			break;
		}
	}
	for (domain = 1; domain < current_domain; domain++) {
		const struct kctrace_execution_context *outer;
		unsigned char candidate;

		/* Only the serving softirq and lower hardirqs in this same softirq
		 * state are interrupted ancestors. Other per-CPU lanes are unrelated.
		 */
		if (domain == 1 ? !softirq : ((domain - 2) & 1) != softirq)
			continue;
		outer = &this_cpu_ptr(binding->irqs)->lanes[domain - 1];
		/* Pair with the lower lane's complete selector publication. */
		candidate = smp_load_acquire(&outer->published_within);
		if (candidate == KCTRACE_EXECUTION_WITHIN_ACTIVE ||
		    (candidate == KCTRACE_EXECUTION_WITHIN_UNKNOWN &&
		     within != KCTRACE_EXECUTION_WITHIN_ACTIVE)) {
			within = candidate;
			source = domain + 1;
		}
	}
	if (within == KCTRACE_EXECUTION_WITHIN_OUTSIDE)
		return KCTRACE_INHERIT_VALID;
	return KCTRACE_INHERIT_VALID |
	       (within == KCTRACE_EXECUTION_WITHIN_ACTIVE ? KCTRACE_INHERIT_WITHIN :
							    KCTRACE_INHERIT_UNKNOWN) |
	       (source << KCTRACE_INHERIT_SOURCE_SHIFT);
}

static void notrace kctrace_binding_recursion_lost(struct kctrace_binding *binding)
{
	struct kctrace_execution_context *context = NULL;
	unsigned int index;

	atomic64_inc(&binding->dropped);
	if (!in_task()) {
		context = kctrace_irq_context(binding);
	} else if (binding->tasks) {
		/* Slots are permanent; acquire observes their fully initialized
		 * context without locking or touching another task's policy.
		 */
		for (index = 0; index < execution_task_count; index++) {
			struct kctrace_task_state *slot = &binding->tasks[index];

			/* Pair with the complete slot publication above. */
			if (smp_load_acquire(&slot->task) == current &&
			    slot->start_ns == current->start_boottime) {
				context = &slot->execution;
				break;
			}
		}
	}
	/* An empty poisoned IRQ lane has no proven recovery point. In particular,
	 * a later activation must not silently become a fresh within root.
	 */
	if (context)
		kctrace_poison_context(context, KCTRACE_EXECUTION_REENTRANT);
}

static void notrace kctrace_wake_readers(struct kctrace_binding *session, __poll_t mask)
{
	struct kctrace_recorder_state previous;

	/* Waking a reader may itself invoke an instrumented scheduler callback.
	 */
	kctrace_recorder_enter(&previous, true);
	wake_up_interruptible_poll(&session->readable, mask);
	kctrace_recorder_leave(&previous);
}

static void notrace kctrace_wake(struct irq_work *work)
{
	struct kctrace_binding *session;

	session = container_of(work, struct kctrace_binding, wakeup);
	kctrace_wake_readers(session, EPOLLIN | EPOLLRDNORM);
}

static void kctrace_free(struct kref *ref)
{
	struct kctrace_binding *session;
	unsigned int cpu;

	session = container_of(ref, struct kctrace_binding, refs);
	irq_work_sync(&session->wakeup);
	if (session->rings) {
		for_each_possible_cpu(cpu)
			kvfree(per_cpu_ptr(session->rings, cpu)->events);
		free_percpu(session->rings);
	}
	kvfree(session->frames);
	kvfree(session->tasks);
	kctrace_free_irqs(session->irqs);
	kfree(session);
}

static void kctrace_disable(struct kctrace_binding *session)
{
	/* Pair with producer acquire: no new records after disconnection. */
	smp_store_release(&session->enabled, false);
	kctrace_wake_readers(session, EPOLLHUP);
}

static bool notrace kctrace_capture_ram(u64 address, unsigned int bytes)
{
	unsigned long first = address, last;

	if (!bytes || check_add_overflow(first, bytes - 1UL, &last))
		return false;
	for (;;) {
		const void *pointer = (const void *)first;
		struct page *page;

		if (virt_addr_valid(pointer))
			page = virt_to_page(pointer);
		else if (is_vmalloc_or_module_addr(pointer))
			page = vmalloc_to_page(pointer);
		else
			return false;
		if (!page || PageReserved(page) || is_zone_device_page(page))
			return false;
		if ((first & PAGE_MASK) == (last & PAGE_MASK))
			return true;
		first = (first & PAGE_MASK) + PAGE_SIZE;
	}
}

/* Non-task snapshots contain only passive scalar state in private IRQ
 * scratch. Never extend this path to target memory or FPU registers.
 */
static noinline void notrace kctrace_capture_scalar_irq(const struct kctrace_capture_plan *plan,
							const struct kctrace_snapshot *snapshot,
							struct kctrace_event *event)
{
	const u8 *state = snapshot->xstate;
	unsigned int slot;

	if (!state)
		return;
	for (slot = 0; slot < KCTRACE_VALUE_SLOTS; slot++) {
		const struct kctrace_capture *capture = &plan->slots[slot];

		if (capture->kind != KCTRACE_CAPTURE_XSTATE ||
		    !(KCTRACE_XSTATE_SCALAR & snapshot->xstate_mask & BIT_ULL(capture->reg)))
			continue;
		memcpy(event->capture_values[slot],
		       state + xstate_offsets[capture->reg] + capture->offset, capture->size);
		event->capture_valid |= 1U << slot;
	}
}

static void notrace kctrace_capture_chunk(const struct kctrace_capture_plan *plan,
					  const struct kctrace_snapshot *snapshot,
					  struct kctrace_event *event)
{
	unsigned long stack_base;
	u64 original_sp = snapshot->registers[KCTRACE_REG_RSP];
	unsigned int slot;

	/* IRQ memory remains outside the capture contract. */
	if (!in_task()) {
		if (snapshot->xstate)
			kctrace_capture_scalar_irq(plan, snapshot, event);
		return;
	}
	stack_base = (unsigned long)task_stack_page(current);
	if (!stack_base || original_sp < stack_base || original_sp - stack_base >= THREAD_SIZE)
		return;
	for (slot = 0; slot < KCTRACE_VALUE_SLOTS; slot++) {
		const struct kctrace_capture *capture = &plan->slots[slot];
		u64 address, base;

		if (capture->kind == KCTRACE_CAPTURE_XSTATE) {
			const u8 *state = snapshot->xstate;
			u64 present, offset = capture->offset;
			unsigned int byte;

			if (!state || !(snapshot->xstate_mask & BIT_ULL(capture->reg)))
				continue;
			memcpy(&present, state + 512, sizeof(present));
			if (!capture->reg && offset >= 32) {
				/* Raw MMX aliases remain readable after EMMS empties
				 * x87 tags. Typed ST consumers validate TOP/FTW.
				 */
				for (byte = 0; byte < capture->size; byte++, offset++)
					event->capture_values[slot][byte] =
						(present & 1) && (offset - 32) % 16 < 10 ?
							state[offset] :
							0;
				event->capture_valid |= 1U << slot;
				continue;
			}
			/* Plain XSAVE writes MXCSR even when the SSE component's
			 * XSTATE_BV bit is clear: that bit can track XMM only.
			 */
			if ((capture->reg == 1 && offset >= 24 && offset < 28) ||
			    (present & BIT_ULL(capture->reg))) {
				if (capture->reg >= 2)
					offset += xstate_offsets[capture->reg];
				memcpy(event->capture_values[slot], state + offset, capture->size);
			} else {
				/* XSAVE may leave init-state bytes untouched in a reused
				 * buffer. Materialize architectural initial values only.
				 */
				for (byte = 0; byte < capture->size; byte++, offset++)
					event->capture_values[slot][byte] =
						!capture->reg && offset == 0 ? 0x7f :
						!capture->reg && offset == 1 ? 0x03 :
									       0;
			}
			event->capture_valid |= 1U << slot;
			continue;
		} else if (capture->kind == KCTRACE_CAPTURE_STACK) {
			base = snapshot->registers[capture->reg];
		} else if (capture->kind == KCTRACE_CAPTURE_OBJECT) {
			base = capture->object;
		} else if (capture->kind == KCTRACE_CAPTURE_GPR) {
			if (!(snapshot->valid_registers & BIT_ULL(capture->reg)))
				continue;
			base = snapshot->registers[capture->reg];
		} else if (capture->kind == KCTRACE_CAPTURE_SLOT) {
			unsigned int source = capture->reserved2 - 1;

			if (!(event->capture_valid & BIT(source)))
				continue;
			memcpy(&base, event->capture_values[source], sizeof(base));
		} else {
			continue;
		}
		if (capture->offset < 0) {
			u64 distance = 0 - (u64)capture->offset;

			if (base < distance)
				continue;
			address = base - distance;
		} else {
			if (base > U64_MAX - capture->offset)
				continue;
			address = base + capture->offset;
		}
		if (capture->kind == KCTRACE_CAPTURE_STACK) {
			/* The no-red-zone kernel ABI keeps locals above original SP,
			 * outside the probe's own register saves and C frame.
			 */
			if (address < original_sp || address < stack_base ||
			    address - stack_base > THREAD_SIZE - capture->size)
				continue;
		}
		if (capture->reserved & KCTRACE_CAPTURE_ADDRESS) {
			memcpy(event->capture_values[slot], &address, sizeof(address));
			event->capture_valid |= 1U << slot;
			continue;
		}
		if ((capture->kind == KCTRACE_CAPTURE_GPR ||
		     capture->kind == KCTRACE_CAPTURE_SLOT) &&
		    !kctrace_capture_ram(address, capture->size))
			continue;
		/* Ownership/type proof is offline plus bind-time validation. The
		 * nofault helper alone is not an MMIO or volatile-read filter.
		 */
		if (copy_from_kernel_nofault(event->capture_values[slot],
					     (const void *)(unsigned long)address, capture->size)) {
			memset(event->capture_values[slot], 0, sizeof(event->capture_values[slot]));
			continue;
		}
		event->capture_valid |= 1U << slot;
	}
}

/* Offset is at most the capacity: subtract first to avoid u32 wrap. */
static __always_inline unsigned int kctrace_ring_offset(unsigned int head, unsigned int offset,
							unsigned int capacity)
{
	unsigned int remaining = capacity - head;

	return offset < remaining ? head + offset : offset - remaining;
}

/* Called only after acquiring a binding lifetime reference. No allocation. */
static void notrace kctrace_emit(struct kctrace_binding *session, u16 type, u64 site_id, u64 pc,
				 const struct kctrace_snapshot *snapshot, u64 probe_begin_ns)
{
	struct kctrace_event *event;
	struct kctrace_ring *ring;
	struct kctrace_recorder_state previous;
	unsigned long flags;
	unsigned int cpu, chunks = 1, chunk, plan_id = 0;
	u64 sequence;

	if (!session)
		return;
	/* NMI is deliberately unadvertised until its recorder is validated. */
	if (unlikely(in_nmi())) {
		atomic64_inc(&session->dropped);
		return;
	}
	kctrace_recorder_enter(&previous, true);
	atomic_inc(&session->active);
	/* PREPARE publishes every ring before enabling its producers. */
	if (!smp_load_acquire(&session->enabled))
		goto done;
	if (snapshot && snapshot->capture_plans) {
		/* Registration bounded and validated every immutable chain. */
		plan_id = snapshot->capture_plan;
		for (chunk = plan_id; snapshot->capture_plans[chunk - 1].next;
		     chunk = snapshot->capture_plans[chunk - 1].next)
			chunks++;
	}
	cpu = get_cpu();
	ring = per_cpu_ptr(session->rings, cpu);
	/* Recursion is rejected before emission and NMI is excluded. Readers
	 * hold this lock only for a fixed event copy or head lookup, never for
	 * user-memory access. Do not lose an event merely to that short reader
	 * section; local IRQ disabling also prevents waiting on our own reader.
	 */
	raw_spin_lock_irqsave(&ring->lock, flags);
	/* Assign only after local IRQs are disabled: a nested IRQ may publish
	 * first, but each CPU's ring must remain ordered for the reader's merge.
	 */
	sequence = atomic64_add_return(chunks, &session->sequence) - chunks + 1;
	if (chunks > session->prepared.events_per_cpu - ring->used) {
		/* A nested IRQ must observe the loss before publishing its event. */
		atomic64_add(chunks, &session->dropped);
		raw_spin_unlock_irqrestore(&ring->lock, flags);
		goto drop_cpu;
	}
	event = &ring->events[ring->head];
	memset(event, 0, sizeof(*event));
	event->size = sizeof(*event);
	event->type = type;
	event->context = in_hardirq()	      ? KCTRACE_CONTEXT_HARDIRQ :
			 in_serving_softirq() ? KCTRACE_CONTEXT_SOFTIRQ :
						KCTRACE_CONTEXT_TASK;
	event->sequence = sequence;
	event->monotonic_ns = probe_begin_ns ? probe_begin_ns : ktime_get_ns();
	event->session_id = session->session_id;
	event->generation = session->generation;
	event->task_start_ns = current->start_boottime;
	event->site_id = site_id;
	event->pc = pc;
	event->tid = task_pid_nr(current);
	event->tgid = task_tgid_nr(current);
	event->cpu = cpu;
	event->level = KCTRACE_LEVEL_FULL;
	event->hardirq_depth = hardirq_count() >> HARDIRQ_SHIFT;
	event->softirq_depth = !!in_serving_softirq();
	event->dropped_total = atomic64_read(&session->dropped);
	if (event->dropped_total)
		event->flags |= KCTRACE_EVENT_SEQUENCE_GAP;
	if (snapshot) {
		unsigned int reg;

		if (snapshot->flags & KCTRACE_EVENT_HAVE_EXECUTION) {
			event->flags |= KCTRACE_EVENT_HAVE_EXECUTION;
			event->execution = snapshot->execution;
			event->level = snapshot->level;
		}
		event->valid_registers = snapshot->valid_registers;
		for (reg = 0; reg < KCTRACE_REGISTER_COUNT; reg++)
			if (snapshot->valid_registers & (1ULL << reg))
				event->registers[reg] = snapshot->registers[reg];
		if (snapshot->flags & KCTRACE_EVENT_HAVE_VALUES) {
			event->flags |= KCTRACE_EVENT_HAVE_VALUES;
			event->capture_plan = snapshot->capture_plan;
			event->reserved2 = chunks;
			if (snapshot->capture_plans) {
				kctrace_capture_chunk(&snapshot->capture_plans[plan_id - 1],
						      snapshot, event);
			} else {
				event->capture_valid = snapshot->capture_valid;
				memcpy(event->capture_values, snapshot->capture_values,
				       sizeof(event->capture_values));
			}
		} else if (snapshot->memory_size) {
			event->flags |= KCTRACE_EVENT_HAVE_MEMORY;
			event->memory_address = snapshot->memory_address;
			event->memory_size = snapshot->memory_size;
			memcpy(event->memory, snapshot->memory, snapshot->memory_size);
		}
	}
	for (chunk = 1; chunk < chunks; chunk++) {
		unsigned int position =
			kctrace_ring_offset(ring->head, chunk, session->prepared.events_per_cpu);
		struct kctrace_event *continuation = &ring->events[position];

		plan_id = snapshot->capture_plans[plan_id - 1].next;
		*continuation = *event;
		continuation->type = KCTRACE_EVENT_CAPTURE;
		continuation->sequence = sequence + chunk;
		continuation->flags &= KCTRACE_EVENT_HAVE_VALUES | KCTRACE_EVENT_SEQUENCE_GAP;
		continuation->valid_registers = 0;
		memset(continuation->registers, 0, sizeof(continuation->registers));
		memset(&continuation->execution, 0, sizeof(continuation->execution));
		continuation->capture_valid = 0;
		memset(continuation->capture_values, 0, sizeof(continuation->capture_values));
		continuation->reserved2 = chunk;
		kctrace_capture_chunk(&snapshot->capture_plans[plan_id - 1], snapshot,
				      continuation);
	}
	if (probe_begin_ns) {
		event->flags |= KCTRACE_EVENT_PROBE_TIMING;
		event->probe_end_ns = ktime_get_ns();
		for (chunk = 1; chunk < chunks; chunk++)
			ring->events[kctrace_ring_offset(ring->head, chunk,
							 session->prepared.events_per_cpu)]
				.probe_end_ns = event->probe_end_ns;
	}
	/* Publish a complete observation; readers never see an incomplete chain. */
	ring->head = kctrace_ring_offset(ring->head, chunks, session->prepared.events_per_cpu);
	ring->used += chunks;
	atomic64_add(chunks, &session->produced);
	atomic64_add(chunks, &session->buffered);
	raw_spin_unlock_irqrestore(&ring->lock, flags);
	irq_work_queue(&session->wakeup);
	put_cpu();
	goto done;

drop_cpu:
	put_cpu();
done:
	/* Only disconnect/unbind wait for all producers to drain. */
	if (atomic_dec_and_test(&session->active) && !READ_ONCE(session->enabled))
		wake_up_all(&session->drained);
	kctrace_recorder_leave(&previous);
}

struct kctrace_binding *kctrace_bind(struct module *target, const struct kctrace_manifest *manifest)
{
	struct kctrace_binding *session;
	struct kctrace_binding *result = ERR_PTR(-ENOENT);

	if (!target || !manifest || manifest->size != sizeof(*manifest) ||
	    memcmp(manifest->contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE) ||
	    manifest->flags ||
	    (manifest->levels != KCTRACE_LEVEL_MASK_FULL &&
	     manifest->levels != (KCTRACE_LEVEL_MASK_ALL & (~0U << KCTRACE_LEVEL_PERFETTO)) &&
	     manifest->levels != KCTRACE_LEVEL_MASK_ALL) ||
	    !manifest->site_count ||
	    strnlen(manifest->module_name, KCTRACE_MODULE_NAME_SIZE) == KCTRACE_MODULE_NAME_SIZE ||
	    strcmp(target->name, manifest->module_name))
		return ERR_PTR(-EINVAL);
	if (target->state != MODULE_STATE_COMING)
		return ERR_PTR(-EINVAL);
	mutex_lock(&sessions_lock);
	list_for_each_entry(session, &sessions, link) {
		if (memcmp(session->prepared.session_nonce, manifest->session_nonce,
			   KCTRACE_NONCE_SIZE))
			continue;
		if (session->state != KCTRACE_STATE_PREPARED || session->bound ||
		    !session->owner_present || !session->enabled) {
			result = ERR_PTR(-EBUSY);
			break;
		}
		if (manifest->levels !=
			    (KCTRACE_LEVEL_MASK_ALL & (~0U << session->prepared.initial_level)) ||
		    strcmp(session->prepared.module_name, manifest->module_name) ||
		    session->prepared.site_count != manifest->site_count ||
		    memcmp(session->prepared.original_sha256, manifest->original_sha256,
			   KCTRACE_HASH_SIZE) ||
		    memcmp(session->prepared.artifact_sha256, manifest->artifact_sha256,
			   KCTRACE_HASH_SIZE)) {
			result = ERR_PTR(-EPERM);
			break;
		}
		kref_get(&session->refs);
		session->generation = atomic64_inc_return(&next_generation);
		session->bound = true;
		session->target = target;
		session->state = KCTRACE_STATE_BOUND;
		session->levels = manifest->levels;
		result = session;
		kctrace_emit(session, KCTRACE_EVENT_BOUND, 0, 0, NULL, 0);
		break;
	}
	mutex_unlock(&sessions_lock);
	return result;
}
EXPORT_SYMBOL_GPL(kctrace_bind);

static int kctrace_compare_sites(const void *left, const void *right)
{
	const struct kctrace_probe_site *a = left;
	const struct kctrace_probe_site *b = right;

	return (a->return_pc > b->return_pc) - (a->return_pc < b->return_pc);
}

static bool kctrace_owned_range(const struct module *target, unsigned long start, u64 bytes,
				bool data_only)
{
	if (!bytes)
		return false;
	for_each_mod_mem_type(type) {
		const struct module_memory *memory = &target->mem[type];
		unsigned long base = (unsigned long)memory->base;

		if (data_only && !mod_mem_type_is_data(type))
			continue;
		if (bytes <= memory->size && start >= base && start - base <= memory->size - bytes)
			return true;
	}
	return false;
}

/* Immutable metadata and the writable bootstrap output use distinct classes. */
static bool kctrace_data_range(const struct module *target, unsigned long start, u64 bytes,
			       bool writable)
{
	if (!bytes)
		return false;
	for_each_mod_mem_type(type) {
		const struct module_memory *memory = &target->mem[type];
		unsigned long base = (unsigned long)memory->base;

		if (writable ? type != MOD_DATA : (type != MOD_RODATA && type != MOD_INIT_RODATA))
			continue;
		if (bytes <= memory->size && start >= base && start - base <= memory->size - bytes)
			return true;
	}
	return false;
}

static bool kctrace_text_address(const struct module *target, u64 address, bool init, bool end)
{
	if (end && address)
		address--;
	for_class_mod_mem_type(type, text)
	{
		if (mod_mem_type_is_init(type) == init &&
		    within_module_mem_type(address, target, type))
			return true;
	}
	return false;
}

static bool kctrace_kernel_range(u64 address, u64 bytes)
{
	return bytes && bytes <= KERNEL_IMAGE_SIZE && address >= __START_KERNEL_map &&
	       address - __START_KERNEL_map <= KERNEL_IMAGE_SIZE - bytes;
}

/* Validate once before publishing a binding. Legal later static-call/jump-label
 * changes preserve the transfer relations proved offline; ENTER reads only the
 * saved callback identity, never these code ranges or a decoder.
 */
static int kctrace_prepare_handlers(const struct module *target,
				    const struct kctrace_program *program,
				    struct kctrace_program_table *table)
{
	struct kctrace_interrupt_proof proof;
	const struct kctrace_interrupt_range *ranges;
	const struct kctrace_interrupt_window *windows;
	unsigned char *live = NULL;
	u64 slide, return_zero, previous = 0;
	unsigned int range, window = 0, index;
	int result = -EINVAL;

	if (!(program->flags & KCTRACE_PROGRAM_WITHIN_INTR))
		return program->interrupt_proof ? -EINVAL : 0;
	if (!(program->flags & KCTRACE_PROGRAM_WITHIN_FILTER) ||
	    !IS_ALIGNED(program->interrupt_proof, __alignof__(proof)) ||
	    !kctrace_data_range(target, program->interrupt_proof, sizeof(proof), false))
		return -EINVAL;
	memcpy(&proof, (const void *)(unsigned long)program->interrupt_proof, sizeof(proof));
	if (proof.size != sizeof(proof) || proof.reserved || !proof.range_count ||
	    proof.range_count > U32_MAX || proof.window_count > U32_MAX || !proof.dispatch_count ||
	    proof.dispatch_count > U32_MAX || proof.entry_count != program->function_count ||
	    !kctrace_kernel_range(proof.anchor, 1) ||
	    !IS_ALIGNED(proof.ranges, __alignof__(*ranges)) ||
	    !IS_ALIGNED(proof.windows, __alignof__(*windows)) ||
	    !IS_ALIGNED(proof.dispatches, __alignof__(*table->handlers)) ||
	    !IS_ALIGNED(proof.entries, sizeof(u64)) ||
	    !kctrace_data_range(target, proof.ranges, proof.range_count * sizeof(*ranges), false) ||
	    (proof.window_count &&
	     !kctrace_data_range(target, proof.windows, proof.window_count * sizeof(*windows),
				 false)) ||
	    !kctrace_data_range(target, proof.dispatches,
				proof.dispatch_count * sizeof(*table->handlers), false) ||
	    !kctrace_data_range(target, proof.entries, proof.entry_count * sizeof(u64), false))
		return -EINVAL;
	slide = (unsigned long)&hrtimer_start_range_ns - proof.anchor;
	if (slide >= KERNEL_IMAGE_SIZE || !IS_ALIGNED(slide, PMD_SIZE) ||
	    (proof.return_zero && (!kctrace_kernel_range(proof.return_zero, 1) ||
				   !kctrace_kernel_range(proof.return_zero + slide, 1))))
		return -EINVAL;
	return_zero = proof.return_zero ? proof.return_zero + slide : 0;
	ranges = (const void *)(unsigned long)proof.ranges;
	windows = (const void *)(unsigned long)proof.windows;
	for (range = 0; range < proof.range_count; range++) {
		const struct kctrace_interrupt_range *area = &ranges[range];
		const unsigned char *original = (const void *)(unsigned long)area->bytes;
		unsigned int cursor = 0;

		if (!area->size || area->size > U32_MAX || area->address < previous ||
		    !kctrace_kernel_range(area->address, area->size) ||
		    !kctrace_kernel_range(area->address + slide, area->size) ||
		    !kctrace_data_range(target, area->bytes, area->size, false))
			goto out;
		previous = area->address + area->size;
		live = kvmalloc(area->size, GFP_KERNEL);
		if (!live) {
			result = -ENOMEM;
			goto out;
		}
		if (copy_from_kernel_nofault(live,
					     (const void *)(unsigned long)(area->address + slide),
					     area->size)) {
			result = -EFAULT;
			goto out;
		}
		while (window < proof.window_count && windows[window].pc < previous) {
			const struct kctrace_interrupt_window *source = &windows[window++];
			struct kctrace_interrupt_patch patch = {
				.pc = source->pc,
				.target = source->target,
				.key = source->key,
				.kind = source->kind,
				.size = source->size,
				.reg = source->reg,
			};
			u64 key = 0, check = 0;
			const void *key_address =
				(const void *)(unsigned long)(source->key + slide);
			unsigned int offset;

			if (source->reserved || source->reserved2 ||
			    source->pc < area->address + cursor || !source->size ||
			    source->size > previous - source->pc)
				goto out;
			offset = source->pc - area->address;
			if (memcmp(original + cursor, live + cursor, offset - cursor))
				goto out;
			if (source->key) {
				if (!kctrace_kernel_range(source->key, sizeof(key)) ||
				    !kctrace_kernel_range(source->key + slide, sizeof(key)) ||
				    copy_from_kernel_nofault(&key, key_address, sizeof(key))) {
					result = -EFAULT;
					goto out;
				}
			}
			if (!kctrace_interrupt_patch_matches(&patch, original + offset,
							     live + offset, area->size - offset,
							     slide, key, return_zero))
				goto out;
			if (source->key &&
			    (copy_from_kernel_nofault(&check, key_address, sizeof(check)) ||
			     check != key)) {
				result = -EAGAIN;
				goto out;
			}
			cursor = offset + source->size;
		}
		if (memcmp(original + cursor, live + cursor, area->size - cursor))
			goto out;
		kvfree(live);
		live = NULL;
	}
	if (window != proof.window_count)
		goto out;
	table->handlers = kvmemdup((const void *)(unsigned long)proof.dispatches,
				   proof.dispatch_count * sizeof(*table->handlers), GFP_KERNEL);
	table->handler_entries = kvmemdup((const void *)(unsigned long)proof.entries,
					  proof.entry_count * sizeof(u64), GFP_KERNEL);
	if (!table->handlers || !table->handler_entries) {
		result = -ENOMEM;
		goto out;
	}
	if (table->handler_entries[0])
		goto out;
	for (index = 1; index < proof.entry_count; index++) {
		u64 entry = table->handler_entries[index];

		if (entry &&
		    !kctrace_text_address(target, entry, within_module_init(entry, target), false))
			goto out;
	}
	previous = 0;
	for (index = 0; index < proof.dispatch_count; index++) {
		struct kctrace_interrupt_dispatch *handler = &table->handlers[index];
		bool found = false;
		unsigned int reg = handler->kind == KCTRACE_INTERRUPT_HRTIMER ?
					   (handler->reg == KCTRACE_REG_R12 ? 12 : 13) :
				   handler->kind == KCTRACE_INTERRUPT_TIMER_LIST ? 5 :
				   handler->kind == KCTRACE_INTERRUPT_TASKLET	 ? 2 :
										   0;

		if (handler->return_pc <= previous || handler->kind > KCTRACE_INTERRUPT_TASKLET)
			goto out;
		previous = handler->return_pc;
		for (window = 0; window < proof.window_count; window++)
			if (windows[window].kind == KCTRACE_INTERRUPT_INDIRECT_CALL &&
			    windows[window].pc + windows[window].size == handler->return_pc &&
			    windows[window].reg == reg)
				found = true;
		if (!found)
			goto out;
		if (handler->kind == KCTRACE_INTERRUPT_HRTIMER ||
		    handler->kind == KCTRACE_INTERRUPT_TIMER_LIST) {
			if (handler->target != KCTRACE_INTERRUPT_SAVED_REGISTER ||
			    handler->word_offset ||
			    (handler->kind == KCTRACE_INTERRUPT_HRTIMER ?
				     (handler->reg != KCTRACE_REG_R13 &&
				      handler->reg != KCTRACE_REG_R12) :
				     handler->reg != KCTRACE_REG_RBP))
				goto out;
		} else if (handler->kind == KCTRACE_INTERRUPT_TASKLET) {
			if (handler->target != KCTRACE_INTERRUPT_TASKLET_TOKEN ||
			    handler->reg != KCTRACE_REG_RDX || handler->word_offset)
				goto out;
		} else if (handler->target != KCTRACE_INTERRUPT_SAVED_WORD ||
			   handler->reg != KCTRACE_REG_RBX ||
			   handler->word_offset !=
				   (handler->kind == KCTRACE_INTERRUPT_HARD_IRQ ?
					    offsetof(struct irqaction, handler) :
					    offsetof(struct irqaction, thread_fn))) {
			goto out;
		}
		handler->return_pc += slide;
	}
	table->handler_count = proof.dispatch_count;
	result = 0;
out:
	kvfree(live);
	return result;
}

static bool kctrace_valid_capture(const struct module *target,
				  const struct kctrace_capture_plan *plan, unsigned int slot)
{
	const struct kctrace_capture *capture = &plan->slots[slot];
	unsigned int bytes = capture->reserved & KCTRACE_CAPTURE_ADDRESS ? 0 : capture->size;

	if (capture->kind == KCTRACE_CAPTURE_NONE)
		return !memchr_inv(capture, 0, sizeof(*capture));
	if (!capture->size || capture->size > 8 || (capture->reserved & ~KCTRACE_CAPTURE_ADDRESS) ||
	    ((capture->reserved & KCTRACE_CAPTURE_ADDRESS) && capture->size != 8) ||
	    (capture->kind != KCTRACE_CAPTURE_SLOT && capture->reserved2))
		return false;
	if (capture->kind == KCTRACE_CAPTURE_XSTATE)
		return !capture->object && !capture->object_size && !capture->reserved &&
		       kctrace_xstate_range(capture) && (plan->xstate_mask & BIT(capture->reg));
	if (capture->kind == KCTRACE_CAPTURE_STACK)
		return !capture->object && !capture->object_size &&
		       (capture->reg == KCTRACE_REG_RSP || capture->reg == KCTRACE_REG_RBP);
	if (capture->kind == KCTRACE_CAPTURE_GPR)
		return !capture->object && !capture->object_size &&
		       capture->reg < KCTRACE_REG_RFLAGS;
	if (capture->kind == KCTRACE_CAPTURE_SLOT)
		return !capture->object && !capture->object_size && !capture->reg &&
		       capture->reserved2 && capture->reserved2 <= slot &&
		       plan->slots[capture->reserved2 - 1].size == 8;
	return capture->kind == KCTRACE_CAPTURE_OBJECT && !capture->reg && capture->offset >= 0 &&
	       bytes <= capture->object_size && capture->offset <= capture->object_size - bytes &&
	       kctrace_owned_range(target, capture->object, capture->object_size, true);
}

static int kctrace_compare_copy_probes(const void *left, const void *right)
{
	const struct kctrace_copy_probe *a = left, *b = right;

	return (a->probe.return_pc > b->probe.return_pc) -
	       (a->probe.return_pc < b->probe.return_pc);
}

static int kctrace_compare_gates(const void *left, const void *right)
{
	const struct kctrace_gate_site *a = left, *b = right;

	return (a->return_pc > b->return_pc) - (a->return_pc < b->return_pc);
}

static int kctrace_compare_landings(const void *left, const void *right)
{
	const struct kctrace_landing *a = left, *b = right;

	return (a->pc > b->pc) - (a->pc < b->pc);
}

static bool kctrace_valid_full_gate(const struct module *target,
				    const struct kctrace_gate_site *gate)
{
	static const u8 endbr[] = { 0xf3, 0x0f, 0x1e, 0xfa };
	static const u8 sealed[] = { 0x0f, 0x1f, 0x40, 0x00 };
	u8 bytes[11];
	u64 distance;
	unsigned int prefix;

	if (gate->return_pc < gate->pc)
		return false;
	distance = gate->return_pc - gate->pc;
	if ((distance != 6 && distance != 10) ||
	    !kctrace_owned_range(target, gate->pc, distance + 1, false))
		return false;
	memcpy(bytes, (const void *)(unsigned long)gate->pc, distance + 1);
	prefix = distance - 6;
	if (prefix && gate->kind != KCTRACE_BOUNDARY_ENTER && gate->kind != KCTRACE_BOUNDARY_SCOPE)
		return false;
	/* Objtool may seal an original ENDBR at a non-address-taken function. */
	if (prefix && memcmp(bytes, endbr, sizeof(endbr)) && memcmp(bytes, sealed, sizeof(sealed)))
		return false;
	if (bytes[prefix] != 0x9c || bytes[prefix + 1] != 0xe8 || bytes[distance] != 0x9d)
		return false;
	/* The final ELF proves the helper import. The loader may redirect this
	 * CALL through its supported call-depth thunk without changing return_pc.
	 */
	return true;
}

static bool kctrace_valid_capture_chains(const struct kctrace_capture_plan *plans,
					 unsigned int count)
{
	unsigned int index;

	for (index = 0; index < count; index++) {
		/* Offline generation appends suffix chunks after their predecessor. */
		if ((plans[index].next &&
		     (plans[index].next <= index + 1 || plans[index].next > count)) ||
		    (plans[index].xstate_mask & ~(xstate_mask | scalar_mask)))
			return false;
	}
	return true;
}

static struct kctrace_program_table *kctrace_copy_program(const struct kctrace_program *program,
							  const struct kctrace_capture_plan *plans,
							  unsigned int plan_count)
{
	struct kctrace_program_table *table;

	table = kzalloc_obj(*table);
	if (!table)
		return NULL;
	table->probe_count = program->probe_count;
	table->gate_count = program->gate_count;
	table->plan_count = plan_count;
	table->flags = program->flags;
	table->minimum_level = program->minimum_level;
	if (program->probe_count)
		table->probes = kvmemdup((const void *)(unsigned long)program->probes,
					 program->probe_count * sizeof(*table->probes), GFP_KERNEL);
	table->gates = kvmemdup((const void *)(unsigned long)program->gates,
				program->gate_count * sizeof(*table->gates), GFP_KERNEL);
	table->functions = kvmemdup((const void *)(unsigned long)program->functions,
				    program->function_count * sizeof(*table->functions),
				    GFP_KERNEL);
	table->paths = kvmemdup((const void *)(unsigned long)program->paths,
				program->path_count * sizeof(*table->paths), GFP_KERNEL);
	if (plan_count)
		table->plans = kvmemdup(plans, plan_count * sizeof(*plans), GFP_KERNEL);
	if (program->flags & KCTRACE_PROGRAM_FIXED_FULL)
		table->landings =
			kvcalloc(program->gate_count, sizeof(*table->landings), GFP_KERNEL);
	if ((program->probe_count && !table->probes) || !table->gates || !table->functions ||
	    !table->paths || (plan_count && !table->plans) ||
	    ((program->flags & KCTRACE_PROGRAM_FIXED_FULL) && !table->landings)) {
		kctrace_free_program(table);
		return NULL;
	}
	table->policy.functions = table->functions;
	table->policy.paths = table->paths;
	table->policy.function_count = program->function_count;
	table->policy.path_count = program->path_count;
	return table;
}

int kctrace_register_program(struct kctrace_binding *binding, const struct kctrace_program *program,
			     const struct kctrace_capture_plan *plans, u64 plan_count)
{
	struct kctrace_program_table *table = NULL, *core = NULL;
	struct kctrace_program descriptor;
	struct {
		u32 function;
		u32 path;
	} *identities = NULL;
	unsigned long *identifiers = NULL;
	unsigned long *entry_ids = NULL;
	unsigned int index, slot, level, cpu, probe_index = 0;
	bool has_init = false, single_full, has_fixed;
	int result = -EINVAL;

	if (!binding || !program)
		return -EINVAL;
	/* Per-CPU softirq ownership requires a nonpreemptible serving interval. */
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		return -EOPNOTSUPP;
	mutex_lock(&sessions_lock);
	if (!binding->bound || !binding->target || binding->state != KCTRACE_STATE_BOUND ||
	    rcu_access_pointer(binding->probe_table) || rcu_access_pointer(binding->program)) {
		result = -EBUSY;
		goto out;
	}
	if (!IS_ALIGNED((unsigned long)program, __alignof__(*program)) ||
	    !kctrace_data_range(binding->target, (unsigned long)program, sizeof(*program), false))
		goto out;
	descriptor = *program;
	single_full = !!(descriptor.flags & KCTRACE_PROGRAM_SINGLE_FULL);
	has_fixed = !!(descriptor.flags & KCTRACE_PROGRAM_FIXED_FULL);
	if (descriptor.size != sizeof(descriptor) ||
	    memcmp(descriptor.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE) ||
	    descriptor.minimum_level > KCTRACE_LEVEL_FULL ||
	    descriptor.minimum_level != binding->prepared.initial_level ||
	    descriptor.flags & ~(KCTRACE_PROGRAM_TERMINAL | KCTRACE_PROGRAM_PERFETTO |
				 KCTRACE_PROGRAM_WITHIN_FILTER | KCTRACE_PROGRAM_SINGLE_FULL |
				 KCTRACE_PROGRAM_WITHIN_INTR | KCTRACE_PROGRAM_FIXED_FULL) ||
	    (single_full && !has_fixed) ||
	    (!single_full && descriptor.minimum_level == KCTRACE_LEVEL_FULL) ||
	    binding->levels != (KCTRACE_LEVEL_MASK_ALL & (~0U << descriptor.minimum_level)) ||
	    descriptor.original_site_count != binding->prepared.site_count ||
	    !descriptor.gate_count || descriptor.function_count < 2 || !descriptor.path_count ||
	    descriptor.original_site_count > U32_MAX || descriptor.probe_count > U32_MAX ||
	    descriptor.gate_count > U32_MAX || descriptor.function_count > U32_MAX ||
	    descriptor.path_count > U32_MAX || plan_count > U32_MAX)
		goto out;
	if (!IS_ALIGNED(descriptor.probes, __alignof__(struct kctrace_copy_probe)) ||
	    !IS_ALIGNED(descriptor.gates, __alignof__(struct kctrace_gate_site)) ||
	    (descriptor.probe_count &&
	     !kctrace_data_range(binding->target, descriptor.probes,
				 descriptor.probe_count * sizeof(struct kctrace_copy_probe),
				 false)) ||
	    !kctrace_data_range(binding->target, descriptor.gates,
				descriptor.gate_count * sizeof(struct kctrace_gate_site), false) ||
	    !kctrace_data_range(binding->target, descriptor.functions,
				descriptor.function_count * sizeof(*table->functions), false) ||
	    !kctrace_data_range(binding->target, descriptor.paths,
				descriptor.path_count * sizeof(struct kctrace_policy_decisions),
				false) ||
	    (plan_count && (!plans || !IS_ALIGNED((unsigned long)plans, __alignof__(*plans)) ||
			    !kctrace_data_range(binding->target, (unsigned long)plans,
						plan_count * sizeof(*plans), false))))
		goto out;
	table = kctrace_copy_program(&descriptor, plans, plan_count);
	identifiers = bitmap_zalloc(descriptor.original_site_count, GFP_KERNEL);
	identities = kvcalloc(descriptor.original_site_count + 1, sizeof(*identities), GFP_KERNEL);
	if (!table || !identifiers || !identities) {
		result = -ENOMEM;
		goto out;
	}
	result = kctrace_prepare_handlers(binding->target, &descriptor, table);
	if (result)
		goto out;
	result = -EINVAL;
	if (table->handler_count) {
		entry_ids = bitmap_zalloc(descriptor.function_count, GFP_KERNEL);
		if (!entry_ids) {
			result = -ENOMEM;
			goto out;
		}
	}
	if (memchr_inv(&table->functions[0], 0, sizeof(table->functions[0])) ||
	    memchr_inv(&table->paths[0], 0, sizeof(table->paths[0])) ||
	    !kctrace_valid_capture_chains(table->plans, plan_count))
		goto out;
	for (index = 1; index < descriptor.function_count; index++) {
		u8 floor = table->functions[index].minimum_level;

		if (floor < descriptor.minimum_level || floor > KCTRACE_LEVEL_FULL ||
		    (single_full && floor != KCTRACE_LEVEL_FULL) ||
		    (!has_fixed && floor == KCTRACE_LEVEL_FULL))
			goto out;
		for (slot = 0; slot < 8; slot++)
			if (table->functions[index].states[slot] > 23)
				goto out;
	}
	for (index = 1; index < descriptor.path_count; index++)
		for (slot = 0; slot < 8; slot++)
			if (table->paths[index].states[slot] > 23)
				goto out;
	for (index = 0; index < plan_count; index++)
		for (slot = 0; slot < KCTRACE_VALUE_SLOTS; slot++) {
			const struct kctrace_capture *capture = &table->plans[index].slots[slot];

			if (!kctrace_valid_capture(binding->target, &table->plans[index], slot))
				goto out;
			has_init |= capture->kind == KCTRACE_CAPTURE_OBJECT &&
				    within_module_init(capture->object, binding->target);
		}
	for (index = 0; index < table->probe_count; index++) {
		const struct kctrace_copy_probe *copy = &table->probes[index];
		const struct kctrace_probe_site *site = &copy->probe;
		bool init = within_module_init(site->return_pc, binding->target);

		if (!site->site_id || site->site_id > descriptor.original_site_count ||
		    site->reserved || copy->reserved || !copy->function ||
		    copy->function >= descriptor.function_count ||
		    copy->level < table->functions[copy->function].minimum_level ||
		    copy->path >= descriptor.path_count || site->capture_plan > plan_count ||
		    site->return_pc < 5 ||
		    !kctrace_text_address(binding->target, site->return_pc - 5, init, false) ||
		    !kctrace_text_address(binding->target, site->return_pc, init, false) ||
		    !kctrace_text_address(binding->target, site->pc, init, false))
			goto out;
		if (identities[site->site_id].function &&
		    (identities[site->site_id].function != copy->function ||
		     identities[site->site_id].path != copy->path))
			goto out;
		identities[site->site_id].function = copy->function;
		identities[site->site_id].path = copy->path;
		if (copy->level == KCTRACE_LEVEL_FULL) {
			if (site->type != KCTRACE_EVENT_INSTRUCTION_BEFORE ||
			    test_and_set_bit(site->site_id - 1, identifiers))
				goto out;
		} else if (copy->level != KCTRACE_LEVEL_PERFETTO || site->capture_plan ||
			   site->type != KCTRACE_EVENT_BLOCK_POINT) {
			goto out;
		}
		has_init |= init;
	}
	for (index = 0; index < table->gate_count; index++) {
		const struct kctrace_gate_site *gate = &table->gates[index];
		bool init = within_module_init(gate->return_pc, binding->target);
		bool call = gate->kind == KCTRACE_BOUNDARY_CALL ||
			    gate->kind == KCTRACE_BOUNDARY_AFTER_CALL ||
			    gate->kind == KCTRACE_BOUNDARY_CALL_UNPAIRED;
		bool full = gate->function < descriptor.function_count &&
			    table->functions[gate->function].minimum_level == KCTRACE_LEVEL_FULL;
		bool guard = full && gate->kind >= KCTRACE_GATE_INDIRECT_REG_BASE &&
			     gate->kind <= KCTRACE_GATE_UNKNOWN_CONTROL;

		if (!gate->site_id || gate->site_id > descriptor.original_site_count ||
		    !gate->function || gate->function >= descriptor.function_count ||
		    gate->path >= descriptor.path_count ||
		    (gate->kind > KCTRACE_BOUNDARY_CALL_UNPAIRED && !guard) ||
		    gate->capture_plan > plan_count ||
		    (gate->capture_plan && gate->kind != KCTRACE_BOUNDARY_ENTER &&
		     gate->kind != KCTRACE_BOUNDARY_EXIT && !guard) ||
		    gate->return_pc < 5 ||
		    !kctrace_text_address(binding->target, gate->return_pc - 5, init, false) ||
		    !kctrace_text_address(binding->target, gate->return_pc, init, false) ||
		    !kctrace_text_address(binding->target, gate->pc, init, false) ||
		    gate->related_site_id > descriptor.original_site_count ||
		    ((gate->kind == KCTRACE_BOUNDARY_CALL ||
		      gate->kind == KCTRACE_BOUNDARY_AFTER_CALL) ?
			     !gate->related_site_id :
			     !!gate->related_site_id))
			goto out;
		if (identities[gate->site_id].function &&
		    (identities[gate->site_id].function != gate->function ||
		     identities[gate->site_id].path != gate->path))
			goto out;
		identities[gate->site_id].function = gate->function;
		identities[gate->site_id].path = gate->path;
		if (full && !kctrace_valid_full_gate(binding->target, gate))
			goto out;
		if (table->handler_count && gate->kind == KCTRACE_BOUNDARY_ENTER) {
			u64 canonical = table->handler_entries[gate->function];
			const void *entry = (const void *)(unsigned long)canonical;
			static const u8 endbr[] = { 0xf3, 0x0f, 0x1e, 0xfa };

			if (test_and_set_bit(gate->function, entry_ids) ||
			    (canonical != gate->pc &&
			     (canonical > U64_MAX - sizeof(endbr) ||
			      canonical + sizeof(endbr) != gate->pc ||
			      !kctrace_owned_range(binding->target, canonical, sizeof(endbr),
						   false) ||
			      memcmp(entry, endbr, sizeof(endbr)))))
				goto out;
		}
		for (level = 0; level < 3; level++) {
			if (!full && level < descriptor.minimum_level) {
				if (gate->continuations[level] || gate->call_returns[level])
					goto out;
				continue;
			}
			if ((full ? !!gate->continuations[level] :
				    !kctrace_text_address(binding->target,
							  gate->continuations[level], init,
							  false)) ||
			    (call ? !kctrace_text_address(binding->target,
							  gate->call_returns[level], init, true) :
				    !!gate->call_returns[level]) ||
			    (full && gate->call_returns[level] != gate->call_returns[0]))
				goto out;
		}
		if (has_fixed && (gate->kind == KCTRACE_BOUNDARY_ENTER ||
				  (full && gate->kind == KCTRACE_BOUNDARY_SCOPE))) {
			struct kctrace_landing *landing = &table->landings[table->landing_count++];

			landing->pc = gate->pc;
			landing->function = gate->function;
			landing->kind = gate->kind;
		}
		/* RET/TAIL observations use their boundary snapshot after the frame
		 * has been popped; no body probe may reconstruct a new policy root.
		 */
		if (gate->kind == KCTRACE_BOUNDARY_EXIT || gate->kind == KCTRACE_BOUNDARY_TAIL ||
		    guard) {
			if (test_and_set_bit(gate->site_id - 1, identifiers) && full)
				goto out;
		}
		has_init |= init;
	}
	/* Original IDs also describe unobserved statement interiors. Terminal
	 * rendering needs boundary value snapshots. PERFETTO-only boundaries
	 * already carry execution identities and do not need extra body probes.
	 */
	for (index = 0; index < table->gate_count; index++) {
		const struct kctrace_gate_site *gate = &table->gates[index];

		if ((descriptor.flags & KCTRACE_PROGRAM_TERMINAL) &&
		    (!test_bit(gate->site_id - 1, identifiers) ||
		     (gate->related_site_id && !test_bit(gate->related_site_id - 1, identifiers))))
			goto out;
	}
	for (index = 0; index < table->probe_count; index++)
		if (!test_bit(table->probes[index].probe.site_id - 1, identifiers))
			goto out;
	if (table->handler_count)
		for (index = 1; index < descriptor.function_count; index++)
			if (table->handler_entries[index] && !test_bit(index, entry_ids))
				goto out;
	if (has_fixed) {
		sort(table->landings, table->landing_count, sizeof(*table->landings),
		     kctrace_compare_landings, NULL);
		for (index = 1; index < table->landing_count; index++)
			if (table->landings[index - 1].pc == table->landings[index].pc)
				goto out;
	}
	sort(table->probes, table->probe_count, sizeof(*table->probes), kctrace_compare_copy_probes,
	     NULL);
	sort(table->gates, table->gate_count, sizeof(*table->gates), kctrace_compare_gates, NULL);
	for (index = 1; index < table->probe_count; index++)
		if (table->probes[index - 1].probe.return_pc ==
		    table->probes[index].probe.return_pc)
			goto out;
	for (index = 0; index < table->gate_count; index++) {
		if (index && table->gates[index - 1].return_pc == table->gates[index].return_pc)
			goto out;
		while (probe_index < table->probe_count &&
		       table->probes[probe_index].probe.return_pc < table->gates[index].return_pc)
			probe_index++;
		if (probe_index < table->probe_count &&
		    table->probes[probe_index].probe.return_pc == table->gates[index].return_pc) {
			const struct kctrace_copy_probe *probe = &table->probes[probe_index];
			const struct kctrace_gate_site *gate = &table->gates[index];

			/* Only a fixed FULL ordinary boundary can share its saved
			 * preinstruction frame with the immediately following point.
			 */
			if (table->functions[gate->function].minimum_level != KCTRACE_LEVEL_FULL ||
			    probe->level != KCTRACE_LEVEL_FULL ||
			    (gate->kind != KCTRACE_BOUNDARY_SCOPE &&
			     gate->kind != KCTRACE_BOUNDARY_CALL &&
			     gate->kind != KCTRACE_BOUNDARY_CALL_UNPAIRED) ||
			    probe->probe.site_id != gate->site_id ||
			    probe->function != gate->function || probe->path != gate->path ||
			    gate->return_pc == U64_MAX || probe->probe.pc != gate->return_pc + 1)
				goto out;
		}
	}
	if (has_init) {
		/* Copy stable IDs and policies; remove only addresses whose lifetime ends.
		 */
		core = kctrace_copy_program(&descriptor, plans, plan_count);
		if (!core) {
			result = -ENOMEM;
			goto out;
		}
		if (table->handler_count) {
			core->handlers = kvmemdup(table->handlers,
						  table->handler_count * sizeof(*table->handlers),
						  GFP_KERNEL);
			core->handler_entries = kvmemdup(table->handler_entries,
							 descriptor.function_count * sizeof(u64),
							 GFP_KERNEL);
			if (!core->handlers || !core->handler_entries) {
				result = -ENOMEM;
				goto out;
			}
			core->handler_count = table->handler_count;
			for (index = 1; index < descriptor.function_count; index++)
				if (within_module_init(core->handler_entries[index],
						       binding->target))
					core->handler_entries[index] = 0;
		}
		core->probe_count = 0;
		core->gate_count = 0;
		for (index = 0; index < table->probe_count; index++)
			if (!within_module_init(table->probes[index].probe.return_pc,
						binding->target))
				core->probes[core->probe_count++] = table->probes[index];
		for (index = 0; index < table->gate_count; index++)
			if (!within_module_init(table->gates[index].return_pc, binding->target))
				core->gates[core->gate_count++] = table->gates[index];
		for (index = 0; index < table->landing_count; index++)
			if (!within_module_init(table->landings[index].pc, binding->target))
				core->landings[core->landing_count++] = table->landings[index];
		for (index = 0; index < plan_count; index++)
			for (slot = 0; slot < KCTRACE_VALUE_SLOTS; slot++) {
				struct kctrace_capture *capture = &core->plans[index].slots[slot];

				if (capture->kind == KCTRACE_CAPTURE_OBJECT &&
				    within_module_init(capture->object, binding->target))
					memset(capture, 0, sizeof(*capture));
			}
	}
	result = kctrace_prepare_xstate(table->plans, table->plan_count);
	if (!result && core)
		result = kctrace_prepare_xstate(core->plans, core->plan_count);
	if (result)
		goto out;
	binding->tasks = kvcalloc(execution_task_count, sizeof(*binding->tasks), GFP_KERNEL);
	binding->frames = kvcalloc(execution_task_count * execution_frame_count,
				   sizeof(*binding->frames), GFP_KERNEL);
	binding->irqs = alloc_percpu(struct kctrace_irq_state);
	if (!binding->tasks || !binding->frames || !binding->irqs) {
		result = -ENOMEM;
		goto free_contexts;
	}
	for_each_possible_cpu(cpu) {
		struct kctrace_irq_state *irq = per_cpu_ptr(binding->irqs, cpu);

		irq->frames = kvcalloc(KCTRACE_IRQ_LANES * execution_irq_frame_count,
				       sizeof(*irq->frames), GFP_KERNEL);
		if (!irq->frames) {
			result = -ENOMEM;
			goto free_contexts;
		}
		for (index = 0; index < KCTRACE_IRQ_LANES; index++) {
			struct kctrace_execution_context *context = &irq->lanes[index];

			context->frames = &irq->frames[index * execution_irq_frame_count];
			context->capacity = execution_irq_frame_count;
			context->terminal = !!(table->flags & KCTRACE_PROGRAM_TERMINAL);
			context->perfetto = !!(table->flags & KCTRACE_PROGRAM_PERFETTO);
			context->within_enabled = !!(table->flags & KCTRACE_PROGRAM_WITHIN_FILTER);
			context->minimum_level = table->minimum_level;
		}
	}
	raw_spin_lock_init(&binding->task_lock);
	for (index = 0; index < table->handler_count; index++) {
		if (table->handlers[index].kind != KCTRACE_INTERRUPT_TASKLET)
			continue;
		result = kctrace_tasklet_get_hooks();
		if (result)
			goto free_contexts;
		binding->tasklet_hooks = true;
		break;
	}
	binding->core_program = core;
	core = NULL;
	rcu_assign_pointer(binding->program, table);
	list_add_tail_rcu(&binding->probe_link, &probe_bindings);
	table = NULL;
	result = 0;
	goto out;
free_contexts:
	kvfree(binding->tasks);
	kvfree(binding->frames);
	kctrace_free_irqs(binding->irqs);
	binding->tasks = NULL;
	binding->frames = NULL;
	binding->irqs = NULL;
out:
	mutex_unlock(&sessions_lock);
	bitmap_free(identifiers);
	bitmap_free(entry_ids);
	kvfree(identities);
	kctrace_free_program(table);
	kctrace_free_program(core);
	return result;
}
EXPORT_SYMBOL_GPL(kctrace_register_program);

int kctrace_register_sites(struct kctrace_binding *binding, const struct kctrace_probe_site *sites,
			   u64 count, const struct kctrace_capture_plan *plans, u64 plan_count)
{
	struct kctrace_probe_table *table = NULL, *core = NULL;
	unsigned long *identifiers = NULL;
	unsigned int index, core_count = 0;
	size_t bytes;
	bool init_capture = false;
	int result = 0;

	if (!binding || !sites || !count)
		return -EINVAL;
	if (count > U32_MAX || plan_count > U32_MAX)
		return -E2BIG;
	bytes = count * sizeof(*sites);
	mutex_lock(&sessions_lock);
	if (!binding->bound || !binding->target || binding->state != KCTRACE_STATE_BOUND ||
	    binding->levels != KCTRACE_LEVEL_MASK_FULL ||
	    rcu_access_pointer(binding->probe_table) || rcu_access_pointer(binding->program)) {
		result = -EBUSY;
		goto out;
	}
	if (count != binding->prepared.site_count) {
		result = -EINVAL;
		goto out;
	}
	/* Generated tables must belong to this target, not arbitrary memory. */
	if (!kctrace_owned_range(binding->target, (unsigned long)sites, bytes, false) ||
	    (plan_count && !plans)) {
		result = -EINVAL;
		goto out;
	}
	if (plan_count && !kctrace_owned_range(binding->target, (unsigned long)plans,
					       plan_count * sizeof(*plans), true)) {
		result = -EINVAL;
		goto out;
	}
	table = kvzalloc_flex(*table, sites, count);
	identifiers = bitmap_zalloc(count, GFP_KERNEL);
	if (!table || !identifiers) {
		result = -ENOMEM;
		goto out;
	}
	table->count = count;
	table->plan_count = plan_count;
	if (plan_count) {
		table->plans = kvcalloc(plan_count, sizeof(*plans), GFP_KERNEL);
		if (!table->plans) {
			result = -ENOMEM;
			goto out;
		}
		memcpy(table->plans, plans, plan_count * sizeof(*plans));
	}
	if (!kctrace_valid_capture_chains(table->plans, plan_count)) {
		result = -EINVAL;
		goto out;
	}
	for (index = 0; index < plan_count; index++) {
		unsigned int slot;

		for (slot = 0; slot < KCTRACE_VALUE_SLOTS; slot++) {
			const struct kctrace_capture *capture = &table->plans[index].slots[slot];

			if (!kctrace_valid_capture(binding->target, &table->plans[index], slot)) {
				result = -EINVAL;
				goto out;
			}
			init_capture |= capture->kind == KCTRACE_CAPTURE_OBJECT &&
					within_module_init(capture->object, binding->target);
		}
	}
	memcpy(table->sites, sites, bytes);
	for (index = 0; index < count; index++) {
		const struct kctrace_probe_site *site = &table->sites[index];
		bool return_valid = false, pc_valid = false, init = false;

		if (!site->site_id || site->site_id > count || site->reserved ||
		    site->capture_plan > plan_count || site->return_pc < 5 ||
		    site->type < KCTRACE_EVENT_FUNCTION_ENTER ||
		    site->type > KCTRACE_EVENT_RETURN ||
		    test_and_set_bit(site->site_id - 1, identifiers)) {
			result = -EINVAL;
			goto out;
		}
		for_class_mod_mem_type(type, text)
		{
			if (within_module_mem_type(site->return_pc - 5, binding->target, type) &&
			    within_module_mem_type(site->return_pc, binding->target, type)) {
				return_valid = true;
				init = mod_mem_type_is_init(type);
			}
			pc_valid |= within_module_mem_type(site->pc, binding->target, type);
		}
		if (!return_valid || !pc_valid) {
			result = -EINVAL;
			goto out;
		}
		if (!init)
			core_count++;
	}
	/* Only relocated address binding occurs here; no code is decoded/generated.
	 */
	sort(table->sites, count, sizeof(*sites), kctrace_compare_sites, NULL);
	for (index = 1; index < count; index++)
		if (table->sites[index - 1].return_pc == table->sites[index].return_pc) {
			result = -EINVAL;
			goto out;
		}
	if (core_count != count || init_capture) {
		core = kvzalloc_flex(*core, sites, core_count);
		if (!core) {
			result = -ENOMEM;
			goto out;
		}
		/* Keep plan IDs stable; init-only slots become unavailable. */
		core->plan_count = plan_count;
		if (plan_count) {
			core->plans = kvcalloc(plan_count, sizeof(*plans), GFP_KERNEL);
			if (!core->plans) {
				result = -ENOMEM;
				goto out;
			}
			memcpy(core->plans, table->plans, plan_count * sizeof(*plans));
			for (index = 0; index < plan_count; index++) {
				unsigned int slot;

				for (slot = 0; slot < KCTRACE_VALUE_SLOTS; slot++) {
					struct kctrace_capture *capture =
						&core->plans[index].slots[slot];

					if (capture->kind == KCTRACE_CAPTURE_OBJECT &&
					    within_module_init(capture->object, binding->target))
						memset(capture, 0, sizeof(*capture));
				}
			}
		}
		for (index = 0; index < count; index++)
			if (!within_module_init(table->sites[index].return_pc, binding->target))
				core->sites[core->count++] = table->sites[index];
	}
	result = kctrace_prepare_xstate(table->plans, table->plan_count);
	if (!result && core)
		result = kctrace_prepare_xstate(core->plans, core->plan_count);
	if (result)
		goto out;
	binding->core_table = core;
	core = NULL;
	/* Publish fully validated immutable tables before exposing the binding.
	 */
	rcu_assign_pointer(binding->probe_table, table);
	list_add_tail_rcu(&binding->probe_link, &probe_bindings);
	table = NULL;
out:
	mutex_unlock(&sessions_lock);
	bitmap_free(identifiers);
	kctrace_free_table(table);
	kctrace_free_table(core);
	return result;
}
EXPORT_SYMBOL_GPL(kctrace_register_sites);

void notrace kctrace_record(struct kctrace_binding *binding, u16 type, u64 site_id, u64 pc,
			    const struct kctrace_snapshot *snapshot)
{
	struct kctrace_recorder_state previous;
	u64 begin_ns;

	if (!binding)
		return;
	if (unlikely(in_nmi())) {
		atomic64_inc(&binding->dropped);
		return;
	}
	if (type < KCTRACE_EVENT_FUNCTION_ENTER || type > KCTRACE_EVENT_RETURN || !site_id ||
	    site_id > binding->prepared.site_count ||
	    (snapshot && (snapshot->reserved || snapshot->reserved2 || snapshot->level ||
			  snapshot->capture_plans || snapshot->xstate || snapshot->xstate_mask ||
			  memchr_inv(&snapshot->execution, 0, sizeof(snapshot->execution)) ||
			  snapshot->memory_size > KCTRACE_MEMORY_SIZE ||
			  snapshot->valid_registers >> KCTRACE_REGISTER_COUNT))) {
		atomic64_inc(&binding->dropped);
		return;
	}
	if (!kctrace_recorder_enter(&previous, false)) {
		preempt_disable_notrace();
		kctrace_binding_recursion_lost(binding);
		preempt_enable_notrace();
		return;
	}
	begin_ns = ktime_get_ns();
	kctrace_emit(binding, type, site_id, pc, snapshot, begin_ns);
	kctrace_recorder_leave(&previous);
}
EXPORT_SYMBOL_GPL(kctrace_record);

static __always_inline void kctrace_capture_values(const struct kctrace_capture_plan *plans,
						   u32 plan_id, struct kctrace_snapshot *snapshot,
						   enum kctrace_capture_mode mode,
						   void *scalar_storage)
{
	u64 mask = 0;
	void *storage;

	if (!plan_id)
		return;
	snapshot->flags |= KCTRACE_EVENT_HAVE_VALUES;
	snapshot->capture_plan = plan_id;
	snapshot->capture_plans = plans;
	if (mode == KCTRACE_CAPTURE_INTEGER || (mode != KCTRACE_CAPTURE_EXTENDED && !in_task()))
		return;
	mask = plans[plan_id - 1].xstate_mask;
	storage = scalar_storage ? scalar_storage :
		  mode == KCTRACE_CAPTURE_AMX || (mode == KCTRACE_CAPTURE_EXTENDED &&
						  (mask & KCTRACE_XSTATE_AMX)) ?
				   this_cpu_read(amx_storage) :
				   this_cpu_read(xstate_storage);
	if (!mask || !storage ||
	    (mask & ~(mode == KCTRACE_CAPTURE_EXTENDED ? xstate_mask | scalar_mask :
		      mode == KCTRACE_CAPTURE_AMX      ? xstate_mask :
							 xstate_fpu_mask)))
		return;
	if (mode == KCTRACE_CAPTURE_EXTENDED && scalar_storage) {
		mask &= KCTRACE_XSTATE_SCALAR;
		if (!mask)
			return;
	}
	if (mode != KCTRACE_CAPTURE_EXTENDED || (mask & ~KCTRACE_XSTATE_SCALAR)) {
		if (native_read_cr0() & X86_CR0_TS) {
			if (mode != KCTRACE_CAPTURE_EXTENDED)
				return;
			mask &= KCTRACE_XSTATE_SCALAR;
		}
	}
	if ((mode == KCTRACE_CAPTURE_AMX ||
	     (mode == KCTRACE_CAPTURE_EXTENDED && (mask & KCTRACE_XSTATE_AMX))) &&
	    boot_cpu_has(X86_FEATURE_XFD)) {
		u64 disabled;
		u32 low, high;

		/* XSAVE reports XFD-disabled tile data as architectural init.
		 * Do not present those bytes as observed target values.
		 */
		if (rdmsr_safe(MSR_IA32_XFD, &low, &high))
			disabled = KCTRACE_XSTATE_AMX;
		else
			disabled = (u64)high << 32 | low;
		mask &= ~(disabled & KCTRACE_XSTATE_AMX);
		if (!mask)
			return;
	}
	storage = PTR_ALIGN(storage, 64);
	memset(storage + 512, 0, 64);
	/* User-state intervals are proved owned offline. Scalar-only captures
	 * below neither access FPU registers nor claim FPU ownership.
	 */
	if (mode != KCTRACE_CAPTURE_EXTENDED || (mask & ~KCTRACE_XSTATE_SCALAR)) {
		u64 saved = mode == KCTRACE_CAPTURE_EXTENDED ? mask & ~KCTRACE_XSTATE_SCALAR : mask;

		asm volatile("xsave64 (%0)"
			     :
			     : "r"(storage), "a"((u32)saved), "d"((u32)(saved >> 32))
			     : "memory");
	}
	if (mode == KCTRACE_CAPTURE_EXTENDED) {
		unsigned int component;
		u64 present;

		if (mask & KCTRACE_XSTATE_SUPERVISOR) {
			for (component = 0; component < ARRAY_SIZE(supervisor_components);
			     component++) {
				unsigned int word;
				u64 bit = BIT_ULL(supervisor_components[component].component);

				if (!(mask & bit))
					continue;
				for (word = 0; word < supervisor_components[component].count;
				     word++) {
					u32 low, high;
					u64 value;

					if (rdmsr_safe(supervisor_components[component].msrs[word],
						       &low, &high)) {
						mask &= ~bit;
						break;
					}
					value = (u64)high << 32 | low;
					memcpy(storage + supervisor_components[component].offset +
						       8 * word,
					       &value, sizeof(value));
				}
			}
		}
		if (mask & KCTRACE_XSTATE_USER_SCALAR) {
			u32 low, high;
			u64 value;

			/* OSPKE availability is fixed before binding. */
			asm volatile("rdpkru" : "=a"(low), "=d"(high) : "c"(0));
			value = low;
			memcpy(storage + 544, &value, sizeof(value));
		}
		memcpy(&present, storage + 512, sizeof(present));
		present |= mask & KCTRACE_XSTATE_SCALAR;
		memcpy(storage + 512, &present, sizeof(present));
	}
	snapshot->xstate = storage;
	snapshot->xstate_mask = mask;
}

static const struct kctrace_copy_probe *notrace
kctrace_find_copy_probe(const struct kctrace_program_table *program, u64 return_pc)
{
	unsigned int low = 0, high = program->probe_count;

	while (low < high) {
		unsigned int middle = low + (high - low) / 2;

		if (program->probes[middle].probe.return_pc < return_pc)
			low = middle + 1;
		else
			high = middle;
	}
	if (low == program->probe_count || program->probes[low].probe.return_pc != return_pc)
		return NULL;
	return &program->probes[low];
}

static const struct kctrace_gate_site *notrace
kctrace_find_gate(const struct kctrace_program_table *program, u64 return_pc)
{
	unsigned int low = 0, high = program->gate_count;

	while (low < high) {
		unsigned int middle = low + (high - low) / 2;

		if (program->gates[middle].return_pc < return_pc)
			low = middle + 1;
		else
			high = middle;
	}
	if (low == program->gate_count || program->gates[low].return_pc != return_pc)
		return NULL;
	return &program->gates[low];
}

static const struct kctrace_probe_site *notrace
kctrace_find_probe(const struct kctrace_probe_table *table, u64 return_pc)
{
	unsigned int low = 0, high = table->count;

	while (low < high) {
		unsigned int middle = low + (high - low) / 2;

		if (table->sites[middle].return_pc < return_pc)
			low = middle + 1;
		else
			high = middle;
	}
	if (low == table->count || table->sites[low].return_pc != return_pc)
		return NULL;
	return &table->sites[low];
}

static void notrace kctrace_recursion_lost(u64 return_pc)
{
	struct kctrace_binding *binding;

	/* A skipped boundary belongs to its actual binding and current IRQ lane,
	 * not to the recorder it interrupted. Lookup only immutable copied tables;
	 * this error path neither takes a ring/task lock nor samples time.
	 */
	if (unlikely(in_nmi()))
		return;
	preempt_disable_notrace();
	if (unlikely(!rcu_is_watching()))
		goto done;
	rcu_read_lock();
	list_for_each_entry_rcu(binding, &probe_bindings, probe_link) {
		const struct kctrace_program_table *program;
		const struct kctrace_probe_table *table;

		if (!READ_ONCE(binding->enabled))
			continue;
		program = rcu_dereference(binding->program);
		table = rcu_dereference(binding->probe_table);
		if ((program && (kctrace_find_gate(program, return_pc) ||
				 kctrace_find_copy_probe(program, return_pc))) ||
		    (table && kctrace_find_probe(table, return_pc))) {
			kctrace_binding_recursion_lost(binding);
			break;
		}
	}
	rcu_read_unlock();
done:
	preempt_enable_notrace();
}

static void notrace kctrace_snapshot_registers(struct kctrace_snapshot *snapshot,
					       const struct kctrace_probe_frame *frame, u64 stack,
					       u64 flags, u64 rax, u64 pc)
{
	snapshot->valid_registers = (1ULL << KCTRACE_REGISTER_COUNT) - 1;
	snapshot->registers[KCTRACE_REG_RAX] = rax;
	snapshot->registers[KCTRACE_REG_RBX] = frame->rbx;
	snapshot->registers[KCTRACE_REG_RCX] = frame->rcx;
	snapshot->registers[KCTRACE_REG_RDX] = frame->rdx;
	snapshot->registers[KCTRACE_REG_RSI] = frame->rsi;
	snapshot->registers[KCTRACE_REG_RDI] = frame->rdi;
	snapshot->registers[KCTRACE_REG_RBP] = frame->rbp;
	snapshot->registers[KCTRACE_REG_RSP] = stack;
	snapshot->registers[KCTRACE_REG_R8] = frame->r8;
	snapshot->registers[KCTRACE_REG_R9] = frame->r9;
	snapshot->registers[KCTRACE_REG_R10] = frame->r10;
	snapshot->registers[KCTRACE_REG_R11] = frame->r11;
	snapshot->registers[KCTRACE_REG_R12] = frame->r12;
	snapshot->registers[KCTRACE_REG_R13] = frame->r13;
	snapshot->registers[KCTRACE_REG_R14] = frame->r14;
	snapshot->registers[KCTRACE_REG_R15] = frame->r15;
	snapshot->registers[KCTRACE_REG_RFLAGS] = flags;
	snapshot->registers[KCTRACE_REG_RIP] = pc;
}

static void notrace kctrace_body_state(struct kctrace_binding *binding,
				       const struct kctrace_program_table *program,
				       const struct kctrace_copy_probe *probe,
				       struct kctrace_snapshot *snapshot)
{
	struct kctrace_execution_context *context;
	const struct kctrace_execution_frame *frame = NULL;
	struct kctrace_execution_record *record = &snapshot->execution;

	context = kctrace_current_context(binding, program, false);
	snapshot->flags |= KCTRACE_EVENT_HAVE_EXECUTION;
	snapshot->level = probe->level;
	record->function = probe->function;
	record->path = probe->path;
	record->kind = KCTRACE_BOUNDARY_POINT;
	if (context && context->depth)
		frame = &context->frames[context->depth - 1];
	if (context && (!frame || frame->function != probe->function ||
			frame->path != probe->path || frame->level != probe->level))
		kctrace_poison_context(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
	if (!context || context->failure) {
		record->flags = KCTRACE_EXEC_UNKNOWN | KCTRACE_EXEC_DISCONTINUITY;
		record->failure = context   ? context->failure :
				  in_task() ? KCTRACE_FAILURE_CONTEXT_LIMIT :
					      KCTRACE_FAILURE_UNSUPPORTED_CONTEXT;
		return;
	}
	record->frame_id = frame->id;
	record->parent_frame_id = frame->parent_id;
	record->call_id = frame->incoming_call;
	record->state = frame->state;
	record->previous_level = frame->level;
}

static const struct kctrace_landing *notrace
kctrace_find_landing(const struct kctrace_program_table *program, u64 pc)
{
	unsigned int low = 0, high = program->landing_count;

	while (low < high) {
		unsigned int middle = low + (high - low) / 2;

		if (program->landings[middle].pc < pc)
			low = middle + 1;
		else
			high = middle;
	}
	if (low == program->landing_count || program->landings[low].pc != pc)
		return NULL;
	return &program->landings[low];
}

/* Both entry helpers hold the recorder guard and the binding's RCU lifetime.
 * A FULL adapter gate ignores the returned level; its physical body is fixed.
 */
static __always_inline unsigned int
kctrace_dispatch_variant(struct kctrace_binding *binding,
			 const struct kctrace_program_table *program,
			 const struct kctrace_gate_site *gate, const void *registers,
			 unsigned long stack, u64 flags, u64 rax, u64 begin_ns,
			 enum kctrace_capture_mode mode, void *scalar_storage)
{
	struct kctrace_execution_boundary boundary = {};
	struct kctrace_execution_result result = {};
	struct kctrace_snapshot snapshot = {};
	struct kctrace_probe_frame common;
	struct kctrace_execution_context *context;
	bool guard = gate->kind >= KCTRACE_GATE_INDIRECT_REG_BASE;
	bool have_registers = false;
	u32 inheritance = 0;
	unsigned int selected = KCTRACE_LEVEL_FULL;

	context = kctrace_current_context(binding, program, true);
	boundary.site_id = gate->site_id;
	boundary.stack = stack;
	boundary.related_site_id = gate->related_site_id;
	boundary.function = gate->function;
	boundary.path = gate->path;
	boundary.kind = gate->kind;
	memcpy(boundary.call_returns, gate->call_returns, sizeof(boundary.call_returns));
	if (guard) {
		const struct kctrace_landing *landing = NULL;
		const struct kctrace_execution_frame *active = NULL;

		/* Guard snapshots are original instruction observations. No POINT
		 * follows them, since a proven tail has already closed its frame.
		 */
		memcpy(&common, registers, sizeof(common));
		kctrace_snapshot_registers(&snapshot, &common, stack, flags, rax, gate->pc);
		have_registers = true;
		boundary.kind = KCTRACE_EXECUTION_SCOPE;
		if (gate->kind < KCTRACE_GATE_UNKNOWN_CONTROL) {
			unsigned int reg = gate->kind - KCTRACE_GATE_INDIRECT_REG_BASE;

			landing = kctrace_find_landing(program, snapshot.registers[reg]);
		}
		if (context && context->depth)
			active = &context->frames[context->depth - 1];
		if (landing && landing->kind == KCTRACE_BOUNDARY_SCOPE &&
		    landing->function == gate->function) {
			/* The destination's own SCOPE gate applies its target path. */
		} else if (landing && landing->kind == KCTRACE_BOUNDARY_ENTER && active &&
			   active->function == gate->function && active->entry_stack == stack) {
			boundary.kind = KCTRACE_EXECUTION_TAIL;
		} else if (context) {
			kctrace_poison_context(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
		}
	}
	if (context && !in_task() && boundary.kind == KCTRACE_EXECUTION_ENTER && !context->depth &&
	    !context->failure) {
		inheritance = context->within_enabled ? kctrace_inherited_within(binding) :
							KCTRACE_INHERIT_VALID;
		boundary.root_within = inheritance & KCTRACE_INHERIT_UNKNOWN ?
					       KCTRACE_EXECUTION_WITHIN_UNKNOWN :
					       !!(inheritance & KCTRACE_INHERIT_WITHIN);
	}
	if ((context || program->handler_count) && boundary.kind == KCTRACE_EXECUTION_ENTER) {
		unsigned long base = (unsigned long)task_stack_page(current);

		/* Only an authenticated canonical ENTRY reads this original return
		 * word. This authorizes no arbitrary IRQ-stack local capture.
		 */
		if ((!in_task() ||
		     (base && stack >= base && stack - base <= THREAD_SIZE - sizeof(u64))) &&
		    copy_from_kernel_nofault(&boundary.return_pc, (const void *)stack, sizeof(u64)))
			boundary.return_pc = 0;
		if (program->handler_count) {
			const struct kctrace_probe_frame *saved = registers;
			unsigned int low = 0, high = program->handler_count;
			bool healthy = context && !context->failure;

			if (!boundary.return_pc && healthy)
				kctrace_poison_context(context, KCTRACE_EXECUTION_BAD_BOUNDARY);
			while (low < high) {
				unsigned int middle = low + (high - low) / 2;

				if (program->handlers[middle].return_pc < boundary.return_pc)
					low = middle + 1;
				else
					high = middle;
			}
			if (low < program->handler_count &&
			    program->handlers[low].return_pc == boundary.return_pc) {
				const struct kctrace_interrupt_dispatch *handler =
					&program->handlers[low];
				u64 address = handler->reg == KCTRACE_REG_RBX ? saved->rbx :
					      handler->reg == KCTRACE_REG_R13 ? saved->r13 :
					      handler->reg == KCTRACE_REG_R12 ? saved->r12 :
					      handler->reg == KCTRACE_REG_RDX ? saved->rdx :
										saved->rbp;
				u64 target = address;
				u64 canonical = program->handler_entries[gate->function];
				enum kctrace_execution_failure bad = KCTRACE_EXECUTION_BAD_BOUNDARY;
				const void *word =
					(const void *)(unsigned long)(address +
								      handler->word_offset);

				if (handler->target == KCTRACE_INTERRUPT_TASKLET_TOKEN) {
					int selected = kctrace_tasklet_handler(saved, canonical);

					/* Failure/overflow must not leave a reusable invocation. */
					if (healthy && selected)
						boundary.handler_within =
							selected > 0 ?
								KCTRACE_EXECUTION_HANDLER_PROVED :
								KCTRACE_EXECUTION_HANDLER_UNKNOWN;
				} else if (healthy) {
					if (handler->target == KCTRACE_INTERRUPT_SAVED_WORD &&
					    (address > U64_MAX - handler->word_offset ||
					     copy_from_kernel_nofault(&target, word,
								      sizeof(target))))
						kctrace_poison_context(context, bad);
					else
						boundary.handler_within = target &&
									  target == canonical;
				}
			}
		}
	}
	if (context) {
		result = kctrace_execution_dispatch(context, &program->policy, &boundary);
		kctrace_publish_within(context);
		selected = result.level;
	} else {
		result.level = KCTRACE_LEVEL_FULL;
		result.flags = KCTRACE_EXECUTION_UNKNOWN | KCTRACE_EXECUTION_DISCONTINUITY;
	}
	snapshot.flags = KCTRACE_EVENT_HAVE_EXECUTION;
	snapshot.level = selected;
	snapshot.execution.frame_id = result.frame_id;
	snapshot.execution.parent_frame_id = result.parent_frame_id;
	snapshot.execution.call_id = result.call_id;
	snapshot.execution.function = gate->function;
	snapshot.execution.path = gate->path;
	snapshot.execution.state = result.state;
	snapshot.execution.previous_level = result.previous_level;
	snapshot.execution.kind = boundary.kind;
	snapshot.execution.flags = result.flags | (guard ? KCTRACE_EXEC_INSTRUCTION : 0);
	snapshot.execution.inheritance = inheritance;
	snapshot.execution.failure = context   ? result.failure :
				     in_task() ? KCTRACE_FAILURE_CONTEXT_LIMIT :
						 KCTRACE_FAILURE_UNSUPPORTED_CONTEXT;
	snapshot.valid_registers |= (1ULL << KCTRACE_REG_RSP) | (1ULL << KCTRACE_REG_RIP);
	snapshot.registers[KCTRACE_REG_RSP] = stack;
	snapshot.registers[KCTRACE_REG_RIP] = gate->pc;
	if (guard ||
	    (result.flags & (KCTRACE_EXECUTION_ENTRY_VALUES | KCTRACE_EXECUTION_RETURN_VALUE)) ||
	    (selected == KCTRACE_LEVEL_FULL && (boundary.kind == KCTRACE_EXECUTION_EXIT ||
						boundary.kind == KCTRACE_EXECUTION_TAIL))) {
		if (!have_registers) {
			/* The assembly frames share this GPR prefix; flags/RAX/SP are
			 * explicit because the selector has one extra saved RAX word.
			 */
			memcpy(&common, registers, sizeof(common));
			kctrace_snapshot_registers(&snapshot, &common, stack, flags, rax, gate->pc);
		}
		kctrace_capture_values(program->plans, gate->capture_plan, &snapshot, mode,
				       scalar_storage);
	}
	kctrace_emit(binding, KCTRACE_EVENT_EXECUTION, gate->site_id, gate->pc, &snapshot,
		     begin_ns);
	return context && context->failure ? KCTRACE_LEVEL_FULL : selected;
}

static unsigned int notrace kctrace_dispatch_regular(struct kctrace_binding *binding,
						     const struct kctrace_program_table *program,
						     const struct kctrace_gate_site *gate,
						     const void *registers, unsigned long stack,
						     u64 flags, u64 rax, u64 begin_ns, bool fpu)
{
	return kctrace_dispatch_variant(binding, program, gate, registers, stack, flags, rax,
					begin_ns,
					fpu ? KCTRACE_CAPTURE_FPU : KCTRACE_CAPTURE_INTEGER, NULL);
}

static __always_inline unsigned int
kctrace_dispatch_gate(struct kctrace_binding *binding, const struct kctrace_program_table *program,
		      const struct kctrace_gate_site *gate, const void *registers,
		      unsigned long stack, u64 flags, u64 rax, u64 begin_ns,
		      enum kctrace_capture_mode mode, void *scalar_storage)
{
	if (mode == KCTRACE_CAPTURE_AMX || mode == KCTRACE_CAPTURE_EXTENDED)
		return kctrace_dispatch_variant(binding, program, gate, registers, stack, flags,
						rax, begin_ns, mode, scalar_storage);
	return kctrace_dispatch_regular(binding, program, gate, registers, stack, flags, rax,
					begin_ns, mode == KCTRACE_CAPTURE_FPU);
}

static __always_inline unsigned int kctrace_select_observe(const struct kctrace_select_frame *frame,
							   enum kctrace_capture_mode mode,
							   void *scalar_storage)
{
	struct kctrace_binding *binding;
	struct kctrace_recorder_state previous;
	unsigned int selected = KCTRACE_LEVEL_FULL;
	u64 begin_ns;

	if (unlikely(in_nmi()))
		return selected;
	if (!kctrace_recorder_enter(&previous, false)) {
		kctrace_recursion_lost(frame->return_pc);
		return selected;
	}
	begin_ns = ktime_get_ns();
	if (unlikely(!rcu_is_watching()))
		goto done;
	rcu_read_lock();
	list_for_each_entry_rcu(binding, &probe_bindings, probe_link) {
		const struct kctrace_program_table *program;
		const struct kctrace_gate_site *gate;

		if (!READ_ONCE(binding->enabled))
			continue;
		program = rcu_dereference(binding->program);
		if (!program || (program->flags & KCTRACE_PROGRAM_SINGLE_FULL))
			continue;
		gate = kctrace_find_gate(program, frame->return_pc);
		if (!gate)
			continue;
		selected = kctrace_dispatch_gate(binding, program, gate, frame,
						 (unsigned long)(frame + 1), frame->flags,
						 frame->original_rax, begin_ns, mode,
						 scalar_storage);
		break;
	}
	rcu_read_unlock();
done:
	kctrace_recorder_leave(&previous);
	return selected;
}

/* Keep the existing integer/FPU body shared. Extended state modes compile
 * separately, so their checks cannot enter the ordinary body.
 */
static unsigned int notrace kctrace_select_regular(const struct kctrace_select_frame *frame,
						   bool fpu)
{
	return kctrace_select_observe(frame, fpu ? KCTRACE_CAPTURE_FPU : KCTRACE_CAPTURE_INTEGER,
				      NULL);
}

unsigned int notrace kctrace_select_saved(const struct kctrace_select_frame *frame)
{
	return kctrace_select_regular(frame, false);
}
EXPORT_SYMBOL(kctrace_select);

unsigned int notrace kctrace_select_fpu_saved(const struct kctrace_select_frame *frame)
{
	return kctrace_select_regular(frame, true);
}
EXPORT_SYMBOL(kctrace_select_fpu);

unsigned int notrace kctrace_select_amx_saved(const struct kctrace_select_frame *frame)
{
	return kctrace_select_observe(frame, KCTRACE_CAPTURE_AMX, NULL);
}
EXPORT_SYMBOL(kctrace_select_amx);

/* Separate frames keep IRQ scratch off the task-context extended path.
 * Each nested IRQ owns its bytes until observation and publication complete.
 */
static noinline unsigned int notrace
kctrace_select_scalar_irq(const struct kctrace_select_frame *frame)
{
	u8 storage[576] __aligned(64);

	return kctrace_select_observe(frame, KCTRACE_CAPTURE_EXTENDED, storage);
}

unsigned int notrace kctrace_select_extended_saved(const struct kctrace_select_frame *frame)
{
	if (!in_task())
		return kctrace_select_scalar_irq(frame);
	return kctrace_select_observe(frame, KCTRACE_CAPTURE_EXTENDED, NULL);
}
EXPORT_SYMBOL(kctrace_select_extended);

void notrace kctrace_perfetto_saved(const struct kctrace_perfetto_frame *frame)
{
	struct kctrace_binding *binding;
	struct kctrace_recorder_state previous;
	struct kctrace_snapshot snapshot = {};
	u64 begin_ns;

	if (unlikely(in_nmi()))
		return;
	if (!kctrace_recorder_enter(&previous, false)) {
		kctrace_recursion_lost(frame->return_pc);
		return;
	}
	begin_ns = ktime_get_ns();
	if (unlikely(!rcu_is_watching()))
		goto done;
	rcu_read_lock();
	list_for_each_entry_rcu(binding, &probe_bindings, probe_link) {
		const struct kctrace_program_table *program;
		const struct kctrace_copy_probe *probe;

		if (!READ_ONCE(binding->enabled))
			continue;
		program = rcu_dereference(binding->program);
		if (!program)
			continue;
		probe = kctrace_find_copy_probe(program, frame->return_pc);
		if (!probe || probe->level != KCTRACE_LEVEL_PERFETTO)
			continue;
		kctrace_body_state(binding, program, probe, &snapshot);
		snapshot.valid_registers = (1ULL << KCTRACE_REG_RSP) | (1ULL << KCTRACE_REG_RIP);
		snapshot.registers[KCTRACE_REG_RSP] = (unsigned long)(frame + 1);
		snapshot.registers[KCTRACE_REG_RIP] = probe->probe.pc;
		kctrace_emit(binding, KCTRACE_EVENT_BLOCK_POINT, probe->probe.site_id,
			     probe->probe.pc, &snapshot, begin_ns);
		break;
	}
	rcu_read_unlock();
done:
	kctrace_recorder_leave(&previous);
}
EXPORT_SYMBOL(kctrace_perfetto_probe);

static __always_inline void kctrace_probe_observe(const struct kctrace_probe_frame *frame,
						  enum kctrace_capture_mode mode,
						  void *scalar_storage)
{
	struct kctrace_binding *binding;
	struct kctrace_recorder_state previous;
	struct kctrace_snapshot snapshot = {};
	u64 begin_ns;

	/* Eligible probes run with RCU watching; noinstr and NMI are unsupported. */
	if (unlikely(in_nmi()))
		return;
	if (!kctrace_recorder_enter(&previous, false)) {
		kctrace_recursion_lost(frame->return_pc);
		return;
	}
	begin_ns = ktime_get_ns();
	if (unlikely(!rcu_is_watching()))
		goto done;
	rcu_read_lock();
	list_for_each_entry_rcu(binding, &probe_bindings, probe_link) {
		const struct kctrace_probe_table *table;
		const struct kctrace_program_table *program;
		const struct kctrace_probe_site *site;

		if (!READ_ONCE(binding->enabled))
			continue;
		program = rcu_dereference(binding->program);
		if (program) {
			const struct kctrace_copy_probe *probe = NULL;

			if (program->flags & KCTRACE_PROGRAM_FIXED_FULL) {
				const struct kctrace_gate_site *gate =
					kctrace_find_gate(program, frame->return_pc);

				if (gate) {
					kctrace_dispatch_gate(binding, program, gate, frame,
							      (unsigned long)(frame + 1),
							      frame->flags, frame->rax, begin_ns,
							      mode, scalar_storage);
					if (gate->kind != KCTRACE_BOUNDARY_SCOPE &&
					    gate->kind != KCTRACE_BOUNDARY_CALL &&
					    gate->kind != KCTRACE_BOUNDARY_CALL_UNPAIRED)
						break;
					probe = kctrace_find_copy_probe(program, frame->return_pc);
					if (!probe)
						break;
					/* The first event accounts for boundary work.
					 * Do not charge it again to the fused point.
					 */
					begin_ns = ktime_get_ns();
				}
			}
			if (!probe)
				probe = kctrace_find_copy_probe(program, frame->return_pc);
			if (!probe || probe->level != KCTRACE_LEVEL_FULL)
				continue;
			kctrace_body_state(binding, program, probe, &snapshot);
			kctrace_snapshot_registers(&snapshot, frame, (unsigned long)(frame + 1),
						   frame->flags, frame->rax, probe->probe.pc);
			kctrace_capture_values(program->plans, probe->probe.capture_plan, &snapshot,
					       mode, scalar_storage);
			kctrace_emit(binding, probe->probe.type, probe->probe.site_id,
				     probe->probe.pc, &snapshot, begin_ns);
			break;
		}
		table = rcu_dereference(binding->probe_table);
		if (!table)
			continue;
		site = kctrace_find_probe(table, frame->return_pc);
		if (!site)
			continue;
		kctrace_snapshot_registers(&snapshot, frame, (unsigned long)(frame + 1),
					   frame->flags, frame->rax, site->pc);
		kctrace_capture_values(table->plans, site->capture_plan, &snapshot, mode,
				       scalar_storage);
		kctrace_emit(binding, site->type, site->site_id, site->pc, &snapshot, begin_ns);
		break;
	}
	rcu_read_unlock();
done:
	kctrace_recorder_leave(&previous);
}

static void notrace kctrace_probe_regular(const struct kctrace_probe_frame *frame, bool fpu)
{
	kctrace_probe_observe(frame, fpu ? KCTRACE_CAPTURE_FPU : KCTRACE_CAPTURE_INTEGER, NULL);
}

void notrace kctrace_probe_saved(const struct kctrace_probe_frame *frame)
{
	kctrace_probe_regular(frame, false);
}
EXPORT_SYMBOL(kctrace_probe);

void notrace kctrace_probe_fpu_saved(const struct kctrace_probe_frame *frame)
{
	kctrace_probe_regular(frame, true);
}
EXPORT_SYMBOL(kctrace_probe_fpu);

void notrace kctrace_probe_amx_saved(const struct kctrace_probe_frame *frame)
{
	kctrace_probe_observe(frame, KCTRACE_CAPTURE_AMX, NULL);
}
EXPORT_SYMBOL(kctrace_probe_amx);

static noinline void notrace kctrace_probe_scalar_irq(const struct kctrace_probe_frame *frame)
{
	u8 storage[576] __aligned(64);

	kctrace_probe_observe(frame, KCTRACE_CAPTURE_EXTENDED, storage);
}

void notrace kctrace_probe_extended_saved(const struct kctrace_probe_frame *frame)
{
	if (!in_task()) {
		kctrace_probe_scalar_irq(frame);
		return;
	}
	kctrace_probe_observe(frame, KCTRACE_CAPTURE_EXTENDED, NULL);
}
EXPORT_SYMBOL(kctrace_probe_extended);

void kctrace_initialized(struct kctrace_binding *binding, int result)
{
	struct kctrace_probe_table *retired = NULL;
	struct kctrace_program_table *retired_program = NULL;

	if (!binding)
		return;
	mutex_lock(&sessions_lock);
	if (binding->bound && binding->state == KCTRACE_STATE_BOUND) {
		if (binding->core_table) {
			retired = rcu_dereference_protected(binding->probe_table,
							    lockdep_is_held(&sessions_lock));
			/* Retire init addresses before the module loader frees them. */
			rcu_assign_pointer(binding->probe_table, binding->core_table);
			binding->core_table = NULL;
		}
		if (binding->core_program) {
			retired_program =
				rcu_dereference_protected(binding->program,
							  lockdep_is_held(&sessions_lock));
			rcu_assign_pointer(binding->program, binding->core_program);
			binding->core_program = NULL;
		}
		binding->init_result = result;
		binding->state = result < 0 ? KCTRACE_STATE_INIT_FAILED : KCTRACE_STATE_LIVE;
		kctrace_emit(binding,
			     result < 0 ? KCTRACE_EVENT_INIT_FAILED : KCTRACE_EVENT_INIT_COMPLETE,
			     0, 0, NULL, 0);
	}
	mutex_unlock(&sessions_lock);
	if (retired || retired_program) {
		synchronize_rcu();
		kctrace_free_table(retired);
		kctrace_free_program(retired_program);
	}
}
EXPORT_SYMBOL(kctrace_initialized);

void kctrace_unbind(struct kctrace_binding *binding)
{
	struct kctrace_probe_table *retired = NULL, *core = NULL;
	struct kctrace_program_table *retired_program = NULL, *core_program = NULL;
	bool release = false;

	if (!binding)
		return;
	/* GOING follows target exit or a failed load. Explicit callers quiesce it. */
	mutex_lock(&sessions_lock);
	if (binding->bound) {
		retired = rcu_dereference_protected(binding->probe_table,
						    lockdep_is_held(&sessions_lock));
		if (retired) {
			RCU_INIT_POINTER(binding->probe_table, NULL);
			core = binding->core_table;
			binding->core_table = NULL;
		}
		retired_program = rcu_dereference_protected(binding->program,
							    lockdep_is_held(&sessions_lock));
		if (retired_program) {
			RCU_INIT_POINTER(binding->program, NULL);
			core_program = binding->core_program;
			binding->core_program = NULL;
		}
		if (retired || retired_program)
			list_del_rcu(&binding->probe_link);
		if (binding->tasklet_hooks) {
			binding->tasklet_hooks = false;
			kctrace_tasklet_put_hooks();
		}
		if (binding->state == KCTRACE_STATE_BOUND) {
			binding->state = KCTRACE_STATE_LOAD_ABORTED;
			kctrace_emit(binding, KCTRACE_EVENT_LOAD_ABORTED, 0, 0, NULL, 0);
		} else if (binding->state != KCTRACE_STATE_INIT_FAILED) {
			binding->state = KCTRACE_STATE_EXIT_COMPLETE;
			kctrace_emit(binding, KCTRACE_EVENT_EXIT_COMPLETE, 0, 0, NULL, 0);
		}
		if (binding->target_slot) {
			/* Pair with the wrapper acquire before releasing the binding. */
			smp_store_release(binding->target_slot, NULL);
			binding->target_slot = NULL;
		}
		binding->bound = false;
		binding->target = NULL;
		kctrace_disable(binding);
		if (!binding->owner_present)
			list_del(&binding->link);
		release = true;
	}
	mutex_unlock(&sessions_lock);
	if (release) {
		/* Lookup and recording share one RCU read section, including IRQs. */
		if (retired || retired_program)
			synchronize_rcu();
		wait_event(binding->drained, !atomic_read(&binding->active));
		kctrace_free_table(retired);
		kctrace_free_table(core);
		kctrace_free_program(retired_program);
		kctrace_free_program(core_program);
		kref_put(&binding->refs, kctrace_free);
	}
}
EXPORT_SYMBOL_GPL(kctrace_unbind);

#ifdef CONFIG_KALLSYMS
/* Only this already relocated target's symbols are inspected. COMING holds
 * its loader lifetime; the full init symbol table remains valid throughout.
 */
static int kctrace_bootstrap_descriptor(struct module *target, struct kctrace_bootstrap *descriptor)
{
	static const char name[] = "__ctrace_bootstrap";
	struct mod_kallsyms *symbols;
	const struct kctrace_bootstrap *found = NULL;
	unsigned int index;
	int result = 0;

	rcu_read_lock();
	symbols = rcu_dereference(target->kallsyms);
	if (!symbols ||
	    !kctrace_owned_range(target, (unsigned long)symbols, sizeof(*symbols), true) ||
	    !kctrace_owned_range(target, (unsigned long)symbols->symtab,
				 (u64)symbols->num_symtab * sizeof(*symbols->symtab), true)) {
		result = -ENODATA;
		goto out;
	}
	for (index = 0; index < symbols->num_symtab; index++) {
		const typeof(*symbols->symtab) *symbol = &symbols->symtab[index];
		unsigned long address, symbol_name;

		if (check_add_overflow((unsigned long)symbols->strtab,
				       (unsigned long)symbol->st_name, &symbol_name) ||
		    !kctrace_owned_range(target, symbol_name, sizeof(name), true) ||
		    memcmp((const void *)symbol_name, name, sizeof(name)))
			continue;
		address = kallsyms_symbol_value(symbol);
		if (found || symbol->st_shndx == SHN_UNDEF ||
		    ELF_ST_TYPE(symbol->st_info) != STT_OBJECT ||
		    symbol->st_size != sizeof(*descriptor) ||
		    !IS_ALIGNED(address, __alignof__(*descriptor)) ||
		    !kctrace_data_range(target, address, sizeof(*descriptor), false)) {
			result = -EINVAL;
			goto out;
		}
		found = (const void *)address;
	}
	if (found) {
		memcpy(descriptor, found, sizeof(*descriptor));
		result = 1;
	}
out:
	rcu_read_unlock();
	return result;
}

static int kctrace_module_notify(struct notifier_block *notifier, unsigned long action,
				 void *argument)
{
	struct module *target = argument;
	struct kctrace_binding *binding = NULL, *entry;
	struct kctrace_bootstrap descriptor;
	struct kctrace_binding **slot;
	u64 site_count, plan_count;
	bool candidate = false;
	int result;

	if (action != MODULE_STATE_COMING && action != MODULE_STATE_GOING)
		return NOTIFY_DONE;
	mutex_lock(&sessions_lock);
	list_for_each_entry(entry, &sessions, link) {
		if (action == MODULE_STATE_GOING && entry->bound && entry->target == target &&
		    entry->target_slot) {
			kref_get(&entry->refs);
			binding = entry;
			break;
		}
		if (action == MODULE_STATE_COMING && entry->state == KCTRACE_STATE_PREPARED &&
		    !strcmp(entry->prepared.module_name, target->name))
			candidate = true;
	}
	mutex_unlock(&sessions_lock);
	if (action == MODULE_STATE_GOING) {
		if (binding) {
			kctrace_unbind(binding);
			kref_put(&binding->refs, kctrace_free);
		}
		return NOTIFY_DONE;
	}
	result = kctrace_bootstrap_descriptor(target, &descriptor);
	if (result == -ENODATA && !candidate)
		return NOTIFY_DONE;
	if (result <= 0)
		return result ? notifier_from_errno(result) : NOTIFY_DONE;
	if (descriptor.size != sizeof(descriptor) ||
	    memcmp(descriptor.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE) ||
	    descriptor.flags ||
	    !IS_ALIGNED(descriptor.manifest, __alignof__(struct kctrace_manifest)) ||
	    !kctrace_data_range(target, descriptor.manifest, sizeof(struct kctrace_manifest),
				false) ||
	    !IS_ALIGNED(descriptor.site_count_address, sizeof(u64)) ||
	    !kctrace_data_range(target, descriptor.site_count_address, sizeof(u64), false) ||
	    !IS_ALIGNED(descriptor.capture_plan_count_address, sizeof(u64)) ||
	    !kctrace_data_range(target, descriptor.capture_plan_count_address, sizeof(u64),
				false) ||
	    !IS_ALIGNED(descriptor.binding_slot, sizeof(void *)) ||
	    !kctrace_data_range(target, descriptor.binding_slot, sizeof(void *), true))
		return notifier_from_errno(-EINVAL);
	slot = (void *)descriptor.binding_slot;
	if (READ_ONCE(*slot))
		return notifier_from_errno(-EINVAL);
	site_count = *(const u64 *)descriptor.site_count_address;
	plan_count = *(const u64 *)descriptor.capture_plan_count_address;
	if (!site_count || site_count > U32_MAX || plan_count > U32_MAX ||
	    (!descriptor.program &&
	     (!IS_ALIGNED(descriptor.sites, __alignof__(struct kctrace_probe_site)) ||
	      !kctrace_data_range(target, descriptor.sites,
				  site_count * sizeof(struct kctrace_probe_site), false))) ||
	    (plan_count &&
	     (!IS_ALIGNED(descriptor.capture_plans, __alignof__(struct kctrace_capture_plan)) ||
	      !kctrace_data_range(target, descriptor.capture_plans,
				  plan_count * sizeof(struct kctrace_capture_plan), false))))
		return notifier_from_errno(-EINVAL);
	binding = kctrace_bind(target, (const void *)descriptor.manifest);
	if (IS_ERR(binding))
		return notifier_from_errno(PTR_ERR(binding));
	if (site_count != binding->prepared.site_count)
		result = -EINVAL;
	else if (descriptor.program)
		result = kctrace_register_program(binding, (const void *)descriptor.program,
						  (const void *)descriptor.capture_plans,
						  plan_count);
	else
		result = kctrace_register_sites(binding, (const void *)descriptor.sites, site_count,
						(const void *)descriptor.capture_plans, plan_count);
	if (!result) {
		mutex_lock(&sessions_lock);
		if (!binding->owner_present || !binding->enabled) {
			result = -ECANCELED;
		} else {
			binding->target_slot = slot;
			/* The wrapper acquire must see complete site-table publication. */
			smp_store_release(slot, binding);
		}
		mutex_unlock(&sessions_lock);
	}
	if (result)
		kctrace_unbind(binding);
	return notifier_from_errno(result);
}

static struct notifier_block kctrace_module_notifier = {
	.notifier_call = kctrace_module_notify,
};
#endif

static int kctrace_open(struct inode *inode, struct file *file)
{
	struct kctrace_binding *session;

	if (!capable(CAP_SYS_MODULE))
		return -EPERM;
	session = kzalloc_obj(*session);
	if (!session)
		return -ENOMEM;
	kref_init(&session->refs);
	mutex_init(&session->consume);
	init_waitqueue_head(&session->readable);
	init_waitqueue_head(&session->drained);
	init_irq_work(&session->wakeup, kctrace_wake);
	INIT_LIST_HEAD(&session->probe_link);
	atomic_set(&session->active, 0);
	atomic64_set(&session->sequence, 0);
	atomic64_set(&session->produced, 0);
	atomic64_set(&session->dropped, 0);
	atomic64_set(&session->buffered, 0);
	session->session_id = atomic64_inc_return(&next_session);
	session->owner_present = true;
	mutex_lock(&sessions_lock);
	list_add_tail(&session->link, &sessions);
	mutex_unlock(&sessions_lock);
	file->private_data = session;
	return nonseekable_open(inode, file);
}

static int kctrace_release(struct inode *inode, struct file *file)
{
	struct kctrace_binding *session = file->private_data;

	mutex_lock(&sessions_lock);
	session->owner_present = false;
	/* A bound target retains the session, but never the collector's lease.
	 */
	if (!session->bound)
		list_del(&session->link);
	kctrace_disable(session);
	mutex_unlock(&sessions_lock);
	wait_event(session->drained, !atomic_read(&session->active));
	kref_put(&session->refs, kctrace_free);
	return 0;
}

static long kctrace_prepare_session(struct kctrace_binding *session, void __user *argument)
{
	struct kctrace_prepare prepare;
	struct kctrace_ring __percpu *rings = NULL;
	unsigned int cpu;
	long result = 0;

	if (copy_from_user(&prepare, argument, sizeof(prepare)))
		return -EFAULT;
	if (prepare.size != sizeof(prepare) ||
	    memcmp(prepare.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE) ||
	    prepare.flags || prepare.reserved || prepare.session_id ||
	    memchr_inv(prepare.session_nonce, 0, sizeof(prepare.session_nonce)) ||
	    !prepare.site_count || !memchr_inv(prepare.original_sha256, 0, KCTRACE_HASH_SIZE) ||
	    !memchr_inv(prepare.artifact_sha256, 0, KCTRACE_HASH_SIZE) || !prepare.module_name[0] ||
	    strnlen(prepare.module_name, KCTRACE_MODULE_NAME_SIZE) == KCTRACE_MODULE_NAME_SIZE)
		return -EINVAL;
	if (prepare.initial_level > KCTRACE_LEVEL_FULL)
		return -EOPNOTSUPP;
	for (cpu = 0; prepare.module_name[cpu]; cpu++)
		if (!((prepare.module_name[cpu] >= 'a' && prepare.module_name[cpu] <= 'z') ||
		      (prepare.module_name[cpu] >= 'A' && prepare.module_name[cpu] <= 'Z') ||
		      (prepare.module_name[cpu] >= '0' && prepare.module_name[cpu] <= '9') ||
		      prepare.module_name[cpu] == '_'))
			return -EINVAL;
	if (!prepare.events_per_cpu)
		prepare.events_per_cpu = default_events_per_cpu;
	mutex_lock(&sessions_lock);
	if (session->state != KCTRACE_STATE_OPEN) {
		result = -EBUSY;
		goto out;
	}
	rings = alloc_percpu(struct kctrace_ring);
	if (!rings) {
		result = -ENOMEM;
		goto out;
	}
	for_each_possible_cpu(cpu) {
		struct kctrace_ring *ring = per_cpu_ptr(rings, cpu);

		raw_spin_lock_init(&ring->lock);
		ring->events = kvcalloc(prepare.events_per_cpu, sizeof(*ring->events), GFP_KERNEL);
		if (!ring->events) {
			result = -ENOMEM;
			goto out;
		}
	}
	get_random_bytes(prepare.session_nonce, sizeof(prepare.session_nonce));
	prepare.session_id = session->session_id;
	/* Publish only after returning the identity; failed output leaves OPEN.
	 */
	if (copy_to_user(argument, &prepare, sizeof(prepare))) {
		result = -EFAULT;
		goto out;
	}
	session->prepared = prepare;
	/* Readers acquire this pointer before touching the initialized rings.
	 */
	smp_store_release(&session->rings, rings);
	rings = NULL;
	session->state = KCTRACE_STATE_PREPARED;
	/* Publish configuration and initialized rings before any producer runs.
	 */
	smp_store_release(&session->enabled, true);
out:
	mutex_unlock(&sessions_lock);
	if (rings) {
		for_each_possible_cpu(cpu)
			kvfree(per_cpu_ptr(rings, cpu)->events);
		free_percpu(rings);
	}
	return result;
}

/* Metadata is protected by sessions_lock; producer counters remain atomic. */
static void kctrace_status_snapshot(struct kctrace_binding *session, struct kctrace_status *status)
{
	lockdep_assert_held(&sessions_lock);
	memset(status, 0, sizeof(*status));
	status->size = sizeof(*status);
	memcpy(status->contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE);
	status->state = session->state;
	status->flags = (!session->enabled ? KCTRACE_STATUS_DISABLED : 0) |
			(session->bound ? KCTRACE_STATUS_BOUND : 0);
	status->session_id = session->session_id;
	status->generation = session->generation;
	status->init_result = session->init_result;
	status->produced = atomic64_read(&session->produced);
	status->dropped = atomic64_read(&session->dropped);
	status->buffered = atomic64_read(&session->buffered);
}

static long kctrace_ioctl(struct file *file, unsigned int command, unsigned long address)
{
	struct kctrace_binding *session = file->private_data;
	void __user *argument = (void __user *)address;
	struct kctrace_query query;
	struct kctrace_status status;
	struct kctrace_control control;
	struct kctrace_observe observe;
	struct kctrace_binding *observed;
	long result = 0;

	if (!capable(CAP_SYS_MODULE))
		return -EPERM;
	switch (command) {
	case KCTRACE_IOC_CONTRACT:
		if (copy_to_user(argument, kctrace_contract_hash, KCTRACE_HASH_SIZE))
			return -EFAULT;
		return 0;
	case KCTRACE_IOC_QUERY:
		if (copy_from_user(&query, argument, sizeof(query)))
			return -EFAULT;
		if (query.size != sizeof(query) ||
		    memcmp(query.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE))
			return -EPROTO;
		memset(&query, 0, sizeof(query));
		query.size = sizeof(query);
		memcpy(query.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE);
		query.capabilities = KCTRACE_CAP_SESSIONS | KCTRACE_CAP_BINARY_EVENTS |
				     KCTRACE_CAP_TASK_CONTEXT | KCTRACE_CAP_IRQ_CONTEXT |
				     KCTRACE_CAP_OBSERVE | KCTRACE_CAP_PROBE_SITES |
				     KCTRACE_CAP_PROBE_TIMING | KCTRACE_CAP_CAPTURE_VALUES |
				     KCTRACE_CAP_INTERRUPT_SCOPE | KCTRACE_CAP_LEVEL_SELECTION;
#ifdef CONFIG_TRACEPOINTS
		query.capabilities |= KCTRACE_CAP_TASKLET_SCOPE;
#endif
#ifdef CONFIG_KALLSYMS
		query.capabilities |= KCTRACE_CAP_PREINIT_BIND;
#endif
		query.event_size = sizeof(struct kctrace_event);
		query.xstate_mask = xstate_mask | scalar_mask;
		query.xstate_size = max(xstate_bytes, amx_bytes);
		if (xstate_mask || scalar_mask)
			query.capabilities |= KCTRACE_CAP_XSTATE;
		query.max_events_per_cpu =
			min_t(u64, U32_MAX, SIZE_MAX / sizeof(struct kctrace_event));
		query.default_events_per_cpu = default_events_per_cpu;
#ifdef CONFIG_STACKTRACE_BUILD_ID
		if (memchr_inv(module_buildid(THIS_MODULE), 0, BUILD_ID_SIZE_MAX)) {
			query.capabilities |= KCTRACE_CAP_RUNTIME_BUILD_ID;
			query.runtime_build_id_size = BUILD_ID_SIZE_MAX;
			memcpy(query.runtime_build_id, module_buildid(THIS_MODULE),
			       BUILD_ID_SIZE_MAX);
		}
#endif
		strscpy(query.kernel_release, init_utsname()->release,
			sizeof(query.kernel_release));
		return copy_to_user(argument, &query, sizeof(query)) ? -EFAULT : 0;
	case KCTRACE_IOC_PREPARE:
		return kctrace_prepare_session(session, argument);
	case KCTRACE_IOC_STATUS:
		if (copy_from_user(&status, argument, sizeof(status)))
			return -EFAULT;
		if (status.size != sizeof(status) ||
		    memcmp(status.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE) ||
		    status.reserved)
			return -EPROTO;
		mutex_lock(&sessions_lock);
		kctrace_status_snapshot(session, &status);
		mutex_unlock(&sessions_lock);
		return copy_to_user(argument, &status, sizeof(status)) ? -EFAULT : 0;
	case KCTRACE_IOC_OBSERVE:
		if (copy_from_user(&observe, argument, sizeof(observe)))
			return -EFAULT;
		if (observe.size != sizeof(observe) ||
		    memcmp(observe.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE))
			return -EPROTO;
		if (!observe.session_id ||
		    !memchr_inv(observe.session_nonce, 0, KCTRACE_NONCE_SIZE))
			return -EINVAL;
		result = -ENOENT;
		mutex_lock(&sessions_lock);
		list_for_each_entry(observed, &sessions, link) {
			if (observed->session_id != observe.session_id ||
			    observed->state == KCTRACE_STATE_OPEN ||
			    memcmp(observed->prepared.session_nonce, observe.session_nonce,
				   KCTRACE_NONCE_SIZE))
				continue;
			if (observe.generation && observe.generation != observed->generation) {
				result = -ESTALE;
				break;
			}
			kctrace_status_snapshot(observed, &observe.status);
			result = 0;
			break;
		}
		mutex_unlock(&sessions_lock);
		if (result)
			return result;
		return copy_to_user(argument, &observe, sizeof(observe)) ? -EFAULT : 0;
	case KCTRACE_IOC_DETACH:
		if (copy_from_user(&control, argument, sizeof(control)))
			return -EFAULT;
		if (control.size != sizeof(control) ||
		    memcmp(control.contract_sha256, kctrace_contract_hash, KCTRACE_HASH_SIZE) ||
		    control.reserved)
			return -EPROTO;
		mutex_lock(&sessions_lock);
		if (control.session_id != session->session_id ||
		    control.generation != session->generation)
			result = -ESTALE;
		else
			kctrace_disable(session);
		mutex_unlock(&sessions_lock);
		return result;
	default:
		return -ENOTTY;
	}
}

static bool kctrace_head_before(const void *left, const void *right, void *args)
{
	const struct kctrace_head *a = left;
	const struct kctrace_head *b = right;

	return a->sequence < b->sequence;
}

static const struct min_heap_callbacks kctrace_head_order = {
	.less = kctrace_head_before,
};

static void kctrace_pop(struct kctrace_binding *session, struct kctrace_heads *heads, u64 cutoff,
			struct kctrace_event *event)
{
	struct kctrace_head *head = &heads->data[0];
	struct kctrace_ring *ring = per_cpu_ptr(session->rings, head->cpu);
	unsigned long flags;
	bool retained;

	/* consume serializes readers; producers only append, never replace tails. */
	raw_spin_lock_irqsave(&ring->lock, flags);
	*event = ring->events[ring->tail];
	ring->tail = (ring->tail + 1) % session->prepared.events_per_cpu;
	ring->used--;
	atomic64_dec(&session->buffered);
	retained = ring->used && ring->events[ring->tail].sequence <= cutoff;
	if (retained)
		head->sequence = ring->events[ring->tail].sequence;
	raw_spin_unlock_irqrestore(&ring->lock, flags);
	if (retained)
		min_heap_sift_down_inline(heads, 0, &kctrace_head_order, NULL);
	else
		(void)min_heap_pop_inline(heads, &kctrace_head_order, NULL);
}

static ssize_t kctrace_read(struct file *file, char __user *buffer, size_t count, loff_t *position)
{
	struct kctrace_binding *session = file->private_data;
	struct kctrace_event event;
	struct kctrace_heads heads;
	struct kctrace_head *storage;
	ssize_t copied = 0;
	int error;

	if (count < sizeof(event))
		return -EINVAL;
	/* Pair with PREPARE publication; no producer can replace these rings.
	 */
	if (!smp_load_acquire(&session->rings))
		return -ENODATA;
	error = mutex_lock_interruptible(&session->consume);
	if (error)
		return error;
	storage = kvmalloc_array(num_possible_cpus(), sizeof(*storage), GFP_KERNEL);
	if (!storage) {
		copied = -ENOMEM;
		goto out;
	}
	min_heap_init_inline(&heads, storage, num_possible_cpus());
	for (;;) {
		unsigned int cpu;
		u64 cutoff = atomic64_read_acquire(&session->sequence);

		/* Snapshot the cutoff before scanning any CPU. A migrating task's
		 * later event cannot pass an earlier event whose ring was scanned
		 * before publication: emit disables preemption through publication.
		 * Unrelated contexts can still publish out of global sequence order.
		 */
		heads.nr = 0;
		for_each_possible_cpu(cpu) {
			struct kctrace_ring *ring = per_cpu_ptr(session->rings, cpu);
			unsigned long flags;

			raw_spin_lock_irqsave(&ring->lock, flags);
			if (ring->used && ring->events[ring->tail].sequence <= cutoff) {
				storage[heads.nr].sequence = ring->events[ring->tail].sequence;
				storage[heads.nr++].cpu = cpu;
			}
			raw_spin_unlock_irqrestore(&ring->lock, flags);
		}
		min_heapify_all_inline(&heads, &kctrace_head_order, NULL);
		while (heads.nr && count - copied >= sizeof(event)) {
			kctrace_pop(session, &heads, cutoff, &event);
			if (copy_to_user(buffer + copied, &event, sizeof(event))) {
				atomic64_inc(&session->dropped);
				if (!copied)
					copied = -EFAULT;
				goto free;
			}
			copied += sizeof(event);
		}
		if (copied || !READ_ONCE(session->enabled))
			break;
		if (file->f_flags & O_NONBLOCK) {
			copied = -EAGAIN;
			break;
		}
		error = wait_event_interruptible(session->readable,
						 atomic64_read(&session->buffered) ||
							 !READ_ONCE(session->enabled));
		if (error) {
			copied = error;
			break;
		}
	}
free:
	kvfree(storage);
out:
	mutex_unlock(&session->consume);
	return copied;
}

static __poll_t kctrace_poll(struct file *file, poll_table *wait)
{
	struct kctrace_binding *session = file->private_data;
	__poll_t result = 0;

	poll_wait(file, &session->readable, wait);
	if (atomic64_read(&session->buffered))
		result |= EPOLLIN | EPOLLRDNORM;
	if (READ_ONCE(session->state) != KCTRACE_STATE_OPEN && !READ_ONCE(session->enabled))
		result |= EPOLLHUP;
	return result;
}

static const struct file_operations kctrace_operations = {
	.owner = THIS_MODULE,
	.open = kctrace_open,
	.release = kctrace_release,
	.unlocked_ioctl = kctrace_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
	.read = kctrace_read,
	.poll = kctrace_poll,
};

static struct miscdevice kctrace_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "kctrace",
	.fops = &kctrace_operations,
	.mode = 0600,
};

static int __init kctrace_init(void)
{
	int result;
	unsigned int eax, ebx, ecx, edx, component;

	BUILD_BUG_ON(sizeof(struct kctrace_event) != 384);
	BUILD_BUG_ON(sizeof(struct kctrace_execution_record) != 48);
	BUILD_BUG_ON(sizeof(struct kctrace_copy_probe) != 48);
	BUILD_BUG_ON(sizeof(struct kctrace_gate_site) != 96);
	BUILD_BUG_ON(sizeof(struct kctrace_program) != 128);
	BUILD_BUG_ON(sizeof(struct kctrace_interrupt_proof) != 88);
	BUILD_BUG_ON(sizeof(struct kctrace_interrupt_range) != 24);
	BUILD_BUG_ON(sizeof(struct kctrace_interrupt_window) != 32);
	BUILD_BUG_ON(sizeof(struct kctrace_interrupt_dispatch) != 24);
	BUILD_BUG_ON(sizeof(struct kctrace_bootstrap) != 104);
	BUILD_BUG_ON(KCTRACE_IRQ_LANES + 1 > KCTRACE_INHERIT_SOURCE_MAX);
	if (boot_cpu_has(X86_FEATURE_XSAVE) && (native_read_cr4() & X86_CR4_OSXSAVE)) {
		cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
		xstate_mask = (((u64)edx << 32) | eax) & xgetbv(XCR_XFEATURE_ENABLED_MASK) &
			      (KCTRACE_XSTATE_FPU | KCTRACE_XSTATE_AMX);
		if (boot_cpu_has(X86_FEATURE_OSPKE)) {
			cpuid_count(0xd, 9, &eax, &ebx, &ecx, &edx);
			if (eax == 8 && !(ecx & 1)) {
				scalar_mask |= KCTRACE_XSTATE_USER_SCALAR;
				xstate_sizes[9] = 8;
				xstate_offsets[9] = 544;
			}
		}
		cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
		if (!(edx & BIT(24)))
			xstate_mask &= ~KCTRACE_XSTATE_AMX;
		if ((xstate_mask & KCTRACE_XSTATE_AMX) != KCTRACE_XSTATE_AMX)
			xstate_mask &= ~KCTRACE_XSTATE_AMX;
		xstate_bytes = 576;
		xstate_sizes[0] = 160;
		xstate_sizes[1] = 416;
		for (component = 2; component < ARRAY_SIZE(xstate_sizes); component++) {
			if (!(xstate_mask & BIT_ULL(component)))
				continue;
			cpuid_count(0xd, component, &eax, &ebx, &ecx, &edx);
			if (!eax || ebx < 576 || ebx > U32_MAX - 63 || eax > U32_MAX - 63 - ebx ||
			    (ecx & 1) || (component == 17 && eax != 64) ||
			    (component == 18 && eax != 8192)) {
				xstate_mask &= ~BIT_ULL(component);
				continue;
			}
			xstate_offsets[component] = ebx;
			xstate_sizes[component] = eax;
			if (BIT(component) & KCTRACE_XSTATE_FPU)
				xstate_bytes = max(xstate_bytes, eax + ebx);
			else
				amx_bytes = max(amx_bytes, eax + ebx);
		}
		if ((xstate_mask & KCTRACE_XSTATE_AMX) != KCTRACE_XSTATE_AMX) {
			xstate_mask &= ~KCTRACE_XSTATE_AMX;
			amx_bytes = 0;
		} else {
			amx_bytes = max(amx_bytes, xstate_bytes);
		}
		xstate_fpu_mask = xstate_mask & KCTRACE_XSTATE_FPU;
		if (boot_cpu_has(X86_FEATURE_XSAVES)) {
			u64 supported;

			cpuid_count(0xd, 1, &eax, &ebx, &ecx, &edx);
			supported = ((u64)edx << 32 | ecx) & KCTRACE_XSTATE_SUPERVISOR;
			for (component = 0; component < ARRAY_SIZE(supervisor_components);
			     component++) {
				const unsigned int id = supervisor_components[component].component;
				unsigned int word;

				if (!(supported & BIT_ULL(id)))
					continue;
				cpuid_count(0xd, id, &eax, &ebx, &ecx, &edx);
				if (eax != supervisor_components[component].count * 8 || ebx ||
				    !(ecx & 1))
					continue;
				/* XSS controls the target transfer, not passive reads.
				 * Disabled components can still be observed unchanged.
				 */
				for (word = 0; word < supervisor_components[component].count;
				     word++) {
					u32 low, high;

					if (rdmsr_safe(supervisor_components[component].msrs[word],
						       &low, &high))
						break;
				}
				if (word != supervisor_components[component].count)
					continue;
				scalar_mask |= BIT_ULL(id);
				xstate_sizes[id] = eax;
				xstate_offsets[id] = supervisor_components[component].offset;
			}
		}
	}
#ifdef CONFIG_KALLSYMS
	result = register_module_notifier(&kctrace_module_notifier);
	if (result)
		return result;
#endif
	result = misc_register(&kctrace_device);
#ifdef CONFIG_KALLSYMS
	if (result)
		unregister_module_notifier(&kctrace_module_notifier);
#endif
	return result;
}

static void __exit kctrace_exit(void)
{
	misc_deregister(&kctrace_device);
#ifdef CONFIG_KALLSYMS
	unregister_module_notifier(&kctrace_module_notifier);
#endif
	kctrace_free_xstate();
}

module_init(kctrace_init);
module_exit(kctrace_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("ctrace contributors");
MODULE_DESCRIPTION("Recording runtime for pre-generated ctrace probes");
MODULE_VERSION(KCTRACE_VERSION);
