/* SPDX-License-Identifier: MIT */
#ifndef _UAPI_KCTRACE_H
#define _UAPI_KCTRACE_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* Unassigned capability bits and numeric IDs remain reserved. */
#define KCTRACE_HASH_SIZE	32
#define KCTRACE_NONCE_SIZE	32
#define KCTRACE_MODULE_NAME_SIZE	64
#define KCTRACE_REGISTER_COUNT	18
#define KCTRACE_MEMORY_SIZE	64
#define KCTRACE_VALUE_SLOTS	8

#define KCTRACE_CAP_SESSIONS	(1ULL << 0)
#define KCTRACE_CAP_BINARY_EVENTS	(1ULL << 1)
#define KCTRACE_CAP_TASK_CONTEXT	(1ULL << 2)
#define KCTRACE_CAP_IRQ_CONTEXT	(1ULL << 3)
#define KCTRACE_CAP_RUNTIME_BUILD_ID	(1ULL << 4)
#define KCTRACE_CAP_NMI_CONTEXT	(1ULL << 6)
#define KCTRACE_CAP_LEVEL_SELECTION	(1ULL << 7)
#define KCTRACE_CAP_OBSERVE	(1ULL << 8)
#define KCTRACE_CAP_PROBE_SITES	(1ULL << 9)
#define KCTRACE_CAP_PROBE_TIMING	(1ULL << 10)
#define KCTRACE_CAP_CAPTURE_VALUES	(1ULL << 11)
#define KCTRACE_CAP_PREINIT_BIND	(1ULL << 12)
#define KCTRACE_CAP_INTERRUPT_SCOPE	(1ULL << 13)
#define KCTRACE_CAP_TASKLET_SCOPE	(1ULL << 14)
#define KCTRACE_CAP_XSTATE	0x8000ULL

#define KCTRACE_STATE_OPEN	0
#define KCTRACE_STATE_PREPARED	1
#define KCTRACE_STATE_BOUND	2
#define KCTRACE_STATE_LIVE	3
#define KCTRACE_STATE_INIT_FAILED	4
/* The target's exit callback completed; memory removal is not yet proven. */
#define KCTRACE_STATE_EXIT_COMPLETE	5
/* Loading stopped before the original initializer reported a result. */
#define KCTRACE_STATE_LOAD_ABORTED	6

#define KCTRACE_STATUS_DISABLED	(1U << 0)
#define KCTRACE_STATUS_BOUND	(1U << 1)

#define KCTRACE_LEVEL_ARM	0
#define KCTRACE_LEVEL_PERFETTO	1
#define KCTRACE_LEVEL_FULL	2

#define KCTRACE_CONTEXT_TASK	0
#define KCTRACE_CONTEXT_SOFTIRQ	1
#define KCTRACE_CONTEXT_HARDIRQ	2
#define KCTRACE_CONTEXT_NMI	3

#define KCTRACE_EVENT_BOUND	1
#define KCTRACE_EVENT_INIT_COMPLETE	2
#define KCTRACE_EVENT_INIT_FAILED	3
#define KCTRACE_EVENT_EXIT_COMPLETE	4
#define KCTRACE_EVENT_FUNCTION_ENTER	5
#define KCTRACE_EVENT_FUNCTION_EXIT	6
#define KCTRACE_EVENT_BLOCK_ENTER	7
#define KCTRACE_EVENT_BLOCK_EXIT	8
#define KCTRACE_EVENT_INSTRUCTION_BEFORE	9
#define KCTRACE_EVENT_INSTRUCTION_AFTER	10
#define KCTRACE_EVENT_CALL	11
#define KCTRACE_EVENT_RETURN	12
#define KCTRACE_EVENT_LOAD_ABORTED	13
#define KCTRACE_EVENT_EXECUTION	14
#define KCTRACE_EVENT_BLOCK_POINT	15
#define KCTRACE_EVENT_CAPTURE	16

#define KCTRACE_EVENT_HAVE_MEMORY	(1U << 0)
#define KCTRACE_EVENT_SEQUENCE_GAP	(1U << 1)
#define KCTRACE_EVENT_PROBE_TIMING	(1U << 2)
#define KCTRACE_EVENT_HAVE_VALUES	(1U << 3)
#define KCTRACE_EVENT_HAVE_EXECUTION	(1U << 4)

#define KCTRACE_BOUNDARY_ENTER	0
#define KCTRACE_BOUNDARY_SCOPE	1
#define KCTRACE_BOUNDARY_CALL	2
#define KCTRACE_BOUNDARY_AFTER_CALL	3
#define KCTRACE_BOUNDARY_EXIT	4
#define KCTRACE_BOUNDARY_TAIL	5
#define KCTRACE_BOUNDARY_CALL_UNPAIRED	6
/* Body observation, not an input to the boundary state machine. */
#define KCTRACE_BOUNDARY_POINT	7

#define KCTRACE_EXEC_UNKNOWN	(1U << 0)
#define KCTRACE_EXEC_DISCONTINUITY	(1U << 1)
#define KCTRACE_EXEC_CALLBACK	(1U << 2)
#define KCTRACE_EXEC_LEVEL_CHANGED	(1U << 3)
#define KCTRACE_EXEC_ENTRY_VALUES	(1U << 4)
#define KCTRACE_EXEC_RETURN_VALUE	(1U << 5)
#define KCTRACE_EXEC_RECOVERED	(1U << 6)
/* SINGLE_FULL guard snapshot represents its original native instruction. */
#define KCTRACE_EXEC_INSTRUCTION	(1U << 7)
#define KCTRACE_EXEC_HANDLER_CRITERION	(1U << 8)

#define KCTRACE_FAILURE_OK	0
#define KCTRACE_FAILURE_OVERFLOW	1
#define KCTRACE_FAILURE_BAD_BOUNDARY	2
#define KCTRACE_FAILURE_COOKIE_EXHAUSTED	3
#define KCTRACE_FAILURE_REENTRANT	4
#define KCTRACE_FAILURE_UNSUPPORTED_CONTEXT	5
#define KCTRACE_FAILURE_CONTEXT_LIMIT	6
#define KCTRACE_FAILURE_INHERITED_UNKNOWN	7

/* Root IRQ ENTER only. Source is a witness lane, not a parent frame. */
#define KCTRACE_INHERIT_VALID	(1U << 0)
#define KCTRACE_INHERIT_WITHIN	(1U << 1)
#define KCTRACE_INHERIT_UNKNOWN	(1U << 2)
#define KCTRACE_INHERIT_SOURCE_SHIFT	8
#define KCTRACE_INHERIT_SOURCE_MASK	(0x3fU << KCTRACE_INHERIT_SOURCE_SHIFT)
#define KCTRACE_INHERIT_SOURCE_NONE	0
#define KCTRACE_INHERIT_SOURCE_TASK	1
#define KCTRACE_INHERIT_SOURCE_SOFTIRQ	2
/* An outer hardirq at depth h, with serving-softirq bit s: 3 + 2*(h-1) + s. */
#define KCTRACE_INHERIT_SOURCE_HARDIRQ	3
#define KCTRACE_INHERIT_SOURCE_MAX	32

/* x86-64 register order; valid_registers gives one bit per entry. */
#define KCTRACE_REG_RAX	0
#define KCTRACE_REG_RBX	1
#define KCTRACE_REG_RCX	2
#define KCTRACE_REG_RDX	3
#define KCTRACE_REG_RSI	4
#define KCTRACE_REG_RDI	5
#define KCTRACE_REG_RBP	6
#define KCTRACE_REG_RSP	7
#define KCTRACE_REG_R8	8
#define KCTRACE_REG_R9	9
#define KCTRACE_REG_R10	10
#define KCTRACE_REG_R11	11
#define KCTRACE_REG_R12	12
#define KCTRACE_REG_R13	13
#define KCTRACE_REG_R14	14
#define KCTRACE_REG_R15	15
#define KCTRACE_REG_RFLAGS	16
#define KCTRACE_REG_RIP	17

/* Fixed bootstrap response: read before any changeable request layout. */
struct kctrace_contract {
	__u8 sha256[KCTRACE_HASH_SIZE];
};

struct kctrace_query {
	__u32 size;
	__u8 contract_sha256[KCTRACE_HASH_SIZE];
	__u64 capabilities;
	__u32 event_size;
	__u32 max_events_per_cpu;
	__u32 default_events_per_cpu;
	__u32 runtime_build_id_size;
	__u8 runtime_build_id[KCTRACE_HASH_SIZE];
	char kernel_release[64];
	__u64 xstate_mask;
	__u32 xstate_size;
	__u32 xstate_reserved;
};

/* One PREPARE per descriptor; output nonce identifies this single load. */
struct kctrace_prepare {
	__u32 size;
	__u8 contract_sha256[KCTRACE_HASH_SIZE];
	__u32 initial_level;
	__u32 flags;
	__u32 events_per_cpu;
	__u32 reserved;
	__u64 site_count;
	char module_name[KCTRACE_MODULE_NAME_SIZE];
	/* Digest of the original input ELF bytes. */
	__u8 original_sha256[KCTRACE_HASH_SIZE];
	/* Template digest: entire manifest region zeroed, signature excluded.
	 */
	__u8 artifact_sha256[KCTRACE_HASH_SIZE];
	__u8 session_nonce[KCTRACE_NONCE_SIZE];
	__u64 session_id;
};

struct kctrace_status {
	__u32 size;
	__u8 contract_sha256[KCTRACE_HASH_SIZE];
	__u32 state;
	__u32 flags;
	__u64 session_id;
	__u64 generation;
	__u64 produced;
	__u64 dropped;
	__u64 buffered;
	__s32 init_result;
	__u32 reserved;
};

struct kctrace_control {
	__u32 size;
	__u8 contract_sha256[KCTRACE_HASH_SIZE];
	__u64 session_id;
	__u64 generation;
	__u64 reserved;
};

/* Read-only lookup from a separate FD; it does not retain the owner's lease. */
struct kctrace_observe {
	__u32 size;
	__u8 contract_sha256[KCTRACE_HASH_SIZE];
	__u64 session_id;
	/* Zero accepts the current generation, including the pre-bind state. */
	__u64 generation;
	__u8 session_nonce[KCTRACE_NONCE_SIZE];
	struct kctrace_status status;
};

/* Exact frame/call identities are scoped to this load and execution context:
 * task_start_ns for tasks, CPU/kind/depth for IRQ lanes.
 * EXIT is result-ready, not proof that RET completed. AFTER_CALL supplies
 * completion evidence. UNKNOWN clears state and may leave identities zero.
 */
struct kctrace_execution_record {
	__u64 frame_id;
	__u64 parent_frame_id;
	__u64 call_id;
	__u32 function;
	__u32 path;
	/* within/recurse/blocked: bits 0/1/2; mode: bits 3..4
	 * (skip=0, over=1, into=2, recurse=3); bits 5..7 are zero.
	 */
	__u8 state;
	__u8 previous_level;
	__u8 kind;
	__u8 reserved;
	__u32 flags;
	__u32 failure;
	/* VALID alone is a known-false root seed. WITHIN/UNKNOWN require a
	 * nonzero source and are mutually exclusive. All other bits are zero.
	 * The source's coherent selector state may precede its recorded event;
	 * this does not assert exact hardware ENTRY/RET/JMP timing.
	 */
	__u32 inheritance;
};

/* Fixed native-endian layout, without userspace pointers. */
struct kctrace_event {
	__u32 size;
	__u16 type;
	__u16 context;
	__u64 sequence;
	/* Shared CLOCK_MONOTONIC domain; probe entry or lifecycle emission. */
	__u64 monotonic_ns;
	/*
	 * With PROBE_TIMING: end of the measured recorder interval, sampled
	 * before ring publication. Automatic probes start after the recursion
	 * guard, before site lookup; explicit record() starts after validation
	 * and its recursion guard. Assembly entry/return, publication unlock,
	 * wakeup and trailing cleanup are outside this interval. Interrupts or
	 * descheduling inside the interval are included, not separately
	 * removed. Lifecycle events have no timing flag and leave probe_end_ns
	 * zero.
	 */
	__u64 probe_end_ns;
	__u64 session_id;
	__u64 generation;
	__u64 task_start_ns;
	__u64 site_id;
	__u64 pc;
	__u32 tid;
	__u32 tgid;
	__u32 cpu;
	__u32 level;
	__u32 flags;
	__u16 hardirq_depth;
	/* Serving a softirq (0 or 1), excluding local_bh_disable nesting. */
	__u16 softirq_depth;
	__u64 valid_registers;
	__u64 registers[KCTRACE_REGISTER_COUNT];
	/* HAVE_MEMORY and HAVE_VALUES are mutually exclusive payload tags.
	 * HAVE_VALUES carries a one-based plan ID and a low-eight-bit valid mask.
	 * Slot widths come from that immutable plan; all other bytes are zero.
	 * A base record is followed by reserved2 - 1 CAPTURE records. Each carries
	 * the same root plan and identity with consecutive sequence numbers. Only
	 * the base has registers, execution state and PROBE_TIMING. Continuations
	 * retain its monotonic_ns/probe_end_ns and HAVE_VALUES/SEQUENCE_GAP flags.
	 */
	union {
		__u64 memory_address;
		__u64 capture_plan;
	};
	union {
		__u32 memory_size;
		__u32 capture_valid;
	};
	/* HAVE_VALUES: base chunk count (1..MAX_CHUNKS), or CAPTURE index (1..).
	 * Zero without HAVE_VALUES. One complete bundle is published or dropped.
	 */
	__u32 reserved2;
	union {
		__u8 memory[KCTRACE_MEMORY_SIZE];
		__u8 capture_values[KCTRACE_VALUE_SLOTS][8];
	};
	__u64 dropped_total;
	/* Zero unless HAVE_EXECUTION; legacy full observations remain supported. */
	struct kctrace_execution_record execution;
};

#define KCTRACE_IOC_CONTRACT _IOR('K', 0x06, struct kctrace_contract)
#define KCTRACE_IOC_QUERY	_IOWR('K', 0x00, struct kctrace_query)
#define KCTRACE_IOC_PREPARE	_IOWR('K', 0x01, struct kctrace_prepare)
#define KCTRACE_IOC_STATUS	_IOWR('K', 0x02, struct kctrace_status)
#define KCTRACE_IOC_DETACH	_IOW('K', 0x03, struct kctrace_control)
#define KCTRACE_IOC_OBSERVE	_IOWR('K', 0x05, struct kctrace_observe)

#endif /* _UAPI_KCTRACE_H */
