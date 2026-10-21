/* SPDX-License-Identifier: MIT */
#ifndef KCTRACE_TARGET_H
#define KCTRACE_TARGET_H

#include "kctrace/runtime.h"

extern const struct kctrace_program __ctrace_program;
extern const __u64 __ctrace_site_count;
extern const struct kctrace_capture_plan __ctrace_capture_plans[];
extern const __u64 __ctrace_capture_plan_count;
extern struct kctrace_binding *__ctrace_binding;
int init_module(void);
void cleanup_module(void);
int __ctrace_init(void);
void __ctrace_exit(void);

#endif
