// SPDX-License-Identifier: MIT

#ifndef CTRACE_OUTPUT_H
#define CTRACE_OUTPUT_H

#include <cstddef>

/* Adopt an inherited log descriptor, or use stderr when descriptor is -1. */
bool ct_output_init(int descriptor);
// Foreign final CLONE_VM tasks release the mutex but do not close a descriptor
// number owned by another process's descriptor table.
void ct_output_exit(bool close_descriptor);
void ct_output_fork_prepare(void);
void ct_output_fork_parent(void);
void ct_output_fork_child(void);
/* Set once at client initialization; fork inherits the current trace policy. */
void ct_output_set_trace_enabled(bool enabled);
bool ct_output_trace_enabled(void);
void ct_output_set_info_enabled(bool enabled);
bool ct_output_info_enabled(void);
void ct_output_set_warning_enabled(bool enabled);
bool ct_output_warning_enabled(void);
/* Suppressed trace records succeed without touching the diagnostic sink. */
bool ct_output_trace_write(const char *text, size_t size);
/* Raw diagnostics are always written. Callers check the selected Info/Warning
 * policy; errors remain unconditional. Serialize one complete record, including
 * all short-write retries, independently of the trace policy. */
bool ct_output_write(const char *text, size_t size);
bool ct_output_printf(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

#endif
