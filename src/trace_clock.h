#ifndef CTRACE_TRACE_CLOCK_H
#define CTRACE_TRACE_CLOCK_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <time.h>

/* RAW is also shifted by Linux time namespaces. Normalize to the initial
 * namespace; refresh the cached offset after entering another namespace. */
static inline bool ct_trace_clock_offset(int64_t *offset) {
  struct stat active, children;
  if (stat("/proc/self/ns/time", &active) != 0) {
    *offset = 0;
    /* Missing procfs must not be mistaken for an older kernel. */
    return errno == ENOENT && stat("/proc/self", &active) == 0;
  }
  if (stat("/proc/self/ns/time_for_children", &children) != 0)
    return false;
  /* timens_offsets describes the namespace for future children. Never apply
   * that offset to an active namespace which has not entered it. */
  if (active.st_dev != children.st_dev || active.st_ino != children.st_ino)
    return false;
  FILE *stream = fopen("/proc/self/timens_offsets", "re");
  if (!stream) {
    *offset = 0;
    return errno == ENOENT; /* Kernels without time namespaces. */
  }
  bool found = false;
  char line[256];
  while (fgets(line, sizeof(line), stream)) {
    char clock[32];
    long long seconds, nanoseconds;
    if (sscanf(line, "%31s %lld %lld", clock, &seconds, &nanoseconds) != 3 ||
        strcmp(clock, "monotonic"))
      continue;
    const __int128 value = (__int128)seconds * 1000000000 + nanoseconds;
    if (nanoseconds >= 0 && nanoseconds < 1000000000 && value >= INT64_MIN &&
        value <= INT64_MAX) {
      *offset = (int64_t)value;
      found = true;
    }
    break;
  }
  fclose(stream);
  return found;
}

static inline uint64_t ct_trace_clock_now(int64_t offset) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &now) != 0)
    return 0;
  const __int128 value =
      (__int128)now.tv_sec * 1000000000 + now.tv_nsec - offset;
  return value > 0 && value <= UINT64_MAX ? (uint64_t)value : 0;
}

#endif
