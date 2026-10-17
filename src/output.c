#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <dr_api.h>

#include <fcntl.h>
#include <sys/stat.h>

#include "output.h"

static void *output_mutex;
static file_t output_descriptor = INVALID_FILE;
static bool output_file_lock;
static bool output_owned;
static bool output_trace = true;

bool ct_output_init(int descriptor) {
  if (output_mutex)
    return false;
  output_trace = true;
  output_descriptor = descriptor >= 0 ? descriptor : STDERR;
  output_owned = descriptor >= 0;
  if (output_owned && !dr_adopt_file_descriptor(output_descriptor, true)) {
    dr_fprintf(STDERR, "ctrace: cannot protect output descriptor\n");
    return false;
  }
  struct stat information;
  const int flags = fcntl(output_descriptor, F_GETFL);
  /* A closed private stdio stream can reserve its stable descriptor with an
   * O_PATH sentinel. It has stat metadata but cannot carry trace output. */
  if (flags < 0 || (flags & O_PATH) ||
      fstat(output_descriptor, &information) != 0) {
    dr_fprintf(STDERR, "ctrace: cannot inspect output descriptor\n");
    if (output_owned)
      dr_close_file(output_descriptor);
    output_owned = false;
    return false;
  }
  output_file_lock = S_ISREG(information.st_mode);
  output_mutex = dr_mutex_create();
  if (!output_mutex && output_owned) {
    dr_close_file(output_descriptor);
    output_owned = false;
  }
  return output_mutex != NULL;
}

void ct_output_exit(bool close_descriptor) {
  if (output_mutex)
    dr_mutex_destroy(output_mutex);
  output_mutex = NULL;
  if (output_owned && close_descriptor)
    dr_close_file(output_descriptor);
  output_descriptor = STDERR;
  output_owned = false;
}

void ct_output_fork_prepare(void) { dr_mutex_lock(output_mutex); }

void ct_output_fork_parent(void) { dr_mutex_unlock(output_mutex); }

void ct_output_fork_child(void) { dr_mutex_reset_after_fork(output_mutex); }

void ct_output_set_trace_enabled(bool enabled) { output_trace = enabled; }

bool ct_output_trace_enabled(void) { return output_trace; }

bool ct_output_write(const char *text, size_t size) {
  if (!output_mutex || (!text && size))
    return false;
  dr_mutex_lock(output_mutex);
  /* Process-associated locks exclude forked processes and the analysis helper.
   * The DR mutex supplies the separate exclusion needed between threads. Do
   * not require file locking for terminals, pipes or devices such as /dev/full.
   */
  struct flock lock = {0};
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  lock.l_len = 1;
  int result = 0;
  if (output_file_lock) {
    do {
      result = fcntl(output_descriptor, F_SETLKW, &lock);
    } while (result < 0 && errno == EINTR);
  }
  bool success = result == 0;
  if (success) {
    size_t written = 0;
    while (written < size) {
      ssize_t count =
          dr_write_file(output_descriptor, text + written, size - written);
      /* DynamoRIO's Linux write API returns negative syscall error numbers. */
      if (count == -EINTR)
        continue;
      if (count <= 0) {
        success = false;
        break;
      }
      written += (size_t)count;
    }
    if (output_file_lock) {
      lock.l_type = F_UNLCK;
      do {
        result = fcntl(output_descriptor, F_SETLK, &lock);
      } while (result < 0 && errno == EINTR);
      success = success && result == 0;
    }
  }
  if (!success) {
    /* The configured sink may be full or disconnected. This diagnostic must
     * bypass it, including when a caller cannot otherwise report the failure.
     */
    const char message[] = "ctrace: cannot write complete log record\n";
    size_t written = 0;
    while (written < sizeof(message) - 1) {
      const ssize_t count = dr_write_file(STDERR, message + written,
                                          sizeof(message) - 1 - written);
      if (count == -EINTR)
        continue;
      if (count <= 0)
        break;
      written += (size_t)count;
    }
  }
  dr_mutex_unlock(output_mutex);
  return success;
}

bool ct_output_trace_write(const char *text, size_t size) {
  if (!text && size)
    return false;
  return !output_trace || ct_output_write(text, size);
}

bool ct_output_printf(const char *format, ...) {
  if (!format)
    return false;
  va_list arguments, measure;
  va_start(arguments, format);
  va_copy(measure, arguments);
  const int count = vsnprintf(NULL, 0, format, measure);
  va_end(measure);
  char *text = count >= 0 ? malloc((size_t)count + 1) : NULL;
  bool success = text != NULL;
  if (text) {
    success = vsnprintf(text, (size_t)count + 1, format, arguments) == count;
    if (success)
      success = ct_output_write(text, (size_t)count);
    free(text);
  }
  va_end(arguments);
  return success;
}
