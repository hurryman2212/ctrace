#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dr_api.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "analysis.h"
#include "analysis_descriptors.h"
#include "analysis_protocol.h"
#include "elf_identity.h"
#include "output.h"
#include "trace_clock.h"

struct ct_analysis {
  ct_analysis_handle remote;
  char *error;
  char *decompile_error;
  char *path;
  char *maps;
  bool remote_open;
  int module_file, debug_descriptor, supplement_descriptor;
  struct ct_analysis *next;
};

static int analysis_fd = -1;
static int broker_fd = -1;
static uint64_t analysis_session;
static uint64_t analysis_trace_origin_ns;
static int64_t analysis_clock_offset;
static dev_t analysis_clock_namespace_device;
static ino_t analysis_clock_namespace_inode;
static bool analysis_clock_namespace_known;
static bool analysis_recording_allowed;
static ct_analysis *analysis_modules;
static int analysis_syntax = -1;
static bool source_bypass;
static void *analysis_lock;
static void (*progress_callback)(const ct_analysis_progress *, void *);
static void *progress_context;

bool ct_analysis_refresh_clock(void) {
  if (!analysis_trace_origin_ns)
    return true;
  struct stat active;
  if (stat("/proc/self/ns/time", &active) != 0) {
    if (errno != ENOENT || analysis_clock_namespace_known ||
        stat("/proc/self", &active) != 0)
      return false;
    __atomic_store_n(&analysis_clock_offset, 0, __ATOMIC_RELAXED);
    analysis_clock_namespace_known = false;
    return true;
  }
  // unshare can change timens_offsets for future children without changing
  // this task's active clock. Keep its verified offset until it enters a new
  // namespace instead of reading those pending offsets again.
  if (analysis_clock_namespace_known &&
      active.st_dev == analysis_clock_namespace_device &&
      active.st_ino == analysis_clock_namespace_inode)
    return true;
  int64_t offset;
  if (!ct_trace_clock_offset(&offset))
    return false;
  __atomic_store_n(&analysis_clock_offset, offset, __ATOMIC_RELAXED);
  analysis_clock_namespace_device = active.st_dev;
  analysis_clock_namespace_inode = active.st_ino;
  analysis_clock_namespace_known = true;
  return true;
}

uint64_t ct_analysis_wall_nanoseconds(void) {
  if (!analysis_trace_origin_ns)
    return 0;
  return ct_trace_clock_now(
      __atomic_load_n(&analysis_clock_offset, __ATOMIC_RELAXED));
}

void ct_analysis_set_progress_callback(
    void (*callback)(const ct_analysis_progress *, void *), void *context) {
  progress_callback = callback;
  progress_context = context;
}

static bool broker_send(uint32_t operation, const char *data, size_t size,
                        int descriptor) {
  if (broker_fd < 0 || size > CT_ANALYSIS_BROKER_LIMIT || (!data && size))
    return false;
  ct_analysis_broker_packet packet = {operation, (uint32_t)size,
                                      analysis_session};
  struct iovec vectors[2] = {{&packet, sizeof(packet)}, {(void *)data, size}};
  union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(int))];
  } control;
  struct msghdr message = {0};
  message.msg_iov = vectors;
  message.msg_iovlen = size ? 2 : 1;
  if (descriptor >= 0) {
    memset(&control, 0, sizeof(control));
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  }
  ssize_t sent;
  do {
    sent = sendmsg(broker_fd, &message, MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);
  return sent == (ssize_t)(sizeof(packet) + size);
}

static bool connect_worker(uint64_t exec_nonce) {
  analysis_recording_allowed = false;
  int sockets[2];
  if (!ct_analysis_create_pair(sockets))
    return false;
  const bool adopted = dr_adopt_file_descriptor_ex(sockets[0], false, true);
  analysis_fd = adopted ? sockets[0] : -1;
  bool connected = adopted && broker_send(CT_ANALYSIS_BROKER_CONNECT,
                                          (const char *)&exec_nonce,
                                          sizeof(exec_nonce), sockets[1]);
  if (!adopted)
    close(sockets[0]);
  close(sockets[1]);
  if (connected) {
    ct_analysis_worker_handshake handshake;
    connected = ct_analysis_transfer(analysis_fd, &handshake, sizeof(handshake),
                                     false) &&
                handshake.session != 0 && handshake.recording_allowed <= 1;
    if (connected) {
      analysis_session = handshake.session;
      analysis_trace_origin_ns = handshake.trace_origin_ns;
      analysis_recording_allowed = handshake.recording_allowed != 0;
      connected = ct_analysis_refresh_clock();
      if (connected) {
        const ct_analysis_request files = {.operation = CT_ANALYSIS_FILESYSTEM,
                                           .offset = 1};
        connected = ct_analysis_transfer(analysis_fd, (void *)&files,
                                         sizeof(files), true);
      }
    }
  }
  if (!connected && analysis_fd != INVALID_FILE) {
    dr_close_file(analysis_fd);
    analysis_fd = -1;
  }
  return connected;
}

bool ct_analysis_object_connect(int descriptor) {
  return descriptor >= 0 && ct_analysis_object_owner() &&
         broker_send(CT_ANALYSIS_BROKER_OBJECT_CONNECT, NULL, 0, descriptor);
}

uint64_t ct_analysis_object_owner(void) {
  struct ucred credentials;
  socklen_t size = sizeof(credentials);
  if (!analysis_session || analysis_fd < 0 ||
      getsockopt(analysis_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) !=
          0 ||
      size != sizeof(credentials) || credentials.pid != syscall(SYS_getpid))
    return 0;
  return analysis_session;
}

bool ct_analysis_connect(int socket_fd) {
  if (socket_fd < 0 || broker_fd >= 0 ||
      !dr_adopt_file_descriptor(socket_fd, true))
    return false;
  broker_fd = socket_fd;
  analysis_lock = dr_mutex_create();
  return analysis_lock && connect_worker(dr_get_exec_client_data());
}

bool ct_analysis_recording_allowed(void) { return analysis_recording_allowed; }

uint64_t ct_analysis_trace_origin_ns(void) { return analysis_trace_origin_ns; }

void ct_analysis_disconnect(void) {
  const bool owns_descriptors = ct_analysis_object_owner() != 0;
  if (owns_descriptors && analysis_fd >= 0)
    dr_close_file(analysis_fd);
  analysis_fd = -1;
  if (owns_descriptors && broker_fd >= 0)
    dr_close_file(broker_fd);
  broker_fd = -1;
  analysis_recording_allowed = false;
  analysis_trace_origin_ns = 0;
  __atomic_store_n(&analysis_clock_offset, 0, __ATOMIC_RELAXED);
  analysis_clock_namespace_known = false;
  if (analysis_lock)
    dr_mutex_destroy(analysis_lock);
  analysis_lock = NULL;
}

void ct_analysis_fork_prepare(void) {
  if (analysis_lock)
    dr_mutex_lock(analysis_lock);
}

void ct_analysis_fork_parent(void) {
  if (analysis_lock)
    dr_mutex_unlock(analysis_lock);
}

bool ct_analysis_trace_event(const char *data, size_t size) {
  return broker_send(CT_ANALYSIS_BROKER_TRACE_EVENT, data, size, -1);
}

bool ct_analysis_trace_footer(const char *data, size_t size) {
  return broker_send(CT_ANALYSIS_BROKER_TRACE_FOOTER, data, size, -1);
}

static bool broker_query(uint32_t operation, const char *data, size_t size,
                         void *response, size_t response_size) {
  int sockets[2];
  if (!ct_analysis_create_pair(sockets))
    return false;
  const bool sent = broker_send(operation, data, size, sockets[1]);
  close(sockets[1]);
  const bool received =
      sent && ct_analysis_transfer(sockets[0], response, response_size, false);
  close(sockets[0]);
  return received;
}

bool ct_analysis_trace_flush(void) {
  bool accepted = false;
  return broker_query(CT_ANALYSIS_BROKER_TRACE_FLUSH, NULL, 0, &accepted,
                      sizeof(accepted)) &&
         accepted;
}

bool ct_analysis_cancel_exec(uint64_t nonce) {
  bool accepted = false;
  return broker_query(CT_ANALYSIS_BROKER_CANCEL_EXEC, (const char *)&nonce,
                      sizeof(nonce), &accepted, sizeof(accepted)) &&
         accepted;
}

uint64_t ct_analysis_prepare_exec(bool recording,
                                  const ct_exec_timestamp *timestamps,
                                  size_t count) {
  if ((!timestamps && count) || count > SIZE_MAX / sizeof(*timestamps))
    return 0;
  const size_t chunk_limit =
      (CT_ANALYSIS_BROKER_LIMIT - sizeof(ct_analysis_exec_timestamps_header)) /
      sizeof(*timestamps);
  const size_t capacity =
      sizeof(ct_analysis_exec_timestamps_header) +
      (count < chunk_limit ? count : chunk_limit) * sizeof(*timestamps);
  char *data = malloc(capacity);
  if (!data)
    return 0;
  uint64_t nonce = 0;
  size_t offset = 0;
  do {
    const size_t remaining = count - offset;
    const size_t chunk = remaining < chunk_limit ? remaining : chunk_limit;
    const bool first = offset == 0;
    size_t header_size;
    if (first) {
      const ct_analysis_exec_header header = {recording ? 1u : 0u,
                                              (uint32_t)chunk};
      header_size = sizeof(header);
      memcpy(data, &header, header_size);
    } else {
      const ct_analysis_exec_timestamps_header header = {nonce, chunk};
      header_size = sizeof(header);
      memcpy(data, &header, header_size);
    }
    if (chunk)
      memcpy(data + header_size, timestamps + offset,
             chunk * sizeof(*timestamps));
    const size_t size = header_size + chunk * sizeof(*timestamps);
    bool accepted = false;
    if (first)
      accepted = broker_query(CT_ANALYSIS_BROKER_PREPARE_EXEC, data, size,
                              &nonce, sizeof(nonce)) &&
                 nonce != 0;
    else {
      bool complete = false;
      accepted = broker_query(CT_ANALYSIS_BROKER_EXEC_TIMESTAMPS, data, size,
                              &complete, sizeof(complete)) &&
                 complete;
    }
    if (!accepted) {
      if (nonce)
        ct_analysis_cancel_exec(nonce);
      nonce = 0;
      break;
    }
    offset += chunk;
  } while (offset < count);
  free(data);
  return nonce;
}

static void transfer(void *buffer, size_t size, bool sending) {
  bool valid = true;
  if (!sending) {
    for (;;) {
      ct_analysis_response response;
      if (!ct_analysis_transfer(analysis_fd, &response, sizeof(response),
                                false)) {
        valid = false;
        break;
      }
      if (response.kind == CT_ANALYSIS_RESULT) {
        valid = response.size == size;
        break;
      }
      if (response.kind == CT_ANALYSIS_FILE) {
        ct_analysis_file_request *file = malloc(sizeof(*file));
        if (!file || response.size != sizeof(*file) ||
            !ct_analysis_transfer(analysis_fd, file, sizeof(*file), false) ||
            !memchr(file->path, 0, sizeof(file->path)) ||
            file->operation > CT_ANALYSIS_FILE_REALPATH) {
          free(file);
          valid = false;
          break;
        }
        int descriptor = -1;
        char *resolved = NULL;
        ct_analysis_file_reply reply = {0};
        const bool opens = file->operation == CT_ANALYSIS_FILE_READ ||
                           file->operation == CT_ANALYSIS_FILE_STATUS;
        if (opens) {
          descriptor =
              open(file->path,
                   O_CLOEXEC | (file->operation == CT_ANALYSIS_FILE_STATUS
                                    ? O_PATH
                                    : O_RDONLY | O_NONBLOCK));
          // DynamoRIO redirects this libc open to redirect_open(), which
          // returns the kernel's negative errno rather than setting libc TLS.
          if (descriptor < 0)
            reply.error = -descriptor;
          else {
            descriptor = ct_analysis_relocate_owned_descriptor(descriptor);
            if (descriptor < 0) {
              reply.error = errno;
            } else if (!dr_adopt_file_descriptor_ex(descriptor, false, false)) {
              close(descriptor);
              descriptor = -1;
              reply.error = EIO;
            }
          }
        } else {
          resolved = file->operation == CT_ANALYSIS_FILE_CWD
                         ? getcwd(NULL, 0)
                         : realpath(file->path, NULL);
          if (!resolved)
            reply.error = errno;
          else if (strlen(resolved) >= sizeof(file->path))
            reply.error = ENAMETOOLONG;
          else
            reply.text_size = (uint32_t)strlen(resolved) + 1;
        }
        free(file);
        valid = ct_analysis_transfer(analysis_fd, &reply, sizeof(reply), true);
        if (valid && !reply.error) {
          if (opens)
            valid = ct_analysis_send_descriptor(analysis_fd, descriptor);
          else
            valid = ct_analysis_transfer(analysis_fd, resolved, reply.text_size,
                                         true);
        }
        if (descriptor >= 0)
          dr_close_file(descriptor);
        free(resolved);
        if (!valid)
          break;
        continue;
      }
      if (response.kind != CT_ANALYSIS_PROGRESS ||
          response.size != sizeof(ct_analysis_progress)) {
        valid = false;
        break;
      }
      // Most replies have no progress update. Do not reserve this large
      // notification on every call, especially from the signal callback stack.
      ct_analysis_progress *progress = malloc(sizeof(*progress));
      if (!progress ||
          !ct_analysis_transfer(analysis_fd, progress, sizeof(*progress),
                                false) ||
          !memchr(progress->stage, 0, sizeof(progress->stage)) ||
          !memchr(progress->module, 0, sizeof(progress->module)) ||
          !memchr(progress->detail, 0, sizeof(progress->detail)) ||
          !memchr(progress->file, 0, sizeof(progress->file)) ||
          !memchr(progress->source_prefix, 0,
                  sizeof(progress->source_prefix)) ||
          !memchr(progress->function, 0, sizeof(progress->function)) ||
          (progress->has_range &&
           progress->begin_offset > progress->end_offset)) {
        free(progress);
        valid = false;
        break;
      }
      if (progress_callback)
        progress_callback(progress, progress_context);
      free(progress);
    }
  }
  if (!valid || !ct_analysis_transfer(analysis_fd, buffer, size, sending)) {
    const char message[] = "ctrace: analysis helper connection failed\n";
    ct_output_write(message, sizeof(message) - 1);
    dr_abort();
  }
}

static void send_request(enum ct_analysis_operation operation,
                         ct_analysis *analysis, uint64_t offset,
                         const char *text, const char *maps) {
  ct_analysis_request message = {0};
  message.operation = operation;
  message.handle = analysis ? analysis->remote.handle : 0;
  message.offset = offset;
  message.text_size = text ? (uint32_t)strlen(text) : 0;
  message.maps_size = maps ? (uint32_t)strlen(maps) : 0;
  transfer(&message, sizeof(message), true);
  transfer((void *)text, message.text_size, true);
  transfer((void *)maps, message.maps_size, true);
}

static bool open_remote_module(ct_analysis *analysis) {
  const bool replay = analysis->remote.handle != 0;
  const int previous[] = {analysis->module_file, analysis->debug_descriptor,
                          analysis->supplement_descriptor};
  ct_analysis_handle *incoming = calloc(1, sizeof(*incoming));
  ct_analysis_open_capture *capture =
      replay ? calloc(1, sizeof(*capture)) : NULL;
  int received[] = {-1, -1, -1};
  bool adopted[] = {false, false, false};
  bool valid = false;
  if (!incoming || (replay && !capture))
    goto cleanup;
  if (capture) {
    for (size_t index = 0; index < 3; ++index)
      if (previous[index] >= 0)
        capture->present |= 1u << index;
    memcpy(capture->debug_file, analysis->remote.debug_file,
           sizeof(capture->debug_file));
    memcpy(capture->supplement_file, analysis->remote.supplement_file,
           sizeof(capture->supplement_file));
    memcpy(capture->identity, analysis->remote.identity,
           sizeof(capture->identity));
    capture->debug_bias_correction = analysis->remote.debug_bias_correction;
  }
  send_request(CT_ANALYSIS_OPEN, NULL, replay ? 2 : previous[0] >= 0,
               analysis->path, analysis->maps);
  if (capture)
    transfer(capture, sizeof(*capture), true);
  for (size_t index = 0; index < (replay ? 3u : 1u); ++index)
    if (previous[index] >= 0 &&
        !ct_analysis_send_descriptor(analysis_fd, previous[index]))
      goto cleanup;
  transfer(incoming, sizeof(*incoming), false);
  const bool present[] = {incoming->has_module_descriptor,
                          incoming->has_debug_descriptor,
                          incoming->has_supplement_descriptor};
  const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  for (size_t index = 0; index < 3; ++index) {
    if (!present[index])
      continue;
    received[index] = ct_analysis_receive_descriptor(analysis_fd);
    if (received[index] < 0)
      goto cleanup;
    const int actual = fcntl(received[index], F_GET_SEALS);
    struct stat metadata;
    if (actual < 0 || (actual & seals) != seals ||
        fstat(received[index], &metadata) != 0 || !S_ISREG(metadata.st_mode))
      goto cleanup;
  }
  if (!incoming->handle ||
      !memchr(incoming->debug_file, 0, sizeof(incoming->debug_file)) ||
      !memchr(incoming->supplement_file, 0,
              sizeof(incoming->supplement_file)) ||
      !memchr(incoming->soname, 0, sizeof(incoming->soname)) ||
      !memchr(incoming->identity, 0, sizeof(incoming->identity)) ||
      (incoming->identity[0] &&
       (strlen(incoming->identity) != 32 ||
        strspn(incoming->identity, "0123456789abcdef") != 32)))
    goto cleanup;
  if (replay &&
      (strcmp(incoming->identity, analysis->remote.identity) ||
       strcmp(incoming->debug_file, analysis->remote.debug_file) ||
       strcmp(incoming->supplement_file, analysis->remote.supplement_file) ||
       strcmp(incoming->soname, analysis->remote.soname) ||
       incoming->has_dwarf != analysis->remote.has_dwarf ||
       incoming->debug_bias_correction !=
           analysis->remote.debug_bias_correction))
    goto cleanup;
  for (size_t index = 0; index < 3; ++index) {
    if (replay && present[index] != (previous[index] >= 0))
      goto cleanup;
    if (received[index] >= 0) {
      adopted[index] =
          dr_adopt_file_descriptor_ex(received[index], false, false);
      if (!adopted[index])
        goto cleanup;
    }
  }
  // Commit only after the complete response is received and verified. A
  // failed reconnect never destroys the inherited, already validated bundle.
  analysis->remote = *incoming;
  analysis->module_file = received[0];
  analysis->debug_descriptor = received[1];
  analysis->supplement_descriptor = received[2];
  analysis->remote_open = true;
  for (size_t index = 0; index < 3; ++index) {
    received[index] = -1;
    if (previous[index] >= 0)
      dr_close_file(previous[index]);
  }
  valid = true;
cleanup:
  for (size_t index = 0; index < 3; ++index)
    if (received[index] >= 0) {
      if (adopted[index])
        dr_close_file(received[index]);
      else
        close(received[index]);
    }
  free(capture);
  free(incoming);
  return valid;
}

static void request(enum ct_analysis_operation operation, ct_analysis *analysis,
                    uint64_t offset, const char *text, const char *maps) {
  // A fork inherits immutable snapshots and local metadata, not a new helper's
  // parsed module objects. Reconstruct only a module that is actually queried.
  if (analysis && !analysis->remote_open && !open_remote_module(analysis)) {
    ct_output_printf("ctrace: cannot restore analysis module in child\n");
    dr_abort();
  }
  send_request(operation, analysis, offset, text, maps);
}

bool ct_analysis_fork_child(void) {
  /* DR closed the worker stream through DR_FILE_CLOSE_ON_FORK. Reset the
   * inherited ownership before using the private session in this child. */
  analysis_fd = -1;
  analysis_session = 0;
  if (!analysis_lock)
    return false;
  dr_mutex_reset_after_fork(analysis_lock);
  if (!connect_worker(0))
    return false;
  request(CT_ANALYSIS_SYNTAX, NULL, (uint64_t)(analysis_syntax + 1), NULL,
          NULL);
  request(CT_ANALYSIS_BYPASS, NULL, source_bypass, NULL, NULL);
  for (ct_analysis *analysis = analysis_modules; analysis;
       analysis = analysis->next)
    analysis->remote_open = false;
  return true;
}

bool ct_analysis_cache_digest(const char *key, char digest[65]) {
  if (!digest)
    return false;
  digest[0] = '\0';
  if (!key || !key[0] || !analysis_lock)
    return false;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_CACHE_DIGEST, NULL, 0, key, NULL);
  transfer(digest, 65, false);
  dr_mutex_unlock(analysis_lock);
  if (digest[64] != '\0' || strspn(digest, "0123456789abcdef") != 64) {
    digest[0] = '\0';
    return false;
  }
  return true;
}

bool ct_analysis_content_digest(const void *data, size_t size,
                                unsigned char digest[32]) {
  if ((!data && size) || !digest || !analysis_lock || size > 128 * 1024 * 1024)
    return false;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_CONTENT_DIGEST, NULL, size, NULL, NULL);
  transfer((void *)data, size, true);
  transfer(digest, 32, false);
  dr_mutex_unlock(analysis_lock);
  return true;
}

static bool runtime_image_read(void *context, uint64_t offset, void *data,
                               size_t size) {
  const uintptr_t base = *(uintptr_t *)context;
  return offset <= UINTPTR_MAX - base && size <= UINTPTR_MAX - base - offset &&
         dr_safe_read((const void *)(base + offset), size, data, NULL);
}

static bool runtime_image_evidence(const void *address, char evidence[256]) {
  FILE *maps = fopen("/proc/thread-self/maps", "re");
  if (!maps)
    maps = fopen("/proc/self/maps", "re");
  if (!maps)
    return false;
  char line[4096];
  uintptr_t base = 0;
  unsigned long inode = 0;
  unsigned device_major = 0, device_minor = 0;
  while (fgets(line, sizeof(line), maps)) {
    unsigned long begin, end, offset;
    char permissions[5];
    if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &begin, &end, permissions,
               &offset, &device_major, &device_minor, &inode) == 7 &&
        (uintptr_t)address >= begin && (uintptr_t)address < end && inode &&
        begin >= offset) {
      base = begin - offset;
      break;
    }
  }
  fclose(maps);
  char identity[129];
  if (!base || !ct_elf_build_id(runtime_image_read, &base, true, identity))
    return false;
  const int size = snprintf(
      evidence, 256, "%llu:%lu:%s",
      (unsigned long long)makedev(device_major, device_minor), inode, identity);
  return size > 0 && size < 256;
}

bool ct_analysis_runtime_identity(char digest[65]) {
  if (!digest)
    return false;
  memset(digest, 0, 65);
  if (!analysis_lock)
    return false;
  dr_mutex_lock(analysis_lock);
  static bool attempted;
  static char client[256], runtime[256];
  if (!attempted) {
    attempted = true;
    if (!runtime_image_evidence((const void *)ct_analysis_runtime_identity,
                                client) ||
        !runtime_image_evidence((const void *)dr_get_client_base, runtime)) {
      client[0] = '\0';
      runtime[0] = '\0';
    }
  }
  if (client[0] && runtime[0]) {
    request(CT_ANALYSIS_RUNTIME_IDENTITY, NULL, 0, client, runtime);
    transfer(digest, 65, false);
  }
  dr_mutex_unlock(analysis_lock);
  if (digest[64] != '\0' || strspn(digest, "0123456789abcdef") != 64) {
    digest[0] = '\0';
    return false;
  }
  return true;
}

bool ct_analysis_cache_read(const char *kind, const char *key,
                            unsigned char **data, size_t *size) {
  if (!data || !size || !kind || !key || !analysis_lock)
    return false;
  *data = NULL;
  *size = 0;
  uint32_t bytes = 0;
  bool found;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_CACHE_READ, NULL, 0, kind, key);
  transfer(&found, sizeof(found), false);
  transfer(&bytes, sizeof(bytes), false);
  if (bytes > 128 * 1024 * 1024)
    dr_abort();
  unsigned char *result = bytes ? malloc(bytes) : NULL;
  if (bytes && !result)
    dr_abort();
  transfer(result, bytes, false);
  dr_mutex_unlock(analysis_lock);
  if (!found) {
    free(result);
    return false;
  }
  *data = result;
  *size = bytes;
  return true;
}

bool ct_analysis_cache_write(const char *kind, const char *key,
                             const void *data, size_t size) {
  if (!kind || !key || (!data && size) || size > 128 * 1024 * 1024 ||
      !analysis_lock)
    return false;
  bool accepted;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_CACHE_WRITE, NULL, size, kind, key);
  transfer((void *)data, size, true);
  transfer(&accepted, sizeof(accepted), false);
  dr_mutex_unlock(analysis_lock);
  return accepted;
}

void ct_analysis_set_syntax(int syntax) {
  dr_mutex_lock(analysis_lock);
  analysis_syntax = syntax;
  request(CT_ANALYSIS_SYNTAX, NULL, (uint64_t)(syntax + 1), NULL, NULL);
  dr_mutex_unlock(analysis_lock);
}

void ct_analysis_set_source_bypass(bool enabled) {
  dr_mutex_lock(analysis_lock);
  source_bypass = enabled;
  request(CT_ANALYSIS_BYPASS, NULL, enabled, NULL, NULL);
  dr_mutex_unlock(analysis_lock);
}

bool ct_analysis_disassemble(uint64_t pc, const unsigned char *bytes,
                             size_t size, char *att, size_t att_capacity,
                             char *intel, size_t intel_capacity) {
  if (!bytes || !size || size > 15 || !att || !att_capacity || !intel ||
      !intel_capacity)
    return false;
  att[0] = intel[0] = '\0';
  ct_analysis_instruction instruction = {0};
  instruction.size = (unsigned char)size;
  memcpy(instruction.bytes, bytes, size);
  ct_analysis_disassembly result;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_DISASSEMBLE, NULL, pc, NULL, NULL);
  transfer(&instruction, sizeof(instruction), true);
  transfer(&result, sizeof(result), false);
  dr_mutex_unlock(analysis_lock);
  if (!result.valid || !memchr(result.att, '\0', sizeof(result.att)) ||
      !memchr(result.intel, '\0', sizeof(result.intel)) ||
      strlen(result.att) >= att_capacity ||
      strlen(result.intel) >= intel_capacity)
    return false;
  memcpy(att, result.att, strlen(result.att) + 1);
  memcpy(intel, result.intel, strlen(result.intel) + 1);
  return true;
}

ct_analysis *ct_analysis_open_fd(const char *path, const char *maps,
                                 int descriptor) {
  ct_analysis *analysis = calloc(1, sizeof(*analysis));
  if (!analysis || !analysis_lock) {
    const char message[] = "ctrace: analysis helper is unavailable\n";
    ct_output_write(message, sizeof(message) - 1);
    dr_abort();
  }
  analysis->path = strdup(path ? path : "");
  analysis->maps = strdup(maps ? maps : "");
  analysis->module_file = -1;
  analysis->debug_descriptor = -1;
  analysis->supplement_descriptor = -1;
  if (!analysis->path || !analysis->maps)
    dr_abort();
  dr_mutex_lock(analysis_lock);
  if (descriptor >= 0) {
    struct stat metadata;
    if (fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode)) {
      analysis->module_file = fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
      if (analysis->module_file >= 0 &&
          !dr_adopt_file_descriptor_ex(analysis->module_file, false, false)) {
        close(analysis->module_file);
        analysis->module_file = -1;
      }
    }
  }
  if (!open_remote_module(analysis))
    dr_abort();
  analysis->next = analysis_modules;
  analysis_modules = analysis;
  dr_mutex_unlock(analysis_lock);
  return analysis;
}

ct_analysis *ct_analysis_open(const char *path, const char *maps) {
  const int descriptor =
      path && *path ? open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK) : -1;
  ct_analysis *analysis = ct_analysis_open_fd(path, maps, descriptor);
  if (descriptor >= 0)
    close(descriptor);
  return analysis;
}

int ct_analysis_module_file(ct_analysis *analysis) {
  return analysis ? analysis->module_file : -1;
}

int ct_analysis_debug_file_descriptor(ct_analysis *analysis) {
  return analysis ? analysis->debug_descriptor : -1;
}

int ct_analysis_supplement_file_descriptor(ct_analysis *analysis) {
  return analysis ? analysis->supplement_descriptor : -1;
}

const char *ct_analysis_supplement_file(ct_analysis *analysis) {
  return analysis ? analysis->remote.supplement_file : "";
}

int64_t ct_analysis_debug_bias_correction(ct_analysis *analysis) {
  return analysis ? analysis->remote.debug_bias_correction : 0;
}

static void receive_record(void *record, size_t decoded_size) {
  uint32_t size;
  transfer(&size, sizeof(size), false);
  if (size > ct_analysis_record_capacity(decoded_size)) {
    ct_output_printf("ctrace: invalid analysis record response\n");
    dr_abort();
  }
  unsigned char *packed = malloc(size ? size : 1);
  if (!packed)
    dr_abort();
  transfer(packed, size, false);
  const bool valid =
      ct_analysis_record_unpack(record, decoded_size, packed, size);
  free(packed);
  if (!valid) {
    ct_output_printf("ctrace: invalid analysis record response\n");
    dr_abort();
  }
}

void ct_analysis_lookup(ct_analysis *analysis, uint64_t module_offset,
                        ct_location *location) {
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_LOOKUP, analysis, module_offset, NULL, NULL);
  receive_record(location, sizeof(*location));
  dr_mutex_unlock(analysis_lock);
}

void ct_analysis_lookup_arming(ct_analysis *analysis, uint64_t module_offset,
                               ct_location *location) {
  // Handler-entry callbacks run on DR's small signal stack.
  ct_arming_location *arming = malloc(sizeof(*arming));
  if (!arming)
    dr_abort();
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_LOOKUP_ARMING, analysis, module_offset, NULL, NULL);
  receive_record(arming, sizeof(*arming));
  dr_mutex_unlock(analysis_lock);
  ct_arming_location_unpack(location, arming);
  free(arming);
}

bool ct_analysis_lookup_batch(ct_analysis *analysis, const uint64_t *offsets,
                              size_t count, bool arming, unsigned char **data,
                              size_t *size) {
  if (!data || !size)
    return false;
  *data = NULL;
  *size = 0;
  if (!analysis || !offsets || !count || count > CT_LOCATION_BATCH_COUNT_LIMIT)
    return false;
  for (size_t index = 1; index < count; ++index)
    if (offsets[index] <= offsets[index - 1])
      return false;
  bool valid;
  uint32_t bytes;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_LOOKUP_BATCH, analysis, count, arming ? "arming" : "full",
          NULL);
  transfer((void *)offsets, count * sizeof(*offsets), true);
  transfer(&valid, sizeof(valid), false);
  transfer(&bytes, sizeof(bytes), false);
  if (bytes > CT_LOCATION_BATCH_BYTE_LIMIT || (!valid && bytes))
    dr_abort();
  unsigned char *result = bytes ? malloc(bytes) : NULL;
  if (bytes && !result)
    dr_abort();
  transfer(result, bytes, false);
  dr_mutex_unlock(analysis_lock);
  if (!valid ||
      !ct_location_batch_valid(result, bytes, offsets, count, arming, NULL)) {
    free(result);
    return false;
  }
  *data = result;
  *size = bytes;
  return true;
}

static bool receive_code_proof(uint32_t level, unsigned char **data,
                               size_t *size) {
  bool valid;
  uint32_t bytes;
  transfer(&valid, sizeof(valid), false);
  transfer(&bytes, sizeof(bytes), false);
  const size_t maximum =
      sizeof(ct_decompiled_proof_header) +
      CT_DECOMPILED_PROOF_LIMIT *
          (sizeof(ct_decompiled_range) + sizeof(ct_decompiled_instruction));
  if (bytes > maximum || (!valid && bytes)) {
    ct_output_printf("ctrace: invalid decompiler code proof response\n");
    dr_abort();
  }
  unsigned char *proof = bytes ? malloc(bytes) : NULL;
  if (bytes && !proof) {
    ct_output_printf("ctrace: cannot allocate decompiler code proof\n");
    dr_abort();
  }
  transfer(proof, bytes, false);
  if (!valid || !ct_decompiled_proof_valid(proof, bytes)) {
    free(proof);
    return false;
  }
  ct_decompiled_proof_header header;
  memcpy(&header, proof, sizeof(header));
  if (header.loaded_level < level || (!level && header.loaded_level)) {
    free(proof);
    return false;
  }
  *data = proof;
  *size = bytes;
  return true;
}

bool ct_analysis_decompile_proof(ct_analysis *analysis, uint64_t module_offset,
                                 uint32_t level, unsigned char **data,
                                 size_t *size) {
  if (!data || !size)
    return false;
  *data = NULL;
  *size = 0;
  if (!analysis ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_DECOMPILE_PROOF, analysis, module_offset,
          level == CT_DECOMPILE_FULL ? "full" : "perfetto", NULL);
  bool valid = receive_code_proof(level, data, size);
  dr_mutex_unlock(analysis_lock);
  return valid;
}

bool ct_analysis_code_proof(ct_analysis *analysis, uint64_t module_offset,
                            unsigned char **data, size_t *size) {
  if (!data || !size)
    return false;
  *data = NULL;
  *size = 0;
  if (!analysis)
    return false;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_CODE_PROOF, analysis, module_offset, NULL, NULL);
  bool valid = receive_code_proof(0, data, size);
  dr_mutex_unlock(analysis_lock);
  return valid;
}

bool ct_analysis_decompile_display(ct_analysis *analysis,
                                   uint64_t module_offset, uint32_t level,
                                   ct_decompiled_display *display) {
  if (!analysis || !display ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  bool valid;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_DECOMPILE_DISPLAY, analysis, module_offset,
          level == CT_DECOMPILE_FULL ? "full" : "perfetto", NULL);
  transfer(&valid, sizeof(valid), false);
  transfer(display, sizeof(*display), false);
  dr_mutex_unlock(analysis_lock);
  valid = valid && display->loaded_level >= level &&
          display->loaded_level <= CT_DECOMPILE_FULL &&
          memchr(display->function_name, 0, sizeof(display->function_name)) &&
          memchr(display->prototype, 0, sizeof(display->prototype)) &&
          memchr(display->control_text, 0, sizeof(display->control_text)) &&
          memchr(display->control_kind, 0, sizeof(display->control_kind)) &&
          memchr(display->control_initializer, 0,
                 sizeof(display->control_initializer)) &&
          memchr(display->control_update, 0, sizeof(display->control_update)) &&
          display->instruction.offset == module_offset &&
          display->instruction.size > 0 &&
          display->instruction.size <= sizeof(display->instruction.bytes);
  if (!valid)
    memset(display, 0, sizeof(*display));
  return valid;
}

bool ct_analysis_decompile(ct_analysis *analysis, uint64_t module_offset,
                           uint32_t level, ct_decompiled_statement *statement) {
  if (!analysis || !statement ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  bool valid;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_DECOMPILE, analysis, module_offset,
          level == CT_DECOMPILE_FULL ? "full" : "perfetto", NULL);
  transfer(&valid, sizeof(valid), false);
  transfer(statement, sizeof(*statement), false);
  dr_mutex_unlock(analysis_lock);
  if (!valid || !statement->id || !statement->instruction_count ||
      statement->instruction_count > CT_DECOMPILED_INSTRUCTION_LIMIT ||
      statement->instruction_index >= statement->instruction_count ||
      !memchr(statement->text, 0, sizeof(statement->text))) {
    memset(statement, 0, sizeof(*statement));
    return false;
  }
  for (uint32_t index = 0; index < statement->instruction_count; ++index) {
    const ct_decompiled_instruction *instruction =
        &statement->instructions[index];
    if (!instruction->size || instruction->size > sizeof(instruction->bytes) ||
        instruction->offset > UINT64_MAX - instruction->size ||
        (index && statement->instructions[index - 1].offset +
                          statement->instructions[index - 1].size !=
                      instruction->offset)) {
      memset(statement, 0, sizeof(*statement));
      return false;
    }
  }
  if (statement->instructions[statement->instruction_index].offset !=
      module_offset) {
    memset(statement, 0, sizeof(*statement));
    return false;
  }
  return true;
}

bool ct_analysis_decompile_variables(ct_analysis *analysis,
                                     uint64_t module_offset, uint32_t level,
                                     ct_decompiled_variables *variables) {
  if (!analysis || !variables ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  bool valid;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_DECOMPILE_VARIABLES, analysis, module_offset,
          level == CT_DECOMPILE_FULL ? "full" : "perfetto", NULL);
  transfer(&valid, sizeof(valid), false);
  transfer(variables, sizeof(*variables), false);
  dr_mutex_unlock(analysis_lock);
  if (variables->count > CT_DECOMPILED_VARIABLE_LIMIT)
    valid = false;
  if (variables->instruction.offset != module_offset ||
      !variables->instruction.size ||
      variables->instruction.size > sizeof(variables->instruction.bytes) ||
      module_offset > UINT64_MAX - variables->instruction.size)
    valid = false;
  for (uint32_t index = 0; valid && index < variables->count; ++index) {
    const ct_decompiled_variable *variable = &variables->entries[index];
    valid =
        variable->id && variable->size && variable->name[0] &&
        variable->kind >= CT_DECOMPILED_STACK &&
        variable->kind <= CT_DECOMPILED_REGISTER && variable->access &&
        !(variable->access & ~(CT_DECOMPILED_READ | CT_DECOMPILED_WRITE)) &&
        variable->type.kind >= CT_VALUE_UNKNOWN &&
        variable->type.kind <= CT_VALUE_POINTER &&
        variable->type.bytes == variable->size &&
        memchr(variable->name, 0, sizeof(variable->name)) &&
        memchr(variable->type_name, 0, sizeof(variable->type_name)) &&
        memchr(variable->register_name, 0, sizeof(variable->register_name)) &&
        (variable->kind != CT_DECOMPILED_REGISTER ||
         variable->register_name[0]);
  }
  if (!valid)
    memset(variables, 0, sizeof(*variables));
  return valid;
}

const char *ct_analysis_decompile_error(ct_analysis *analysis) {
  if (!analysis)
    return NULL;
  uint32_t size;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_DECOMPILE_ERROR, analysis, 0, NULL, NULL);
  transfer(&size, sizeof(size), false);
  if (size >= CT_DECOMPILE_ERROR_CAPACITY)
    dr_abort();
  free(analysis->decompile_error);
  analysis->decompile_error = malloc((size_t)size + 1);
  if (!analysis->decompile_error)
    dr_abort();
  transfer(analysis->decompile_error, size, false);
  analysis->decompile_error[size] = 0;
  dr_mutex_unlock(analysis_lock);
  return size ? analysis->decompile_error : NULL;
}

bool ct_analysis_has_dwarf(ct_analysis *analysis) {
  return analysis && analysis->remote.has_dwarf;
}

const char *ct_analysis_debug_file(ct_analysis *analysis) {
  return analysis ? analysis->remote.debug_file : "";
}

const char *ct_analysis_soname(ct_analysis *analysis) {
  return analysis ? analysis->remote.soname : "";
}

const char *ct_analysis_identity(ct_analysis *analysis) {
  return analysis ? analysis->remote.identity : "";
}

bool ct_analysis_source_allowed(ct_analysis *analysis, uint64_t source_id) {
  bool allowed;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_ALLOWED, analysis, source_id, NULL, NULL);
  transfer(&allowed, sizeof(allowed), false);
  dr_mutex_unlock(analysis_lock);
  return allowed;
}

const char *ct_analysis_source_error(ct_analysis *analysis) {
  uint32_t size;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_ERROR, analysis, 0, NULL, NULL);
  transfer(&size, sizeof(size), false);
  free(analysis->error);
  analysis->error = malloc((size_t)size + 1);
  if (!analysis->error)
    dr_abort();
  transfer(analysis->error, size, false);
  analysis->error[size] = '\0';
  dr_mutex_unlock(analysis_lock);
  return size ? analysis->error : NULL;
}

void ct_analysis_functions(ct_analysis *analysis,
                           void (*callback)(uint64_t, const char *, void *),
                           void *context) {
  uint32_t count;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_FUNCTIONS, analysis, 0, NULL, NULL);
  transfer(&count, sizeof(count), false);
  size_t size = (size_t)count * sizeof(ct_analysis_function);
  ct_analysis_function *functions = malloc(size);
  if (size && !functions)
    dr_abort();
  transfer(functions, size, false);
  dr_mutex_unlock(analysis_lock);
  for (uint32_t index = 0; index < count; ++index)
    callback(functions[index].offset, functions[index].name, context);
  free(functions);
}

void ct_analysis_close(ct_analysis *analysis) {
  if (!analysis)
    return;
  dr_mutex_lock(analysis_lock);
  const bool owns_descriptors = ct_analysis_object_owner() != 0;
  if (owns_descriptors && analysis->remote_open)
    send_request(CT_ANALYSIS_CLOSE, analysis, 0, NULL, NULL);
  ct_analysis **entry = &analysis_modules;
  while (*entry && *entry != analysis)
    entry = &(*entry)->next;
  if (*entry)
    *entry = analysis->next;
  // The last CLONE_VM task can have a different descriptor table from the
  // process that prepared these modules. Release shared heap state without
  // using that process's descriptor numbers or analysis-worker connection.
  if (owns_descriptors && analysis->debug_descriptor >= 0)
    dr_close_file(analysis->debug_descriptor);
  if (owns_descriptors && analysis->supplement_descriptor >= 0)
    dr_close_file(analysis->supplement_descriptor);
  if (owns_descriptors && analysis->module_file >= 0)
    dr_close_file(analysis->module_file);
  dr_mutex_unlock(analysis_lock);
  free(analysis->path);
  free(analysis->maps);
  free(analysis->error);
  free(analysis->decompile_error);
  free(analysis);
}

void ct_analysis_inline_scopes(ct_analysis *analysis,
                               void (*callback)(uint64_t, uint64_t,
                                                const char *, void *),
                               void *context) {
  if (!analysis || !callback)
    return;
  uint32_t count;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_INLINE_SCOPES, analysis, 0, NULL, NULL);
  transfer(&count, sizeof(count), false);
  size_t size = (size_t)count * sizeof(ct_analysis_inline_scope);
  ct_analysis_inline_scope *scopes = malloc(size);
  if (size && !scopes)
    dr_abort();
  transfer(scopes, size, false);
  dr_mutex_unlock(analysis_lock);
  for (uint32_t index = 0; index < count; ++index)
    callback(scopes[index].begin_offset, scopes[index].end_offset,
             scopes[index].linkage_name, context);
  free(scopes);
}

bool ct_analysis_observation_boundaries(ct_analysis *analysis,
                                        void (*callback)(uint64_t, void *),
                                        void *context) {
  if (!analysis || !callback)
    return false;
  bool complete;
  uint32_t count;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_OBSERVATION_BOUNDARIES, analysis, 0, NULL, NULL);
  transfer(&complete, sizeof(complete), false);
  transfer(&count, sizeof(count), false);
  if (count > (128 * 1024 * 1024) / sizeof(uint64_t))
    dr_abort();
  const size_t size = (size_t)count * sizeof(uint64_t);
  uint64_t *offsets = size ? malloc(size) : NULL;
  if (size && !offsets)
    dr_abort();
  transfer(offsets, size, false);
  dr_mutex_unlock(analysis_lock);
  for (uint32_t index = 1; index < count; ++index)
    if (offsets[index] <= offsets[index - 1])
      complete = false;
  if (complete)
    for (uint32_t index = 0; index < count; ++index)
      callback(offsets[index], context);
  free(offsets);
  return complete;
}

bool ct_analysis_flow(ct_analysis *analysis, uint64_t module_offset,
                      ct_flow_range *range,
                      void (*callback)(uint64_t, uint32_t, uint64_t, void *),
                      void (*region_callback)(const ct_flow_region *, void *),
                      void (*switch_callback)(const ct_flow_switch *, void *),
                      void *context) {
  if (range)
    memset(range, 0, sizeof(*range));
  if (!analysis || !range)
    return false;
  ct_analysis_flow_header header;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_FLOW, analysis, module_offset, NULL, NULL);
  transfer(&header, sizeof(header), false);
  size_t size = (size_t)header.count * sizeof(ct_analysis_flow_boundary);
  ct_analysis_flow_boundary *boundaries = malloc(size);
  if (size && !boundaries)
    dr_abort();
  transfer(boundaries, size, false);
  size_t region_size = (size_t)header.region_count * sizeof(ct_flow_region);
  ct_flow_region *regions = malloc(region_size);
  if (region_size && !regions)
    dr_abort();
  transfer(regions, region_size, false);
  size_t switch_size = (size_t)header.switch_count * sizeof(ct_flow_switch);
  ct_flow_switch *switches = malloc(switch_size);
  if (switch_size && !switches)
    dr_abort();
  transfer(switches, switch_size, false);
  dr_mutex_unlock(analysis_lock);
  range->begin_offset = header.begin_offset;
  range->end_offset = header.end_offset;
  range->complete = header.complete;
  range->bounded = header.bounded;
  if (header.valid && callback)
    for (uint32_t index = 0; index < header.count; ++index)
      callback(boundaries[index].offset, boundaries[index].roles,
               boundaries[index].group_offset, context);
  if (header.valid && region_callback)
    for (uint32_t index = 0; index < header.region_count; ++index)
      region_callback(&regions[index], context);
  if (header.valid && switch_callback)
    for (uint32_t index = 0; index < header.switch_count; ++index)
      switch_callback(&switches[index], context);
  free(boundaries);
  free(regions);
  free(switches);
  return header.valid;
}

bool ct_analysis_code_graph(
    ct_analysis *analysis, uint64_t module_offset, ct_flow_range *range,
    void (*instruction_callback)(const ct_flow_instruction *, void *),
    void (*edge_callback)(const ct_flow_edge *, void *), void *context) {
  if (range)
    memset(range, 0, sizeof(*range));
  if (!analysis || !range)
    return false;
  ct_analysis_code_graph_header header;
  dr_mutex_lock(analysis_lock);
  request(CT_ANALYSIS_CODE_GRAPH, analysis, module_offset, NULL, NULL);
  transfer(&header, sizeof(header), false);
  if (header.instruction_count > CT_FLOW_GRAPH_INSTRUCTION_LIMIT ||
      header.edge_count > CT_FLOW_GRAPH_EDGE_LIMIT ||
      (!header.valid && (header.instruction_count || header.edge_count))) {
    ct_output_printf("ctrace: invalid code graph response size\n");
    dr_abort();
  }
  const size_t instruction_size =
      (size_t)header.instruction_count * sizeof(ct_flow_instruction);
  const size_t edge_size = (size_t)header.edge_count * sizeof(ct_flow_edge);
  ct_flow_instruction *instructions =
      instruction_size ? malloc(instruction_size) : NULL;
  ct_flow_edge *edges = edge_size ? malloc(edge_size) : NULL;
  if ((instruction_size && !instructions) || (edge_size && !edges))
    dr_abort();
  transfer(instructions, instruction_size, false);
  transfer(edges, edge_size, false);
  dr_mutex_unlock(analysis_lock);
  const bool valid =
      header.valid && header.entry_offset == module_offset &&
      ct_flow_graph_valid(&header.range, module_offset, instructions,
                          header.instruction_count, edges, header.edge_count);
  if (valid) {
    *range = header.range;
    if (instruction_callback)
      for (uint32_t index = 0; index < header.instruction_count; ++index)
        instruction_callback(&instructions[index], context);
    if (edge_callback)
      for (uint32_t index = 0; index < header.edge_count; ++index)
        edge_callback(&edges[index], context);
  }
  free(instructions);
  free(edges);
  return valid;
}
