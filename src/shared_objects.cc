// SPDX-License-Identifier: MIT

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>

#include <fcntl.h>
#include <linux/memfd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "shared_objects_platform.hh"
#include "shared_objects_protocol.hh"

struct ct_shared_channel {
  int fd;
  uint64_t process;
  uint64_t thread;
  uint64_t participant;
  uint64_t session;
  uint64_t request;
  uint64_t sequence;
};

static bool owned(const ct_shared_channel *channel) {
  return channel && channel->fd >= 0 && channel->session &&
         channel->session == ct_shared_platform_session() &&
         channel->process == (uint64_t)syscall(SYS_getpid) &&
         channel->thread == (uint64_t)syscall(SYS_gettid);
}

static int protect_descriptor(int descriptor, bool inherit_fork) {
  if (descriptor < 0)
    return -1;
  if (!ct_shared_platform_adopt(descriptor, inherit_fork)) {
    close(descriptor);
    return -1;
  }
  return descriptor;
}

static bool send_packet(ct_shared_channel *channel, ct_shared_packet *packet,
                        int descriptor) {
  memcpy(packet->contract, ct_contract_digest, sizeof(packet->contract));
  if (!owned(channel) || channel->request == UINT64_MAX)
    return false;
  packet->request = ++channel->request;
  struct iovec vector = {packet, sizeof(*packet)};
  union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(int))];
  } ancillary = {};
  struct msghdr message = {};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  if (descriptor >= 0) {
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  }
  ssize_t size;
  do {
    size = sendmsg(channel->fd, &message, MSG_NOSIGNAL);
  } while (size < 0 && errno == EINTR);
  return size == sizeof(*packet);
}

static bool receive_packet(ct_shared_channel *channel, ct_shared_packet *packet,
                           int *descriptor) {
  *descriptor = -1;
  if (!owned(channel))
    return false;
  memset(packet, 0, sizeof(*packet));
  struct iovec vector = {packet, sizeof(*packet)};
  union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(int) * 4)];
  } ancillary = {};
  struct msghdr message = {};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = ancillary.bytes;
  message.msg_controllen = sizeof(ancillary.bytes);
  ssize_t size;
  do {
    size = recvmsg(channel->fd, &message, MSG_CMSG_CLOEXEC);
  } while (size < 0 && errno == EINTR);
  bool valid = size == sizeof(*packet) &&
               !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
               ct_contract_matches(packet->contract);
  int received = -1;
  for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(0)) {
      valid = false;
      continue;
    }
    const size_t count = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    for (size_t index = 0; index < count; ++index) {
      int fd;
      memcpy(&fd, CMSG_DATA(header) + index * sizeof(fd), sizeof(fd));
      if (received < 0)
        received = fd;
      else {
        close(fd);
        valid = false;
      }
    }
  }
  if (valid && received >= 0) {
    const bool reservation =
        (packet->operation == CT_SHARED_FORK_RESERVE ||
         packet->operation == CT_SHARED_FORK_RESERVE_SELECTED) &&
        packet->status == CT_SHARED_OK;
    received = protect_descriptor(received, reservation);
    valid = received >= 0;
    if (valid && reservation) {
      struct stat information;
      const int flags = fcntl(received, F_GETFL);
      valid = packet->token && flags >= 0 && (flags & O_ACCMODE) == O_WRONLY &&
              fstat(received, &information) == 0 &&
              S_ISFIFO(information.st_mode);
      if (!valid)
        ct_shared_platform_close(received);
    } else if (valid) {
      struct stat information;
      ct_shared_envelope envelope;
      const long page_size = sysconf(_SC_PAGESIZE);
      const int seals = fcntl(received, F_GET_SEALS);
      const int required = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW |
                           F_SEAL_WRITE | F_SEAL_EXEC;
      valid =
          packet->status == CT_SHARED_READY && packet->object.object_id &&
          seals >= 0 && (seals & required) == required &&
          fstat(received, &information) == 0 && S_ISREG(information.st_mode) &&
          information.st_size >= 0 &&
          pread(received, &envelope, sizeof(envelope), 0) == sizeof(envelope) &&
          ct_shared_envelope_valid(&envelope, information.st_size) &&
          ((information.st_mode & 0111) != 0) ==
              (envelope.key.kind != CT_SHARED_DECOMPILE) &&
          page_size > 0 && envelope.payload_offset % (uint64_t)page_size == 0 &&
          envelope.payload_offset == packet->object.payload_offset &&
          envelope.payload_size == packet->object.payload_size &&
          !memcmp(&envelope.key, &packet->object.key, sizeof(envelope.key)) &&
          !memcmp(envelope.digest, packet->object.digest,
                  sizeof(envelope.digest));
      if (!valid)
        ct_shared_platform_close(received);
    }
  } else if (received >= 0)
    close(received);
  if (!valid || (packet->status == CT_SHARED_READY && received < 0))
    return false;
  *descriptor = received;
  if (channel->sequence < packet->sequence)
    channel->sequence = packet->sequence;
  return true;
}

static bool exchange(ct_shared_channel *channel, ct_shared_packet *request,
                     int descriptor, ct_shared_packet *response, int *fd) {
  if (!send_packet(channel, request, descriptor))
    return false;
  for (;;) {
    if (!receive_packet(channel, response, fd))
      return false;
    if (response->operation == CT_SHARED_NOTIFY && !response->request &&
        *fd < 0)
      continue;
    if (response->operation == request->operation &&
        response->request == request->request)
      return true;
    if (*fd >= 0)
      ct_shared_platform_close(*fd);
    return false;
  }
}

static void result_packet(const ct_shared_packet *packet, int descriptor,
                          ct_shared_result *result) {
  memset(result, 0, sizeof(*result));
  result->status = packet->status;
  result->error = packet->error;
  result->token = packet->token;
  result->sequence = packet->sequence;
  result->object = packet->object;
  result->fd = descriptor;
  result->owner_process = (uint64_t)syscall(SYS_getpid);
  result->owner_session = ct_shared_platform_session();
}

ct_shared_channel *ct_shared_open(void) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0)
    return NULL;
  const int descriptor = protect_descriptor(sockets[0], false);
  const bool connected =
      descriptor >= 0 && ct_shared_platform_connect(sockets[1]);
  close(sockets[1]);
  if (!connected) {
    if (descriptor >= 0)
      ct_shared_platform_close(descriptor);
    return NULL;
  }
  ct_shared_channel *channel =
      static_cast<ct_shared_channel *>(calloc(1, sizeof(*channel)));
  if (!channel) {
    ct_shared_platform_close(descriptor);
    return NULL;
  }
  channel->fd = descriptor;
  channel->process = (uint64_t)syscall(SYS_getpid);
  channel->thread = (uint64_t)syscall(SYS_gettid);
  channel->session = ct_shared_platform_session();
  ct_shared_packet packet;
  int received;
  if (!receive_packet(channel, &packet, &received) || received >= 0 ||
      packet.operation != CT_SHARED_HELLO || packet.status != CT_SHARED_OK ||
      !packet.token) {
    if (received >= 0)
      ct_shared_platform_close(received);
    ct_shared_close(channel);
    return NULL;
  }
  channel->participant = packet.token;
  return channel;
}

bool ct_shared_close(ct_shared_channel *channel) {
  if (!owned(channel))
    return false;
  ct_shared_platform_close(channel->fd);
  free(channel);
  return true;
}

bool ct_shared_close_quiescent(ct_shared_channel *channel) {
  if (!channel || channel->fd < 0 || !channel->session ||
      channel->session != ct_shared_platform_session() ||
      channel->process != (uint64_t)syscall(SYS_getpid))
    return false;
  ct_shared_platform_close(channel->fd);
  free(channel);
  return true;
}

void ct_shared_abandon_channel(ct_shared_channel *channel) { free(channel); }

bool ct_shared_fork_forget_channel(ct_shared_channel *channel) {
  const uint64_t current = ct_shared_platform_session();
  if (!channel || !current || channel->session == current)
    return false;
  free(channel);
  return true;
}

bool ct_shared_acquire(ct_shared_channel *channel, const ct_shared_key *key,
                       ct_shared_result *result) {
  if (!result || !ct_shared_key_valid(key))
    return false;
  ct_shared_packet request = {}, response;
  request.operation = CT_SHARED_ACQUIRE;
  request.key = *key;
  int descriptor;
  if (!exchange(channel, &request, -1, &response, &descriptor))
    return false;
  result_packet(&response, descriptor, result);
  return true;
}

static bool dr_member_exchange(ct_shared_channel *channel,
                               const ct_shared_key *key,
                               const unsigned char *provenance,
                               const unsigned char *body,
                               uint64_t expected_object, bool available,
                               ct_shared_dr_member_result *result) {
  if (!result || !ct_shared_key_valid(key) || key->kind != CT_SHARED_DR_CODE ||
      key->format != CT_SHARED_FORMAT_DR_MEMBER ||
      ((provenance == NULL) != (body == NULL)))
    return false;
  ct_shared_packet request = {}, response;
  request.operation = available    ? CT_SHARED_DR_MEMBER_BIND_AVAILABLE
                      : provenance ? CT_SHARED_DR_MEMBER_BIND
                                   : CT_SHARED_DR_MEMBER_ACQUIRE;
  request.key = *key;
  request.object.object_id = expected_object;
  if (provenance) {
    memcpy(request.object.key.identity, provenance, 32);
    memcpy(request.object.digest, body, 32);
  }
  int descriptor;
  if (!exchange(channel, &request, -1, &response, &descriptor))
    return false;
  memset(result, 0, sizeof(*result));
  result_packet(&response, descriptor, &result->result);
  result->member_offset = response.cursor;
  result->member_size = response.count;
  if (response.status == CT_SHARED_READY &&
      (response.object.key.kind != CT_SHARED_DR_CODE ||
       response.object.key.format != CT_SHARED_FORMAT_DR_COMPACT ||
       !response.count || response.cursor % 16 ||
       response.cursor > response.object.payload_size ||
       response.count > response.object.payload_size - response.cursor)) {
    ct_shared_result_close(&result->result);
    ct_shared_release(channel, response.object.object_id);
    return false;
  }
  return true;
}

bool ct_shared_dr_member_acquire(ct_shared_channel *channel,
                                 const ct_shared_key *member,
                                 ct_shared_dr_member_result *result) {
  return dr_member_exchange(channel, member, NULL, NULL, 0, false, result);
}

bool ct_shared_dr_member_bind(ct_shared_channel *channel,
                              const ct_shared_key *member,
                              const unsigned char provenance[32],
                              const unsigned char body[32],
                              ct_shared_dr_member_result *result) {
  if (!provenance || !body)
    return false;
  return dr_member_exchange(channel, member, provenance, body, 0, false,
                            result);
}

bool ct_shared_dr_member_bind_to(ct_shared_channel *channel,
                                 const ct_shared_key *member,
                                 const unsigned char provenance[32],
                                 const unsigned char body[32],
                                 uint64_t expected_object,
                                 ct_shared_dr_member_result *result) {
  if (!provenance || !body || !expected_object)
    return false;
  if (!dr_member_exchange(channel, member, provenance, body, expected_object,
                          false, result))
    return false;
  if (result->result.status == CT_SHARED_READY &&
      result->result.object.object_id != expected_object) {
    ct_shared_result_close(&result->result);
    ct_shared_release(channel, result->result.object.object_id);
    return false;
  }
  return true;
}

bool ct_shared_dr_member_bind_available(ct_shared_channel *channel,
                                        const ct_shared_key *member,
                                        const unsigned char provenance[32],
                                        const unsigned char body[32],
                                        uint64_t expected_object,
                                        ct_shared_dr_member_result *result) {
  if (!provenance || !body || !expected_object ||
      !dr_member_exchange(channel, member, provenance, body, expected_object,
                          true, result))
    return false;
  if (result->result.status == CT_SHARED_READY &&
      result->result.object.object_id != expected_object) {
    ct_shared_result_close(&result->result);
    ct_shared_release(channel, result->result.object.object_id);
    return false;
  }
  return true;
}

bool ct_shared_dr_member_scan(ct_shared_channel *channel, uint64_t upper_bound,
                              uint64_t cursor, ct_shared_scan_page *page) {
  if (!page || cursor > upper_bound)
    return false;
  ct_shared_packet request = {}, response;
  request.operation = CT_SHARED_DR_MEMBER_SCAN;
  request.token = upper_bound;
  request.cursor = cursor;
  int descriptor;
  if (!exchange(channel, &request, -1, &response, &descriptor))
    return false;
  if (descriptor >= 0)
    ct_shared_platform_close(descriptor);
  if (descriptor >= 0 || response.status != CT_SHARED_OK ||
      response.count > CT_SHARED_SNAPSHOT_CAPACITY ||
      response.cursor < cursor || response.cursor > response.token ||
      (upper_bound && response.token != upper_bound))
    return false;
  memset(page, 0, sizeof(*page));
  page->upper_bound = response.token;
  page->cursor = response.cursor;
  page->sequence = response.sequence;
  page->count = response.count;
  page->more = response.more != 0;
  memcpy(page->entries, response.entries,
         response.count * sizeof(response.entries[0]));
  return true;
}

bool ct_shared_dr_compact_member_key(uint32_t level,
                                     const unsigned char provenance[32],
                                     const unsigned char body[32],
                                     ct_shared_key *key) {
  if (!provenance || !body || !key || level > 2)
    return false;
  struct {
    char magic[8];
    uint32_t level;
    uint32_t reserved;
  } identity = {{'C', 'T', 'D', 'R', 'P', 'R', 'O', 'F'}, level, 0};
  memset(key, 0, sizeof(*key));
  key->kind = CT_SHARED_DR_CODE;
  key->format = CT_SHARED_FORMAT_DR_MEMBER;
  key->level = level;
  const ct_digest_part parts[] = {
      {ct_contract_digest, sizeof(ct_contract_digest)},
      {&identity, sizeof(identity)},
      {provenance, 32},
      {body, 32}};
  return ct_shared_platform_digest_parts(parts, 4, key->identity);
}

bool ct_shared_dr_compact_digest(uint32_t isa_mode,
                                 const ct_shared_dr_compact_member *member,
                                 const void *relocations, const void *code,
                                 size_t code_size, size_t private_size,
                                 unsigned char digest[32]) {
  if (!member || !code || !digest || !relocations || !member->size ||
      member->reserved || !member->private_size || !member->relocation_count ||
      member->relocation_count > member->size / 4 || !code_size ||
      code_size > CT_SHARED_DR_COMPACT_LIMIT || !private_size ||
      private_size > CT_SHARED_DR_COMPACT_LIMIT || member->offset % 16 ||
      member->offset > code_size || member->size > code_size - member->offset ||
      member->private_offset % 16 || member->private_offset > private_size ||
      member->private_size > private_size - member->private_offset ||
      member->prototype_private_offset < member->size ||
      member->prototype_private_offset > CT_SHARED_DR_COMPACT_LIMIT)
    return false;
  struct {
    char magic[8];
    uint32_t isa, size, private_size, prototype, count, reserved;
  } identity = {{'C', 'T', 'D', 'R', 'T', 'P', 'L', '\0'},
                isa_mode,
                member->size,
                member->private_size,
                member->prototype_private_offset,
                member->relocation_count,
                0};
  const size_t count = member->relocation_count;
  const bool normalized_mapping = member->offset == 0 &&
                                  member->private_offset == 0 &&
                                  code_size == member->prototype_private_offset;
  ct_digest_part fixed[] = {
      {&identity, sizeof(identity)},
      {relocations, count * sizeof(ct_shared_dr_relocation)},
      {code, member->size}};
  ct_digest_part *parts = static_cast<ct_digest_part *>(
      normalized_mapping ? NULL : calloc(3 + 2 * count, sizeof(*parts)));
  uint32_t *words = static_cast<uint32_t *>(
      normalized_mapping ? NULL : calloc(count, sizeof(*words)));
  if (!normalized_mapping && (!parts || !words)) {
    free(parts);
    free(words);
    return false;
  }
  if (!normalized_mapping) {
    parts[0] = fixed[0];
    parts[1] = fixed[1];
  }
  size_t previous = 0, used = 2;
  bool valid = true;
  for (size_t i = 0; valid && i < count; ++i) {
    ct_shared_dr_relocation record;
    memcpy(&record, (const unsigned char *)relocations + i * sizeof(record),
           sizeof(record));
    const ct_shared_dr_relocation *relocation = &record;
    valid = !relocation->reserved && relocation->field_offset >= previous &&
            relocation->field_offset <= member->size - 4 &&
            relocation->target_offset < member->private_size &&
            (relocation->kind == 1 || relocation->kind == 2);
    if (!valid)
      break;
    int64_t actual = (int64_t)code_size + member->private_offset -
                     member->offset + relocation->target_offset;
    int64_t normalized =
        (int64_t)member->prototype_private_offset + relocation->target_offset;
    if (relocation->kind == 2) {
      actual -= (int64_t)relocation->field_offset + 4;
      normalized -= (int64_t)relocation->field_offset + 4;
      valid = actual >= INT32_MIN && actual <= INT32_MAX &&
              normalized >= INT32_MIN && normalized <= INT32_MAX;
    } else {
      valid = actual >= 0 && actual <= UINT32_MAX && normalized >= 0 &&
              normalized <= UINT32_MAX;
    }
    uint32_t encoded;
    memcpy(&encoded, (const unsigned char *)code + relocation->field_offset, 4);
    valid &= encoded == (uint32_t)actual;
    if (!normalized_mapping) {
      words[i] = (uint32_t)normalized;
      parts[used++] = ct_digest_part{(const unsigned char *)code + previous,
                                     relocation->field_offset - previous};
      parts[used++] = ct_digest_part{&words[i], sizeof(words[i])};
    }
    previous = (size_t)relocation->field_offset + 4;
  }
  if (normalized_mapping) {
    return valid && ct_shared_platform_digest_parts(fixed, 3, digest);
  } else {
    parts[used++] = ct_digest_part{(const unsigned char *)code + previous,
                                   member->size - previous};
    valid = valid && ct_shared_platform_digest_parts(parts, used, digest);
  }
  free(words);
  free(parts);
  return valid;
}

bool ct_shared_dr_compact_validate(const void *index, size_t index_size,
                                   const void *code, size_t size) {
  if (!index || !code || index_size < sizeof(ct_shared_dr_compact_header) ||
      index_size > CT_SHARED_DR_COMPACT_LIMIT)
    return false;
  const ct_shared_dr_compact_header *header =
      static_cast<const ct_shared_dr_compact_header *>(index);
  const long page = sysconf(_SC_PAGESIZE);
  if (page <= 0 || memcmp(header->magic, "CTDRCMP", 8) ||
      !ct_contract_matches(header->contract) || header->reserved ||
      !header->count || !header->relocation_count || !size ||
      size != header->code_size || size > CT_SHARED_DR_COMPACT_LIMIT ||
      size % (size_t)page || !header->private_size ||
      header->private_size > CT_SHARED_DR_COMPACT_LIMIT ||
      header->private_size % (size_t)page ||
      header->count >
          (index_size - sizeof(*header)) / sizeof(ct_shared_dr_compact_member))
    return false;
  const size_t relocation_offset =
      sizeof(*header) + header->count * sizeof(ct_shared_dr_compact_member);
  if (header->relocation_count !=
          (index_size - relocation_offset) / sizeof(ct_shared_dr_relocation) ||
      (index_size - relocation_offset) % sizeof(ct_shared_dr_relocation))
    return false;
  const ct_shared_dr_compact_member *members =
      (const ct_shared_dr_compact_member *)((const unsigned char *)index +
                                            sizeof(*header));
  const ct_shared_dr_relocation *relocations =
      (const ct_shared_dr_relocation *)((const unsigned char *)index +
                                        relocation_offset);
  uint64_t previous_rx = 0, previous_private = 0, previous_relocation = 0;
  for (uint32_t i = 0; i < header->count; ++i) {
    const ct_shared_dr_compact_member *member = &members[i];
    unsigned char digest[32];
    if (member->offset > size || member->offset < previous_rx ||
        member->private_offset < previous_private ||
        member->relocation_index != previous_relocation ||
        member->relocation_index > header->relocation_count ||
        member->relocation_count >
            header->relocation_count - member->relocation_index ||
        !ct_shared_dr_compact_digest(
            header->isa_mode, member, relocations + member->relocation_index,
            (const unsigned char *)code + member->offset, size,
            header->private_size, digest) ||
        memcmp(digest, member->identity, sizeof(digest)))
      return false;
    previous_rx = (uint64_t)member->offset + member->size;
    previous_private = (uint64_t)member->private_offset + member->private_size;
    previous_relocation += member->relocation_count;
  }
  return previous_relocation == header->relocation_count;
}

bool ct_shared_wait(ct_shared_channel *channel, uint64_t ticket, int timeout_ms,
                    ct_shared_result *result) {
  if (!owned(channel) || !ticket || !result || timeout_ms < -1)
    return false;
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    return false;
  const uint64_t began =
      (uint64_t)start.tv_sec * 1000 + start.tv_nsec / 1000000;
  for (;;) {
    ct_shared_packet request = {}, response;
    request.operation = CT_SHARED_WAIT_STATUS;
    request.token = ticket;
    int descriptor;
    if (!exchange(channel, &request, -1, &response, &descriptor))
      return false;
    result_packet(&response, descriptor, result);
    if (result->status != CT_SHARED_WAIT || timeout_ms == 0)
      return true;
    int remaining = -1;
    if (timeout_ms >= 0) {
      struct timespec current;
      if (clock_gettime(CLOCK_MONOTONIC, &current) != 0)
        return false;
      const uint64_t now =
          (uint64_t)current.tv_sec * 1000 + current.tv_nsec / 1000000;
      if (now - began >= (uint64_t)timeout_ms)
        return true;
      remaining = timeout_ms - (int)(now - began);
    }
    struct pollfd pollfd = {channel->fd, POLLIN, 0};
    const int ready = poll(&pollfd, 1, remaining);
    if (!ready)
      return true;
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (!(pollfd.revents & POLLIN) ||
        !receive_packet(channel, &response, &descriptor))
      return false;
    if (descriptor >= 0)
      ct_shared_platform_close(descriptor);
    if (response.operation != CT_SHARED_NOTIFY || response.request ||
        descriptor >= 0)
      return false;
  }
}

static bool acknowledge(ct_shared_channel *channel, uint32_t operation,
                        uint64_t token) {
  ct_shared_packet request = {}, response;
  request.operation = operation;
  request.token = token;
  int descriptor;
  if (!exchange(channel, &request, -1, &response, &descriptor))
    return false;
  if (descriptor >= 0)
    ct_shared_platform_close(descriptor);
  return descriptor < 0 && response.status == CT_SHARED_OK;
}

bool ct_shared_cancel_wait(ct_shared_channel *channel, uint64_t ticket) {
  return acknowledge(channel, CT_SHARED_CANCEL_WAIT, ticket);
}

bool ct_shared_fail(ct_shared_channel *channel, uint64_t lease) {
  return acknowledge(channel, CT_SHARED_FAIL, lease);
}

bool ct_shared_release(ct_shared_channel *channel, uint64_t object_id) {
  return acknowledge(channel, CT_SHARED_RELEASE, object_id);
}

bool ct_shared_publish(ct_shared_channel *channel, uint64_t lease,
                       const ct_shared_file *file, ct_shared_result *result) {
  if (!file || file->fd < 0 || !result || !file->owner_session ||
      file->owner_session != ct_shared_platform_session() ||
      file->owner_process != (uint64_t)syscall(SYS_getpid))
    return false;
  ct_shared_packet request = {}, response;
  request.operation = CT_SHARED_PUBLISH;
  request.token = lease;
  int descriptor;
  if (!exchange(channel, &request, file->fd, &response, &descriptor))
    return false;
  result_packet(&response, descriptor, result);
  return true;
}

bool ct_shared_result_close(ct_shared_result *result) {
  if (!result || !result->owner_session ||
      result->owner_session != ct_shared_platform_session() ||
      result->owner_process != (uint64_t)syscall(SYS_getpid))
    return false;
  if (result->fd >= 0)
    ct_shared_platform_close(result->fd);
  result->fd = -1;
  return true;
}

static bool write_bytes(int fd, const void *data, size_t size,
                        uint64_t offset) {
  size_t written = 0;
  while (written < size) {
    const ssize_t count = pwrite(fd, (const unsigned char *)data + written,
                                 size - written, offset + written);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    written += (size_t)count;
  }
  return true;
}

static bool create_indexed_file(const ct_shared_key *key, const void *index,
                                size_t index_size, const void *payload,
                                size_t size, ct_shared_file *file) {
  if (!file || !ct_shared_key_valid(key) || (!payload && size) ||
      (index_size && !index))
    return false;
  ct_shared_envelope envelope = {};
  const long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0 || sizeof(envelope) > (uint64_t)page_size ||
      (index_size > (uint64_t)page_size - sizeof(envelope) &&
       (key->kind != CT_SHARED_DR_CODE ||
        key->format != CT_SHARED_FORMAT_DR_COMPACT ||
        index_size > CT_SHARED_DR_COMPACT_LIMIT)))
    return false;
  const uint64_t offset =
      (sizeof(envelope) + index_size + (uint64_t)page_size - 1) /
      (uint64_t)page_size * (uint64_t)page_size;
  if (offset > uint64_t(std::numeric_limits<off_t>::max()) ||
      size > uint64_t(std::numeric_limits<off_t>::max()) - offset)
    return false;
  memcpy(envelope.magic, "CTSHOBJ", 8);
  memcpy(envelope.contract, ct_contract_digest, sizeof(envelope.contract));
  envelope.header_size = sizeof(envelope) + index_size;
  envelope.key = *key;
  envelope.payload_offset = offset;
  envelope.payload_size = size;
  const ct_digest_part parts[] = {{index, index_size}, {payload, size}};
  if (!ct_shared_platform_digest_parts(parts, 2, envelope.digest))
    return false;
  const unsigned policy =
      key->kind == CT_SHARED_DECOMPILE ? MFD_NOEXEC_SEAL : MFD_EXEC;
  file->fd =
      protect_descriptor((int)syscall(SYS_memfd_create, "ctrace-shared",
                                      MFD_CLOEXEC | MFD_ALLOW_SEALING | policy),
                         false);
  file->owner_process = (uint64_t)syscall(SYS_getpid);
  file->owner_session = ct_shared_platform_session();
  if (file->fd < 0)
    return false;
  const bool complete =
      ftruncate(file->fd, offset + size) == 0 &&
      write_bytes(file->fd, &envelope, sizeof(envelope), 0) &&
      write_bytes(file->fd, index, index_size, sizeof(envelope)) &&
      write_bytes(file->fd, payload, size, offset) &&
      fcntl(file->fd, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL |
                F_SEAL_EXEC) == 0;
  if (!complete)
    ct_shared_file_close(file);
  return complete;
}

bool ct_shared_file_create(const ct_shared_key *key, const void *payload,
                           size_t size, ct_shared_file *file) {
  return create_indexed_file(key, NULL, 0, payload, size, file);
}

bool ct_shared_dr_compact_create(const void *index, size_t index_size,
                                 const void *code, size_t size,
                                 ct_shared_key *key, ct_shared_file *file) {
  if (!key || !file ||
      !ct_shared_dr_compact_validate(index, index_size, code, size))
    return false;
  memset(key, 0, sizeof(*key));
  key->kind = CT_SHARED_DR_CODE;
  key->format = CT_SHARED_FORMAT_DR_COMPACT;
  const ct_digest_part parts[] = {{index, index_size}, {code, size}};
  return ct_shared_platform_digest_parts(parts, 2, key->identity) &&
         create_indexed_file(key, index, index_size, code, size, file);
}

bool ct_shared_file_close(ct_shared_file *file) {
  if (!file || !file->owner_session ||
      file->owner_session != ct_shared_platform_session() ||
      file->owner_process != (uint64_t)syscall(SYS_getpid))
    return false;
  if (file->fd >= 0)
    ct_shared_platform_close(file->fd);
  file->fd = -1;
  return true;
}

static bool fork_reserve(ct_shared_channel *channel, int selected, size_t count,
                         ct_shared_fork_reservation *reservation) {
  if (!reservation)
    return false;
  ct_shared_packet request = {}, response;
  request.operation =
      selected >= 0 ? CT_SHARED_FORK_RESERVE_SELECTED : CT_SHARED_FORK_RESERVE;
  request.cursor = count;
  int descriptor;
  if (!exchange(channel, &request, selected, &response, &descriptor))
    return false;
  if (response.status != CT_SHARED_OK || !response.token || descriptor < 0) {
    if (descriptor >= 0)
      ct_shared_platform_close(descriptor);
    return false;
  }
  reservation->token = response.token;
  reservation->fd = descriptor;
  reservation->owner_process = channel->process;
  reservation->owner_session = channel->session;
  return true;
}

bool ct_shared_fork_reserve(ct_shared_channel *channel,
                            ct_shared_fork_reservation *reservation) {
  return fork_reserve(channel, -1, 0, reservation);
}

bool ct_shared_fork_reserve_selected(ct_shared_channel *channel,
                                     const uint64_t *object_ids, size_t count,
                                     ct_shared_fork_reservation *reservation) {
  if (!owned(channel) || !reservation || (!object_ids && count) ||
      count > uint64_t(std::numeric_limits<off_t>::max()) / sizeof(*object_ids))
    return false;
  const int descriptor = protect_descriptor(
      syscall(SYS_memfd_create, "ctrace-fork-references",
              MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL),
      false);
  if (descriptor < 0)
    return false;
  const size_t size = count * sizeof(*object_ids);
  size_t done = 0;
  while (done < size) {
    ssize_t bytes =
        write(descriptor, (const char *)object_ids + done, size - done);
    if (bytes < 0 && errno == EINTR)
      continue;
    if (bytes <= 0)
      break;
    done += bytes;
  }
  const int seals =
      F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL | F_SEAL_EXEC;
  const bool success = done == size &&
                       fcntl(descriptor, F_ADD_SEALS, seals) == 0 &&
                       fork_reserve(channel, descriptor, count, reservation);
  ct_shared_platform_close(descriptor);
  return success;
}

bool ct_shared_fork_parent_done(ct_shared_fork_reservation *reservation) {
  if (!reservation || !reservation->owner_session ||
      reservation->owner_session != ct_shared_platform_session() ||
      reservation->owner_process != (uint64_t)syscall(SYS_getpid))
    return false;
  if (reservation->fd >= 0)
    ct_shared_platform_close(reservation->fd);
  reservation->fd = -1;
  reservation->token = 0;
  return true;
}

bool ct_shared_fork_claim(ct_shared_channel *channel,
                          ct_shared_fork_reservation *reservation) {
  if (!owned(channel) || !reservation || reservation->fd < 0 ||
      !reservation->token || !reservation->owner_session ||
      reservation->owner_session == channel->session)
    return false;
  ct_shared_packet request = {}, response;
  request.operation = CT_SHARED_FORK_CLAIM;
  request.token = reservation->token;
  int descriptor = -1;
  const bool received =
      exchange(channel, &request, reservation->fd, &response, &descriptor);
  ct_shared_platform_close(reservation->fd);
  reservation->fd = -1;
  reservation->token = 0;
  reservation->owner_process = channel->process;
  reservation->owner_session = channel->session;
  if (descriptor >= 0)
    ct_shared_platform_close(descriptor);
  return received && descriptor < 0 && response.status == CT_SHARED_OK;
}

bool ct_shared_list(ct_shared_channel *channel, uint64_t sequence,
                    uint64_t cursor, ct_shared_snapshot *snapshot) {
  if (!snapshot)
    return false;
  ct_shared_packet request = {}, response;
  request.operation = CT_SHARED_LIST;
  request.sequence = sequence;
  request.cursor = cursor;
  int descriptor;
  if (!exchange(channel, &request, -1, &response, &descriptor))
    return false;
  if (descriptor >= 0)
    ct_shared_platform_close(descriptor);
  if (descriptor >= 0 || response.count > CT_SHARED_SNAPSHOT_CAPACITY ||
      (response.status != CT_SHARED_OK && response.status != CT_SHARED_RESYNC))
    return false;
  memset(snapshot, 0, sizeof(*snapshot));
  snapshot->sequence = response.sequence;
  snapshot->cursor = response.cursor;
  snapshot->count = response.count;
  snapshot->more = response.more != 0;
  snapshot->resync = response.status == CT_SHARED_RESYNC;
  memcpy(snapshot->entries, response.entries,
         response.count * sizeof(*snapshot->entries));
  return true;
}

uint64_t ct_shared_sequence(const ct_shared_channel *channel) {
  return owned(channel) ? channel->sequence : 0;
}

bool ct_shared_scan(ct_shared_channel *channel, uint32_t kind,
                    uint64_t upper_bound, uint64_t cursor,
                    ct_shared_scan_page *page) {
  if (!page || kind > CT_SHARED_DECOMPILE || cursor > upper_bound)
    return false;
  ct_shared_packet request = {}, response;
  request.operation = CT_SHARED_SCAN;
  request.key.kind = kind;
  request.token = upper_bound;
  request.cursor = cursor;
  int descriptor;
  if (!exchange(channel, &request, -1, &response, &descriptor))
    return false;
  if (descriptor >= 0)
    ct_shared_platform_close(descriptor);
  if (descriptor >= 0 || response.status != CT_SHARED_OK || response.error ||
      response.count > CT_SHARED_SNAPSHOT_CAPACITY || response.more > 1 ||
      (upper_bound && response.token != upper_bound) ||
      response.cursor < cursor || response.cursor > response.token ||
      (response.more &&
       (response.cursor == cursor || response.cursor == response.token)) ||
      (!response.more && response.cursor != response.token))
    return false;
  uint64_t previous = cursor;
  for (uint32_t index = 0; index < response.count; ++index) {
    const ct_shared_descriptor *object = &response.entries[index];
    if (!ct_shared_key_valid(&object->key) ||
        (kind && object->key.kind != kind) || object->object_id <= previous ||
        object->object_id > response.cursor || !object->sequence ||
        object->sequence > response.sequence)
      return false;
    previous = object->object_id;
  }
  memset(page, 0, sizeof(*page));
  page->upper_bound = response.token;
  page->cursor = response.cursor;
  page->sequence = response.sequence;
  page->count = response.count;
  page->more = response.more != 0;
  memcpy(page->entries, response.entries,
         response.count * sizeof(*page->entries));
  return true;
}

bool ct_shared_poll(ct_shared_channel *channel, int timeout_ms,
                    uint64_t *sequence) {
  if (!owned(channel) || !sequence || timeout_ms < -1)
    return false;
  // Availability hints are advisory. Bound one safe-point drain even while
  // another participant continuously publishes; unread hints remain queued.
  for (size_t hints = 0; hints < CT_SHARED_SNAPSHOT_CAPACITY; ++hints) {
    struct pollfd descriptor = {channel->fd, POLLIN, 0};
    const int ready = poll(&descriptor, 1, timeout_ms);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (!ready) {
      *sequence = channel->sequence;
      return true;
    }
    ct_shared_packet packet;
    int received;
    if (!(descriptor.revents & POLLIN) ||
        !receive_packet(channel, &packet, &received))
      return false;
    if (received >= 0)
      ct_shared_platform_close(received);
    if (packet.operation != CT_SHARED_NOTIFY || packet.request || received >= 0)
      return false;
    timeout_ms = 0;
  }
  *sequence = channel->sequence;
  return true;
}
