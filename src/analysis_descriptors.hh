// SPDX-License-Identifier: MIT

#ifndef CTRACE_ANALYSIS_DESCRIPTORS_H
#define CTRACE_ANALYSIS_DESCRIPTORS_H

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

/* Only newly created/received owned descriptors use this helper. Borrowed
 * caller descriptors retain their numbers. This removes persistent standard
 * FD occupation; creation and relocation are not one atomic kernel operation.
 */
static inline int ct_analysis_relocate_owned_descriptor(int descriptor) {
  if (descriptor < 0 || descriptor > 2)
    return descriptor;
  int moved;
  do {
    moved = fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
  } while (moved < 0 && errno == EINTR);
  const int error = errno;
  close(descriptor);
  if (moved < 0)
    errno = error;
  return moved;
}

static inline bool ct_analysis_create_pair(int sockets[2]) {
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0)
    return false;
  for (size_t index = 0; index < 2; ++index)
    sockets[index] = ct_analysis_relocate_owned_descriptor(sockets[index]);
  if (sockets[0] >= 0 && sockets[1] >= 0)
    return true;
  const int error = errno;
  for (size_t index = 0; index < 2; ++index)
    if (sockets[index] >= 0) {
      close(sockets[index]);
      sockets[index] = -1;
    }
  errno = error;
  return false;
}

/* One explicitly framed stream byte carries exactly one borrowed descriptor.
 * Callers serialize these messages with the surrounding analysis request. */
static inline bool ct_analysis_send_descriptor(int stream, int descriptor) {
  if (stream < 0 || descriptor < 0)
    return false;
  unsigned char marker = 1;
  struct iovec vector = {&marker, sizeof(marker)};
  union {
    struct cmsghdr alignment;
    unsigned char bytes[CMSG_SPACE(sizeof(int))];
  } ancillary;
  memset(&ancillary, 0, sizeof(ancillary));
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = ancillary.bytes;
  message.msg_controllen = sizeof(ancillary.bytes);
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  ssize_t sent;
  do {
    sent = sendmsg(stream, &message, MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);
  return sent == sizeof(marker);
}

/* The recipient owns the returned CLOEXEC descriptor. Reject malformed frames
 * and close every received descriptor on failure, including truncated lists. */
static inline int ct_analysis_receive_descriptor(int stream) {
  unsigned char marker = 0;
  struct iovec vector = {&marker, sizeof(marker)};
  union {
    struct cmsghdr alignment;
    unsigned char bytes[CMSG_SPACE(4 * sizeof(int))];
  } ancillary;
  struct msghdr message;
  ssize_t received;
  do {
    memset(&message, 0, sizeof(message));
    memset(&ancillary, 0, sizeof(ancillary));
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes;
    message.msg_controllen = sizeof(ancillary.bytes);
    received = recvmsg(stream, &message, MSG_CMSG_CLOEXEC);
  } while (received < 0 && errno == EINTR);
  int result = -1;
  bool valid = received == sizeof(marker) && marker == 1 &&
               !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
  size_t count = 0;
  for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(0)) {
      valid = false;
      continue;
    }
    const size_t bytes = header->cmsg_len - CMSG_LEN(0);
    if (bytes % sizeof(int))
      valid = false;
    for (size_t offset = 0; offset + sizeof(int) <= bytes;
         offset += sizeof(int)) {
      int descriptor;
      memcpy(&descriptor, (unsigned char *)CMSG_DATA(header) + offset,
             sizeof(descriptor));
      if (count++ == 0)
        result = descriptor;
      else
        close(descriptor);
    }
  }
  if (!valid || count != 1) {
    if (result >= 0)
      close(result);
    return -1;
  }
  return ct_analysis_relocate_owned_descriptor(result);
}

#endif
