#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "shared_objects_host.h"
#include "shared_objects_platform.h"

static int broker_control = -1;
static uint64_t broker_session = 0;
static pid_t broker_owner = 0;

void ct_shared_host_init(int control, uint64_t session) {
  broker_control = control;
  broker_session = session;
  broker_owner = getpid();
}

bool ct_shared_host_available() {
  return broker_control >= 0 && broker_session && broker_owner == getpid();
}

bool ct_shared_host_connect(ct_shared_host_operation operation,
                            int descriptor) {
  if (!ct_shared_host_available() || descriptor < 0)
    return false;
  ct_shared_host_request request{operation, 0, broker_session};
  iovec vector{&request, sizeof(request)};
  union {
    cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(int))];
  } ancillary{};
  msghdr message{};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = ancillary.bytes;
  message.msg_controllen = sizeof(ancillary.bytes);
  auto *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  ssize_t count;
  do {
    count = sendmsg(broker_control, &message, MSG_NOSIGNAL);
  } while (count < 0 && errno == EINTR);
  return count == sizeof(request);
}

bool ct_shared_platform_adopt(int descriptor, bool inherit_fork) {
  const int flags = fcntl(descriptor, F_GETFD);
  return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0;
}

void ct_shared_platform_close(int descriptor) { close(descriptor); }

uint64_t ct_shared_platform_session(void) {
  return ct_shared_host_available() ? broker_session : 0;
}

bool ct_shared_platform_connect(int descriptor) {
  return ct_shared_host_connect(CT_SHARED_HOST_OBJECT_CONNECT, descriptor);
}
