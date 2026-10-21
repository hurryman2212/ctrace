// SPDX-License-Identifier: MIT

#ifndef CTRACE_SHARED_OBJECTS_SERVER_H
#define CTRACE_SHARED_OBJECTS_SERVER_H

#include <cstdint>
#include <memory>
#include <vector>

#include <poll.h>

class ct_shared_broker {
  struct State;
  std::unique_ptr<State> state;

public:
  ct_shared_broker();
  ~ct_shared_broker();
  /* Takes ownership of fd on success; credentials use the broker's namespace.
   */
  bool connect(int fd, int64_t process, uint64_t session);
  void close_session(uint64_t session);
  void append_poll(std::vector<pollfd> &descriptors) const;
  void service(const std::vector<pollfd> &descriptors);
  bool validating() const;
  void close_for_worker();
};

#endif
