#ifndef CTRACE_THREAD_SUSPEND_SERVER_H
#define CTRACE_THREAD_SUSPEND_SERVER_H

#include <cstdint>
#include <memory>
#include <vector>

#include <dr_thread_suspend.h>

#include <poll.h>

// The family broker stays outside descendant PID namespaces. It retains task
// pidfds rather than interpreting a client's namespace-local PID or TID.
class ct_thread_suspend_broker {
  struct State;
  std::unique_ptr<State> state;

public:
  ct_thread_suspend_broker();
  ~ct_thread_suspend_broker();
  // Always consumes the received descriptors, including rejected requests.
  void connect(const dr_thread_suspend_request_t &request,
               std::vector<int> files, int64_t sender);
  void append_poll(std::vector<pollfd> &descriptors) const;
  void service(const std::vector<pollfd> &descriptors);
  void commit_exec(int64_t sender);
  void close_for_worker();
};

#endif
