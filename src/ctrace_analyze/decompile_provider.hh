// SPDX-License-Identifier: MIT

#ifndef CTRACE_DECOMPILE_PROVIDER_H
#define CTRACE_DECOMPILE_PROVIDER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <poll.h>

#include "shared_objects.hh"

class ct_shared_broker;
struct ct_decompile_module;

/* The broker owns helper channels and starts one producer only on the first
 * request. No LLVM/Ghidra work executes in the process that forks helpers. */
class ct_decompile_broker {
  struct State;
  std::unique_ptr<State> state;

public:
  explicit ct_decompile_broker(ct_shared_broker &objects);
  ~ct_decompile_broker();
  bool worker_channel(int &descriptor, uint64_t &session);
  void worker_started(uint64_t session, int64_t process);
  void append_poll(std::vector<pollfd> &descriptors) const;
  void service(const std::vector<pollfd> &descriptors);
  void close_for_worker();
};

/* A consumer receives catalog identities, never JSON or owning Function trees.
 * The producer keeps publication references until its connection closes; the
 * consumer acquires its own references before reading the immutable views. */
bool ct_decompile_provider_request(int &connection, const char *path,
                                   int module_fd, uint64_t link_base,
                                   const std::string &analysis_identity,
                                   uint64_t offset, uint32_t level,
                                   ct_shared_key &common, ct_shared_key &full,
                                   std::string &error);

/* Only the dedicated producer calls this parser/export boundary. */
bool ct_decompile_produce(ct_decompile_module *module, uint64_t offset,
                          uint32_t level, std::vector<unsigned char> &common,
                          std::vector<unsigned char> &full,
                          std::string &identity, std::string &error);
const char *ct_decompile_producer_identity(ct_decompile_module *module);
bool ct_decompile_producer_manifest(ct_decompile_module *module,
                                    std::string &manifest, std::string &error);
// Dedicated pre-load producers close every backend before reporting FINISHED.
void ct_decompile_producer_shutdown();
// Borrowed private control socket; EOF/new data cancels an in-flight request.
// Kernel producers do not pipeline requests. Ordinary consumers leave -1.
void ct_decompile_producer_cancel_fd(int descriptor);
int ct_decompile_worker_event_fd();
void ct_decompile_service_worker();

#endif
