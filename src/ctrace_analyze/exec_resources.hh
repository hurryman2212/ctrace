// SPDX-License-Identifier: MIT

#ifndef CTRACE_EXEC_RESOURCES_H
#define CTRACE_EXEC_RESOURCES_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <dr_exec_resources.h>

// Pending exec owns only descriptor references and an immutable metadata view.
// Library bytes remain in the original file backing; GET sends new references.
class ct_exec_resources {
  std::vector<int> descriptors;
  void *mapping = nullptr;
  size_t size = 0;
  int owner = -1;
  explicit ct_exec_resources(std::vector<int> files);
  bool validate(uint32_t count, uint64_t expected_size);

public:
  ~ct_exec_resources();
  ct_exec_resources(const ct_exec_resources &) = delete;
  ct_exec_resources &operator=(const ct_exec_resources &) = delete;
  static std::unique_ptr<ct_exec_resources>
  accept(std::vector<int> files, uint32_t count, uint64_t expected_size,
         int reply_socket, int64_t sender);
  int liveness_descriptor() const { return owner; }
  bool send(int socket, uint64_t nonce) const;
};

bool ct_exec_resource_reply(int socket, const dr_exec_resource_reply_t &reply,
                            const std::vector<int> &files = {});

#endif
