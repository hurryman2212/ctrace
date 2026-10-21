// SPDX-License-Identifier: MIT

#ifndef CTRACE_EXECUTION_CACHE_H
#define CTRACE_EXECUTION_CACHE_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "instrumentation.hh"

struct ct_execution_instruction {
  uint64_t offset = 0;
  uint8_t length = 0;
  uint8_t bytes[15]{};
};

struct ct_execution_recipe {
  bool quiet_transfer = false;
  bool inline_scope = false;
  // An inline entry/exit boundary, independent of the instruction's position
  // in the current DR block. The block's first-instruction flag stays dynamic.
  bool scope_boundary = false;
  bool perfetto_boundary = false;
  // True unless a source/decompiler plan proves that no snapshot is needed.
  bool full_observation = true;
};

// Level indexes reference a common original-instruction object; changing the
// initial preparation level does not duplicate its bytes. The policy contains
// only options affecting classification, never the initial level or output
// sink. Reuses instruction classifications, never executable DR fragments or
// live pointers. The caller supplies the complete original bytes,
// module-relative offsets, module/debug identity, and every option affecting
// classification. The helper also fingerprints the client, analyzer, and
// selected DR runtime. Build fresh DR instructions, clean calls, TLS operands,
// and thread state even on a hit. The caller owns the per-module recipe table
// and its synchronization.
bool ct_execution_cache_load(
    const std::string &identity, const std::string &policy,
    ct_instrument_level level, uint64_t module_size,
    const std::vector<ct_execution_instruction> &instructions,
    std::vector<ct_execution_recipe> &recipes);
bool ct_execution_cache_store(
    const std::string &identity, const std::string &policy,
    ct_instrument_level level, uint64_t module_size,
    const std::vector<ct_execution_instruction> &instructions,
    const std::vector<ct_execution_recipe> &recipes);

// Initial preparation packs exact BB classifications into one bounded index.
// The common original image is shared across levels; entries still bind the
// complete BB image and policy, including first-instruction scope boundaries.
// This object belongs to one preparation request and is discarded on cancel.
struct ct_execution_batch {
  struct Entry {
    std::vector<uint32_t> instructions;
    std::vector<uint8_t> flags;
  };
  std::vector<ct_execution_instruction> instructions;
  std::map<std::string, Entry> entries;
  std::vector<unsigned char> image;
  std::string kind, key, object;
  char index_digest[65]{};
  ct_instrument_level level = ct_instrument_level::arm;
  size_t encoded_size = 0;
  bool dirty = false;
};

// True means batching is enabled, including an ordinary disk miss. Oversized
// images return false so their caller retains the existing per-BB cache path.
bool ct_execution_batch_open(const std::string &identity,
                             const std::string &policy,
                             ct_instrument_level level, uint64_t module_size,
                             std::vector<ct_execution_instruction> instructions,
                             ct_execution_batch &batch);
bool ct_execution_batch_lookup(
    const ct_execution_batch &batch, const std::string &key,
    const std::vector<ct_execution_instruction> &instructions,
    std::vector<ct_execution_recipe> &recipes);
// False means this entry must use the existing per-BB store instead. Previously
// collected entries remain available for publication within the same bound.
bool ct_execution_batch_collect(
    ct_execution_batch &batch, const std::string &key,
    const std::vector<ct_execution_instruction> &instructions,
    const std::vector<ct_execution_recipe> &recipes);
// Call only after the request's final byte/generation proof reports READY.
bool ct_execution_batch_store(const ct_execution_batch &batch);

#endif
