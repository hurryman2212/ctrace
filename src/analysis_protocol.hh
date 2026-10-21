// SPDX-License-Identifier: MIT

#ifndef CTRACE_ANALYSIS_PROTOCOL_H
#define CTRACE_ANALYSIS_PROTOCOL_H

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <sys/socket.h>

#include "analysis.hh"
#include "contract.hh"

/* Native-ABI records are private to the same build on both socket endpoints.
 * Disk payloads additionally use the cache's exact executable/dependency key.
 */
#define CT_DECOMPILE_ERROR_CAPACITY 4096

/* Same-build records have large zero-filled fixed-capacity arrays. A bitmap
 * followed by the present 64-byte blocks preserves every byte, including ABI
 * padding, without copying empty capacity through the socket or disk cache.
 * The receiver knows the decoded size from its record type, never from input.
 */
static inline size_t ct_analysis_record_capacity(size_t size) {
  return size + ((size + 63) / 64 + 7) / 8;
}

static inline size_t ct_analysis_record_pack(unsigned char *wire,
                                             const void *record, size_t size) {
  const unsigned char zero[64] = {0};
  const unsigned char *source = (const unsigned char *)record;
  const size_t blocks = (size + 63) / 64;
  size_t position = (blocks + 7) / 8;
  memset(wire, 0, position);
  for (size_t index = 0; index < blocks; ++index) {
    const size_t offset = index * 64;
    const size_t count = size - offset < 64 ? size - offset : 64;
    if (memcmp(source + offset, zero, count) == 0)
      continue;
    wire[index / 8] |= 1u << (index % 8);
    memcpy(wire + position, source + offset, count);
    position += count;
  }
  return position;
}

static inline bool ct_analysis_record_valid(size_t size,
                                            const unsigned char *wire,
                                            size_t wire_size) {
  const size_t blocks = (size + 63) / 64;
  const size_t bitmap = (blocks + 7) / 8;
  if (wire_size < bitmap || wire_size > bitmap + size ||
      (blocks % 8 && (wire[bitmap - 1] & ~((1u << (blocks % 8)) - 1))))
    return false;
  // Validate the complete payload before exposing any part of the result.
  size_t expected = bitmap;
  for (size_t index = 0; index < blocks; ++index)
    if (wire[index / 8] & (1u << (index % 8))) {
      const size_t remaining = size - index * 64;
      expected += remaining < 64 ? remaining : 64;
    }
  if (expected != wire_size)
    return false;
  return true;
}

static inline bool ct_analysis_record_unpack(void *record, size_t size,
                                             const unsigned char *wire,
                                             size_t wire_size) {
  if (!ct_analysis_record_valid(size, wire, wire_size))
    return false;
  const size_t blocks = (size + 63) / 64;
  const size_t bitmap = (blocks + 7) / 8;
  memset(record, 0, size);
  unsigned char *target = (unsigned char *)record;
  size_t position = bitmap;
  for (size_t index = 0; index < blocks; ++index) {
    if (!(wire[index / 8] & (1u << (index % 8))))
      continue;
    const size_t offset = index * 64;
    const size_t count = size - offset < 64 ? size - offset : 64;
    memcpy(target + offset, wire + position, count);
    position += count;
  }
  return true;
}

/* Validate the complete original instruction cover before using decompiled
 * display information. This is shared by the producer and runtime consumer. */
static inline bool ct_decompiled_proof_valid(const unsigned char *data,
                                             size_t size) {
  if (!data || size < sizeof(ct_decompiled_proof_header))
    return false;
  ct_decompiled_proof_header header;
  memcpy(&header, data, sizeof(header));
  if (!header.range_count || !header.instruction_count ||
      header.loaded_level > CT_DECOMPILE_FULL || header.code_identity[64] ||
      header.range_count >
          (size - sizeof(header)) / sizeof(ct_decompiled_range))
    return false;
  const size_t remainder =
      size - sizeof(header) -
      size_t(header.range_count) * sizeof(ct_decompiled_range);
  if (remainder % sizeof(ct_decompiled_instruction) ||
      header.instruction_count != remainder / sizeof(ct_decompiled_instruction))
    return false;
  for (unsigned index = 0; index < 64; ++index)
    if (!((header.code_identity[index] >= '0' &&
           header.code_identity[index] <= '9') ||
          (header.code_identity[index] >= 'a' &&
           header.code_identity[index] <= 'f')))
      return false;
  const size_t instructions =
      sizeof(header) + header.range_count * sizeof(ct_decompiled_range);
  uint32_t instruction_index = 0;
  uint64_t previous_end = 0;
  bool contains_entry = false;
  for (uint32_t index = 0; index < header.range_count; ++index) {
    ct_decompiled_range range;
    memcpy(&range, data + sizeof(header) + index * sizeof(range),
           sizeof(range));
    if (range.begin >= range.end || (index && range.begin < previous_end))
      return false;
    contains_entry |= header.function_offset >= range.begin &&
                      header.function_offset < range.end;
    uint64_t cursor = range.begin;
    while (cursor < range.end) {
      if (instruction_index >= header.instruction_count)
        return false;
      ct_decompiled_instruction instruction;
      memcpy(&instruction,
             data + instructions + instruction_index++ * sizeof(instruction),
             sizeof(instruction));
      if (instruction.offset != cursor || !instruction.size ||
          instruction.size > sizeof(instruction.bytes) ||
          instruction.size > range.end - cursor)
        return false;
      cursor += instruction.size;
    }
    previous_end = range.end;
  }
  return contains_entry && instruction_index == header.instruction_count;
}

/* A shared inherited packet socket is used only for atomic broker requests.
 * Each analysis worker has its own stream; no response is read on this socket.
 */
enum ct_analysis_broker_operation {
  CT_ANALYSIS_BROKER_CONNECT,
  CT_ANALYSIS_BROKER_TRACE_EVENT,
  CT_ANALYSIS_BROKER_TRACE_FOOTER,
  CT_ANALYSIS_BROKER_TRACE_FLUSH,
  CT_ANALYSIS_BROKER_PREPARE_EXEC,
  CT_ANALYSIS_BROKER_EXEC_TIMESTAMPS,
  CT_ANALYSIS_BROKER_CANCEL_EXEC,
  CT_ANALYSIS_BROKER_OBJECT_CONNECT
};
enum { CT_ANALYSIS_BROKER_LIMIT = 128 * 1024 };
typedef struct ct_analysis_broker_packet {
  uint32_t operation;
  uint32_t size;
  uint64_t session;
  unsigned char contract[32];
} ct_analysis_broker_packet;

typedef struct ct_analysis_worker_handshake {
  uint64_t session;
  uint64_t trace_origin_ns;
  uint32_t recording_allowed;
  unsigned char contract[32];
} ct_analysis_worker_handshake;

/* Followed by count ct_exec_timestamp records from analysis.h. */
typedef struct ct_analysis_exec_header {
  uint32_t recording;
  uint32_t count;
} ct_analysis_exec_header;
typedef struct ct_analysis_exec_timestamps_header {
  uint64_t nonce;
  uint64_t count;
} ct_analysis_exec_timestamps_header;

enum ct_analysis_response_kind {
  CT_ANALYSIS_RESULT,
  CT_ANALYSIS_PROGRESS,
  CT_ANALYSIS_FILE
};
enum ct_analysis_file_operation {
  CT_ANALYSIS_FILE_READ,
  CT_ANALYSIS_FILE_STATUS,
  CT_ANALYSIS_FILE_CWD,
  CT_ANALYSIS_FILE_REALPATH
};
typedef struct ct_analysis_file_request {
  uint32_t operation;
  char path[4096];
} ct_analysis_file_request;
typedef struct ct_analysis_file_reply {
  int32_t error;
  uint32_t text_size;
} ct_analysis_file_reply;
typedef struct ct_analysis_response {
  uint32_t kind;
  uint32_t size;
} ct_analysis_response;

enum ct_analysis_operation {
  CT_ANALYSIS_OPEN,
  CT_ANALYSIS_LOOKUP,
  CT_ANALYSIS_ALLOWED,
  CT_ANALYSIS_ERROR,
  CT_ANALYSIS_FUNCTIONS,
  CT_ANALYSIS_CLOSE,
  CT_ANALYSIS_SYNTAX,
  CT_ANALYSIS_BYPASS,
  CT_ANALYSIS_DISASSEMBLE,
  CT_ANALYSIS_INLINE_SCOPES,
  CT_ANALYSIS_FLOW,
  CT_ANALYSIS_DECOMPILE,
  CT_ANALYSIS_DECOMPILE_VARIABLES,
  CT_ANALYSIS_DECOMPILE_ERROR,
  CT_ANALYSIS_CACHE_READ,
  CT_ANALYSIS_CACHE_WRITE,
  CT_ANALYSIS_CACHE_QUEUE,
  CT_ANALYSIS_OBSERVATION_BOUNDARIES,
  CT_ANALYSIS_LOOKUP_ARMING,
  CT_ANALYSIS_CACHE_DIGEST,
  CT_ANALYSIS_DECOMPILE_DISPLAY,
  CT_ANALYSIS_DECOMPILE_PROOF,
  CT_ANALYSIS_CODE_PROOF,
  CT_ANALYSIS_CONTENT_DIGEST,
  CT_ANALYSIS_RUNTIME_IDENTITY,
  CT_ANALYSIS_FILESYSTEM,
  CT_ANALYSIS_CODE_GRAPH,
  CT_ANALYSIS_LOOKUP_BATCH
};

typedef struct ct_analysis_request {
  uint32_t operation;
  uint32_t text_size;
  uint32_t maps_size;
  uint64_t handle;
  uint64_t offset;
} ct_analysis_request;

typedef struct ct_analysis_handle {
  uint64_t handle;
  bool has_dwarf;
  bool has_module_descriptor;
  bool has_debug_descriptor;
  bool has_supplement_descriptor;
  char debug_file[4096];
  char supplement_file[4096];
  char soname[4096];
  char identity[33];
  int64_t debug_bias_correction;
} ct_analysis_handle;

/* OPEN offset 0/1 performs initial discovery without/with a module FD.
 * Offset 2 replays this captured selection, followed by the present FDs in
 * module/debug/supplement order. Missing companions must remain missing. */
typedef struct ct_analysis_open_capture {
  uint32_t present;
  char debug_file[4096];
  char supplement_file[4096];
  char identity[33];
  int64_t debug_bias_correction;
} ct_analysis_open_capture;

enum ct_analysis_capture_file {
  CT_ANALYSIS_CAPTURE_MODULE = 1,
  CT_ANALYSIS_CAPTURE_DEBUG = 2,
  CT_ANALYSIS_CAPTURE_SUPPLEMENT = 4
};

typedef struct ct_analysis_function {
  uint64_t offset;
  char name[512];
} ct_analysis_function;

typedef struct ct_analysis_inline_scope {
  uint64_t begin_offset;
  uint64_t end_offset;
  char linkage_name[1024];
} ct_analysis_inline_scope;

typedef struct ct_analysis_flow_header {
  uint64_t begin_offset;
  uint64_t end_offset;
  uint32_t count;
  uint32_t region_count;
  uint32_t switch_count;
  bool valid;
  bool complete;
  bool bounded;
} ct_analysis_flow_header;

typedef struct ct_analysis_flow_boundary {
  uint64_t offset;
  uint64_t group_offset;
  uint32_t roles;
} ct_analysis_flow_boundary;

/* Each switch header is followed by exactly case_count ct_flow_case records;
 * the in-process vector is never copied into the socket stream. */
struct ct_analysis_flow_switch_header {
  uint64_t guard_offset;
  uint64_t dispatch_offset;
  uint64_t selector_offset;
  uint64_t join_offset;
  uint64_t default_offset;
  char selector_register[16];
  uint32_t case_count;
};

typedef struct ct_analysis_code_graph_header {
  ct_flow_range range;
  uint64_t entry_offset;
  uint32_t instruction_count;
  uint32_t edge_count;
  bool valid;
} ct_analysis_code_graph_header;

/* Both the helper's cached graph and the proxy reply use the same
 * pointer-free records. A frontier is never an executable successor. */
static inline bool ct_flow_graph_valid(const ct_flow_range *range,
                                       uint64_t entry_offset,
                                       const ct_flow_instruction *instructions,
                                       size_t instruction_count,
                                       const ct_flow_edge *edges,
                                       size_t edge_count) {
  if (!range || range->begin_offset >= range->end_offset || !instructions ||
      !instruction_count ||
      instruction_count > range->end_offset - range->begin_offset ||
      (edge_count && !edges))
    return false;
  size_t edge_index = 0;
  uint64_t previous_end = range->begin_offset;
  bool contains_entry = false;
  for (size_t index = 0; index < instruction_count; ++index) {
    const ct_flow_instruction *instruction = &instructions[index];
    const uint32_t flags = instruction->flags;
    if (instruction->offset < previous_end ||
        instruction->offset >= range->end_offset || !instruction->size ||
        instruction->size > sizeof(instruction->bytes) ||
        instruction->size > range->end_offset - instruction->offset ||
        (flags & ~(CT_FLOW_CALL | CT_FLOW_RETURN | CT_FLOW_BRANCH |
                   CT_FLOW_CONDITIONAL | CT_FLOW_SYSCALL | CT_FLOW_INDIRECT |
                   CT_FLOW_FRONTIER)) ||
        ((flags & CT_FLOW_CONDITIONAL) && !(flags & CT_FLOW_BRANCH)) ||
        ((flags & CT_FLOW_INDIRECT) &&
         !(flags & (CT_FLOW_CALL | CT_FLOW_BRANCH))) ||
        ((flags & CT_FLOW_RETURN) &&
         (flags & (CT_FLOW_CALL | CT_FLOW_BRANCH))) ||
        (range->complete && (flags & CT_FLOW_FRONTIER)))
      return false;
    previous_end = instruction->offset + instruction->size;
    contains_entry |= instruction->offset == entry_offset;
    const size_t first_edge = edge_index;
    bool frontier = false;
    uint64_t previous_target = 0;
    while (edge_index < edge_count &&
           edges[edge_index].from_offset == instruction->offset) {
      const uint64_t target = edges[edge_index].to_offset;
      if (edge_index > first_edge && target <= previous_target)
        return false;
      previous_target = target;
      bool decoded = false;
      if (target != UINT64_MAX) {
        size_t first = 0, last = instruction_count;
        while (first < last) {
          const size_t middle = first + (last - first) / 2;
          if (instructions[middle].offset < target)
            first = middle + 1;
          else
            last = middle;
        }
        decoded =
            first < instruction_count && instructions[first].offset == target;
      }
      frontier |= !decoded;
      if ((flags & CT_FLOW_CALL) && target != UINT64_MAX &&
          target != previous_end)
        return false;
      ++edge_index;
    }
    if ((flags & CT_FLOW_RETURN) ? edge_index != first_edge
                                 : edge_index == first_edge)
      return false;
    if (frontier != ((flags & CT_FLOW_FRONTIER) != 0))
      return false;
  }
  return contains_entry && edge_index == edge_count;
}

typedef struct ct_analysis_instruction {
  unsigned char bytes[15];
  unsigned char size;
} ct_analysis_instruction;

typedef struct ct_analysis_disassembly {
  bool valid;
  char att[1024];
  char intel[1024];
} ct_analysis_disassembly;

/* Entry-gate metadata excludes ct_location's large source/value payloads. */
typedef struct ct_arming_location {
  char file[4096];
  char function[512];
  char symbol[1024];
  char qualified_function[1024];
  char aliases[4096];
  uint32_t aliases_size;
  char scope_chain[4096];
  uint32_t scope_chain_size;
  char physical_aliases[4096];
  uint32_t physical_aliases_size;
  uint64_t line;
  uint64_t source_id;
  uint64_t function_id;
  uint32_t column;
  uint32_t discriminator;
  bool has_line;
  bool inlined;
  bool is_plt;
  char plt_symbol[1024];
} ct_arming_location;

static inline void ct_arming_location_pack(ct_arming_location *target,
                                           const ct_location *source) {
  memset(target, 0, sizeof(*target));
  memcpy(target->file, source->file, sizeof(target->file));
  memcpy(target->function, source->function, sizeof(target->function));
  memcpy(target->symbol, source->symbol, sizeof(target->symbol));
  memcpy(target->qualified_function, source->qualified_function,
         sizeof(target->qualified_function));
  memcpy(target->aliases, source->aliases, sizeof(target->aliases));
  target->aliases_size = source->aliases_size;
  memcpy(target->scope_chain, source->scope_chain, sizeof(target->scope_chain));
  target->scope_chain_size = source->scope_chain_size;
  memcpy(target->physical_aliases, source->physical_aliases,
         sizeof(target->physical_aliases));
  target->physical_aliases_size = source->physical_aliases_size;
  target->line = source->line;
  target->source_id = source->source_id;
  target->function_id = source->function_id;
  target->column = source->column;
  target->discriminator = source->discriminator;
  target->has_line = source->has_line;
  target->inlined = source->inlined;
  target->is_plt = source->is_plt;
  memcpy(target->plt_symbol, source->plt_symbol, sizeof(target->plt_symbol));
}

static inline void ct_arming_location_unpack(ct_location *target,
                                             const ct_arming_location *source) {
  memset(target, 0, sizeof(*target));
  memcpy(target->file, source->file, sizeof(source->file));
  memcpy(target->function, source->function, sizeof(source->function));
  memcpy(target->symbol, source->symbol, sizeof(source->symbol));
  memcpy(target->qualified_function, source->qualified_function,
         sizeof(source->qualified_function));
  memcpy(target->aliases, source->aliases, sizeof(source->aliases));
  target->aliases_size = source->aliases_size;
  memcpy(target->scope_chain, source->scope_chain, sizeof(source->scope_chain));
  target->scope_chain_size = source->scope_chain_size;
  memcpy(target->physical_aliases, source->physical_aliases,
         sizeof(source->physical_aliases));
  target->physical_aliases_size = source->physical_aliases_size;
  target->line = source->line;
  target->source_id = source->source_id;
  target->function_id = source->function_id;
  target->column = source->column;
  target->discriminator = source->discriminator;
  target->has_line = source->has_line;
  target->inlined = source->inlined;
  target->is_plt = source->is_plt;
  memcpy(target->plt_symbol, source->plt_symbol, sizeof(source->plt_symbol));
}

/* Bound both query work and packed staging memory, independently of the large
 * expanded location type. A response may cover only a nonempty prefix. */
enum {
  CT_LOCATION_BATCH_COUNT_LIMIT = 256,
  CT_LOCATION_BATCH_BYTE_LIMIT = 4 * 1024 * 1024
};
typedef struct ct_location_batch_header {
  unsigned char contract[32];
  uint32_t arming;
  uint32_t requested;
  uint32_t count;
  char key[65];
  unsigned char reserved[7];
} ct_location_batch_header;

typedef struct ct_location_batch_record {
  uint64_t offset;
  uint32_t size;
  uint32_t reserved;
} ct_location_batch_record;

static inline bool ct_location_batch_valid(const unsigned char *data,
                                           size_t size, const uint64_t *offsets,
                                           size_t count, bool arming,
                                           const char *key) {
  if (!data || !offsets || !count || count > CT_LOCATION_BATCH_COUNT_LIMIT ||
      size < sizeof(ct_location_batch_header) ||
      size > CT_LOCATION_BATCH_BYTE_LIMIT)
    return false;
  ct_location_batch_header header;
  memcpy(&header, data, sizeof(header));
  const unsigned char zero[sizeof(header.reserved)] = {0};
  if (!ct_contract_matches(header.contract) ||
      header.arming != (uint32_t)arming || header.requested != count ||
      !header.count || header.count > count || header.key[64] ||
      strspn(header.key, "0123456789abcdef") != 64 ||
      (key && strcmp(header.key, key)) ||
      memcmp(header.reserved, zero, sizeof(zero)))
    return false;
  for (size_t index = 1; index < count; ++index)
    if (offsets[index] <= offsets[index - 1])
      return false;
  size_t position = sizeof(header);
  for (uint32_t index = 0; index < header.count; ++index) {
    if (size - position < sizeof(ct_location_batch_record))
      return false;
    ct_location_batch_record record;
    memcpy(&record, data + position, sizeof(record));
    position += sizeof(record);
    if (record.offset != offsets[index] || record.reserved ||
        record.size > size - position ||
        !ct_analysis_record_valid(arming ? sizeof(ct_arming_location)
                                         : sizeof(ct_location),
                                  data + position, record.size))
      return false;
    position += record.size;
  }
  return position == size;
}

static inline bool ct_analysis_transfer(int fd, void *buffer, size_t size,
                                        bool sending) {
  char *cursor = (char *)buffer;
  while (size) {
    ssize_t count = sending ? send(fd, cursor, size, MSG_NOSIGNAL)
                            : recv(fd, cursor, size, 0);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    cursor += count;
    size -= (size_t)count;
  }
  return true;
}

#endif
