#ifndef CTRACE_SHARED_OBJECTS_PROTOCOL_H
#define CTRACE_SHARED_OBJECTS_PROTOCOL_H

#include <string.h>

#include "shared_dr_batch.h"
#include "shared_objects.h"

enum { CT_SHARED_PROTOCOL = 1, CT_SHARED_OBJECT_LIMIT = 128 * 1024 * 1024 };

/* The envelope is pointer-free. The payload's own schema and relocation
 * semantics must additionally be validated by its execution/decompile reader.
 */
typedef struct ct_shared_envelope {
  char magic[8];
  uint32_t version;
  uint32_t header_size;
  ct_shared_key key;
  uint64_t payload_offset;
  uint64_t payload_size;
  unsigned char digest[32];
} ct_shared_envelope;

enum ct_shared_operation {
  CT_SHARED_HELLO = 1,
  CT_SHARED_ACQUIRE,
  CT_SHARED_PUBLISH,
  CT_SHARED_FAIL,
  CT_SHARED_WAIT_STATUS,
  CT_SHARED_CANCEL_WAIT,
  CT_SHARED_RELEASE,
  CT_SHARED_LIST,
  CT_SHARED_NOTIFY,
  CT_SHARED_FORK_RESERVE,
  CT_SHARED_FORK_CLAIM,
  CT_SHARED_FORK_RESERVE_SELECTED,
  CT_SHARED_SCAN,
  CT_SHARED_DR_MEMBER_ACQUIRE,
  CT_SHARED_DR_MEMBER_BIND,
  CT_SHARED_DR_MEMBER_SCAN,
  CT_SHARED_DR_MEMBER_BIND_AVAILABLE
};

typedef struct ct_shared_packet {
  uint32_t version;
  uint32_t operation;
  uint32_t status;
  uint32_t error;
  uint64_t request;
  uint64_t token;
  uint64_t sequence;
  uint64_t cursor;
  uint32_t count;
  uint32_t more;
  ct_shared_key key;
  ct_shared_descriptor object;
  ct_shared_descriptor entries[CT_SHARED_SNAPSHOT_CAPACITY];
} ct_shared_packet;

static inline bool ct_shared_key_valid(const ct_shared_key *key) {
  return key && key->kind >= CT_SHARED_USERSPACE_CODE &&
         key->kind <= CT_SHARED_DECOMPILE && key->schema && key->level <= 2 &&
         !key->reserved &&
         (key->kind != CT_SHARED_DECOMPILE || key->level != 0);
}

static inline bool ct_shared_envelope_valid(const ct_shared_envelope *header,
                                            uint64_t size) {
  return header && !memcmp(header->magic, "CTSHOBJ1", 8) &&
         header->version == CT_SHARED_PROTOCOL &&
         (header->header_size == sizeof(*header) ||
          (header->key.kind == CT_SHARED_DR_CODE &&
           header->key.schema == CT_SHARED_DR_COMPACT_SCHEMA &&
           header->header_size >=
               sizeof(*header) + sizeof(ct_shared_dr_compact_header) &&
           header->header_size <=
               sizeof(*header) + CT_SHARED_DR_COMPACT_LIMIT)) &&
         ct_shared_key_valid(&header->key) &&
         header->payload_offset >= header->header_size &&
         header->payload_offset <= CT_SHARED_OBJECT_LIMIT &&
         header->payload_size <=
             CT_SHARED_OBJECT_LIMIT - header->payload_offset &&
         size == header->payload_offset + header->payload_size;
}

#endif
