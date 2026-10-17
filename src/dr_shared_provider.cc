#include <algorithm>
#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include <dr_api.h>
#include <drmgr.h>

#include <sys/syscall.h>
#include <unistd.h>

#include "dr_shared_provider.h"
#include "output.h"
#include "shared_dr_batch.h"
#include "shared_objects_platform.h"
#include "shared_objects_protocol.h"

// Bound temporary generation data across the entire image, not per tag or
// thread. Already adopted code retains only its small ownership token.
static constexpr size_t pending_limit = 64 * 1024;
static constexpr size_t pending_body_overhead = 192;
static constexpr size_t ready_limit = 64;
static_assert(ready_limit <= 64);
static constexpr size_t observed_limit = 64 * 1024;
static constexpr uint64_t pending_age_us = 100000;
static constexpr uint32_t service_check_interval = 256;
static constexpr uint64_t recovery_sweep_interval_us = 1000000;

using Digest = std::array<unsigned char, 32>;

struct SharedDRWork {
  ct_shared_key key{};
  Digest source{}, provenance{}, body{};
  app_pc tag = nullptr;
  uint64_t incarnation = 0, generation = 0;
  size_t original_private = 0, retained_private = 0, private_allocation = 0;
  bool replay_available = false;
  uint32_t emission_id = 0;
  size_t retained_code = 0;
};

struct SharedDRAvailability {
  bool current;
  dr_shared_fragment_rebind_status_t status;
};

struct SharedDRDemand {
  std::atomic<app_pc> tag{nullptr};
  std::atomic<uint64_t> sequence{0};
  uint64_t seen = 0; // Only the serialized service owner consumes a sequence.
};

enum class SharedDRRecovery { complete, staged, retry };

struct SharedDRProof {
  uint32_t magic = 0x43544452, version = 2;
  Digest source{};
  uint64_t incarnation = 0, generation = 0;
  uint32_t level = 0, reserved = 0;
};
static_assert(sizeof(SharedDRProof) == 64);

struct SharedDRPending {
  Digest body{};
  uint32_t isa = 0;
  size_t code_size = 0;
  size_t private_size = 0;
  uint64_t updated = 0;
  size_t replay_ready = 0;
  bool replay_busy = false;
  std::vector<byte> code;
  std::vector<ct_shared_dr_relocation> relocations;
  std::vector<SharedDRWork> work;
};

struct SharedDRLayout {
  size_t original = 0, retained = 0, working = 0, bindings = 0;
  size_t retained_code = 0, execution = SIZE_MAX;
  size_t rows = 0, mappings = 0, members = 0, rx = 0, private_size = 0,
         index = 0, steady = SIZE_MAX, staging = 0;
};

struct SharedDRBacking {
  uint64_t object = 0, file_offset = 0, code_size = 0;
  byte *metadata = nullptr;
  byte *code = nullptr;
  size_t metadata_size = 0, references = 0;
  const ct_shared_dr_compact_header *header = nullptr;
  const ct_shared_dr_compact_member *members = nullptr;
  std::vector<uint32_t> occupied;
  struct Reservation {
    size_t instance;
    uint64_t occupied;
  };
  std::vector<Reservation> reservations;
};

struct SharedDRToken {
  SharedDRToken *previous = nullptr, *next = nullptr, *retired_next = nullptr;
  SharedDRBacking *backing = nullptr;
  uint64_t process = 0, session = 0, created = 0;
  int fd = -1;
  uint32_t slot = UINT32_MAX;
  size_t private_instance = 0;
  Digest source_key{};
  app_pc tag = nullptr;
  uint64_t incarnation = 0, generation = 0;
  std::atomic<bool> adopted{false}, retired{false};
  bool fork_pinned = false;
  uint32_t emission_id = 0;
};

using SharedDRReady = std::multimap<Digest, SharedDRToken *>;

struct SharedDRAlias {
  ct_shared_key key{};
  Digest provenance{}, body{};
  app_pc tag = nullptr;
  uint64_t incarnation = 0, generation = 0, object = 0;
};

struct SharedDRChannel {
  SharedDRChannel *next = nullptr;
  void *context = nullptr;
  ct_shared_channel *channel = nullptr;
};

struct SharedDRProvider {
  void *lock = nullptr;
  int tls = -1;
  ptr_uint_t note = DRMGR_NOTE_NONE;
  uint64_t process = 0, session = 0;
  void *fork_context = nullptr;
  bool fork_pending = false;
  ct_dr_shared_current current = nullptr;
  ct_dr_shared_current_try current_try = nullptr;
  std::atomic<bool> servicing{false}, has_work{false}, stopping{false};
  std::atomic<uint32_t> service_checks{0};
  std::atomic<uint64_t> next_service{0};
  std::atomic<uint64_t> anchor_revision{0};
  size_t pending_bytes = 0;
  bool statistics = false;
  bool candidate_statistics = false;
  bool packing = true;
  size_t next_private_instance = 1;
  std::atomic<uint64_t> requests{0}, queued{0}, offers{0}, adopted{0};
  std::atomic<uint64_t> rejected_private{0};
  uint64_t published = 0, rejected_cost = 0, original_bytes = 0,
           retained_bytes = 0;
  uint64_t rejected_original = 0, rejected_retained = 0;
  uint64_t largest_original = 0, largest_cost = 0, largest_count = 0;
  uint64_t largest_rx = 0, largest_private = 0, largest_retained = 0,
           largest_pending = 0;
  uint64_t largest_rows = 0, largest_members = 0, largest_body_types = 0,
           largest_index = 0, largest_working = 0, largest_code = 0,
           largest_binding_extent = 0, largest_steady = 0,
           largest_replacement_peak = 0;
  size_t recipe_slot = 0, recipe_storage = 0, recipe_live = 0;
  uint64_t promotion_requests = 0, promotion_failures = 0;
  size_t service_offers = 0;
  std::array<SharedDRDemand, ready_limit> demands;
  std::atomic<size_t> demand_overwrite{0};
  std::atomic<bool> demand_pending{false};
  size_t demand_cursor = 0;
  uint64_t reconstruction_attempts = 0, reconstruction_staged = 0,
           reconstruction_mismatch = 0;
  std::map<Digest, std::unique_ptr<SharedDRPending>> pending;
  std::map<Digest, std::unique_ptr<SharedDRPending>> in_flight;
  SharedDRReady ready;
  std::vector<SharedDRReady::node_type> consumed_ready_nodes;
  std::vector<SharedDRAlias> aliases, aliases_in_flight;
  std::map<uint64_t, std::unique_ptr<SharedDRBacking>> backings;
  std::vector<SharedDRWork> observed;
  std::vector<SharedDRWork> discovery_observations;
  std::vector<SharedDRAvailability> discovery_current;
  SharedDRWork recent_resume;
  uint64_t observed_revision = 0, scanned_revision = 0, scanned_sequence = 0;
  uint64_t scan_revision = 0, scan_sequence = 0;
  uint64_t scan_anchor_revision = 0, scanned_anchor_revision = 0;
  uint64_t next_recovery_sweep = 0;
  size_t anchor_cursor = 0;
  std::array<dr_shared_fragment_snapshot_t, ready_limit> recovery_snapshots{};
  size_t recovery_count = 0, recovery_cursor = 0;
  byte *recovery_buffer = nullptr;
  bool scanning = false, discovery_retry = false;
  SharedDRToken *tokens = nullptr;
  std::atomic<SharedDRToken *> retired{nullptr};
  SharedDRChannel *channels = nullptr;
  std::vector<byte> batch_code;
  std::vector<ct_shared_dr_compact_member> batch_members;
  std::vector<ct_shared_dr_relocation> batch_relocations;
  std::vector<byte> batch_index;
  std::vector<SharedDRPending *> batch_bodies;
  std::vector<size_t> batch_bindings, batch_best_placements;
};

static SharedDRProvider provider;

static void release_backing_mappings(SharedDRBacking &backing) {
  if (backing.code && !dr_unmap_file(backing.code, backing.code_size))
    dr_abort_with_code(1);
  if (backing.metadata &&
      !dr_unmap_file(backing.metadata, backing.metadata_size))
    dr_abort_with_code(1);
  backing.code = backing.metadata = nullptr;
}

static bool current_image() {
  return provider.session &&
         provider.process == static_cast<uint64_t>(syscall(SYS_getpid)) &&
         provider.session == ct_shared_platform_session();
}

static bool regular_fork_child() {
  return provider.fork_pending &&
         provider.fork_context == dr_get_current_drcontext();
}

static void queue_retired(SharedDRToken *token) {
  SharedDRToken *head = provider.retired.load(std::memory_order_relaxed);
  do {
    token->retired_next = head;
  } while (!provider.retired.compare_exchange_weak(
      head, token, std::memory_order_release, std::memory_order_relaxed));
  provider.has_work.store(true, std::memory_order_release);
}

static void file_finished(void *context, void *opaque, bool adopted) {
  auto *token = static_cast<SharedDRToken *>(opaque);
  if (!token || !current_image())
    return;
  // This store precedes closing the borrowed FD or entering any safe wait.
  // A regular-fork snapshot must see every installed execution view.
  token->adopted.store(adopted, std::memory_order_release);
  if (adopted)
    provider.adopted.fetch_add(1, std::memory_order_relaxed);
  ct_shared_result descriptor{};
  descriptor.fd = token->fd;
  descriptor.owner_process = token->process;
  descriptor.owner_session = token->session;
  if (ct_shared_result_close(&descriptor))
    token->fd = -1;
  if (!adopted) {
    token->retired.store(true, std::memory_order_release);
    queue_retired(token);
  }
}

static void retired(void *context, void *opaque) {
  auto *token = static_cast<SharedDRToken *>(opaque);
  if (!token || ((token->session != provider.session ||
                  token->process != provider.process) &&
                 !regular_fork_child()))
    return;
  // A CLONE_VM child may share the execution view while using a separate FD
  // table. Its retirement only queues this image's token; the owner process
  // performs descriptor/catalog operations. A regular fork can likewise retire
  // vanished-thread views before its new session claims the inherited pins.
  if (!token->retired.exchange(true, std::memory_order_acq_rel))
    queue_retired(token);
}

static ct_shared_channel *channel_for(void *context) {
  auto *holder = static_cast<SharedDRChannel *>(
      drmgr_get_tls_field(context, provider.tls));
  if (!holder) {
    auto created = std::make_unique<SharedDRChannel>();
    created->context = context;
    dr_mutex_lock(provider.lock);
    created->next = provider.channels;
    provider.channels = created.get();
    holder = created.release();
    drmgr_set_tls_field(context, provider.tls, holder);
    dr_mutex_unlock(provider.lock);
  }
  if (!holder->channel)
    holder->channel = ct_shared_open();
  return holder->channel;
}

static void release_retired(ct_shared_channel *channel) {
  SharedDRToken *token =
      provider.retired.exchange(nullptr, std::memory_order_acquire);
  while (token) {
    SharedDRToken *next = token->retired_next;
    ct_shared_result descriptor{};
    descriptor.fd = token->fd;
    descriptor.owner_process = token->process;
    descriptor.owner_session = token->session;
    ct_shared_result_close(&descriptor);
    const uint64_t object = token->backing->object;
    std::unique_ptr<SharedDRBacking> released;
    dr_mutex_lock(provider.lock);
    ++provider.observed_revision;
    if (token->previous)
      token->previous->next = token->next;
    else
      provider.tokens = token->next;
    if (token->next)
      token->next->previous = token->previous;
    auto &backing = *token->backing;
    if (token->slot != UINT32_MAX && backing.occupied[token->slot]) {
      --backing.occupied[token->slot];
      for (auto row = backing.reservations.begin();
           row != backing.reservations.end(); ++row) {
        if (row->instance == token->private_instance) {
          row->occupied &= ~(uint64_t(1) << token->slot);
          if (!row->occupied)
            backing.reservations.erase(row);
          break;
        }
      }
    }
    if (!--backing.references) {
      auto found = provider.backings.find(object);
      released = std::move(found->second);
      provider.backings.erase(found);
    }
    dr_mutex_unlock(provider.lock);
    if (released)
      release_backing_mappings(*released);
    // Drop image-local allocations before an IPC can become a fork-safe wait.
    // A vanished parent's service stack must not hide them from child cleanup.
    delete token;
    released.reset();
    // A failed channel may already have acknowledged the decrement. Never
    // retry it; process-image session teardown cleans any remaining reference.
    if (channel)
      ct_shared_release(channel, object);
    token = next;
  }
}

static SharedDRBacking *
load_backing(const ct_shared_result &result,
             std::unique_ptr<SharedDRBacking> &created) {
  const auto &object = result.object;
  SharedDRBacking *backing = nullptr;
  dr_mutex_lock(provider.lock);
  const auto known = provider.backings.find(object.object_id);
  if (known != provider.backings.end())
    backing = known->second.get();
  dr_mutex_unlock(provider.lock);
  if (!backing) {
    if (object.key.kind != CT_SHARED_DR_CODE ||
        object.key.schema != CT_SHARED_DR_COMPACT_SCHEMA || object.key.level ||
        !object.payload_offset || object.payload_offset % dr_page_size() ||
        object.payload_offset > CT_SHARED_DR_COMPACT_LIMIT + dr_page_size() ||
        !object.payload_size ||
        object.payload_size > CT_SHARED_DR_COMPACT_LIMIT)
      return nullptr;
    created = std::make_unique<SharedDRBacking>();
    created->object = object.object_id;
    created->file_offset = object.payload_offset;
    created->code_size = object.payload_size;
    created->metadata_size = object.payload_offset;
    created->metadata = static_cast<byte *>(dr_map_file(
        result.fd, &created->metadata_size, 0, nullptr, DR_MEMPROT_READ, 0));
    if (!created->metadata)
      return nullptr;
    const auto *envelope =
        reinterpret_cast<const ct_shared_envelope *>(created->metadata);
    created->header = reinterpret_cast<const ct_shared_dr_compact_header *>(
        created->metadata + sizeof(*envelope));
    const auto &header = *created->header;
    bool valid =
        created->metadata_size == object.payload_offset &&
        ct_shared_envelope_valid(envelope,
                                 object.payload_offset + object.payload_size) &&
        envelope->header_size <= created->metadata_size &&
        !std::memcmp(&envelope->key, &object.key, sizeof(object.key)) &&
        !std::memcmp(envelope->digest, object.digest, 32) &&
        !std::memcmp(header.magic, "CTDRCMP1", 8) && header.version == 1 &&
        header.count && header.count <= ready_limit &&
        header.code_size == object.payload_size &&
        header.count <=
            (created->metadata_size - sizeof(*envelope) - sizeof(header)) /
                sizeof(ct_shared_dr_compact_member) &&
        envelope->header_size ==
            sizeof(*envelope) + sizeof(header) +
                header.count * sizeof(ct_shared_dr_compact_member) +
                uint64_t(header.relocation_count) *
                    sizeof(ct_shared_dr_relocation);
    size_t mapped_size = object.payload_size;
    byte *mapped = valid ? static_cast<byte *>(dr_map_file(
                               result.fd, &mapped_size, object.payload_offset,
                               nullptr, DR_MEMPROT_READ, 0))
                         : nullptr;
    valid = mapped && mapped_size == object.payload_size &&
            ct_shared_dr_compact_validate(
                created->header, envelope->header_size - sizeof(*envelope),
                mapped, mapped_size);
    if (!valid) {
      if (mapped && !dr_unmap_file(mapped, mapped_size))
        dr_abort_with_code(1);
      if (!dr_unmap_file(created->metadata, created->metadata_size))
        dr_abort_with_code(1);
      created->metadata = nullptr;
      return nullptr;
    }
    created->code = mapped;
    created->members = reinterpret_cast<const ct_shared_dr_compact_member *>(
        created->metadata + sizeof(*envelope) + sizeof(header));
    created->occupied.resize(header.count);
    backing = created.get();
  }
  return backing;
}

// Report per-view metadata even when another participant owns the RX/index
// backing. These telemetry charges do not decide executable-byte admission.
static size_t retained_work_cost(const SharedDRWork &work) {
  constexpr size_t metadata = sizeof(SharedDRToken) + sizeof(ct_shared_key) +
                              sizeof(SharedDRAlias) + sizeof(SharedDRWork) +
                              pending_body_overhead;
  return work.retained_private > SIZE_MAX - metadata
             ? SIZE_MAX
             : work.retained_private + metadata;
}

// Admission compares executable storage. Bookkeeping and staging remain in
// the separate memory telemetry and never veto a smaller executable image.
static size_t execution_cost(size_t retained_code, size_t shared_rx,
                             size_t private_bytes, size_t mappings) {
  return retained_code + shared_rx + mappings * private_bytes;
}

static bool same_work(const SharedDRWork &left, const SharedDRWork &right) {
  return left.tag == right.tag && left.source == right.source &&
         left.emission_id == right.emission_id &&
         left.incarnation == right.incarnation &&
         left.generation == right.generation &&
         !std::memcmp(&left.key, &right.key, sizeof(left.key));
}

static size_t pending_cost(const SharedDRPending &body) {
  return sizeof(body) + body.code.capacity() +
         body.relocations.capacity() * sizeof(ct_shared_dr_relocation) +
         body.work.capacity() * sizeof(SharedDRWork) + pending_body_overhead;
}

static SharedDRLayout
evaluate_batch(const std::vector<SharedDRPending *> &bodies,
               const std::vector<size_t> &bindings, size_t page, bool packing) {
  SharedDRLayout best;
  size_t maximum_rows = 0;
  for (size_t i = 0; i < bodies.size(); ++i) {
    const auto &body = *bodies[i];
    best.bindings += bindings[i];
    best.working += pending_cost(body);
    maximum_rows = std::max(maximum_rows, bindings[i]);
    for (size_t j = 0; j < bindings[i]; ++j) {
      best.original += body.work[j].original_private;
      best.retained += retained_work_cost(body.work[j]);
      best.retained_code += body.work[j].retained_code;
    }
  }
  if (!maximum_rows) {
    best.steady = 0;
    best.execution = 0;
    return best;
  }
  // For fixed rows, ceil(bindings/rows) is the minimum placement count per
  // body. More placements only grow RX, private and metadata storage. Search
  // all feasible layouts while keeping every selected eligible body. A first
  // publication must not depend on another local copy already existing.
  for (size_t rows = 1; rows <= maximum_rows; ++rows) {
    size_t mappings = 0, members = 0, rx_end = 0, private_end = 0,
           relocation_count = 0;
    for (size_t i = 0; i < bodies.size(); ++i) {
      const auto &body = *bodies[i];
      const size_t placements = packing ? (bindings[i] + rows - 1) / rows : 1;
      mappings =
          std::max(mappings, (bindings[i] + placements - 1) / placements);
      members += placements;
      rx_end += placements * ((body.code.size() + 15) & ~size_t(15));
      private_end += placements * ((body.private_size + 15) & ~size_t(15));
      relocation_count += placements * body.relocations.size();
    }
    const size_t rx = (rx_end + page - 1) / page * page;
    const size_t private_bytes = (private_end + page - 1) / page * page;
    const size_t index = sizeof(ct_shared_dr_compact_header) +
                         members * sizeof(ct_shared_dr_compact_member) +
                         relocation_count * sizeof(ct_shared_dr_relocation);
    if (members > ready_limit || rx > pending_limit ||
        private_bytes > pending_limit || index > pending_limit)
      continue;
    const size_t metadata =
        (sizeof(ct_shared_envelope) + index + page - 1) / page * page;
    const size_t steady = rx + metadata + mappings * private_bytes +
                          best.retained + sizeof(SharedDRBacking) +
                          members * sizeof(uint32_t) +
                          mappings * ((rx + private_bytes) / 128 + page) + page;
    const size_t execution =
        execution_cost(best.retained_code, rx, private_bytes, mappings);
    // Templates and assembly buffers are released after publication. Account
    // for their preparation peak separately from steady resident admission.
    const size_t staging = best.working + rx + index +
                           members * sizeof(ct_shared_dr_compact_member) +
                           relocation_count * sizeof(ct_shared_dr_relocation);
    if (execution < best.execution ||
        (execution == best.execution &&
         (steady < best.steady ||
          (steady == best.steady && staging < best.staging)))) {
      best.rows = rows;
      best.mappings = mappings;
      best.members = members;
      best.rx = rx;
      best.private_size = private_bytes;
      best.index = index;
      best.steady = steady;
      best.staging = staging;
      best.execution = execution;
    }
  }
  return best;
}

// Safe-service snapshot only: neither this check nor a catalog grant pins the
// fragment. The core rechecks its exact recipe serial before adoption.
static dr_shared_fragment_rebind_status_t
replay_status(const SharedDRWork &work) {
  if (!provider.current(work.tag, work.incarnation, work.generation))
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
  SharedDRProof proof;
  proof.source = work.source;
  proof.incarnation = work.incarnation;
  proof.generation = work.generation;
  proof.level = work.key.level;
  return dr_shared_fragment_rebind_available(
      work.tag, reinterpret_cast<const byte *>(&proof), work.emission_id);
}

static dr_shared_fragment_rebind_status_t
validate_candidate(const SharedDRWork &work, byte *code, size_t size,
                   size_t private_base) {
  if (!provider.current(work.tag, work.incarnation, work.generation))
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
  SharedDRProof proof;
  proof.source = work.source;
  proof.incarnation = work.incarnation;
  proof.generation = work.generation;
  proof.level = work.key.level;
  dr_shared_fragment_restore_t restore{};
  restore.struct_size = sizeof(restore);
  restore.buffer = code;
  restore.capacity = restore.content_size = size;
  restore.private_base = private_base;
  return dr_shared_fragment_rebind_validate(
      work.tag, work.emission_id, reinterpret_cast<const byte *>(&proof),
      work.body.data(), &restore);
}

// Both sealed catalog members and this service's immutable pending prototype
// must match the exact original byte spans before receiving admission credit.
static dr_shared_fragment_rebind_status_t
validate_member(const SharedDRWork &work, const SharedDRBacking &backing) {
  for (uint32_t index = 0; index < backing.header->count; ++index) {
    const auto &member = backing.members[index];
    if (std::memcmp(member.identity, work.body.data(), work.body.size()))
      continue;
    return validate_candidate(work, backing.code + member.offset, member.size,
                              backing.code_size + member.private_offset -
                                  member.offset);
  }
  return DR_SHARED_FRAGMENT_REBIND_ABSENT;
}

static bool prepare_ready(const SharedDRWork &work,
                          ct_shared_dr_member_result &result,
                          ct_shared_channel *channel) {
  if (provider.servicing.load(std::memory_order_relaxed) &&
      provider.service_offers == ready_limit)
    return false;
  const auto status = replay_status(work);
  if (status != DR_SHARED_FRAGMENT_REBIND_AVAILABLE &&
      status != DR_SHARED_FRAGMENT_REBIND_RESTORABLE)
    return false;
  const auto &object = result.result.object;
  std::unique_ptr<SharedDRBacking> created;
  SharedDRBacking *backing = load_backing(result.result, created);
  if (!backing)
    return false;
  const auto *envelope =
      reinterpret_cast<const ct_shared_envelope *>(backing->metadata);
  bool matches = backing->file_offset == object.payload_offset &&
                 backing->code_size == object.payload_size &&
                 !std::memcmp(envelope->digest, object.digest, 32);
  bool found_body = false;
  uint64_t previous = 0;
  for (uint32_t index = 0; matches && index < backing->header->count; ++index) {
    const auto &member = backing->members[index];
    matches = member.size && member.offset % 16 == 0 &&
              member.offset >= previous && member.offset < backing->code_size &&
              member.size <= backing->code_size - member.offset;
    previous = uint64_t(member.offset) + member.size;
    if (!std::memcmp(member.identity, work.body.data(), work.body.size()))
      found_body = true;
  }
  if (!matches || !found_body ||
      validate_member(work, *backing) != DR_SHARED_FRAGMENT_REBIND_AVAILABLE) {
    if (created)
      release_backing_mappings(*created);
    return false;
  }
  auto token = std::make_unique<SharedDRToken>();
  token->backing = backing;
  token->fd = result.result.fd;
  token->process = result.result.owner_process;
  token->session = result.result.owner_session;
  token->created = dr_get_microseconds();
  std::memcpy(token->source_key.data(), work.key.identity, 32);
  token->tag = work.tag;
  token->incarnation = work.incarnation;
  token->generation = work.generation;
  token->emission_id = work.emission_id;
  dr_mutex_lock(provider.lock);
  uint32_t chosen = UINT32_MAX;
  SharedDRBacking::Reservation *reservation = nullptr;
  for (auto &row : backing->reservations) {
    for (uint32_t i = 0; i < backing->header->count; ++i) {
      if (!(row.occupied & (uint64_t(1) << i)) &&
          !std::memcmp(backing->members[i].identity, work.body.data(), 32)) {
        chosen = i;
        reservation = &row;
        break;
      }
    }
    if (reservation)
      break;
  }
  if (!reservation) {
    for (uint32_t i = 0; i < backing->header->count; ++i) {
      if (!std::memcmp(backing->members[i].identity, work.body.data(), 32)) {
        chosen = i;
        break;
      }
    }
  }
  // READY already owns globally published RX pages. Require the same local
  // instruction-byte reduction as initial capture; page rounding and mapping
  // metadata are reported, not a reason to keep duplicate instructions.
  if (chosen == UINT32_MAX || backing->occupied[chosen] == UINT32_MAX ||
      (!reservation && provider.next_private_instance == SIZE_MAX) ||
      execution_cost(work.retained_code, 0,
                     (backing->members[chosen].private_size + 15) & ~size_t(15),
                     1) >= work.original_private) {
    dr_mutex_unlock(provider.lock);
    if (created)
      release_backing_mappings(*created);
    return false;
  }
  if (!reservation) {
    backing->reservations.push_back({provider.next_private_instance++, 0});
    reservation = &backing->reservations.back();
  }
  reservation->occupied |= uint64_t(1) << chosen;
  ++backing->occupied[chosen];
  token->slot = chosen;
  token->private_instance = reservation->instance;
  const size_t alias_slots = std::min(
      ready_limit, provider.aliases.size() + provider.aliases_in_flight.size() +
                       provider.ready.size() + 1);
  const size_t node_slots =
      std::min(ready_limit, provider.consumed_ready_nodes.size() +
                                provider.ready.size() + 1);
  for (auto *aliases : {&provider.aliases, &provider.aliases_in_flight}) {
    if (aliases->capacity() < alias_slots)
      aliases->reserve(
          std::min(ready_limit,
                   std::max(alias_slots,
                            std::max(size_t(16), aliases->capacity() * 2))));
  }
  if (provider.consumed_ready_nodes.capacity() < node_slots)
    provider.consumed_ready_nodes.reserve(std::min(
        ready_limit,
        std::max(node_slots,
                 std::max(size_t(16),
                          provider.consumed_ready_nodes.capacity() * 2))));
  if (provider.ready.size() >= ready_limit) {
    const auto oldest =
        std::min_element(provider.ready.begin(), provider.ready.end(),
                         [](const auto &left, const auto &right) {
                           return left.second->created < right.second->created;
                         });
    auto *unused = oldest->second;
    unused->retired.store(true, std::memory_order_release);
    queue_retired(unused);
    provider.ready.erase(oldest);
  }
  if (created)
    provider.backings.emplace(object.object_id, std::move(created));
  ++backing->references;
  token->next = provider.tokens;
  if (token->next)
    token->next->previous = token.get();
  provider.tokens = token.get();
  provider.ready.emplace(work.body, token.release());
  ++provider.service_offers;
  result.result.fd = -1; // The token now owns this READY borrow and reference.
  dr_mutex_unlock(provider.lock);
  release_retired(channel);
  if (provider.current(work.tag, work.incarnation, work.generation)) {
    ++provider.promotion_requests;
    if (!dr_delay_shared_fragment_promotion(work.tag, work.emission_id))
      ++provider.promotion_failures;
  }
  return true;
}

static bool fragment_source(instrlist_t *ilist, SharedDRWork &work,
                            uint32_t &level) {
  bool proof = false, local = false;
  for (instr_t *instruction = instrlist_first(ilist); instruction;
       instruction = instr_get_next(instruction)) {
    if (!instr_is_label(instruction))
      continue;
    const ptr_uint_t note =
        reinterpret_cast<ptr_uint_t>(instr_get_note(instruction));
    if (note == provider.note + 3)
      return false;
    const auto *data = instr_get_label_data_area(instruction);
    if (note >= provider.note && note < provider.note + 3) {
      if (proof && (level != note - provider.note ||
                    std::memcmp(work.provenance.data(), data, 32)))
        return false;
      level = note - provider.note;
      std::memcpy(work.provenance.data(), data, 32);
      proof = true;
    } else if (note == provider.note + 4) {
      if (local && (work.incarnation != data->data[0] ||
                    work.generation != data->data[1]))
        return false;
      work.incarnation = data->data[0];
      work.generation = data->data[1];
      local = true;
    }
  }
  return proof && local;
}

static bool candidate(void *, instrlist_t *ilist) {
  if (provider.stopping.load(std::memory_order_relaxed))
    return false;
  SharedDRWork work;
  uint32_t level = 0;
  return fragment_source(ilist, work, level);
}

static bool capture_proof(void *, const instrlist_t *ilist,
                          byte proof_bytes[64]) {
  if (!ilist || !proof_bytes ||
      provider.stopping.load(std::memory_order_relaxed))
    return false;
  SharedDRWork work;
  SharedDRProof proof;
  proof.version = 1; // Before lowering, labels carry the original source proof.
  if (!fragment_source(const_cast<instrlist_t *>(ilist), work, proof.level) ||
      proof.level > 2)
    return false;
  proof.source = work.provenance;
  proof.incarnation = work.incarnation;
  proof.generation = work.generation;
  std::memcpy(proof_bytes, &proof, sizeof(proof));
  return true;
}

static dr_shared_fragment_rebind_status_t
restore_layout(void *, app_pc tag, uint emission_id, const byte proof_bytes[64],
               const byte body_identity[32],
               dr_shared_fragment_restore_t *restore) {
  if (!restore || restore->struct_size != sizeof(*restore) ||
      !restore->buffer || !proof_bytes || !body_identity || !emission_id ||
      provider.stopping.load(std::memory_order_relaxed))
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
  SharedDRProof proof;
  std::memcpy(&proof, proof_bytes, sizeof(proof));
  ct_shared_key key{};
  if (proof.magic != 0x43544452 || proof.version != 2 || proof.reserved ||
      proof.level > 2 ||
      !ct_shared_dr_compact_member_key(proof.level, proof.source.data(),
                                       body_identity, &key))
    return DR_SHARED_FRAGMENT_REBIND_ABSENT;
  const auto generation =
      provider.current_try(tag, proof.incarnation, proof.generation);
  if (generation != ct_dr_shared_generation::current)
    return generation == ct_dr_shared_generation::busy
               ? DR_SHARED_FRAGMENT_REBIND_BUSY
               : DR_SHARED_FRAGMENT_REBIND_ABSENT;
  if (!dr_mutex_trylock(provider.lock))
    return DR_SHARED_FRAGMENT_REBIND_BUSY;
  Digest body;
  std::memcpy(body.data(), body_identity, body.size());
  const auto candidates = provider.ready.equal_range(body);
  auto status = DR_SHARED_FRAGMENT_REBIND_ABSENT;
  for (auto entry = candidates.first; entry != candidates.second; ++entry) {
    const auto &token = *entry->second;
    const auto &backing = *token.backing;
    if (token.tag != tag || token.emission_id != emission_id ||
        token.incarnation != proof.incarnation ||
        token.generation != proof.generation ||
        token.retired.load(std::memory_order_acquire) ||
        token.adopted.load(std::memory_order_acquire) ||
        std::memcmp(token.source_key.data(), key.identity, 32) ||
        token.slot >= backing.header->count || !backing.code)
      continue;
    const auto &member = backing.members[token.slot];
    if (!member.size || member.size > restore->capacity ||
        std::memcmp(member.identity, body_identity, 32))
      continue;
    std::memcpy(restore->buffer, backing.code + member.offset, member.size);
    restore->content_size = member.size;
    restore->private_base =
        backing.code_size + member.private_offset - member.offset;
    status = DR_SHARED_FRAGMENT_REBIND_AVAILABLE;
    break;
  }
  dr_mutex_unlock(provider.lock);
  return status;
}

static dr_shared_fragment_status_t
request_impl(void *context, const dr_shared_fragment_request_t *description,
             dr_shared_fragment_file_t *file, const SharedDRWork *reconstructed,
             bool *reconstruction_deferred = nullptr) {
  if (reconstruction_deferred)
    *reconstruction_deferred = false;
  provider.requests.fetch_add(1, std::memory_order_relaxed);
  if (description && description->struct_size == sizeof(*description) &&
      description->capture)
    description->capture->valid = false;
  if (!description || description->struct_size != sizeof(*description) ||
      (!description->ilist && !description->rebind_proof) ||
      !description->code || !file ||
      (description->ilist && description->rebind_proof) ||
      provider.stopping.load(std::memory_order_relaxed) || !current_image() ||
      description->isa_mode != DR_ISA_AMD64 || !description->content_size ||
      description->content_size > description->code_size ||
      description->private_allocation_size < description->private_slot_size ||
      description->private_allocation_size > SIZE_MAX - (dr_page_size() - 1) ||
      !description->relocations || !description->relocation_count ||
      description->relocation_count >
          CT_SHARED_DR_COMPACT_LIMIT / sizeof(ct_shared_dr_relocation) ||
      !description->private_island_size ||
      description->private_island_size > CT_SHARED_DR_COMPACT_LIMIT ||
      description->code_size % dr_page_size() ||
      description->code_size > pending_limit)
    return DR_SHARED_FRAGMENT_DECLINED;
  if (reconstructed && !description->rebind_proof)
    return DR_SHARED_FRAGMENT_DECLINED;
  // This disposition is permanent for the exact emitted bytes. Neither a
  // second consumer nor tighter page packing removes its retained instructions
  // and private island slot, so do not create a durable recovery obligation.
  if (description->retained_code_size >= description->original_private_size ||
      description->private_slot_size >= description->original_private_size -
                                            description->retained_code_size) {
    provider.rejected_private.fetch_add(1, std::memory_order_relaxed);
    return DR_SHARED_FRAGMENT_DECLINED;
  }
  const bool replay = description->rebind_proof && !reconstructed;
  SharedDRWork work;
  static_assert(sizeof(ct_shared_dr_relocation) ==
                sizeof(dr_shared_fragment_relocation_t));
  static_assert(DR_SHARED_FRAGMENT_U32_PRIVATE == 1 &&
                DR_SHARED_FRAGMENT_REL32_PRIVATE == 2 &&
                DR_SHARED_FRAGMENT_BUNDLE_LIMIT == CT_SHARED_DR_COMPACT_LIMIT);
  ct_shared_dr_compact_member normalized{};
  normalized.size = description->content_size;
  normalized.private_size = description->private_island_size;
  normalized.prototype_private_offset = description->prototype_private_offset;
  normalized.relocation_count = description->relocation_count;
  uint32_t level = 0;
  bool final_provenance = false;
  if (description->rebind_proof) {
    SharedDRProof proof;
    std::memcpy(&proof, description->rebind_proof, sizeof(proof));
    if (proof.magic != 0x43544452 ||
        (proof.version != 1 && proof.version != 2) || proof.reserved ||
        proof.level > 2)
      return DR_SHARED_FRAGMENT_DECLINED;
    work.provenance = proof.source;
    work.incarnation = proof.incarnation;
    work.generation = proof.generation;
    level = proof.level;
    final_provenance = proof.version == 2;
  } else if (!fragment_source(description->ilist, work, level)) {
    return DR_SHARED_FRAGMENT_DECLINED;
  }
  if (!description->identity || !description->identity_size ||
      description->identity_size > description->content_size)
    return DR_SHARED_FRAGMENT_DECLINED;
  const ct_digest_part parts[] = {
      {work.provenance.data(), work.provenance.size()},
      {description->identity, description->identity_size}};
  if ((!final_provenance &&
       !ct_shared_platform_digest_parts(parts, 2, work.provenance.data())) ||
      !ct_shared_dr_compact_digest(
          description->isa_mode, &normalized, description->relocations,
          description->code, description->prototype_private_offset,
          description->private_allocation_size, work.body.data()) ||
      !ct_shared_dr_compact_member_key(level, work.provenance.data(),
                                       work.body.data(), &work.key))
    return DR_SHARED_FRAGMENT_DECLINED;
  // This version binds the original source and the exact initial lowering
  // layout. Replays use it directly: hashing the layout a second time would
  // silently change the source association after recipe eviction.
  work.source = work.provenance;
  work.tag = static_cast<app_pc>(description->tag);
  work.emission_id = description->emission_id;
  work.original_private = description->original_private_size;
  work.retained_private = description->retained_private_size;
  work.retained_code = description->retained_code_size;
  work.private_allocation = description->private_allocation_size;
  // Reconstruction is only a candidate. The original source/layout binding
  // and freshly hashed canonical body must match the durable emission before
  // taking a provider lock or admitting any reconstructed staging bytes.
  if (reconstructed &&
      (!same_work(work, *reconstructed) || work.body != reconstructed->body)) {
    ++provider.reconstruction_mismatch;
    return DR_SHARED_FRAGMENT_DECLINED;
  }
  if (description->capture && work.emission_id) {
    SharedDRProof proof;
    proof.source = work.source;
    proof.incarnation = work.incarnation;
    proof.generation = work.generation;
    proof.level = level;
    std::memcpy(description->capture->proof, &proof, sizeof(proof));
    std::memcpy(description->capture->body_identity, work.body.data(),
                work.body.size());
    description->capture->valid = true;
    if (!description->rebind_proof) {
      provider.anchor_revision.fetch_add(1, std::memory_order_relaxed);
      provider.has_work.store(true, std::memory_order_release);
    }
  }
  // Capture survives all temporary staging/offer decisions, including
  // contention.
  if (description->rebind_proof) {
    const auto generation =
        provider.current_try(work.tag, work.incarnation, work.generation);
    if (generation != ct_dr_shared_generation::current) {
      if (reconstruction_deferred)
        *reconstruction_deferred = generation == ct_dr_shared_generation::busy;
      return generation == ct_dr_shared_generation::busy
                 ? DR_SHARED_FRAGMENT_DEFER
                 : DR_SHARED_FRAGMENT_DECLINED;
    }
  }
  if (!dr_mutex_trylock(provider.lock)) {
    if (reconstruction_deferred)
      *reconstruction_deferred = true;
    return replay || reconstructed ? DR_SHARED_FRAGMENT_DEFER
                                   : DR_SHARED_FRAGMENT_DECLINED;
  }
  if (!reconstructed) {
    provider.recipe_slot = description->retained_recipe_size;
    provider.recipe_storage = description->recipe_storage_size;
    provider.recipe_live = description->recipe_live_size;
  }
  bool observed = false;
  for (auto &known : provider.observed) {
    if (replay)
      break;
    if (known.tag == work.tag &&
        !std::memcmp(&known.key, &work.key, sizeof(work.key))) {
      if (known.incarnation != work.incarnation ||
          known.generation != work.generation ||
          known.original_private != work.original_private ||
          known.retained_private != work.retained_private ||
          known.retained_code != work.retained_code ||
          known.private_allocation != work.private_allocation ||
          known.emission_id != work.emission_id || known.replay_available)
        ++provider.observed_revision;
      known = work;
      observed = true;
      break;
    }
  }
  const size_t observed_capacity = observed_limit / sizeof(SharedDRWork);
  if (!observed && !replay) {
    if (provider.observed.size() == observed_capacity)
      provider.observed.erase(provider.observed.begin());
    if (provider.observed.size() == provider.observed.capacity())
      provider.observed.reserve(
          std::min(observed_capacity,
                   std::max(size_t(16), provider.observed.capacity() * 2)));
    provider.observed.push_back(work);
    ++provider.observed_revision;
    provider.has_work.store(true, std::memory_order_release);
  }
  // Pool entries own independent prepaid catalog references. A body match
  // only supplies storage: the label/source proof and current core layout
  // above have already been validated, and DR checks all canonical bytes.
  auto ready = replay || reconstructed ? provider.ready.end()
                                       : provider.ready.find(work.body);
  const auto matches = provider.ready.equal_range(work.body);
  for (auto found = matches.first; !reconstructed && found != matches.second;
       ++found) {
    const auto &token = *found->second;
    if (token.tag == work.tag && token.incarnation == work.incarnation &&
        token.generation == work.generation &&
        token.emission_id == work.emission_id &&
        !std::memcmp(token.source_key.data(), work.key.identity, 32)) {
      ready = found;
      break;
    }
  }
  if (ready != provider.ready.end() &&
      provider.aliases.size() + provider.aliases_in_flight.size() <
          ready_limit) {
    SharedDRToken *token = ready->second;
    SharedDRBacking &backing = *token->backing;
    const uint32_t chosen = token->slot;
    if (replay) {
      if (provider.aliases.size() == provider.aliases.capacity() ||
          provider.consumed_ready_nodes.size() ==
              provider.consumed_ready_nodes.capacity()) {
        dr_mutex_unlock(provider.lock);
        return DR_SHARED_FRAGMENT_DEFER;
      }
      provider.consumed_ready_nodes.push_back(provider.ready.extract(ready));
    } else {
      provider.ready.erase(ready);
    }
    if (chosen < backing.header->count && token->private_instance &&
        backing.header->isa_mode == description->isa_mode &&
        backing.members[chosen].size == description->content_size &&
        backing.members[chosen].private_size ==
            description->private_island_size &&
        !std::memcmp(backing.members[chosen].identity, work.body.data(),
                     work.body.size())) {
      file->fd = token->fd;
      file->offset = backing.file_offset;
      file->size = backing.code_size;
      file->member_offset = backing.members[chosen].offset;
      file->private_offset = backing.members[chosen].private_offset;
      file->private_extent = backing.header->private_size;
      file->private_instance = token->private_instance;
      std::memcpy(token->source_key.data(), work.key.identity, 32);
      token->tag = work.tag;
      token->incarnation = work.incarnation;
      token->generation = work.generation;
      token->emission_id = work.emission_id;
      file->token = token;
      provider.aliases.push_back(
          SharedDRAlias{work.key, work.provenance, work.body,
                        static_cast<app_pc>(description->tag), work.incarnation,
                        work.generation, backing.object});
      provider.has_work.store(true, std::memory_order_release);
      provider.offers.fetch_add(1, std::memory_order_relaxed);
      dr_mutex_unlock(provider.lock);
      return DR_SHARED_FRAGMENT_READY;
    }
    token->retired.store(true, std::memory_order_release);
    queue_retired(token);
  }
  if (replay) {
    dr_mutex_unlock(provider.lock);
    // Capacity eviction can retire an offer after its promotion was queued.
    // Stop that attempt; the durable anchor lets a future READY offer queue
    // another exact-emission promotion. Only actual contention should retry.
    return DR_SHARED_FRAGMENT_DECLINED;
  }
  // Do not create a second unsealed working set while another safe callback
  // is publishing this image's bounded batch. Existing READY tokens still win.
  if (!reconstructed &&
      (provider.servicing.load(std::memory_order_acquire) ||
       provider.demand_pending.load(std::memory_order_acquire))) {
    dr_mutex_unlock(provider.lock);
    return DR_SHARED_FRAGMENT_DEFER;
  }
  auto pending = provider.pending.find(work.body);
  if (pending != provider.pending.end()) {
    for (const auto &known : pending->second->work) {
      if (same_work(known, work)) {
        dr_mutex_unlock(provider.lock);
        return DR_SHARED_FRAGMENT_DEFER;
      }
    }
  }
  const size_t previous_cost =
      pending == provider.pending.end() ? 0 : pending_cost(*pending->second);
  const size_t base_cost =
      pending == provider.pending.end()
          ? sizeof(SharedDRPending) + description->content_size +
                description->relocation_count *
                    sizeof(ct_shared_dr_relocation) +
                pending_body_overhead
          : previous_cost -
                pending->second->work.capacity() * sizeof(SharedDRWork);
  if (base_cost > pending_limit - sizeof(SharedDRWork)) {
    dr_mutex_unlock(provider.lock);
    return reconstructed ? DR_SHARED_FRAGMENT_DECLINED
                         : DR_SHARED_FRAGMENT_DEFER;
  }
  const size_t maximum_count =
      (pending_limit - base_cost) / sizeof(SharedDRWork);
  size_t count = 1;
  unsigned __int128 benefit =
      work.original_private -
      execution_cost(work.retained_code, 0, work.private_allocation, 1);
  if (pending != provider.pending.end()) {
    count += pending->second->work.size();
    for (const auto &known : pending->second->work)
      benefit +=
          known.original_private -
          execution_cost(known.retained_code, 0, known.private_allocation, 1);
  }
  if (count > maximum_count) {
    if (reconstruction_deferred)
      *reconstruction_deferred = true;
    dr_mutex_unlock(provider.lock);
    return DR_SHARED_FRAGMENT_DEFER;
  }
  // Recover only distinct work already observed and confirmed AVAILABLE by a
  // safe service. This is a bounded retention preference, not an admission
  // proof: generation, recipe availability and exact packing are checked again
  // before publication. No analysis or broker locks are taken in this callback.
  const auto recoverable = [&](const SharedDRWork &known) {
    if (known.body != work.body || !known.replay_available ||
        same_work(known, work))
      return false;
    if (pending != provider.pending.end()) {
      for (const auto &queued : pending->second->work)
        if (same_work(known, queued))
          return false;
    }
    return true;
  };
  size_t recovered = 0;
  for (const auto &known : provider.observed) {
    if (count == maximum_count)
      break;
    if (recoverable(known)) {
      ++count;
      ++recovered;
      benefit +=
          known.original_private -
          execution_cost(known.retained_code, 0, known.private_allocation, 1);
    }
  }
  const size_t next_capacity =
      pending == provider.pending.end()
          ? count
          : std::max(count, pending->second->work.capacity());
  const size_t total_cost = base_cost + next_capacity * sizeof(SharedDRWork);
  const size_t charge = total_cost - previous_cost;
  if (reconstructed && charge > pending_limit - provider.pending_bytes) {
    // Keep earlier recovered members until the next service publishes them.
    // A held scan entry resumes after that bounded pending store is drained.
    if (reconstruction_deferred)
      *reconstruction_deferred = true;
    dr_mutex_unlock(provider.lock);
    return DR_SHARED_FRAGMENT_DEFER;
  }
  while (charge > pending_limit - provider.pending_bytes) {
    auto victim = provider.pending.end();
    unsigned __int128 victim_benefit = 0;
    size_t victim_cost = 0;
    for (auto item = provider.pending.begin(); item != provider.pending.end();
         ++item) {
      if (item == pending)
        continue;
      const auto &body = *item->second;
      const bool singleton = body.work.size() < 2;
      if (victim != provider.pending.end() && victim->second->work.size() < 2) {
        if (singleton && body.updated < victim->second->updated)
          victim = item;
        continue;
      }
      if (singleton) {
        victim = item;
        continue;
      }
      if (count < 2)
        continue;
      unsigned __int128 saved = 0;
      for (const auto &known : body.work)
        saved +=
            known.original_private -
            execution_cost(known.retained_code, 0, known.private_allocation, 1);
      const size_t cost = pending_cost(body);
      if (benefit * cost <= saved * total_cost)
        continue;
      if (victim == provider.pending.end() ||
          saved * victim_cost < victim_benefit * cost ||
          (saved * victim_cost == victim_benefit * cost &&
           body.updated < victim->second->updated)) {
        victim = item;
        victim_benefit = saved;
        victim_cost = cost;
      }
    }
    if (victim == provider.pending.end()) {
      dr_mutex_unlock(provider.lock);
      // Keep the observation for discovery without displacing a stronger
      // repeated cohort. In-flight publication is never an eviction target.
      return DR_SHARED_FRAGMENT_DEFER;
    }
    provider.pending_bytes -= pending_cost(*victim->second);
    provider.pending.erase(victim);
  }
  if (pending == provider.pending.end()) {
    auto body = std::make_unique<SharedDRPending>();
    body->body = work.body;
    body->isa = description->isa_mode;
    body->code_size = description->prototype_private_offset;
    body->private_size = description->private_island_size;
    body->relocations.resize(description->relocation_count);
    std::memcpy(body->relocations.data(), description->relocations,
                body->relocations.size() * sizeof(body->relocations[0]));
    body->code.assign(description->code,
                      description->code + description->content_size);
    pending = provider.pending.emplace(work.body, std::move(body)).first;
  }
  pending->second->work.reserve(next_capacity);
  pending->second->work.push_back(work);
  for (const auto &known : provider.observed) {
    if (!recovered)
      break;
    if (recoverable(known)) {
      pending->second->work.push_back(known);
      --recovered;
    }
  }
  pending->second->updated = dr_get_microseconds();
  provider.queued.fetch_add(1, std::memory_order_relaxed);
  if (reconstructed)
    ++provider.reconstruction_staged;
  provider.pending_bytes += charge;
  provider.has_work.store(true, std::memory_order_release);
  dr_mutex_unlock(provider.lock);
  return DR_SHARED_FRAGMENT_DEFER;
}

static dr_shared_fragment_status_t
request(void *context, const dr_shared_fragment_request_t *description,
        dr_shared_fragment_file_t *file) {
  return request_impl(context, description, file, nullptr);
}

bool ct_dr_shared_stamp(void *context, instrlist_t *ilist,
                        const unsigned char provenance[32],
                        ct_instrument_level level, uint64_t incarnation,
                        uint64_t generation) {
  if (provider.note == DRMGR_NOTE_NONE || !ilist || !provenance ||
      unsigned(level) > unsigned(ct_instrument_level::full))
    return false;
  static_assert(sizeof(dr_instr_label_data_t) >= 32);
  bool found = false;
  for (instr_t *instruction = instrlist_first(ilist); instruction;
       instruction = instr_get_next(instruction)) {
    const ptr_uint_t note =
        reinterpret_cast<ptr_uint_t>(instr_get_note(instruction));
    if (!instr_is_label(instruction) || note < provider.note ||
        note >= provider.note + 4)
      continue;
    const bool same =
        note == provider.note + unsigned(level) &&
        !std::memcmp(instr_get_label_data_area(instruction), provenance, 32);
    if (!same) {
      instr_set_note(instruction, reinterpret_cast<void *>(provider.note + 3));
      return false;
    }
    found = true;
  }
  if (!found) {
    instr_t *label = INSTR_CREATE_label(context);
    instr_set_note(label,
                   reinterpret_cast<void *>(provider.note + unsigned(level)));
    std::memcpy(instr_get_label_data_area(label), provenance, 32);
    instrlist_meta_preinsert(ilist, instrlist_first(ilist), label);
  }
  for (instr_t *instruction = instrlist_first(ilist); instruction;
       instruction = instr_get_next(instruction)) {
    if (!instr_is_label(instruction) ||
        instr_get_note(instruction) !=
            reinterpret_cast<void *>(provider.note + 4))
      continue;
    const auto *data = instr_get_label_data_area(instruction);
    const bool same =
        data->data[0] == incarnation && data->data[1] == generation;
    if (!same)
      instr_set_note(instruction, reinterpret_cast<void *>(provider.note + 3));
    return same;
  }
  instr_t *local = INSTR_CREATE_label(context);
  instr_set_note(local, reinterpret_cast<void *>(provider.note + 4));
  auto *data = instr_get_label_data_area(local);
  std::memset(data, 0, sizeof(*data));
  data->data[0] = incarnation;
  data->data[1] = generation;
  instrlist_meta_preinsert(ilist, instrlist_first(ilist), local);
  return true;
}

// A READY descriptor owns a catalog reference even when it cannot be adopted.
static void release_result(ct_shared_channel *channel,
                           ct_shared_result &result) {
  if (result.status == CT_SHARED_READY) {
    ct_shared_result_close(&result);
    ct_shared_release(channel, result.object.object_id);
  } else if (result.status == CT_SHARED_WAIT) {
    ct_shared_cancel_wait(channel, result.token);
  } else if (result.status == CT_SHARED_CREATE) {
    ct_shared_fail(channel, result.token);
  }
  result = {};
  result.fd = -1;
}

static bool acquire_member(ct_shared_channel *channel, const SharedDRWork &work,
                           uint64_t admitted_object = 0) {
  dr_mutex_lock(provider.lock);
  bool offered = false, adopted = false;
  for (auto *token = provider.tokens; token; token = token->next) {
    if (!token->retired.load(std::memory_order_acquire) &&
        token->tag == work.tag && token->incarnation == work.incarnation &&
        token->generation == work.generation &&
        token->emission_id == work.emission_id &&
        !std::memcmp(token->source_key.data(), work.key.identity, 32)) {
      offered = true;
      adopted = token->adopted.load(std::memory_order_acquire);
      break;
    }
  }
  dr_mutex_unlock(provider.lock);
  if (offered) {
    // A pending mapping change can postpone the original queue request, or a
    // previous attempt can end before consumption. The exact offer remains
    // valid after rollback and the core coalesces requests for this emission.
    if (!adopted &&
        provider.current(work.tag, work.incarnation, work.generation)) {
      ++provider.promotion_requests;
      if (!dr_delay_shared_fragment_promotion(work.tag, work.emission_id))
        ++provider.promotion_failures;
    }
    return true;
  }
  if (provider.service_offers == ready_limit)
    return false;
  ct_shared_dr_member_result found{};
  found.result.fd = -1;
  bool received = admitted_object
                      ? ct_shared_dr_member_bind_to(
                            channel, &work.key, work.provenance.data(),
                            work.body.data(), admitted_object, &found)
                      : ct_shared_dr_member_acquire(channel, &work.key, &found);
  if (!admitted_object && received && found.result.status == CT_SHARED_ABSENT)
    received = ct_shared_dr_member_bind(
        channel, &work.key, work.provenance.data(), work.body.data(), &found);
  const bool ready = received && found.result.status == CT_SHARED_READY &&
                     prepare_ready(work, found, channel);
  if (!ready)
    release_result(channel, found.result);
  return ready;
}

// Recent observations and durable core snapshots use the same exact-emission
// proof, catalog lookup, bounded export and canonical hash validation. Retry
// keeps exact work queued through temporary contention or the next store drain.
static SharedDRRecovery recover_member(ct_shared_channel *channel,
                                       const SharedDRWork &work,
                                       size_t &reconstructed_bytes) {
  SharedDRProof proof;
  proof.source = work.source;
  proof.incarnation = work.incarnation;
  proof.generation = work.generation;
  proof.level = work.key.level;
  const auto generation =
      provider.current_try(work.tag, work.incarnation, work.generation);
  if (generation != ct_dr_shared_generation::current) {
    const bool retry =
        generation == ct_dr_shared_generation::busy ||
        dr_shared_fragment_discard(work.tag, work.emission_id,
                                   reinterpret_cast<const byte *>(&proof)) ==
            DR_SHARED_FRAGMENT_REBIND_BUSY;
    provider.discovery_retry |= retry;
    return retry ? SharedDRRecovery::retry : SharedDRRecovery::complete;
  }
  dr_mutex_lock(provider.lock);
  bool staged = false;
  for (const auto *bodies : {&provider.pending, &provider.in_flight}) {
    const auto body = bodies->find(work.body);
    if (body != bodies->end())
      staged |= std::any_of(
          body->second->work.begin(), body->second->work.end(),
          [&](const auto &known) { return same_work(known, work); });
  }
  dr_mutex_unlock(provider.lock);
  if (staged)
    return SharedDRRecovery::staged;
  if (acquire_member(channel, work))
    return SharedDRRecovery::complete;
  if (provider.service_offers == ready_limit)
    return SharedDRRecovery::retry;
  if (work.original_private > pending_limit)
    return SharedDRRecovery::complete;
  if (work.original_private > pending_limit - reconstructed_bytes)
    return SharedDRRecovery::retry;
  reconstructed_bytes += work.original_private;
  if (!provider.recovery_buffer)
    provider.recovery_buffer = static_cast<byte *>(
        dr_nonheap_alloc(2 * DR_SHARED_FRAGMENT_BUNDLE_LIMIT,
                         DR_MEMPROT_READ | DR_MEMPROT_WRITE));
  if (!provider.recovery_buffer)
    return SharedDRRecovery::retry;
  dr_shared_fragment_export_t exported{};
  exported.struct_size = sizeof(exported);
  exported.buffer = provider.recovery_buffer;
  exported.capacity = 2 * DR_SHARED_FRAGMENT_BUNDLE_LIMIT;
  ++provider.reconstruction_attempts;
  const auto status =
      dr_shared_fragment_export(work.tag, work.emission_id, &exported);
  if (status == DR_SHARED_FRAGMENT_REBIND_BUSY) {
    provider.discovery_retry = true;
    return SharedDRRecovery::retry;
  }
  if (status != DR_SHARED_FRAGMENT_REBIND_AVAILABLE ||
      exported.buffer != provider.recovery_buffer ||
      exported.capacity != 2 * DR_SHARED_FRAGMENT_BUNDLE_LIMIT ||
      exported.snapshot.tag != work.tag ||
      exported.snapshot.emission_id != work.emission_id ||
      exported.snapshot.original_size != work.original_private ||
      std::memcmp(exported.snapshot.proof, &proof, sizeof(proof)) ||
      std::memcmp(exported.snapshot.body_identity, work.body.data(),
                  work.body.size()) ||
      exported.code_size > exported.capacity ||
      exported.relocation_offset < exported.code_size ||
      exported.relocation_offset > exported.capacity ||
      exported.relocation_offset % alignof(dr_shared_fragment_relocation_t) ||
      exported.relocation_count >
          (exported.capacity - exported.relocation_offset) /
              sizeof(dr_shared_fragment_relocation_t))
    return SharedDRRecovery::complete;
  dr_shared_fragment_request_t description{};
  description.struct_size = sizeof(description);
  description.tag = work.tag;
  description.isa_mode = exported.isa_mode;
  description.fragment_flags = exported.fragment_flags;
  description.identity = description.code = exported.buffer;
  description.identity_size = exported.identity_size;
  description.code_size = exported.code_size;
  description.content_size = exported.content_size;
  description.original_private_size = exported.snapshot.original_size;
  description.retained_private_size = exported.snapshot.retained_private_size;
  description.retained_code_size = exported.snapshot.retained_code_size;
  description.private_island_size = exported.private_island_size;
  description.private_slot_size = description.private_allocation_size =
      exported.private_slot_size;
  description.prototype_private_offset = exported.prototype_private_offset;
  description.relocations = reinterpret_cast<dr_shared_fragment_relocation_t *>(
      exported.buffer + exported.relocation_offset);
  description.relocation_count = exported.relocation_count;
  description.rebind_proof = exported.snapshot.proof;
  description.emission_id = work.emission_id;
  dr_shared_fragment_file_t file{};
  // request_impl verifies the reconstructed SHA against work.body before
  // copying into the ordinary bounded pending store. It cannot consume READY.
  bool deferred = false;
  const auto result =
      request_impl(nullptr, &description, &file, &work, &deferred);
  return deferred                                ? SharedDRRecovery::retry
         : result == DR_SHARED_FRAGMENT_DECLINED ? SharedDRRecovery::complete
                                                 : SharedDRRecovery::staged;
}

// Publish the tag before advancing its sequence. A service that observes the
// old sequence while publication is in progress will still see the later hit.
// Repeated same-tag emissions therefore cannot be erased by a pointer-only
// compare/clear. Overflow replaces one slot in round-robin order; the durable
// core scan remains the fallback for overwritten scheduling hints.
static void record_demand(app_pc tag) {
  SharedDRDemand *selected = nullptr;
  for (auto &slot : provider.demands) {
    if (slot.tag.load(std::memory_order_relaxed) == tag) {
      selected = &slot;
      break;
    }
  }
  if (!selected) {
    for (auto &slot : provider.demands) {
      app_pc empty = nullptr;
      if (slot.tag.compare_exchange_strong(empty, tag,
                                           std::memory_order_release,
                                           std::memory_order_relaxed)) {
        selected = &slot;
        break;
      }
    }
  }
  if (!selected)
    selected = &provider.demands[provider.demand_overwrite.fetch_add(
                                     1, std::memory_order_relaxed) %
                                 provider.demands.size()];
  selected->tag.store(tag, std::memory_order_release);
  selected->sequence.fetch_add(1, std::memory_order_release);
  provider.demand_pending.store(true, std::memory_order_release);
  provider.has_work.store(true, std::memory_order_release);
}

static void service_demands(ct_shared_channel *channel,
                            size_t &reconstructed_bytes) {
  if (!channel)
    return;
  for (size_t visited = 0; visited < provider.demands.size(); ++visited) {
    auto &slot = provider.demands[provider.demand_cursor];
    const uint64_t sequence = slot.sequence.load(std::memory_order_acquire);
    const app_pc tag = slot.tag.load(std::memory_order_acquire);
    if (sequence != slot.seen && tag &&
        sequence == slot.sequence.load(std::memory_order_acquire)) {
      dr_shared_fragment_snapshot_t snapshot{};
      const auto status = dr_shared_fragment_snapshot(tag, &snapshot);
      if (status == DR_SHARED_FRAGMENT_REBIND_BUSY)
        break;
      auto recovered = SharedDRRecovery::complete;
      SharedDRProof proof;
      std::memcpy(&proof, snapshot.proof, sizeof(proof));
      if (status == DR_SHARED_FRAGMENT_REBIND_AVAILABLE &&
          snapshot.tag == tag && snapshot.emission_id &&
          snapshot.original_size && proof.magic == 0x43544452 &&
          proof.version == 2 && !proof.reserved && proof.level <= 2) {
        SharedDRWork work;
        work.source = work.provenance = proof.source;
        std::memcpy(work.body.data(), snapshot.body_identity, work.body.size());
        work.tag = tag;
        work.emission_id = snapshot.emission_id;
        work.incarnation = proof.incarnation;
        work.generation = proof.generation;
        work.original_private = snapshot.original_size;
        work.retained_private = snapshot.retained_private_size;
        work.retained_code = snapshot.retained_code_size;
        if (ct_shared_dr_compact_member_key(proof.level, work.provenance.data(),
                                            work.body.data(), &work.key))
          recovered = recover_member(channel, work, reconstructed_bytes);
      }
      if (recovered == SharedDRRecovery::retry)
        break;
      if (recovered == SharedDRRecovery::complete)
        slot.seen = sequence;
      // Staging alone does not satisfy demand. Keep its sequence outstanding
      // until publication produces an exact offer or the anchor disappears.
    }
    provider.demand_cursor =
        (provider.demand_cursor + 1) % provider.demands.size();
  }
  // Acquire any producer preceding the reset; producers following it leave
  // their flag set. A plain release store would not order the sequence scan.
  provider.demand_pending.exchange(false, std::memory_order_acq_rel);
  for (const auto &slot : provider.demands) {
    if (slot.sequence.load(std::memory_order_acquire) != slot.seen) {
      provider.demand_pending.store(true, std::memory_order_release);
      break;
    }
  }
}

static void clear_discovery_storage() {
  if (provider.recovery_buffer) {
    dr_nonheap_free(provider.recovery_buffer,
                    2 * DR_SHARED_FRAGMENT_BUNDLE_LIMIT);
    provider.recovery_buffer = nullptr;
  }
  std::vector<SharedDRWork>().swap(provider.discovery_observations);
  std::vector<SharedDRAvailability>().swap(provider.discovery_current);
}

static void discover_ready(ct_shared_channel *channel, uint64_t now,
                           size_t *service_reconstructed_bytes = nullptr) {
  if (!channel)
    return;
  auto &observations = provider.discovery_observations;
  dr_mutex_lock(provider.lock);
  observations = provider.observed;
  dr_mutex_unlock(provider.lock);
  auto &current = provider.discovery_current;
  current.reserve(observations.size());
  bool busy = false;
  for (const auto &work : observations) {
    const bool valid =
        provider.current(work.tag, work.incarnation, work.generation);
    const auto status =
        valid ? replay_status(work) : DR_SHARED_FRAGMENT_REBIND_ABSENT;
    current.push_back({valid, status});
    busy |= status == DR_SHARED_FRAGMENT_REBIND_BUSY;
  }
  dr_mutex_lock(provider.lock);
  for (auto item = provider.observed.begin();
       item != provider.observed.end();) {
    bool invalid = false, adopted = false;
    for (size_t i = 0; i < observations.size(); ++i) {
      const auto &work = observations[i];
      if (work.tag == item->tag && work.incarnation == item->incarnation &&
          work.generation == item->generation &&
          work.emission_id == item->emission_id &&
          !std::memcmp(&work.key, &item->key, sizeof(work.key))) {
        invalid |= !current[i].current ||
                   current[i].status == DR_SHARED_FRAGMENT_REBIND_ABSENT;
        if (current[i].status != DR_SHARED_FRAGMENT_REBIND_BUSY) {
          const bool available =
              current[i].status == DR_SHARED_FRAGMENT_REBIND_AVAILABLE;
          if (available != item->replay_available) {
            item->replay_available = available;
            ++provider.observed_revision;
          }
        }
      }
    }
    for (auto *token = provider.tokens; token && !invalid;
         token = token->next) {
      if (token->adopted.load(std::memory_order_acquire) &&
          !token->retired.load(std::memory_order_acquire) &&
          token->tag == item->tag && token->incarnation == item->incarnation &&
          token->generation == item->generation &&
          token->emission_id == item->emission_id &&
          !std::memcmp(token->source_key.data(), item->key.identity, 32)) {
        adopted = true;
        break;
      }
    }
    if (invalid || adopted) {
      item = provider.observed.erase(item);
      ++provider.observed_revision;
    } else {
      ++item;
    }
  }
  if (provider.observed.empty()) {
    std::vector<SharedDRWork>().swap(provider.observed);
  } else if (provider.observed.size() < provider.observed.capacity() / 2) {
    std::vector<SharedDRWork>(provider.observed).swap(provider.observed);
  }
  observations.clear();
  for (const auto &work : provider.observed) {
    bool offered = false;
    for (auto *token = provider.tokens; token; token = token->next) {
      if (!token->retired.load(std::memory_order_acquire) &&
          token->adopted.load(std::memory_order_acquire) &&
          token->tag == work.tag && token->incarnation == work.incarnation &&
          token->generation == work.generation &&
          token->emission_id == work.emission_id &&
          !std::memcmp(token->source_key.data(), work.key.identity, 32)) {
        offered = true;
        break;
      }
    }
    if (!offered)
      observations.push_back(work);
  }
  const uint64_t revision = provider.observed_revision;
  dr_mutex_unlock(provider.lock);
  uint64_t sequence = 0;
  if (!ct_shared_poll(channel, 0, &sequence))
    return;
  if (!provider.scanning) {
    const auto anchor_revision =
        provider.anchor_revision.load(std::memory_order_relaxed);
    if (sequence == provider.scanned_sequence &&
        revision == provider.scanned_revision && !provider.discovery_retry &&
        !busy && anchor_revision == provider.scanned_anchor_revision &&
        now < provider.next_recovery_sweep)
      return;
    provider.discovery_retry = false;
    provider.scan_sequence = sequence;
    provider.scan_revision = revision;
    provider.scan_anchor_revision = anchor_revision;
    provider.anchor_cursor = 0;
    provider.recovery_count = provider.recovery_cursor = 0;
    provider.scanning = true;
  }
  provider.discovery_retry |= busy;
  // Recent exact emissions get a complete publication attempt before the
  // background table sweep. Remember the deferred proof, not a vector index:
  // adopted/stale observations can disappear between service callbacks.
  size_t local_reconstructed_bytes = 0;
  size_t &reconstructed_bytes = service_reconstructed_bytes
                                    ? *service_reconstructed_bytes
                                    : local_reconstructed_bytes;
  auto next_recent = observations.begin();
  if (provider.recent_resume.emission_id) {
    const auto resumed = std::find_if(
        observations.begin(), observations.end(), [&](const auto &work) {
          return same_work(work, provider.recent_resume);
        });
    if (resumed != observations.end())
      next_recent = resumed;
  }
  for (; next_recent != observations.end(); ++next_recent) {
    if (recover_member(channel, *next_recent, reconstructed_bytes) ==
        SharedDRRecovery::retry) {
      provider.recent_resume = *next_recent;
      return;
    }
  }
  provider.recent_resume = {};
  bool scanned = true;
  if (provider.recovery_cursor == provider.recovery_count) {
    provider.recovery_count = provider.recovery_cursor = 0;
    scanned = dr_shared_fragment_scan(
        &provider.anchor_cursor, provider.recovery_snapshots.data(),
        provider.recovery_snapshots.size(), &provider.recovery_count);
    provider.discovery_retry |= !scanned;
  }
  observations.reserve(observations.size() + provider.recovery_count);
  size_t blocked_cursor = provider.recovery_count;
  for (size_t index = 0; index < provider.recovery_count; ++index) {
    const auto &snapshot = provider.recovery_snapshots[index];
    SharedDRProof proof;
    std::memcpy(&proof, snapshot.proof, sizeof(proof));
    if (proof.magic != 0x43544452 || proof.version != 2 || proof.reserved ||
        proof.level > 2 || !snapshot.emission_id)
      continue;
    const auto generation =
        provider.current_try(snapshot.tag, proof.incarnation, proof.generation);
    if (generation != ct_dr_shared_generation::current) {
      // A pending mapping syscall may fail and restore this proof. Only a
      // known stale module incarnation or generation permits exact retirement.
      const bool retry = generation == ct_dr_shared_generation::busy ||
                         dr_shared_fragment_discard(
                             snapshot.tag, snapshot.emission_id,
                             snapshot.proof) == DR_SHARED_FRAGMENT_REBIND_BUSY;
      provider.discovery_retry |= retry;
      if (retry && index >= provider.recovery_cursor)
        blocked_cursor = std::min(blocked_cursor, index);
      continue;
    }
    SharedDRWork work;
    work.source = work.provenance = proof.source;
    std::memcpy(work.body.data(), snapshot.body_identity, work.body.size());
    work.tag = snapshot.tag;
    work.emission_id = snapshot.emission_id;
    work.incarnation = proof.incarnation;
    work.generation = proof.generation;
    work.original_private = snapshot.original_size;
    work.retained_private = snapshot.retained_private_size;
    work.retained_code = snapshot.retained_code_size;
    if (!ct_shared_dr_compact_member_key(proof.level, work.provenance.data(),
                                         work.body.data(), &work.key))
      continue;
    if (std::none_of(observations.begin(), observations.end(),
                     [&](const auto &known) { return same_work(known, work); }))
      observations.push_back(work);
  }
  // An emission can outlive both bounded stores before anybody publishes its
  // body. Reconstruct only at safe service, with a bounded amount of original
  // code per turn. Keep the remainder of this scan page for fair progress.
  while (provider.recovery_cursor < provider.recovery_count) {
    // An offer admitted during this service must reach the dispatcher before
    // a later offer can evict it. Keep the scan position for the next service.
    if (provider.recovery_cursor == blocked_cursor ||
        provider.service_offers == ready_limit)
      break;
    const auto &snapshot =
        provider.recovery_snapshots[provider.recovery_cursor];
    auto found = std::find_if(observations.begin(), observations.end(),
                              [&](const auto &work) {
                                return work.tag == snapshot.tag &&
                                       work.emission_id == snapshot.emission_id;
                              });
    if (found == observations.end() || !snapshot.original_size) {
      ++provider.recovery_cursor;
      continue;
    }
    const SharedDRWork work = *found;
    if (recover_member(channel, work, reconstructed_bytes) ==
        SharedDRRecovery::retry)
      break;
    ++provider.recovery_cursor;
  }
  const bool anchors_complete =
      scanned && provider.anchor_cursor == 0 &&
      provider.recovery_cursor == provider.recovery_count;
  if (anchors_complete) {
    provider.scanned_sequence = provider.scan_sequence;
    provider.scanned_revision = provider.scan_revision;
    provider.scanned_anchor_revision = provider.scan_anchor_revision;
    provider.scanning = false;
    // Emission capture precedes publication in DR's table. An infrequent
    // repeat also catches entries moved by a concurrent table resize.
    provider.next_recovery_sweep = now + recovery_sweep_interval_us;
  }
}

void ct_dr_shared_service(void *context, bool drain_pending,
                          app_pc executed_tag) {
  if (executed_tag && provider.lock &&
      !provider.stopping.load(std::memory_order_relaxed))
    record_demand(executed_tag);
  if (!provider.lock ||
      (!drain_pending && !provider.has_work.load(std::memory_order_acquire)))
    return;
  // Throttle shared-code service so durable recovery work does not query the
  // clock or broker on every traced instruction.
  if (!drain_pending &&
      provider.service_checks.fetch_add(1, std::memory_order_relaxed) %
          service_check_interval)
    return;
  const uint64_t now = dr_get_microseconds();
  if (!drain_pending &&
      now < provider.next_service.load(std::memory_order_relaxed))
    return;
  if (!current_image() ||
      provider.servicing.exchange(true, std::memory_order_acquire))
    return;
  provider.service_offers = 0;
  ct_shared_channel *channel = channel_for(context);
  release_retired(channel);
  size_t reconstructed_bytes = 0;
  if (!drain_pending && provider.demand_pending.load(std::memory_order_acquire))
    service_demands(channel, reconstructed_bytes);
  // Generic READY storage is bounded by capacity, not a source tag or timer.
  // Different source/policy/level proofs may reuse byte-identical backing only
  // after their own emission passes all proof and exact-byte checks.
  dr_mutex_lock(provider.lock);
  provider.consumed_ready_nodes.clear();
  if (drain_pending) {
    for (const auto &entry : provider.ready) {
      entry.second->retired.store(true, std::memory_order_release);
      queue_retired(entry.second);
    }
    provider.ready.clear();
  }
  provider.in_flight.swap(provider.pending);
  provider.aliases_in_flight.swap(provider.aliases);
  dr_mutex_unlock(provider.lock);
  release_retired(channel);

  while (!provider.aliases_in_flight.empty()) {
    const SharedDRAlias association = provider.aliases_in_flight.back();
    if (channel && provider.current(association.tag, association.incarnation,
                                    association.generation)) {
      ct_shared_dr_member_result advertised{};
      advertised.result.fd = -1;
      if (ct_shared_dr_member_bind_to(
              channel, &association.key, association.provenance.data(),
              association.body.data(), association.object, &advertised)) {
        // This temporary acknowledgement does not replace the execution view's
        // prepaid reference. A retired view simply produces ABSENT.
        release_result(channel, advertised.result);
      }
    }
    dr_mutex_lock(provider.lock);
    provider.aliases_in_flight.pop_back();
    dr_mutex_unlock(provider.lock);
  }

  // Neither lookup waits for an in-progress producer. The callbacks that
  // generate IR only enqueue bounded byte prefixes and never enter this IPC.
  for (auto &entry : provider.in_flight) {
    auto &body = *entry.second;
    body.replay_ready = 0;
    body.replay_busy = false;
    for (size_t index = 0; index < body.work.size();) {
      const auto &work = body.work[index];
      const bool valid =
          !drain_pending && channel && !provider.stopping.load() &&
          provider.current(work.tag, work.incarnation, work.generation);
      auto status =
          valid ? replay_status(work) : DR_SHARED_FRAGMENT_REBIND_ABSENT;
      if (status == DR_SHARED_FRAGMENT_REBIND_RESTORABLE)
        status = validate_candidate(work, body.code.data(), body.code.size(),
                                    body.code_size);
      if (!valid || (status == DR_SHARED_FRAGMENT_REBIND_AVAILABLE &&
                     acquire_member(channel, work))) {
        body.work.erase(body.work.begin() + index);
        continue;
      }
      if (status == DR_SHARED_FRAGMENT_REBIND_AVAILABLE) {
        std::swap(body.work[body.replay_ready], body.work[index]);
        ++body.replay_ready;
      } else {
        body.replay_busy |= status == DR_SHARED_FRAGMENT_REBIND_BUSY;
      }
      ++index;
    }
  }

  const size_t page = dr_page_size();
  for (auto candidate = provider.in_flight.begin();
       candidate != provider.in_flight.end();) {
    if (!candidate->second->replay_ready) {
      ++candidate;
      continue;
    }
    provider.batch_bodies.clear();
    std::vector<ct_shared_dr_compact_member>().swap(provider.batch_members);
    std::vector<ct_shared_dr_relocation>().swap(provider.batch_relocations);
    std::vector<byte>().swap(provider.batch_code);
    std::vector<byte>().swap(provider.batch_index);
    const uint32_t isa = candidate->second->isa;
    size_t available = ready_limit;
    size_t rx_end = 0, private_end = 0, relocation_count = 0;
    // These survive fork-safe catalog waits below. Keep ownership visible to
    // child cleanup if the service thread does not survive the fork.
    auto &bindings = provider.batch_bindings;
    auto &best_placements = provider.batch_best_placements;
    bindings.clear();
    best_placements.clear();
    for (; candidate != provider.in_flight.end(); ++candidate) {
      auto &body = *candidate->second;
      if (!body.replay_ready)
        continue;
      const size_t index_size = sizeof(ct_shared_dr_compact_header) +
                                (provider.batch_bodies.size() + 1) *
                                    sizeof(ct_shared_dr_compact_member) +
                                (relocation_count + body.relocations.size()) *
                                    sizeof(ct_shared_dr_relocation);
      const size_t rx_span = (body.code.size() + 15) & ~size_t(15);
      const size_t private_span = (body.private_size + 15) & ~size_t(15);
      if ((!provider.packing && !provider.batch_bodies.empty()) ||
          body.isa != isa || !available || index_size > pending_limit ||
          rx_span > pending_limit - rx_end ||
          private_span > pending_limit - private_end)
        break;
      const size_t count = std::min(available, body.replay_ready);
      available -= count;
      bindings.push_back(count);
      provider.batch_bodies.push_back(&body);
      rx_end += rx_span;
      private_end += private_span;
      relocation_count += body.relocations.size();
    }
    if (provider.batch_bodies.empty()) {
      if (candidate != provider.in_flight.end())
        ++candidate;
      continue;
    }
    const auto layout =
        evaluate_batch(provider.batch_bodies, bindings, page, provider.packing);
    if (!layout.bindings || layout.execution == SIZE_MAX) {
      ++provider.rejected_cost;
      continue;
    }
    const size_t original = layout.original, retained = layout.retained,
                 working = layout.working, best_rx = layout.rx,
                 best_private = layout.private_size, best_index = layout.index,
                 best_mappings = layout.mappings, best_members = layout.members,
                 best_steady = layout.steady, best_staging = layout.staging,
                 best_cost = best_steady + best_staging;
    best_placements.resize(bindings.size());
    for (size_t i = 0; i < bindings.size(); ++i)
      best_placements[i] =
          provider.packing ? (bindings[i] + layout.rows - 1) / layout.rows : 1;
    if (provider.candidate_statistics) {
      ct_output_printf(
          "ctrace DR candidate: pid=%llu group=%llu original=%zu cost=%zu "
          "steady=%zu staging=%zu replacement_peak=%zu "
          "executable=%zu "
          "types=%zu rows=%zu code=%zu binding=%zu index=%zu retained=%zu "
          "working=%zu\n",
          static_cast<unsigned long long>(provider.process),
          static_cast<unsigned long long>(provider.published +
                                          provider.rejected_cost),
          original, best_cost, best_steady, best_staging, original + best_cost,
          layout.execution, provider.batch_bodies.size(), best_mappings,
          best_rx, best_private, best_index, retained, working);
      for (size_t i = 0; i < provider.batch_bodies.size(); ++i) {
        const auto &body = *provider.batch_bodies[i];
        size_t body_original = 0, body_retained = 0;
        for (size_t j = 0; j < bindings[i]; ++j) {
          body_original += body.work[j].original_private;
          body_retained += retained_work_cost(body.work[j]);
        }
        ct_output_printf(
            "ctrace DR candidate body: pid=%llu group=%llu body=%zu count=%zu "
            "content=%zu private=%zu relocations=%zu original=%zu retained=%zu "
            "working=%zu placements=%zu\n",
            static_cast<unsigned long long>(provider.process),
            static_cast<unsigned long long>(provider.published +
                                            provider.rejected_cost),
            i, bindings[i], body.code.size(), body.private_size,
            body.relocations.size(), body_original, body_retained,
            pending_cost(body), best_placements[i]);
      }
    }
    if (original > provider.largest_original) {
      provider.largest_original = original;
      provider.largest_cost = best_cost;
      provider.largest_count = layout.bindings;
      provider.largest_rx =
          best_rx +
          (sizeof(ct_shared_envelope) + best_index + page - 1) / page * page;
      provider.largest_private = best_mappings * best_private;
      provider.largest_retained = retained;
      provider.largest_pending = working + best_rx + 2 * best_index -
                                 sizeof(ct_shared_dr_compact_header);
      provider.largest_rows = best_mappings;
      provider.largest_members = best_members;
      provider.largest_body_types = provider.batch_bodies.size();
      provider.largest_index = best_index;
      provider.largest_working = working;
      provider.largest_code = best_rx;
      provider.largest_binding_extent = best_private;
      provider.largest_steady = best_steady;
      provider.largest_replacement_peak = original + best_cost;
    }
    // Publish eligible singleton bodies too. Initial page rounding may exceed
    // this image's old footprint; another address space must still be able to
    // acquire these exact pages. The recorded costs make no future-saving
    // claim.
    provider.original_bytes += original;
    provider.retained_bytes += best_steady;
    provider.batch_code.assign(best_rx, 0);
    provider.batch_members.reserve(best_members);
    provider.batch_relocations.reserve(
        (best_index - sizeof(ct_shared_dr_compact_header) -
         best_members * sizeof(ct_shared_dr_compact_member)) /
        sizeof(ct_shared_dr_relocation));
    rx_end = private_end = 0;
    for (size_t i = 0; i < best_placements.size(); ++i) {
      const auto &body = *provider.batch_bodies[i];
      for (size_t copy = 0; copy < best_placements[i]; ++copy) {
        ct_shared_dr_compact_member member{};
        std::memcpy(member.identity, body.body.data(), 32);
        member.offset = rx_end;
        member.size = body.code.size();
        member.private_offset = private_end;
        member.private_size = body.private_size;
        member.prototype_private_offset = body.code_size;
        member.relocation_index = provider.batch_relocations.size();
        member.relocation_count = body.relocations.size();
        std::memcpy(provider.batch_code.data() + member.offset,
                    body.code.data(), body.code.size());
        for (const auto &relocation : body.relocations) {
          int64_t value = int64_t(best_rx) + member.private_offset -
                          member.offset + relocation.target_offset;
          if (relocation.kind == 2)
            value -= int64_t(relocation.field_offset) + 4;
          const uint32_t encoded = uint32_t(value);
          std::memcpy(provider.batch_code.data() + member.offset +
                          relocation.field_offset,
                      &encoded, 4);
        }
        provider.batch_members.push_back(member);
        provider.batch_relocations.insert(provider.batch_relocations.end(),
                                          body.relocations.begin(),
                                          body.relocations.end());
        rx_end += (member.size + 15) & ~size_t(15);
        private_end += (member.private_size + 15) & ~size_t(15);
      }
    }
    ct_shared_dr_compact_header header{};
    std::memcpy(header.magic, "CTDRCMP1", 8);
    header.version = 1;
    header.isa_mode = isa;
    header.count = provider.batch_members.size();
    header.relocation_count = provider.batch_relocations.size();
    header.code_size = best_rx;
    header.private_size = best_private;
    provider.batch_index.resize(best_index);
    std::memcpy(provider.batch_index.data(), &header, sizeof(header));
    std::memcpy(provider.batch_index.data() + sizeof(header),
                provider.batch_members.data(),
                provider.batch_members.size() *
                    sizeof(provider.batch_members[0]));
    std::memcpy(provider.batch_index.data() + sizeof(header) +
                    provider.batch_members.size() *
                        sizeof(provider.batch_members[0]),
                provider.batch_relocations.data(),
                provider.batch_relocations.size() *
                    sizeof(provider.batch_relocations[0]));
    ct_shared_key key{};
    ct_shared_file file{};
    file.fd = -1;
    if (!ct_shared_dr_compact_create(provider.batch_index.data(),
                                     provider.batch_index.size(),
                                     provider.batch_code.data(),
                                     provider.batch_code.size(), &key, &file))
      continue;
    ct_shared_result publication{};
    publication.fd = -1;
    if (ct_shared_acquire(channel, &key, &publication)) {
      if (publication.status == CT_SHARED_CREATE) {
        const uint64_t lease = publication.token;
        if (!ct_shared_publish(channel, lease, &file, &publication))
          ct_shared_fail(channel, lease);
      }
      if (publication.status == CT_SHARED_READY) {
        ++provider.published;
        for (size_t index = 0; index < provider.batch_bodies.size(); ++index) {
          auto &body = *provider.batch_bodies[index];
          const auto end = body.work.begin() + bindings[index];
          const auto remaining = std::remove_if(
              body.work.begin(), end, [&](const SharedDRWork &work) {
                const auto status = replay_status(work);
                body.replay_busy |= status == DR_SHARED_FRAGMENT_REBIND_BUSY;
                return (status == DR_SHARED_FRAGMENT_REBIND_AVAILABLE ||
                        status == DR_SHARED_FRAGMENT_REBIND_RESTORABLE) &&
                       acquire_member(channel, work,
                                      publication.object.object_id);
              });
          body.replay_ready -= end - remaining;
          body.work.erase(remaining, end);
        }
      }
    }
    ct_shared_file_close(&file);
    release_result(channel, publication);
  }
  provider.batch_bodies.clear();
  std::vector<size_t>().swap(provider.batch_bindings);
  std::vector<size_t>().swap(provider.batch_best_placements);
  std::vector<ct_shared_dr_compact_member>().swap(provider.batch_members);
  std::vector<ct_shared_dr_relocation>().swap(provider.batch_relocations);
  std::vector<byte>().swap(provider.batch_index);
  std::vector<byte>().swap(provider.batch_code);
  // Quiet singletons expire, but repeated current AVAILABLE cohorts retain
  // their template until capacity pressure. Otherwise a slow instrumentation
  // pass loses one useful body just before its observed peer becomes ready.
  dr_mutex_lock(provider.lock);
  provider.pending_bytes = 0;
  for (auto &entry : provider.in_flight) {
    auto &body = *entry.second;
    if (!body.work.empty() && !drain_pending &&
        (body.replay_ready > 1 || body.replay_busy || now <= body.updated ||
         now - body.updated < pending_age_us)) {
      provider.pending_bytes += pending_cost(body);
      provider.pending.emplace(entry.first, std::move(entry.second));
    }
  }
  provider.in_flight.clear();
  if (drain_pending)
    std::vector<SharedDRWork>().swap(provider.observed);
  dr_mutex_unlock(provider.lock);
  if (!drain_pending) {
    if (provider.demand_pending.load(std::memory_order_acquire))
      service_demands(channel, reconstructed_bytes);
    if (!provider.demand_pending.load(std::memory_order_acquire))
      discover_ready(channel, now, &reconstructed_bytes);
  }
  clear_discovery_storage();
  const auto before_count =
      provider.anchor_revision.load(std::memory_order_relaxed);
  const size_t live_anchors = dr_shared_fragment_pending_count();
  dr_mutex_lock(provider.lock);
  if (live_anchors == 0) {
    for (const auto &entry : provider.ready) {
      if (!entry.second->retired.exchange(true, std::memory_order_acq_rel))
        queue_retired(entry.second);
    }
    provider.ready.clear();
  }
  provider.has_work.exchange(false, std::memory_order_acq_rel);
  if (!provider.pending.empty() || !provider.aliases.empty() ||
      !provider.observed.empty() || live_anchors != 0 ||
      provider.demand_pending.load(std::memory_order_acquire) ||
      provider.anchor_revision.load(std::memory_order_relaxed) !=
          before_count ||
      provider.retired.load(std::memory_order_acquire))
    provider.has_work.store(true, std::memory_order_release);
  provider.next_service.store(now + pending_age_us, std::memory_order_relaxed);
  const size_t pending_bytes = provider.pending_bytes;
  const size_t observed_bytes =
      provider.observed.capacity() * sizeof(SharedDRWork);
  const size_t staging_bytes =
      provider.batch_code.capacity() + provider.batch_index.capacity() +
      provider.batch_members.capacity() * sizeof(ct_shared_dr_compact_member) +
      provider.batch_relocations.capacity() * sizeof(ct_shared_dr_relocation);
  provider.servicing.store(false, std::memory_order_release);
  dr_mutex_unlock(provider.lock);
  if (provider.candidate_statistics)
    ct_output_printf("ctrace DR preparation released: pid=%llu staging=%zu "
                     "pending=%zu observed=%zu\n",
                     static_cast<unsigned long long>(provider.process),
                     staging_bytes, pending_bytes, observed_bytes);
}

static void thread_exit(void *context) {
  if (!current_image() || provider.tls < 0)
    return;
  auto *holder = static_cast<SharedDRChannel *>(
      drmgr_get_tls_field(context, provider.tls));
  if (!holder)
    return;
  dr_mutex_lock(provider.lock);
  auto **entry = &provider.channels;
  while (*entry && *entry != holder)
    entry = &(*entry)->next;
  if (*entry)
    *entry = holder->next;
  drmgr_set_tls_field(context, provider.tls, nullptr);
  dr_mutex_unlock(provider.lock);
  if (holder->channel)
    ct_shared_close_quiescent(holder->channel);
  delete holder;
}

bool ct_dr_shared_init(ct_dr_shared_current current,
                       ct_dr_shared_current_try current_try) {
  const char *setting = std::getenv("CTRACE_DR_SHARING");
  const char *packing = std::getenv("CTRACE_DR_PACKING");
  if ((setting && !std::strcmp(setting, "0")) || !current || !current_try ||
      dr_page_size() != 4096)
    return false;
  provider.packing = !packing || std::strcmp(packing, "0");
  provider.session = ct_shared_platform_session();
  if (!provider.session)
    return false;
  provider.process = static_cast<uint64_t>(syscall(SYS_getpid));
  provider.statistics = std::getenv("CTRACE_LAZY_STATS") != nullptr ||
                        std::getenv("CTRACE_DR_SHARING_STATS") != nullptr;
  provider.candidate_statistics =
      ct_output_trace_enabled() &&
      std::getenv("CTRACE_DR_SHARING_CANDIDATES") != nullptr;
  provider.current = current;
  provider.current_try = current_try;
  provider.lock = dr_mutex_create();
  provider.tls = drmgr_register_tls_field();
  provider.note = drmgr_reserve_note_range(5);
  if (!provider.lock || provider.tls < 0 || provider.note == DRMGR_NOTE_NONE) {
    if (provider.tls >= 0)
      drmgr_unregister_tls_field(provider.tls);
    if (provider.lock)
      dr_mutex_destroy(provider.lock);
    provider.tls = -1;
    provider.lock = nullptr;
    provider.note = DRMGR_NOTE_NONE;
    provider.session = 0;
    return false;
  }
  dr_shared_fragment_provider_t callbacks{};
  callbacks.struct_size = sizeof(callbacks);
  callbacks.request = request;
  callbacks.file_finished = file_finished;
  callbacks.retired = retired;
  callbacks.pack_small_fragments = true;
  callbacks.compact_private_bindings = true;
  callbacks.require_private_saving = true;
  callbacks.candidate = candidate;
  callbacks.capture_proof = capture_proof;
  callbacks.restore_layout = restore_layout;
  if (!drmgr_register_thread_exit_event(thread_exit) ||
      !dr_register_shared_fragment_provider(&callbacks)) {
    drmgr_unregister_thread_exit_event(thread_exit);
    drmgr_unregister_tls_field(provider.tls);
    provider.tls = -1;
    dr_mutex_destroy(provider.lock);
    provider.lock = nullptr;
    provider.note = DRMGR_NOTE_NONE;
    provider.session = 0;
    return false;
  }
  return true;
}

void ct_dr_shared_fork_prepare(void *context,
                               std::vector<uint64_t> &published_objects) {
  if (!provider.lock || !current_image())
    return;
  provider.fork_context = context;
  provider.fork_pending = true;
  for (auto *token = provider.tokens; token; token = token->next) {
    token->fork_pinned = token->adopted.load(std::memory_order_acquire) &&
                         !token->retired.load(std::memory_order_acquire);
    if (token->fork_pinned)
      published_objects.push_back(token->backing->object);
  }
}

void ct_dr_shared_fork_parent_done(void *context) {
  if (provider.fork_context == context && current_image()) {
    provider.fork_pending = false;
    provider.fork_context = nullptr;
  }
}

void ct_dr_shared_fork_child(void *context) {
  if (!provider.lock || !regular_fork_child())
    return;
  const uint64_t session = ct_shared_platform_session();
  if (!session || session == provider.session)
    return;
  dr_mutex_reset_after_fork(provider.lock);
  provider.session = session;
  provider.process = static_cast<uint64_t>(syscall(SYS_getpid));
  provider.retired.store(nullptr, std::memory_order_relaxed);
  provider.pending.clear();
  clear_discovery_storage();
  provider.in_flight.clear();
  provider.batch_bodies.clear();
  std::vector<size_t>().swap(provider.batch_bindings);
  std::vector<size_t>().swap(provider.batch_best_placements);
  std::vector<ct_shared_dr_compact_member>().swap(provider.batch_members);
  std::vector<ct_shared_dr_relocation>().swap(provider.batch_relocations);
  std::vector<byte>().swap(provider.batch_index);
  std::vector<byte>().swap(provider.batch_code);
  provider.ready.clear();
  provider.consumed_ready_nodes.clear();
  provider.aliases.clear();
  provider.aliases_in_flight.clear();
  provider.pending_bytes = 0;
  provider.scanned_sequence = provider.scanned_revision = 0;
  provider.recent_resume = {};
  for (auto &demand : provider.demands) {
    demand.tag.store(nullptr, std::memory_order_relaxed);
    demand.sequence.store(0, std::memory_order_relaxed);
    demand.seen = 0;
  }
  provider.demand_pending.store(false, std::memory_order_relaxed);
  provider.demand_overwrite.store(0, std::memory_order_relaxed);
  provider.demand_cursor = 0;
  provider.scanning = provider.discovery_retry = false;
  provider.anchor_cursor = 0;
  provider.recovery_count = provider.recovery_cursor = 0;
  provider.scanned_anchor_revision = 0;
  provider.next_recovery_sweep = 0;
  for (auto &entry : provider.backings) {
    entry.second->references = 0;
    std::fill(entry.second->occupied.begin(), entry.second->occupied.end(), 0);
    for (auto &row : entry.second->reservations)
      row.occupied = 0;
  }
  for (auto *token = provider.tokens; token;) {
    auto *next = token->next;
    if (token->fork_pinned) {
      token->process = provider.process;
      token->session = session;
      token->fd = -1;
      token->fork_pinned = false;
      ++token->backing->references;
      if (token->slot != UINT32_MAX) {
        ++token->backing->occupied[token->slot];
        for (auto &row : token->backing->reservations) {
          if (row.instance == token->private_instance) {
            row.occupied |= uint64_t(1) << token->slot;
            break;
          }
        }
      }
      if (token->retired.load(std::memory_order_acquire))
        queue_retired(token);
    } else {
      if (token->previous)
        token->previous->next = token->next;
      else
        provider.tokens = token->next;
      if (token->next)
        token->next->previous = token->previous;
      delete token;
    }
    token = next;
  }
  for (auto entry = provider.backings.begin();
       entry != provider.backings.end();) {
    auto &backing = *entry->second;
    if (!backing.references) {
      release_backing_mappings(backing);
      entry = provider.backings.erase(entry);
    } else {
      backing.reservations.erase(
          std::remove_if(backing.reservations.begin(),
                         backing.reservations.end(),
                         [](const SharedDRBacking::Reservation &row) {
                           return row.occupied == 0;
                         }),
          backing.reservations.end());
      ++entry;
    }
  }
  auto *holder = provider.channels;
  while (holder) {
    auto *next = holder->next;
    if (holder->channel)
      ct_shared_fork_forget_channel(holder->channel);
    delete holder;
    holder = next;
  }
  provider.channels = nullptr;
  drmgr_set_tls_field(context, provider.tls, nullptr);
  provider.servicing.store(false, std::memory_order_release);
  provider.has_work.store(!provider.observed.empty() ||
                              dr_shared_fragment_pending_count() != 0 ||
                              provider.retired.load() != nullptr,
                          std::memory_order_release);
  provider.next_service.store(0, std::memory_order_relaxed);
  provider.fork_context = nullptr;
  provider.fork_pending = false;
}

bool ct_dr_shared_exit(void *context) {
  if (!provider.lock)
    return true;
  const bool owns_channels = current_image();
  provider.stopping.store(true, std::memory_order_release);
  provider.next_service.store(0, std::memory_order_relaxed);
  if (owns_channels)
    ct_dr_shared_service(context, true);
  if (provider.servicing.load(std::memory_order_acquire))
    return false;
  auto *holder = provider.channels;
  while (holder) {
    auto *next = holder->next;
    if (holder->channel) {
      if (owns_channels)
        ct_shared_close_quiescent(holder->channel);
      else
        ct_shared_abandon_channel(holder->channel);
    }
    delete holder;
    holder = next;
  }
  provider.channels = nullptr;
  drmgr_set_tls_field(context, provider.tls, nullptr);
  drmgr_unregister_thread_exit_event(thread_exit);
  drmgr_unregister_tls_field(provider.tls);
  provider.tls = -1;
  if (owns_channels && provider.statistics && ct_output_trace_enabled())
    ct_output_printf(
        "ctrace DR sharing: pid=%llu requests=%llu queued=%llu ready=%llu "
        "adopted=%llu published=%llu rejected_cost=%llu rejected_private=%llu "
        "original_bytes=%llu retained_bytes=%llu rejected_original=%llu "
        "rejected_retained=%llu largest_original=%llu largest_cost=%llu "
        "largest_count=%llu largest_rx=%llu largest_private=%llu "
        "largest_retained=%llu largest_pending=%llu largest_rows=%llu "
        "largest_members=%llu largest_body_types=%llu largest_index=%llu "
        "largest_working=%llu largest_code=%llu largest_binding_extent=%llu "
        "largest_steady=%llu largest_replacement_peak=%llu "
        "promotion_requests=%llu promotion_failures=%llu "
        "reconstruction_attempts=%llu reconstruction_staged=%llu "
        "reconstruction_mismatch=%llu "
        "observed_bytes=%zu last_recipe_slot=%zu "
        "last_recipe_storage=%zu last_recipe_live=%zu\n",
        static_cast<unsigned long long>(provider.process),
        static_cast<unsigned long long>(provider.requests.load()),
        static_cast<unsigned long long>(provider.queued.load()),
        static_cast<unsigned long long>(provider.offers.load()),
        static_cast<unsigned long long>(provider.adopted.load()),
        static_cast<unsigned long long>(provider.published),
        static_cast<unsigned long long>(provider.rejected_cost),
        static_cast<unsigned long long>(provider.rejected_private.load()),
        static_cast<unsigned long long>(provider.original_bytes),
        static_cast<unsigned long long>(provider.retained_bytes),
        static_cast<unsigned long long>(provider.rejected_original),
        static_cast<unsigned long long>(provider.rejected_retained),
        static_cast<unsigned long long>(provider.largest_original),
        static_cast<unsigned long long>(provider.largest_cost),
        static_cast<unsigned long long>(provider.largest_count),
        static_cast<unsigned long long>(provider.largest_rx),
        static_cast<unsigned long long>(provider.largest_private),
        static_cast<unsigned long long>(provider.largest_retained),
        static_cast<unsigned long long>(provider.largest_pending),
        static_cast<unsigned long long>(provider.largest_rows),
        static_cast<unsigned long long>(provider.largest_members),
        static_cast<unsigned long long>(provider.largest_body_types),
        static_cast<unsigned long long>(provider.largest_index),
        static_cast<unsigned long long>(provider.largest_working),
        static_cast<unsigned long long>(provider.largest_code),
        static_cast<unsigned long long>(provider.largest_binding_extent),
        static_cast<unsigned long long>(provider.largest_steady),
        static_cast<unsigned long long>(provider.largest_replacement_peak),
        static_cast<unsigned long long>(provider.promotion_requests),
        static_cast<unsigned long long>(provider.promotion_failures),
        static_cast<unsigned long long>(provider.reconstruction_attempts),
        static_cast<unsigned long long>(provider.reconstruction_staged),
        static_cast<unsigned long long>(provider.reconstruction_mismatch),
        provider.observed.capacity() * sizeof(SharedDRWork),
        provider.recipe_slot, provider.recipe_storage, provider.recipe_live);
  // DR can still retire adopted fragments after the client exit event. Their
  // tokens and read-only metadata must outlive drmgr and remain valid until
  // process-image teardown closes the remaining catalog references.
  // Those callbacks only touch the retained tokens and atomic retirement
  // queue. New requests decline while stopping, so none needs this mutex.
  dr_mutex_destroy(provider.lock);
  provider.lock = nullptr;
  return true;
}
