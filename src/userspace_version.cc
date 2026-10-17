#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <type_traits>
#include <vector>

#include <dr_api.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "analysis.h"
#include "userspace_version.h"
#include "userspace_version_cache.h"

struct UserspaceVersionNode {
  struct {
    uint64_t offset = 0, length = 0;
    byte bytes[15]{};
    uint8_t boundary = 0;
  } original;
  uint64_t ingress = 0, entry = 0, operation = 0, encoded_length = 0;
  uint64_t successor = 0, private_operation = 0;
  int64_t relative_target = 0;
  uint8_t relative_offset = 0;
  byte relative_encoding[15]{};
  uint8_t gate = 0, dr_only = 0, branch = 0, fallthrough = 0;
  uint8_t relative = 0;
  byte reserved[3]{};
};
static_assert(sizeof(UserspaceVersionNode) == 112 &&
              std::is_trivially_copyable_v<UserspaceVersionNode>);

struct UserspaceVersionPreparation {
  byte *scratch = nullptr;
  instrlist_t *decoded_list = nullptr;
  std::vector<ct_userspace_instruction_template> templates;
  std::vector<ct_userspace_template_layout> layout;
  std::vector<instr_t *> decoded;
  std::vector<dr_userspace_pc_mapping_t> mappings;
  std::vector<byte> key_material;
  ct_userspace_template_keys template_keys;
  std::vector<dr_userspace_bound_gate_t> gates;
  std::vector<app_pc> application_pcs;
};

struct ct_userspace_version {
  ct_instrument_level level = ct_instrument_level::arm;
  uint64_t generation = 0;
  app_pc code = nullptr;
  app_pc original_base = nullptr;
  size_t size = 0, code_size = 0;
  size_t used = 0, relative_size = 0, binding_offset = 0, binding_count = 0;
  bool shared_layout = false, shared = false, mapping_failed = false;
  bool artifact_restored = false;
  bool common_restored = false, layout_restored = false;
  size_t decoded_count = 0;
  dr_alloc_flags_t allocation = DR_ALLOC_NON_HEAP;
  dr_userspace_code_t *registration = nullptr;
  std::vector<UserspaceVersionNode> nodes;
  void *metadata = nullptr;
  size_t metadata_size = 0, shared_node_count = 0;
  const UserspaceVersionNode *shared_nodes = nullptr;
  void *creator = nullptr;
  bool published = false;
  ct_userspace_version *next_live = nullptr;
  std::unique_ptr<UserspaceVersionPreparation> preparation;
};

static std::atomic<void *> versions_lock{nullptr};
static ct_userspace_version *live_versions;
// A hint only: current mappings and operand reach are checked before every
// allocation. Atomic publication permits unrelated producers to prepare in
// parallel; collisions simply take the normal free-region search.
static std::atomic<uintptr_t> allocation_hint{0};

static void *version_registry_lock() {
  void *lock = versions_lock.load(std::memory_order_acquire);
  if (!lock) {
    void *created = dr_mutex_create();
    if (!versions_lock.compare_exchange_strong(lock, created,
                                               std::memory_order_acq_rel))
      dr_mutex_destroy(created);
    else
      lock = created;
  }
  return lock;
}

void ct_userspace_version_init() { version_registry_lock(); }

bool ct_userspace_version_exit() {
  void *lock = versions_lock.load(std::memory_order_acquire);
  if (!lock)
    return true;
  dr_mutex_lock(lock);
  if (live_versions) {
    dr_mutex_unlock(lock);
    return false;
  }
  // The exit caller has stopped all producers. No version destructor can
  // still acquire this lock once the registry is empty.
  versions_lock.store(nullptr, std::memory_order_release);
  dr_mutex_unlock(lock);
  dr_mutex_destroy(lock);
  return true;
}

static ct_userspace_version *new_version(void *context) {
  void *lock = version_registry_lock();
  dr_mutex_lock(lock);
  auto *version = new ct_userspace_version;
  version->preparation = std::make_unique<UserspaceVersionPreparation>();
  version->creator = context;
  version->next_live = live_versions;
  live_versions = version;
  dr_mutex_unlock(lock);
  return version;
}

static const UserspaceVersionNode *
version_nodes(const ct_userspace_version *version) {
  return version->shared_nodes ? version->shared_nodes : version->nodes.data();
}

static size_t version_node_count(const ct_userspace_version *version) {
  return version->shared_nodes ? version->shared_node_count
                               : version->nodes.size();
}

static app_pc original_address(const ct_userspace_version *version,
                               const UserspaceVersionNode &node) {
  return version->original_base + node.original.offset;
}

// Shared by entry lookup, relocation planning, and original-byte lookup.
static const UserspaceVersionNode *
version_node(const ct_userspace_version *version, app_pc pc) {
  if (!version || version->mapping_failed)
    return nullptr;
  const size_t count = version_node_count(version);
  if (!count || pc < version->original_base)
    return nullptr;
  const auto *nodes = version_nodes(version);
  const uint64_t offset = pc - version->original_base;
  auto found = std::lower_bound(nodes, nodes + count, offset,
                                [](const auto &node, uint64_t address) {
                                  return node.original.offset < address;
                                });
  return found != nodes + count && found->original.offset == offset ? found
                                                                    : nullptr;
}

static bool allocate_version(ct_userspace_version *version, std::string &error,
                             bool ready = false) {
  const size_t page_size = dr_page_size();
  // Intersect every RIP-relative operand's legal displacement range. A single
  // nearby allocation preserves the original memory operands and fault context.
  // Shared bodies use private islands for these address-dependent operations.
  uintptr_t lower = page_size;
  uintptr_t upper = std::numeric_limits<intptr_t>::max();
  bool relative = false;
  for (size_t index = 0; index < version_node_count(version); ++index) {
    const auto &node = version_nodes(version)[index];
    if (!node.relative)
      continue;
    relative = true;
    const __int128 target =
        __int128(reinterpret_cast<uintptr_t>(original_address(version, node))) +
        node.relative_target;
    const __int128 end_offset =
        (version->shared_layout ? node.private_operation : node.operation) +
        node.encoded_length;
    const __int128 minimum = target - end_offset - INT32_MAX;
    const __int128 maximum = target - end_offset - INT32_MIN;
    if (minimum > upper || maximum < lower) {
      error = "RIP-relative operands have no common allocation range";
      return false;
    }
    lower = uintptr_t(std::max<__int128>(lower, minimum));
    upper = uintptr_t(std::min<__int128>(upper, maximum));
  }
  if (relative) {
    version->allocation =
        dr_alloc_flags_t(DR_ALLOC_NON_HEAP | DR_ALLOC_FIXED_LOCATION);
    lower = (lower + page_size - 1) / page_size * page_size;
    if (lower > upper) {
      error = "RIP-relative allocation range contains no aligned address";
      return false;
    }
    const uintptr_t preferred =
        std::clamp(reinterpret_cast<uintptr_t>(version->original_base) /
                       page_size * page_size,
                   lower, upper);
    const uintptr_t observed_hint =
        allocation_hint.load(std::memory_order_relaxed);
    const uintptr_t hint = observed_hint >= lower && observed_hint <= upper &&
                                   version->size <= UINTPTR_MAX - observed_hint
                               ? observed_hint
                               : preferred;
    for (uintptr_t start : {hint, preferred, lower}) {
      for (uintptr_t cursor = start; cursor <= upper;) {
        dr_mem_info_t memory{};
        if (!dr_query_memory_ex(reinterpret_cast<app_pc>(cursor), &memory) ||
            !memory.size ||
            memory.size > UINTPTR_MAX - uintptr_t(memory.base_pc))
          break;
        const uintptr_t end = uintptr_t(memory.base_pc) + memory.size;
        if (memory.type == DR_MEMTYPE_FREE && end > cursor &&
            version->size <= end - cursor) {
          version->code = static_cast<app_pc>(
              dr_custom_alloc(nullptr, version->allocation, version->size,
                              DR_MEMPROT_READ | DR_MEMPROT_WRITE,
                              reinterpret_cast<void *>(cursor)));
          if (version->code)
            break;
        }
        if (end <= cursor || end > UINTPTR_MAX - page_size + 1)
          break;
        cursor = (end + page_size - 1) / page_size * page_size;
      }
      if (version->code)
        break;
    }
  } else {
    version->code = static_cast<app_pc>(
        dr_custom_alloc(nullptr, version->allocation, version->size,
                        DR_MEMPROT_READ | DR_MEMPROT_WRITE, nullptr));
  }
  if (!version->code) {
    error = "no safe executable allocation for userspace relocation";
    return false;
  }

  // Unconstrained bodies can be far from application code. Preserve the last
  // useful relative hint so they do not restart the nearby mapping search.
  if (relative)
    allocation_hint.store(uintptr_t(version->code) + version->size,
                          std::memory_order_relaxed);
  // READY replaces the entire RX prefix with sealed pages before publication.
  // Do not fault in anonymous copies of pages that are immediately discarded.
  const size_t untouched = ready ? version->code_size : 0;
  std::memset(version->code + untouched, 0, version->size - untouched);
  return true;
}

static bool register_version(ct_userspace_version *version,
                             std::string &error) {
  auto &mappings = version->preparation->mappings;
  mappings.clear();
  for (size_t index = 0; index < version_node_count(version); ++index) {
    const auto &node = version_nodes(version)[index];
    if (node.dr_only)
      continue;
    const app_pc original = original_address(version, node);
    mappings.push_back(
        {node.operation,
         version->shared_layout && node.relative ? 5 : node.encoded_length,
         original});
    // The ENDBR landing and its following JMP both restore the same original
    // PC. One contiguous range preserves every lookup while avoiding a second
    // private registry record per instruction.
    mappings.push_back({node.entry, 9, original});
    if (version->shared_layout && node.relative) {
      mappings.push_back(
          {node.private_operation, node.encoded_length, original});
      mappings.push_back({node.private_operation + node.encoded_length, 5,
                          original + node.original.length});
    }
  }
  std::sort(mappings.begin(), mappings.end(),
            [](const auto &left, const auto &right) {
              return left.offset < right.offset;
            });
  if (version->shared_layout &&
      !dr_memory_protect(version->code + version->binding_offset,
                         version->size - version->binding_offset,
                         DR_MEMPROT_READ)) {
    error = "userspace address bindings cannot be made read-only";
    return false;
  }
  if (!dr_memory_protect(version->code,
                         version->code_size + version->relative_size,
                         DR_MEMPROT_READ | DR_MEMPROT_EXEC)) {
    error = "userspace code cannot be made read-only and executable";
    return false;
  }
  version->registration = dr_register_userspace_code(
      version->code,
      version->relative_size ? version->code_size + version->relative_size
                             : version->used,
      mappings.data(), mappings.size(), version->generation);
  if (!version->registration) {
    error = "userspace code PC mapping registration failed";
    return false;
  }
  std::vector<dr_userspace_pc_mapping_t>().swap(mappings);
  return true;
}

static bool bind_private_state(ct_userspace_version *version,
                               std::string &error, bool encode_gates = false) {
  auto *bindings =
      reinterpret_cast<app_pc *>(version->code + version->binding_offset);
  auto &gates = version->preparation->gates;
  auto &applications = version->preparation->application_pcs;
  gates.clear();
  applications.clear();
  for (size_t index = 0; index < version_node_count(version); ++index) {
    const auto &node = version_nodes(version)[index];
    const app_pc original = original_address(version, node);
    if (node.gate) {
      gates.push_back({node.ingress, original});
      applications.push_back(original);
    }
    if (node.dr_only)
      continue;
    if (node.relative) {
      byte *encoded = version->code + node.private_operation;
      std::memcpy(encoded, node.relative_encoding, node.encoded_length);
      const __int128 displacement =
          __int128(reinterpret_cast<uintptr_t>(original)) +
          node.relative_target - reinterpret_cast<uintptr_t>(encoded) -
          node.encoded_length;
      if (displacement < INT32_MIN || displacement > INT32_MAX) {
        error = "shared userspace private relocation is out of reach";
        return false;
      }
      const int32_t target = int32_t(displacement);
      std::memcpy(encoded + node.relative_offset, &target, sizeof(target));
      encoded[node.encoded_length] = 0xe9;
      const int32_t back =
          int32_t(int64_t(node.successor) -
                  int64_t(node.private_operation + node.encoded_length + 5));
      std::memcpy(encoded + node.encoded_length + 1, &back, sizeof(back));
    }
    const app_pc successor = original + node.original.length;
    if (node.fallthrough && !version_node(version, successor)) {
      gates.push_back({node.successor, successor});
      applications.push_back(successor);
    }
  }
  if (applications.size() + 1 != version->binding_count ||
      !(encode_gates
            ? dr_encode_userspace_bound_gates(version->code, version->code_size,
                                              gates.data(), gates.size(),
                                              bindings + 1, bindings)
            : dr_bind_userspace_gate_slots_bulk(applications.data(),
                                                applications.size(),
                                                bindings + 1, bindings))) {
    error = "shared userspace gateway batch binding failed";
    return false;
  }
  std::vector<dr_userspace_bound_gate_t>().swap(gates);
  std::vector<app_pc>().swap(applications);

  return true;
}

struct UserspaceVersionArchive {
  uint64_t magic = UINT64_C(0x3152414853455355);
  uint64_t schema = 1, header_size = sizeof(UserspaceVersionArchive);
  uint64_t node_size = sizeof(UserspaceVersionNode), node_count = 0;
  uint64_t page_size = 0, gate_size = 26, used = 0, code_size = 0;
  uint64_t relative_size = 0, binding_offset = 0, binding_count = 0;
  uint64_t allocation_size = 0, nodes_offset = sizeof(UserspaceVersionArchive);
  uint64_t rx_offset = 0, payload_size = 0;
  ct_shared_key key{};
  byte nodes_digest[32]{}, code_digest[32]{}, header_digest[32]{};
};
static_assert(std::is_trivially_copyable_v<UserspaceVersionArchive> &&
              sizeof(UserspaceVersionArchive) == 272);

bool ct_userspace_version_shared_key(
    const ct_userspace_version_cache *cache, ct_instrument_level level,
    const ct_userspace_version_instruction *instructions, size_t count,
    ct_shared_key &key, std::string &error) {
  key = {};
  error.clear();
  if (!cache || !cache->identity || !*cache->identity ||
      !cache->runtime_identity || !*cache->runtime_identity ||
      !cache->module_base || !cache->module_size || !instructions || !count ||
      count > 65536 ||
      cache->module_size > UINTPTR_MAX - uintptr_t(cache->module_base) ||
      (level != ct_instrument_level::arm &&
       level != ct_instrument_level::perfetto &&
       level != ct_instrument_level::full)) {
    error = "shared userspace identity is incomplete";
    return false;
  }
  // A digest RPC can become a fork-safe wait. Keep its material in the same
  // registry as unfinished versions so vanished producers leave no heap behind.
  auto scratch = std::unique_ptr<ct_userspace_version,
                                 decltype(&ct_userspace_version_discard)>(
      new_version(dr_get_current_drcontext()), ct_userspace_version_discard);
  auto &material = scratch->preparation->key_material;
  const auto number = [&](uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      material.push_back(byte(value >> shift));
  };
  const auto string = [&](const char *value) {
    const size_t size = value ? std::strlen(value) : 0;
    number(size);
    if (size)
      material.insert(material.end(), value, value + size);
  };
  string("ctrace-userspace-shared-artifact-v1-amd64");
  string(cache->identity);
  string(cache->runtime_identity);
  string(cache->policy);
  number(cache->module_size);
  number(unsigned(level));
  number(dr_page_size());
  number(sizeof(void *));
  number(dr_is_fsgsbase_enabled());
  number(proc_has_feature(FEATURE_AVX));
  number(proc_has_feature(FEATURE_AVX512F));
  number(count);
  uintptr_t previous_end = uintptr_t(cache->module_base);
  for (size_t index = 0; index < count; ++index) {
    const auto &instruction = instructions[index];
    const uintptr_t address = uintptr_t(instruction.pc);
    if (address < previous_end || address < uintptr_t(cache->module_base) ||
        !instruction.length || instruction.length > sizeof(instruction.bytes)) {
      error = "shared userspace original instruction proof is invalid";
      return false;
    }
    const uint64_t offset = address - uintptr_t(cache->module_base);
    if (offset >= cache->module_size ||
        instruction.length > cache->module_size - offset) {
      error = "shared userspace proof exceeds its module";
      return false;
    }
    number(offset);
    number(instruction.length);
    number(instruction.boundary);
    material.insert(material.end(), instruction.bytes,
                    instruction.bytes + instruction.length);
    previous_end = address + instruction.length;
  }
  key.kind = CT_SHARED_USERSPACE_CODE;
  key.schema = 1;
  key.level = unsigned(level);
  if (!ct_analysis_content_digest(material.data(), material.size(),
                                  key.identity)) {
    key = {};
    error = "shared userspace identity digest failed";
    return false;
  }
  return true;
}

bool ct_userspace_version_export(const ct_userspace_version *version,
                                 const ct_shared_key &key,
                                 std::vector<byte> &payload, size_t &rx_offset,
                                 std::string &error) {
  error.clear();
  payload.clear();
  rx_offset = 0;
  if (!version || !version->shared_layout || version->mapping_failed ||
      !version->registration || !version_node_count(version) ||
      key.kind != CT_SHARED_USERSPACE_CODE || key.schema != 1 || key.reserved ||
      key.level != unsigned(version->level)) {
    error = "userspace version cannot be exported";
    return false;
  }
  UserspaceVersionArchive header{};
  header.node_count = version_node_count(version);
  header.page_size = dr_page_size();
  header.used = version->used;
  header.code_size = version->code_size;
  header.relative_size = version->relative_size;
  header.binding_offset = version->binding_offset;
  header.binding_count = version->binding_count;
  header.allocation_size = version->size;
  header.key = key;
  const size_t nodes_size = header.node_count * sizeof(UserspaceVersionNode);
  header.rx_offset = (sizeof(header) + nodes_size + header.page_size - 1) /
                     header.page_size * header.page_size;
  header.payload_size = header.rx_offset + header.code_size;
  if (header.payload_size > 128 * 1024 * 1024 ||
      !ct_analysis_content_digest(version_nodes(version), nodes_size,
                                  header.nodes_digest) ||
      !ct_analysis_content_digest(version->code, header.code_size,
                                  header.code_digest) ||
      !ct_analysis_content_digest(
          &header, offsetof(UserspaceVersionArchive, header_digest),
          header.header_digest)) {
    error = "shared userspace artifact digest failed";
    return false;
  }
  payload.resize(header.payload_size);
  std::memcpy(payload.data(), &header, sizeof(header));
  std::memcpy(payload.data() + header.nodes_offset, version_nodes(version),
              nodes_size);
  std::memcpy(payload.data() + header.rx_offset, version->code,
              header.code_size);
  rx_offset = header.rx_offset;
  return true;
}

bool ct_userspace_version_adopt_metadata(ct_userspace_version *version,
                                         const ct_shared_key &expected_key,
                                         int fd, uint64_t payload_offset,
                                         uint64_t payload_size,
                                         std::string &error) {
  error = "invalid shared userspace producer metadata";
  const size_t page = dr_page_size();
  UserspaceVersionArchive header{};
  struct stat file{};
  constexpr int required =
      F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  const int seals = fd < 0 ? -1 : fcntl(fd, F_GET_SEALS);
  if (!version || !version->shared_layout || version->mapping_failed ||
      version->published || version->metadata || !version->registration ||
      !page || payload_offset % page || payload_size < sizeof(header) ||
      payload_size > 128 * 1024 * 1024 ||
      payload_offset > uint64_t(INT64_MAX) - payload_size || seals < 0 ||
      (seals & required) != required || fstat(fd, &file) != 0 ||
      file.st_size < 0 ||
      uint64_t(file.st_size) < payload_offset + payload_size ||
      pread(fd, &header, sizeof(header), off_t(payload_offset)) !=
          sizeof(header))
    return false;
  const size_t count = version->nodes.size();
  const size_t node_bytes = count * sizeof(UserspaceVersionNode);
  byte digest[32];
  if (header.magic != UINT64_C(0x3152414853455355) || header.schema != 1 ||
      header.header_size != sizeof(header) ||
      header.node_size != sizeof(UserspaceVersionNode) ||
      header.node_count != count || header.page_size != page ||
      header.gate_size != 26 || header.nodes_offset != sizeof(header) ||
      header.rx_offset !=
          (sizeof(header) + node_bytes + page - 1) / page * page ||
      header.payload_size != payload_size || header.used != version->used ||
      header.code_size != version->code_size ||
      header.relative_size != version->relative_size ||
      header.binding_offset != version->binding_offset ||
      header.binding_count != version->binding_count ||
      header.allocation_size != version->size ||
      header.payload_size != header.rx_offset + header.code_size ||
      expected_key.kind != CT_SHARED_USERSPACE_CODE ||
      expected_key.schema != 1 || expected_key.reserved ||
      expected_key.level != unsigned(version->level) ||
      std::memcmp(&header.key, &expected_key, sizeof(expected_key)) ||
      !ct_analysis_content_digest(
          &header, offsetof(UserspaceVersionArchive, header_digest), digest) ||
      std::memcmp(digest, header.header_digest, sizeof(digest)))
    return false;
  // Install ownership before the digest RPC can suspend this producer. Until
  // validation succeeds lookups still use the original private node vector.
  version->metadata_size = header.rx_offset;
  version->metadata = dr_map_file(fd, &version->metadata_size, payload_offset,
                                  nullptr, DR_MEMPROT_READ, 0);
  const auto *nodes = version->metadata
                          ? reinterpret_cast<const UserspaceVersionNode *>(
                                static_cast<const byte *>(version->metadata) +
                                header.nodes_offset)
                          : nullptr;
  const bool valid = nodes && version->metadata_size == header.rx_offset &&
                     !std::memcmp(nodes, version->nodes.data(), node_bytes) &&
                     ct_analysis_content_digest(nodes, node_bytes, digest) &&
                     !std::memcmp(digest, header.nodes_digest, sizeof(digest));
  if (!valid) {
    if (version->metadata &&
        dr_unmap_file(version->metadata, version->metadata_size))
      version->metadata = nullptr;
    return false;
  }
  version->shared_nodes = nodes;
  version->shared_node_count = count;
  std::vector<UserspaceVersionNode>().swap(version->nodes);
  error.clear();
  return true;
}

ct_userspace_version *ct_userspace_version_restore(
    void *context, ct_instrument_level level, uint64_t generation,
    const ct_userspace_version_instruction *instructions, size_t count,
    const ct_shared_key &expected_key, int fd, uint64_t payload_offset,
    uint64_t payload_size, std::string &error) {
  error.clear();
  const auto invalid = [&](const char *reason,
                           size_t index = SIZE_MAX) -> ct_userspace_version * {
    error = std::string("shared userspace artifact: ") + reason;
    if (index != SIZE_MAX)
      error += " at instruction " + std::to_string(index);
    return nullptr;
  };
  const size_t page = dr_page_size();
  constexpr int seals =
      F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  const int actual_seals = fd < 0 ? -1 : fcntl(fd, F_GET_SEALS);
  struct stat file{};
  UserspaceVersionArchive header{};
  if (!context || !generation || !instructions || !count || count > 65536 ||
      !page || payload_offset % page || payload_size < sizeof(header) ||
      payload_size > 128 * 1024 * 1024 ||
      payload_offset > uint64_t(INT64_MAX) - payload_size || actual_seals < 0 ||
      (actual_seals & seals) != seals || fstat(fd, &file) != 0 ||
      file.st_size < 0 ||
      uint64_t(file.st_size) < payload_offset + payload_size ||
      pread(fd, &header, sizeof(header), off_t(payload_offset)) !=
          sizeof(header) ||
      dr_get_isa_mode(context) != DR_ISA_AMD64)
    return invalid("envelope or platform validation");
  byte digest[32];
  if (header.magic != UINT64_C(0x3152414853455355) || header.schema != 1 ||
      header.header_size != sizeof(header) ||
      header.node_size != sizeof(UserspaceVersionNode) ||
      header.node_count != count || header.page_size != page ||
      header.gate_size != 26 || header.nodes_offset != sizeof(header) ||
      header.rx_offset !=
          (sizeof(header) + count * sizeof(UserspaceVersionNode) + page - 1) /
              page * page ||
      header.payload_size != payload_size || !header.used ||
      header.used > header.code_size ||
      header.code_size != (header.used + page - 1) / page * page ||
      header.code_size > payload_size ||
      header.rx_offset != payload_size - header.code_size ||
      header.relative_size % page || header.relative_size > INT32_MAX ||
      header.binding_offset != header.code_size + header.relative_size ||
      !header.binding_count || header.binding_count > count * 2 + 1 ||
      header.allocation_size !=
          header.binding_offset +
              (header.binding_count * sizeof(app_pc) + page - 1) / page *
                  page ||
      header.allocation_size > INT32_MAX ||
      expected_key.kind != CT_SHARED_USERSPACE_CODE ||
      expected_key.schema != 1 || expected_key.reserved ||
      expected_key.level != unsigned(level) ||
      std::memcmp(&header.key, &expected_key, sizeof(expected_key)) ||
      !ct_analysis_content_digest(
          &header, offsetof(UserspaceVersionArchive, header_digest), digest) ||
      std::memcmp(digest, header.header_digest, sizeof(digest)))
    return invalid("header, key, layout or digest validation");
  auto version = std::unique_ptr<ct_userspace_version,
                                 decltype(&ct_userspace_version_discard)>(
      new_version(context), ct_userspace_version_discard);
  version->level = level;
  version->generation = generation;
  version->original_base = instructions[0].pc;
  version->shared_layout = true;
  version->size = header.allocation_size;
  version->used = header.used;
  version->code_size = header.code_size;
  version->relative_size = header.relative_size;
  version->binding_offset = header.binding_offset;
  version->binding_count = header.binding_count;
  version->metadata_size = header.rx_offset;
  version->metadata = dr_map_file(fd, &version->metadata_size, payload_offset,
                                  nullptr, DR_MEMPROT_READ, 0);
  if (!version->metadata || version->metadata_size != header.rx_offset)
    return invalid("metadata mapping failed");
  version->shared_node_count = count;
  version->shared_nodes = reinterpret_cast<const UserspaceVersionNode *>(
      static_cast<const byte *>(version->metadata) + header.nodes_offset);
  if (!ct_analysis_content_digest(version->shared_nodes,
                                  count * sizeof(UserspaceVersionNode),
                                  digest) ||
      std::memcmp(digest, header.nodes_digest, sizeof(digest)))
    return invalid("node digest mismatch");
  uintptr_t previous_end = uintptr_t(version->original_base);
  size_t expected_bindings = 1;
  for (size_t index = 0; index < count; ++index) {
    const auto &node = version->shared_nodes[index];
    const auto &original = instructions[index];
    if (!original.pc || uintptr_t(original.pc) < previous_end ||
        original.length > UINTPTR_MAX - uintptr_t(original.pc) ||
        !node.original.length || node.original.length > 15 ||
        node.original.length != original.length ||
        node.original.boundary != original.boundary ||
        node.original.offset !=
            uintptr_t(original.pc) - uintptr_t(version->original_base) ||
        std::memcmp(node.original.bytes, original.bytes, original.length) ||
        node.gate > 1 || node.dr_only > 1 || node.branch > 1 ||
        node.fallthrough > 1 || node.relative > 1 || node.reserved[0] ||
        node.reserved[1] || node.reserved[2] ||
        node.gate != bool(node.dr_only || original.boundary ||
                          level == ct_instrument_level::full) ||
        node.ingress > header.used ||
        (node.gate && header.used - node.ingress < 26))
      return invalid("original proof, policy or ingress mismatch", index);
    previous_end = uintptr_t(original.pc) + original.length;
    expected_bindings += node.gate;
    if (node.dr_only) {
      if (node.relative)
        return invalid("DR-only instruction contains relocation", index);
      continue;
    }
    if (!node.encoded_length || node.encoded_length > 15 ||
        node.operation > header.used ||
        node.encoded_length > header.used - node.operation ||
        node.entry > header.used || header.used - node.entry < 9 ||
        node.operation != node.ingress + (node.gate ? 26 : 0) ||
        node.successor != node.operation + node.encoded_length)
      return invalid("operation or dispatch layout mismatch", index);
    if (node.relative &&
        (!node.fallthrough || node.encoded_length < 5 ||
         size_t(node.relative_offset) + 4 > node.encoded_length ||
         node.private_operation < header.code_size ||
         node.private_operation > header.binding_offset ||
         node.encoded_length + 5 >
             header.binding_offset - node.private_operation ||
         node.relative_encoding[node.relative_offset] ||
         node.relative_encoding[node.relative_offset + 1] ||
         node.relative_encoding[node.relative_offset + 2] ||
         node.relative_encoding[node.relative_offset + 3]))
      return invalid("private relocation recipe mismatch", index);
    if (node.fallthrough &&
        !version_node(version.get(), original.pc + original.length)) {
      if (node.successor > header.used || header.used - node.successor < 26)
        return invalid("missing exit gateway", index);
      ++expected_bindings;
    }
  }
  if (expected_bindings != header.binding_count)
    return invalid("gateway binding count mismatch");
  if (!allocate_version(version.get(), error, true))
    return nullptr;
  void *mapped = mmap(version->code, version->code_size, PROT_READ | PROT_EXEC,
                      MAP_FIXED | MAP_SHARED, fd,
                      off_t(payload_offset + header.rx_offset));
  if (mapped == MAP_FAILED) {
    version->mapping_failed = true;
    error = "shared userspace code mapping failed";
    return nullptr;
  }
  version->shared = true;
  if (!ct_analysis_content_digest(version->code, version->code_size, digest) ||
      std::memcmp(digest, header.code_digest, sizeof(digest)))
    return invalid("shared RX digest mismatch");
  if (!bind_private_state(version.get(), error) ||
      !register_version(version.get(), error))
    return nullptr;
  version->artifact_restored = true;
  version->preparation.reset();
  error.clear();
  return version.release();
}

bool ct_userspace_version_shared_restored(const ct_userspace_version *version) {
  return version && version->artifact_restored;
}

ct_userspace_version *ct_userspace_version_prepare(
    void *context, ct_instrument_level level, uint64_t generation,
    const ct_userspace_version_instruction *instructions, size_t count,
    std::string &error, const ct_userspace_version_cache *cache,
    bool shared_layout) {
  error.clear();
  if (!context || !instructions || !count || !generation ||
      (level != ct_instrument_level::arm &&
       level != ct_instrument_level::perfetto &&
       level != ct_instrument_level::full)) {
    error = "invalid userspace execution version";
    return nullptr;
  }
  if (dr_get_isa_mode(context) != DR_ISA_AMD64) {
    error = "userspace relocation requires x86-64";
    return nullptr;
  }
  auto version = std::unique_ptr<ct_userspace_version,
                                 decltype(&ct_userspace_version_discard)>(
      new_version(context), ct_userspace_version_discard);
  version->level = level;
  version->generation = generation;
  version->original_base = instructions[0].pc;
  version->shared_layout = shared_layout;
  version->nodes.reserve(count);
  uintptr_t previous_end = 0;
  for (size_t index = 0; index < count; ++index) {
    const auto &original = instructions[index];
    const uintptr_t pc = reinterpret_cast<uintptr_t>(original.pc);
    if (!pc || !original.length || original.length > sizeof(original.bytes) ||
        pc < previous_end || original.length > UINTPTR_MAX - pc) {
      error = "invalid or overlapping original instruction ranges";
      return nullptr;
    }
    previous_end = pc + original.length;
    UserspaceVersionNode node{};
    node.original.offset = original.pc - version->original_base;
    node.original.length = original.length;
    node.original.boundary = original.boundary;
    std::memcpy(node.original.bytes, original.bytes, original.length);
    version->nodes.push_back(node);
  }

  // The gateway size belongs to the selected DR runtime ABI. Measure it instead
  // of copying its byte layout into ctrace. This page never becomes executable.
  version->preparation->scratch = static_cast<byte *>(
      dr_nonheap_alloc(128, DR_MEMPROT_READ | DR_MEMPROT_WRITE));
  byte *scratch = version->preparation->scratch;
  if (!scratch) {
    error = "userspace relocation scratch allocation failed";
    return nullptr;
  }
  const size_t gate_size =
      shared_layout ? dr_encode_userspace_bound_gate(
                          scratch, 64, instructions[0].pc,
                          reinterpret_cast<app_pc *>(scratch + 64),
                          reinterpret_cast<app_pc *>(scratch + 72))
                    : dr_encode_userspace_gate(scratch, 64, instructions[0].pc);
  if (!gate_size || (shared_layout && gate_size != 26)) {
    error = "userspace gateway encoding is unavailable";
    return nullptr;
  }
  auto &keys = version->preparation->template_keys;
  ct_userspace_template_identify(cache, level, gate_size, instructions, count,
                                 keys);
  auto &templates = version->preparation->templates;
  version->common_restored =
      ct_userspace_template_load_common(keys, instructions, count, templates);
  bool cacheable = true;
  auto &decoded = version->preparation->decoded;
  if (!version->common_restored) {
    version->preparation->decoded_list = instrlist_create(context);
    templates.resize(count);
    decoded.reserve(count);
    for (size_t index = 0; index < count; ++index) {
      auto &node = version->nodes[index];
      auto &recipe = templates[index];
      instr_t *instruction = instr_create(context);
      instrlist_append(version->preparation->decoded_list, instruction);
      decoded.push_back(instruction);
      ++version->decoded_count;
      byte *next =
          decode_from_copy(context, node.original.bytes,
                           original_address(version.get(), node), instruction);
      if (!next || size_t(next - node.original.bytes) != node.original.length ||
          !instr_valid(instruction)) {
        error = "original instruction cannot be decoded exactly";
        return nullptr;
      }
      const int opcode = instr_get_opcode(instruction);
      const uint category = instr_get_category(instruction);
      if ((category & DR_INSTR_CATEGORY_FP &&
           !(category & DR_INSTR_CATEGORY_SIMD)) ||
          instr_is_xsave(instruction) || instr_is_xrstor(instruction) ||
          opcode == OP_fxsave32 || opcode == OP_fxsave64 ||
          opcode == OP_fxrstor32 || opcode == OP_fxrstor64 ||
          opcode == OP_xbegin || opcode == OP_xend || opcode == OP_xabort ||
          opcode == OP_xtest || opcode == OP_wrfsbase ||
          opcode == OP_wrgsbase || opcode == OP_rdgsbase ||
          opcode == OP_swapgs ||
          instr_writes_to_reg(instruction, DR_SEG_FS, DR_QUERY_DEFAULT) ||
          instr_writes_to_reg(instruction, DR_SEG_GS, DR_QUERY_DEFAULT)) {
        error = "instruction requires original-PC or runtime-state handling";
        return nullptr;
      }
      app_pc relative_target = nullptr;
      for (int operand_index = 0;
           operand_index <
           instr_num_srcs(instruction) + instr_num_dsts(instruction);
           ++operand_index) {
        const opnd_t operand =
            operand_index < instr_num_srcs(instruction)
                ? instr_get_src(instruction, operand_index)
                : instr_get_dst(instruction,
                                operand_index - instr_num_srcs(instruction));
        if ((opnd_is_memory_reference(operand) &&
             opnd_get_segment(operand) == DR_SEG_GS) ||
            (opnd_is_reg(operand) && opnd_get_reg(operand) == DR_SEG_GS)) {
          error = "instruction depends on the application's GS state";
          return nullptr;
        }
        if (opnd_is_rel_addr(operand)) {
          const app_pc target = static_cast<app_pc>(opnd_get_addr(operand));
          if (relative_target && relative_target != target) {
            error =
                "multiple relative operands require distinct relocation fields";
            return nullptr;
          }
          relative_target = target;
        }
      }
      recipe.branch = instr_is_cbr(instruction) || instr_is_ubr(instruction);
      recipe.dr_only =
          instr_is_call(instruction) || instr_is_return(instruction) ||
          instr_is_syscall(instruction) || instr_is_interrupt(instruction) ||
          instr_is_mbr(instruction) || instr_is_far_cti(instruction) ||
          instr_is_cti_loop(instruction);
      recipe.fallthrough = !instr_is_ubr(instruction);
      if (recipe.branch && !recipe.dr_only) {
        const opnd_t target = instr_get_target(instruction);
        app_pc destination = opnd_is_pc(target) ? opnd_get_pc(target) : nullptr;
        const auto *target_node = version_node(version.get(), destination);
        if (!target_node ||
            (recipe.fallthrough &&
             !version_node(version.get(),
                           original_address(version.get(), node) +
                               node.original.length))) {
          recipe.dr_only = true;
        } else {
          recipe.relocation = ct_userspace_instruction_template::InternalBranch;
          recipe.target = target_node - version->nodes.data();
        }
      }
      if (recipe.dr_only)
        continue;
      if (opcode >= OP_jo_short && opcode <= OP_jnle_short)
        instr_set_opcode(instruction, OP_jo + opcode - OP_jo_short);
      else if (opcode == OP_jmp_short)
        instr_set_opcode(instruction, OP_jmp);
      instr_set_raw_bits_valid(instruction, false);
      next = instr_encode_to_copy(context, instruction, scratch,
                                  original_address(version.get(), node));
      if (!next || next <= scratch || next - scratch > 15) {
        error = "instruction cannot be re-encoded without expansion";
        return nullptr;
      }
      recipe.length = next - scratch;
      byte encoding[15]{};
      std::memcpy(encoding, scratch, recipe.length);
      if (recipe.relocation ==
          ct_userspace_instruction_template::InternalBranch) {
        if (recipe.length < 4) {
          error = "internal branch has no relocatable displacement";
          return nullptr;
        }
        recipe.relocation_offset = recipe.length - 4;
        const app_pc destination = original_address(
            version.get(), version->nodes[size_t(recipe.target)]);
        const int32_t expected =
            int32_t(destination - original_address(version.get(), node) -
                    recipe.length);
        if (std::memcmp(encoding + recipe.relocation_offset, &expected,
                        sizeof(expected))) {
          error =
              "internal branch displacement is not independently relocatable";
          return nullptr;
        }
      } else if (relative_target) {
        recipe.relocation = ct_userspace_instruction_template::RipRelative;
        recipe.target = intptr_t(relative_target) -
                        intptr_t(original_address(version.get(), node));
        // Address-size overrides can wrap EIP. Keep their runtime relocation,
        // but do not persist a delta that would depend on the current ASLR
        // base.
        cacheable &= recipe.target >= INT32_MIN &&
                     recipe.target <= int64_t(INT32_MAX) + 15;
        const int32_t displacement = int32_t(recipe.target - recipe.length);
        const intptr_t shift = displacement < INT32_MIN + 256 ? -256 : 256;
        const int32_t shifted =
            int32_t(uint32_t(displacement) - uint32_t(shift));
        byte *probe = scratch + 32;
        byte *probe_end =
            instr_encode_to_copy(context, instruction, probe,
                                 original_address(version.get(), node) + shift);
        size_t matches = 0;
        if (probe_end == probe + recipe.length) {
          for (size_t offset = 0; offset + 4 <= recipe.length; ++offset)
            if (!std::memcmp(encoding + offset, &displacement, 4) &&
                !std::memcmp(probe + offset, &shifted, 4) &&
                !std::memcmp(encoding, probe, offset) &&
                !std::memcmp(encoding + offset + 4, probe + offset + 4,
                             recipe.length - offset - 4)) {
              recipe.relocation_offset = offset;
              ++matches;
            }
        }
        if (matches != 1) {
          error = "relative memory displacement cannot be isolated safely";
          return nullptr;
        }
      }
      if (recipe.relocation != ct_userspace_instruction_template::None)
        std::memset(encoding + recipe.relocation_offset, 0, 4);
      byte original[15]{};
      std::memcpy(original, node.original.bytes, node.original.length);
      if (recipe.relocation != ct_userspace_instruction_template::None &&
          size_t(recipe.relocation_offset) + 4 <= node.original.length)
        std::memset(original + recipe.relocation_offset, 0, 4);
      if (recipe.length != node.original.length ||
          std::memcmp(encoding, original, recipe.length)) {
        for (size_t offset = 0; offset < recipe.length; ++offset) {
          const byte value = encoding[offset];
          const auto *source =
              std::find(node.original.bytes,
                        node.original.bytes + node.original.length, value);
          recipe.encoding.push_back(
              source != node.original.bytes + node.original.length
                  ? uint16_t(256 + (source - node.original.bytes))
                  : value);
        }
      }
    }
  }
  for (size_t index = 0; index < count; ++index) {
    auto &node = version->nodes[index];
    const auto &recipe = templates[index];
    node.dr_only = recipe.dr_only;
    node.branch = recipe.branch;
    node.fallthrough = recipe.fallthrough;
    node.encoded_length = recipe.length;
  }
  size_t used = 0;
  auto &layout = version->preparation->layout;
  version->layout_restored =
      version->common_restored &&
      ct_userspace_template_load_layout(keys, level, gate_size, instructions,
                                        templates, layout, used);
  if (!version->layout_restored) {
    size_t copied = 0;
    layout.resize(count);
    for (size_t index = 0; index < count; ++index) {
      auto &position = layout[index];
      const auto &recipe = templates[index];
      if (used > size_t(INT32_MAX) - (gate_size * 2 + 17)) {
        error = "userspace execution version exceeds relative-branch reach";
        return nullptr;
      }
      position.gate = recipe.dr_only || instructions[index].boundary ||
                      level == ct_instrument_level::full;
      position.ingress = used;
      if (position.gate)
        used += gate_size;
      if (recipe.dr_only)
        continue;
      ++copied;
      position.operation = used;
      used += recipe.length;
      position.successor = used;
      if (recipe.fallthrough &&
          !version_node(version.get(),
                        instructions[index].pc + instructions[index].length))
        used += gate_size;
    }
    if (!copied) {
      error = "region contains no safely relocatable application instructions";
      return nullptr;
    }
    for (size_t index = 0; index < count; ++index) {
      if (templates[index].dr_only)
        continue;
      if (used > size_t(INT32_MAX) - 9) {
        error = "userspace dispatch islands exceed relative-branch reach";
        return nullptr;
      }
      layout[index].entry = used;
      used += 9;
    }
  }
  for (size_t index = 0; index < count; ++index) {
    auto &node = version->nodes[index];
    const auto &position = layout[index];
    node.ingress = position.ingress;
    node.entry = position.entry;
    node.operation = position.operation;
    node.successor = position.successor;
    node.gate = position.gate;
  }
  const size_t page_size = dr_page_size();
  if (!page_size || used > SIZE_MAX - page_size + 1) {
    error = "invalid userspace execution allocation size";
    return nullptr;
  }
  version->code_size = (used + page_size - 1) / page_size * page_size;
  version->size = version->code_size;
  size_t relative_size = 0;
  if (shared_layout) {
    for (size_t index = 0; index < count; ++index) {
      const auto &recipe = templates[index];
      if (recipe.dr_only ||
          recipe.relocation != ct_userspace_instruction_template::RipRelative)
        continue;
      // The original RIP-relative operation stays intact in a private island.
      // Only fixed relative jumps to/from that island appear in shared RX.
      if (recipe.length < 5 || !recipe.fallthrough ||
          relative_size > size_t(INT32_MAX) - recipe.length - 5) {
        error = "RIP-relative operation cannot use a private island";
        return nullptr;
      }
      version->nodes[index].private_operation =
          version->code_size + relative_size;
      relative_size += recipe.length + 5;
    }
    relative_size = (relative_size + page_size - 1) / page_size * page_size;
    if (relative_size > size_t(INT32_MAX) ||
        version->size > size_t(INT32_MAX) - relative_size) {
      error = "userspace private islands exceed relative-branch reach";
      return nullptr;
    }
    version->size += relative_size;
  }
  const size_t binding_offset = version->size;
  size_t binding_count = 1; // One runtime entry slot is shared by all gateways.
  if (shared_layout) {
    for (const auto &node : version->nodes) {
      binding_count += node.gate;
      binding_count +=
          !node.dr_only && node.fallthrough &&
          !version_node(version.get(), original_address(version.get(), node) +
                                           node.original.length);
    }
    if (binding_count > (SIZE_MAX - page_size + 1) / sizeof(app_pc)) {
      error = "userspace address bindings exceed allocation bounds";
      return nullptr;
    }
    const size_t bindings = (binding_count * sizeof(app_pc) + page_size - 1) /
                            page_size * page_size;
    if (bindings > size_t(INT32_MAX) ||
        version->size > size_t(INT32_MAX) - bindings) {
      error = "userspace address bindings exceed gateway reach";
      return nullptr;
    }
    version->size += bindings;
  }

  version->used = used;
  version->relative_size = relative_size;
  version->binding_offset = binding_offset;
  version->binding_count = binding_count;
  for (size_t index = 0; index < count; ++index) {
    auto &node = version->nodes[index];
    const auto &recipe = templates[index];
    if (recipe.relocation != ct_userspace_instruction_template::RipRelative)
      continue;
    node.relative = true;
    node.relative_target = recipe.target;
    node.relative_offset = recipe.relocation_offset;
    for (size_t offset = 0; offset < recipe.length; ++offset) {
      const uint16_t token = recipe.encoding.empty() ? uint16_t(256 + offset)
                                                     : recipe.encoding[offset];
      node.relative_encoding[offset] =
          token < 256 ? byte(token) : node.original.bytes[token - 256];
    }
    std::memset(node.relative_encoding + node.relative_offset, 0, 4);
  }
  if (!allocate_version(version.get(), error) ||
      (shared_layout && !bind_private_state(version.get(), error, true)))
    return nullptr;

  const byte endbr[] = {0xf3, 0x0f, 0x1e, 0xfa};
  size_t next_binding = 1;
  const auto encode_gate = [&](size_t offset, app_pc original) {
    if (!shared_layout)
      return dr_encode_userspace_gate(version->code + offset, gate_size,
                                      original) == gate_size;
    if (next_binding >= binding_count)
      return false;
    ++next_binding; // The entire shared gateway batch is already encoded.
    return true;
  };
  for (size_t index = 0; index < count; ++index) {
    const auto &node = version->nodes[index];
    if (node.gate &&
        !encode_gate(node.ingress, original_address(version.get(), node))) {
      error = "userspace instruction gateway encoding failed";
      return nullptr;
    }
    if (node.dr_only)
      continue;
    const auto &recipe = templates[index];
    const bool private_relative =
        shared_layout &&
        recipe.relocation == ct_userspace_instruction_template::RipRelative;
    const size_t operation =
        private_relative ? node.private_operation : node.operation;
    byte *encoded = version->code + operation;
    if (!private_relative && recipe.encoding.empty()) {
      std::memcpy(encoded, node.original.bytes, recipe.length);
    } else if (!private_relative) {
      for (size_t offset = 0; offset < recipe.length; ++offset) {
        const uint16_t token = recipe.encoding[offset];
        encoded[offset] =
            token < 256 ? byte(token) : node.original.bytes[token - 256];
      }
    }
    if (!private_relative &&
        recipe.relocation != ct_userspace_instruction_template::None) {
      const __int128 target =
          recipe.relocation == ct_userspace_instruction_template::InternalBranch
              ? __int128(reinterpret_cast<uintptr_t>(version->code)) +
                    version->nodes[size_t(recipe.target)].ingress
              : __int128(reinterpret_cast<uintptr_t>(
                    original_address(version.get(), node))) +
                    recipe.target;
      const __int128 displacement =
          target - reinterpret_cast<uintptr_t>(encoded) - recipe.length;
      if (displacement < INT32_MIN || displacement > INT32_MAX) {
        error = "bound userspace relocation is out of reach";
        return nullptr;
      }
      const int32_t relative_target = int32_t(displacement);
      std::memcpy(encoded + recipe.relocation_offset, &relative_target,
                  sizeof(relative_target));
    }
    if (!version->common_restored) {
      instr_t *instruction = decoded[index];
      if (node.branch)
        instr_set_target(
            instruction,
            opnd_create_pc(version->code +
                           version->nodes[size_t(recipe.target)].ingress));
      instr_t verified;
      instr_init(context, &verified);
      byte *verified_end = decode(context, encoded, &verified);
      const bool equivalent = verified_end == encoded + recipe.length &&
                              instr_same(instruction, &verified);
      instr_free(context, &verified);
      if (!equivalent) {
        error = "relocated instruction does not preserve its decoded operands";
        return nullptr;
      }
    }
    if (private_relative) {
      byte *jump = version->code + node.operation;
      std::memset(jump, 0x90, node.encoded_length);
      jump[0] = 0xe9;
      const int32_t into_island = int32_t(operation - (node.operation + 5));
      std::memcpy(jump + 1, &into_island, sizeof(into_island));
    }
    if (!node.fallthrough)
      continue;
    const app_pc original_next =
        original_address(version.get(), node) + node.original.length;
    if (!version_node(version.get(), original_next) &&
        !encode_gate(node.successor, original_next)) {
      error = "userspace exit gateway encoding failed";
      return nullptr;
    }
  }
  for (const auto &node : version->nodes) {
    if (node.dr_only)
      continue;
    byte *entry = version->code + node.entry;
    std::memcpy(entry, endbr, sizeof(endbr));
    entry[4] = 0xe9;
    const int64_t displacement =
        int64_t(node.operation) - int64_t(node.entry + 9);
    if (displacement < INT32_MIN || displacement > INT32_MAX) {
      error = "userspace dispatch island target is out of reach";
      return nullptr;
    }
    const int32_t target = int32_t(displacement);
    std::memcpy(entry + 5, &target, sizeof(target));
  }
  if (shared_layout && next_binding != binding_count) {
    error = "userspace address binding count differs from layout";
    return nullptr;
  }
  if (!register_version(version.get(), error))
    return nullptr;
  if (cacheable) {
    if (!version->common_restored)
      ct_userspace_template_store_common(keys, templates);
    if (!version->layout_restored)
      ct_userspace_template_store_layout(keys, level, gate_size, layout, used);
  }
  if (version->preparation->decoded_list) {
    instrlist_clear_and_destroy(context, version->preparation->decoded_list);
    version->preparation->decoded_list = nullptr;
  }
  dr_nonheap_free(version->preparation->scratch, 128);
  version->preparation->scratch = nullptr;
  version->preparation.reset();
  return version.release();
}

const byte *ct_userspace_version_image(const ct_userspace_version *version,
                                       size_t *size) {
  if (!version || !size || !version->shared_layout || version->mapping_failed)
    return nullptr;
  *size = version->code_size;
  return version->code;
}

bool ct_userspace_version_map_shared(ct_userspace_version *version, int fd,
                                     uint64_t offset) {
  if (!version || !version->shared_layout || !version->code ||
      version->mapping_failed || fd < 0 || offset % dr_page_size() ||
      offset > uint64_t(INT64_MAX) ||
      version->code_size > uint64_t(INT64_MAX) - offset)
    return false;
  const int seals = fcntl(fd, F_GET_SEALS);
  constexpr int required =
      F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  struct stat metadata{};
  if (seals < 0 || (seals & required) != required ||
      fstat(fd, &metadata) != 0 || metadata.st_size < 0 ||
      uint64_t(metadata.st_size) < offset + version->code_size)
    return false;

  size_t size = version->code_size;
  void *candidate = dr_map_file(fd, &size, offset, nullptr, DR_MEMPROT_READ, 0);
  if (!candidate)
    return false;
  const bool equivalent = size == version->code_size &&
                          !std::memcmp(candidate, version->code, size);
  if (!dr_unmap_file(candidate, size) || !equivalent)
    return false;

  // This replaces only pages of our own unpublished DR allocation, at the
  // same address and with the same permissions/bytes. Preserve DR's allocation
  // accounting and VM ownership rather than registering a second allocation
  // over it; discard() releases the entire reserved code+binding layout.
  // Seals prevent changes between comparison and mapping. No executing or
  // queued user may reach this address during MAP_FIXED's replacement window.
  void *mapped = mmap(version->code, version->code_size, PROT_READ | PROT_EXEC,
                      MAP_FIXED | MAP_SHARED, fd, static_cast<off_t>(offset));
  if (mapped == MAP_FAILED) {
    // MAP_FIXED need not preserve the old mapping on every kernel failure.
    // Make it impossible to publish this version after a partial replacement.
    version->mapping_failed = true;
    return false;
  }
  version->shared = true;
  return true;
}

bool ct_userspace_version_shared(const ct_userspace_version *version) {
  return version && version->shared;
}

app_pc ct_userspace_version_entry(const ct_userspace_version *version,
                                  app_pc original_pc) {
  const auto *node = version_node(version, original_pc);
  return node && !node->dr_only ? version->code + node->entry : nullptr;
}

void ct_userspace_version_exits(const ct_userspace_version *version,
                                void (*callback)(app_pc, void *),
                                void *context) {
  if (!version || version->mapping_failed || !callback)
    return;
  const auto *nodes = version_nodes(version);
  for (size_t index = 0; index < version_node_count(version); ++index) {
    const auto &node = nodes[index];
    const app_pc original = original_address(version, node);
    if (node.gate)
      callback(original, context);
    if (!node.dr_only && node.fallthrough &&
        !version_node(version, original + node.original.length))
      callback(original + node.original.length, context);
  }
}

app_pc ct_userspace_version_ingress(const ct_userspace_version *version,
                                    app_pc original_pc) {
  const auto *node = version_node(version, original_pc);
  return node ? version->code + node->ingress : nullptr;
}

ct_instrument_level
ct_userspace_version_level(const ct_userspace_version *version) {
  return version ? version->level : ct_instrument_level::arm;
}

uint64_t ct_userspace_version_generation(const ct_userspace_version *version) {
  return version ? version->generation : 0;
}

size_t ct_userspace_version_size(const ct_userspace_version *version) {
  return version ? version->size : 0;
}

bool ct_userspace_version_restored(const ct_userspace_version *version) {
  return version && version->layout_restored;
}

bool ct_userspace_version_common_restored(const ct_userspace_version *version) {
  return version && version->common_restored;
}

size_t ct_userspace_version_decoded_count(const ct_userspace_version *version) {
  return version ? version->decoded_count : 0;
}

bool ct_userspace_version_original(const ct_userspace_version *version,
                                   app_pc original_pc, byte *bytes,
                                   size_t *length) {
  const auto *node = version_node(version, original_pc);
  if (!node)
    return false;
  if (bytes)
    std::memcpy(bytes, node->original.bytes, node->original.length);
  if (length)
    *length = node->original.length;
  return true;
}

bool ct_userspace_version_validate(const ct_userspace_version *version,
                                   bool (*read_original)(app_pc pc, size_t size,
                                                         void *destination)) {
  if (!version || version->mapping_failed || !read_original)
    return false;
  for (size_t index = 0; index < version_node_count(version); ++index) {
    const auto &node = version_nodes(version)[index];
    byte bytes[15];
    if (!read_original(original_address(version, node), node.original.length,
                       bytes) ||
        std::memcmp(bytes, node.original.bytes, node.original.length))
      return false;
  }
  return true;
}

bool ct_userspace_version_discard(ct_userspace_version *version) {
  if (!version)
    return true;
  if (version->registration) {
    if (!dr_unregister_userspace_code(version->registration))
      return false;
    version->registration = nullptr;
  }
  if (version->code) {
    if (!dr_custom_free(nullptr, version->allocation, version->code,
                        version->size))
      return false;
    version->code = nullptr;
  }
  if (version->metadata) {
    if (!dr_unmap_file(version->metadata, version->metadata_size))
      return false;
    version->metadata = nullptr;
  }
  if (version->preparation) {
    if (version->preparation->decoded_list)
      instrlist_clear_and_destroy(version->creator,
                                  version->preparation->decoded_list);
    if (version->preparation->scratch)
      dr_nonheap_free(version->preparation->scratch, 128);
  }
  void *lock = version_registry_lock();
  dr_mutex_lock(lock);
  auto **entry = &live_versions;
  while (*entry && *entry != version)
    entry = &(*entry)->next_live;
  if (*entry)
    *entry = version->next_live;
  dr_mutex_unlock(lock);
  delete version;
  return true;
}

void ct_userspace_version_mark_published(ct_userspace_version *version) {
  if (!version)
    return;
  void *lock = version_registry_lock();
  dr_mutex_lock(lock);
  version->published = true;
  dr_mutex_unlock(lock);
}

void ct_userspace_version_fork_child(void *surviving_context) {
  void *lock = versions_lock.load(std::memory_order_acquire);
  if (!lock)
    return;
  dr_mutex_reset_after_fork(lock);
  for (auto *version = live_versions; version;) {
    auto *next = version->next_live;
    if (!version->published && version->creator != surviving_context) {
      // DR has removed the vanished thread's private heap. Its decoded IR
      // must not be destroyed through that stale dcontext. Global allocations
      // (RX, mappings, metadata and scratch) remain ours to release locally.
      if (version->preparation)
        version->preparation->decoded_list = nullptr;
      ct_userspace_version_discard(version);
    }
    version = next;
  }
}

void ct_userspace_version_thread_exit(void *context) {
  void *lock = versions_lock.load(std::memory_order_acquire);
  if (!lock)
    return;
  for (;;) {
    dr_mutex_lock(lock);
    auto *version = live_versions;
    while (version && (version->published || version->creator != context))
      version = version->next_live;
    dr_mutex_unlock(lock);
    if (!version)
      break;
    // The creator cannot resume. DR owns its private IR heap and destroys that
    // heap with the exiting context; only global version resources are ours.
    if (version->preparation)
      version->preparation->decoded_list = nullptr;
    if (!ct_userspace_version_discard(version))
      break;
  }
}
