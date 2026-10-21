// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <list>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/Compression.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/SHA256.h>

#include <fcntl.h>
#include <link.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cache.hh"
#include "ctrace_contract.h"
#include "elf_identity.hh"

// Bound reusable payloads independently of their expanded caller-side views.
static constexpr size_t artifact_payload_limit = 64 * 1024 * 1024;
static constexpr size_t artifact_entry_limit = 65536;
// Records no larger than a filesystem block share a pack; larger payloads
// retain independent files so compaction never copies large analysis results.
static constexpr size_t packed_payload_limit = 4096;
static constexpr size_t packed_bucket_count = 64;
static std::mutex cache_mutex;
struct ArtifactRecord {
  std::vector<unsigned char> bytes;
  size_t decoded_size;
  bool compressed;
  std::list<std::string>::iterator recent;
};
static std::map<std::string, ArtifactRecord> artifact_records;
static std::list<std::string> artifact_recent;
static size_t artifact_payload_bytes = 0;

// The cache mutex covers both the index and its least-recently-used order.
static void retain_artifact(const std::string &identity,
                            llvm::ArrayRef<uint8_t> bytes, size_t decoded_size,
                            bool compressed) {
  if (auto found = artifact_records.find(identity);
      found != artifact_records.end()) {
    artifact_payload_bytes -= found->second.bytes.size();
    artifact_recent.erase(found->second.recent);
    artifact_records.erase(found);
  }
  if (bytes.size() > artifact_payload_limit)
    return;
  while (!artifact_recent.empty() &&
         (artifact_records.size() >= artifact_entry_limit ||
          bytes.size() > artifact_payload_limit - artifact_payload_bytes)) {
    auto oldest = artifact_records.find(artifact_recent.back());
    artifact_payload_bytes -= oldest->second.bytes.size();
    artifact_records.erase(oldest);
    artifact_recent.pop_back();
  }
  artifact_recent.push_front(identity);
  artifact_records.emplace(identity,
                           ArtifactRecord{{bytes.begin(), bytes.end()},
                                          decoded_size,
                                          compressed,
                                          artifact_recent.begin()});
  artifact_payload_bytes += bytes.size();
}

static bool restore_artifact(llvm::ArrayRef<uint8_t> bytes, size_t decoded_size,
                             bool compressed,
                             std::vector<unsigned char> &data) {
  data.clear();
  if (!compressed) {
    if (bytes.size() != decoded_size)
      return false;
    data.assign(bytes.begin(), bytes.end());
    return true;
  }
  if (!llvm::compression::zstd::isAvailable())
    return false;
  data.resize(decoded_size);
  size_t actual_size = decoded_size;
  if (auto error = llvm::compression::zstd::decompress(bytes, data.data(),
                                                       actual_size)) {
    llvm::consumeError(std::move(error));
    data.clear();
    return false;
  }
  if (actual_size != decoded_size) {
    data.clear();
    return false;
  }
  return true;
}

static std::string digest_text(const std::array<uint8_t, 32> &bytes) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (unsigned char byte : bytes) {
    result += hex[byte >> 4];
    result += hex[byte & 15];
  }
  return result;
}

std::string ct_cache_key(std::initializer_list<std::string_view> parts) {
  llvm::SHA256 digest;
  for (const auto part : parts) {
    // Length framing prevents ambiguous concatenations of independent inputs.
    digest.update(std::to_string(part.size()));
    digest.update(":");
    digest.update(llvm::StringRef(part.data(), part.size()));
  }
  return digest_text(digest.final());
}

std::string ct_cache_file_key(const std::string &path) {
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return ct_cache_key({path, "unavailable", std::to_string(errno)});
  struct stat before{}, after{};
  bool valid = fstat(fd, &before) == 0 && S_ISREG(before.st_mode);
  llvm::SHA256 digest;
  std::array<unsigned char, 65536> buffer;
  while (valid) {
    const ssize_t size = read(fd, buffer.data(), buffer.size());
    if (size < 0 && errno == EINTR)
      continue;
    if (size < 0) {
      valid = false;
      break;
    }
    if (!size)
      break;
    digest.update(llvm::ArrayRef<uint8_t>(buffer.data(), size));
  }
  valid = valid && fstat(fd, &after) == 0 && before.st_size == after.st_size &&
          before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
          before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
          before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
          before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  close(fd);
  return valid ? ct_cache_key({path, digest_text(digest.final())})
               : std::string{};
}

std::string ct_cache_runtime_identity(std::string_view client_evidence,
                                      std::string_view runtime_evidence) {
  struct File {
    std::string path;
    struct stat status;
  };
  struct Build {
    bool attempted = false;
    std::string digest;
    std::string client;
    std::string runtime;
    std::vector<File> files;
  };
  static Build build;
  static std::mutex mutex;
  std::lock_guard<std::mutex> lock(mutex);
  const auto unchanged = [](const struct stat &left, const struct stat &right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_size == right.st_size && left.st_mode == right.st_mode &&
           left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
           left.st_ctim.tv_sec == right.st_ctim.tv_sec &&
           left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
  };
  if (!build.attempted) {
    build.attempted = true;
    const char *client = std::getenv("CTRACE_CLIENT_PATH");
    const char *runtime = std::getenv("CTRACE_DYNAMORIO_PATH");
    if (!client || !*client || !runtime || !*runtime)
      return {};
    std::vector<std::string> paths{client, runtime, "/proc/self/exe"};
    dl_iterate_phdr(
        [](dl_phdr_info *info, size_t, void *context) {
          if (info->dlpi_name && info->dlpi_name[0] == '/')
            static_cast<std::vector<std::string> *>(context)->emplace_back(
                info->dlpi_name);
          return 0;
        },
        &paths);
    std::sort(paths.begin() + 3, paths.end());
    std::vector<std::string> hashes;
    for (const auto &path : paths) {
      const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
      if (fd < 0)
        return {};
      struct stat before{}, after{};
      bool valid = fstat(fd, &before) == 0 && S_ISREG(before.st_mode);
      char identity[129]{};
      if (hashes.size() < 2) {
        valid =
            valid &&
            ct_elf_build_id(
                [](void *context, uint64_t offset, void *data, size_t size) {
                  const int file = *static_cast<int *>(context);
                  if (offset > INT64_MAX - size)
                    return false;
                  size_t done = 0;
                  while (done < size) {
                    ssize_t count =
                        pread(file, static_cast<char *>(data) + done,
                              size - done, offset + done);
                    if (count < 0 && errno == EINTR)
                      continue;
                    if (count <= 0)
                      return false;
                    done += count;
                  }
                  return true;
                },
                const_cast<int *>(&fd), false, identity);
      }
      llvm::SHA256 digest;
      std::array<unsigned char, 65536> bytes;
      while (valid) {
        const ssize_t count = read(fd, bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR)
          continue;
        if (count < 0) {
          valid = false;
          break;
        }
        if (!count)
          break;
        digest.update(llvm::ArrayRef<uint8_t>(bytes.data(), count));
      }
      valid = valid && fstat(fd, &after) == 0 && unchanged(before, after);
      close(fd);
      if (!valid)
        return {};
      if (hashes.size() < 2) {
        std::string evidence = std::to_string(before.st_dev) + ":" +
                               std::to_string(before.st_ino) + ":" + identity;
        (hashes.empty() ? build.client : build.runtime) = evidence;
      }
      hashes.push_back(digest_text(digest.final()));
      build.files.push_back({path, before});
    }
    // Compiled client and helper contents cover their code generators and
    // fixed-layout ABI. Addresses, file locations and instrumentation policy
    // are not build inputs. Dependencies are an unordered content set.
    std::sort(hashes.begin() + 3, hashes.end());
    std::string dependencies;
    for (size_t index = 3; index < hashes.size(); ++index)
      dependencies += hashes[index];
    build.digest =
        ct_cache_key({"ctrace-executable-build", CTRACE_CONTRACT_HASH,
                      hashes[0], hashes[1], hashes[2], dependencies});
  }
  if (build.digest.empty() || client_evidence != build.client ||
      runtime_evidence != build.runtime)
    return {};
  for (const auto &file : build.files) {
    struct stat status{};
    if (stat(file.path.c_str(), &status) != 0 ||
        !unchanged(file.status, status)) {
      build.digest.clear();
      return {};
    }
  }
  return build.digest;
}

static bool cache_identity_valid(const char *kind, const std::string &key) {
  if (!kind || !kind[0] || key.size() != 64 ||
      key.find_first_not_of("0123456789abcdef") != std::string::npos)
    return false;
  // Execution objects and their level indexes are the only nested families.
  // Do not admit arbitrary slashes, empty components, or parent traversal.
  return std::strcmp(kind, "execution/objects") == 0 ||
         std::strcmp(kind, "execution/arm") == 0 ||
         std::strcmp(kind, "execution/perfetto") == 0 ||
         std::strcmp(kind, "execution/full") == 0 ||
         std::strspn(kind, "abcdefghijklmnopqrstuvwxyz0123456789-_") ==
             std::strlen(kind);
}

static std::filesystem::path cache_path(const char *kind,
                                        const std::string &key) {
  const char *configured = std::getenv("CTRACE_CACHE_DIR");
  if ((configured && !configured[0]) || !cache_identity_valid(kind, key))
    return {};
  const bool execution = std::strncmp(kind, "execution/", 10) == 0;
  std::filesystem::path root;
  if (configured) {
    root = configured;
  } else {
    const char *value = std::getenv("XDG_CACHE_HOME");
    if (value && value[0] == '/')
      root = std::filesystem::path(value) / "ctrace";
    if (root.empty()) {
      const char *home = std::getenv("HOME");
      if (!home || !home[0])
        return {};
      root = std::filesystem::path(home) / ".cache/ctrace";
    }
  }
  static const std::string runtime = [] {
    const char *path = std::getenv("CTRACE_DYNAMORIO_PATH");
    struct stat status{};
    if (!path || !path[0] || stat(path, &status) != 0 ||
        !S_ISREG(status.st_mode) || access(path, R_OK) != 0)
      return std::string{};
    return ct_cache_file_key(path);
  }();
  // Unknown custom launchers may select a runtime we cannot fingerprint.
  // Retain their recipes in memory, but never reuse DR-specific disk records.
  if (runtime.empty() && (std::strcmp(kind, "userspace-patches") == 0 ||
                          std::strcmp(kind, "userspace-flow") == 0 ||
                          std::strcmp(kind, "backend-cost") == 0 ||
                          std::strcmp(kind, "dr-blocks") == 0 || execution))
    return {};
  // Include the analyzer, client, actual DynamoRIO library, and the analyzer's
  // loaded dependencies. Fixed-layout records are private to this exact build.
  static const std::string build = [] {
    std::string identity = ct_cache_file_key("/proc/self/exe");
    if (const char *client = std::getenv("CTRACE_CLIENT_PATH");
        client && *client)
      identity += ct_cache_file_key(client);
    identity += runtime;
    dl_iterate_phdr(
        [](dl_phdr_info *info, size_t, void *argument) {
          if (info->dlpi_name && info->dlpi_name[0] == '/')
            *static_cast<std::string *>(argument) +=
                ct_cache_file_key(info->dlpi_name);
          return 0;
        },
        &identity);
    return ct_cache_key({"ctrace-cache", CTRACE_CONTRACT_HASH, identity});
  }();
  return root / kind / build / (key + ".bin");
}

// Each pack has two checksummed header generations. A writer appends complete
// records before publishing the next header; a killed writer leaves either the
// previous generation or a complete new generation. The stable lock file also
// serializes atomic replacement during compaction.
struct CachePackHeader {
  std::array<char, 8> magic{};
  uint64_t generation = 0;
  uint64_t live = 0;
  uint64_t obsolete = 0;
  uint64_t end = 2 * sizeof(CachePackHeader);
  std::array<uint64_t, 64> heads{};
  std::array<uint8_t, 32> checksum{};
};

struct CachePackRecord {
  uint64_t next = 0;
  std::array<uint8_t, 32> key{};
  std::array<uint8_t, 48> header{};
  uint64_t size = 0;
  uint64_t external = 0;
  std::array<uint8_t, 32> checksum{};
};

static bool cache_transfer(int fd, void *data, size_t size, uint64_t offset,
                           bool writing) {
  if (offset > INT64_MAX || size > INT64_MAX - offset)
    return false;
  size_t done = 0;
  while (done < size) {
    const auto count = writing ? pwrite(fd, static_cast<char *>(data) + done,
                                        size - done, offset + done)
                               : pread(fd, static_cast<char *>(data) + done,
                                       size - done, offset + done);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    done += count;
  }
  return true;
}

template <typename T> static auto cache_checksum(const T &value) {
  return llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(
      reinterpret_cast<const uint8_t *>(&value), offsetof(T, checksum)));
}

struct CachePack {
  std::filesystem::path path;
  int lock = -1;
  int fd = -1;
  CachePackHeader header;
  std::array<uint8_t, 32> key{};
  size_t slot = 0;

  CachePack(const std::filesystem::path &record_path,
            const std::string &identity, bool writing) {
    const auto digit = [](char ch) {
      return ch <= '9' ? ch - '0' : ch - 'a' + 10;
    };
    for (size_t index = 0; index < key.size(); ++index)
      key[index] =
          (digit(identity[index * 2]) << 4) | digit(identity[index * 2 + 1]);
    slot = key[1] & (header.heads.size() - 1);
    path = record_path.parent_path() /
           (std::to_string(key[0] % packed_bucket_count) + ".pack");
    const std::string lock_path = path.string() + ".lock";
    lock = open(lock_path.c_str(),
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                    (writing ? O_CREAT : 0),
                0600);
    if (lock < 0)
      return;
    struct stat status{};
    if (fstat(lock, &status) != 0 || !S_ISREG(status.st_mode))
      return;
    while (flock(lock, writing ? LOCK_EX : LOCK_SH) != 0) {
      if (errno != EINTR)
        return;
    }
    // A previous writer may have died while creating an external payload or
    // compacted pack. One scratch name per locked bucket bounds those
    // leftovers.
    if (writing)
      unlink((path.string() + ".tmp").c_str());
    fd = open(path.c_str(),
              O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                  (writing ? O_RDWR | O_CREAT : O_RDONLY),
              0600);
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
      if (fd >= 0)
        close(fd);
      fd = -1;
      return;
    }
    bool found = false;
    for (size_t index = 0; index < 2; ++index) {
      CachePackHeader candidate;
      if (cache_transfer(fd, &candidate, sizeof(candidate),
                         index * sizeof(candidate), false) &&
          std::memcmp(candidate.magic.data(), "CTCPACK", 8) == 0 &&
          candidate.generation && candidate.end >= 2 * sizeof(candidate) &&
          candidate.end <= uint64_t(status.st_size) &&
          candidate.live <= candidate.end - 2 * sizeof(candidate) &&
          candidate.obsolete ==
              candidate.end - 2 * sizeof(candidate) - candidate.live &&
          candidate.checksum == cache_checksum(candidate) &&
          (!found || candidate.generation > header.generation)) {
        header = candidate;
        found = true;
      }
    }
    if (!found) {
      if (!writing) {
        close(fd);
        fd = -1;
        return;
      }
      header = {};
      std::memcpy(header.magic.data(), "CTCPACK", 8);
    }
    // Uncommitted tails are not visible and can be reclaimed on the next write.
    if (writing && ftruncate(fd, header.end) != 0) {
      close(fd);
      fd = -1;
    }
  }

  ~CachePack() {
    if (fd >= 0)
      close(fd);
    if (lock >= 0)
      close(lock);
  }

  bool record(uint64_t offset, CachePackRecord &value) const {
    return fd >= 0 && offset >= 2 * sizeof(header) && offset <= header.end &&
           sizeof(value) <= header.end - offset &&
           cache_transfer(fd, &value, sizeof(value), offset, false) &&
           value.checksum == cache_checksum(value) && value.external <= 1 &&
           (value.external || value.size <= packed_payload_limit) &&
           (value.external ||
            value.size <= header.end - offset - sizeof(value)) &&
           (!value.next ||
            (value.next >= 2 * sizeof(header) && value.next < offset));
  }

  bool find(CachePackRecord &value, uint64_t &offset) const {
    offset = header.heads[slot];
    while (offset) {
      if (!record(offset, value))
        return false;
      if (value.key == key)
        return true;
      offset = value.next;
    }
    return false;
  }

  bool publish() {
    if (header.generation == UINT64_MAX)
      return false;
    ++header.generation;
    header.checksum = cache_checksum(header);
    return cache_transfer(fd, &header, sizeof(header),
                          (header.generation & 1) * sizeof(header), true);
  }

  bool compact() {
    const std::string temporary = path.string() + ".tmp";
    const int replacement =
        open(temporary.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (replacement < 0)
      return false;
    CachePackHeader next;
    std::memcpy(next.magic.data(), "CTCPACK", 8);
    bool valid = true;
    for (size_t index = 0; valid && index < header.heads.size(); ++index) {
      // Keep only the newest instance of each key. No persistent index or
      // whole-cache payload copy is needed: only one hash chain is visited.
      std::set<std::array<uint8_t, 32>> seen;
      uint64_t offset = header.heads[index];
      while (valid && offset) {
        CachePackRecord value;
        // An untrusted suffix is already a cache miss. Drop it rather than
        // letting a damaged historical record prevent all future reclamation.
        if (!record(offset, value))
          break;
        const auto previous = value.next;
        if (seen.insert(value.key).second) {
          const size_t payload_size = value.external ? 0 : value.size;
          std::vector<uint8_t> payload(payload_size);
          valid = cache_transfer(fd, payload.data(), payload.size(),
                                 offset + sizeof(value), false);
          value.next = next.heads[index];
          value.checksum = cache_checksum(value);
          if (next.end > INT64_MAX - sizeof(value) - payload_size) {
            valid = false;
            break;
          }
          valid = valid &&
                  cache_transfer(replacement, &value, sizeof(value), next.end,
                                 true) &&
                  cache_transfer(replacement, payload.data(), payload.size(),
                                 next.end + sizeof(value), true);
          next.heads[index] = next.end;
          next.end += sizeof(value) + payload_size;
        }
        offset = previous;
      }
    }
    next.live = next.end - 2 * sizeof(next);
    next.generation = 1;
    next.checksum = cache_checksum(next);
    valid = valid && cache_transfer(replacement, &next, sizeof(next),
                                    sizeof(next), true);
    if (valid)
      valid = rename(temporary.c_str(), path.c_str()) == 0;
    if (valid) {
      close(fd);
      fd = replacement;
      header = next;
    } else {
      close(replacement);
      unlink(temporary.c_str());
    }
    return valid;
  }
};

bool ct_cache_read(const char *kind, const std::string &key,
                   std::vector<unsigned char> &data) {
  if (!cache_identity_valid(kind, key)) {
    data.clear();
    return false;
  }
  std::lock_guard<std::mutex> lock(cache_mutex);
  const std::string identity = std::string(kind) + ":" + key;
  if (const auto found = artifact_records.find(identity);
      found != artifact_records.end()) {
    const auto &record = found->second;
    if (restore_artifact(record.bytes, record.decoded_size, record.compressed,
                         data)) {
      artifact_recent.splice(artifact_recent.begin(), artifact_recent,
                             record.recent);
      return true;
    }
    artifact_payload_bytes -= record.bytes.size();
    artifact_recent.erase(record.recent);
    artifact_records.erase(found);
  }
  data.clear();
  const auto path = cache_path(kind, key);
  if (path.empty())
    return false;
  CachePack pack(path, key, false);
  CachePackRecord record;
  uint64_t offset = 0;
  if (pack.fd < 0 || !pack.find(record, offset))
    return false;
  uint64_t size = 0;
  for (size_t index = 0; index < 8; ++index)
    size |= uint64_t(record.header[8 + index]) << (index * 8);
  const bool compressed = std::memcmp(record.header.data(), "CTCACHEZ", 8) == 0;
  if ((!compressed && std::memcmp(record.header.data(), "CTCACHER", 8) != 0) ||
      size > data.max_size() || record.size > data.max_size() ||
      (!compressed && size != record.size))
    return false;
  int fd = pack.fd;
  bool valid = true;
  if (record.external) {
    fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat status{};
    std::array<uint8_t, 48> header{};
    valid = fd >= 0 && fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
            status.st_size >= off_t(header.size()) &&
            uint64_t(status.st_size) - header.size() == record.size &&
            cache_transfer(fd, header.data(), header.size(), 0, false) &&
            header == record.header;
    offset = 0;
  }
  std::vector<unsigned char> encoded;
  if (valid) {
    encoded.resize(record.size);
    valid = cache_transfer(
        fd, encoded.data(), encoded.size(),
        offset + (record.external ? record.header.size() : sizeof(record)),
        false);
  }
  if (record.external && fd >= 0)
    close(fd);
  if (valid) {
    if (!compressed)
      data = std::move(encoded);
    else
      valid = restore_artifact(encoded, size, true, data);
  }
  if (valid) {
    const auto hash = llvm::SHA256::hash(data);
    valid =
        std::memcmp(record.header.data() + 16, hash.data(), hash.size()) == 0;
  }
  if (!valid) {
    data.clear();
    return false;
  }
  retain_artifact(identity,
                  compressed ? llvm::ArrayRef<uint8_t>(encoded)
                             : llvm::ArrayRef<uint8_t>(data),
                  size, compressed);
  return true;
}

void ct_cache_write(const char *kind, const std::string &key,
                    const std::vector<unsigned char> &data) {
  if (!cache_identity_valid(kind, key))
    return;
  std::lock_guard<std::mutex> lock(cache_mutex);
  llvm::SmallVector<uint8_t, 0> compressed;
  if (!data.empty() && llvm::compression::zstd::isAvailable())
    llvm::compression::zstd::compress(data, compressed);
  const bool use_compressed =
      !compressed.empty() && compressed.size() < data.size();
  const auto encoded = use_compressed ? llvm::ArrayRef<uint8_t>(compressed)
                                      : llvm::ArrayRef<uint8_t>(data);
  retain_artifact(std::string(kind) + ":" + key, encoded, data.size(),
                  use_compressed);
  const auto path = cache_path(kind, key);
  if (path.empty())
    return;
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error)
    return;
  CachePack pack(path, key, true);
  if (pack.fd < 0)
    return;
  CachePackRecord record;
  record.key = pack.key;
  record.size = encoded.size();
  record.external = encoded.size() > packed_payload_limit;
  std::memcpy(record.header.data(), use_compressed ? "CTCACHEZ" : "CTCACHER",
              8);
  for (size_t index = 0; index < 8; ++index)
    record.header[8 + index] = (uint64_t(data.size()) >> (index * 8)) & 255;
  const auto hash = llvm::SHA256::hash(data);
  std::memcpy(record.header.data() + 16, hash.data(), hash.size());
  CachePackRecord previous;
  uint64_t previous_offset = 0;
  const bool replacing = pack.find(previous, previous_offset);
  const uint64_t previous_size =
      replacing ? sizeof(previous) + (previous.external ? 0 : previous.size)
                : 0;
  if (previous_size > pack.header.live)
    return;
  if (replacing && previous.header == record.header &&
      previous.size == record.size && previous.external == record.external) {
    int existing = pack.fd;
    uint64_t offset = previous_offset + sizeof(previous);
    bool identical = true;
    if (record.external) {
      existing =
          open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
      struct stat status{};
      std::array<uint8_t, 48> header{};
      identical =
          existing >= 0 && fstat(existing, &status) == 0 &&
          S_ISREG(status.st_mode) && status.st_size >= off_t(header.size()) &&
          uint64_t(status.st_size) - header.size() == encoded.size() &&
          cache_transfer(existing, header.data(), header.size(), 0, false) &&
          header == record.header;
      offset = header.size();
    }
    // A matching digest must not make a damaged payload permanent: compare the
    // encoded bytes before skipping an identical write, without a second copy.
    std::array<uint8_t, 65536> bytes;
    for (size_t done = 0; identical && done < encoded.size();) {
      const auto count = std::min(bytes.size(), encoded.size() - done);
      identical =
          cache_transfer(existing, bytes.data(), count, offset + done, false) &&
          std::memcmp(bytes.data(), encoded.data() + done, count) == 0;
      done += count;
    }
    if (record.external && existing >= 0)
      close(existing);
    if (identical) {
      if (!record.external)
        unlink(path.c_str());
      return;
    }
  }
  const std::string temporary = pack.path.string() + ".tmp";
  if (record.external) {
    const int fd =
        open(temporary.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
      return;
    bool valid = cache_transfer(fd, record.header.data(), record.header.size(),
                                0, true) &&
                 cache_transfer(fd, const_cast<uint8_t *>(encoded.data()),
                                encoded.size(), record.header.size(), true);
    if (close(fd) != 0)
      valid = false;
    if (!valid) {
      unlink(temporary.c_str());
      return;
    }
  }
  record.next = pack.header.heads[pack.slot];
  record.checksum = cache_checksum(record);
  const uint64_t record_size =
      sizeof(record) + (record.external ? 0 : record.size);
  if (pack.header.end > INT64_MAX - record_size ||
      !cache_transfer(pack.fd, &record, sizeof(record), pack.header.end,
                      true) ||
      (!record.external &&
       !cache_transfer(pack.fd, const_cast<uint8_t *>(encoded.data()),
                       encoded.size(), pack.header.end + sizeof(record), true)))
    return;
  pack.header.heads[pack.slot] = pack.header.end;
  pack.header.end += record_size;
  pack.header.live += record_size;
  pack.header.live -= previous_size;
  pack.header.obsolete += previous_size;
  // Readers hold the same bucket lock. Interrupted storage transitions may
  // invalidate this key, but cannot expose old bytes as the newly hashed value
  // or accumulate unreferenced large payloads.
  if (!record.external)
    unlink(path.c_str());
  if (!pack.publish()) {
    unlink(temporary.c_str());
    return;
  }
  if (record.external && rename(temporary.c_str(), path.c_str()) != 0) {
    unlink(temporary.c_str());
    return;
  }
  if (pack.header.obsolete > pack.header.live)
    pack.compact();
}
