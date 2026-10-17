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
#include <sys/stat.h>
#include <unistd.h>

#include "cache.h"
#include "elf_identity.h"

// Bounds a single serialized analysis artifact, including corrupt files.
static constexpr size_t cache_record_limit = 128 * 1024 * 1024;
// Bound reusable payloads independently of their expanded caller-side views.
static constexpr size_t artifact_payload_limit = 64 * 1024 * 1024;
static constexpr size_t artifact_entry_limit = 65536;
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
    build.digest = ct_cache_key({"ctrace-executable-build-v1", hashes[0],
                                 hashes[1], hashes[2], dependencies});
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
    return ct_cache_key({"ctrace-cache-v2", identity});
  }();
  return root / kind / build / (key + ".bin");
}

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
  const int fd =
      open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    return false;
  struct stat status{};
  // Eight magic bytes, an eight-byte little-endian length, then SHA-256.
  std::array<unsigned char, 48> header{};
  bool valid = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
               status.st_size >= static_cast<off_t>(header.size()) &&
               static_cast<uint64_t>(status.st_size) <=
                   cache_record_limit + header.size();
  size_t have = 0;
  while (valid && have < header.size()) {
    ssize_t count = read(fd, header.data() + have, header.size() - have);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      valid = false;
      break;
    }
    have += count;
  }
  uint64_t size = 0;
  for (size_t index = 0; index < 8; ++index)
    size |= uint64_t(header[8 + index]) << (index * 8);
  const bool compressed = std::memcmp(header.data(), "CTCACHEZ", 8) == 0;
  valid = valid &&
          (compressed || std::memcmp(header.data(), "CTCACHE1", 8) == 0) &&
          size <= cache_record_limit &&
          (compressed || size == uint64_t(status.st_size) - header.size());
  std::vector<unsigned char> encoded;
  if (valid) {
    encoded.resize(status.st_size - header.size());
    have = 0;
    while (have < encoded.size()) {
      ssize_t count = read(fd, encoded.data() + have, encoded.size() - have);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0) {
        valid = false;
        break;
      }
      have += count;
    }
  }
  close(fd);
  if (valid) {
    if (!compressed)
      data = std::move(encoded);
    else
      valid = restore_artifact(encoded, size, true, data);
  }
  if (valid) {
    const auto hash = llvm::SHA256::hash(data);
    valid = std::memcmp(header.data() + 16, hash.data(), hash.size()) == 0;
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
  if (!cache_identity_valid(kind, key) || data.size() > cache_record_limit)
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
  std::string temporary = path.string() + ".tmp-XXXXXX";
  const int fd = mkostemp(temporary.data(), O_CLOEXEC);
  if (fd < 0)
    return;
  std::array<unsigned char, 48> header{};
  std::memcpy(header.data(), use_compressed ? "CTCACHEZ" : "CTCACHE1", 8);
  for (size_t index = 0; index < 8; ++index)
    header[8 + index] = (uint64_t(data.size()) >> (index * 8)) & 255;
  const auto hash = llvm::SHA256::hash(data);
  std::memcpy(header.data() + 16, hash.data(), hash.size());
  bool valid = true;
  for (const auto part : {llvm::ArrayRef<uint8_t>(header), encoded}) {
    size_t done = 0;
    while (done < part.size()) {
      ssize_t count = write(fd, part.data() + done, part.size() - done);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0) {
        valid = false;
        break;
      }
      done += count;
    }
    if (!valid)
      break;
  }
  if (close(fd) != 0)
    valid = false;
  if (valid)
    std::filesystem::rename(temporary, path, error);
  if (!valid || error)
    unlink(temporary.c_str());
}
