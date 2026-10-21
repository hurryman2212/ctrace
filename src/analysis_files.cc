// SPDX-License-Identifier: MIT

#include <array>
#include <cerrno>
#include <cstdlib>
#include <utility>

#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/SHA256.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "analysis_files.hh"
#include "cache.hh"

static ct_analysis_file_callback filesystem_callback;

static llvm::ErrorOr<llvm::vfs::Status> file_status(int descriptor,
                                                    const std::string &path) {
  llvm::sys::fs::file_status status;
  if (auto error = llvm::sys::fs::status(descriptor, status))
    return error;
  return llvm::vfs::Status::copyWithNewName(status, path);
}

class AnalysisFile final : public llvm::vfs::File {
  int descriptor;
  std::string path;

public:
  AnalysisFile(int input, std::string name)
      : descriptor(input), path(std::move(name)) {}
  ~AnalysisFile() override {
    // Explicit close() reports errors; destruction can only release ownership.
    [[maybe_unused]] const auto error = close();
  }
  llvm::ErrorOr<llvm::vfs::Status> status() override {
    return file_status(descriptor, path);
  }
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>>
  getBuffer(const llvm::Twine &name, int64_t size, bool terminated,
            bool) override {
    auto info = status();
    if (!info)
      return info.getError();
    if (!info->isRegularFile())
      return std::make_error_code(std::errc::invalid_argument);
    return llvm::MemoryBuffer::getOpenFile(
        descriptor, name, size < 0 ? info->getSize() : uint64_t(size),
        terminated, true);
  }
  std::error_code close() override {
    if (descriptor >= 0) {
      const int input = std::exchange(descriptor, -1);
      if (::close(input) != 0)
        return std::error_code(errno, std::generic_category());
    }
    return {};
  }
};

class AnalysisDirectory final : public llvm::vfs::detail::DirIterImpl {
  DIR *directory;
  std::string path;

public:
  AnalysisDirectory(DIR *input, std::string name)
      : directory(input), path(std::move(name)) {}
  ~AnalysisDirectory() override { closedir(directory); }
  std::error_code increment() override {
    while (true) {
      errno = 0;
      dirent *entry = readdir(directory);
      if (!entry) {
        CurrentEntry = {};
        return std::error_code(errno, std::generic_category());
      }
      if (std::string_view(entry->d_name) == "." ||
          std::string_view(entry->d_name) == "..")
        continue;
      struct stat info{};
      if (fstatat(dirfd(directory), entry->d_name, &info,
                  AT_SYMLINK_NOFOLLOW) != 0)
        return std::error_code(errno, std::generic_category());
      const auto type =
          S_ISDIR(info.st_mode)   ? llvm::sys::fs::file_type::directory_file
          : S_ISREG(info.st_mode) ? llvm::sys::fs::file_type::regular_file
          : S_ISLNK(info.st_mode) ? llvm::sys::fs::file_type::symlink_file
                                  : llvm::sys::fs::file_type::type_unknown;
      CurrentEntry =
          llvm::vfs::directory_entry(path + "/" + entry->d_name, type);
      return {};
    }
  }
};

class AnalysisFileSystem final : public llvm::vfs::FileSystem {
  std::string directory;
  std::error_code directory_error;

  llvm::ErrorOr<std::string> absolute(const llvm::Twine &name) const {
    llvm::SmallString<256> path;
    name.toVector(path);
    if (!llvm::sys::path::is_absolute(path)) {
      if (directory_error)
        return directory_error;
      llvm::SmallString<256> full(directory);
      llvm::sys::path::append(full, path);
      path = full;
    }
    return path.str().str();
  }

public:
  AnalysisFileSystem() {
    auto cwd = ct_analysis_file_access(CT_ANALYSIS_FILE_CWD);
    directory = std::move(cwd.path);
    directory_error = cwd.error;
  }
  llvm::ErrorOr<llvm::vfs::Status> status(const llvm::Twine &name) override {
    auto path = absolute(name);
    if (!path)
      return path.getError();
    auto input = ct_analysis_file_access(CT_ANALYSIS_FILE_STATUS, *path);
    if (input.error)
      return input.error;
    auto result = file_status(input.descriptor, *path);
    close(input.descriptor);
    return result;
  }
  llvm::ErrorOr<std::unique_ptr<llvm::vfs::File>>
  openFileForRead(const llvm::Twine &name) override {
    auto path = absolute(name);
    if (!path)
      return path.getError();
    auto input = ct_analysis_file_access(CT_ANALYSIS_FILE_READ, *path);
    if (input.error)
      return input.error;
    return std::unique_ptr<llvm::vfs::File>(
        new AnalysisFile(input.descriptor, *path));
  }
  llvm::vfs::directory_iterator dir_begin(const llvm::Twine &name,
                                          std::error_code &error) override {
    auto path = absolute(name);
    if (!path) {
      error = path.getError();
      return {};
    }
    auto input = ct_analysis_file_access(CT_ANALYSIS_FILE_READ, *path);
    if (input.error) {
      error = input.error;
      return {};
    }
    DIR *contents = fdopendir(input.descriptor);
    if (!contents) {
      error = std::error_code(errno, std::generic_category());
      close(input.descriptor);
      return {};
    }
    auto iterator = std::make_shared<AnalysisDirectory>(contents, *path);
    error = iterator->increment();
    return error ? llvm::vfs::directory_iterator{}
                 : llvm::vfs::directory_iterator(std::move(iterator));
  }
  llvm::ErrorOr<std::string> getCurrentWorkingDirectory() const override {
    if (directory_error)
      return directory_error;
    return directory;
  }
  std::error_code setCurrentWorkingDirectory(const llvm::Twine &name) override {
    auto path = absolute(name);
    if (!path)
      return path.getError();
    auto info = status(*path);
    if (!info)
      return info.getError();
    if (!info->isDirectory())
      return std::make_error_code(std::errc::not_a_directory);
    directory = std::move(*path);
    directory_error.clear();
    return {};
  }
  std::error_code getRealPath(const llvm::Twine &name,
                              llvm::SmallVectorImpl<char> &output) override {
    auto path = absolute(name);
    if (!path)
      return path.getError();
    auto result = ct_analysis_file_access(CT_ANALYSIS_FILE_REALPATH, *path);
    if (!result.error)
      output.assign(result.path.begin(), result.path.end());
    return result.error;
  }
};

llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> ct_analysis_filesystem() {
  return llvm::makeIntrusiveRefCnt<AnalysisFileSystem>();
}

void ct_analysis_set_filesystem(ct_analysis_file_callback callback) {
  filesystem_callback = std::move(callback);
}

bool ct_analysis_remote_filesystem() { return bool(filesystem_callback); }

ct_analysis_file_result ct_analysis_file_access(ct_analysis_file_operation kind,
                                                const std::string &path) {
  if (filesystem_callback)
    return filesystem_callback(kind, path);
  ct_analysis_file_result result;
  if (kind == CT_ANALYSIS_FILE_READ || kind == CT_ANALYSIS_FILE_STATUS) {
    result.descriptor =
        open(path.c_str(), O_CLOEXEC | (kind == CT_ANALYSIS_FILE_STATUS
                                            ? O_PATH
                                            : O_RDONLY | O_NONBLOCK));
    if (result.descriptor < 0)
      result.error = std::error_code(errno, std::generic_category());
  } else {
    char *resolved = kind == CT_ANALYSIS_FILE_CWD
                         ? getcwd(nullptr, 0)
                         : realpath(path.c_str(), nullptr);
    if (resolved) {
      result.path = resolved;
      std::free(resolved);
    } else {
      result.error = std::error_code(errno, std::generic_category());
    }
  }
  return result;
}

llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>>
ct_analysis_read_file(const std::string &path) {
  auto file = ct_analysis_file_access(CT_ANALYSIS_FILE_READ, path);
  if (file.error)
    return file.error;
  struct stat before{}, after{};
  if (fstat(file.descriptor, &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_size < 0) {
    close(file.descriptor);
    return std::make_error_code(std::errc::invalid_argument);
  }
  auto bytes = llvm::MemoryBuffer::getOpenFile(file.descriptor, path,
                                               before.st_size, true, true);
  const bool stable = fstat(file.descriptor, &after) == 0 &&
                      before.st_size == after.st_size &&
                      before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
                      before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
                      before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
                      before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  close(file.descriptor);
  if (!stable)
    return std::make_error_code(std::errc::resource_unavailable_try_again);
  return bytes;
}

std::string ct_analysis_file_key(const std::string &path, bool listing) {
  auto file = ct_analysis_file_access(CT_ANALYSIS_FILE_STATUS, path);
  if (file.error)
    return ct_cache_key(
        {path, "unavailable", std::to_string(file.error.value())});
  struct stat metadata{};
  const bool valid = fstat(file.descriptor, &metadata) == 0;
  close(file.descriptor);
  if (!valid)
    return {};
  if (S_ISDIR(metadata.st_mode)) {
    if (!listing)
      return ct_cache_key({path, "directory"});
    return "listing:" +
           ct_cache_key({path, "directory", std::to_string(metadata.st_dev),
                         std::to_string(metadata.st_ino),
                         std::to_string(metadata.st_mtim.tv_sec),
                         std::to_string(metadata.st_mtim.tv_nsec),
                         std::to_string(metadata.st_ctim.tv_sec),
                         std::to_string(metadata.st_ctim.tv_nsec)});
  }
  if (!S_ISREG(metadata.st_mode))
    return ct_cache_key({path, "nonregular", std::to_string(metadata.st_mode)});
  file = ct_analysis_file_access(CT_ANALYSIS_FILE_READ, path);
  if (file.error)
    return ct_cache_key(
        {path, "unavailable", std::to_string(file.error.value())});
  struct stat before{}, after{};
  bool stable = fstat(file.descriptor, &before) == 0 && S_ISREG(before.st_mode);
  llvm::SHA256 digest;
  std::array<unsigned char, 65536> chunk;
  while (stable) {
    const ssize_t size = read(file.descriptor, chunk.data(), chunk.size());
    if (size < 0 && errno == EINTR)
      continue;
    if (size < 0) {
      stable = false;
      break;
    }
    if (!size)
      break;
    digest.update(llvm::ArrayRef<uint8_t>(chunk.data(), size_t(size)));
  }
  stable &= fstat(file.descriptor, &after) == 0 &&
            before.st_size == after.st_size &&
            before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
            before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
            before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
            before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  close(file.descriptor);
  return stable ? ct_cache_key({path, llvm::toHex(digest.final(), true)})
                : std::string{};
}
