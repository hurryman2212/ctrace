#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <utility>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/MD5.h>

#include <elf.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "exec_resources.h"

static bool read_at(int fd, void *buffer, size_t size, uint64_t offset) {
  if (offset > INT64_MAX || size > uint64_t(INT64_MAX) - offset)
    return false;
  auto *bytes = static_cast<unsigned char *>(buffer);
  while (size) {
    const ssize_t count = pread(fd, bytes, size, static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    bytes += count;
    size -= count;
    offset += count;
  }
  return true;
}

static bool elf_identity(int fd, const dr_exec_resource_record_t &record) {
  Elf64_Ehdr header{};
  if (!read_at(fd, &header, sizeof(header), 0) ||
      std::memcmp(header.e_ident, ELFMAG, SELFMAG) ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_ident[EI_VERSION] != EV_CURRENT ||
      header.e_ident[EI_CLASS] != record.elf_class ||
      header.e_ident[EI_DATA] != record.elf_data ||
      header.e_machine != record.elf_machine || header.e_machine != EM_X86_64 ||
      header.e_ehsize != sizeof(header) ||
      header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum ||
      header.e_phnum == PN_XNUM || header.e_phoff > record.file_size ||
      header.e_phnum > (record.file_size - header.e_phoff) / sizeof(Elf64_Phdr))
    return false;
  std::vector<Elf64_Phdr> segments(header.e_phnum);
  if (!read_at(fd, segments.data(), segments.size() * sizeof(Elf64_Phdr),
               header.e_phoff))
    return false;
  llvm::MD5 digest;
  digest.update(llvm::ArrayRef<unsigned char>(
      reinterpret_cast<const unsigned char *>(&header), sizeof(header)));
  digest.update(llvm::ArrayRef<unsigned char>(
      reinterpret_cast<const unsigned char *>(segments.data()),
      segments.size() * sizeof(Elf64_Phdr)));
  std::array<unsigned char, 16384> bytes{};
  bool loaded = false;
  for (const auto &segment : segments) {
    if (segment.p_type != PT_LOAD)
      continue;
    if (segment.p_filesz > segment.p_memsz ||
        segment.p_offset > record.file_size ||
        segment.p_filesz > record.file_size - segment.p_offset)
      return false;
    loaded = true;
    for (uint64_t offset = 0; offset < segment.p_filesz;) {
      const size_t size =
          std::min<uint64_t>(bytes.size(), segment.p_filesz - offset);
      if (!read_at(fd, bytes.data(), size, segment.p_offset + offset))
        return false;
      digest.update(llvm::ArrayRef<unsigned char>(bytes.data(), size));
      offset += size;
    }
  }
  llvm::MD5::MD5Result value;
  digest.final(value);
  return loaded && !std::memcmp(value.data(), record.load_digest, value.size());
}

ct_exec_resources::ct_exec_resources(std::vector<int> files)
    : descriptors(std::move(files)) {}

ct_exec_resources::~ct_exec_resources() {
  if (mapping)
    munmap(mapping, size);
  for (int fd : descriptors)
    if (fd >= 0)
      close(fd);
  if (owner >= 0)
    close(owner);
}

bool ct_exec_resources::validate(uint32_t count, uint64_t expected_size) {
  if (!count || count > DR_EXEC_RESOURCE_LIMIT ||
      descriptors.size() != count + 1 ||
      expected_size < sizeof(dr_exec_manifest_t) ||
      expected_size > DR_EXEC_MANIFEST_LIMIT)
    return false;
  struct stat status{};
  constexpr int seals =
      F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
  const int actual_seals = fcntl(descriptors[0], F_GET_SEALS);
  if (fstat(descriptors[0], &status) || !S_ISREG(status.st_mode) ||
      status.st_size < 0 || uint64_t(status.st_size) != expected_size ||
      actual_seals < 0 || (actual_seals & seals) != seals)
    return false;
  size = expected_size;
  mapping = mmap(nullptr, size, PROT_READ, MAP_SHARED, descriptors[0], 0);
  if (mapping == MAP_FAILED) {
    mapping = nullptr;
    return false;
  }
  dr_exec_manifest_t header;
  std::memcpy(&header, mapping, sizeof(header));
  if (header.magic != DR_EXEC_RESOURCE_MAGIC ||
      header.version != DR_EXEC_RESOURCE_VERSION ||
      header.resource_count != count || header.total_size != size ||
      header.reserved || header.records_offset != sizeof(header) ||
      count > (size - sizeof(header)) / sizeof(dr_exec_resource_record_t) ||
      header.strings_offset !=
          sizeof(header) + count * sizeof(dr_exec_resource_record_t))
    return false;
  const auto *bytes = static_cast<const unsigned char *>(mapping);
  const auto string_valid = [&](uint64_t offset, uint64_t length) {
    return offset >= header.strings_offset && offset <= size && length &&
           length <= size - offset && bytes[offset + length - 1] == 0 &&
           !std::memchr(bytes + offset, 0, length - 1);
  };
  unsigned runtime = 0, target = 0, procfs = 0;
  for (uint32_t index = 0; index < count; ++index) {
    dr_exec_resource_record_t record;
    std::memcpy(&record, bytes + header.records_offset + index * sizeof(record),
                sizeof(record));
    if (record.reserved || record.reserved2 ||
        !string_valid(record.path_offset, record.path_size) ||
        record.path_size == 1 ||
        !string_valid(record.soname_offset, record.soname_size) ||
        record.modified_nanoseconds >= 1000000000 ||
        fstat(descriptors[index + 1], &status) || status.st_size < 0 ||
        uint64_t(status.st_size) != record.file_size ||
        uint64_t(status.st_dev) != record.device ||
        uint64_t(status.st_ino) != record.inode ||
        status.st_mtim.tv_sec != record.modified_seconds ||
        uint64_t(status.st_mtim.tv_nsec) != record.modified_nanoseconds)
      return false;
    const int flags = fcntl(descriptors[index + 1], F_GETFL);
    if (flags < 0 || (flags & O_PATH) || (flags & O_ACCMODE) != O_RDONLY)
      return false;
    if (record.role == DR_EXEC_RESOURCE_PROCFS) {
      struct statfs filesystem{};
      const std::array<unsigned char, 16> zero{};
      if (++procfs > 1 || !S_ISDIR(status.st_mode) ||
          fstatfs(descriptors[index + 1], &filesystem) ||
          filesystem.f_type != PROC_SUPER_MAGIC || record.elf_class ||
          record.elf_data || record.elf_machine ||
          std::memcmp(record.load_digest, zero.data(), zero.size()))
        return false;
    } else {
      struct stat after{};
      if (!S_ISREG(status.st_mode) ||
          !elf_identity(descriptors[index + 1], record) ||
          fstat(descriptors[index + 1], &after) ||
          after.st_size != status.st_size || after.st_dev != status.st_dev ||
          after.st_ino != status.st_ino ||
          after.st_mtim.tv_sec != status.st_mtim.tv_sec ||
          after.st_mtim.tv_nsec != status.st_mtim.tv_nsec)
        return false;
      if (record.role == DR_EXEC_RESOURCE_RUNTIME)
        ++runtime;
      else if (record.role == DR_EXEC_RESOURCE_TARGET)
        ++target;
      else if (record.role != DR_EXEC_RESOURCE_PRIVATE)
        return false;
    }
  }
  return runtime == 1 && target == 1 && procfs == 1;
}

std::unique_ptr<ct_exec_resources>
ct_exec_resources::accept(std::vector<int> files, uint32_t count,
                          uint64_t expected_size, int reply_socket,
                          int64_t sender) {
  auto result = std::unique_ptr<ct_exec_resources>(
      new ct_exec_resources(std::move(files)));
  if (!result->validate(count, expected_size))
    return nullptr;
  struct ucred peer{};
  socklen_t length = sizeof(peer);
  if (getsockopt(reply_socket, SOL_SOCKET, SO_PEERCRED, &peer, &length) ||
      peer.pid != sender)
    return nullptr;
  length = sizeof(result->owner);
  // The per-request socket pins its creator's process identity across PID
  // reuse. A numeric pidfd_open after validation would have a reuse race.
  if (getsockopt(reply_socket, SOL_SOCKET, SO_PEERPIDFD, &result->owner,
                 &length) ||
      result->owner < 0 || fcntl(result->owner, F_SETFD, FD_CLOEXEC))
    return nullptr;
  pollfd alive{result->owner, POLLIN, 0};
  if (poll(&alive, 1, 0) != 0)
    return nullptr;
  return result;
}

bool ct_exec_resource_reply(int socket, const dr_exec_resource_reply_t &reply,
                            const std::vector<int> &files) {
  if (files.size() > DR_EXEC_RESOURCE_LIMIT + 1)
    return false;
  union {
    struct cmsghdr alignment;
    unsigned char bytes[CMSG_SPACE(sizeof(int) * (DR_EXEC_RESOURCE_LIMIT + 1))];
  } control{};
  struct iovec vector{const_cast<dr_exec_resource_reply_t *>(&reply),
                      sizeof(reply)};
  struct msghdr message{};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  if (!files.empty()) {
    message.msg_control = control.bytes;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * files.size());
    auto *rights = CMSG_FIRSTHDR(&message);
    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN(sizeof(int) * files.size());
    std::memcpy(CMSG_DATA(rights), files.data(), sizeof(int) * files.size());
  }
  ssize_t sent;
  do {
    sent = sendmsg(socket, &message, MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);
  return sent == sizeof(reply);
}

bool ct_exec_resources::send(int socket, uint64_t nonce) const {
  const dr_exec_resource_reply_t reply{
      DR_EXEC_RESOURCE_MAGIC,
      DR_EXEC_RESOURCE_VERSION,
      DR_EXEC_RESOURCE_OK,
      nonce,
      static_cast<uint32_t>(descriptors.size() - 1),
      0,
      size};
  return ct_exec_resource_reply(socket, reply, descriptors);
}
