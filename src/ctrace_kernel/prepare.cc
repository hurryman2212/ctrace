// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>

#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/Allocator.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/StringSaver.h>

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cache.hh"
#include "copies.hh"
#include "decompile.hh"
#include "decompile_transport.hh"
#include "interrupt.hh"
#include "kctrace/contract.h"
#include "object.hh"
#include "prepare.hh"
#include "prepare_validate.hh"
#include "source_flow.hh"

struct KernelWorkspace {
  std::string path;
  ~KernelWorkspace() {
    if (!path.empty()) {
      std::error_code ignored;
      std::filesystem::remove_all(path, ignored);
    }
  }
};

static bool read_preparation_file(const std::string &path,
                                  std::vector<unsigned char> &bytes,
                                  std::string &error) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  const std::streampos size = input.tellg();
  if (!input || size < 0 || uint64_t(size) > bytes.max_size()) {
    error = "cannot read preparation input: " + path;
    return false;
  }
  bytes.resize(size_t(size));
  input.seekg(0);
  if (!bytes.empty())
    input.read(reinterpret_cast<char *>(bytes.data()), bytes.size());
  if (!input) {
    error = "preparation input changed while reading: " + path;
    return false;
  }
  return true;
}

static bool write_preparation_file(const std::string &path,
                                   const std::vector<unsigned char> &bytes,
                                   std::string &error) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!bytes.empty())
    output.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  output.close();
  if (!output) {
    error = "cannot write preparation output: " + path;
    return false;
  }
  return true;
}

static bool read_preparation_noreturns(const std::string &path,
                                       std::vector<unsigned char> &bytes,
                                       bool &missing, std::string &error) {
  missing = false;
  bytes.clear();
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) {
    const int failure = errno;
    if (failure == ENOENT || failure == ENOTDIR) {
      missing = true;
      return true;
    }
    error =
        "cannot open selected-kernel objtool noreturn declarations: " + path +
        ": " + std::strerror(failure);
    return false;
  }
  struct stat before{}, after{};
  bool valid =
      !fstat(fd, &before) && S_ISREG(before.st_mode) && before.st_size >= 0 &&
      uint64_t(before.st_size) <= std::vector<unsigned char>{}.max_size();
  if (valid) {
    bytes.resize(size_t(before.st_size));
    size_t offset = 0;
    while (offset < bytes.size()) {
      const ssize_t count =
          read(fd, bytes.data() + offset, bytes.size() - offset);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0) {
        valid = false;
        break;
      }
      offset += size_t(count);
    }
  }
  valid = valid && !fstat(fd, &after) && before.st_size == after.st_size &&
          before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
          before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
          before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
          before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  if (close(fd))
    valid = false;
  if (!valid) {
    error = "cannot read stable selected-kernel objtool noreturn "
            "declarations: " +
            path;
    return false;
  }
  return true;
}

static std::string preparation_digest(const std::vector<unsigned char> &bytes) {
  std::string result;
  for (unsigned char value : llvm::SHA256::hash(bytes)) {
    result += "0123456789abcdef"[value >> 4];
    result += "0123456789abcdef"[value & 15];
  }
  return result;
}

static std::string preparation_tool(const std::string &name,
                                    bool preserve_name = false) {
  std::error_code error;
  // A fixed tool search avoids inherited compiler wrappers and build overrides.
  for (const char *directory : {"/usr/bin/", "/bin/"}) {
    const auto path = std::filesystem::canonical(directory + name, error);
    if (!error && access(path.c_str(), X_OK) == 0)
      // LLVM's multicall tools (notably ld.lld and llvm-strip) select their
      // driver from argv[0], so their executable symlink name must survive.
      return preserve_name ? directory + name : path.string();
  }
  return {};
}

static bool run_preparation(const std::vector<std::string> &arguments,
                            const KernelWorkspace &workspace,
                            std::string &output, std::string &error) {
  if (arguments.empty() || arguments.front().empty()) {
    error = "required kernel preparation tool is unavailable";
    return false;
  }
  const std::string log = workspace.path + "/tool.log";
  const int fd =
      open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    error = "cannot create preparation tool log";
    return false;
  }
  std::vector<char *> argv;
  for (const auto &argument : arguments)
    argv.push_back(const_cast<char *>(argument.c_str()));
  argv.push_back(nullptr);
  const pid_t parent = getpid();
  const pid_t child = fork();
  if (!child) {
    struct sigaction death{};
    death.sa_handler = [](int) { (void)kill(0, SIGKILL); };
    if (setpgid(0, 0) || sigemptyset(&death.sa_mask) ||
        sigaction(SIGTERM, &death, nullptr) ||
        sigprocmask(SIG_SETMASK, &death.sa_mask, nullptr) ||
        prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent ||
        chdir(workspace.path.c_str()) || dup2(fd, STDOUT_FILENO) < 0 ||
        dup2(fd, STDERR_FILENO) < 0)
      _exit(126);
    close(fd);
    // Kbuild spawns compilers and assemblers. Keep a group supervisor alive
    // so killing the collector also terminates the complete preparation tree.
    const pid_t worker = fork();
    if (worker < 0)
      _exit(126);
    if (worker) {
      int status;
      pid_t waited;
      do {
        waited = waitpid(worker, &status, 0);
      } while (waited < 0 && errno == EINTR);
      _exit(waited == worker && WIFEXITED(status) ? WEXITSTATUS(status) : 126);
    }
    char path[] = "PATH=/usr/bin:/bin";
    char locale[] = "LC_ALL=C";
    char timestamp[] = "SOURCE_DATE_EPOCH=0";
    char home[] = "HOME=/nonexistent";
    char *environment[] = {path, locale, timestamp, home, nullptr};
    execve(argv.front(), argv.data(), environment);
    _exit(127);
  }
  close(fd);
  if (child < 0) {
    error = "cannot start kernel preparation tool";
    return false;
  }
  (void)setpgid(child, child);
  siginfo_t status{};
  int waited;
  do {
    waited = waitid(P_PID, child, &status, WEXITED | WNOWAIT);
  } while (waited < 0 && errno == EINTR);
  const bool finished = !waited && status.si_pid == child;
  if (!waited || errno != ECHILD) {
    // Keep the group identity reserved until any surviving tool children exit.
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
    }
  }
  std::vector<unsigned char> data;
  if (!read_preparation_file(log, data, error))
    return false;
  output.assign(data.begin(), data.end());
  if (!finished || status.si_code != CLD_EXITED || status.si_status) {
    // Keep diagnostics useful without flooding the terminal with Kbuild output.
    error = "kernel preparation tool failed: " + arguments.front() + "\n" +
            output.substr(output.size() > 8192 ? output.size() - 8192 : 0);
    return false;
  }
  return true;
}

static bool preparation_tool_identity(const std::string &path,
                                      const KernelWorkspace &workspace,
                                      std::string &identity,
                                      std::string &error) {
  std::vector<unsigned char> bytes;
  if (!read_preparation_file(path, bytes, error))
    return false;
  Elf64_Ehdr header{};
  if (bytes.size() < sizeof(header)) {
    error = "kernel tools must be direct ELF executables, not wrappers";
    return false;
  }
  std::memcpy(&header, bytes.data(), sizeof(header));
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_phentsize != sizeof(Elf64_Phdr) ||
      header.e_phoff > bytes.size() ||
      uint64_t(header.e_phnum) * sizeof(Elf64_Phdr) >
          bytes.size() - header.e_phoff) {
    error = "unsupported kernel preparation tool executable: " + path;
    return false;
  }
  identity += path + ":" + preparation_digest(bytes) + "\n";
  std::string interpreter;
  for (unsigned index = 0; index < header.e_phnum; ++index) {
    Elf64_Phdr program{};
    std::memcpy(&program,
                bytes.data() + header.e_phoff + index * sizeof(program),
                sizeof(program));
    if (program.p_type != PT_INTERP)
      continue;
    if (!program.p_filesz || program.p_offset > bytes.size() ||
        program.p_filesz > bytes.size() - program.p_offset ||
        bytes[program.p_offset + program.p_filesz - 1]) {
      error = "invalid kernel tool interpreter";
      return false;
    }
    interpreter.assign(
        reinterpret_cast<const char *>(bytes.data() + program.p_offset),
        program.p_filesz - 1);
  }
  if (interpreter.empty())
    return true;
  if (!read_preparation_file(interpreter, bytes, error))
    return false;
  identity += interpreter + ":" + preparation_digest(bytes) + "\n";
  std::string output;
  if (!run_preparation({interpreter, "--list", path}, workspace, output, error))
    return false;
  std::istringstream lines(output);
  std::string line;
  while (std::getline(lines, line)) {
    const size_t begin = line.find('/');
    if (begin == std::string::npos)
      continue;
    const size_t end = line.find(" (", begin);
    if (end == std::string::npos) {
      error = "unrecognized kernel tool dependency resolution";
      return false;
    }
    const std::string dependency = line.substr(begin, end - begin);
    if (!read_preparation_file(dependency, bytes, error))
      return false;
    identity += dependency + ":" + preparation_digest(bytes) + "\n";
  }
  return true;
}

static bool preparation_kernel_identity(const std::string &build,
                                        std::string &identity,
                                        std::string &build_id_hex,
                                        std::string &error) {
  build_id_hex.clear();
  std::vector<unsigned char> running;
  if (!read_preparation_file("/sys/kernel/notes", running, error))
    return false;
  const auto build_id = [](const std::vector<unsigned char> &notes) {
    std::vector<unsigned char> result;
    size_t offset = 0;
    while (sizeof(Elf64_Nhdr) <= notes.size() - offset) {
      Elf64_Nhdr note{};
      std::memcpy(&note, notes.data() + offset, sizeof(note));
      offset += sizeof(note);
      const uint64_t name_size = (uint64_t(note.n_namesz) + 3) & ~uint64_t(3);
      const uint64_t data_size = (uint64_t(note.n_descsz) + 3) & ~uint64_t(3);
      if (name_size > notes.size() - offset ||
          data_size > notes.size() - offset - name_size)
        return std::vector<unsigned char>();
      if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
          !std::memcmp(notes.data() + offset, "GNU", 4)) {
        if (!result.empty() || !note.n_descsz)
          return std::vector<unsigned char>();
        result.assign(notes.begin() + offset + name_size,
                      notes.begin() + offset + name_size + note.n_descsz);
      }
      offset += name_size + data_size;
    }
    if (offset != notes.size())
      return std::vector<unsigned char>();
    return result;
  };
  const auto running_id = build_id(running);
  utsname system{};
  std::ifstream release_file(build + "/include/config/kernel.release");
  std::string release;
  if (running_id.empty() || uname(&system) != 0 ||
      !std::getline(release_file, release) || release != system.release) {
    error =
        "selected kernel build release or running GNU build ID is unavailable "
        "or does not match";
    return false;
  }

  // Debug packages and boot images need not live in the headers directory.
  // Read only the note inventory for ELF candidates, including large debug
  // images. A compressed boot image is decoded once with bounded output.
  const auto matches = [&](uint64_t size, const auto &read) {
    Elf64_Ehdr header{};
    if (!read(0, &header, sizeof(header)) ||
        std::memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_ident[EI_VERSION] != EV_CURRENT ||
        header.e_version != EV_CURRENT || header.e_type != ET_EXEC ||
        header.e_machine != EM_X86_64 ||
        header.e_ehsize != sizeof(Elf64_Ehdr) ||
        header.e_shentsize != sizeof(Elf64_Shdr) || !header.e_shnum ||
        header.e_shoff > size ||
        uint64_t(header.e_shnum) * sizeof(Elf64_Shdr) > size - header.e_shoff) {
      error =
          "kernel identity requires an x86-64 vmlinux ELF with GNU build ID";
      return false;
    }
    std::vector<unsigned char> notes;
    for (unsigned index = 0; index < header.e_shnum; ++index) {
      Elf64_Shdr section{};
      if (!read(header.e_shoff + index * sizeof(section), &section,
                sizeof(section))) {
        error = "cannot read kernel vmlinux section inventory";
        return false;
      }
      if (section.sh_type != SHT_NOTE)
        continue;
      if (section.sh_offset > size ||
          section.sh_size > size - section.sh_offset ||
          section.sh_size >
              std::vector<unsigned char>{}.max_size() - notes.size()) {
        error = "invalid kernel vmlinux note section";
        return false;
      }
      const size_t offset = notes.size();
      notes.resize(offset + section.sh_size);
      if (!read(section.sh_offset, notes.data() + offset, section.sh_size)) {
        error = "cannot read kernel vmlinux identity";
        return false;
      }
    }
    if (running_id != build_id(notes)) {
      error = "selected vmlinux GNU build ID does not match the running kernel";
      return false;
    }
    return true;
  };
  bool matched = false;
  for (const std::string &path :
       {build + "/vmlinux", "/lib/modules/" + release + "/vmlinux",
        "/boot/vmlinux-" + release, "/usr/lib/debug/boot/vmlinux-" + release,
        "/usr/lib/debug/lib/modules/" + release + "/vmlinux"}) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    const std::streampos size = input.tellg();
    if (!input || size < 0)
      continue;
    matched =
        matches(uint64_t(size), [&](uint64_t offset, void *data, size_t count) {
          if (offset > uint64_t(size) || count > uint64_t(size) - offset)
            return false;
          input.seekg(offset);
          if (count)
            input.read(static_cast<char *>(data), count);
          return bool(input);
        });
    if (matched)
      break;
    // An explicit build-tree image must not be silently replaced with a
    // matching boot image if the selected build itself is inconsistent.
    if (path == build + "/vmlinux") {
      error += ": " + path;
      return false;
    }
  }
  if (!matched) {
    for (const std::string &path :
         {"/boot/vmlinuz-" + release, "/lib/modules/" + release + "/vmlinuz"}) {
      std::vector<unsigned char> image, decoded;
      std::string reason;
      if (!read_preparation_file(path, image, reason))
        continue;
      const std::string key = ct_cache_key(
          {"kernel-boot-build-id", release,
           std::string_view(reinterpret_cast<const char *>(image.data()),
                            image.size())});
      std::vector<unsigned char> cached;
      if (ct_cache_read("kernel-image", key, cached) && cached == running_id) {
        matched = true;
        break;
      }
      if (!ct_kernel_boot_elf(image, decoded, reason)) {
        error = reason + ": " + path;
        continue;
      }
      matched = matches(
          decoded.size(), [&](uint64_t offset, void *data, size_t count) {
            if (offset > decoded.size() || count > decoded.size() - offset)
              return false;
            if (count)
              std::memcpy(data, decoded.data() + offset, count);
            return true;
          });
      if (matched) {
        // Only the validated identity is needed here, not a duplicate of the
        // full uncompressed kernel. The key covers the boot image bytes and
        // decoder/helper identity; every reuse still checks the running ID.
        ct_cache_write("kernel-image", key, running_id);
        break;
      }
      error += ": " + path;
    }
  }
  if (!matched) {
    if (error.empty())
      error = "cannot find a readable vmlinux or /boot/vmlinuz-" + release +
              " with the running kernel's GNU build ID";
    return false;
  }
  error.clear();
  identity = preparation_digest(running_id);
  for (unsigned char byte : running_id) {
    build_id_hex += "0123456789abcdef"[byte >> 4];
    build_id_hex += "0123456789abcdef"[byte & 15];
  }
  return true;
}

static bool preparation_symbol(const ct_kernel_object &object,
                               const std::string &name, uint32_t &table,
                               uint32_t &index, Elf64_Sym &symbol,
                               std::string &error) {
  unsigned found = 0;
  for (uint32_t section = 1; section < object.section_count(); ++section) {
    const auto *header = object.section_header(section);
    if (header->sh_type != SHT_SYMTAB)
      continue;
    const auto *content = object.section_content(section);
    const auto *names = object.section_content(header->sh_link);
    for (size_t offset = 0; offset < content->size();
         offset += sizeof(symbol)) {
      Elf64_Sym item{};
      std::memcpy(&item, content->data() + offset, sizeof(item));
      if (item.st_name >= names->size())
        continue;
      const char *text =
          reinterpret_cast<const char *>(names->data() + item.st_name);
      const void *end = std::memchr(text, 0, names->size() - item.st_name);
      if (!end ||
          std::string_view(text, static_cast<const char *>(end) - text) != name)
        continue;
      table = section;
      index = offset / sizeof(item);
      symbol = item;
      ++found;
    }
  }
  if (found != 1) {
    error = "expected exactly one kernel object symbol: " + name;
    return false;
  }
  return true;
}

static bool preparation_layout(
    std::vector<unsigned char> &bytes, const std::string &vermagic,
    std::array<uint64_t, 3> &layout, std::array<uint64_t, 4> &parameter_layout,
    std::array<uint64_t, 7> &interrupt_layout,
    std::array<uint64_t, 4> &bug_layout,
    std::vector<unsigned char> &entry_unwind,
    std::map<std::string, std::tuple<uint64_t, uint64_t, bool>> &appended_code,
    std::string &error) {
  ct_kernel_image image;
  image.bytes.swap(bytes);
  ct_kernel_object object(image);
  image.bytes.swap(bytes);
  if (!object.valid(error))
    return false;
  for (uint32_t section = 1; section < object.section_count(); ++section) {
    const auto *header = object.section_header(section);
    if (!(header->sh_flags & SHF_EXECINSTR))
      continue;
    const auto &code = *object.section_content(section);
    static constexpr unsigned char endbr[] = {0xf3, 0x0f, 0x1e, 0xfa};
    const bool landing = code.size() >= sizeof(endbr) &&
                         !std::memcmp(code.data(), endbr, sizeof(endbr));
    appended_code.emplace(
        object.section_name(section),
        std::make_tuple(header->sh_addralign, header->sh_size, landing));
  }
  uint32_t table = 0, index = 0;
  Elf64_Sym symbol{};
  for (bool parameters : {false, true}) {
    const char *name = parameters ? "__ctrace_param_layout" : "__ctrace_layout";
    if (!preparation_symbol(object, name, table, index, symbol, error))
      return false;
    const auto *content = object.section_content(symbol.st_shndx);
    const auto size = parameters ? sizeof(parameter_layout) : sizeof(layout);
    if (!content || symbol.st_size != size ||
        symbol.st_value > content->size() ||
        size > content->size() - symbol.st_value) {
      error = std::string("kernel headers did not produce a usable ") + name;
      return false;
    }
    std::memcpy(parameters ? parameter_layout.data() : layout.data(),
                content->data() + symbol.st_value, size);
  }
  if (!preparation_symbol(object, "__ctrace_interrupt_layout", table, index,
                          symbol, error))
    return false;
  const auto *interrupt = object.section_content(symbol.st_shndx);
  if (!interrupt || symbol.st_size != sizeof(interrupt_layout) ||
      symbol.st_value > interrupt->size() ||
      sizeof(interrupt_layout) > interrupt->size() - symbol.st_value) {
    error = "kernel headers did not produce a usable interrupt layout";
    return false;
  }
  std::memcpy(interrupt_layout.data(), interrupt->data() + symbol.st_value,
              sizeof(interrupt_layout));
  if (std::any_of(interrupt_layout.begin(), interrupt_layout.end(),
                  [](uint64_t offset) { return offset > UINT32_MAX; })) {
    error = "selected kernel interrupt layout exceeds its encoding";
    return false;
  }
  if (!preparation_symbol(object, "__ctrace_bug_layout", table, index, symbol,
                          error))
    return false;
  const auto *bugs = object.section_content(symbol.st_shndx);
  if (!bugs || symbol.st_size != sizeof(bug_layout) ||
      symbol.st_value > bugs->size() ||
      sizeof(bug_layout) > bugs->size() - symbol.st_value) {
    error = "kernel headers did not produce a usable BUG/WARN layout";
    return false;
  }
  std::memcpy(bug_layout.data(), bugs->data() + symbol.st_value,
              sizeof(bug_layout));
  if (!preparation_symbol(object, "__ctrace_entry_unwind", table, index, symbol,
                          error))
    return false;
  const auto *unwind = object.section_content(symbol.st_shndx);
  if (!unwind || !symbol.st_size || symbol.st_size > 16 ||
      symbol.st_value > unwind->size() ||
      symbol.st_size > unwind->size() - symbol.st_value) {
    error = "kernel headers did not produce a bounded ORC entry witness";
    return false;
  }
  entry_unwind.assign(unwind->begin() + symbol.st_value,
                      unwind->begin() + symbol.st_value + symbol.st_size);
  if (!preparation_symbol(object, "__ctrace_vermagic", table, index, symbol,
                          error))
    return false;
  const auto *content = object.section_content(symbol.st_shndx);
  if (!content || !symbol.st_size || symbol.st_value > content->size() ||
      symbol.st_size > content->size() - symbol.st_value ||
      (*content)[symbol.st_value + symbol.st_size - 1] ||
      std::string(
          reinterpret_cast<const char *>(content->data() + symbol.st_value),
          symbol.st_size - 1) != vermagic) {
    error = "module vermagic does not match the selected kernel build";
    return false;
  }
  return true;
}

static bool preparation_bug_hints(const ct_kernel_image &image,
                                  const ct_kernel_copies &copies,
                                  const std::array<uint64_t, 4> &layout,
                                  std::string &annotations,
                                  std::string &error) {
  if (std::none_of(image.sections.begin(), image.sections.end(),
                   [](const auto &section) {
                     return section.name == "__bug_table" && section.size;
                   }))
    return true;
  const auto fail = [&](const char *message) {
    error = message;
    return false;
  };
  const auto [stride, flags_offset, flags_size, warning] = layout;
  if ((stride != 8 && stride != 12 && stride != 16) ||
      flags_size != sizeof(uint16_t) || flags_offset < stride - 4 ||
      flags_offset > stride - flags_size || !warning || warning > UINT16_MAX ||
      (warning & (warning - 1)))
    return fail("selected kernel BUG/WARN layout is unsupported");
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  for (const auto &symbol : image.symbols)
    symbols.emplace(std::make_pair(symbol.table, symbol.index), &symbol);
  std::map<std::pair<uint32_t, uint64_t>, const ct_kernel_copy_site *> sites;
  for (const auto &site : copies.sites)
    sites.emplace(std::make_pair(site.original.section, site.original.offset),
                  &site);
  std::set<std::pair<uint32_t, uint64_t>> emitted;
  for (uint32_t index = 1; index < image.sections.size(); ++index) {
    const auto &section = image.sections[index];
    if (section.name != "__bug_table" || !section.size)
      continue;
    if (section.type != SHT_PROGBITS || section.size % stride ||
        section.size / stride > UINT32_MAX ||
        section.offset > image.bytes.size() ||
        section.size > image.bytes.size() - section.offset)
      return fail("BUG/WARN table differs from the selected kernel layout");
    std::vector<bool> seen(section.size / stride);
    for (const auto &relocation : image.relocations) {
      if (relocation.section != index || relocation.type == R_X86_64_NONE)
        continue;
      const auto found =
          symbols.find({relocation.symbol_table, relocation.symbol});
      if (found == symbols.end() ||
          found->second->section >= image.sections.size())
        return fail("BUG/WARN relocation has no original section");
      const auto &symbol = *found->second;
      const auto &body = image.sections[symbol.section];
      if (!(body.flags & SHF_EXECINSTR))
        continue;
      if (relocation.type != R_X86_64_PC32 || relocation.offset % stride ||
          relocation.offset >= section.size || seen[relocation.offset / stride])
        return fail(
            "BUG/WARN fault fields differ from selected kernel entries");
      const __int128 offset = __int128(symbol.offset) + relocation.addend;
      if (offset < 0 || offset >= body.size || body.size - offset < 2)
        return fail("BUG/WARN fault address leaves the original code");
      const auto site = sites.find({symbol.section, uint64_t(offset)});
      if (site == sites.end() ||
          image.bytes[body.offset + uint64_t(offset)] != 0x0f ||
          image.bytes[body.offset + uint64_t(offset) + 1] != 0x0b)
        return fail("BUG/WARN fault address has no exact UD2 copy");
      seen[relocation.offset / stride] = true;
      uint16_t flags = 0;
      std::memcpy(&flags,
                  image.bytes.data() + section.offset + relocation.offset +
                      flags_offset,
                  sizeof(flags));
      if (!(flags & warning))
        continue;
      const auto &operation = site->second->levels[2].operation;
      for (const auto &level : site->second->levels)
        if (level.operation.section != operation.section ||
            level.operation.offset != operation.offset)
          return fail("WARN reachability requires one shared full body");
      if (!emitted.emplace(operation.section, operation.offset).second)
        continue;
      // Final .ko linking discarded the compiler's reachability annotation.
      // Restore it only for a proven WARN; BUG remains a terminating UD2.
      annotations +=
          "__ASM_ANNOTATE(.discard.annotate_insn, __ctrace_copy_anchor_" +
          std::to_string(operation.section) + "+" +
          std::to_string(operation.offset) + ", ANNOTYPE_REACHABLE)\n";
    }
    if (std::find(seen.begin(), seen.end(), false) != seen.end())
      return fail("BUG/WARN table has no fault address for a kernel entry");
  }
  return true;
}

static bool
preparation_unwind_hints(const ct_kernel_image &image,
                         const ct_kernel_copies &copies,
                         const std::vector<unsigned char> &entry_unwind,
                         std::string &annotations, std::string &error) {
  if (std::none_of(copies.boundaries.begin(), copies.boundaries.end(),
                   [](const auto &boundary) { return boundary.address_taken; }))
    return true;
  const auto fail = [&](const char *message) {
    error = message;
    return false;
  };
  uint32_t unwind = 0, ips = 0;
  for (uint32_t index = 1; index < image.sections.size(); ++index) {
    const auto &name = image.sections[index].name;
    if (name != ".orc_unwind" && name != ".orc_unwind_ip")
      continue;
    auto &slot = name == ".orc_unwind" ? unwind : ips;
    if (slot)
      return fail("ambiguous original ORC sections for addressed landings");
    slot = index;
  }
  if (!unwind && !ips)
    return true;
  if (!unwind || !ips || entry_unwind.empty())
    return fail("incomplete original ORC sections for addressed landings");
  const auto &records = image.sections[unwind];
  const auto &addresses = image.sections[ips];
  if (records.type != SHT_PROGBITS || addresses.type != SHT_PROGBITS ||
      records.offset > image.bytes.size() ||
      records.size > image.bytes.size() - records.offset ||
      addresses.offset > image.bytes.size() ||
      addresses.size > image.bytes.size() - addresses.offset ||
      addresses.size % 4 || addresses.size / 4 > UINT32_MAX ||
      records.size % entry_unwind.size() ||
      records.size / entry_unwind.size() != addresses.size / 4)
    return fail("invalid original ORC record bounds for addressed landings");
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  for (const auto &symbol : image.symbols)
    symbols.emplace(std::make_pair(symbol.table, symbol.index), &symbol);
  std::vector<bool> seen(addresses.size / 4);
  std::map<std::pair<uint32_t, uint64_t>, bool> states;
  for (const auto &relocation : image.relocations) {
    if (relocation.section == unwind && relocation.type != R_X86_64_NONE)
      return fail("original ORC state contains a relocation");
    if (relocation.section != ips)
      continue;
    const auto position =
        symbols.find({relocation.symbol_table, relocation.symbol});
    if (relocation.type != R_X86_64_PC32 || relocation.offset % 4 ||
        relocation.offset / 4 >= seen.size() || seen[relocation.offset / 4] ||
        position == symbols.end())
      return fail("invalid original ORC IP relocation for addressed landings");
    uint32_t field = 0;
    std::memcpy(&field,
                image.bytes.data() + addresses.offset + relocation.offset,
                sizeof(field));
    if (field)
      return fail("original ORC IP relocation field is not zero");
    const auto &symbol = *position->second;
    const __int128 offset = __int128(symbol.offset) + relocation.addend;
    if (!symbol.section || symbol.section >= image.sections.size() ||
        !(image.sections[symbol.section].flags & SHF_EXECINSTR) || offset < 0 ||
        offset > image.sections[symbol.section].size)
      return fail("original ORC IP leaves its executable section");
    const auto row = relocation.offset / 4;
    seen[row] = true;
    const bool compatible =
        std::memcmp(image.bytes.data() + records.offset +
                        row * entry_unwind.size(),
                    entry_unwind.data(), entry_unwind.size()) == 0;
    const auto [found, inserted] = states.emplace(
        std::make_pair(symbol.section, uint64_t(offset)), compatible);
    // Conflicting states, including an undefined terminator, cannot supply a
    // new seed. Ordinary objtool control-flow analysis still has to succeed.
    if (!inserted)
      found->second &= compatible;
  }
  if (std::find(seen.begin(), seen.end(), false) != seen.end())
    return fail("original ORC IP record has no relocation");
  std::set<std::pair<uint32_t, uint64_t>> emitted;
  for (const auto &boundary : copies.boundaries) {
    if (!boundary.address_taken)
      continue;
    if (copies.function_levels[boundary.function] != KCTRACE_LEVEL_FULL ||
        boundary.kind != ct_kernel_copy_boundary_kind::scope)
      return fail("invalid addressed landing unwind request");
    auto state = states.upper_bound(
        {boundary.original.section, boundary.original.offset});
    if (state == states.begin() ||
        (--state)->first.first != boundary.original.section || !state->second)
      continue;
    if (!emitted.emplace(boundary.entry.section, boundary.entry.offset).second)
      continue;
    // Only the complete selected-kernel normal-entry state is representable
    // here. A generic CALL hint cannot preserve arbitrary saved-BP rules.
    // Other states receive no invented hint and remain subject to objtool.
    annotations +=
        ".pushsection .discard.unwind_hints\n.balign 4\n"
        "ANNOTATE_DATA_SPECIAL\n.long __ctrace_copy_anchor_" +
        std::to_string(boundary.entry.section) + "+" +
        std::to_string(boundary.entry.offset) +
        " - .\n.short 8\n.byte ORC_REG_SP\n.byte UNWIND_HINT_TYPE_FUNC\n"
        ".byte 0\n.balign 4\n.popsection\n";
  }
  return true;
}

static bool preparation_noreturn_witnesses(
    const ct_kernel_image &image, const KernelWorkspace &workspace,
    const std::string &compiler, const std::string &objtool,
    const std::vector<unsigned char> &entry_unwind, const std::string &identity,
    std::vector<std::string> &noreturn_symbols, std::string &error) {
  const auto fail = [&](const char *message) {
    error = std::string("selected-kernel noreturn witness: ") + message;
    return false;
  };
  std::map<std::pair<uint32_t, uint32_t>, const ct_kernel_symbol *> symbols;
  for (const auto &symbol : image.symbols)
    symbols.emplace(std::make_pair(symbol.table, symbol.index), &symbol);
  std::set<std::string> candidates;
  for (const auto &relocation : image.relocations) {
    if ((relocation.type != R_X86_64_PC32 &&
         relocation.type != R_X86_64_PLT32) ||
        relocation.addend != -4 || relocation.section >= image.sections.size())
      continue;
    const auto &section = image.sections[relocation.section];
    const auto found =
        symbols.find({relocation.symbol_table, relocation.symbol});
    if (!(section.flags & SHF_EXECINSTR) || !relocation.offset ||
        relocation.offset > section.size ||
        section.size - relocation.offset < 4 || found == symbols.end() ||
        found->second->section != SHN_UNDEF ||
        (found->second->type != STT_NOTYPE && found->second->type != STT_FUNC))
      continue;
    if (section.offset > image.bytes.size() ||
        section.size > image.bytes.size() - section.offset)
      return fail("original call section leaves its input image");
    if (image.bytes[section.offset + relocation.offset - 1] != 0xe8)
      continue;
    const auto &name = found->second->name;
    // The emitter accepts exactly these identifiers for direct noreturn
    // imports. Other symbol spellings keep their existing conservative path.
    if (name.empty() || (name.front() >= '0' && name.front() <= '9') ||
        name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU"
                               "VWXYZ0123456789_") != std::string::npos)
      continue;
    candidates.insert(name);
  }
  if (candidates.empty())
    return true;
  if (entry_unwind.empty())
    return fail("selected headers provide no ORC record layout");
  std::string names;
  for (const auto &name : candidates)
    names += name + '\n';
  const std::string key = ct_cache_key(
      {"kernel-noreturn-witness", identity, names,
       std::string_view(reinterpret_cast<const char *>(entry_unwind.data()),
                        entry_unwind.size())});
  std::vector<unsigned char> decisions;
  const bool cached =
      ct_cache_read("kernel-noreturn", key, decisions) &&
      decisions.size() == candidates.size() &&
      std::all_of(decisions.begin(), decisions.end(),
                  [](unsigned char value) { return value <= 1; });
  if (!cached) {
    // A CALL followed by UD2 is valid for both returning and noreturn targets.
    // Objtool emits an undefined ORC state at CALL+5 only for the latter.
    // Local controls establish both states using this exact tool; no warning
    // text, private objtool ELF layout, or built-in function list is assumed.
    const std::string prefix = "__ctrace_noreturn_" + key + "_";
    std::string assembly =
        ".text\n.type " + prefix + "returns,@function\n" + prefix +
        "returns:\nret\n.size " + prefix + "returns,.-" + prefix +
        "returns\n.type " + prefix + "stops,@function\n" + prefix +
        "stops:\nud2\n.size " + prefix + "stops,.-" + prefix + "stops\n";
    std::vector<std::string> targets{prefix + "returns", prefix + "stops"};
    targets.insert(targets.end(), candidates.begin(), candidates.end());
    for (size_t index = 0; index < targets.size(); ++index) {
      const std::string name = prefix + std::to_string(index);
      assembly += ".type " + name + ",@function\n" + name + ":\ncall " +
                  targets[index] + "\nud2\n.size " + name + ",.-" + name + '\n';
    }
    assembly += ".section .note.GNU-stack,\"\",@progbits\n";
    std::vector<unsigned char> bytes(assembly.begin(), assembly.end());
    std::string output;
    if (!write_preparation_file(workspace.path + "/noreturn.S", bytes, error) ||
        !run_preparation(
            {compiler, "-m64", "-c", "noreturn.S", "-o", "noreturn.o"},
            workspace, output, error) ||
        !run_preparation(
            {objtool, "--orc", "--module", "--werror", "noreturn.o"}, workspace,
            output, error) ||
        !read_preparation_file(workspace.path + "/noreturn.o", bytes, error))
      return false;
    ct_kernel_image witness;
    witness.bytes.swap(bytes);
    ct_kernel_object object(witness);
    if (!object.valid(error))
      return false;
    uint32_t text = 0, records = 0, addresses = 0, relocations = 0;
    for (uint32_t index = 1; index < object.section_count(); ++index) {
      const auto name = object.section_name(index);
      if (name == ".text")
        text = index;
      else if (name == ".orc_unwind")
        records = index;
      else if (name == ".orc_unwind_ip")
        addresses = index;
    }
    for (uint32_t index = 1; index < object.section_count(); ++index) {
      const auto *header = object.section_header(index);
      if (header->sh_type == SHT_RELA && header->sh_info == addresses) {
        if (relocations)
          return fail("ambiguous ORC address relocation tables");
        relocations = index;
      }
    }
    if (!text || !records || !addresses || !relocations)
      return fail("objtool did not produce complete ORC records");
    const auto &code = *object.section_content(text);
    const auto &orc = *object.section_content(records);
    const auto &ips = *object.section_content(addresses);
    const auto &relas = *object.section_content(relocations);
    if (orc.empty() || orc.size() % entry_unwind.size() || ips.size() % 4 ||
        orc.size() / entry_unwind.size() != ips.size() / 4 ||
        relas.size() / sizeof(Elf64_Rela) != ips.size() / 4 ||
        code.size() != 3 + targets.size() * 7 || code[0] != 0xc3 ||
        code[1] != 0x0f || code[2] != 0x0b)
      return fail("objtool witness layout differs from its exact controls");
    const auto *table =
        object.section_content(object.section_header(relocations)->sh_link);
    if (!table)
      return fail("ORC address relocations lack a symbol table");
    std::map<uint64_t, std::vector<unsigned char>> states;
    std::set<uint64_t> rows;
    for (size_t index = 0; index < relas.size(); index += sizeof(Elf64_Rela)) {
      Elf64_Rela relocation{};
      std::memcpy(&relocation, relas.data() + index, sizeof(relocation));
      const uint64_t symbol_offset =
          uint64_t(ELF64_R_SYM(relocation.r_info)) * sizeof(Elf64_Sym);
      if (ELF64_R_TYPE(relocation.r_info) != R_X86_64_PC32 ||
          relocation.r_offset % 4 || relocation.r_offset >= ips.size() ||
          !rows.insert(relocation.r_offset / 4).second ||
          symbol_offset > table->size() ||
          sizeof(Elf64_Sym) > table->size() - symbol_offset)
        return fail("invalid ORC address relocation");
      Elf64_Sym symbol{};
      std::memcpy(&symbol, table->data() + symbol_offset, sizeof(symbol));
      uint32_t field = 0;
      std::memcpy(&field, ips.data() + relocation.r_offset, sizeof(field));
      const __int128 address = __int128(symbol.st_value) + relocation.r_addend;
      if (symbol.st_shndx != text || field || address < 0 ||
          address > code.size())
        return fail("ORC witness address leaves its known text");
      const auto begin =
          orc.begin() + (relocation.r_offset / 4) * entry_unwind.size();
      if (!states
               .emplace(uint64_t(address),
                        std::vector<unsigned char>(begin,
                                                   begin + entry_unwind.size()))
               .second)
        return fail("ambiguous ORC witness state");
    }
    const auto state_at =
        [&](uint64_t address) -> const std::vector<unsigned char> * {
      const auto next = states.upper_bound(address);
      return next == states.begin() ? nullptr : &std::prev(next)->second;
    };
    const auto *returning = state_at(3 + 5);
    const auto *terminal = state_at(3 + 7 + 5);
    if (!returning || !terminal || *returning != entry_unwind ||
        *terminal == entry_unwind)
      return fail("objtool cannot distinguish returning and noreturn controls");
    decisions.clear();
    for (size_t index = 0; index < targets.size(); ++index) {
      const uint64_t address = 3 + index * 7;
      const auto *entry = state_at(address);
      const auto *after = state_at(address + 5);
      if (code[address] != 0xe8 || code[address + 5] != 0x0f ||
          code[address + 6] != 0x0b || !entry || !after ||
          *entry != entry_unwind ||
          (*after != entry_unwind && *after != *terminal))
        return fail("call witness has an unexpected ORC state");
      if (index >= 2)
        decisions.push_back(*after == *terminal);
    }
    ct_cache_write("kernel-noreturn", key, decisions);
  }
  size_t index = 0;
  for (const auto &name : candidates)
    if (decisions[index++])
      noreturn_symbols.push_back(name);
  return true;
}

bool ct_kernel_prepare(const ct_kernel_image &image,
                       const ct_kernel_prepare_options &options,
                       ct_kernel_prepared &prepared, std::string &error) {
  prepared = {};
  if (options.minimum_level > KCTRACE_LEVEL_FULL ||
      (options.minimum_level < KCTRACE_LEVEL_FULL &&
       !options.level_selection)) {
    error = "requested kernel instrumentation requires level-selection support";
    return false;
  }
  prepared.minimum_level = options.minimum_level;
  prepared.level_selection = options.minimum_level < KCTRACE_LEVEL_FULL;
  prepared.program_flags =
      (options.observation.emit_terminal ? KCTRACE_PROGRAM_TERMINAL : 0U) |
      (options.perfetto ? KCTRACE_PROGRAM_PERFETTO : 0U) |
      (!options.observation.within.empty() || options.observation.within_init ||
               options.observation.within_intr
           ? KCTRACE_PROGRAM_WITHIN_FILTER
           : 0U) |
      (options.observation.within_intr ? KCTRACE_PROGRAM_WITHIN_INTR : 0U);
  error.clear();
  if (image.signature_present &&
      (!image.signature_format_valid || image.signature_hash.empty())) {
    error = "original module signature trailer has an unsupported or invalid "
            "format";
    return false;
  }
  if (!image.signature_present && options.signing) {
    error = "kernel signing options require an already signed input module";
    return false;
  }
  std::error_code filesystem_error;
  const std::string build =
      std::filesystem::canonical(options.kernel_build, filesystem_error)
          .string();
  if (filesystem_error ||
      build.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
                              "WXYZ0123456789_./+-") != std::string::npos) {
    error = "kernel build directory is unavailable or unsuitable for Kbuild";
    return false;
  }
  std::string kernel_identity, kernel_build_id;
  if (!preparation_kernel_identity(build, kernel_identity, kernel_build_id,
                                   error))
    return false;
  for (const auto &symbol : image.symbols) {
    if (symbol.name.rfind("kctrace_", 0) == 0 ||
        symbol.name.rfind("__ctrace_", 0) == 0) {
      error = "input module uses a reserved kctrace runtime symbol";
      return false;
    }
    if (symbol.section == SHN_UNDEF &&
        symbol.name == "__register_nmi_handler" &&
        std::any_of(image.relocations.begin(), image.relocations.end(),
                    [&](const auto &relocation) {
                      return relocation.symbol_table == symbol.table &&
                             relocation.symbol == symbol.index &&
                             relocation.type != R_X86_64_NONE &&
                             relocation.section < image.sections.size() &&
                             (image.sections[relocation.section].flags &
                              SHF_ALLOC);
                    })) {
      error = "NMI handler registration is unsupported: __register_nmi_handler";
      return false;
    }
  }
  std::vector<unsigned char> bytes;
  if (!read_preparation_file(build + "/.config", bytes, error))
    return false;
  const std::string config(bytes.begin(), bytes.end());
  std::istringstream config_lines(config);
  std::string config_line;
  constexpr std::string_view hash_setting = "CONFIG_MODULE_SIG_HASH=\"";
  while (std::getline(config_lines, config_line)) {
    if (config_line.compare(0, hash_setting.size(), hash_setting) == 0 &&
        config_line.size() > hash_setting.size() && config_line.back() == '"') {
      prepared.default_signature_hash = config_line.substr(
          hash_setting.size(), config_line.size() - hash_setting.size() - 1);
      break;
    }
  }
  const auto enabled = [&](std::string_view name) {
    return config.find(std::string(name) + "=y\n") != std::string::npos;
  };
  for (const char *required :
       {"CONFIG_X86_64", "CONFIG_MODULES", "CONFIG_MODULE_UNLOAD",
        "CONFIG_OBJTOOL", "CONFIG_UNWINDER_ORC", "CONFIG_KALLSYMS"})
    if (!enabled(required)) {
      error = "kernel preparation currently requires " + std::string(required);
      return false;
    }
  for (const char *unsupported :
       {"CONFIG_MODVERSIONS", "CONFIG_EXTENDED_MODVERSIONS",
        "CONFIG_LTO_CLANG_THIN_DIST", "CONFIG_CFI", "CONFIG_CFI_CLANG",
        "CONFIG_FINEIBT", "CONFIG_KASAN", "CONFIG_KCSAN", "CONFIG_UBSAN",
        "CONFIG_KCOV", "CONFIG_GCOV_KERNEL", "CONFIG_GCC_PLUGINS",
        "CONFIG_PREEMPT_RT"})
    if (enabled(unsupported)) {
      error = "kernel preparation has no verified handler for " +
              std::string(unsupported);
      return false;
    }
  const bool clang = enabled("CONFIG_CC_IS_CLANG");
  const bool lto = enabled("CONFIG_LTO_CLANG");
  if (clang == enabled("CONFIG_CC_IS_GCC") ||
      (clang &&
       (!enabled("CONFIG_AS_IS_LLVM") || !enabled("CONFIG_LD_IS_LLD"))) ||
      (lto && (!clang || (enabled("CONFIG_LTO_CLANG_FULL") ==
                          enabled("CONFIG_LTO_CLANG_THIN"))))) {
    error = "kernel preparation requires GCC or Clang with its integrated "
            "assembler and LLD, and a recognized full/thin LTO configuration";
    return false;
  }
  const auto version = [&](const char *name) {
    const std::string prefix = std::string(name) + "=";
    const size_t begin = config.find("\n" + prefix);
    unsigned value = 0;
    if (begin != std::string::npos)
      (void)std::sscanf(config.c_str() + begin + 1 + prefix.size(), "%u",
                        &value);
    return value;
  };
  const unsigned compiler_version =
      version(clang ? "CONFIG_CLANG_VERSION" : "CONFIG_GCC_VERSION");
  const unsigned linker_version = clang ? version("CONFIG_LLD_VERSION") : 0;
  if (!compiler_version || (clang && !linker_version)) {
    error = "kernel compiler identity is missing";
    return false;
  }
  const std::string suffix = "-" + std::to_string(compiler_version / 10000);
  const std::string compiler =
      preparation_tool((clang ? "clang" : "gcc") + suffix, clang);
  const std::string make = preparation_tool("make");
  const std::string linker = preparation_tool(
      clang ? "ld.lld-" + std::to_string(linker_version / 10000) : "ld", clang);
  const std::string objcopy =
      preparation_tool(clang ? "llvm-objcopy" + suffix : "objcopy", clang);
  const std::string objtool = build + "/tools/objtool/objtool";
  if (compiler.empty() || make.empty() || linker.empty() || objcopy.empty()) {
    error = clang ? "matching Clang, LLD and LLVM tools are required for "
                    "kernel preparation"
                  : "matching GCC and native binutils are required for "
                    "kernel preparation";
    return false;
  }
  KernelWorkspace workspace;
  char directory[] = "/tmp/ctrace-kernel-XXXXXX";
  if (!mkdtemp(directory)) {
    error = "cannot create a private kernel preparation directory";
    return false;
  }
  workspace.path = directory;
  std::string output;
  std::map<std::string, std::string> llvm_tools;
  if (clang) {
    for (const auto &[tool, marker, expected] :
         {std::tuple{compiler, "clang version ", compiler_version},
          std::tuple{linker, "LLD ", linker_version}}) {
      if (!run_preparation({tool, "--version"}, workspace, output, error))
        return false;
      const size_t begin = output.find(marker);
      unsigned major = 0, minor = 0, patch = 0;
      if (begin == std::string::npos ||
          std::sscanf(output.c_str() + begin + std::strlen(marker), "%u.%u.%u",
                      &major, &minor, &patch) != 3 ||
          major * 10000 + minor * 100 + patch != expected) {
        error = "kernel preparation tool version differs from selected "
                "kernel configuration: " +
                tool;
        return false;
      }
    }
    for (const auto &[variable, name] : {std::pair{"AR", "llvm-ar"},
                                         {"NM", "llvm-nm"},
                                         {"OBJDUMP", "llvm-objdump"},
                                         {"OBJCOPY", "llvm-objcopy"},
                                         {"READELF", "llvm-readelf"},
                                         {"STRIP", "llvm-strip"}}) {
      const std::string tool = preparation_tool(name + suffix, true);
      if (tool.empty() ||
          !run_preparation({tool, "--version"}, workspace, output, error)) {
        if (tool.empty())
          error = std::string("matching LLVM tool is unavailable: ") + name +
                  suffix;
        return false;
      }
      const size_t begin = output.find("LLVM version ");
      unsigned major = 0, minor = 0, patch = 0;
      if (begin == std::string::npos ||
          std::sscanf(output.c_str() + begin + std::strlen("LLVM version "),
                      "%u.%u.%u", &major, &minor, &patch) != 3 ||
          major * 10000 + minor * 100 + patch != compiler_version) {
        error = "LLVM tool version differs from selected Clang: " + tool;
        return false;
      }
      llvm_tools.emplace(variable, tool);
    }
  }
  std::string resource_identity;
  for (const char *directory : {"include/uapi/linux", "include/kctrace"}) {
    std::filesystem::create_directories(workspace.path + "/" + directory,
                                        filesystem_error);
    if (filesystem_error) {
      error = "cannot prepare kernel header directory: " +
              filesystem_error.message();
      return false;
    }
  }
  for (const char *resource :
       {"target.c", "target.h", "include/uapi/linux/kctrace.h",
        "include/kctrace/runtime.h", "include/kctrace/contract.h",
        "include/kctrace/contract.sha256"}) {
    if (!read_preparation_file(options.resource_root + "/" + resource, bytes,
                               error) ||
        !write_preparation_file(workspace.path + "/" + resource, bytes, error))
      return false;
    resource_identity +=
        std::string(resource) + ":" + preparation_digest(bytes) + "\n";
  }
  const std::string contract = KCTRACE_CONTRACT_HEX;
  if (std::string(bytes.begin(), bytes.end()) != contract + "\n") {
    error = "kernel resources differ from the helper runtime contract";
    return false;
  }
  std::string kbuild = "obj-m += target.o\n"
                       "ccflags-y += -I$(src)/include/uapi -I$(src)/include "
                       "-g0 -frandom-seed=ctrace-target "
                       "-ffile-prefix-map=$(src)=/ctrace-kernel-build "
                       "-fdebug-prefix-map=$(src)=/ctrace-kernel-build "
                       "-fmacro-prefix-map=$(src)=/ctrace-kernel-build\n";
  kbuild += "ccflags-y += '-DKCTRACE_CONTRACT_HEX=\"" + contract +
            "\"' '-DKCTRACE_CONTRACT_BYTES={";
  for (size_t offset = 0; offset < contract.size(); offset += 2) {
    if (offset)
      kbuild += ',';
    kbuild += "0x" + contract.substr(offset, 2);
  }
  kbuild += "}'\n";
  if (clang)
    kbuild += "ldflags-y += --threads=1\n";
  bytes.assign(kbuild.begin(), kbuild.end());
  if (!write_preparation_file(workspace.path + "/Kbuild", bytes, error))
    return false;
  if (options.progress)
    options.progress(
        "Validating kernel build and compiling the module binding");
  std::vector<std::string> compile{make,
                                   "--no-print-directory",
                                   "-j1",
                                   "-C",
                                   build,
                                   "M=" + workspace.path,
                                   "CC=" + compiler,
                                   "LD=" + linker,
                                   "OBJCOPY=" + objcopy,
                                   "target.o"};
  if (clang) {
    compile.insert(compile.end() - 1, "LLVM=" + suffix);
    for (const auto &[variable, tool] : llvm_tools)
      compile.insert(compile.end() - 1, variable + "=" + tool);
  }
  if (!run_preparation(compile, workspace, output, error) ||
      !read_preparation_file(workspace.path + "/target.o", bytes, error))
    return false;
  const std::string target_digest = preparation_digest(bytes);
  std::array<uint64_t, 3> layout{};
  std::array<uint64_t, 4> parameter_layout{};
  std::array<uint64_t, 7> interrupt_layout{};
  std::array<uint64_t, 4> bug_layout{};
  std::vector<unsigned char> entry_unwind;
  std::map<std::string, std::tuple<uint64_t, uint64_t, bool>> appended_code;
  if (!preparation_layout(bytes, image.vermagic, layout, parameter_layout,
                          interrupt_layout, bug_layout, entry_unwind,
                          appended_code, error) ||
      !ct_kernel_validate_parameters(image, parameter_layout, error))
    return false;
  std::string interrupt_identity;
  if (options.observation.within_intr) {
    std::vector<unsigned char> kernel_image, boot_relocations;
    const std::string snapshot = workspace.path + "/vmlinux.unstripped";
    const std::string relocator = build + "/arch/x86/tools/relocs";
    if (!read_preparation_file(build + "/vmlinux.unstripped", kernel_image,
                               error) ||
        !read_preparation_file(build +
                                   "/arch/x86/boot/compressed/vmlinux.relocs",
                               boot_relocations, error) ||
        !preparation_tool_identity(relocator, workspace, interrupt_identity,
                                   error))
      return false;
    const auto verify_relocations = [&](std::string &issue) {
      if (options.progress)
        options.progress("Proving selected-kernel interrupt callback dispatch");
      if (!write_preparation_file(snapshot, kernel_image, issue) ||
          !run_preparation({relocator, snapshot}, workspace, output, issue))
        return false;
      if (output.size() == boot_relocations.size() &&
          !std::memcmp(output.data(), boot_relocations.data(), output.size()))
        return true;
      issue = "selected kernel boot relocations do not match its exact image";
      return false;
    };
    auto proof = std::make_shared<ct_kernel_interrupt_proof>();
    const ct_kernel_interrupt_layout selected{
        uint32_t(interrupt_layout[0]), uint32_t(interrupt_layout[1]),
        uint32_t(interrupt_layout[2]), uint32_t(interrupt_layout[3]),
        uint32_t(interrupt_layout[4]), uint32_t(interrupt_layout[5]),
        uint32_t(interrupt_layout[6])};
    if (!ct_kernel_interrupt_prepare(kernel_image, kernel_build_id, selected,
                                     boot_relocations, interrupt_identity,
                                     verify_relocations, *proof, error))
      return false;
    interrupt_identity += proof->image_digest + ":" + proof->relocation_digest;
    prepared.interrupt = std::move(proof);
  }
  if (!read_preparation_file(workspace.path + "/.target.o.cmd", bytes, error))
    return false;
  std::string command(bytes.begin(), bytes.end());
  const size_t command_begin = command.find(" := ");
  if (command_begin == std::string::npos) {
    error = "kernel compiler command is unavailable";
    return false;
  }
  {
    llvm::BumpPtrAllocator command_allocator;
    llvm::StringSaver command_saver(command_allocator);
    llvm::SmallVector<const char *, 128> command_tokens;
    llvm::cl::TokenizeGNUCommandLine(
        command.substr(command_begin + 4,
                       command.find('\n') - command_begin - 4),
        command_saver, command_tokens);
    if (command_tokens.empty() || command_tokens.front() != compiler) {
      error = "Kbuild did not use the selected kernel compiler";
      return false;
    }
    for (size_t index = 1; index < command_tokens.size(); ++index) {
      const std::string argument(command_tokens[index]);
      if (argument == ";")
        break;
      if (argument == "-o" || argument == "-MF" || argument == "-MT" ||
          argument == "-MQ") {
        ++index;
        continue;
      }
      if (argument == "-I" && index + 1 < command_tokens.size() &&
          std::string(command_tokens[index + 1]).find(workspace.path) !=
              std::string::npos) {
        ++index;
        continue;
      }
      if (argument == "-c" || argument == "target.c" ||
          argument == "./target.c" || argument == "target.o" ||
          argument == "./target.o" ||
          argument.find(workspace.path) != std::string::npos ||
          argument.rfind("-Wp,-MMD,", 0) == 0 ||
          argument.rfind("-DKBUILD_", 0) == 0 ||
          argument.rfind("-D__KBUILD_", 0) == 0)
        continue;
      prepared.compiler_arguments.push_back(argument);
    }
  }
  // Each warm preparation repeats dependency discovery. Hash the files Kbuild
  // actually selected as well, including private inline implementations whose
  // names alone do not identify their contents.
  std::set<std::string> dependencies;
  std::istringstream dependency_lines(command);
  std::string dependency_line;
  while (std::getline(dependency_lines, dependency_line)) {
    const size_t begin = dependency_line.find_first_not_of(" \t");
    if (begin == std::string::npos || dependency_line[begin] != '/')
      continue;
    const size_t end = dependency_line.find_first_of(" \t", begin);
    const std::string dependency = dependency_line.substr(begin, end - begin);
    if (dependency.rfind(workspace.path + "/", 0) != 0)
      dependencies.insert(dependency);
  }
  std::string source =
      std::filesystem::canonical(build + "/source", filesystem_error).string();
  if (filesystem_error)
    source = build;
  std::vector<std::string> noreturn_symbols;
  std::string noreturn_identity;
  {
    const std::string noreturns = source + "/tools/objtool/noreturns.h";
    bool missing = false;
    if (!read_preparation_noreturns(noreturns, bytes, missing, error))
      return false;
    noreturn_identity = noreturns + (missing ? ":absent\n" : ":present\n");
    if (!missing) {
      dependencies.insert(noreturns);
      std::istringstream declarations(std::string(bytes.begin(), bytes.end()));
      std::set<std::string> names;
      std::string line;
      while (std::getline(declarations, line)) {
        const auto begin = line.find_first_not_of(" \t\r");
        if (begin == std::string::npos || line.compare(begin, 8, "NORETURN"))
          continue;
        line = line.substr(begin, line.find_last_not_of(" \t\r") - begin + 1);
        if (line.size() < 11 || line.compare(0, 9, "NORETURN(") ||
            line.back() != ')') {
          error = "unsupported selected-kernel objtool noreturn declaration";
          return false;
        }
        const std::string name = line.substr(9, line.size() - 10);
        if (name.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
                "WXYZ0123456789_") != std::string::npos ||
            (name.front() >= '0' && name.front() <= '9') ||
            !names.insert(name).second) {
          error =
              "invalid or duplicate selected-kernel objtool noreturn symbol";
          return false;
        }
      }
      if (names.empty()) {
        error = "selected-kernel objtool noreturn declarations are unavailable";
        return false;
      }
      noreturn_symbols.assign(names.begin(), names.end());
    }
  }
  for (const char *script :
       {"Makefile", "scripts/Makefile.build", "scripts/Makefile.lib",
        "scripts/Makefile.compiler", "scripts/Makefile.host",
        "scripts/Makefile.asm-headers", "scripts/Kbuild.include"})
    dependencies.insert(source + "/" + script);
  size_t position = 0;
  while ((position = command.find(workspace.path, position)) !=
         std::string::npos) {
    command.replace(position, workspace.path.size(), "/ctrace-kernel-build");
    position += std::strlen("/ctrace-kernel-build");
  }
  // Kbuild's own objtool invocation is the authoritative configuration. Reject
  // compound commands rather than evaluating shell text from a command file.
  const size_t tool_begin = command.find(objtool + " ");
  const size_t tool_end = tool_begin == std::string::npos
                              ? std::string::npos
                              : command.find(" target.o", tool_begin);
  size_t absolute_end =
      tool_begin == std::string::npos
          ? std::string::npos
          : command.find(" /ctrace-kernel-build/target.o", tool_begin);
  const size_t invocation_end = std::min(tool_end, absolute_end);
  if (tool_begin == std::string::npos || invocation_end == std::string::npos) {
    error = "cannot recover the exact kernel objtool configuration";
    return false;
  }
  llvm::BumpPtrAllocator allocator;
  llvm::StringSaver saver(allocator);
  llvm::SmallVector<const char *, 32> tokens;
  llvm::cl::TokenizeGNUCommandLine(
      command.substr(tool_begin, invocation_end - tool_begin), saver, tokens);
  std::vector<std::string> validation;
  for (const char *token : tokens) {
    std::string argument(token);
    if (validation.empty()) {
      if (argument != objtool) {
        error = "unexpected objtool executable";
        return false;
      }
    } else if (argument.find_first_not_of("-_="
                                          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
                                          "KLMNOPQRSTUVWXYZ0123456789,") !=
                   std::string::npos ||
               argument.rfind("--", 0) != 0) {
      error = "unsupported objtool invocation argument";
      return false;
    }
    validation.push_back(std::move(argument));
  }
  if (std::find(validation.begin(), validation.end(), "--werror") ==
      validation.end())
    validation.push_back("--werror");
  std::string identity = ct_cache_key(
      {command, options.runtime_identity, target_digest, kernel_identity,
       resource_identity, interrupt_identity, noreturn_identity});
  for (const std::string &path :
       {build + "/.config", build + "/Makefile",
        build + "/include/generated/autoconf.h",
        build + "/include/config/auto.conf",
        build + "/include/config/kernel.release", build + "/Module.symvers",
        build + "/scripts/module.lds"}) {
    if (!read_preparation_file(path, bytes, error))
      return false;
    identity += path + ":" + preparation_digest(bytes) + "\n";
  }
  for (const std::string &path : dependencies) {
    if (!read_preparation_file(path, bytes, error))
      return false;
    identity += path + ":" + preparation_digest(bytes) + "\n";
  }
  for (const std::string &tool : {make, compiler, linker, objcopy, objtool})
    if (!preparation_tool_identity(tool, workspace, identity, error))
      return false;
  if (clang) {
    for (const auto &[variable, tool] : llvm_tools)
      if (tool != objcopy &&
          !preparation_tool_identity(tool, workspace, identity, error))
        return false;
  } else {
    for (const char *program : {"cc1", "as"}) {
      if (!run_preparation(
              {compiler, std::string("-print-prog-name=") + program}, workspace,
              output, error))
        return false;
      output.erase(output.find_last_not_of("\r\n") + 1);
      const std::string tool = output.find('/') == std::string::npos
                                   ? preparation_tool(output)
                                   : output;
      if (!preparation_tool_identity(tool, workspace, identity, error))
        return false;
    }
  }
  if (std::string_view(noreturn_identity).ends_with(":absent\n")) {
    if (!preparation_noreturn_witnesses(image, workspace, compiler, objtool,
                                        entry_unwind, identity,
                                        noreturn_symbols, error))
      return false;
    for (const auto &name : noreturn_symbols)
      identity += "noreturn:" + name + '\n';
  }
  prepared.module_name = image.name;
  prepared.original_digest =
      image.input_digest.empty() ? image.digest : image.input_digest;
  prepared.kernel_identity = ct_cache_key({identity});
  ct_kernel_rewrite_plan rewrite;
  if (!rewrite.prepare(image, prepared.sites, error, [&] {
        if (options.progress)
          options.progress("Analyzing all module instructions");
      }))
    return false;
  auto source_metadata = std::make_shared<ct_kernel_source_metadata>();
  auto values = std::make_shared<ct_kernel_value_metadata>();
  auto source_options = options.source;
  source_options.kernel_build = build;
  source_options.arguments = prepared.compiler_arguments;
  if (!ct_kernel_collect_source(image, prepared.sites, source_options,
                                *source_metadata, error) ||
      !ct_kernel_collect_values(image, prepared.sites, *values, error) ||
      !ct_kernel_complete_source(image, prepared.sites, *values,
                                 *source_metadata, error))
    return false;
  std::string decompile_identity;
  if (options.decompile) {
    std::vector<unsigned char> analysis_image;
    if (options.analysis_helper.empty() ||
        access(options.analysis_helper.c_str(), X_OK) != 0) {
      error = "kernel decompile analysis helper is unavailable";
      return false;
    }
    if (!ct_kernel_make_decompile_image(image, analysis_image, error))
      return false;
    ct_kernel_decompile_client producer;
    std::string manifest;
    const std::string analysis_identity = ct_cache_key(
        {"kernel-decompile", image.digest, prepared.kernel_identity});
    if (!producer.open(
            options.analysis_helper, image.path, analysis_identity,
            analysis_image,
            [&](const ct_analysis_progress &progress) {
              if (options.progress)
                options.progress(progress.detail);
            },
            manifest, error))
      return false;
    std::vector<unsigned char>().swap(analysis_image);
    ct_kernel_decompile_layout decompiled_layout;
    if (!ct_kernel_parse_decompile_layout(image, manifest, decompiled_layout,
                                          error))
      return false;
    std::string().swap(manifest);
    auto metadata = std::make_shared<ct_kernel_decompile_metadata>();
    if (!ct_kernel_collect_decompile(
            image, prepared.sites, *source_metadata, decompiled_layout,
            [&](uint32_t section, uint64_t offset, ct_decompile_view &view,
                std::string &issue) {
              const auto region = std::find_if(
                  decompiled_layout.regions.begin(),
                  decompiled_layout.regions.end(),
                  [&](const auto &entry) { return entry.section == section; });
              if (region == decompiled_layout.regions.end() ||
                  offset >= region->size) {
                issue = "decompile request is outside its original section";
                return false;
              }
              const __int128 address = __int128(region->address) + offset -
                                       decompiled_layout.image_base;
              if (address < 0 || address > UINT64_MAX) {
                issue = "decompile request address overflows";
                return false;
              }
              return producer.function(uint64_t(address), CT_DECOMPILE_FULL,
                                       view, issue);
            },
            *values, *metadata, error))
      return false;
    // The module descriptor supplies stronger ABI evidence than an inferred
    // prototype: init is int(void), exit is void(void). Identify its exact
    // relocation fields using this kernel's layout, never by source names.
    for (const auto &descriptor : image.symbols) {
      if (descriptor.name != "__this_module" || descriptor.type != STT_OBJECT ||
          descriptor.size != layout[0])
        continue;
      for (bool entering : {true, false}) {
        const uint64_t member = layout[entering ? 1 : 2];
        if (descriptor.offset > UINT64_MAX - member)
          continue;
        const ct_kernel_symbol *target = nullptr;
        bool ambiguous = false;
        for (const auto &relocation : image.relocations) {
          if (relocation.section != descriptor.section ||
              relocation.offset != descriptor.offset + member)
            continue;
          if (target || relocation.type != R_X86_64_64 || relocation.addend) {
            ambiguous = true;
            break;
          }
          for (const auto &symbol : image.symbols)
            if (symbol.table == relocation.symbol_table &&
                symbol.index == relocation.symbol && symbol.type == STT_FUNC &&
                symbol.section && symbol.section < SHN_LORESERVE &&
                symbol.section < image.sections.size()) {
              target = &symbol;
              break;
            }
        }
        if (!target || ambiguous)
          continue;
        for (auto &function : metadata->functions) {
          if (function.section != target->section ||
              function.begin != target->offset || !function.value_function ||
              function.value_function >= values->functions.size())
            continue;
          function.prototype = std::string(entering ? "int32_t " : "void ") +
                               function.name + "(void)";
          function.parameters.clear();
          auto &contract = values->functions[function.value_function];
          contract.returns_void = !entering;
          contract.return_type = 0;
          contract.return_register = entering ? 0 : UINT32_MAX;
          if (entering) {
            const auto type =
                std::find_if(values->types.begin(), values->types.end(),
                             [](const auto &entry) {
                               return !entry.guarded &&
                                      entry.name == "int32_t" &&
                                      entry.scalar.kind == CT_VALUE_SIGNED &&
                                      entry.scalar.bytes == 4;
                             });
            contract.return_type = uint32_t(type - values->types.begin());
            if (type == values->types.end())
              values->types.push_back({{CT_VALUE_SIGNED, 4}, "int32_t", false});
          }
        }
      }
    }
    if (!ct_kernel_complete_decompile_returns(*values, *metadata, error))
      return false;
    decompile_identity = producer.identity();
    if (!producer.finish(error))
      return false;
    // No worker, LLVM decompile parser, or mapped function view survives into
    // module execution. Only the normalized immutable observation data does.
    if (options.source.warning)
      for (const auto &warning : metadata->warnings)
        options.source.warning(warning);
    prepared.decompile = std::move(metadata);
  }
  std::vector<ct_kernel_capture_plan> captures(1);
  if (options.observation.emit_terminal &&
      !ct_kernel_plan_captures(image, prepared.sites, *source_metadata, *values,
                               captures, error))
    return false;
  std::vector<ct_kernel_xstate_site> xstate;
  std::map<uint64_t, uint8_t> tiles;
  std::map<uint64_t, uint32_t> scalar;
  if (!rewrite.xstate_sites(image, xstate, error, &tiles, &scalar) ||
      (options.observation.emit_terminal &&
       !ct_kernel_plan_xstate(xstate, *values, captures, error, tiles, scalar,
                              source_metadata.get(), &prepared.sites,
                              prepared.decompile.get())))
    return false;
  prepared.captures =
      std::make_shared<const std::vector<ct_kernel_capture_plan>>(
          std::move(captures));
  prepared.source = std::move(source_metadata);
  prepared.values = std::move(values);
  auto observation = options.observation;
  observation.source = prepared.source;
  observation.decompile = prepared.decompile;
  observation.values = observation.emit_terminal ? prepared.values : nullptr;
  observation.captures =
      observation.emit_terminal ? prepared.captures : nullptr;
  prepared.trace = std::make_shared<ct_kernel_trace>();
  if (!prepared.trace->prepare(image, prepared.sites, observation, error))
    return false;
  std::vector<unsigned char> capture_identity;
  const auto capture_field = [&](const auto &value) {
    const auto *begin = reinterpret_cast<const unsigned char *>(&value);
    capture_identity.insert(capture_identity.end(), begin,
                            begin + sizeof(value));
  };
  capture_field(uint64_t(prepared.captures->size()));
  for (const auto &plan : *prepared.captures) {
    capture_field(uint64_t(plan.slots.size()));
    for (const auto &slot : plan.slots) {
      const auto &capture = slot.capture;
      capture_field(capture.object);
      capture_field(capture.object_size);
      capture_field(capture.offset);
      capture_field(capture.kind);
      capture_field(capture.reg);
      capture_field(capture.size);
      capture_field(slot.section);
      capture_field(slot.object_offset);
    }
  }
  for (const auto &site : prepared.values->sites)
    capture_field(site.capture_plan);
  ct_kernel_copies copies;
  const auto &policy = prepared.trace->prepared_policy();
  const auto &timing = prepared.trace->timing_sites();
  const auto &observations = prepared.trace->observation_sites();
  if (options.progress)
    options.progress(prepared.minimum_level == KCTRACE_LEVEL_FULL
                         ? "Preparing full module execution boundaries"
                     : prepared.minimum_level == KCTRACE_LEVEL_PERFETTO
                         ? "Preparing perfetto and full module copies"
                         : "Preparing arm, perfetto and full module copies");
  if (!rewrite.emit_copies(image, policy, copies, error, timing,
                           noreturn_symbols, nullptr,
                           prepared.minimum_level == KCTRACE_LEVEL_FULL,
                           &observations, prepared.minimum_level))
    return false;
  prepared.level_selection = !copies.single_full;
  if (copies.single_full)
    prepared.program_flags |= KCTRACE_PROGRAM_SINGLE_FULL;
  const auto fixed_functions =
      std::count(copies.function_levels.begin() + 1,
                 copies.function_levels.end(), KCTRACE_LEVEL_FULL);
  if (fixed_functions)
    prepared.program_flags |= KCTRACE_PROGRAM_FIXED_FULL;
  if (options.progress && prepared.minimum_level < KCTRACE_LEVEL_FULL) {
    options.progress("Prepared " +
                     std::to_string(copies.functions.size() - fixed_functions) +
                     " selectable functions and " +
                     std::to_string(fixed_functions) + " fixed full functions");
    for (const auto &restriction : copies.restrictions) {
      const auto &function = policy.functions[restriction.function];
      const auto alias = policy.aliases[function.first_alias];
      options.progress("Fixed full " + image.symbols[alias].name + ": " +
                       restriction.reason);
    }
  }
  // Both layouts carry the same compiled scope policy and execution identities.
  // A full-only artifact must not be reused with another filter configuration.
  capture_field(prepared.program_flags);
  capture_field(prepared.minimum_level);
  for (auto level : copies.function_levels)
    capture_field(level);
  capture_field(uint64_t(policy.functions.size()));
  for (const auto &function : policy.functions)
    capture_field(function.states);
  capture_field(uint64_t(policy.paths.size()));
  for (const auto &path : policy.paths)
    capture_field(path.states);
  capture_field(uint64_t(policy.sites.size()));
  for (const auto &site : policy.sites) {
    capture_field(site.function);
    capture_field(site.path);
  }
  capture_field(uint64_t(timing.size()));
  for (uint64_t site : timing)
    capture_field(site);
  capture_field(uint64_t(observations.size()));
  for (uint8_t observed : observations)
    capture_field(observed);
  const auto *expected_copies = &copies;
  const std::string key =
      ct_cache_key({"kernel-prepared",
                    image.digest,
                    prepared.kernel_identity,
                    target_digest,
                    decompile_identity,
                    {reinterpret_cast<const char *>(capture_identity.data()),
                     capture_identity.size()}});
  std::vector<unsigned char> cached;
  if (!options.runtime_identity.empty() &&
      ct_cache_read("kernel-prepared", key, cached)) {
    size_t offset = 0;
    const auto field = [&](auto &value) {
      if (sizeof(value) > cached.size() - offset)
        return false;
      std::memcpy(&value, cached.data() + offset, sizeof(value));
      offset += sizeof(value);
      return true;
    };
    uint64_t count = 0, size = 0;
    bool valid = field(count) && field(size) && field(prepared.probe_count) &&
                 count <= UINT32_MAX &&
                 size <= std::vector<unsigned char>{}.max_size();
    valid &= count == prepared.sites.size();
    for (uint64_t index = 0; valid && index < count; ++index) {
      ct_kernel_site site;
      uint8_t probe = 0;
      valid = field(site.section) && field(site.offset) && field(site.entry) &&
              field(site.operation) && field(site.id) &&
              field(site.original_size) && field(site.emitted_size) &&
              field(probe) && probe <= 1;
      site.probe = probe != 0;
      if (valid) {
        const auto &expected = prepared.sites[index];
        valid =
            site.section == expected.section &&
            site.offset == expected.offset && site.entry == expected.entry &&
            site.operation == expected.operation && site.id == expected.id &&
            site.original_size == expected.original_size &&
            site.emitted_size == expected.emitted_size &&
            site.probe == expected.probe;
      }
    }
    if (valid && size == cached.size() - offset) {
      prepared.bytes.assign(cached.begin() + offset, cached.end());
      if (ct_kernel_validate_prepared(image, prepared, layout, parameter_layout,
                                      error, expected_copies)) {
        prepared.cache_hit = true;
        return true;
      }
    }
    prepared.bytes.clear();
    prepared.probe_count = 0;
    prepared.manifest_offset = 0;
    prepared.template_digest.clear();
    error.clear();
  }
  std::vector<unsigned char> expanded;
  {
    std::vector<uint32_t> captures_by_site;
    captures_by_site.reserve(prepared.values->sites.size());
    for (const auto &site : prepared.values->sites)
      captures_by_site.push_back(site.capture_plan);
    if (!ct_kernel_materialize_copies(
            image, prepared.trace->prepared_policy(), copies,
            prepared.program_flags, captures_by_site, expanded, error,
            prepared.interrupt.get(),
            ct_kernel_capture_xstate_masks(*prepared.values,
                                           *prepared.captures)))
      return false;
  }
  if (options.progress)
    options.progress(
        "Binding prepared instructions, value captures and entry/exit");
  ct_kernel_image expanded_image;
  expanded_image.bytes = std::move(expanded);
  ct_kernel_object object(expanded_image);
  if (!object.valid(error))
    return false;
  std::vector<unsigned char>().swap(expanded_image.bytes);
  uint32_t descriptor_table = 0, descriptor_index = 0;
  Elf64_Sym descriptor{};
  if (!preparation_symbol(object, "__this_module", descriptor_table,
                          descriptor_index, descriptor, error) ||
      descriptor.st_size != layout[0] || descriptor.st_value) {
    error = "module descriptor does not match the selected kernel headers";
    return false;
  }
  uint32_t init_table = 0, init_index = 0, exit_table = 0, exit_index = 0;
  Elf64_Sym original_init{}, original_exit{};
  if (!preparation_symbol(object, "init_module", init_table, init_index,
                          original_init, error) ||
      !preparation_symbol(object, "cleanup_module", exit_table, exit_index,
                          original_exit, error) ||
      init_table != descriptor_table || exit_table != descriptor_table ||
      !original_init.st_shndx || !original_exit.st_shndx) {
    error =
        "module requires concrete init_module and cleanup_module definitions";
    return false;
  }
  Elf64_Sym wrapper{};
  wrapper.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
  uint32_t init_wrapper = 0, exit_wrapper = 0;
  if (!object.append_symbol(descriptor_table, "__ctrace_init", wrapper,
                            init_wrapper, error) ||
      !object.append_symbol(descriptor_table, "__ctrace_exit", wrapper,
                            exit_wrapper, error))
    return false;
  unsigned init_replaced = 0, exit_replaced = 0;
  for (uint32_t section = 1; section < object.section_count(); ++section) {
    const auto *header = object.section_header(section);
    if (header->sh_type != SHT_RELA || header->sh_info != descriptor.st_shndx)
      continue;
    const std::vector<unsigned char> content = *object.section_content(section);
    for (size_t offset = 0; offset < content.size();
         offset += sizeof(Elf64_Rela)) {
      Elf64_Rela relocation{};
      std::memcpy(&relocation, content.data() + offset, sizeof(relocation));
      const uint32_t reference = ELF64_R_SYM(relocation.r_info);
      if (relocation.r_offset != layout[1] && relocation.r_offset != layout[2])
        continue;
      const bool init = relocation.r_offset == layout[1];
      const auto *symbols = object.section_content(header->sh_link);
      Elf64_Sym target{};
      if (!symbols || reference >= symbols->size() / sizeof(target)) {
        error = "module init/exit descriptor has an invalid symbol reference";
        return false;
      }
      std::memcpy(&target, symbols->data() + reference * sizeof(target),
                  sizeof(target));
      const auto &expected = init ? original_init : original_exit;
      if (header->sh_link != descriptor_table ||
          ELF64_R_TYPE(relocation.r_info) != R_X86_64_64 ||
          target.st_shndx != expected.st_shndx ||
          __int128(target.st_value) + relocation.r_addend !=
              expected.st_value) {
        error = "module init/exit descriptor relocation does not match kernel "
                "layout";
        return false;
      }
      relocation.r_info =
          ELF64_R_INFO(init ? init_wrapper : exit_wrapper, R_X86_64_64);
      relocation.r_addend = 0;
      if (!object.replace_relocation(section, offset / sizeof(relocation),
                                     relocation, error))
        return false;
      ++(init ? init_replaced : exit_replaced);
    }
  }
  if (init_replaced != 1 || exit_replaced != 1) {
    error = "module init/exit descriptor relocations are ambiguous or absent";
    return false;
  }
  if (!prepared.captures || prepared.captures->empty() ||
      prepared.captures->size() > 65537) {
    error = "invalid prepared capture plan count";
    return false;
  }
  std::vector<ct_kernel_capture_chunk_plan> capture_chunks;
  if (!ct_kernel_capture_chunks(*prepared.captures, capture_chunks, error))
    return false;
  const uint64_t capture_count = capture_chunks.size();
  std::vector<unsigned char> capture_bytes(capture_count *
                                           sizeof(kctrace_capture_plan));
  for (size_t index = 1; index <= capture_chunks.size(); ++index)
    for (size_t slot = 0; slot < KCTRACE_VALUE_SLOTS; ++slot)
      std::memcpy(capture_bytes.data() +
                      (index - 1) * sizeof(kctrace_capture_plan) +
                      slot * sizeof(kctrace_capture),
                  &capture_chunks[index - 1].slots[slot].capture,
                  sizeof(kctrace_capture));
  for (size_t index = 0; index < capture_chunks.size(); ++index) {
    std::memcpy(capture_bytes.data() + index * sizeof(kctrace_capture_plan) +
                    offsetof(kctrace_capture_plan, next),
                &capture_chunks[index].next, sizeof(uint32_t));
    std::memcpy(capture_bytes.data() + index * sizeof(kctrace_capture_plan) +
                    offsetof(kctrace_capture_plan, xstate_mask),
                &capture_chunks[index].xstate_mask, sizeof(uint32_t));
  }
  const uint32_t capture_section = object.add_section(
      ".init.rodata.ctrace_capture_plans", SHT_PROGBITS, SHF_ALLOC, 8,
      sizeof(kctrace_capture_plan), 0, 0, capture_bytes, error);
  if (!capture_section || capture_section >= SHN_LORESERVE)
    return false;
  Elf64_Sym capture_symbol{};
  capture_symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
  capture_symbol.st_shndx = capture_section;
  capture_symbol.st_size = capture_bytes.size();
  uint32_t capture_symbol_index = 0;
  if (!object.append_symbol(descriptor_table, "__ctrace_capture_plans",
                            capture_symbol, capture_symbol_index, error))
    return false;
  std::map<uint32_t, uint32_t> data_anchors;
  for (size_t index = 1; index <= capture_chunks.size(); ++index) {
    for (size_t slot_index = 0; slot_index < KCTRACE_VALUE_SLOTS;
         ++slot_index) {
      const auto &slot = capture_chunks[index - 1].slots[slot_index];
      if (slot.capture.kind != KCTRACE_CAPTURE_OBJECT)
        continue;
      if (!slot.section || slot.section >= image.sections.size() ||
          slot.object_offset > image.sections[slot.section].size ||
          slot.capture.object_size >
              image.sections[slot.section].size - slot.object_offset) {
        error = "capture object exceeds its original section";
        return false;
      }
      auto anchor = data_anchors.find(slot.section);
      if (anchor == data_anchors.end()) {
        Elf64_Sym symbol{};
        symbol.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
        symbol.st_other = STV_HIDDEN;
        symbol.st_shndx = slot.section;
        uint32_t symbol_index = 0;
        if (!object.append_symbol(descriptor_table,
                                  "__ctrace_data_anchor_" +
                                      std::to_string(slot.section),
                                  symbol, symbol_index, error))
          return false;
        anchor = data_anchors.emplace(slot.section, symbol_index).first;
      }
      Elf64_Rela relocation{};
      relocation.r_offset = (index - 1) * sizeof(kctrace_capture_plan) +
                            slot_index * sizeof(kctrace_capture) +
                            offsetof(kctrace_capture, object);
      relocation.r_info = ELF64_R_INFO(anchor->second, R_X86_64_64);
      relocation.r_addend = slot.object_offset;
      if (!object.add_relocation(capture_section, descriptor_table, relocation,
                                 error))
        return false;
    }
  }
  std::vector<unsigned char> capture_count_bytes(sizeof(capture_count));
  std::memcpy(capture_count_bytes.data(), &capture_count,
              sizeof(capture_count));
  const uint32_t capture_count_section = object.add_section(
      ".init.rodata.ctrace_capture_count", SHT_PROGBITS, SHF_ALLOC, 8,
      sizeof(capture_count), 0, 0, capture_count_bytes, error);
  if (!capture_count_section || capture_count_section >= SHN_LORESERVE)
    return false;
  capture_symbol.st_shndx = capture_count_section;
  capture_symbol.st_size = sizeof(capture_count);
  if (!object.append_symbol(descriptor_table, "__ctrace_capture_plan_count",
                            capture_symbol, capture_symbol_index, error))
    return false;
  std::string annotations = "#include <linux/annotate.h>\n"
                            "#include <linux/objtool.h>\n"
                            "#include <asm/orc_types.h>\n";
  // The module link discards the original NOENDBR annotations. Static-call
  // updates take trampoline addresses as data; they never enter indirectly.
  // Restore the annotation for the independently validated fixed layout.
  for (const auto &symbol : image.symbols)
    if (symbol.type == STT_FUNC && symbol.section < image.sections.size() &&
        image.sections[symbol.section].name == ".static_call.text")
      annotations += "__ASM_ANNOTATE(.discard.annotate_insn, " + symbol.name +
                     ", ANNOTYPE_NOENDBR)\n";
  std::set<uint32_t> anchors;
  for (const auto &site : prepared.sites)
    prepared.probe_count += site.probe;
  {
    // Immutable program pointers are lookup keys. Objtool must not mistake
    // interior gate/probe addresses for new indirect IBT entry points.
    std::set<std::pair<uint32_t, uint64_t>> lookup_addresses;
    if (prepared.interrupt)
      for (const auto &function : copies.functions)
        lookup_addresses.emplace(function.canonical.section,
                                 function.canonical.offset);
    for (const auto &site : copies.sites)
      for (const auto &location : site.levels)
        if (location.probe) {
          lookup_addresses.emplace(location.operation.section,
                                   location.operation.offset - 1);
          lookup_addresses.emplace(location.operation.section,
                                   location.operation.offset);
        }
    for (const auto &gate : copies.boundaries) {
      lookup_addresses.emplace(gate.entry.section, gate.entry.offset);
      lookup_addresses.emplace(gate.selector_return.section,
                               gate.selector_return.offset);
      for (const auto &target : gate.continuations)
        if (target.section)
          lookup_addresses.emplace(target.section, target.offset);
      for (const auto &target : gate.call_returns)
        if (target.section)
          lookup_addresses.emplace(target.section, target.offset);
    }
    for (const auto &[section, offset] : lookup_addresses) {
      const std::string name =
          "__ctrace_copy_anchor_" + std::to_string(section);
      const auto *header = object.section_header(section);
      if (!header || offset > header->sh_size) {
        error = "copy lookup address exceeds its generated section";
        return false;
      }
      if (anchors.insert(section).second) {
        uint32_t table = 0, index = 0;
        Elf64_Sym anchor{};
        if (!preparation_symbol(object, name, table, index, anchor, error) ||
            anchor.st_shndx != section || anchor.st_value) {
          error = "copy lookup address has no exact generated section anchor";
          return false;
        }
      }
      // A final noreturn CALL has a one-past lookup key. Linking target.o
      // can place alignment padding or its code at that address; annotate
      // only that now-interior key, preserving an actual ENDBR landing.
      if (offset == header->sh_size) {
        const auto appended = appended_code.find(object.section_name(section));
        if (appended == appended_code.end())
          continue;
        const auto [alignment, size, landing] = appended->second;
        if ((!alignment || offset % alignment == 0) && (!size || landing))
          continue;
      }
      // Single-full ENTRY and address-taken SCOPE keys can name the actual
      // ENDBR landing pad. Preserve its indirect-entry annotation semantics.
      const auto &code = *object.section_content(section);
      static constexpr unsigned char endbr[] = {0xf3, 0x0f, 0x1e, 0xfa};
      if (code.size() - offset >= sizeof(endbr) &&
          !std::memcmp(code.data() + offset, endbr, sizeof(endbr)))
        continue;
      annotations += "__ASM_ANNOTATE(.discard.annotate_insn, " + name + "+" +
                     std::to_string(offset) + ", ANNOTYPE_NOENDBR)\n";
    }
  }
  {
    // Objtool's noreturn scan follows only one cold child per function. A
    // layered split function can end its symbol inventory with a fragment
    // whose return lives in another fragment. Restore the original return
    // evidence at direct callers; stack/control-flow validation stays active.
    std::set<uint32_t> split_functions, returning;
    for (size_t index = 1; index < policy.functions.size(); ++index)
      if (policy.functions[index].logical_function != index)
        split_functions.insert(policy.functions[index].logical_function);
    for (const auto &boundary : copies.boundaries)
      if (boundary.kind == ct_kernel_copy_boundary_kind::return_ &&
          split_functions.count(boundary.function))
        returning.insert(boundary.function);
    std::set<uint64_t> calls;
    for (const auto &boundary : copies.boundaries)
      if (boundary.kind == ct_kernel_copy_boundary_kind::call_before &&
          returning.count(boundary.target_function))
        calls.insert(boundary.site_id);
    std::set<std::pair<uint32_t, uint64_t>> emitted;
    for (const auto &site : copies.sites) {
      if (!calls.count(site.id))
        continue;
      for (const auto &location : site.levels) {
        if (!location.operation.section)
          continue;
        const auto &operation = location.operation;
        if (!emitted.emplace(operation.section, operation.offset).second)
          continue;
        const auto *code = object.section_content(operation.section);
        if (!code || location.emitted_size < 5 ||
            operation.offset > code->size() ||
            location.emitted_size > code->size() - operation.offset ||
            (*code)[operation.offset + location.emitted_size - 5] != 0xe8) {
          error = "split function return evidence has no exact direct CALL";
          return false;
        }
        annotations +=
            "__ASM_ANNOTATE(.discard.annotate_insn, __ctrace_copy_anchor_" +
            std::to_string(operation.section) + "+" +
            std::to_string(operation.offset) + ", ANNOTYPE_REACHABLE)\n";
      }
    }
  }
  if (!preparation_bug_hints(image, copies, bug_layout, annotations, error) ||
      !preparation_unwind_hints(image, copies, entry_unwind, annotations,
                                error))
    return false;
  annotations += ".section .note.GNU-stack,\"\",@progbits\n";
  bytes.assign(annotations.begin(), annotations.end());
  if (!write_preparation_file(workspace.path + "/annotations.S", bytes,
                              error) ||
      !object.serialize(bytes, error) ||
      !write_preparation_file(workspace.path + "/expanded.o", bytes, error))
    return false;
  std::vector<unsigned char>().swap(bytes);
  compile.back() = "annotations.o";
  std::vector<std::string> link{linker};
  if (clang)
    link.push_back("--threads=1");
  link.insert(link.end(), {"-r", "expanded.o", "target.o", "annotations.o",
                           "-o", "linked.o"});
  if (!run_preparation(compile, workspace, output, error) ||
      !run_preparation(link, workspace, output, error))
    return false;
  std::vector<std::string> strip{objcopy, "--wildcard",
                                 "--strip-symbol=__pfx_*"};
  for (const char *section :
       {".return_sites", ".call_sites", ".static_call_sites",
        ".retpoline_sites", ".ibt_endbr_seal", ".note.gnu.build-id",
        ".orc_unwind", ".orc_unwind_ip"})
    strip.push_back(std::string("--remove-section=") + section);
  strip.insert(strip.end(), {"linked.o", "validated.o"});
  if (!run_preparation(strip, workspace, output, error))
    return false;
  if (options.progress)
    options.progress(
        "Validating rewritten module control flow and unwind metadata");
  // Existing fentry slots have already become NOPs, so objtool cannot
  // reconstruct their table from CALL relocations. Its addresses were mapped
  // with the original instructions; retain that table and skip regeneration.
  if (std::any_of(
          image.sections.begin(), image.sections.end(),
          [](const auto &section) { return section.name == "__mcount_loc"; })) {
    std::erase(validation, "--mcount");
    std::erase(validation, "--mnop");
  }
  validation.push_back("validated.o");
  link.resize(clang ? 2 : 1);
  link.insert(link.end(),
              {"-r", "--build-id=sha1", "-T", build + "/scripts/module.lds",
               "validated.o", "-o", "final.ko"});
  if (!run_preparation(validation, workspace, output, error) ||
      !run_preparation(link, workspace, output, error) ||
      !read_preparation_file(workspace.path + "/final.ko", prepared.bytes,
                             error) ||
      !ct_kernel_validate_prepared(image, prepared, layout, parameter_layout,
                                   error, expected_copies))
    return false;
  if (!options.runtime_identity.empty()) {
    cached.clear();
    const auto field = [&](const auto &value) {
      const auto *begin = reinterpret_cast<const unsigned char *>(&value);
      cached.insert(cached.end(), begin, begin + sizeof(value));
    };
    field(uint64_t(prepared.sites.size()));
    field(uint64_t(prepared.bytes.size()));
    field(prepared.probe_count);
    for (const auto &site : prepared.sites) {
      field(site.section);
      field(site.offset);
      field(site.entry);
      field(site.operation);
      field(site.id);
      field(site.original_size);
      field(site.emitted_size);
      field(site.probe);
    }
    cached.insert(cached.end(), prepared.bytes.begin(), prepared.bytes.end());
    ct_cache_write("kernel-prepared", key, cached);
  }
  return true;
}

bool ct_kernel_bind_prepared(const ct_kernel_prepared &prepared,
                             const kctrace_prepare &session,
                             std::vector<unsigned char> &bound,
                             std::string &error) {
  bound.clear();
  error.clear();
  if (session.size != sizeof(session) ||
      std::memcmp(session.contract_sha256, kctrace_contract_hash,
                  KCTRACE_HASH_SIZE) ||
      session.initial_level != prepared.minimum_level || session.flags ||
      session.reserved || !session.session_id || !prepared.probe_count ||
      prepared.module_name.empty() ||
      prepared.module_name.size() >= sizeof(session.module_name) ||
      session.site_count != prepared.probe_count ||
      strnlen(session.module_name, sizeof(session.module_name)) !=
          prepared.module_name.size() ||
      std::string_view(session.module_name, prepared.module_name.size()) !=
          prepared.module_name ||
      std::all_of(std::begin(session.session_nonce),
                  std::end(session.session_nonce),
                  [](unsigned char value) { return value == 0; }) ||
      prepared.manifest_offset > prepared.bytes.size() ||
      sizeof(kctrace_manifest) >
          prepared.bytes.size() - prepared.manifest_offset ||
      preparation_digest(prepared.bytes) != prepared.template_digest) {
    error = "prepared kernel session does not match the immutable template";
    return false;
  }
  kctrace_manifest manifest{};
  manifest.size = sizeof(manifest);
  std::memcpy(manifest.contract_sha256, kctrace_contract_hash,
              KCTRACE_HASH_SIZE);
  manifest.levels = KCTRACE_LEVEL_MASK_ALL & (~0U << prepared.minimum_level);
  manifest.site_count = prepared.probe_count;
  std::memcpy(manifest.module_name, session.module_name,
              sizeof(manifest.module_name));
  std::memcpy(manifest.original_sha256, session.original_sha256,
              sizeof(manifest.original_sha256));
  std::memcpy(manifest.artifact_sha256, session.artifact_sha256,
              sizeof(manifest.artifact_sha256));
  std::memcpy(manifest.session_nonce, session.session_nonce,
              sizeof(manifest.session_nonce));
  const auto hex = [](const unsigned char *digest) {
    std::string text;
    for (unsigned index = 0; index < KCTRACE_HASH_SIZE; ++index) {
      text += "0123456789abcdef"[digest[index] >> 4];
      text += "0123456789abcdef"[digest[index] & 15];
    }
    return text;
  };
  if (hex(session.original_sha256) != prepared.original_digest ||
      hex(session.artifact_sha256) != prepared.template_digest ||
      std::any_of(prepared.bytes.begin() + prepared.manifest_offset,
                  prepared.bytes.begin() + prepared.manifest_offset +
                      sizeof(manifest),
                  [](unsigned char value) { return value != 0; })) {
    error = "kernel session digests or manifest placeholder are invalid";
    return false;
  }
  bound = prepared.bytes;
  std::memcpy(bound.data() + prepared.manifest_offset, &manifest,
              sizeof(manifest));
  return true;
}
