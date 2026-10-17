#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>

#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <uapi/kctrace.h>

#include "cache.h"
#include "kernel_image.h"
#include "kernel_load.h"
#include "kernel_perfetto.h"
#include "kernel_prepare.h"
#include "kernel_rewrite.h"
#include "kernel_sign.h"
#include "kernel_trace.h"

static bool decode_hash(const std::string &text, unsigned char *output) {
  if (text.size() != KCTRACE_HASH_SIZE * 2)
    return false;
  for (size_t index = 0; index < KCTRACE_HASH_SIZE; ++index) {
    unsigned value = 0;
    const char *begin = text.data() + index * 2;
    const auto parsed = std::from_chars(begin, begin + 2, value, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != begin + 2)
      return false;
    output[index] = value;
  }
  return true;
}

static int open_runtime(kctrace_query &query, std::string &identity,
                        std::string &error) {
  int descriptor = open("/dev/kctrace", O_RDWR | O_CLOEXEC | O_NONBLOCK);
  if (descriptor < 0 && errno == ENOENT) {
    // Only the installed observation runtime is an automatic dependency.
    // The target itself is always inserted through the verified artifact FD.
    const pid_t loader = fork();
    if (loader == 0) {
      execlp("modprobe", "modprobe", "--", "kctrace",
             static_cast<char *>(nullptr));
      _exit(127);
    }
    if (loader < 0) {
      error = "cannot start kctrace runtime loader: " +
              std::string(std::strerror(errno));
      return -1;
    }
    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(loader, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != loader || !WIFEXITED(status) || WEXITSTATUS(status)) {
      error = "kctrace runtime unavailable; install module/ with DKMS for the "
              "running kernel";
      return -1;
    }
    descriptor = open("/dev/kctrace", O_RDWR | O_CLOEXEC | O_NONBLOCK);
  }
  if (descriptor < 0) {
    error = "cannot open /dev/kctrace: " + std::string(std::strerror(errno));
    return -1;
  }
  query.size = sizeof(query);
  query.abi = KCTRACE_ABI_VERSION;
  constexpr uint64_t required =
      KCTRACE_CAP_SESSIONS | KCTRACE_CAP_BINARY_EVENTS | KCTRACE_CAP_OBSERVE |
      KCTRACE_CAP_PROBE_SITES | KCTRACE_CAP_CAPTURE_VALUES |
      KCTRACE_CAP_PREINIT_BIND;
  if (ioctl(descriptor, KCTRACE_IOC_QUERY, &query) != 0) {
    error =
        "cannot query kctrace runtime: " + std::string(std::strerror(errno));
    close(descriptor);
    return -1;
  }
  if (query.size != sizeof(query) || query.abi != KCTRACE_ABI_VERSION ||
      query.event_size != sizeof(kctrace_event) ||
      (query.capabilities & required) != required ||
      query.runtime_build_id_size > sizeof(query.runtime_build_id) ||
      !std::memchr(query.kernel_release, 0, sizeof(query.kernel_release))) {
    error = "incompatible kctrace runtime ABI/capabilities";
    close(descriptor);
    return -1;
  }
  // Holding the device also keeps the runtime module and these notes alive.
  const char *notes = "/sys/module/kctrace/notes/.note.gnu.build-id";
  const int note_descriptor = open(notes, O_RDONLY | O_CLOEXEC);
  if (note_descriptor >= 0) {
    // A GNU module build-ID note is small. Require successful EOF rather than
    // treating a missing/unreadable file's cache sentinel as identity evidence.
    std::array<char, 4096> bytes;
    ssize_t count;
    do {
      count = read(note_descriptor, bytes.data(), bytes.size());
    } while (count < 0 && errno == EINTR);
    char remaining;
    ssize_t tail;
    do {
      tail = read(note_descriptor, &remaining, sizeof(remaining));
    } while (tail < 0 && errno == EINTR);
    if (count > 0 && count < ssize_t(bytes.size()) && tail == 0)
      identity = ct_cache_key({std::string_view(bytes.data(), size_t(count))});
    close(note_descriptor);
  }
  if (identity.empty() && (query.capabilities & KCTRACE_CAP_RUNTIME_BUILD_ID) &&
      query.runtime_build_id_size)
    identity = ct_cache_key({std::string_view(
        reinterpret_cast<const char *>(query.runtime_build_id),
        query.runtime_build_id_size)});
  if (!identity.empty())
    identity = ct_cache_key({identity, std::to_string(query.abi),
                             std::to_string(query.capabilities)});
  return descriptor;
}

static int module_descriptor(const std::vector<unsigned char> &bytes,
                             std::string &error) {
  const int descriptor = int(syscall(SYS_memfd_create, "ctrace-module",
                                     MFD_CLOEXEC | MFD_ALLOW_SEALING));
  if (descriptor < 0) {
    error = "cannot create prepared module descriptor: " +
            std::string(std::strerror(errno));
    return -1;
  }
  size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count =
        write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      error =
          "cannot write prepared module: " + std::string(std::strerror(errno));
      close(descriptor);
      return -1;
    }
    offset += size_t(count);
  }
  if (lseek(descriptor, 0, SEEK_SET) < 0 ||
      fcntl(descriptor, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0) {
    error = "cannot seal prepared module: " + std::string(std::strerror(errno));
    close(descriptor);
    return -1;
  }
  return descriptor;
}

int main(int argc, char **argv) {
  std::string path, cache, rewrite_output, level = "full";
  std::string source_map, perfetto_prefix;
  ct_kernel_sign_options signing;
  bool cache_set = false, inspect = false, decompile = false, perfetto = false;
  bool no_style = false, perfetto_only = false, skip_checksum = false;
  uint32_t controller_tid = uint32_t(syscall(SYS_gettid));
  struct Files {
    int runtime = -1, module = -1, directory = -1;
    ~Files() {
      for (int descriptor : {module, runtime, directory})
        if (descriptor >= 0)
          close(descriptor);
    }
  } files;
  ct_kernel_trace_options trace_options;
  trace_options.within.clear();
  std::vector<std::string> parameters;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--") {
      for (++index; index < argc; ++index)
        parameters.emplace_back(argv[index]);
      break;
    }
    if (argument == "--inspect") {
      inspect = true;
      continue;
    }
    if (argument == "--decompile") {
      decompile = true;
      continue;
    }
    if (argument == "--perfetto") {
      perfetto = true;
      continue;
    }
    if (argument == "--perfetto-only") {
      perfetto_only = true;
      continue;
    }
    if (argument == "--no-style") {
      no_style = true;
      continue;
    }
    if (argument == "--skip-src-checksum") {
      skip_checksum = true;
      continue;
    }
    if (argument == "--within-init") {
      trace_options.within_init = true;
      continue;
    }
    if (argument == "--within-intr") {
      trace_options.within_intr = true;
      continue;
    }
    const size_t equals = argument.find('=');
    const std::string_view option = argument.substr(0, equals);
    std::string value;
    if (equals != std::string_view::npos)
      value = argument.substr(equals + 1);
    else if (index + 1 < argc)
      value = argv[++index];
    else {
      std::fprintf(stderr, "ctrace: missing kernel option value: %s\n",
                   argv[index]);
      return 2;
    }
    if (option == "--module")
      path = value;
    else if (option == "--rewrite-output")
      rewrite_output = value;
    else if (option == "--kernel-sign-key")
      signing.key = value;
    else if (option == "--kernel-sign-cert")
      signing.certificate = value;
    else if (option == "--kernel-sign-hash") {
      if (value.empty() || value.front() == '-' || value.front() == '_' ||
          value.find_first_not_of(
              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
              "WXYZ0123456789_-") != std::string::npos) {
        std::fprintf(stderr, "ctrace: invalid kernel signature hash name\n");
        return 2;
      }
      signing.hash = value;
    } else if (option == "--cache-dir") {
      cache = value;
      cache_set = true;
    } else if (option == "--init-instrument")
      level = value;
    else if (option == "--output-fd") {
      char *end = nullptr;
      errno = 0;
      const long descriptor = std::strtol(value.c_str(), &end, 10);
      if (errno || !end || *end || descriptor < 0 || descriptor > INT32_MAX ||
          fcntl(int(descriptor), F_GETFD) < 0 ||
          dup2(int(descriptor), STDERR_FILENO) < 0) {
        std::fprintf(stderr, "ctrace: invalid kernel output descriptor\n");
        return 2;
      }
    } else if (option == "--within")
      trace_options.within.push_back(value);
    else if (option == "--step-into")
      trace_options.into.push_back(value);
    else if (option == "--recurse-step-into")
      trace_options.recurse.push_back(value);
    else if (option == "--step-over")
      trace_options.over.push_back(value);
    else if (option == "--src-map")
      source_map = value;
    else if (option == "--x86-syntax") {
      if (value != "intel" && value != "att") {
        std::fprintf(stderr, "ctrace: unknown x86 syntax: %s\n", value.c_str());
        return 2;
      }
      trace_options.intel = value == "intel";
    } else if (option == "--perfetto-prefix")
      perfetto_prefix = value;
    else if (option == "--controller-tid") {
      const auto parsed = std::from_chars(
          value.data(), value.data() + value.size(), controller_tid);
      if (parsed.ec != std::errc{} ||
          parsed.ptr != value.data() + value.size() || !controller_tid) {
        std::fprintf(stderr, "ctrace: invalid kernel controller TID\n");
        return 2;
      }
    } else if (option != "--install-prefix") {
      std::fprintf(stderr, "ctrace: unknown kernel backend option: %.*s\n",
                   int(option.size()), option.data());
      return 2;
    }
  }
  if (path.empty() || level != "full") {
    std::fprintf(stderr, "ctrace: kernel preparation requires --module and "
                         "full initial instrumentation\n");
    return 2;
  }
  if (perfetto_only && !perfetto) {
    std::fprintf(stderr, "ctrace: --perfetto-only requires --perfetto\n");
    return 2;
  }
  if (signing.key.empty() != signing.certificate.empty() ||
      (!signing.hash.empty() && signing.key.empty())) {
    std::fprintf(stderr,
                 "ctrace: kernel signing requires both key and certificate\n");
    return 2;
  }
  if (perfetto) {
    if (perfetto_prefix.empty()) {
      std::fprintf(stderr, "ctrace: missing kernel Perfetto filename prefix\n");
      return 2;
    }
    // Keep the invoking shell's actual directory even if its pathname is
    // renamed during preparation or a child changes its working directory.
    files.directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (files.directory < 0) {
      std::fprintf(stderr,
                   "ctrace: cannot retain Perfetto working directory: %s\n",
                   std::strerror(errno));
      return 1;
    }
  }
  if (cache_set && setenv("CTRACE_CACHE_DIR", cache.c_str(), 1) != 0) {
    std::fprintf(stderr, "ctrace: cannot configure kernel cache: %s\n",
                 std::strerror(errno));
    return 1;
  }
  ct_kernel_image image;
  std::string error, inventory;
  if (!ct_kernel_read_image(path, image, error)) {
    std::fprintf(stderr, "ctrace: %s: %s\n", path.c_str(), error.c_str());
    return 1;
  }
  if (!rewrite_output.empty()) {
    // Developer verification output: not finalized, signed or load-ready.
    std::vector<unsigned char> bytes;
    std::vector<ct_kernel_site> sites;
    if (!ct_kernel_expand(image, bytes, sites, error)) {
      std::fprintf(stderr, "ctrace: %s: %s\n", path.c_str(), error.c_str());
      return 1;
    }
    const int descriptor = open(rewrite_output.c_str(),
                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
      std::fprintf(stderr,
                   "ctrace: cannot create rewrite verification file: %s\n",
                   std::strerror(errno));
      return 1;
    }
    size_t written = 0;
    while (written < bytes.size()) {
      const ssize_t count =
          write(descriptor, bytes.data() + written, bytes.size() - written);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        break;
      written += size_t(count);
    }
    const bool complete = written == bytes.size();
    const int closed = close(descriptor);
    if (!complete || closed != 0) {
      std::fprintf(stderr,
                   "ctrace: cannot write complete rewrite verification file\n");
      return 1;
    }
    llvm::json::Array mapping;
    for (const auto &site : sites)
      mapping.emplace_back(
          llvm::json::Object{{"section", site.section},
                             {"site_id", site.id},
                             {"offset", site.offset},
                             {"entry", site.entry},
                             {"operation", site.operation},
                             {"original_size", site.original_size},
                             {"emitted_size", site.emitted_size},
                             {"probe", site.probe}});
    const std::string report =
        llvm::formatv("{0}", llvm::json::Value(llvm::json::Object{
                                 {"schema", 1},
                                 {"load_ready", false},
                                 {"original_sha256", image.input_digest.empty()
                                                         ? image.digest
                                                         : image.input_digest},
                                 {"sites", std::move(mapping)}}))
            .str();
    if (std::fwrite(report.data(), 1, report.size(), stdout) != report.size() ||
        std::fputc('\n', stdout) == EOF || std::fflush(stdout) != 0)
      return 1;
    return 0;
  }
  if (inspect) {
    if (!ct_kernel_inventory(image, inventory, error)) {
      std::fprintf(stderr, "ctrace: %s: %s\n", path.c_str(), error.c_str());
      return 1;
    }
    if (std::fwrite(inventory.data(), 1, inventory.size(), stdout) !=
            inventory.size() ||
        std::fputc('\n', stdout) == EOF || std::fflush(stdout) != 0)
      return 1;
    return 0;
  }
  if (image.signature_present &&
      (!image.signature_format_valid || image.signature_hash.empty())) {
    std::fprintf(stderr, "ctrace: original module signature trailer has an "
                         "unsupported or invalid format or hash\n");
    return 2;
  }
  if (!image.signature_present && !signing.key.empty()) {
    std::fprintf(stderr, "ctrace: kernel signing options require an already "
                         "signed input module\n");
    return 2;
  }
  std::vector<std::pair<std::string, std::string>> mappings;
  for (size_t begin = 0; begin < source_map.size();) {
    const size_t end = source_map.find(',', begin);
    const std::string item = source_map.substr(begin, end - begin);
    const size_t equals = item.find('=');
    if (equals == std::string::npos || !equals || equals + 1 == item.size() ||
        item.front() != '/' || item[equals + 1] != '/') {
      std::fprintf(stderr, "ctrace: invalid kernel source-prefix mapping\n");
      return 2;
    }
    mappings.emplace_back(item.substr(0, equals), item.substr(equals + 1));
    if (end == std::string::npos)
      break;
    begin = end + 1;
  }
  std::sort(mappings.begin(), mappings.end(),
            [](const auto &left, const auto &right) {
              return left.first.size() > right.first.size();
            });
  const bool style = !no_style;
  const auto info = [&](const std::string &message) {
    if (perfetto_only)
      return;
    std::fprintf(stderr, "%sInfo: %s: source prefix ?=?: ? ?:? ?: %s%s\n",
                 style ? "\033[34m" : "", image.path.c_str(), message.c_str(),
                 style ? "\033[0m" : "");
  };
  bool output_failed = false;
  const auto warning = [&](const std::string &message) {
    if (output_failed || std::ferror(stderr))
      return;
    std::fprintf(stderr, "%sWarning: %s: %s%s\n", style ? "\033[1;33m" : "",
                 image.path.c_str(), message.c_str(), style ? "\033[0m" : "");
  };
  kctrace_query query{};
  ct_kernel_prepare_options preparation;
  files.runtime = open_runtime(query, preparation.runtime_identity, error);
  if (files.runtime < 0) {
    warning(error);
    return 1;
  }
  if (perfetto && !(query.capabilities & KCTRACE_CAP_PROBE_TIMING)) {
    warning("kernel Perfetto requires runtime probe timing support");
    return 1;
  }
  if (trace_options.within_intr &&
      !(query.capabilities & KCTRACE_CAP_INTERRUPT_SCOPE)) {
    warning(
        "--within-intr requires kctrace interrupt-handler identity support");
    return 1;
  }
  if (trace_options.within_intr &&
      !(query.capabilities & KCTRACE_CAP_TASKLET_SCOPE)) {
    warning("--within-intr requires kctrace tasklet identity support; update "
            "the runtime module");
    return 1;
  }
  utsname running{};
  if (uname(&running) != 0 ||
      std::strcmp(query.kernel_release, running.release)) {
    warning("running kernel does not match the kctrace runtime");
    return 1;
  }
  preparation.kernel_build =
      "/lib/modules/" + std::string(running.release) + "/build";
  signing.kernel_build = preparation.kernel_build;
  preparation.signing = !signing.key.empty();
  std::error_code filesystem_error;
  const auto executable =
      std::filesystem::canonical("/proc/self/exe", filesystem_error);
  if (filesystem_error) {
    warning("cannot locate kernel preparation resources: " +
            filesystem_error.message());
    return 1;
  }
  preparation.resource_root =
      (executable.parent_path() / "ctrace_kernel_data").string();
  preparation.decompile = decompile;
  preparation.analysis_helper =
      (executable.parent_path() / "ctrace_analyze").string();
  preparation.progress = info;
  preparation.source.maps = mappings;
  preparation.source.skip_checksum = skip_checksum;
  preparation.source.progress = info;
  preparation.source.warning = warning;
  trace_options.emit_terminal = !perfetto_only;
  preparation.observation = trace_options;
  preparation.level_selection =
      (query.capabilities & KCTRACE_CAP_LEVEL_SELECTION) != 0;
  preparation.perfetto = perfetto;
  ct_kernel_prepared artifact;
  if (!ct_kernel_prepare(image, preparation, artifact, error)) {
    warning(error);
    return 1;
  }
  if (preparation.signing &&
      !ct_kernel_select_sign_hash(signing, image.signature_hash,
                                  artifact.default_signature_hash, error)) {
    warning(error);
    return 1;
  }
  if (!artifact.trace) {
    warning("kernel observation preparation returned no trace policy");
    return 1;
  }
  auto &trace = *artifact.trace;
  const bool source_paths_mapped = bool(artifact.source);
  info(decompile ? "kernel source, decompile and assembly observations prepared"
                 : "kernel source and assembly observations prepared");
  std::unique_ptr<ct_kernel_perfetto> timeline;
  if (perfetto) {
    timeline = std::make_unique<ct_kernel_perfetto>();
    if (!timeline->open(perfetto_prefix, files.directory, controller_tid,
                        image.name, image.path, error)) {
      warning(error);
      return 1;
    }
  }
  kctrace_prepare session{};
  session.size = sizeof(session);
  session.abi = KCTRACE_ABI_VERSION;
  session.initial_level = KCTRACE_LEVEL_FULL;
  session.events_per_cpu = query.default_events_per_cpu;
  session.site_count = artifact.probe_count;
  if (artifact.module_name.size() >= sizeof(session.module_name) ||
      !decode_hash(artifact.original_digest, session.original_sha256) ||
      !decode_hash(artifact.template_digest, session.artifact_sha256)) {
    warning("invalid prepared module identity");
    return 1;
  }
  std::memcpy(session.module_name, artifact.module_name.c_str(),
              artifact.module_name.size() + 1);
  if (ioctl(files.runtime, KCTRACE_IOC_PREPARE, &session) != 0) {
    warning("cannot prepare kernel observation session: " +
            std::string(std::strerror(errno)));
    return 1;
  }
  std::vector<unsigned char> bound;
  if (!ct_kernel_bind_prepared(artifact, session, bound, error)) {
    warning(error);
    return 1;
  }
  if (preparation.signing) {
    info("Signing the session-bound module with " + signing.hash);
    if (!ct_kernel_sign_module(signing, bound, error)) {
      warning(error);
      return 1;
    }
  }
  files.module = module_descriptor(bound, error);
  if (files.module < 0) {
    warning(error);
    return 1;
  }
  // Analysis and artifact bytes are no longer needed once the immutable
  // descriptor and offline display table exist. Never read them during trace.
  std::vector<unsigned char>().swap(bound);
  std::vector<unsigned char>().swap(artifact.bytes);
  std::vector<ct_kernel_site>().swap(artifact.sites);
  artifact.captures.reset();
  artifact.source.reset();
  artifact.values.reset();
  artifact.decompile.reset();
  std::vector<unsigned char>().swap(image.bytes);
  std::vector<ct_kernel_section>().swap(image.sections);
  std::vector<ct_kernel_symbol>().swap(image.symbols);
  std::vector<ct_kernel_relocation>().swap(image.relocations);
  const std::string label = std::filesystem::path(path).filename().string();
  std::vector<ct_kernel_trace_record> records;
  std::vector<ct_kernel_trace_transition> transitions;
  const auto display = [&] {
    if (output_failed || std::ferror(stderr)) {
      records.clear();
      return false;
    }
    bool written = true;
    for (const auto &record : records) {
      if (record.stage == ct_kernel_trace_stage::discontinuity) {
        warning(record.text);
        continue;
      }
      if (perfetto_only)
        continue;
      std::string file = record.file;
      if (!source_paths_mapped)
        for (const auto &[old_prefix, new_prefix] : mappings)
          if (file.compare(0, old_prefix.size(), old_prefix) == 0 &&
              (file.size() == old_prefix.size() ||
               file[old_prefix.size()] == '/')) {
            file = new_prefix + file.substr(old_prefix.size());
            break;
          }
      const std::string line = record.line ? std::to_string(record.line) : "?";
      const size_t delimiter = record.text.find(" # ");
      const size_t comment = record.source ? record.comment_offset
                             : delimiter == std::string::npos
                                 ? std::string::npos
                                 : delimiter + 1;
      const size_t code_size = std::min(comment, record.text.size());
      std::string text;
      if (style && record.source && (record.entry || record.call_entry)) {
        text = "\033[39;42m" + record.text.substr(0, code_size) + "\033[0m";
      } else if (style && record.source) {
        size_t offset = 0;
        for (const auto &highlight : record.code_highlights) {
          if (highlight.begin < offset || highlight.begin >= highlight.end ||
              highlight.end > code_size)
            continue;
          text += record.text.substr(offset, highlight.begin - offset);
          text += "\033[39;42m";
          text += record.text.substr(highlight.begin,
                                     highlight.end - highlight.begin);
          text += "\033[0m";
          offset = highlight.end;
        }
        text += record.text.substr(offset, code_size - offset);
      } else {
        text = record.text.substr(0, code_size);
      }
      if (style && comment < record.text.size()) {
        text += "\033[34m";
        size_t offset = comment;
        for (const auto &span : record.values) {
          if ((!span.introduction && !span.unknown) || span.offset < offset ||
              span.offset > record.text.size() ||
              span.length > record.text.size() - span.offset)
            continue;
          text += record.text.substr(offset, span.offset - offset);
          text += span.unknown
                      ? (span.introduction ? "\033[1;39;41m" : "\033[22;39;41m")
                      : "\033[1;39;44m";
          text += record.text.substr(span.offset, span.length);
          text += "\033[22;34;49m";
          offset = span.offset + span.length;
        }
        text += record.text.substr(offset);
        text += "\033[0m";
      } else {
        text += record.text.substr(code_size);
      }
      if (std::fprintf(stderr, "%s[tid %u] L%llx %s %s:%s %s | %s\n",
                       label.c_str(), record.tid,
                       static_cast<unsigned long long>(record.pc),
                       image.path.c_str(), file.empty() ? "?" : file.c_str(),
                       line.c_str(),
                       record.function.empty() ? "?" : record.function.c_str(),
                       text.c_str()) < 0)
        written = false;
    }
    records.clear();
    return written && !std::ferror(stderr);
  };
  bool rendering_failed = false;
  uint64_t last_timestamp = 0;
  const auto result = ct_kernel_load(
      files.runtime, session, files.module, image.path, parameters,
      [&](const kctrace_event &event) {
        last_timestamp = std::max<uint64_t>(last_timestamp, event.monotonic_ns);
        transitions.clear();
        const bool accepted =
            timeline ? trace.consume(event, records, transitions, error)
                     : trace.consume(event, records, error);
        if (!accepted ||
            (timeline && !timeline->observe(event, transitions, error))) {
          warning(error);
          rendering_failed = true;
          return false;
        }
        const bool written = display();
        rendering_failed |= !written;
        return written;
      },
      warning);
  output_failed = result.output_failed;
  const char *finish_status =
      result.reason == ct_kernel_finish::unloaded        ? "unloaded"
      : result.reason == ct_kernel_finish::external_exit ? "external-observed"
      : result.reason == ct_kernel_finish::init_failed   ? "init-failed"
      : result.reason == ct_kernel_finish::load_failed   ? "load-failed"
                                                         : "error";
  transitions.clear();
  if (timeline)
    trace.finish(records, transitions, last_timestamp, finish_status);
  else
    trace.finish(records);
  bool written = display();
  if (timeline && !timeline->finish(transitions, finish_status, error)) {
    warning(error);
    written = false;
  }
  if (result.reason == ct_kernel_finish::load_failed) {
    if (result.exec_error)
      warning("cannot execute insmod: " +
              std::string(std::strerror(result.exec_error)));
    if (WIFEXITED(result.load_status) && WEXITSTATUS(result.load_status))
      return WEXITSTATUS(result.load_status);
    if (WIFSIGNALED(result.load_status))
      return 128 + WTERMSIG(result.load_status);
    return 1;
  }
  if (result.reason == ct_kernel_finish::error ||
      result.reason == ct_kernel_finish::init_failed) {
    warning("kernel trace failed: " + std::string(std::strerror(result.error)));
    return 1;
  }
  return written && !rendering_failed ? 0 : 1;
}
