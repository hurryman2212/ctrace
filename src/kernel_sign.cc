#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <string_view>
#include <thread>

#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kernel_sign.h"

static constexpr size_t signing_module_limit = 128 * 1024 * 1024;
static constexpr size_t signing_signature_limit = 1024 * 1024;
static constexpr rlim_t signing_memory_limit = 1024 * 1024 * 1024;
static constexpr unsigned signing_seconds = 30;
static constexpr std::array<std::string_view, 6> signing_hashes{
    "sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"};

bool ct_kernel_signature_size(const std::vector<unsigned char> &suffix,
                              size_t &appended_size, std::string &error) {
  appended_size = 0;
  error.clear();
  constexpr std::string_view marker = "~Module signature appended~\n";
  if (suffix.size() <= marker.size() + 12) {
    error = "module signature trailer is absent or truncated";
    return false;
  }
  const size_t trailer = suffix.size() - marker.size() - 12;
  const auto *header = suffix.data() + trailer;
  uint32_t signature_size = 0;
  for (unsigned index = 8; index < 12; ++index)
    signature_size = (signature_size << 8) | header[index];
  if (std::memcmp(header + 12, marker.data(), marker.size()) ||
      !signature_size || signature_size > trailer ||
      signature_size > signing_signature_limit - marker.size() - 12 ||
      header[0] || header[1] || header[2] != 2 || header[3] || header[4] ||
      header[5] || header[6] || header[7]) {
    error = "kernel signer returned an invalid PKCS#7 signature trailer";
    return false;
  }
  // Validate a single DER ContentInfo(SignedData) envelope. Cryptographic
  // validity and certificate trust remain the kernel loader's responsibility.
  const size_t start = trailer - signature_size;
  size_t cursor = start;
  const auto extent = [&](unsigned char tag, size_t end, size_t &body_end) {
    if (cursor >= end || suffix[cursor++] != tag || cursor >= end)
      return false;
    uint64_t length = suffix[cursor++];
    if (length & 0x80) {
      const auto count = length & 0x7f;
      if (!count || count > 4 || count > end - cursor || !suffix[cursor])
        return false;
      length = 0;
      for (uint64_t index = 0; index < count; ++index)
        length = (length << 8) | suffix[cursor++];
      if (length < 128)
        return false;
    }
    if (length > end - cursor)
      return false;
    body_end = cursor + length;
    return true;
  };
  constexpr std::array<unsigned char, 11> signed_data_oid{
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02};
  size_t end = 0;
  if (!extent(0x30, trailer, end) || end != trailer ||
      signed_data_oid.size() > end - cursor ||
      std::memcmp(suffix.data() + cursor, signed_data_oid.data(),
                  signed_data_oid.size())) {
    error = "kernel signer returned an invalid PKCS#7 SignedData envelope";
    return false;
  }
  cursor += signed_data_oid.size();
  if (!extent(0xa0, trailer, end) || end != trailer ||
      !extent(0x30, end, end) || end != trailer || cursor == end) {
    error = "module signature has an invalid SignedData body";
    return false;
  }
  appended_size = suffix.size() - start;
  return true;
}

bool ct_kernel_signature_hash(const std::vector<unsigned char> &bytes,
                              std::string &hash, std::string &error) {
  hash.clear();
  size_t appended = 0;
  if (!ct_kernel_signature_size(bytes, appended, error))
    return false;
  constexpr std::string_view marker = "~Module signature appended~\n";
  const size_t length = appended - marker.size() - 12;
  const auto *begin = bytes.data() + bytes.size() - appended;
  const auto *cursor = begin;
  std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> content(
      d2i_CMS_ContentInfo(nullptr, &cursor, long(length)),
      CMS_ContentInfo_free);
  if (!content || cursor != begin + length ||
      OBJ_obj2nid(CMS_get0_type(content.get())) != NID_pkcs7_signed ||
      CMS_is_detached(content.get()) != 1 ||
      OBJ_obj2nid(CMS_get0_eContentType(content.get())) != NID_pkcs7_data) {
    error =
        "module signature must be detached CMS SignedData with data content";
    return false;
  }
  const auto *signers = CMS_get0_SignerInfos(content.get());
  if (!signers || sk_CMS_SignerInfo_num(signers) != 1) {
    error = "module signature must contain exactly one CMS signer";
    return false;
  }
  auto *signer = sk_CMS_SignerInfo_value(signers, 0);
  const auto *signature = CMS_SignerInfo_get0_signature(signer);
  X509_ALGOR *digest = nullptr;
  CMS_SignerInfo_get0_algs(signer, nullptr, nullptr, &digest, nullptr);
  if (!signature || ASN1_STRING_length(signature) <= 0 || !digest) {
    error = "module signature has an incomplete CMS signer";
    return false;
  }
  const ASN1_OBJECT *algorithm = nullptr;
  int parameter = V_ASN1_UNDEF;
  X509_ALGOR_get0(&algorithm, &parameter, nullptr, digest);
  if (!algorithm || (parameter != V_ASN1_UNDEF && parameter != V_ASN1_NULL)) {
    error = "module signature has malformed digest parameters";
    return false;
  }
  // CMS exposes the signer digest, but not SignedData.digestAlgorithms.
  // Read only that bounded prefix with libcrypto's ASN.1 primitives; require
  // one matching algorithm instead of choosing from inconsistent metadata.
  cursor = begin;
  const auto *end = begin + length;
  const auto extent = [&](int expected, const unsigned char *limit,
                          const unsigned char *&body_end) {
    if (cursor >= limit)
      return false;
    long size = 0;
    int tag = 0, tag_class = 0;
    const int flags =
        ASN1_get_object(&cursor, &size, &tag, &tag_class, long(limit - cursor));
    if ((flags & 0x81) || cursor > limit || size < 0 ||
        size_t(size) > size_t(limit - cursor) ||
        (tag | tag_class | (flags & V_ASN1_CONSTRUCTED)) != expected)
      return false;
    body_end = cursor + size;
    return true;
  };
  const unsigned char *outer = nullptr, *part = nullptr,
                      *algorithms_end = nullptr;
  if (!extent(0x30, end, outer) || outer != end || !extent(0x06, outer, part)) {
    error = "module signature has an invalid CMS digest prefix";
    return false;
  }
  cursor = part;
  if (!extent(0xa0, outer, part) || part != end || !extent(0x30, part, outer) ||
      outer != end || !extent(0x02, outer, part)) {
    error = "module signature has an invalid CMS SignedData version";
    return false;
  }
  cursor = part;
  if (!extent(0x31, outer, algorithms_end)) {
    error = "module signature has an invalid CMS digest algorithm set";
    return false;
  }
  std::unique_ptr<X509_ALGOR, decltype(&X509_ALGOR_free)> declared(
      d2i_X509_ALGOR(nullptr, &cursor, long(algorithms_end - cursor)),
      X509_ALGOR_free);
  const ASN1_OBJECT *declared_algorithm = nullptr;
  int declared_parameter = V_ASN1_UNDEF;
  if (declared)
    X509_ALGOR_get0(&declared_algorithm, &declared_parameter, nullptr,
                    declared.get());
  if (!declared || cursor != algorithms_end || !declared_algorithm ||
      OBJ_cmp(declared_algorithm, algorithm) ||
      (declared_parameter != V_ASN1_UNDEF &&
       declared_parameter != V_ASN1_NULL)) {
    error = "module signature must declare exactly its single signer's digest";
    return false;
  }
  switch (OBJ_obj2nid(algorithm)) {
  case NID_sha256:
    hash = "sha256";
    break;
  case NID_sha384:
    hash = "sha384";
    break;
  case NID_sha512:
    hash = "sha512";
    break;
  case NID_sha3_256:
    hash = "sha3-256";
    break;
  case NID_sha3_384:
    hash = "sha3-384";
    break;
  case NID_sha3_512:
    hash = "sha3-512";
    break;
  default: {
    const auto *digest = EVP_get_digestbynid(OBJ_obj2nid(algorithm));
    if (digest) {
      hash = EVP_MD_name(digest);
      for (char &byte : hash)
        if (byte >= 'A' && byte <= 'Z')
          byte += 'a' - 'A';
    } else {
      const int size = OBJ_obj2txt(nullptr, 0, algorithm, 1);
      if (size <= 0 || size_t(size) > signing_signature_limit) {
        error = "module signature has an invalid digest identifier";
        return false;
      }
      std::vector<char> name(size_t(size) + 1);
      if (OBJ_obj2txt(name.data(), int(name.size()), algorithm, 1) != size) {
        error = "module signature digest identifier changed while reading";
        return false;
      }
      hash.assign(name.data(), size);
    }
    break;
  }
  }
  return true;
}

static bool signing_paths(const ct_kernel_sign_options &options,
                          std::array<std::string, 3> &paths,
                          std::string &error) {
  if (options.kernel_build.empty() || options.key.empty() ||
      options.certificate.empty()) {
    error = "kernel signing requires a key, certificate and kernel build";
    return false;
  }
  std::error_code issue;
  const std::array<std::string, 3> inputs{options.kernel_build +
                                              "/scripts/sign-file",
                                          options.key, options.certificate};
  for (size_t index = 0; index < paths.size(); ++index) {
    if (inputs[index].find('\0') != std::string::npos) {
      error = "kernel signing paths contain an invalid byte";
      return false;
    }
    paths[index] = std::filesystem::canonical(inputs[index], issue).string();
    struct stat status{};
    if (issue || stat(paths[index].c_str(), &status) ||
        !S_ISREG(status.st_mode) ||
        access(paths[index].c_str(), index ? R_OK : X_OK)) {
      error = index ? "kernel signing key or certificate is unavailable"
                    : "selected kernel scripts/sign-file is unavailable";
      return false;
    }
  }
  return true;
}

static X509 *signing_certificate(const std::string &path) {
  std::unique_ptr<BIO, decltype(&BIO_free)> input(
      BIO_new_file(path.c_str(), "rb"), BIO_free);
  if (!input)
    return nullptr;
  auto *certificate = PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr);
  if (!certificate && BIO_seek(input.get(), 0) >= 0)
    certificate = d2i_X509_bio(input.get(), nullptr);
  return certificate;
}

// Check newly generated signatures mathematically with the supplied public
// certificate. Certificate trust and original-input signatures are not checked.
static bool signing_verify(const unsigned char *der, size_t der_size,
                           const unsigned char *data, size_t data_size,
                           X509 *certificate) {
  if (!certificate || !der_size || der_size > signing_signature_limit ||
      !data_size || data_size > signing_module_limit)
    return false;
  const auto *cursor = der;
  std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> content(
      d2i_CMS_ContentInfo(nullptr, &cursor, long(der_size)),
      CMS_ContentInfo_free);
  const auto release = [](STACK_OF(X509) * certificates) {
    sk_X509_free(certificates);
  };
  std::unique_ptr<STACK_OF(X509), decltype(release)> certificates(
      sk_X509_new_null(), release);
  std::unique_ptr<BIO, decltype(&BIO_free)> input(
      BIO_new_mem_buf(data, int(data_size)), BIO_free);
  std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_null()),
                                                   BIO_free);
  return content && cursor == der + der_size && certificates && input &&
         output && sk_X509_push(certificates.get(), certificate) == 1 &&
         CMS_verify(content.get(), certificates.get(), nullptr, input.get(),
                    output.get(),
                    CMS_BINARY | CMS_NOINTERN | CMS_NO_SIGNER_CERT_VERIFY) == 1;
}

// Only ordinary exit status reaches the caller. Timeouts, signals and process
// setup failures are fatal; neither probe nor final signing records stderr.
static int signing_child(const std::function<int()> &run, std::string &pin,
                         std::string &error) {
  struct Descriptor {
    int value = open("/dev/null", O_RDWR | O_CLOEXEC);
    ~Descriptor() {
      if (value >= 0)
        close(value);
    }
  } null;
  struct sigaction action{};
  if (null.value < 0 || sigaction(SIGCHLD, nullptr, &action) ||
      action.sa_handler == SIG_IGN || (action.sa_flags & SA_NOCLDWAIT)) {
    explicit_bzero(pin.data(), pin.size());
    error =
        "kernel signing requires a waitable process and private diagnostics";
    return -1;
  }
  const auto parent = getpid();
  const auto child = fork();
  if (!child) {
    struct rlimit memory{signing_memory_limit, signing_memory_limit};
    struct rlimit cpu{signing_seconds, signing_seconds};
    struct rlimit file{signing_module_limit, signing_module_limit};
    struct rlimit core{0, 0};
    if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) ||
        getppid() != parent || setrlimit(RLIMIT_AS, &memory) ||
        setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_FSIZE, &file) ||
        setrlimit(RLIMIT_CORE, &core) || dup2(null.value, STDIN_FILENO) < 0 ||
        dup2(null.value, STDOUT_FILENO) < 0 ||
        dup2(null.value, STDERR_FILENO) < 0 ||
        fcntl(STDIN_FILENO, F_SETFD, 0) || fcntl(STDOUT_FILENO, F_SETFD, 0) ||
        fcntl(STDERR_FILENO, F_SETFD, 0))
      _exit(126);
    _exit(run());
  }
  explicit_bzero(pin.data(), pin.size());
  if (child < 0) {
    error = "cannot start kernel signing process";
    return -1;
  }
  (void)setpgid(child, child);
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(signing_seconds);
  siginfo_t status{};
  bool finished = false, waitable = true;
  while (std::chrono::steady_clock::now() < deadline) {
    if (!waitid(P_PID, child, &status, WEXITED | WNOHANG | WNOWAIT)) {
      if (status.si_pid == child) {
        finished = true;
        break;
      }
    } else if (errno != EINTR) {
      waitable = errno != ECHILD;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  // Keep the group leader unreaped until its possible descendants are gone.
  if (waitable) {
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
    }
  }
  if (!finished || status.si_code != CLD_EXITED) {
    error = !finished ? "kernel signing process timed out"
                      : "kernel signing process terminated unexpectedly";
    return -1;
  }
  return status.si_status;
}

static bool signing_module_once(const ct_kernel_sign_options &options,
                                std::vector<unsigned char> &bytes,
                                std::string &error, bool &candidate_failure) {
  error.clear();
  candidate_failure = false;
  constexpr std::string_view marker = "~Module signature appended~\n";
  if (options.kernel_build.empty() || options.key.empty() ||
      options.certificate.empty() || options.hash.empty() || bytes.empty() ||
      bytes.size() > signing_module_limit ||
      std::find(signing_hashes.begin(), signing_hashes.end(), options.hash) ==
          signing_hashes.end() ||
      (bytes.size() >= marker.size() &&
       !std::memcmp(bytes.data() + bytes.size() - marker.size(), marker.data(),
                    marker.size()))) {
    error =
        "kernel signing requires a key, certificate, hash and unsigned module";
    return false;
  }
  std::array<std::string, 3> paths;
  if (!signing_paths(options, paths, error))
    return false;
  struct Resources {
    std::string directory;
    int signer = -1, input = -1, output = -1;
    ~Resources() {
      for (const int descriptor : {signer, input, output})
        if (descriptor >= 0)
          close(descriptor);
      if (!directory.empty()) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
      }
    }
  } resources;
  resources.signer = open(paths[0].c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  Elf64_Ehdr executable{};
  if (resources.signer < 0 ||
      pread(resources.signer, &executable, sizeof(executable), 0) !=
          sizeof(executable) ||
      std::memcmp(executable.e_ident, ELFMAG, SELFMAG) ||
      executable.e_ident[EI_CLASS] != ELFCLASS64 ||
      executable.e_ident[EI_DATA] != ELFDATA2LSB ||
      executable.e_machine != EM_X86_64 ||
      (executable.e_type != ET_EXEC && executable.e_type != ET_DYN)) {
    error = "selected kernel sign-file must be a direct x86-64 ELF executable";
    return false;
  }
  if (resources.signer < STDERR_FILENO + 1) {
    const int saved =
        fcntl(resources.signer, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    if (saved < 0) {
      error = "cannot retain selected kernel signer descriptor";
      return false;
    }
    close(resources.signer);
    resources.signer = saved;
  }
  std::string directory = "/tmp/ctrace-sign-XXXXXX";
  if (!mkdtemp(directory.data())) {
    error = "cannot create private kernel signing directory";
    return false;
  }
  resources.directory = std::move(directory);
  const auto input = resources.directory + "/bound.ko";
  const auto output = resources.directory + "/signed.ko";
  resources.input =
      open(input.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  resources.output =
      open(output.c_str(), O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (resources.input < 0 || resources.output < 0) {
    error = "cannot create bounded kernel signing files";
    return false;
  }
  size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count =
        write(resources.input, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      error = "cannot write kernel signing input";
      return false;
    }
    offset += size_t(count);
  }
  std::array<std::string, 6> arguments{paths[0], options.hash, paths[1],
                                       paths[2], input,        output};
  std::array<char *, 7> argv{};
  for (size_t index = 0; index < arguments.size(); ++index)
    argv[index] = arguments[index].data();
  // Forward the established sign-file PIN channel only. Do not capture the
  // signer's diagnostics: even a failed crypto provider may echo secrets.
  std::string pin;
  if (const char *value = std::getenv("KBUILD_SIGN_PIN"))
    pin = std::string("KBUILD_SIGN_PIN=") + value;
  char path[] = "PATH=/usr/bin:/bin", locale[] = "LC_ALL=C";
  char home[] = "HOME=/nonexistent";
  std::array<char *, 5> environment{
      path, locale, home, pin.empty() ? nullptr : pin.data(), nullptr};
  const int status = signing_child(
      [&] {
        fexecve(resources.signer, argv.data(), environment.data());
        return 127;
      },
      pin, error);
  if (status < 0)
    return false;
  if (status) {
    candidate_failure = status == 1;
    error = "kernel module sign-file failed (status " + std::to_string(status) +
            ")";
    return false;
  }
  struct stat before{}, after{};
  if (fstat(resources.output, &before) || !S_ISREG(before.st_mode) ||
      before.st_size <= 0 || uint64_t(before.st_size) > signing_module_limit ||
      uint64_t(before.st_size) <= bytes.size() + marker.size() + 12 ||
      uint64_t(before.st_size) - bytes.size() > signing_signature_limit) {
    error = "kernel signer returned an invalid module size";
    return false;
  }
  std::array<unsigned char, 64 * 1024> buffer;
  for (offset = 0; offset < bytes.size();) {
    const auto size = std::min(buffer.size(), bytes.size() - offset);
    const auto count = pread(resources.output, buffer.data(), size, offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0 ||
        std::memcmp(buffer.data(), bytes.data() + offset, count)) {
      error = "kernel signer changed the session-bound module";
      return false;
    }
    offset += size_t(count);
  }
  std::vector<unsigned char> suffix(before.st_size - bytes.size());
  for (offset = 0; offset < suffix.size();) {
    const auto count = pread(resources.output, suffix.data() + offset,
                             suffix.size() - offset, bytes.size() + offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      error = "cannot read complete kernel signature";
      return false;
    }
    offset += size_t(count);
  }
  size_t appended = 0;
  if (!ct_kernel_signature_size(suffix, appended, error) ||
      appended != suffix.size()) {
    if (error.empty())
      error = "kernel signer inserted bytes before the signature";
    return false;
  }
  std::string signed_hash;
  if (!ct_kernel_signature_hash(suffix, signed_hash, error))
    return false;
  if (signed_hash != options.hash) {
    error = "kernel signer changed the requested signature digest algorithm";
    return false;
  }
  if (fstat(resources.output, &after) || before.st_size != after.st_size ||
      before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
      before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
      before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
    error = "kernel signer output changed while reading";
    return false;
  }
  std::string no_pin;
  const int verified = signing_child(
      [&] {
        std::unique_ptr<X509, decltype(&X509_free)> certificate(
            signing_certificate(paths[2]), X509_free);
        if (!certificate)
          return 64;
        return signing_verify(suffix.data(), suffix.size() - marker.size() - 12,
                              bytes.data(), bytes.size(), certificate.get())
                   ? 0
                   : 65;
      },
      no_pin, error);
  if (verified < 0)
    return false;
  if (verified) {
    error = verified == 64
                ? "cannot read signing certificate for verification"
                : "kernel signer returned an invalid cryptographic signature";
    return false;
  }
  bytes.insert(bytes.end(), suffix.begin(), suffix.end());
  return true;
}

bool ct_kernel_select_sign_hash(ct_kernel_sign_options &options,
                                std::string_view original_hash,
                                std::string_view kernel_hash,
                                std::string &error) {
  error.clear();
  std::vector<unsigned> candidates;
  const auto add = [&](std::string_view hash) {
    const auto found =
        std::find(signing_hashes.begin(), signing_hashes.end(), hash);
    if (found == signing_hashes.end())
      return;
    const auto index = unsigned(found - signing_hashes.begin());
    if (std::find(candidates.begin(), candidates.end(), index) ==
        candidates.end())
      candidates.push_back(index);
  };
  if (!options.hash.empty()) {
    add(options.hash);
    if (candidates.empty()) {
      error = "unsupported explicit kernel signing hash";
      return false;
    }
  } else {
    add(original_hash);
    add(kernel_hash);
    for (auto hash : signing_hashes)
      add(hash);
  }
  std::array<std::string, 3> paths;
  if (!signing_paths(options, paths, error))
    return false;
  std::string pin;
  if (const char *value = std::getenv("KBUILD_SIGN_PIN"))
    pin = value;
  const int preflight = signing_child(
      [&] {
        // Password callbacks never prompt. The key and decrypted material live
        // only in this bounded child and are released before it exits.
        const auto password = [](char *buffer, int size, int, void *context) {
          const auto &secret = *static_cast<const std::string *>(context);
          if (size <= 0 || secret.size() >= size_t(size))
            return 0;
          std::memcpy(buffer, secret.data(), secret.size());
          return int(secret.size());
        };
        std::unique_ptr<BIO, decltype(&BIO_free)> key_file(
            BIO_new_file(paths[1].c_str(), "rb"), BIO_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
            key_file ? PEM_read_bio_PrivateKey(key_file.get(), nullptr,
                                               password, &pin)
                     : nullptr,
            EVP_PKEY_free);
        if (!key)
          return 64;
        std::unique_ptr<X509, decltype(&X509_free)> certificate(
            signing_certificate(paths[2]), X509_free);
        if (!certificate)
          return 65;
        if (X509_check_private_key(certificate.get(), key.get()) != 1)
          return 66;
        int mask = 0;
        for (unsigned index : candidates) {
          const auto *digest =
              EVP_get_digestbyname(signing_hashes[index].data());
          if (!digest)
            continue;
          constexpr unsigned flags =
              CMS_BINARY | CMS_DETACHED | CMS_NOATTR | CMS_NOCERTS;
          std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)>
              content(CMS_sign(nullptr, nullptr, nullptr, nullptr,
                               flags | CMS_PARTIAL),
                      CMS_ContentInfo_free);
          constexpr char sample[] = "ctrace signing compatibility";
          std::unique_ptr<BIO, decltype(&BIO_free)> input(
              BIO_new_mem_buf(sample, sizeof(sample) - 1), BIO_free);
          if (!content || !input)
            return 67;
          if (!CMS_add1_signer(content.get(), certificate.get(), key.get(),
                               digest, flags) ||
              CMS_final(content.get(), input.get(), nullptr, flags) != 1)
            continue;
          const int size = i2d_CMS_ContentInfo(content.get(), nullptr);
          if (size <= 0 || size_t(size) > signing_signature_limit)
            continue;
          std::vector<unsigned char> encoded(size);
          auto *cursor = encoded.data();
          if (i2d_CMS_ContentInfo(content.get(), &cursor) == size &&
              signing_verify(encoded.data(), encoded.size(),
                             reinterpret_cast<const unsigned char *>(sample),
                             sizeof(sample) - 1, certificate.get()))
            mask |= 1 << index;
        }
        return 128 + mask;
      },
      pin, error);
  if (preflight < 0)
    return false;
  if (preflight < 128 || preflight > 191) {
    error = preflight == 64   ? "cannot read signing private key or unlock it "
                                "with KBUILD_SIGN_PIN"
            : preflight == 65 ? "cannot read signing certificate"
            : preflight == 66 ? "signing key does not match its certificate"
                              : "kernel signing credential preflight failed";
    return false;
  }
  const int compatible = preflight - 128;
  for (unsigned index : candidates) {
    if (!(compatible & (1 << index)))
      continue;
    auto candidate = options;
    candidate.hash = signing_hashes[index];
    std::vector<unsigned char> sample{'c', 't', 'r', 'a', 'c', 'e'};
    bool rejected = false;
    if (signing_module_once(candidate, sample, error, rejected)) {
      options.hash = std::move(candidate.hash);
      return true;
    }
    // Credentials and complete crypto finalization were already checked.
    // Only an ordinary sign-file exit 1 is a candidate rejection; all process,
    // input/output, prefix and digest validation failures are fatal.
    if (!rejected)
      return false;
  }
  error = options.hash.empty()
              ? "no compatible kernel signing hash is available"
              : "explicit kernel signing hash is incompatible";
  return false;
}

bool ct_kernel_sign_module(const ct_kernel_sign_options &options,
                           std::vector<unsigned char> &bytes,
                           std::string &error) {
  bool candidate_failure = false;
  return signing_module_once(options, bytes, error, candidate_failure);
}
