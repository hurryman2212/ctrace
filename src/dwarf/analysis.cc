// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <llvm/ADT/SmallString.h>
#include <llvm/DebugInfo/DWARF/DWARFCompileUnit.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugFrame.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugLine.h>
#include <llvm/DebugInfo/DWARF/DWARFDie.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/SymbolSize.h>
#include <llvm/Support/CRC.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MD5.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/TargetSelect.h>

// Declare LLVM ELF enums before elfutils introduces the system ELF macros.
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>

#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "analysis.hh"
#include "analysis_cache.hh"
#include "analysis_files.hh"
#include "analysis_protocol.hh"
#include "c_cpp_source.hh"
#include "cache.hh"
#include "ctrace_analyze/decompile.hh"
#include "flow.hh"

struct SourceText {
  std::unique_ptr<llvm::MemoryBuffer> bytes;
  std::vector<llvm::StringRef> lines;
};

// All accesses hold analysis_mutex. Weak entries do not retain unloaded source
// text; compilation units that refer to the same bytes share one line table.
static std::map<std::string, std::weak_ptr<const SourceText>> source_texts;

static std::shared_ptr<const SourceText>
share_source_text(const std::string &path,
                  std::unique_ptr<llvm::MemoryBuffer> bytes) {
  const auto identity =
      ct_cache_key({path, std::string_view(bytes->getBufferStart(),
                                           bytes->getBufferSize())});
  auto &entry = source_texts[identity];
  if (auto existing = entry.lock())
    return existing;
  auto content = std::make_shared<SourceText>();
  content->bytes = std::move(bytes);
  llvm::StringRef remainder = content->bytes->getBuffer();
  while (!remainder.empty()) {
    auto line = remainder.split('\n');
    content->lines.push_back(line.first.rtrim("\r"));
    remainder = line.second;
  }
  entry = content;
  return content;
}

struct SourceDisplay {
  int syntax = -2;
  std::map<unsigned, ct_source_asm_line> lines;
  std::string identity;
  std::map<std::tuple<uint64_t, uint64_t, uint64_t, uint64_t>,
           std::pair<uint64_t, uint64_t>>
      block_ranges;
};

struct SourceFile {
  uint64_t id = 0;
  std::string path;
  std::string display_path;
  std::string prefix;
  std::shared_ptr<const SourceText> content;
  bool verified = false;
  std::unique_ptr<SourceDisplay> display;
  std::string error;
  bool error_bypassed = false;

  std::string progress_prefix(
      const std::vector<std::pair<std::string, std::string>> &mappings) const {
    if (prefix.rfind("directory:", 0) == 0) {
      const std::string directory = prefix.substr(10);
      return directory + "=" + directory;
    }
    if (prefix.rfind("map:", 0) == 0)
      for (const auto &[original, mapped] : mappings)
        if (original == prefix.substr(4))
          return original + "=" + mapped;
    return {};
  }

  SourceDisplay &
  display_for(const char *module, int syntax,
              const std::vector<std::pair<std::string, std::string>> &mappings,
              const ct_source_compile_context &compile_context) {
    if (!display)
      display = std::make_unique<SourceDisplay>();
    if (display->syntax != syntax) {
      display->lines = ct_analyze_source(
          content->bytes->getBuffer(), path.c_str(), syntax, module,
          &display->identity, progress_prefix(mappings).c_str(),
          &compile_context);
      display->syntax = syntax;
    }
    return *display;
  }

  void archive(ct_analysis_archive &archive) {
    bool readable = bool(content);
    std::string content_identity;
    if (!archive.reading)
      content_identity =
          readable
              ? ct_cache_key(
                    {path, std::string_view(content->bytes->getBufferStart(),
                                            content->bytes->getBufferSize())})
              : ct_analysis_file_key(path);
    archive.fields(id, path, display_path, prefix, verified, error,
                   error_bypassed, readable, content_identity);
    if (!archive.valid)
      return;
    if (!readable && content_identity != ct_analysis_file_key(path)) {
      archive.valid = false;
      return;
    }
    if (readable) {
      auto current = ct_analysis_read_file(path);
      if (!current ||
          content_identity !=
              ct_cache_key(
                  {path, std::string_view((*current)->getBufferStart(),
                                          (*current)->getBufferSize())})) {
        archive.valid = false;
        return;
      }
      if (archive.reading)
        content = share_source_text(path, std::move(*current));
    }
  }
};

struct SourceTable {
  llvm::DWARFDebugLine::LineTable table;
  std::map<uint64_t, SourceFile> files;
  ct_source_compile_context compile_context;
  void archive(ct_analysis_archive &archive) {
    archive.fields(table.Rows, table.Sequences, files, compile_context.producer,
                   compile_context.directory, compile_context.source,
                   compile_context.language);
    if (archive.reading && archive.valid)
      for (const auto &sequence : table.Sequences)
        if (sequence.FirstRowIndex > sequence.LastRowIndex ||
            sequence.LastRowIndex > table.Rows.size())
          archive.valid = false;
  }
};

struct FunctionSymbol {
  uint64_t address;
  uint64_t size;
  std::string name;
  std::string symbol;
  void archive(ct_analysis_archive &archive) {
    archive.fields(address, size, name, symbol);
  }
};

struct ct_analysis {
  llvm::object::OwningBinary<llvm::object::Binary> binary;
  llvm::object::OwningBinary<llvm::object::Binary> debug_binary;
  std::unique_ptr<llvm::DWARFContext> dwarf;
  std::vector<SourceTable> tables;
  std::vector<std::pair<std::string, std::string>> source_mappings;
  std::vector<FunctionSymbol> symbols;
  std::vector<std::pair<uint64_t, uint64_t>> plt_ranges;
  std::map<uint64_t, std::string> plt_symbols;
  uint64_t link_base = 0;
  std::string path;
  int module_file = -1, debug_descriptor = -1, supplement_descriptor = -1;
  std::unique_ptr<llvm::MemoryBuffer> supplement_bytes;
  int64_t debug_bias_correction = 0;
  ct_decompile_module *decompiler = nullptr;
  bool has_dwarf = false;
  std::string debug_file;
  std::string supplement_file;
  std::string soname;
  std::string identity;
  std::string cache_key;
  std::string source_error;
  bool functions_loaded = false;
  std::map<uint64_t, std::string> functions;
  bool inline_scopes_loaded = false;
  bool inline_scopes_complete = true;
  std::vector<std::pair<std::pair<uint64_t, uint64_t>, std::string>>
      inline_scopes;
  bool flow_frames_loaded = false;
  std::vector<std::pair<uint64_t, uint64_t>> flow_frames;
  struct Flow {
    ct_flow_range range{};
    ct_flow_analysis flow_analysis;
  };
  std::map<std::pair<uint64_t, uint64_t>, Flow> flows;
  struct CodeGraph {
    std::vector<ct_flow_instruction> instructions;
    std::vector<ct_flow_edge> edges;
    bool complete = false;
  };
  std::map<std::tuple<uint64_t, uint64_t, uint64_t>, CodeGraph> code_graphs;
  std::map<std::pair<uint64_t, uint64_t>, std::vector<unsigned char>>
      code_proofs;
  ~ct_analysis() {
    if (supplement_descriptor >= 0)
      close(supplement_descriptor);
    if (debug_descriptor >= 0)
      close(debug_descriptor);
    if (module_file >= 0)
      close(module_file);
  }
};

// Bound the bytes presented to the decoder for unusually large functions.

/* A later dlopen may revoke a prefix used by already cached instruction sites.
 */
static std::mutex analysis_mutex;
static std::map<std::string, std::string> rejected_prefixes;
static std::map<std::string, std::string> bypassed_prefixes;
static int source_syntax = -1;
static bool bypass_source_checksum = false;
void ct_analysis_set_syntax(int syntax) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  source_syntax = syntax;
}

void ct_analysis_set_source_bypass(bool enabled) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  bypass_source_checksum = enabled;
}

static std::string normalized_path(llvm::StringRef path) {
  llvm::SmallString<256> result(path);
  llvm::sys::path::remove_dots(result, true);
  return result.str().str();
}

static void progress_source(const ct_analysis &analysis, uint64_t address,
                            ct_analysis_progress &progress) {
  for (const auto &table : analysis.tables) {
    const auto index = table.table.lookupAddress(
        {address, llvm::object::SectionedAddress::UndefSection});
    if (index >= table.table.Rows.size())
      continue;
    const auto &row = table.table.Rows[index];
    const auto source = table.files.find(row.File);
    if (row.EndSequence || !row.Line || source == table.files.end())
      continue;
    std::snprintf(progress.file, sizeof(progress.file), "%s",
                  source->second.display_path.c_str());
    std::snprintf(
        progress.source_prefix, sizeof(progress.source_prefix), "%s",
        source->second.progress_prefix(analysis.source_mappings).c_str());
    progress.line = row.Line;
    return;
  }
}

static std::string function_name(llvm::StringRef symbol) {
  llvm::ItaniumPartialDemangler demangler;
  std::string name = symbol.str();
  if (!demangler.partialDemangle(name.c_str()) && demangler.isFunction()) {
    char *full = demangler.getFunctionName(nullptr, nullptr);
    char *context = demangler.getFunctionDeclContextName(nullptr, nullptr);
    if (full)
      name = full;
    // The demangler identifies the context; :: inside template/operator names
    // is not a scope separator here.
    if (context && *context &&
        llvm::StringRef(name).starts_with(std::string(context) + "::"))
      name.erase(0, std::strlen(context) + 2);
    std::free(full);
    std::free(context);
  }
  return name;
}

// Keep one immutable backing object across helper processes and decompilers.
// Consume the already-open file identity instead of reopening a pathname.
static int freeze_file(int input) {
  const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  struct stat before{}, after{};
  if (input < 0 || fstat(input, &before) || !S_ISREG(before.st_mode) ||
      before.st_size < 0)
    return -1;
  const int current = fcntl(input, F_GET_SEALS);
  if (current >= 0 && (current & seals) == seals)
    return fcntl(input, F_DUPFD_CLOEXEC, 0);
  const uint64_t size = uint64_t(before.st_size);
  bool noexec = true;
  int output = int(syscall(SYS_memfd_create, "ctrace-module",
                           MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL));
  if (output < 0 && errno == EINVAL) {
    // MFD_NOEXEC_SEAL is newer than ordinary sealed data memfds.
    noexec = false;
    output = int(syscall(SYS_memfd_create, "ctrace-module",
                         MFD_CLOEXEC | MFD_ALLOW_SEALING));
  }
  if (output < 0)
    return -1;
  bool valid = fchmod(output, 0444) == 0 && ftruncate(output, off_t(size)) == 0;
  // Stream the copy; large debug companions must not require a second full
  // heap buffer. The finished descriptor is mapped directly by LLVM.
  std::array<char, 65536> chunk;
  for (uint64_t offset = 0; valid && offset < size;) {
    const ssize_t count = pread(
        input, chunk.data(),
        size_t(std::min<uint64_t>(chunk.size(), size - offset)), off_t(offset));
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      valid = false;
      break;
    }
    for (ssize_t written = 0; valid && written < count;) {
      const ssize_t amount =
          pwrite(output, chunk.data() + written, size_t(count - written),
                 off_t(offset + written));
      if (amount < 0 && errno == EINTR)
        continue;
      if (amount <= 0)
        valid = false;
      else
        written += amount;
    }
    offset += uint64_t(count);
  }
  valid &= fstat(input, &after) == 0 && before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino && before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
  if (!valid ||
      fcntl(output, F_ADD_SEALS, seals | (noexec ? F_SEAL_EXEC : 0)) != 0) {
    close(output);
    return -1;
  }
  return output;
}

static llvm::Expected<llvm::object::OwningBinary<llvm::object::Binary>>
read_binary(const char *path, int descriptor) {
  struct stat metadata{};
  if (descriptor < 0 || fstat(descriptor, &metadata) != 0 ||
      !S_ISREG(metadata.st_mode) || metadata.st_size < 0)
    return llvm::createStringError(std::errc::invalid_argument,
                                   "module descriptor is not a regular file");
  // Every caller supplies a sealed snapshot, so LLVM can share its file pages
  // rather than copy the entire object into a private volatile-input buffer.
  auto bytes = llvm::MemoryBuffer::getOpenFile(descriptor, path,
                                               metadata.st_size, true, false);
  if (!bytes)
    return llvm::errorCodeToError(bytes.getError());
  auto binary = llvm::object::createBinary((*bytes)->getMemBufferRef());
  if (!binary)
    return binary.takeError();
  return llvm::object::OwningBinary<llvm::object::Binary>(std::move(*binary),
                                                          std::move(*bytes));
}

static int find_debug_snapshot(Dwfl_Module *module, void **userdata,
                               const char *name, Dwarf_Addr base,
                               const char *file_name, const char *debuglink,
                               GElf_Word crc, char **debug_name) {
  if (ct_analysis_remote_filesystem()) {
    const unsigned char *build_id = nullptr;
    GElf_Addr id_address;
    const int id_size = dwfl_module_build_id(module, &build_id, &id_address);
    std::vector<std::string> candidates;
    if (id_size > 1) {
      std::string identifier;
      for (int index = 0; index < id_size; ++index) {
        char pair[3];
        std::snprintf(pair, sizeof(pair), "%02x", build_id[index]);
        identifier += pair;
      }
      candidates.push_back("/usr/lib/debug/.build-id/" +
                           identifier.substr(0, 2) + "/" +
                           identifier.substr(2) + ".debug");
    }
    const std::string source = file_name ? file_name : name;
    const auto directory = llvm::sys::path::parent_path(source).str();
    const std::string leaf =
        debuglink && debuglink[0]
            ? debuglink
            : llvm::sys::path::filename(source).str() + ".debug";
    if (!directory.empty()) {
      candidates.push_back(directory + "/" + leaf);
      candidates.push_back(directory + "/.debug/" + leaf);
    }
    // Mirror libdwfl's default debug-name search under /usr/lib/debug,
    // stripping leading path components at each attempt.
    llvm::StringRef remainder(directory);
    while (remainder.starts_with('/'))
      remainder = remainder.drop_front();
    while (!remainder.empty()) {
      candidates.push_back("/usr/lib/debug/" + remainder.str() + "/" + leaf);
      const auto separator = remainder.find('/');
      if (separator == llvm::StringRef::npos)
        break;
      remainder = remainder.drop_front(separator + 1);
    }
    candidates.push_back("/usr/lib/debug/" + leaf);
    for (const auto &candidate : candidates) {
      auto file = ct_analysis_file_access(CT_ANALYSIS_FILE_READ, candidate);
      if (file.error)
        continue;
      const int snapshot = freeze_file(file.descriptor);
      close(file.descriptor);
      if (snapshot < 0)
        continue;
      Elf *elf = elf_begin(snapshot, ELF_C_READ, nullptr);
      const void *candidate_id = nullptr;
      const ssize_t candidate_size =
          elf ? dwelf_elf_gnu_build_id(elf, &candidate_id) : -1;
      bool matches = id_size > 0 && candidate_size == id_size &&
                     std::memcmp(build_id, candidate_id, size_t(id_size)) == 0;
      if (elf && candidate_size >= 0 && (id_size <= 0 || candidate_size == 0) &&
          debuglink && debuglink[0]) {
        uint32_t checksum = 0;
        off_t offset = 0;
        std::array<unsigned char, 65536> chunk;
        bool complete = true;
        for (;;) {
          const ssize_t size =
              pread(snapshot, chunk.data(), chunk.size(), offset);
          if (size < 0 && errno == EINTR)
            continue;
          if (size <= 0) {
            complete = size == 0;
            break;
          }
          checksum = llvm::crc32(
              checksum, llvm::ArrayRef<uint8_t>(chunk.data(), size_t(size)));
          offset += size;
        }
        matches = complete && checksum == crc;
      }
      if (elf)
        elf_end(elf);
      if (matches) {
        auto *analysis = static_cast<ct_analysis *>(*userdata);
        char *path = strdup(candidate.c_str());
        const int retained =
            analysis && path ? fcntl(snapshot, F_DUPFD_CLOEXEC, 0) : -1;
        if (retained >= 0) {
          if (analysis->debug_descriptor >= 0)
            close(analysis->debug_descriptor);
          analysis->debug_descriptor = retained;
          *debug_name = path;
          return snapshot;
        }
        std::free(path);
      }
      close(snapshot);
    }
    // Do not substitute the broker's same-named debug file after a namespace
    // lookup fails. The embedded-DWARF/assembly fallback remains available.
    return -1;
  }
  const int input = dwfl_standard_find_debuginfo(
      module, userdata, name, base, file_name, debuglink, crc, debug_name);
  if (input >= 0) {
    auto *analysis = static_cast<ct_analysis *>(*userdata);
    if (analysis) {
      if (analysis->debug_descriptor >= 0)
        close(analysis->debug_descriptor);
      // Capture the file before libdw decompresses sections in its private
      // ELF image. elf_rawfile() after that may expose changed section headers
      // alongside the original compressed payload.
      analysis->debug_descriptor = freeze_file(input);
    }
  }
  return input;
}

static void collect_symbols(llvm::object::ObjectFile &object,
                            std::vector<FunctionSymbol> &symbols) {
  auto append = [&](llvm::object::SymbolRef symbol, uint64_t size) {
    auto type = symbol.getType();
    auto name = symbol.getName();
    auto address = symbol.getAddress();
    auto flags = symbol.getFlags();
    if (type && name && address && flags &&
        *type == llvm::object::SymbolRef::ST_Function &&
        !(*flags & llvm::object::SymbolRef::SF_Undefined))
      symbols.push_back({*address, size, function_name(*name), name->str()});
    if (!type)
      llvm::consumeError(type.takeError());
    if (!name)
      llvm::consumeError(name.takeError());
    if (!address)
      llvm::consumeError(address.takeError());
    if (!flags)
      llvm::consumeError(flags.takeError());
  };
  for (const auto &[symbol, size] : llvm::object::computeSymbolSizes(object))
    append(symbol, size);
  if (auto *elf = llvm::dyn_cast<llvm::object::ELFObjectFileBase>(&object))
    for (auto symbol : elf->getDynamicSymbolIterators())
      append(symbol, symbol.getSize());
}

static ct_analysis *open_analysis(const char *path, const char *maps,
                                  int descriptor,
                                  const ct_analysis_file_bundle *captured) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  auto analysis = std::make_unique<ct_analysis>();
  if (captured) {
    if (!captured->debug_path || !captured->supplement_path ||
        !captured->identity || std::strlen(captured->identity) > 32 ||
        (captured->identity[0] &&
         (std::strlen(captured->identity) != 32 ||
          std::strspn(captured->identity, "0123456789abcdef") != 32)) ||
        (captured->debug_file >= 0 && !captured->debug_path[0]) ||
        (captured->supplement_file >= 0 && !captured->supplement_path[0]) ||
        (captured->supplement_file < 0 && captured->supplement_path[0]) ||
        (descriptor < 0 &&
         (captured->debug_file >= 0 || captured->supplement_file >= 0 ||
          captured->debug_path[0] || captured->identity[0] ||
          captured->debug_bias_correction)))
      return nullptr;
    const int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    for (const int file :
         {descriptor, captured->debug_file, captured->supplement_file}) {
      if (file < 0)
        continue;
      const int actual = fcntl(file, F_GET_SEALS);
      struct stat metadata{};
      if (actual < 0 || (actual & seals) != seals ||
          fstat(file, &metadata) != 0 || !S_ISREG(metadata.st_mode))
        return nullptr;
    }
  }
  analysis->path = path;
  analysis->soname = llvm::sys::path::filename(path).str();
  llvm::SmallVector<llvm::StringRef> entries;
  llvm::StringRef(maps ? maps : "").split(entries, ',', -1, false);
  for (llvm::StringRef entry : entries) {
    auto pair = entry.split('=');
    analysis->source_mappings.emplace_back(normalized_path(pair.first),
                                           normalized_path(pair.second));
  }
  std::sort(analysis->source_mappings.begin(), analysis->source_mappings.end(),
            [](const auto &left, const auto &right) {
              return left.first.size() > right.first.size();
            });
  analysis->module_file = freeze_file(descriptor);
  if (analysis->module_file < 0) {
    if (captured && descriptor >= 0)
      return nullptr;
    analysis->source_error = "cannot read module; source path is unknown";
    return analysis.release();
  }
  auto binary = read_binary(path, analysis->module_file);
  if (!binary) {
    llvm::consumeError(binary.takeError());
    if (captured && captured->identity[0])
      return nullptr;
    analysis->source_error = "cannot read module; source path is unknown";
    return analysis.release();
  }
  analysis->binary = std::move(*binary);
  llvm::MD5 identity;
  identity.update(analysis->binary.getBinary()->getData());
  auto *object =
      llvm::dyn_cast<llvm::object::ObjectFile>(analysis->binary.getBinary());
  if (!object) {
    if (captured && captured->identity[0])
      return nullptr;
    analysis->source_error = "module has no object debug information";
    return analysis.release();
  }
  auto *module_object = object;
  if (captured) {
    analysis->debug_file = captured->debug_path;
    analysis->supplement_file = captured->supplement_path;
    analysis->debug_bias_correction = captured->debug_bias_correction;
    if (captured->debug_file >= 0) {
      analysis->debug_descriptor = freeze_file(captured->debug_file);
      if (analysis->debug_descriptor < 0)
        return nullptr;
      auto debug =
          read_binary(analysis->debug_file.c_str(), analysis->debug_descriptor);
      if (debug) {
        analysis->debug_binary = std::move(*debug);
        identity.update(analysis->debug_binary.getBinary()->getData());
        if (auto *debug_object = llvm::dyn_cast<llvm::object::ObjectFile>(
                analysis->debug_binary.getBinary()))
          object = debug_object;
      } else {
        // Preserve initial-open behavior when libdw accepts debug information
        // that LLVM cannot represent. Identity comparison below still rejects
        // any new loss of previously selected bytes.
        llvm::consumeError(debug.takeError());
      }
    }
    if (captured->supplement_file >= 0) {
      analysis->supplement_descriptor = freeze_file(captured->supplement_file);
      struct stat metadata{};
      if (analysis->supplement_descriptor < 0 ||
          fstat(analysis->supplement_descriptor, &metadata) != 0 ||
          metadata.st_size <= 0)
        return nullptr;
      auto bytes = llvm::MemoryBuffer::getOpenFile(
          analysis->supplement_descriptor, analysis->supplement_file,
          metadata.st_size, true, false);
      if (!bytes)
        return nullptr;
      analysis->supplement_bytes = std::move(*bytes);
      identity.update(analysis->supplement_bytes->getBuffer());
    }
  } else {
    /* elfutils resolves .gnu_debuglink/build-ID and verifies external debug
     * files. */
    Dwfl_Callbacks callbacks{};
    callbacks.find_debuginfo = find_debug_snapshot;
    callbacks.section_address = dwfl_offline_section_address;
    if (Dwfl *dwfl = dwfl_begin(&callbacks)) {
      const int input = fcntl(analysis->module_file, F_DUPFD_CLOEXEC, 0);
      Dwfl_Module *module =
          input < 0 ? nullptr : dwfl_report_offline(dwfl, path, path, input);
      if (!module && input >= 0)
        close(input);
      if (module && dwfl_report_end(dwfl, nullptr, nullptr) == 0) {
        void **userdata = nullptr;
        dwfl_module_info(module, &userdata, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr);
        if (userdata)
          *userdata = analysis.get();
        Dwarf_Addr bias;
        if (Dwarf *dwarf = dwfl_module_getdwarf(module, &bias)) {
          GElf_Addr elf_bias = 0;
          if (dwfl_module_getelf(module, &elf_bias))
            analysis->debug_bias_correction = int64_t(bias - elf_bias);
          const char *debug_path = nullptr;
          dwfl_module_info(module, nullptr, nullptr, nullptr, nullptr, nullptr,
                           nullptr, &debug_path);
          analysis->debug_file = debug_path ? debug_path : path;
          if (debug_path && std::strcmp(debug_path, path)) {
            auto debug = read_binary(debug_path, analysis->debug_descriptor);
            if (debug) {
              analysis->debug_binary = std::move(*debug);
              identity.update(analysis->debug_binary.getBinary()->getData());
              if (auto *debug_object = llvm::dyn_cast<llvm::object::ObjectFile>(
                      analysis->debug_binary.getBinary())) {
                object = debug_object;
              }
            } else {
              llvm::consumeError(debug.takeError());
            }
          }
          const char *supplement_name = nullptr;
          const void *supplement_id = nullptr;
          const ssize_t supplement_id_size = dwelf_dwarf_gnu_debugaltlink(
              dwarf, &supplement_name, &supplement_id);
          if (supplement_id_size > 0 && supplement_name && supplement_name[0]) {
            llvm::SmallString<256> candidate(supplement_name);
            if (!llvm::sys::path::is_absolute(candidate)) {
              candidate = llvm::sys::path::parent_path(analysis->debug_file);
              llvm::sys::path::append(candidate, supplement_name);
            }
            auto input = ct_analysis_file_access(CT_ANALYSIS_FILE_READ,
                                                 candidate.str().str());
            if (!input.error) {
              const int snapshot = freeze_file(input.descriptor);
              close(input.descriptor);
              Elf *elf = snapshot < 0
                             ? nullptr
                             : elf_begin(snapshot, ELF_C_READ, nullptr);
              const void *actual_id = nullptr;
              const ssize_t actual_size =
                  elf ? dwelf_elf_gnu_build_id(elf, &actual_id) : -1;
              const bool matches = actual_size == supplement_id_size &&
                                   std::memcmp(supplement_id, actual_id,
                                               size_t(actual_size)) == 0;
              if (elf)
                elf_end(elf);
              struct stat metadata{};
              if (matches && fstat(snapshot, &metadata) == 0 &&
                  metadata.st_size > 0) {
                auto bytes = llvm::MemoryBuffer::getOpenFile(
                    snapshot, candidate, metadata.st_size, true, false);
                if (bytes) {
                  analysis->supplement_bytes = std::move(*bytes);
                  analysis->supplement_descriptor = snapshot;
                  analysis->supplement_file = candidate.str().str();
                  identity.update(analysis->supplement_bytes->getBuffer());
                }
              }
              if (snapshot >= 0 && snapshot != analysis->supplement_descriptor)
                close(snapshot);
            }
          }
        } else if (analysis->debug_descriptor >= 0) {
          close(analysis->debug_descriptor);
          analysis->debug_descriptor = -1;
        }
      }
      dwfl_end(dwfl);
    }
  }
  llvm::MD5::MD5Result digest;
  identity.final(digest);
  llvm::SmallString<32> identity_text;
  llvm::MD5::stringifyResult(digest, identity_text);
  analysis->identity = identity_text.str().str();
  if (captured && analysis->identity != captured->identity)
    return nullptr;
  auto *debug_object = object;
  object = module_object;
  const llvm::StringRef module_bytes = analysis->binary.getBinary()->getData();
  const llvm::StringRef debug_bytes = debug_object->getData();
  const auto supplementary = analysis->supplement_bytes
                                 ? analysis->supplement_bytes->getBuffer()
                                 : llvm::StringRef{};
  analysis->cache_key = ct_cache_key(
      {"module", path,
       std::string_view(module_bytes.data(), module_bytes.size()),
       analysis->debug_file,
       std::string_view(debug_bytes.data(), debug_bytes.size()),
       std::string_view(supplementary.data(), supplementary.size()),
       maps ? maps : "", bypass_source_checksum ? "skip" : "verify"});
  std::vector<unsigned char> catalog;
  bool catalog_hit = false;
  if (ct_cache_read("modules", analysis->cache_key, catalog)) {
    ct_analysis_archive reader{catalog, true};
    reader.fields(analysis->soname, analysis->link_base, analysis->symbols,
                  analysis->plt_ranges, analysis->plt_symbols,
                  analysis->has_dwarf, analysis->source_error,
                  analysis->tables);
    catalog_hit = reader.complete();
    if (!catalog_hit) {
      analysis->soname = llvm::sys::path::filename(path).str();
      analysis->symbols.clear();
      analysis->plt_ranges.clear();
      analysis->plt_symbols.clear();
      analysis->has_dwarf = false;
      analysis->source_error.clear();
      analysis->tables.clear();
    }
  }
  auto ignore_error = [](llvm::Error error) {
    llvm::consumeError(std::move(error));
  };
  analysis->dwarf = llvm::DWARFContext::create(
      *debug_object, llvm::DWARFContext::ProcessDebugRelocations::Process,
      nullptr, "", ignore_error, ignore_error);
  if (catalog_hit) {
    for (const auto &table : analysis->tables)
      for (const auto &[index, source] : table.files)
        if (!source.error.empty())
          (source.error_bypassed ? bypassed_prefixes : rejected_prefixes)
              .try_emplace(source.prefix, source.error);
    return analysis.release();
  }
  ct_analysis_progress progress{};
  std::snprintf(progress.stage, sizeof(progress.stage), "instrumentation");
  std::snprintf(progress.module, sizeof(progress.module), "%s", path);
  std::snprintf(progress.detail, sizeof(progress.detail),
                "loading module metadata and collecting functions");
  ct_analysis_report_progress(&progress);
  if (auto *elf = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(object)) {
    auto dynamic = elf->getELFFile().dynamicEntries();
    if (dynamic) {
      uint64_t strings = 0, size = 0, name = UINT64_MAX;
      for (const auto &entry : *dynamic) {
        if (entry.d_tag == DT_STRTAB)
          strings = entry.d_un.d_ptr;
        else if (entry.d_tag == DT_STRSZ)
          size = entry.d_un.d_val;
        else if (entry.d_tag == DT_SONAME)
          name = entry.d_un.d_val;
      }
      if (strings && name < size) {
        auto mapped = elf->getELFFile().toMappedAddr(strings);
        if (mapped) {
          const auto bytes = object->getData();
          const char *start = reinterpret_cast<const char *>(*mapped);
          const size_t offset = start - bytes.data();
          if (offset < bytes.size() && size <= bytes.size() - offset) {
            llvm::StringRef table(start, size);
            auto text = table.drop_front(name);
            if (text.contains('\0'))
              analysis->soname = text.split('\0').first.str();
          }
        } else {
          llvm::consumeError(mapped.takeError());
        }
      }
    } else {
      llvm::consumeError(dynamic.takeError());
    }
    auto headers = elf->getELFFile().program_headers();
    if (headers) {
      uint64_t base = UINT64_MAX;
      for (const auto &header : *headers)
        if (header.p_type == PT_LOAD)
          base = std::min(base, uint64_t(header.p_vaddr));
      if (base != UINT64_MAX)
        analysis->link_base = base & ~uint64_t(4095); // x86-64 page alignment.
    } else {
      llvm::consumeError(headers.takeError());
    }
  }
  if (auto *elf = llvm::dyn_cast<llvm::object::ELFObjectFileBase>(object)) {
    // Match decoded PLT jumps to their GOT relocation rather than assuming a
    // fixed entry size or relocation order. This also covers CET .plt.sec.
    std::map<uint64_t, std::string> linkage_symbols;
    if (elf->getEMachine() == EM_X86_64) {
      for (const auto &section : object->sections()) {
        for (const auto &relocation : section.relocations()) {
          if (relocation.getType() != R_X86_64_JUMP_SLOT &&
              relocation.getType() != R_X86_64_GLOB_DAT)
            continue;
          const auto symbol = relocation.getSymbol();
          if (symbol == object->symbol_end())
            continue;
          auto name = symbol->getName();
          if (!name) {
            llvm::consumeError(name.takeError());
            continue;
          }
          if (name->empty() ||
              name->size() >= sizeof(ct_location::plt_symbol) ||
              name->contains("*/") ||
              std::any_of(name->begin(), name->end(), [](unsigned char byte) {
                return byte < 0x20 || byte >= 0x7f;
              }))
            continue;
          linkage_symbols.emplace(relocation.getOffset(), name->str());
        }
      }
    }
    std::unique_ptr<llvm::MCSubtargetInfo> subtarget;
    std::unique_ptr<llvm::MCInstrInfo> instructions;
    std::unique_ptr<llvm::MCInstrAnalysis> instruction_analysis;
    if (!linkage_symbols.empty()) {
      llvm::InitializeNativeTarget();
      const auto triple = object->makeTriple();
      std::string error;
      if (const auto *target =
              llvm::TargetRegistry::lookupTarget(triple.str(), error)) {
        subtarget.reset(
            target->createMCSubtargetInfo(triple.str(), "generic", ""));
        instructions.reset(target->createMCInstrInfo());
        if (instructions)
          instruction_analysis.reset(
              target->createMCInstrAnalysis(instructions.get()));
      }
    }
    for (const auto &section : object->sections()) {
      auto name = section.getName();
      if (!name) {
        llvm::consumeError(name.takeError());
        continue;
      }
      if (!section.isText() || (*name != ".plt" && *name != ".plt.sec" &&
                                *name != ".plt.got" && *name != ".iplt"))
        continue;
      const uint64_t address = section.getAddress(), size = section.getSize();
      if (address < analysis->link_base || !size || size > UINT64_MAX - address)
        continue;
      analysis->plt_ranges.emplace_back(address - analysis->link_base,
                                        address + size - analysis->link_base);
      if (!subtarget || !instruction_analysis)
        continue;
      auto contents = section.getContents();
      if (!contents) {
        llvm::consumeError(contents.takeError());
        continue;
      }
      const auto bytes = llvm::ArrayRef<uint8_t>(
          reinterpret_cast<const uint8_t *>(contents->data()),
          contents->size());
      for (const auto &[entry, got] :
           instruction_analysis->findPltEntries(address, bytes, *subtarget)) {
        const auto symbol = linkage_symbols.find(got);
        if (entry < address || entry >= address + size ||
            symbol == linkage_symbols.end())
          continue;
        analysis->plt_symbols.emplace(entry - analysis->link_base,
                                      symbol->second);
        // LLVM reports the JMP address. An immediately preceding ENDBR64 is
        // the entry landing pad in an Intel CET-enabled linkage stub.
        const uint64_t offset = entry - address;
        if (offset >= 4 && offset <= contents->size() &&
            contents->substr(offset - 4, 4) == "\xf3\x0f\x1e\xfa")
          analysis->plt_symbols.emplace(entry - 4 - analysis->link_base,
                                        symbol->second);
      }
    }
  }
  collect_symbols(*object, analysis->symbols);
  if (debug_object != object)
    collect_symbols(*debug_object, analysis->symbols);
  object = debug_object;
  std::sort(analysis->symbols.begin(), analysis->symbols.end(),
            [](const auto &left, const auto &right) {
              return left.address < right.address;
            });
  for (const auto &section : object->sections()) {
    auto name = section.getName();
    if (!name) {
      llvm::consumeError(name.takeError());
      continue;
    }
    if (section.getSize() &&
        (*name == ".debug_info" || *name == ".debug_line" ||
         *name == ".debug_types" || *name == ".zdebug_info" ||
         *name == ".zdebug_line" || *name == ".zdebug_types"))
      analysis->has_dwarf = true;
  }
  std::map<uint64_t, std::string> compilation_directories;
  std::map<uint64_t, ct_source_compile_context> compilation_contexts;
  std::set<uint64_t> ambiguous_contexts;
  for (const auto &unit : analysis->dwarf->normal_units()) {
    const auto die = unit->getUnitDIE();
    const auto offset = die.find(llvm::dwarf::DW_AT_stmt_list);
    const auto value = offset ? offset->getAsSectionOffset() : std::nullopt;
    if (!value)
      continue;
    const uint64_t table_offset = *value + unit->getLineTableOffset();
    ct_source_compile_context context;
    if (const char *directory = unit->getCompilationDir())
      context.directory = normalized_path(directory);
    if (const auto language = die.find(llvm::dwarf::DW_AT_language))
      context.language = language->getAsUnsignedConstant().value_or(0);
    for (auto [attribute, target] :
         {std::pair{llvm::dwarf::DW_AT_producer, &context.producer},
          std::pair{llvm::dwarf::DW_AT_name, &context.source}}) {
      if (const auto field = die.find(attribute)) {
        auto text = field->getAsCString();
        if (text)
          *target = *text;
        else
          llvm::consumeError(text.takeError());
      }
    }
    if (!context.source.empty()) {
      llvm::SmallString<256> source(context.source);
      if (!llvm::sys::path::is_absolute(source) && !context.directory.empty()) {
        source = context.directory;
        llvm::sys::path::append(source, context.source);
      }
      context.source = normalized_path(source);
    }
    // A shared line table can still have a useful common directory even when
    // conflicting CU metadata cannot establish one compilation environment.
    auto [directory, new_directory] =
        compilation_directories.try_emplace(table_offset, context.directory);
    if (!new_directory && directory->second != context.directory)
      directory->second.clear();
    if (ambiguous_contexts.count(table_offset))
      continue;
    auto [entry, inserted] =
        compilation_contexts.try_emplace(table_offset, std::move(context));
    if (!inserted && std::tie(entry->second.producer, entry->second.directory,
                              entry->second.source, entry->second.language) !=
                         std::tie(context.producer, context.directory,
                                  context.source, context.language)) {
      entry->second = {};
      ambiguous_contexts.insert(table_offset);
    }
  }
  const auto &dwarf_object = analysis->dwarf->getDWARFObj();
  llvm::DWARFDataExtractor data(dwarf_object, dwarf_object.getLineSection(),
                                dwarf_object.isLittleEndian(), 8);
  llvm::DWARFDebugLine::SectionParser parser(data, *analysis->dwarf,
                                             analysis->dwarf->normal_units());
  uint64_t next_source_id = 0;
  while (!parser.done()) {
    const auto directory = compilation_directories[parser.getOffset()];
    auto context = compilation_contexts[parser.getOffset()];
    // Resolve source remapping against recorded paths only. A relative DWARF
    // directory does not establish an absolute root in the tracer's cwd.
    for (auto *path : {&context.directory, &context.source}) {
      if (!llvm::sys::path::is_absolute(*path))
        continue;
      for (const auto &[original, replacement] : analysis->source_mappings) {
        if (llvm::StringRef(*path).starts_with(original) &&
            (original == "/" || path->size() == original.size() ||
             (*path)[original.size()] == '/')) {
          llvm::SmallString<256> mapped(replacement);
          llvm::sys::path::append(
              mapped, llvm::StringRef(*path).drop_front(original.size()));
          *path = normalized_path(mapped);
          break;
        }
      }
    }
    SourceTable source_table{
        parser.parseNext(ignore_error, ignore_error), {}, std::move(context)};
    const auto &prologue = source_table.table.Prologue;
    auto last = prologue.getLastValidFileIndex();
    if (!last)
      continue;
    for (uint64_t index = prologue.getVersion() >= 5 ? 0 : 1; index <= *last;
         ++index) {
      std::string original;
      if (!prologue.getFileNameByIndex(
              index, directory,
              llvm::DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
              original))
        continue;
      original = normalized_path(original);
      SourceFile source;
      source.id = ++next_source_id;
      source.path = original;
      auto file_name = prologue.getFileNameEntry(index).Name.getAsCString();
      if (file_name) {
        llvm::StringRef name(*file_name);
        // Compiler pseudo files contain no source bytes to validate. Keep
        // their line mappings without quarantining the surrounding directory.
        if (name == "<built-in>" || name == "<command-line>" ||
            name == "<command line>" || name == "<scratch space>") {
          source.path = name.str();
          source.display_path = source.path;
          source_table.files.emplace(index, std::move(source));
          continue;
        }
      } else {
        llvm::consumeError(file_name.takeError());
      }
      std::string old_prefix = llvm::sys::path::parent_path(original).str();
      std::string new_prefix = old_prefix;
      source.prefix = "directory:" + old_prefix;
      for (const auto &[old_path, new_path] : analysis->source_mappings) {
        if (llvm::StringRef(original).starts_with(old_path) &&
            (old_path == "/" || original.size() == old_path.size() ||
             original[old_path.size()] == '/')) {
          old_prefix = old_path;
          new_prefix = new_path;
          source.prefix = "map:" + old_path;
          llvm::SmallString<256> mapped(new_path);
          llvm::sys::path::append(
              mapped, llvm::StringRef(original).drop_front(old_path.size()));
          source.path = normalized_path(mapped);
          break;
        }
      }
      // A relative DWARF compilation directory does not establish an absolute
      // source root. Display the recorded/mapped path without inventing one
      // from the tracer's current directory.
      source.display_path = source.path;
      std::string error;
      bool checksum_error = !prologue.ContentTypes.HasMD5;
      if (checksum_error)
        error = "DWARF source checksum is absent";
      if (prologue.ContentTypes.HasMD5 || bypass_source_checksum) {
        auto bytes = ct_analysis_read_file(source.path);
        if (!bytes) {
          error = "source cannot be read: " + bytes.getError().message();
          checksum_error = false;
        } else {
          if (prologue.ContentTypes.HasMD5) {
            llvm::MD5 hash;
            hash.update((*bytes)->getBuffer());
            llvm::MD5::MD5Result checksum;
            hash.final(checksum);
            source.verified =
                checksum == prologue.getFileNameEntry(index).Checksum;
            if (!source.verified) {
              error = "source checksum mismatch";
              checksum_error = true;
            }
          }
          if (source.verified || bypass_source_checksum) {
            source.content = share_source_text(source.path, std::move(*bytes));
          }
        }
      }
      if (!error.empty()) {
        const bool bypassed = checksum_error && bypass_source_checksum;
        auto &prefixes = bypassed ? bypassed_prefixes : rejected_prefixes;
        source.error = "source prefix " + old_prefix + "=" + new_prefix + ": " +
                       (bypassed ? "checksum verification skipped: " : "") +
                       error + " (" + source.path + ")";
        source.error_bypassed = bypassed;
        prefixes.try_emplace(source.prefix, source.error);
      }
      source_table.files.emplace(index, std::move(source));
    }
    // Paths and checksum results now live in SourceFile. Address lookups use
    // only rows/sequences, as on the disk-restored path, which never stores
    // this parsing prologue. Do not retain its directory/file tables twice.
    source_table.table.Prologue = {};
    source_table.table.Rows.shrink_to_fit();
    source_table.table.Sequences.shrink_to_fit();
    analysis->tables.push_back(std::move(source_table));
  }
  if (analysis->tables.empty())
    analysis->source_error = analysis->has_dwarf
                                 ? "DWARF has no usable source file table"
                                 : "DWARF is absent; source path is unknown";
  catalog.clear();
  ct_analysis_archive writer{catalog, false};
  writer.fields(analysis->soname, analysis->link_base, analysis->symbols,
                analysis->plt_ranges, analysis->plt_symbols,
                analysis->has_dwarf, analysis->source_error, analysis->tables);
  if (writer.complete())
    ct_cache_write("modules", analysis->cache_key, catalog);
  return analysis.release();
}

ct_analysis *ct_analysis_open_fd(const char *path, const char *maps,
                                 int descriptor) {
  return open_analysis(path, maps, descriptor, nullptr);
}

ct_analysis *ct_analysis_open_bundle(const char *path, const char *maps,
                                     const ct_analysis_file_bundle *bundle) {
  return bundle ? open_analysis(path, maps, bundle->module_file, bundle)
                : nullptr;
}

ct_analysis *ct_analysis_open(const char *path, const char *maps) {
  const int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  ct_analysis *analysis = ct_analysis_open_fd(path, maps, descriptor);
  if (descriptor >= 0)
    close(descriptor);
  return analysis;
}

int ct_analysis_module_file(ct_analysis *analysis) {
  return analysis ? analysis->module_file : -1;
}

int ct_analysis_debug_file_descriptor(ct_analysis *analysis) {
  return analysis ? analysis->debug_descriptor : -1;
}

int ct_analysis_supplement_file_descriptor(ct_analysis *analysis) {
  return analysis ? analysis->supplement_descriptor : -1;
}

const char *ct_analysis_supplement_file(ct_analysis *analysis) {
  return analysis ? analysis->supplement_file.c_str() : "";
}

int64_t ct_analysis_debug_bias_correction(ct_analysis *analysis) {
  return analysis ? analysis->debug_bias_correction : 0;
}

static void lookup_location(ct_analysis *analysis, uint64_t module_offset,
                            ct_location *location, bool detail) {
  std::memset(location, 0, sizeof(*location));
  if (!analysis)
    return;
  location->is_plt = std::any_of(
      analysis->plt_ranges.begin(), analysis->plt_ranges.end(),
      [module_offset](const auto &range) {
        return module_offset >= range.first && module_offset < range.second;
      });
  if (auto symbol = analysis->plt_symbols.find(module_offset);
      location->is_plt && symbol != analysis->plt_symbols.end())
    std::snprintf(location->plt_symbol, sizeof(location->plt_symbol), "%s",
                  symbol->second.c_str());
  const uint64_t address = module_offset + analysis->link_base;
  llvm::DIInliningInfo inlining;
  llvm::DWARFContext::DIEsForAddress dies{};
  if (analysis->dwarf) {
    inlining = analysis->dwarf->getInliningInfoForAddress(
        {address, llvm::object::SectionedAddress::UndefSection},
        {llvm::DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
         llvm::DINameKind::LinkageName});
    dies = analysis->dwarf->getDIEsForAddress(address);
  }
  if (inlining.getNumberOfFrames()) {
    const auto &leaf = inlining.getFrame(0);
    if (leaf.FunctionName != llvm::DILineInfo::BadString)
      std::snprintf(location->symbol, sizeof(location->symbol), "%s",
                    leaf.FunctionName.c_str());
  }
  location->inlined = inlining.getNumberOfFrames() > 1;
  llvm::SmallVector<llvm::DWARFDie> scopes;
  if (dies.FunctionDIE) {
    dies.FunctionDIE.getDwarfUnit()->getInlinedChainForAddress(address, scopes);
    if (!scopes.empty()) {
      location->function_id = scopes.front().getOffset() + 1;
      location->inlined |=
          scopes.front().getTag() == llvm::dwarf::DW_TAG_inlined_subroutine;
      for (auto scope = scopes.rbegin(); scope != scopes.rend(); ++scope) {
        const char *name =
            scope->getSubroutineName(llvm::DINameKind::LinkageName);
        const size_t size = name ? std::strlen(name) + 1 : 1;
        if (size > sizeof(location->scope_chain) - location->scope_chain_size)
          break;
        std::memcpy(location->scope_chain + location->scope_chain_size,
                    name ? name : "", size);
        location->scope_chain_size += size;
      }
    }
  }
  if (!location->symbol[0] && dies.FunctionDIE) {
    if (const char *name =
            dies.FunctionDIE.getSubroutineName(llvm::DINameKind::LinkageName))
      std::snprintf(location->symbol, sizeof(location->symbol), "%s", name);
  }
  auto end = std::upper_bound(
      analysis->symbols.begin(), analysis->symbols.end(), address,
      [](uint64_t value, const auto &entry) { return value < entry.address; });
  if (end != analysis->symbols.begin()) {
    const uint64_t start = (end - 1)->address;
    auto begin = std::lower_bound(analysis->symbols.begin(), end, start,
                                  [](const auto &entry, uint64_t value) {
                                    return entry.address < value;
                                  });
    bool contains = false, named = !location->symbol[0];
    bool physical_named = false;
    for (auto symbol = begin; symbol != end; ++symbol) {
      const bool covered = address == start || address - start < symbol->size;
      contains |= covered;
      named |= symbol->symbol == location->symbol;
      physical_named |=
          location->scope_chain_size && symbol->symbol == location->scope_chain;
      if (covered && !location->symbol[0])
        std::snprintf(location->symbol, sizeof(location->symbol), "%s",
                      symbol->symbol.c_str());
    }
    if (!named && dies.FunctionDIE) {
      auto low = dies.FunctionDIE.find(llvm::dwarf::DW_AT_low_pc);
      if (low)
        physical_named |= low->getAsAddress() == start;
    }
    physical_named |= !location->inlined && named;
    if (contains && physical_named) {
      std::vector<llvm::StringRef> copied;
      for (auto symbol = begin; symbol != end; ++symbol) {
        if (std::find(copied.begin(), copied.end(), symbol->symbol) !=
            copied.end())
          continue;
        const size_t size = symbol->symbol.size() + 1;
        if (size > sizeof(location->physical_aliases) -
                       location->physical_aliases_size)
          continue;
        std::memcpy(location->physical_aliases +
                        location->physical_aliases_size,
                    symbol->symbol.c_str(), size);
        location->physical_aliases_size += size;
        copied.push_back(symbol->symbol);
      }
      if (!location->inlined) {
        std::memcpy(location->aliases, location->physical_aliases,
                    location->physical_aliases_size);
        location->aliases_size = location->physical_aliases_size;
      }
    }
  }
  if (!location->scope_chain_size && !location->inlined &&
      location->symbol[0]) {
    location->scope_chain_size = std::strlen(location->symbol) + 1;
    std::memcpy(location->scope_chain, location->symbol,
                location->scope_chain_size);
  }
  if (location->symbol[0]) {
    std::snprintf(location->function, sizeof(location->function), "%s",
                  function_name(location->symbol).c_str());
    std::snprintf(location->qualified_function,
                  sizeof(location->qualified_function), "%s",
                  llvm::demangle(location->symbol).c_str());
  }
  if (!analysis->dwarf)
    return;
  for (auto &table : analysis->tables) {
    auto index = table.table.lookupAddress(
        {address, llvm::object::SectionedAddress::UndefSection});
    if (index >= table.table.Rows.size())
      continue;
    const auto &row = table.table.Rows[index];
    auto entry = table.files.find(row.File);
    if (row.EndSequence || entry == table.files.end())
      continue;
    auto &source = entry->second;
    if (row.Line) {
      std::snprintf(location->file, sizeof(location->file), "%s",
                    source.display_path.c_str());
      location->line = row.Line;
      location->source_id = source.id;
      location->column = row.Column;
      location->discriminator = row.Discriminator;
      location->has_line = true;
    }
    if (!detail)
      return;
    for (size_t depth = 0; depth + 1 < scopes.size(); ++depth) {
      const auto &callee = scopes[scopes.size() - depth - 2];
      const auto &caller = scopes[scopes.size() - depth - 1];
      if (callee.getTag() != llvm::dwarf::DW_TAG_inlined_subroutine)
        continue;
      const auto file =
          llvm::dwarf::toUnsigned(callee.find(llvm::dwarf::DW_AT_call_file));
      const auto line =
          llvm::dwarf::toUnsigned(callee.find(llvm::dwarf::DW_AT_call_line));
      if (!file || !line || !*line)
        continue;
      const auto call_source = table.files.find(*file);
      if (call_source == table.files.end())
        continue;
      if (location->inline_call_count == std::size(location->inline_calls)) {
        location->inline_call_count = 0;
        break;
      }
      const auto &path = call_source->second.display_path;
      size_t file_offset = 0;
      while (file_offset < location->inline_files_size &&
             path != location->inline_files + file_offset)
        file_offset += std::strlen(location->inline_files + file_offset) + 1;
      if (file_offset == location->inline_files_size) {
        if (path.size() + 1 > sizeof(location->inline_files) - file_offset)
          continue;
        std::memcpy(location->inline_files + file_offset, path.c_str(),
                    path.size() + 1);
        location->inline_files_size += path.size() + 1;
      }
      location->inline_calls[location->inline_call_count++] = {
          call_source->second.id,
          caller.getOffset() + 1,
          *line,
          uint32_t(llvm::dwarf::toUnsigned(
                       callee.find(llvm::dwarf::DW_AT_call_column))
                       .value_or(0)),
          uint32_t(depth),
          file_offset};
    }
    if (row.Line && source.content && !rejected_prefixes.count(source.prefix) &&
        row.Line <= source.content->lines.size()) {
      llvm::StringRef text = source.content->lines[row.Line - 1].ltrim();
      auto &display =
          source.display_for(analysis->path.c_str(), source_syntax,
                             analysis->source_mappings, table.compile_context);
      auto converted = display.lines.find(row.Line);
      if (converted != display.lines.end()) {
        text = llvm::StringRef(converted->second.text).ltrim();
        std::snprintf(location->conversion_error,
                      sizeof(location->conversion_error), "%s",
                      converted->second.error.c_str());
        location->structural = converted->second.structural;
      }
      std::snprintf(location->text, sizeof(location->text), "%.*s",
                    int(std::min(text.size(), sizeof(location->text) - 1)),
                    text.data());
      location->source_usable = text.size() < sizeof(location->text);
      location->source_verified = location->source_usable && source.verified;
      if (location->source_usable && !location->inlined && dies.FunctionDIE) {
        auto entry_pc = dies.FunctionDIE.find(llvm::dwarf::DW_AT_entry_pc);
        auto function_entry =
            entry_pc ? entry_pc->getAsAddress() : std::nullopt;
        if (!function_entry) {
          entry_pc = dies.FunctionDIE.find(llvm::dwarf::DW_AT_low_pc);
          function_entry = entry_pc ? entry_pc->getAsAddress() : std::nullopt;
        }
        if (function_entry && *function_entry == address) {
          auto declaration = display.lines.find(dies.FunctionDIE.getDeclLine());
          if (declaration != display.lines.end()) {
            const auto &signature = declaration->second.declaration;
            bool owner = signature.function == location->symbol;
            for (size_t offset = 0;
                 !owner && offset < location->aliases_size;) {
              owner = signature.function == location->aliases + offset;
              offset += std::strlen(location->aliases + offset) + 1;
            }
            if (owner && !signature.text.empty() &&
                signature.text.size() < sizeof(location->entry_declaration)) {
              std::memcpy(location->entry_declaration, signature.text.c_str(),
                          signature.text.size() + 1);
              location->entry_declaration_line = signature.line;
            }
          }
        }
      }
      if (location->source_usable && converted != display.lines.end()) {
        size_t case_begin = 0, case_end = std::string::npos;
        size_t display_begin = 0, display_end = text.size();
        bool case_body = false;
        for (const auto &candidate : converted->second.cases) {
          bool owner = candidate.function == location->symbol;
          for (size_t offset = 0; !owner && offset < location->aliases_size;) {
            owner = candidate.function == location->aliases + offset;
            offset += std::strlen(location->aliases + offset) + 1;
          }
          if (!owner ||
              (row.Column && (row.Column < candidate.begin_column ||
                              row.Column >= candidate.end_column)) ||
              (!row.Column && candidate.column_required))
            continue;
          if (location->source_case_count ==
              std::size(location->source_cases)) {
            location->source_case_count = 0;
            case_body = false;
            case_begin = display_begin = 0;
            case_end = std::string::npos;
            display_end = text.size();
            break;
          }
          location->source_cases[location->source_case_count++] =
              candidate.label;
          if (candidate.label.group_id) {
            case_body = true;
            case_begin = std::max(case_begin, candidate.begin);
            case_end = std::min(case_end, candidate.end);
            display_begin = std::max(display_begin, candidate.display_begin);
            display_end = std::min(display_end, candidate.display_end);
          }
        }
        if (case_body && display_begin <= display_end &&
            display_end <= text.size()) {
          const auto body = text.slice(display_begin, display_end).ltrim();
          display_begin = body.data() - text.data();
          std::snprintf(location->text, sizeof(location->text), "%.*s",
                        int(body.size()), body.data());
          location->source_case_label_only = body.trim().empty();
          location->structural |= location->source_case_label_only;
        }
        for (const auto &candidate : converted->second.closures) {
          bool owner = candidate.function == location->symbol;
          for (size_t offset = 0; !owner && offset < location->aliases_size;) {
            owner = candidate.function == location->aliases + offset;
            offset += std::strlen(location->aliases + offset) + 1;
          }
          if (!owner || candidate.display_offset < display_begin ||
              candidate.display_offset >= display_end)
            continue;
          if (location->source_closure_count ==
              std::size(location->source_closures)) {
            location->source_closure_count = 0;
            break;
          }
          location->source_closures[location->source_closure_count++] =
              candidate.closure;
        }
        for (const auto &annotation : converted->second.macros) {
          bool owner = annotation.function == location->symbol;
          for (size_t offset = 0; !owner && offset < location->aliases_size;) {
            owner = annotation.function == location->aliases + offset;
            offset += std::strlen(location->aliases + offset) + 1;
          }
          if (!owner)
            continue;
          if (location->source_macro_count ==
              std::size(location->source_macros)) {
            location->source_macro_count = 0;
            break;
          }
          location->source_macros[location->source_macro_count++] =
              annotation.macro;
        }
        for (const auto &candidate : converted->second.calls) {
          bool owner = candidate.function == location->symbol;
          for (size_t offset = 0; !owner && offset < location->aliases_size;) {
            owner = candidate.function == location->aliases + offset;
            offset += std::strlen(location->aliases + offset) + 1;
          }
          if (!owner ||
              location->source_call_count ==
                  std::size(location->source_calls) ||
              candidate.parameters.size() >
                  std::size(location->call_parameters) -
                      location->call_parameter_count)
            continue;
          auto &contract = location->source_calls[location->source_call_count];
          if (candidate.callee.size() >= sizeof(contract.callee))
            continue;
          std::memcpy(contract.callee, candidate.callee.c_str(),
                      candidate.callee.size() + 1);
          if (candidate.declaration.size() < sizeof(contract.declaration))
            std::memcpy(contract.declaration, candidate.declaration.c_str(),
                        candidate.declaration.size() + 1);
          contract.variadic = candidate.variadic;
          contract.parameter_begin = location->call_parameter_count;
          contract.parameter_count = candidate.parameters.size();
          for (const auto &parameter : candidate.parameters)
            location->call_parameters[location->call_parameter_count++] =
                parameter;
          ++location->source_call_count;
        }
        for (const auto &candidate : converted->second.call_results) {
          bool owner = candidate.function == location->symbol;
          for (size_t offset = 0; !owner && offset < location->aliases_size;) {
            owner = candidate.function == location->aliases + offset;
            offset += std::strlen(location->aliases + offset) + 1;
          }
          if (!owner || candidate.begin < case_begin ||
              candidate.end > case_end)
            continue;
          if (location->source_call_result_count ==
              std::size(location->source_call_results)) {
            // A partial candidate list could make ambiguous repeated calls
            // appear unique and attach a result to the wrong expression.
            location->source_call_result_count = 0;
            break;
          }
          location->source_call_results[location->source_call_result_count++] =
              candidate.result;
        }
        if (converted->second.highlights.size() <=
            std::size(location->source_highlights)) {
          for (const auto &highlight : converted->second.highlights) {
            if (highlight.begin < display_begin || highlight.end > display_end)
              continue;
            location->source_highlights[location->source_highlight_count++] = {
                uint32_t(highlight.begin - display_begin),
                uint32_t(highlight.end - display_begin)};
          }
        }
        std::pair<uint64_t, uint64_t> function_range{};
        if (!converted->second.blocks.empty() && !location->inlined &&
            dies.FunctionDIE) {
          auto ranges = dies.FunctionDIE.getAddressRanges();
          if (!ranges)
            llvm::consumeError(ranges.takeError());
          else
            for (const auto &range : *ranges)
              if (address >= range.LowPC && address < range.HighPC) {
                function_range = {range.LowPC, range.HighPC};
                break;
              }
        }
        for (const auto &candidate : converted->second.blocks) {
          bool owner = candidate.function == location->symbol;
          for (size_t offset = 0; !owner && offset < location->aliases_size;) {
            owner = candidate.function == location->aliases + offset;
            offset += std::strlen(location->aliases + offset) + 1;
          }
          if (!owner)
            continue;
          if (!candidate.complete || location->source_block_count ==
                                         std::size(location->source_blocks)) {
            location->source_block_count = 0;
            break;
          }
          auto &block = location->source_blocks[location->source_block_count++];
          block = candidate.block;
          if (function_range.first < function_range.second) {
            const auto key =
                std::make_tuple(location->function_id, block.id,
                                function_range.first, function_range.second);
            auto [cached, inserted] = display.block_ranges.try_emplace(key);
            if (inserted) {
              uint64_t begin = function_range.second, end = 0;
              for (size_t row_index = 0;
                   row_index + 1 < table.table.Rows.size(); ++row_index) {
                const auto &candidate_row = table.table.Rows[row_index];
                const auto &next = table.table.Rows[row_index + 1];
                const uint64_t pc = candidate_row.Address.Address;
                if (candidate_row.EndSequence ||
                    candidate_row.File != row.File ||
                    candidate_row.Line < block.start_line ||
                    candidate_row.Line > block.closing_line ||
                    pc < function_range.first || pc >= function_range.second)
                  continue;
                // Zero-width location views identify lexical association but
                // never extend the envelope past a real instruction interval.
                begin = std::min(begin, pc);
                if (next.Address.SectionIndex ==
                        candidate_row.Address.SectionIndex &&
                    next.Address.Address > pc)
                  end = std::max(end, std::min(next.Address.Address,
                                               function_range.second));
              }
              if (begin < end && begin >= analysis->link_base)
                cached->second = {begin - analysis->link_base,
                                  end - analysis->link_base};
            }
            block.begin_offset = cached->second.first;
            block.end_offset = cached->second.second;
            block.has_address_range = block.begin_offset < block.end_offset;
          }
        }
        const auto &declaration = converted->second.declaration;
        bool owner = declaration.function == location->symbol;
        for (size_t offset = 0; !owner && offset < location->aliases_size;) {
          owner = declaration.function == location->aliases + offset;
          offset += std::strlen(location->aliases + offset) + 1;
        }
        if (owner && !declaration.text.empty() &&
            declaration.text.size() < sizeof(location->declaration)) {
          std::snprintf(location->declaration, sizeof(location->declaration),
                        "%s", declaration.text.c_str());
          location->declaration_line = declaration.line;
        }
        std::set<std::string> seen, declared;
        const auto &variables = location->declaration[0]
                                    ? declaration.variables
                                    : converted->second.variables;
        for (const auto &variable : variables) {
          bool owner = variable.function == location->symbol;
          for (size_t offset = 0; !owner && offset < location->aliases_size;) {
            owner = variable.function == location->aliases + offset;
            offset += std::strlen(location->aliases + offset) + 1;
          }
          if (!owner || variable.offset < case_begin ||
              variable.offset >= case_end)
            continue;
          const size_t declaration_bytes = variable.name.size() + 1;
          if (variable.declaration && declared.insert(variable.name).second &&
              declaration_bytes <= sizeof(location->source_declarations) -
                                       location->source_declarations_size) {
            std::memcpy(location->source_declarations +
                            location->source_declarations_size,
                        variable.name.c_str(), declaration_bytes);
            location->source_declarations_size += declaration_bytes;
          }
          // A local declaration introduces storage, not an input value.
          // Separate DeclRefExpr entries still preserve initializer reads,
          // including references to another declaration on the same line.
          if (variable.declaration && !location->declaration[0])
            continue;
          const auto &selected = variable.declaration || variable.access.empty()
                                     ? variable.name
                                     : variable.access;
          const size_t bytes = selected.size() + 1;
          if (!seen.insert(selected).second)
            continue;
          if (bytes > sizeof(location->source_variables) -
                          location->source_variables_size)
            continue;
          std::memcpy(location->source_variables +
                          location->source_variables_size,
                      selected.c_str(), bytes);
          location->source_variables_size += bytes;
        }
      }
      if (location->source_usable && !location->inlined &&
          converted != display.lines.end()) {
        const auto &expression = converted->second.expression;
        bool owner = expression.function == location->symbol;
        for (size_t offset = 0; !owner && offset < location->aliases_size;) {
          owner = expression.function == location->aliases + offset;
          offset += std::strlen(location->aliases + offset) + 1;
        }
        if (expression.kind != CT_EXPRESSION_NONE && owner &&
            expression.text.size() < sizeof(location->expression) &&
            expression.assignment.size() < sizeof(location->assignment) &&
            expression.callee.size() < sizeof(location->expression_callee)) {
          location->expression_kind = expression.kind;
          location->expression_is_call = expression.is_call;
          location->expression_return_type = expression.return_type;
          std::snprintf(location->expression, sizeof(location->expression),
                        "%s", expression.text.c_str());
          std::snprintf(location->assignment, sizeof(location->assignment),
                        "%s", expression.assignment.c_str());
          std::snprintf(location->expression_callee,
                        sizeof(location->expression_callee), "%s",
                        expression.callee.c_str());
        }
      }
    }
    const uint32_t local_blocks = location->source_block_count;
    bool complete_callers = true;
    for (uint32_t caller_index = 0;
         caller_index < location->inline_call_count && complete_callers;
         ++caller_index) {
      const auto &call = location->inline_calls[caller_index];
      if (call.depth + 1 >= scopes.size())
        continue;
      const auto caller = scopes[scopes.size() - call.depth - 1];
      const char *name =
          caller.getSubroutineName(llvm::DINameKind::LinkageName);
      if (!name)
        continue;
      const auto found = std::find_if(
          table.files.begin(), table.files.end(),
          [&](const auto &file) { return file.second.id == call.source_id; });
      if (found == table.files.end())
        continue;
      auto &parent = found->second;
      if (!parent.content || rejected_prefixes.count(parent.prefix) ||
          !call.line || call.line > parent.content->lines.size())
        continue;
      auto &parent_display =
          parent.display_for(analysis->path.c_str(), source_syntax,
                             analysis->source_mappings, table.compile_context);
      const auto parent_line = parent_display.lines.find(call.line);
      if (parent_line == parent_display.lines.end())
        continue;
      for (const auto &candidate : parent_line->second.blocks) {
        if (candidate.function != name)
          continue;
        if (!candidate.complete || location->source_block_count ==
                                       std::size(location->source_blocks)) {
          complete_callers = false;
          break;
        }
        auto &block = location->source_blocks[location->source_block_count++];
        block = candidate.block;
        block.inline_caller = caller_index + 1;
      }
    }
    // Borrow only complete caller chains; a partial chain could invent the
    // nesting of a condition or detach a case from its containing switch.
    if (!complete_callers)
      location->source_block_count = local_blocks;
    return;
  }
}

static std::string location_cache_key(ct_analysis *analysis,
                                      uint64_t module_offset, bool arming,
                                      bool &cacheable) {
  cacheable = !analysis->cache_key.empty();
  // Arming depends on the ELF/debug catalogs and source maps, not source
  // bodies.
  if (arming)
    return ct_cache_key({"arming-location", analysis->cache_key,
                         std::to_string(module_offset)});
  std::string source_identity;
  for (auto &table : analysis->tables) {
    const auto index = table.table.lookupAddress(
        {module_offset + analysis->link_base,
         llvm::object::SectionedAddress::UndefSection});
    if (index >= table.table.Rows.size())
      continue;
    const auto &row = table.table.Rows[index];
    auto found = table.files.find(row.File);
    if (row.EndSequence || found == table.files.end())
      continue;
    auto &source = found->second;
    if (source.content && !rejected_prefixes.count(source.prefix) &&
        row.Line <= source.content->lines.size()) {
      source_identity =
          source
              .display_for(analysis->path.c_str(), source_syntax,
                           analysis->source_mappings, table.compile_context)
              .identity;
      cacheable &= !source_identity.empty();
    }
    if (analysis->dwarf) {
      const uint64_t address = module_offset + analysis->link_base;
      const auto dies = analysis->dwarf->getDIEsForAddress(address);
      llvm::SmallVector<llvm::DWARFDie> scopes;
      if (dies.FunctionDIE)
        dies.FunctionDIE.getDwarfUnit()->getInlinedChainForAddress(address,
                                                                   scopes);
      std::set<uint64_t> seen{row.File};
      for (const auto &scope : scopes) {
        const auto file =
            llvm::dwarf::toUnsigned(scope.find(llvm::dwarf::DW_AT_call_file));
        if (!file || !seen.insert(*file).second)
          continue;
        const auto parent = table.files.find(*file);
        if (parent == table.files.end() || !parent->second.content ||
            rejected_prefixes.count(parent->second.prefix))
          continue;
        const auto &identity =
            parent->second
                .display_for(analysis->path.c_str(), source_syntax,
                             analysis->source_mappings, table.compile_context)
                .identity;
        cacheable &= !identity.empty();
        source_identity += ":" + std::to_string(*file) + ":" + identity;
      }
    }
    break;
  }
  std::vector<unsigned char> policy;
  ct_analysis_archive policy_writer{policy, false};
  policy_writer.field(rejected_prefixes);
  return ct_cache_key(
      {"location", analysis->cache_key, std::to_string(module_offset),
       std::to_string(source_syntax), source_identity,
       std::string_view(reinterpret_cast<const char *>(policy.data()),
                        policy.size())});
}

void ct_analysis_lookup_arming(ct_analysis *analysis, uint64_t module_offset,
                               ct_location *location) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis) {
    *location = {};
    return;
  }
  bool cacheable;
  const std::string key =
      location_cache_key(analysis, module_offset, true, cacheable);
  std::vector<unsigned char> bytes;
  auto arming = std::make_unique<ct_arming_location>();
  bool hit = false;
  if (cacheable && ct_cache_read("arming-locations", key, bytes))
    hit = ct_analysis_record_unpack(arming.get(), sizeof(*arming), bytes.data(),
                                    bytes.size());
  if (hit) {
    ct_arming_location_unpack(location, arming.get());
  } else {
    lookup_location(analysis, module_offset, location, false);
    ct_arming_location_pack(arming.get(), location);
    if (cacheable) {
      bytes.resize(ct_analysis_record_capacity(sizeof(*arming)));
      bytes.resize(
          ct_analysis_record_pack(bytes.data(), arming.get(), sizeof(*arming)));
      ct_cache_write("arming-locations", key, bytes);
    }
  }
}

void ct_analysis_lookup(ct_analysis *analysis, uint64_t module_offset,
                        ct_location *location) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis) {
    *location = {};
    return;
  }
  bool cacheable;
  const std::string key =
      location_cache_key(analysis, module_offset, false, cacheable);
  std::vector<unsigned char> bytes;
  bool hit = false;
  if (cacheable && ct_cache_read("locations", key, bytes))
    hit = ct_analysis_record_unpack(location, sizeof(*location), bytes.data(),
                                    bytes.size());
  if (!hit) {
    lookup_location(analysis, module_offset, location, true);
    if (cacheable) {
      bytes.resize(ct_analysis_record_capacity(sizeof(*location)));
      bytes.resize(
          ct_analysis_record_pack(bytes.data(), location, sizeof(*location)));
      ct_cache_write("locations", key, bytes);
    }
  }
}

bool ct_analysis_lookup_batch(ct_analysis *analysis, const uint64_t *offsets,
                              size_t count, bool arming, unsigned char **data,
                              size_t *size) {
  if (!data || !size)
    return false;
  *data = nullptr;
  *size = 0;
  if (!analysis || !offsets || !count || count > CT_LOCATION_BATCH_COUNT_LIMIT)
    return false;
  for (size_t index = 1; index < count; ++index)
    if (offsets[index] <= offsets[index - 1])
      return false;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  bool cacheable = true;
  std::string members;
  for (size_t index = 0; index < count; ++index) {
    bool member_cacheable;
    members +=
        location_cache_key(analysis, offsets[index], arming, member_cacheable);
    cacheable &= member_cacheable;
  }
  const std::string key = ct_cache_key(
      {arming ? "arming-location-batch" : "location-batch", members});
  const char *kind = arming ? "arming-locations" : "locations";
  std::vector<unsigned char> bytes;
  if (!cacheable || !ct_cache_read(kind, key, bytes) ||
      !ct_location_batch_valid(bytes.data(), bytes.size(), offsets, count,
                               arming, key.c_str())) {
    ct_location_batch_header header{};
    std::memcpy(header.contract, ct_contract_digest, sizeof(header.contract));
    header.arming = arming;
    header.requested = count;
    std::memcpy(header.key, key.c_str(), sizeof(header.key));
    bytes.assign(sizeof(header), 0);
    auto location = std::make_unique<ct_location>();
    auto compact = std::make_unique<ct_arming_location>();
    const size_t decoded_size = arming ? sizeof(*compact) : sizeof(*location);
    std::vector<unsigned char> packed(
        ct_analysis_record_capacity(decoded_size));
    for (size_t index = 0; index < count; ++index) {
      lookup_location(analysis, offsets[index], location.get(), !arming);
      if (arming)
        ct_arming_location_pack(compact.get(), location.get());
      const size_t packed_size =
          ct_analysis_record_pack(packed.data(),
                                  arming ? static_cast<void *>(compact.get())
                                         : static_cast<void *>(location.get()),
                                  decoded_size);
      if (sizeof(ct_location_batch_record) + packed_size >
          CT_LOCATION_BATCH_BYTE_LIMIT - bytes.size())
        break;
      const ct_location_batch_record record{offsets[index],
                                            uint32_t(packed_size), 0};
      const auto *entry = reinterpret_cast<const unsigned char *>(&record);
      bytes.insert(bytes.end(), entry, entry + sizeof(record));
      bytes.insert(bytes.end(), packed.begin(), packed.begin() + packed_size);
      ++header.count;
    }
    if (!header.count)
      return false;
    std::memcpy(bytes.data(), &header, sizeof(header));
    if (!ct_location_batch_valid(bytes.data(), bytes.size(), offsets, count,
                                 arming, key.c_str()))
      return false;
    if (cacheable)
      ct_cache_write(kind, key, bytes);
  }
  auto *result = static_cast<unsigned char *>(std::malloc(bytes.size()));
  if (!result)
    return false;
  std::memcpy(result, bytes.data(), bytes.size());
  *data = result;
  *size = bytes.size();
  return true;
}

bool ct_analysis_has_dwarf(ct_analysis *analysis) {
  return analysis && analysis->has_dwarf;
}

const char *ct_analysis_debug_file(ct_analysis *analysis) {
  return analysis ? analysis->debug_file.c_str() : "";
}

const char *ct_analysis_soname(ct_analysis *analysis) {
  return analysis ? analysis->soname.c_str() : "";
}

const char *ct_analysis_identity(ct_analysis *analysis) {
  return analysis ? analysis->identity.c_str() : "";
}

bool ct_analysis_source_allowed(ct_analysis *analysis, uint64_t source_id) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis)
    return false;
  for (const auto &table : analysis->tables)
    for (const auto &[index, source] : table.files)
      if (source.id == source_id && source.content &&
          !rejected_prefixes.count(source.prefix))
        return true;
  return false;
}

const char *ct_analysis_source_error(ct_analysis *analysis) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis)
    return "module analysis is unavailable";
  for (const auto &table : analysis->tables)
    for (const auto &[index, source] : table.files) {
      auto rejected = rejected_prefixes.find(source.prefix);
      if (rejected != rejected_prefixes.end()) {
        analysis->source_error = rejected->second;
        return analysis->source_error.c_str();
      }
    }
  for (const auto &table : analysis->tables)
    for (const auto &[index, source] : table.files) {
      auto bypassed = bypassed_prefixes.find(source.prefix);
      if (bypassed != bypassed_prefixes.end()) {
        analysis->source_error = bypassed->second;
        return analysis->source_error.c_str();
      }
    }
  return analysis->source_error.empty() ? nullptr
                                        : analysis->source_error.c_str();
}

void ct_analysis_close(ct_analysis *analysis) {
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (analysis)
    ct_decompile_close(analysis->decompiler);
  delete analysis;
  for (auto entry = source_texts.begin(); entry != source_texts.end();)
    if (entry->second.expired())
      entry = source_texts.erase(entry);
    else
      ++entry;
}

bool ct_analysis_decompile(ct_analysis *analysis, uint64_t module_offset,
                           uint32_t level, ct_decompiled_statement *statement) {
  if (!statement)
    return false;
  *statement = {};
  if (!analysis || !analysis->binary.getBinary() ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis->decompiler)
    analysis->decompiler =
        ct_decompile_open(analysis->path.c_str(), analysis->link_base,
                          analysis->cache_key.c_str(), analysis->module_file);
  return ct_decompile_lookup(analysis->decompiler, module_offset, level,
                             statement);
}

bool ct_analysis_decompile_variables(ct_analysis *analysis,
                                     uint64_t module_offset, uint32_t level,
                                     ct_decompiled_variables *variables) {
  if (!variables)
    return false;
  *variables = {};
  if (!analysis || !analysis->binary.getBinary() ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis->decompiler)
    analysis->decompiler =
        ct_decompile_open(analysis->path.c_str(), analysis->link_base,
                          analysis->cache_key.c_str(), analysis->module_file);
  return ct_decompile_variables(analysis->decompiler, module_offset, level,
                                variables);
}

bool ct_analysis_decompile_proof(ct_analysis *analysis, uint64_t module_offset,
                                 uint32_t level, unsigned char **data,
                                 size_t *size) {
  if (!data || !size)
    return false;
  *data = nullptr;
  *size = 0;
  if (!analysis || !analysis->binary.getBinary() ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis->decompiler)
    analysis->decompiler =
        ct_decompile_open(analysis->path.c_str(), analysis->link_base,
                          analysis->cache_key.c_str(), analysis->module_file);
  std::vector<unsigned char> proof;
  if (!ct_decompile_proof(analysis->decompiler, module_offset, level, proof))
    return false;
  *data = static_cast<unsigned char *>(std::malloc(proof.size()));
  if (!*data)
    return false;
  std::memcpy(*data, proof.data(), proof.size());
  *size = proof.size();
  return true;
}

bool ct_analysis_decompile_display(ct_analysis *analysis,
                                   uint64_t module_offset, uint32_t level,
                                   ct_decompiled_display *display) {
  if (!display)
    return false;
  *display = {};
  if (!analysis || !analysis->binary.getBinary() ||
      (level != CT_DECOMPILE_PERFETTO && level != CT_DECOMPILE_FULL))
    return false;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis->decompiler)
    analysis->decompiler =
        ct_decompile_open(analysis->path.c_str(), analysis->link_base,
                          analysis->cache_key.c_str(), analysis->module_file);
  return ct_decompile_display(analysis->decompiler, module_offset, level,
                              display);
}

const char *ct_analysis_decompile_error(ct_analysis *analysis) {
  return analysis ? ct_decompile_error(analysis->decompiler) : "";
}

void ct_analysis_functions(ct_analysis *analysis,
                           void (*callback)(uint64_t, const char *, void *),
                           void *context) {
  if (!analysis || !callback)
    return;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis->functions_loaded) {
    std::vector<unsigned char> bytes;
    bool hit = false;
    if (ct_cache_read("functions", analysis->cache_key, bytes)) {
      ct_analysis_archive reader{bytes, true};
      reader.field(analysis->functions);
      hit = reader.complete();
    }
    if (!hit) {
      auto &functions = analysis->functions;
      functions.clear();
      for (const auto &symbol : analysis->symbols)
        if (symbol.address >= analysis->link_base)
          functions.try_emplace(symbol.address, symbol.name);
      if (analysis->dwarf)
        for (const auto &unit : analysis->dwarf->normal_units()) {
          for (const auto &entry : unit->dies()) {
            llvm::DWARFDie die(unit.get(), &entry);
            if (die.getTag() != llvm::dwarf::DW_TAG_subprogram)
              continue;
            auto declaration = die.find(llvm::dwarf::DW_AT_declaration);
            if (declaration && declaration->getAsUnsignedConstant().value_or(0))
              continue;
            auto pc = die.find(llvm::dwarf::DW_AT_entry_pc);
            auto address = pc ? pc->getAsAddress() : std::nullopt;
            if (!address) {
              pc = die.find(llvm::dwarf::DW_AT_low_pc);
              address = pc ? pc->getAsAddress() : std::nullopt;
            }
            if (!address || *address < analysis->link_base ||
                functions.count(*address))
              continue;
            const char *name =
                die.getSubroutineName(llvm::DINameKind::LinkageName);
            if (name && *name)
              functions.emplace(*address, function_name(name));
          }
        }
      bytes.clear();
      ct_analysis_archive writer{bytes, false};
      writer.field(functions);
      ct_cache_write("functions", analysis->cache_key, bytes);
    }
    analysis->functions_loaded = true;
  }
  for (const auto &[address, name] : analysis->functions)
    callback(address - analysis->link_base, name.c_str(), context);
}

void ct_analysis_inline_scopes(ct_analysis *analysis,
                               void (*callback)(uint64_t, uint64_t,
                                                const char *, void *),
                               void *context) {
  if (!analysis || !analysis->dwarf || !callback)
    return;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (!analysis->inline_scopes_loaded) {
    std::vector<unsigned char> bytes;
    const std::string key =
        ct_cache_key({"inline-scopes", analysis->cache_key});
    bool hit = false;
    if (ct_cache_read("inline-scopes", key, bytes)) {
      ct_analysis_archive reader{bytes, true};
      reader.fields(analysis->inline_scopes_complete, analysis->inline_scopes);
      hit = reader.complete();
    }
    if (!hit) {
      analysis->inline_scopes.clear();
      analysis->inline_scopes_complete = true;
      for (const auto &unit : analysis->dwarf->normal_units()) {
        for (const auto &entry : unit->dies()) {
          llvm::DWARFDie die(unit.get(), &entry);
          if (die.getTag() != llvm::dwarf::DW_TAG_inlined_subroutine)
            continue;
          const char *name =
              die.getSubroutineName(llvm::DINameKind::LinkageName);
          if (!name || !*name)
            continue;
          auto ranges = die.getAddressRanges();
          if (!ranges) {
            analysis->inline_scopes_complete = false;
            llvm::consumeError(ranges.takeError());
            continue;
          }
          for (const auto &range : *ranges)
            if (range.LowPC >= analysis->link_base &&
                range.LowPC < range.HighPC)
              analysis->inline_scopes.push_back(
                  {{range.LowPC - analysis->link_base,
                    range.HighPC - analysis->link_base},
                   name});
        }
      }
      bytes.clear();
      ct_analysis_archive writer{bytes, false};
      writer.fields(analysis->inline_scopes_complete, analysis->inline_scopes);
      ct_cache_write("inline-scopes", key, bytes);
    }
    analysis->inline_scopes_loaded = true;
  }
  for (const auto &[range, name] : analysis->inline_scopes)
    callback(range.first, range.second, name.c_str(), context);
}

bool ct_analysis_observation_boundaries(ct_analysis *analysis,
                                        void (*callback)(uint64_t, void *),
                                        void *context) {
  if (!analysis || !callback)
    return false;
  std::set<uint64_t> boundaries;
  ct_analysis_inline_scopes(
      analysis,
      [](uint64_t begin, uint64_t end, const char *, void *context) {
        auto &offsets = *static_cast<std::set<uint64_t> *>(context);
        offsets.insert(begin);
        offsets.insert(end);
      },
      &boundaries);
  {
    std::lock_guard<std::mutex> lock(analysis_mutex);
    if (!analysis->inline_scopes_complete)
      return false;
    for (const auto &table : analysis->tables) {
      bool previous_readable = false;
      for (const auto &row : table.table.Rows) {
        const auto file = table.files.find(row.File);
        const bool readable = !row.EndSequence && row.Line &&
                              file != table.files.end() &&
                              file->second.content &&
                              !rejected_prefixes.count(file->second.prefix) &&
                              row.Line <= file->second.content->lines.size();
        // Include the first unreadable/end-sequence row too: it ends the
        // preceding source scope, even though no source text exists there.
        if ((readable || previous_readable) &&
            row.Address.Address >= analysis->link_base)
          boundaries.insert(row.Address.Address - analysis->link_base);
        previous_readable = readable;
      }
    }
  }
  for (const uint64_t offset : boundaries)
    callback(offset, context);
  return true;
}

bool ct_analysis_flow(ct_analysis *analysis, uint64_t module_offset,
                      ct_flow_range *range,
                      void (*callback)(uint64_t, uint32_t, uint64_t, void *),
                      void (*region_callback)(const ct_flow_region *, void *),
                      void (*switch_callback)(const ct_flow_switch *, void *),
                      void *context) {
  if (range)
    *range = {};
  if (!analysis || !range || module_offset > UINT64_MAX - analysis->link_base)
    return false;
  ct_flow_analysis flow_analysis;
  {
    std::lock_guard<std::mutex> lock(analysis_mutex);
    const auto *object = llvm::dyn_cast_or_null<llvm::object::ObjectFile>(
        analysis->binary.getBinary());
    if (!object || object->getArch() != llvm::Triple::x86_64)
      return false;
    const uint64_t pc = module_offset + analysis->link_base;
    llvm::StringRef bytes;
    uint64_t section_begin = 0, section_end = 0;
    for (const auto &section : object->sections()) {
      const uint64_t begin = section.getAddress(), size = section.getSize();
      if (!section.isText() || pc < begin || pc - begin >= size ||
          size > UINT64_MAX - begin)
        continue;
      auto contents = section.getContents();
      if (!contents) {
        llvm::consumeError(contents.takeError());
        return false;
      }
      if (contents->size() < size)
        return false;
      bytes = *contents;
      section_begin = begin;
      section_end = begin + size;
      break;
    }
    if (bytes.empty())
      return false;
    uint64_t begin = pc, end = section_end;
    bool bounded = false;
    auto following =
        std::upper_bound(analysis->symbols.begin(), analysis->symbols.end(), pc,
                         [](uint64_t value, const auto &symbol) {
                           return value < symbol.address;
                         });
    while (following != analysis->symbols.begin()) {
      const auto &symbol = *--following;
      if (symbol.address < section_begin)
        break;
      if (symbol.size && pc - symbol.address < symbol.size &&
          symbol.size <= section_end - symbol.address) {
        begin = symbol.address;
        end = symbol.address + symbol.size;
        bounded = true;
        break;
      }
    }
    if (!bounded && analysis->dwarf) {
      const auto dies = analysis->dwarf->getDIEsForAddress(pc);
      if (dies.FunctionDIE) {
        auto ranges = dies.FunctionDIE.getAddressRanges();
        if (!ranges)
          llvm::consumeError(ranges.takeError());
        else if (ranges->size() == 1) {
          const auto &function = ranges->front();
          if (function.LowPC >= section_begin &&
              function.HighPC <= section_end && pc >= function.LowPC &&
              pc < function.HighPC) {
            begin = function.LowPC;
            end = function.HighPC;
            bounded = true;
          }
        }
      }
    }
    if (!bounded && !analysis->flow_frames_loaded) {
      analysis->flow_frames_loaded = true;
      std::vector<unsigned char> frame_bytes;
      bool frame_hit = false;
      if (ct_cache_read("unwind", analysis->cache_key, frame_bytes)) {
        ct_analysis_archive reader{frame_bytes, true};
        reader.field(analysis->flow_frames);
        frame_hit = reader.complete();
      }
      if (!frame_hit) {
        analysis->flow_frames.clear();
        // Separate debug files may omit .eh_frame; read unwind bounds from the
        // executable itself even when source/DWARF debug information is absent.
        auto ignore = [](llvm::Error error) {
          llvm::consumeError(std::move(error));
        };
        auto unwind = llvm::DWARFContext::create(
            *object, llvm::DWARFContext::ProcessDebugRelocations::Process,
            nullptr, "", ignore, ignore);
        auto frame = unwind->getEHFrame();
        if (!frame)
          llvm::consumeError(frame.takeError());
        else if (*frame)
          for (const auto &entry : (*frame)->entries()) {
            const auto *fde = llvm::dyn_cast<llvm::dwarf::FDE>(&entry);
            if (!fde)
              continue;
            const uint64_t start = fde->getInitialLocation();
            const uint64_t size = fde->getAddressRange();
            if (size && size <= UINT64_MAX - start)
              analysis->flow_frames.emplace_back(start, start + size);
          }
        std::sort(analysis->flow_frames.begin(), analysis->flow_frames.end());
        frame_bytes.clear();
        ct_analysis_archive writer{frame_bytes, false};
        writer.field(analysis->flow_frames);
        ct_cache_write("unwind", analysis->cache_key, frame_bytes);
      }
    }
    if (!bounded)
      for (const auto &function : analysis->flow_frames)
        if (pc >= function.first && pc < function.second &&
            function.first >= section_begin && function.second <= section_end) {
          begin = function.first;
          end = function.second;
          bounded = true;
          break;
        }
    const auto key = std::make_pair(begin, end);
    auto [cached, inserted] = analysis->flows.try_emplace(key);
    auto &flow = cached->second;
    const std::string disk_key =
        ct_cache_key({"flow", analysis->cache_key, std::to_string(begin),
                      std::to_string(end), bounded ? "bounded" : "unbounded"});
    std::vector<unsigned char> flow_bytes;
    if (inserted && ct_cache_read("flow", disk_key, flow_bytes)) {
      ct_analysis_archive reader{flow_bytes, true};
      reader.fields(flow.range, flow.flow_analysis.roles,
                    flow.flow_analysis.groups, flow.flow_analysis.regions,
                    flow.flow_analysis.switches, flow.flow_analysis.complete,
                    flow.flow_analysis.instructions, flow.flow_analysis.edges);
      const ct_flow_range graph_range{begin, end, flow.range.complete, bounded};
      const auto &instructions = flow.flow_analysis.instructions;
      if (reader.complete() &&
          flow.range.begin_offset == begin - analysis->link_base &&
          flow.range.end_offset == end - analysis->link_base &&
          ((!flow.range.complete && instructions.empty() &&
            flow.flow_analysis.edges.empty()) ||
           (ct_flow_graph_valid(&graph_range, begin, instructions.data(),
                                instructions.size(),
                                flow.flow_analysis.edges.data(),
                                flow.flow_analysis.edges.size()) &&
            std::all_of(instructions.begin(), instructions.end(),
                        [&](const auto &instruction) {
                          return !std::memcmp(
                              instruction.bytes,
                              bytes.data() + instruction.offset - section_begin,
                              instruction.size);
                        }))) &&
          std::all_of(flow.flow_analysis.roles.begin(),
                      flow.flow_analysis.roles.end(), [&](const auto &role) {
                        return flow.flow_analysis.groups.count(role.first);
                      }))
        inserted = false;
      else
        flow = {};
    }
    if (inserted) {
      ct_analysis_progress progress{};
      std::snprintf(progress.stage, sizeof(progress.stage), "instrumentation");
      std::snprintf(progress.module, sizeof(progress.module), "%s",
                    analysis->path.c_str());
      std::snprintf(progress.detail, sizeof(progress.detail), "Instrumenting");
      // The request already holds analysis_mutex. Read the available DWARF
      // location directly; the normal lookup can start source analysis.
      if (analysis->dwarf) {
        const auto dies = analysis->dwarf->getDIEsForAddress(begin);
        if (dies.FunctionDIE)
          if (const char *name = dies.FunctionDIE.getSubroutineName(
                  llvm::DINameKind::LinkageName))
            std::snprintf(progress.function, sizeof(progress.function), "%s",
                          function_name(name).c_str());
      }
      for (const auto &symbol : analysis->symbols) {
        if (symbol.address == begin) {
          std::snprintf(progress.detail, sizeof(progress.detail),
                        "Instrumenting %s", symbol.name.c_str());
          if (!progress.function[0])
            std::snprintf(progress.function, sizeof(progress.function), "%s",
                          symbol.name.c_str());
          break;
        }
      }
      progress_source(*analysis, begin, progress);
      progress.begin_offset = begin - analysis->link_base;
      progress.end_offset = end - analysis->link_base;
      progress.has_range = true;
      ct_analysis_report_progress(&progress);
      const uint64_t size = end - begin;
      const auto *start =
          reinterpret_cast<const unsigned char *>(bytes.data()) +
          (begin - section_begin);
      flow.flow_analysis = ct_analyze_flow(
          {start, size}, begin, begin,
          [object](uint64_t address, size_t count,
                   std::vector<unsigned char> &result) {
            for (const auto &section : object->sections()) {
              const uint64_t base = section.getAddress();
              if (!llvm::isa<llvm::object::ELFObjectFileBase>(object) ||
                  !(llvm::object::ELFSectionRef(section).getFlags() &
                    SHF_ALLOC) ||
                  (llvm::object::ELFSectionRef(section).getFlags() &
                   SHF_WRITE) ||
                  address < base || address - base > section.getSize() ||
                  count > section.getSize() - (address - base))
                continue;
              auto contents = section.getContents();
              if (!contents) {
                llvm::consumeError(contents.takeError());
                return false;
              }
              if (address - base > contents->size() ||
                  count > contents->size() - (address - base))
                return false;
              const auto *data = reinterpret_cast<const unsigned char *>(
                  contents->data() + address - base);
              result.assign(data, data + count);
              return true;
            }
            return false;
          });
      if (analysis->dwarf)
        for (auto &region : flow.flow_analysis.regions) {
          if (!region.has_initializer)
            continue;
          auto *unit =
              analysis->dwarf->getDIEsForAddress(region.initializer_offset)
                  .CompileUnit;
          // Native libdw and this helper must refer to the same CU/file
          // index namespace. Split-unit declarations need separate mapping.
          if (!unit || unit->isDWOUnit() || unit->getDWOId())
            continue;
          const auto *table = analysis->dwarf->getLineTableForUnit(unit);
          if (!table)
            continue;
          const auto row_index = table->lookupAddress(
              {region.initializer_offset,
               llvm::object::SectionedAddress::UndefSection});
          if (row_index >= table->Rows.size())
            continue;
          const auto &row = table->Rows[row_index];
          if (row.EndSequence || !row.Line || !table->hasFileAtIndex(row.File))
            continue;
          const auto cu = unit->getUnitDIE();
          if (!cu)
            continue;
          region.initializer_source = {cu.getOffset(), row.File, row.Line,
                                       true};
        }
      flow.range.begin_offset = begin - analysis->link_base;
      flow.range.end_offset = end - analysis->link_base;
      flow.range.bounded = bounded;
      flow.range.complete = flow.flow_analysis.complete;
      flow_bytes.clear();
      ct_analysis_archive writer{flow_bytes, false};
      writer.fields(flow.range, flow.flow_analysis.roles,
                    flow.flow_analysis.groups, flow.flow_analysis.regions,
                    flow.flow_analysis.switches, flow.flow_analysis.complete,
                    flow.flow_analysis.instructions, flow.flow_analysis.edges);
      ct_cache_write("flow", disk_key, flow_bytes);
    }
    *range = flow.range;
    // Copy only requested display payloads before releasing the mutex. Graph
    // export and bounds-only callers do not duplicate these or the code cover.
    if (callback) {
      flow_analysis.roles = flow.flow_analysis.roles;
      flow_analysis.groups = flow.flow_analysis.groups;
    }
    if (region_callback)
      flow_analysis.regions = flow.flow_analysis.regions;
    if (switch_callback)
      flow_analysis.switches = flow.flow_analysis.switches;
  }
  if (callback)
    for (const auto &[address, role] : flow_analysis.roles)
      if (address >= analysis->link_base)
        callback(address - analysis->link_base, role,
                 flow_analysis.groups.at(address) - analysis->link_base,
                 context);
  if (region_callback)
    for (auto region : flow_analysis.regions) {
      region.branch_offset -= analysis->link_base;
      region.taken_offset -= analysis->link_base;
      region.fallthrough_offset -= analysis->link_base;
      region.join_offset -= analysis->link_base;
      if (region.kind == CT_FLOW_LOOP)
        region.loop_header_offset -= analysis->link_base;
      if (region.has_update)
        region.update_offset -= analysis->link_base;
      if (region.has_initializer)
        region.initializer_offset -= analysis->link_base;
      region_callback(&region, context);
    }
  if (switch_callback)
    for (auto region : flow_analysis.switches) {
      region.guard_offset -= analysis->link_base;
      region.dispatch_offset -= analysis->link_base;
      region.selector_offset -= analysis->link_base;
      region.join_offset -= analysis->link_base;
      region.default_offset -= analysis->link_base;
      for (auto &item : region.cases)
        item.target_offset -= analysis->link_base;
      switch_callback(&region, context);
    }
  return true;
}

bool ct_analysis_code_graph(
    ct_analysis *analysis, uint64_t module_offset, ct_flow_range *range,
    void (*instruction_callback)(const ct_flow_instruction *, void *),
    void (*edge_callback)(const ct_flow_edge *, void *), void *context) {
  if (range)
    *range = {};
  if (!analysis || !range || module_offset > UINT64_MAX - analysis->link_base)
    return false;
  ct_flow_range bounds{};
  if (!ct_analysis_flow(analysis, module_offset, &bounds, nullptr, nullptr,
                        nullptr, nullptr))
    return false;
  std::vector<ct_flow_instruction> instructions;
  std::vector<ct_flow_edge> edges;
  {
    std::lock_guard<std::mutex> lock(analysis_mutex);
    const uint64_t begin = bounds.begin_offset + analysis->link_base;
    const uint64_t end = bounds.end_offset + analysis->link_base;
    const uint64_t entry = module_offset + analysis->link_base;
    const auto original = analysis->flows.find({begin, end});
    if (original == analysis->flows.end())
      return false;
    const auto &initial = original->second.flow_analysis;
    const auto found = std::lower_bound(
        initial.instructions.begin(), initial.instructions.end(), entry,
        [](const auto &instruction, uint64_t pc) {
          return instruction.offset < pc;
        });
    if (found != initial.instructions.begin() &&
        std::prev(found)->offset + std::prev(found)->size > entry)
      return false;
    if (found != initial.instructions.end() && found->offset == entry) {
      instructions = initial.instructions;
      edges = initial.edges;
    } else {
      // An observed alternate entry can be unreachable from the physical
      // entry. Analyze its actual successors without treating the intervening
      // bytes as code.
      const auto key = std::make_tuple(begin, end, entry);
      auto [position, inserted] = analysis->code_graphs.try_emplace(key);
      auto &graph = position->second;
      if (inserted) {
        const auto *object = llvm::dyn_cast_or_null<llvm::object::ObjectFile>(
            analysis->binary.getBinary());
        llvm::StringRef bytes;
        uint64_t section_begin = 0;
        if (object)
          for (const auto &section : object->sections()) {
            const uint64_t address = section.getAddress(),
                           size = section.getSize();
            if (!section.isText() || entry < address || entry - address >= size)
              continue;
            auto contents = section.getContents();
            if (!contents) {
              llvm::consumeError(contents.takeError());
              break;
            }
            if (contents->size() < size || end < entry || end - address > size)
              break;
            bytes = *contents;
            section_begin = address;
            break;
          }
        if (bytes.empty())
          return false;
        const std::string disk_key = ct_cache_key(
            {"flow-graph", analysis->cache_key, std::to_string(begin),
             std::to_string(end), std::to_string(entry)});
        std::vector<unsigned char> cached;
        bool hit = false;
        if (ct_cache_read("flow-graph", disk_key, cached)) {
          ct_analysis_archive reader{cached, true};
          reader.fields(graph.instructions, graph.edges, graph.complete);
          const ct_flow_range graph_range{begin, end, graph.complete,
                                          bounds.bounded};
          hit = reader.complete() &&
                ct_flow_graph_valid(&graph_range, entry,
                                    graph.instructions.data(),
                                    graph.instructions.size(),
                                    graph.edges.data(), graph.edges.size()) &&
                std::all_of(
                    graph.instructions.begin(), graph.instructions.end(),
                    [&](const auto &instruction) {
                      return !std::memcmp(instruction.bytes,
                                          bytes.data() + instruction.offset -
                                              section_begin,
                                          instruction.size);
                    });
        }
        if (!hit) {
          const size_t size = end - begin;
          ct_analysis_progress progress{};
          std::snprintf(progress.stage, sizeof(progress.stage),
                        "instrumentation");
          std::snprintf(progress.module, sizeof(progress.module), "%s",
                        analysis->path.c_str());
          std::snprintf(progress.detail, sizeof(progress.detail),
                        "Instrumenting code graph");
          progress.begin_offset = bounds.begin_offset;
          progress.end_offset = bounds.end_offset;
          progress.has_range = true;
          progress_source(*analysis, entry, progress);
          for (const auto &symbol : analysis->symbols)
            if (symbol.address == begin) {
              std::snprintf(progress.function, sizeof(progress.function), "%s",
                            symbol.name.c_str());
              break;
            }
          ct_analysis_report_progress(&progress);
          const auto *start =
              reinterpret_cast<const unsigned char *>(bytes.data()) +
              (begin - section_begin);
          auto decoded = ct_analyze_flow(
              {start, size}, begin, entry,
              [object](uint64_t address, size_t count,
                       std::vector<unsigned char> &result) {
                for (const auto &section : object->sections()) {
                  const uint64_t base = section.getAddress();
                  if (!llvm::isa<llvm::object::ELFObjectFileBase>(object) ||
                      !(llvm::object::ELFSectionRef(section).getFlags() &
                        SHF_ALLOC) ||
                      (llvm::object::ELFSectionRef(section).getFlags() &
                       SHF_WRITE) ||
                      address < base || address - base > section.getSize() ||
                      count > section.getSize() - (address - base))
                    continue;
                  auto contents = section.getContents();
                  if (!contents) {
                    llvm::consumeError(contents.takeError());
                    return false;
                  }
                  if (address - base > contents->size() ||
                      count > contents->size() - (address - base))
                    return false;
                  const auto *data =
                      reinterpret_cast<const unsigned char *>(contents->data());
                  result.assign(data + address - base,
                                data + address - base + count);
                  return true;
                }
                return false;
              });
          graph.instructions = std::move(decoded.instructions);
          graph.edges = std::move(decoded.edges);
          graph.complete = decoded.complete;
          cached.clear();
          ct_analysis_archive writer{cached, false};
          writer.fields(graph.instructions, graph.edges, graph.complete);
          ct_cache_write("flow-graph", disk_key, cached);
        }
      }
      instructions = graph.instructions;
      edges = graph.edges;
      bounds.complete = graph.complete;
    }
    for (auto &instruction : instructions)
      instruction.offset -= analysis->link_base;
    for (auto &edge : edges) {
      edge.from_offset -= analysis->link_base;
      edge.to_offset =
          edge.to_offset != UINT64_MAX && edge.to_offset >= analysis->link_base
              ? edge.to_offset - analysis->link_base
              : UINT64_MAX;
    }
  }
  if (!ct_flow_graph_valid(&bounds, module_offset, instructions.data(),
                           instructions.size(), edges.data(), edges.size()))
    return false;
  *range = bounds;
  if (instruction_callback)
    for (const auto &instruction : instructions)
      instruction_callback(&instruction, context);
  if (edge_callback)
    for (const auto &edge : edges)
      edge_callback(&edge, context);
  return true;
}

bool ct_analysis_code_proof(ct_analysis *analysis, uint64_t module_offset,
                            unsigned char **data, size_t *size) {
  if (!data || !size)
    return false;
  *data = nullptr;
  *size = 0;
  if (!analysis || module_offset > UINT64_MAX - analysis->link_base)
    return false;
  ct_flow_range bounds{};
  if (!ct_analysis_flow(analysis, module_offset, &bounds, nullptr, nullptr,
                        nullptr, nullptr) ||
      !bounds.bounded || !bounds.complete ||
      bounds.begin_offset >= bounds.end_offset)
    return false;
  std::lock_guard<std::mutex> lock(analysis_mutex);
  if (analysis->dwarf) {
    const auto dies =
        analysis->dwarf->getDIEsForAddress(module_offset + analysis->link_base);
    if (dies.FunctionDIE) {
      auto ranges = dies.FunctionDIE.getAddressRanges();
      if (!ranges) {
        llvm::consumeError(ranges.takeError());
        return false;
      }
      // A hot/cold fragment's symbol or FDE cannot prove the other fragments
      // of the same source function. Reject until the entire footprint fits.
      if (ranges->size() != 1 || ranges->front().LowPC < analysis->link_base ||
          ranges->front().LowPC - analysis->link_base < bounds.begin_offset ||
          ranges->front().HighPC < analysis->link_base ||
          ranges->front().HighPC - analysis->link_base > bounds.end_offset)
        return false;
    }
  }
  const auto range_key = std::make_pair(bounds.begin_offset, bounds.end_offset);
  auto existing = analysis->code_proofs.find(range_key);
  if (existing == analysis->code_proofs.end()) {
    const std::string disk_key =
        ct_cache_key({"original-code-proof", analysis->cache_key,
                      std::to_string(bounds.begin_offset),
                      std::to_string(bounds.end_offset)});
    std::vector<unsigned char> proof;
    bool loaded = ct_cache_read("code-proofs", disk_key, proof) &&
                  ct_decompiled_proof_valid(proof.data(), proof.size());
    if (loaded) {
      ct_decompiled_proof_header header;
      std::memcpy(&header, proof.data(), sizeof(header));
      ct_decompiled_range stored_range;
      std::memcpy(&stored_range, proof.data() + sizeof(header),
                  sizeof(stored_range));
      loaded = header.loaded_level == 0 && header.range_count == 1 &&
               header.function_offset == bounds.begin_offset &&
               stored_range.begin == bounds.begin_offset &&
               stored_range.end == bounds.end_offset;
    }
    if (!loaded) {
      const auto *object = llvm::dyn_cast_or_null<llvm::object::ObjectFile>(
          analysis->binary.getBinary());
      if (!object || bounds.end_offset > UINT64_MAX - analysis->link_base)
        return false;
      llvm::StringRef bytes;
      const uint64_t begin = bounds.begin_offset + analysis->link_base;
      const uint64_t end = bounds.end_offset + analysis->link_base;
      for (const auto &section : object->sections()) {
        const uint64_t base = section.getAddress();
        if (!section.isText() || begin < base || end - base > section.getSize())
          continue;
        auto contents = section.getContents();
        if (!contents) {
          llvm::consumeError(contents.takeError());
          return false;
        }
        if (end - base > contents->size())
          return false;
        bytes = contents->substr(begin - base, end - begin);
        break;
      }
      std::vector<ct_decompiled_instruction> instructions;
      if (bytes.empty() ||
          !ct_decode_code_range(
              {reinterpret_cast<const unsigned char *>(bytes.data()),
               bytes.size()},
              bounds.begin_offset, instructions) ||
          !ct_build_code_proof(bounds.begin_offset, 0,
                               {{bounds.begin_offset, bounds.end_offset}},
                               instructions, proof))
        return false;
      ct_cache_write("code-proofs", disk_key, proof);
    }
    existing = analysis->code_proofs.emplace(range_key, std::move(proof)).first;
  }
  *data = static_cast<unsigned char *>(std::malloc(existing->second.size()));
  if (!*data)
    return false;
  std::memcpy(*data, existing->second.data(), existing->second.size());
  *size = existing->second.size();
  return true;
}
