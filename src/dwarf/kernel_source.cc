// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

#include <clang/Driver/Options.h>
#include <clang/Driver/Types.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugLine.h>
#include <llvm/DebugInfo/DWARF/DWARFDie.h>
#include <llvm/DebugInfo/DWARF/DWARFUnit.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Option/ArgList.h>
#include <llvm/Support/Allocator.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/MD5.h>
#include <llvm/Support/MemoryBufferRef.h>
#include <llvm/Support/StringSaver.h>

#include <elf.h>

#include "analysis_files.hh"
#include "c_cpp_source.hh"
#include "cache.hh"
#include "ctrace_kernel/flow.hh"
#include "dwarf/kernel_source.hh"

struct KernelSourceInput {
  uint32_t file = 0;
  ct_source_compile_context context;
  std::string checksum, content;
  std::vector<std::string> lines;
  std::map<std::string, std::string> signatures;
  std::map<std::string, std::vector<ct_source_variable>> parameters;
  std::map<unsigned, std::string> function_openings;
};

struct KernelSourceRow {
  uint32_t section = 0, input = 0, line = 0, column = 0;
  uint64_t begin = 0, end = 0, prefix_end = 0;
  uint32_t discriminator = 0;
  bool statement = false;
};

struct KernelSourceCandidate {
  uint64_t block = 0;
  uint32_t input = 0;
  std::string function;
  ct_source_block source{};
};

static std::string source_path(const std::string &path,
                               const ct_kernel_source_options &options) {
  const std::string normalized =
      std::filesystem::path(path).lexically_normal().string();
  const std::pair<std::string, std::string> *selected = nullptr;
  for (const auto &mapping : options.maps)
    if (!mapping.first.empty() && normalized.rfind(mapping.first, 0) == 0 &&
        (mapping.first == "/" || normalized.size() == mapping.first.size() ||
         normalized[mapping.first.size()] == '/') &&
        (!selected || mapping.first.size() > selected->first.size()))
      selected = &mapping;
  if (!selected)
    return normalized;
  std::string suffix = normalized.substr(selected->first.size());
  while (!suffix.empty() && suffix.front() == '/')
    suffix.erase(suffix.begin());
  return (std::filesystem::path(selected->second) / suffix)
      .lexically_normal()
      .string();
}

static void source_add_range(std::vector<ct_kernel_source_range> &ranges,
                             uint32_t section, uint64_t begin, uint64_t end) {
  if (begin >= end)
    return;
  ranges.push_back({section, begin, end});
}

static void source_merge_ranges(std::vector<ct_kernel_source_range> &ranges) {
  std::sort(ranges.begin(), ranges.end(), [](const auto &a, const auto &b) {
    return std::tie(a.section, a.begin, a.end) <
           std::tie(b.section, b.begin, b.end);
  });
  size_t used = 0;
  for (const auto &range : ranges) {
    if (used && ranges[used - 1].section == range.section &&
        range.begin <= ranges[used - 1].end)
      ranges[used - 1].end = std::max(ranges[used - 1].end, range.end);
    else
      ranges[used++] = range;
  }
  ranges.resize(used);
}

uint32_t ct_kernel_source_row(const ct_kernel_source_metadata &metadata,
                              uint64_t site_id, std::string *owner) {
  if (owner)
    owner->clear();
  if (site_id >= metadata.sites.size())
    return 0;
  const auto &site = metadata.sites[site_id];
  std::vector<std::pair<std::string, uint32_t>> owners;
  if (site.function && site.function < metadata.functions.size()) {
    const auto &function = metadata.functions[site.function];
    owners.emplace_back(function.name, function.file);
  }
  for (const auto block : site.blocks)
    if (block && block < metadata.blocks.size() &&
        metadata.blocks[block].kind ==
            ct_kernel_source_block_kind::inline_function)
      owners.emplace_back(metadata.blocks[block].header,
                          metadata.blocks[block].file);
  if (owner && !owners.empty())
    *owner = owners.back().first;
  if (!site.line || site.line >= metadata.lines.size())
    return 0;
  const auto &line = metadata.lines[site.line];
  if (!line.presentation || line.text.empty() ||
      line.file >= metadata.files.size() ||
      !metadata.files[line.file].available)
    return 0;
  const auto &presentation = *line.presentation;
  std::string name;
  const bool semantic = !presentation.statement_function.empty() ||
                        !presentation.expression.function.empty() ||
                        !presentation.declaration.function.empty() ||
                        !presentation.variables.empty() ||
                        !presentation.call_results.empty();
  for (auto candidate = owners.rbegin(); candidate != owners.rend();
       ++candidate) {
    const auto &[function, file] = *candidate;
    bool owned =
        !function.empty() && (presentation.statement_function == function ||
                              presentation.expression.function == function ||
                              presentation.declaration.function == function);
    for (const auto &reference : presentation.variables)
      owned |= !function.empty() && reference.function == function;
    for (const auto &call : presentation.call_results)
      owned |= !function.empty() && call.function == function;
    // Exact DWARF rows remain valid source locations when an isolated header
    // cannot be parsed or its function body was generated by a macro. This
    // authorizes display only: no AST expression or value is invented.
    owned |= !semantic && file == line.file;
    if (owned) {
      name = function;
      break;
    }
  }
  if (owner)
    *owner = name;
  // Distinct same-line lexical declarations cannot be resolved by spelling.
  const bool mixed_scope_declarations =
      presentation.expression.kind == CT_EXPRESSION_NONE &&
      line.text.find('{') != std::string::npos &&
      line.text.find('}') != std::string::npos &&
      std::any_of(presentation.variables.begin(), presentation.variables.end(),
                  [&](const auto &variable) {
                    return variable.function == name && variable.declaration;
                  });
  return !name.empty() && !mixed_scope_declarations ? site.line : 0;
}

bool ct_kernel_collect_line_locations(
    const ct_kernel_image &image, const std::vector<ct_kernel_site> &sites,
    std::vector<ct_kernel_line_location> &locations, std::string &error) {
  locations.clear();
  error.clear();
  const llvm::MemoryBufferRef bytes(
      {reinterpret_cast<const char *>(image.bytes.data()), image.bytes.size()},
      image.path);
  auto object = llvm::object::ObjectFile::createObjectFile(bytes);
  if (!object) {
    error = llvm::toString(object.takeError());
    return false;
  }
  auto dwarf = llvm::DWARFContext::create(**object);
  const llvm::DILineInfoSpecifier specification(
      llvm::DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
      llvm::DILineInfoSpecifier::FunctionNameKind::LinkageName);
  std::vector<ct_kernel_line_location> result;
  for (const auto &site : sites) {
    if (!site.probe)
      continue;
    if (!site.id ||
        site.id >= std::vector<ct_kernel_source_site>{}.max_size() ||
        site.section >= image.sections.size()) {
      error = "invalid kernel site identity";
      return false;
    }
    const auto location = dwarf->getLineInfoForAddress(
        {site.offset, site.section}, specification);
    if (location && location->FileName != llvm::DILineInfo::BadString)
      result.push_back({site.id, location->FileName, location->Line});
  }
  locations = std::move(result);
  return true;
}

bool ct_kernel_collect_source(const ct_kernel_image &image,
                              const std::vector<ct_kernel_site> &sites,
                              const ct_kernel_source_options &options,
                              ct_kernel_source_metadata &metadata,
                              std::string &error) {
  metadata = {};
  error.clear();
  uint64_t largest_id = 0;
  for (const auto &site : sites)
    if (site.probe)
      largest_id = std::max(largest_id, site.id);
  if (largest_id >= metadata.sites.max_size()) {
    error = "kernel source site inventory exceeds its bound";
    return false;
  }
  metadata.sites.resize(largest_id + 1);
  const llvm::MemoryBufferRef memory(
      {reinterpret_cast<const char *>(image.bytes.data()), image.bytes.size()},
      image.path);
  auto object = llvm::object::ObjectFile::createObjectFile(memory);
  if (!object) {
    error = llvm::toString(object.takeError());
    return false;
  }
  const auto diagnostic = [&](llvm::Error issue) {
    auto message = llvm::toString(std::move(issue));
    if (error.empty())
      error = "kernel source DWARF: " + message;
  };
  auto dwarf = llvm::DWARFContext::create(
      **object, llvm::DWARFContext::ProcessDebugRelocations::Process, nullptr,
      "", diagnostic, diagnostic);
  struct Unit {
    llvm::DWARFUnit *unit = nullptr;
    std::map<uint64_t, uint32_t> files;
    ct_source_compile_context context;
  };
  std::vector<Unit> units;
  std::vector<KernelSourceInput> inputs(1);
  std::map<std::string, uint32_t> input_keys;
  std::map<uint32_t, std::vector<KernelSourceRow>> rows;
  for (const auto &unit : dwarf->normal_units()) {
    const auto die = unit->getUnitDIE();
    const auto *table = dwarf->getLineTableForUnit(unit.get());
    Unit current;
    current.unit = unit.get();
    if (const char *directory = unit->getCompilationDir())
      current.context.directory = source_path(directory, options);
    if (const auto language = die.find(llvm::dwarf::DW_AT_language))
      current.context.language = language->getAsUnsignedConstant().value_or(0);
    for (auto [attribute, target] :
         {std::pair{llvm::dwarf::DW_AT_producer, &current.context.producer},
          std::pair{llvm::dwarf::DW_AT_name, &current.context.source}}) {
      if (const auto value = die.find(attribute)) {
        auto text = value->getAsCString();
        if (text)
          *target = *text;
        else
          llvm::consumeError(text.takeError());
      }
    }
    if (!current.context.source.empty()) {
      auto source = std::filesystem::path(current.context.source);
      if (source.is_relative() && !current.context.directory.empty())
        source = std::filesystem::path(current.context.directory) / source;
      current.context.source = source_path(source.string(), options);
    }
    current.context.arguments = options.arguments;
    if (!options.arguments.empty()) {
      // Binding compilation supplies the kernel's includes and definitions,
      // but an individual CU may deliberately enable FPU instructions. GCC
      // records those overrides in its producer string. Preserve their order
      // after Kbuild defaults; a real compilation database still takes
      // priority.
      if (current.context.producer.starts_with("GNU ")) {
        llvm::BumpPtrAllocator allocator;
        llvm::StringSaver saver(allocator);
        llvm::SmallVector<const char *, 32> tokens;
        llvm::cl::TokenizeGNUCommandLine(current.context.producer, saver,
                                         tokens);
        const auto first =
            std::find_if(tokens.begin(), tokens.end(),
                         [](const char *token) { return token[0] == '-'; });
        llvm::ArrayRef<const char *> arguments(first, tokens.end());
        unsigned missing_index = 0, missing_count = 0;
        auto parsed = clang::driver::getDriverOptTable().ParseArgs(
            arguments, missing_index, missing_count);
        using namespace clang::driver::options;
        if (!missing_count && !parsed.hasArg(OPT_INPUT)) {
          for (const auto *argument : parsed) {
            const auto &option = argument->getOption();
            if (option.matches(OPT_mhard_float) ||
                option.matches(OPT_msoft_float)) {
              // Clang rejects GCC's float-mode spelling on x86-64.
              current.context.arguments.push_back(
                  option.matches(OPT_mhard_float) ? "-m80387" : "-mno-80387");
            } else if (option.matches(OPT_m_x86_Features_Group) ||
                       option.matches(OPT_m_x86_AVX10_Features_Group) ||
                       option.matches(OPT_march_EQ)) {
              llvm::opt::ArgStringList rendered;
              argument->render(parsed, rendered);
              for (const char *text : rendered)
                current.context.arguments.emplace_back(text);
            }
          }
        }
      }
      current.context.arguments.push_back("-DKBUILD_MODNAME=\"" + image.name +
                                          "\"");
      current.context.arguments.push_back(
          "-DKBUILD_BASENAME=\"" +
          std::filesystem::path(current.context.source).stem().string() + "\"");
      // Kbuild's generated include paths are relative to its configured output.
      if (!options.kernel_build.empty())
        current.context.directory = options.kernel_build;
    }
    if (table) {
      const auto &prologue = table->Prologue;
      if (const auto last = prologue.getLastValidFileIndex()) {
        for (uint64_t index = prologue.getVersion() >= 5 ? 0 : 1;
             index <= *last; ++index) {
          std::string path;
          if (!prologue.getFileNameByIndex(
                  index, unit->getCompilationDir(),
                  llvm::DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
                  path))
            continue;
          path = source_path(path, options);
          std::string checksum;
          if (prologue.ContentTypes.HasMD5) {
            for (unsigned char byte :
                 prologue.getFileNameEntry(index).Checksum) {
              checksum += "0123456789abcdef"[byte >> 4];
              checksum += "0123456789abcdef"[byte & 15];
            }
          }
          const std::string key =
              ct_cache_key({path, checksum, current.context.producer,
                            current.context.directory, current.context.source,
                            std::to_string(current.context.language)});
          auto [entry, inserted] = input_keys.emplace(key, inputs.size());
          if (inserted) {
            if (inputs.size() >= UINT32_MAX) {
              error = "kernel DWARF source file inventory exceeds its bound";
              return false;
            }
            KernelSourceInput input;
            input.file = metadata.files.size();
            input.context = current.context;
            input.checksum = std::move(checksum);
            inputs.push_back(std::move(input));
            ct_kernel_source_file file;
            file.path = std::move(path);
            const auto extension =
                std::filesystem::path(file.path).extension().string();
            const auto type = clang::driver::types::lookupTypeForExtension(
                llvm::StringRef(extension).drop_front(extension.empty() ? 0
                                                                        : 1));
            file.assembly =
                type == clang::driver::types::TY_Asm ||
                type == clang::driver::types::TY_PP_Asm ||
                current.context.language == llvm::dwarf::DW_LANG_Mips_Assembler;
            metadata.files.push_back(std::move(file));
          }
          current.files[index] = entry->second;
        }
      }
      for (size_t index = 0; index + 1 < table->Rows.size(); ++index) {
        const auto &row = table->Rows[index], &next = table->Rows[index + 1];
        const auto file = current.files.find(row.File);
        if (row.EndSequence || !row.Line || file == current.files.end() ||
            row.Address.SectionIndex ==
                llvm::object::SectionedAddress::UndefSection ||
            row.Address.SectionIndex != next.Address.SectionIndex ||
            row.Address.SectionIndex >= image.sections.size() ||
            row.Address.Address >= next.Address.Address)
          continue;
        const auto &section = image.sections[row.Address.SectionIndex];
        if (!(section.flags & SHF_EXECINSTR) ||
            next.Address.Address > section.size)
          continue;
        rows[row.Address.SectionIndex].push_back(
            {uint32_t(row.Address.SectionIndex), file->second, row.Line,
             row.Column, row.Address.Address, next.Address.Address, 0,
             row.Discriminator, row.IsStmt});
      }
    }
    units.push_back(std::move(current));
  }
  if (!error.empty()) {
    metadata = {};
    return false;
  }
  for (auto &[section, entries] : rows) {
    std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
      return std::tie(a.begin, a.end, a.input, a.line, a.column) <
             std::tie(b.begin, b.end, b.input, b.line, b.column);
    });
    uint64_t end = 0;
    for (auto &row : entries)
      row.prefix_end = end = std::max(end, row.end);
  }
  std::set<uint32_t> needed;
  std::vector<uint32_t> site_inputs(largest_id + 1), site_lines(largest_id + 1);
  std::map<std::pair<uint32_t, uint32_t>, uint32_t> line_ids;
  std::map<uint32_t, uint32_t> canonical_rows;
  const auto source_row = [&](uint32_t input, uint32_t number) {
    const auto key = std::make_pair(input, number);
    if (const auto found = line_ids.find(key); found != line_ids.end())
      return found->second;
    if (metadata.lines.size() > UINT32_MAX) {
      error = "kernel source row index is not representable";
      return uint32_t(0);
    }
    const uint32_t id = metadata.lines.size();
    line_ids.emplace(key, id);
    metadata.lines.push_back({inputs[input].file, number, {}, {}});
    return id;
  };
  for (const auto &site : sites) {
    if (!site.probe)
      continue;
    if (!site.id || site.section >= image.sections.size()) {
      error = "invalid source site identity";
      return false;
    }
    const auto found = rows.find(site.section);
    if (found == rows.end())
      continue;
    const auto &entries = found->second;
    auto position = std::upper_bound(
        entries.begin(), entries.end(), site.offset,
        [](uint64_t offset, const auto &row) { return offset < row.begin; });
    const KernelSourceRow *selected = nullptr;
    while (position != entries.begin()) {
      --position;
      if (position->prefix_end <= site.offset)
        break;
      if (position->begin > site.offset || position->end <= site.offset)
        continue;
      if (selected &&
          std::tie(selected->input, selected->line, selected->column) !=
              std::tie(position->input, position->line, position->column)) {
        selected = nullptr;
        break;
      }
      selected = &*position;
    }
    if (!selected)
      continue;
    needed.insert(selected->input);
    site_inputs[site.id] = selected->input;
    site_lines[site.id] = selected->line;
    const uint32_t line = source_row(selected->input, selected->line);
    if (!line)
      return false;
    metadata.sites[site.id].line = line;
    metadata.sites[site.id].column = selected->column;
    metadata.sites[site.id].discriminator = selected->discriminator;
    metadata.sites[site.id].statement = selected->statement;
  }
  // An inline invocation can have no line-table row of its own. Retain its
  // exact caller coordinates before parsing so the caller assignment survives.
  for (const auto &unit : units) {
    std::vector<std::pair<llvm::DWARFDie, unsigned>> pending{
        {unit.unit->getUnitDIE(false), 0}};
    while (!pending.empty()) {
      const auto [die, depth] = pending.back();
      pending.pop_back();
      if (die.getTag() == llvm::dwarf::DW_TAG_inlined_subroutine) {
        const auto file = die.find(llvm::dwarf::DW_AT_call_file);
        const auto row = die.find(llvm::dwarf::DW_AT_call_line);
        const auto input = unit.files.find(
            file ? file->getAsUnsignedConstant().value_or(UINT64_MAX)
                 : UINT64_MAX);
        const uint64_t number =
            row ? row->getAsUnsignedConstant().value_or(0) : 0;
        if (input != unit.files.end() && number && number <= UINT32_MAX) {
          needed.insert(input->second);
          if (!source_row(input->second, uint32_t(number)))
            return false;
        }
      }
      for (auto child : die.children())
        pending.emplace_back(child, depth + 1);
    }
  }
  std::set<std::string> warnings;
  std::vector<KernelSourceCandidate> candidates;
  std::map<std::pair<uint32_t, uint32_t>, std::vector<ct_source_case_info>>
      case_rows;
  std::map<std::tuple<uint32_t, uint64_t, uint64_t>, uint64_t> case_blocks;
  std::map<uint64_t, std::map<uint64_t, ct_source_case>> case_labels;
  for (uint32_t index : needed) {
    auto &input = inputs[index];
    auto &file = metadata.files[input.file];
    if (!std::filesystem::path(file.path).is_absolute()) {
      file.error = "source path is not absolute";
    } else if (input.checksum.empty() && !options.skip_checksum) {
      file.error = "DWARF source checksum is absent";
    } else {
      auto content = ct_analysis_read_file(file.path);
      if (!content) {
        file.error = "source cannot be read: " + content.getError().message();
      } else {
        input.content = (*content)->getBuffer().str();
        if (!input.checksum.empty()) {
          llvm::MD5 digest;
          digest.update(input.content);
          llvm::MD5::MD5Result checksum;
          digest.final(checksum);
          llvm::SmallString<32> text;
          llvm::MD5::stringifyResult(checksum, text);
          file.verified = text == input.checksum;
        }
        file.available = file.verified || options.skip_checksum;
        file.checksum_skipped = !file.verified && options.skip_checksum;
        if (!file.verified)
          file.error = input.checksum.empty()
                           ? "DWARF source checksum is absent"
                           : "source checksum mismatch";
        if (file.available) {
          std::istringstream lines(input.content);
          std::string line;
          while (std::getline(lines, line)) {
            if (!line.empty() && line.back() == '\r')
              line.pop_back();
            input.lines.push_back(std::move(line));
          }
          if (!file.assembly) {
            ct_analysis_set_progress_callback(
                [](const ct_analysis_progress *progress, void *context) {
                  const auto *configuration =
                      static_cast<const ct_kernel_source_options *>(context);
                  if (configuration->progress)
                    configuration->progress(progress->detail);
                },
                const_cast<ct_kernel_source_options *>(&options));
            std::string analysis_identity;
            auto analysis = ct_analyze_source(
                input.content, file.path.c_str(), -1, image.path.c_str(),
                &analysis_identity, nullptr, &input.context);
            ct_analysis_set_progress_callback(nullptr, nullptr);
            std::string().swap(input.content);
            std::map<uint64_t, ct_source_block_info> blocks;
            // A multiline statement is one source observation. Its individual
            // DWARF continuation rows still provide exact PC ownership; merge
            // only spans the AST proved to contain one complete statement.
            for (const auto &[number, info] : analysis) {
              if (info.statement.function.empty() ||
                  info.statement.text.empty() || !info.error.empty() ||
                  analysis_identity.empty())
                continue;
              bool referenced =
                  info.expression.constant || !info.call_results.empty();
              for (auto row = line_ids.lower_bound({index, number});
                   row != line_ids.end() && row->first.first == index &&
                   row->first.second <= info.statement.end_line;
                   ++row)
                referenced = true;
              if (!referenced)
                continue;
              const uint32_t canonical = source_row(index, number);
              if (!canonical)
                return false;
              if (info.statement.end_line > number)
                metadata.lines[canonical].text = info.statement.text;
              for (auto row = line_ids.lower_bound({index, number});
                   row != line_ids.end() && row->first.first == index &&
                   row->first.second <= info.statement.end_line;
                   ++row)
                canonical_rows[row->second] = canonical;
            }
            for (auto &[number, line_info] : analysis) {
              if (!analysis_identity.empty() && line_info.error.empty()) {
                for (const auto &item : line_info.cases) {
                  if (!item.label.group_id)
                    continue;
                  const auto key = std::make_tuple(index, item.label.switch_id,
                                                   item.label.group_id);
                  auto [position, inserted] =
                      case_blocks.emplace(key, metadata.blocks.size());
                  if (inserted) {
                    ct_kernel_source_block block;
                    block.id = position->second;
                    block.file = input.file;
                    block.start_line = item.label.line;
                    block.kind = ct_kernel_source_block_kind::switch_case;
                    block.source_available = true;
                    metadata.blocks.push_back(std::move(block));
                  }
                  auto &block = metadata.blocks[position->second];
                  block.start_line =
                      std::min<uint64_t>(block.start_line, item.label.line);
                  block.end_line = std::max(block.end_line, number);
                  case_labels[block.id].emplace(item.label.id, item.label);
                }
                if (!line_info.cases.empty())
                  case_rows.emplace(std::make_pair(index, number),
                                    std::move(line_info.cases));
              }
              if (!line_info.declaration.function.empty() &&
                  !line_info.declaration.text.empty()) {
                input.signatures.emplace(line_info.declaration.function,
                                         line_info.declaration.text);
                if (!analysis_identity.empty() && line_info.error.empty())
                  input.parameters.emplace(line_info.declaration.function,
                                           line_info.declaration.variables);
                input.function_openings.emplace(number,
                                                line_info.declaration.function);
              }
              for (const auto &closure : line_info.closures)
                if (closure.closure.function_body && closure.closure.opening[0])
                  input.signatures.emplace(closure.function,
                                           closure.closure.opening);
              for (const auto &block : line_info.blocks)
                if (block.complete)
                  blocks.emplace(block.block.id, block);
              const auto row = line_ids.find({index, number});
              if (!analysis_identity.empty() && line_info.error.empty() &&
                  row != line_ids.end()) {
                auto presentation =
                    std::make_shared<ct_kernel_source_presentation>();
                presentation->structural = line_info.structural;
                presentation->expression = std::move(line_info.expression);
                presentation->variables = std::move(line_info.variables);
                presentation->declaration = std::move(line_info.declaration);
                presentation->calls = std::move(line_info.calls);
                presentation->call_results = std::move(line_info.call_results);
                presentation->highlights = std::move(line_info.highlights);
                presentation->statement_function = line_info.statement.function;
                if (line_info.statement.end_line > number) {
                  presentation->highlights.clear();
                  for (auto part = analysis.upper_bound(number);
                       part != analysis.end() &&
                       part->first <= line_info.statement.end_line;
                       ++part) {
                    if (!part->second.error.empty())
                      continue;
                    for (const auto &variable : part->second.variables)
                      if (variable.function == line_info.statement.function)
                        presentation->variables.push_back(variable);
                    for (const auto &call : part->second.calls)
                      if (call.function == line_info.statement.function)
                        presentation->calls.push_back(call);
                    for (const auto &call : part->second.call_results)
                      if (call.function == line_info.statement.function)
                        presentation->call_results.push_back(call);
                  }
                }
                metadata.lines[row->second].presentation =
                    std::move(presentation);
              }
            }
            for (const auto &[id, info] : blocks) {
              ct_kernel_source_block block;
              block.id = metadata.blocks.size();
              block.file = input.file;
              block.start_line = info.block.start_line;
              block.end_line = info.block.loop_end_line
                                   ? info.block.loop_end_line
                                   : info.block.closing_line;
              block.loop = info.block.loop_end_line != 0;
              block.source_available = true;
              block.header = info.block.opening_context;
              block.display = info.block.display;
              block.display_line = info.block.display_line;
              block.kind =
                  info.block.kind == CT_SOURCE_BLOCK_CONTROL
                      ? ct_kernel_source_block_kind::control
                  : info.block.kind == CT_SOURCE_BLOCK_STATEMENT_EXPRESSION
                      ? ct_kernel_source_block_kind::statement_expression
                      : ct_kernel_source_block_kind::compound;
              candidates.push_back(
                  {block.id, index, info.function, info.block});
              metadata.blocks.push_back(std::move(block));
            }
          } else {
            std::string().swap(input.content);
          }
        }
      }
    }
    if (!file.error.empty() &&
        warnings.insert(file.path + ": " + file.error).second &&
        options.warning)
      options.warning(
          file.path + ": " +
          (file.checksum_skipped ? "checksum verification skipped: " : "") +
          file.error);
  }
  for (const auto &[id, labels] : case_labels) {
    auto &block = metadata.blocks[id];
    std::set<uint64_t> rows;
    for (const auto &[label_id, label] : labels) {
      if (!block.header.empty())
        block.header += ' ';
      block.header += label.text;
      if (label.display[0] && !rows.insert(label.line).second)
        continue;
      if (!block.display.empty())
        block.display += '\n';
      else
        block.display_line = label.line;
      block.display += label.display[0] ? label.display : label.text;
    }
  }
  for (const auto &[key, index] : line_ids) {
    const auto &input = inputs[key.first];
    if (metadata.lines[index].text.empty() &&
        metadata.files[input.file].available && key.second &&
        key.second <= input.lines.size()) {
      std::string text = input.lines[key.second - 1];
      const auto begin = metadata.files[input.file].assembly
                             ? 0
                             : text.find_first_not_of(" \t");
      metadata.lines[index].text =
          begin == std::string::npos ? std::string() : text.substr(begin);
    }
    auto &line = metadata.lines[index];
    if (!line.presentation && metadata.files[input.file].available &&
        !metadata.files[input.file].assembly && !line.text.empty())
      line.presentation = std::make_shared<ct_kernel_source_presentation>();
  }
  for (auto &site : metadata.sites)
    if (const auto row = canonical_rows.find(site.line);
        row != canonical_rows.end())
      site.line = row->second;
  for (auto &[key, index] : line_ids)
    if (const auto row = canonical_rows.find(index);
        row != canonical_rows.end())
      index = row->second;
  struct Scope {
    uint64_t function = 0, block = 0;
    unsigned depth = 0;
    std::vector<ct_kernel_source_range> ranges;
  };
  std::vector<Scope> scopes;
  struct InlineCall {
    uint32_t input = 0, line = 0, column = 0;
    uint64_t owner = 0;
    std::string function;
  };
  std::map<uint64_t, InlineCall> inline_calls;
  for (const auto &unit : units) {
    struct Pending {
      llvm::DWARFDie die, function_die;
      uint64_t function, parent;
      unsigned depth;
    };
    std::vector<Pending> pending{{unit.unit->getUnitDIE(false), {}, 0, 0, 0}};
    while (!pending.empty()) {
      Pending current = pending.back();
      pending.pop_back();
      const auto tag = current.die.getTag();
      bool body_fragment = false;
      if (tag == llvm::dwarf::DW_TAG_inlined_subroutine && current.function &&
          current.die.getParent() == current.function_die) {
        const auto origin = current.die.getAttributeValueAsReferencedDie(
            llvm::dwarf::DW_AT_abstract_origin);
        const auto physical_origin =
            current.function_die.getAttributeValueAsReferencedDie(
                llvm::dwarf::DW_AT_abstract_origin);
        body_fragment =
            origin && origin.getDwarfUnit() == current.die.getDwarfUnit() &&
            (origin == physical_origin || origin == current.function_die);
        for (const auto &[call_attribute, declaration_attribute] :
             {std::pair{llvm::dwarf::DW_AT_call_file,
                        llvm::dwarf::DW_AT_decl_file},
              std::pair{llvm::dwarf::DW_AT_call_line,
                        llvm::dwarf::DW_AT_decl_line},
              std::pair{llvm::dwarf::DW_AT_call_column,
                        llvm::dwarf::DW_AT_decl_column}}) {
          if (!body_fragment)
            break;
          const auto call = current.die.find(call_attribute);
          const auto declaration =
              origin.findRecursively({declaration_attribute});
          body_fragment = call && declaration &&
                          call->getAsUnsignedConstant().value_or(0) &&
                          call->getAsUnsignedConstant() ==
                              declaration->getAsUnsignedConstant();
        }
        if (body_fragment) {
          const auto file =
              unit.files.find(current.die.find(llvm::dwarf::DW_AT_call_file)
                                  ->getAsUnsignedConstant()
                                  .value());
          const auto line = current.die.find(llvm::dwarf::DW_AT_call_line)
                                ->getAsUnsignedConstant()
                                .value();
          body_fragment = file != unit.files.end();
          if (body_fragment) {
            const auto &input = inputs[file->second];
            const auto opening = input.function_openings.find(line);
            const auto &name = metadata.functions[current.function].name;
            // GCC may wrap an out-of-line body fragment in a self-origin
            // inline DIE at its declaration. Only fold it when Clang proves
            // that row has no executable body: recursive call sites, macros,
            // one-line definitions and unavailable source remain distinct.
            body_fragment = input.parameters.count(name) &&
                            opening != input.function_openings.end() &&
                            opening->second == name;
          }
        }
      }
      if (tag == llvm::dwarf::DW_TAG_subprogram ||
          tag == llvm::dwarf::DW_TAG_inlined_subroutine ||
          tag == llvm::dwarf::DW_TAG_lexical_block) {
        std::vector<ct_kernel_source_range> ranges;
        auto addresses = current.die.getAddressRanges();
        if (!addresses) {
          llvm::consumeError(addresses.takeError());
        } else {
          for (const auto &range : *addresses)
            if (range.SectionIndex !=
                    llvm::object::SectionedAddress::UndefSection &&
                range.SectionIndex < image.sections.size() &&
                (image.sections[range.SectionIndex].flags & SHF_EXECINSTR) &&
                range.LowPC < range.HighPC &&
                range.HighPC <= image.sections[range.SectionIndex].size)
              source_add_range(ranges, range.SectionIndex, range.LowPC,
                               range.HighPC);
        }
        source_merge_ranges(ranges);
        if (!ranges.empty()) {
          const char *name =
              current.die.getSubroutineName(llvm::DINameKind::LinkageName);
          if (!name)
            name = current.die.getSubroutineName(llvm::DINameKind::ShortName);
          if (tag == llvm::dwarf::DW_TAG_subprogram) {
            ct_kernel_source_function function;
            function.id = metadata.functions.size();
            function.name = name ? name : "?";
            function.ranges = ranges;
            if (const auto value =
                    current.die.findRecursively({llvm::dwarf::DW_AT_decl_line}))
              function.line = value->getAsUnsignedConstant().value_or(0);
            if (const auto value = current.die.findRecursively(
                    {llvm::dwarf::DW_AT_decl_file})) {
              const auto file = unit.files.find(
                  value->getAsUnsignedConstant().value_or(UINT64_MAX));
              if (file != unit.files.end())
                function.file = inputs[file->second].file;
            }
            current.function = function.id;
            current.function_die = current.die;
            current.parent = 0;
            metadata.functions.push_back(std::move(function));
            scopes.push_back(
                {current.function, 0, current.depth, std::move(ranges)});
          } else if (current.function && !body_fragment) {
            ct_kernel_source_block block;
            block.id = metadata.blocks.size();
            block.parent = current.parent;
            block.function = current.function;
            block.kind = tag == llvm::dwarf::DW_TAG_inlined_subroutine
                             ? ct_kernel_source_block_kind::inline_function
                             : ct_kernel_source_block_kind::lexical;
            block.header = tag == llvm::dwarf::DW_TAG_inlined_subroutine && name
                               ? name
                               : "";
            block.ranges = ranges;
            if (tag == llvm::dwarf::DW_TAG_inlined_subroutine) {
              if (const auto value = current.die.findRecursively(
                      {llvm::dwarf::DW_AT_decl_line}))
                block.start_line = value->getAsUnsignedConstant().value_or(0);
              if (const auto value = current.die.findRecursively(
                      {llvm::dwarf::DW_AT_decl_file})) {
                const auto file = unit.files.find(
                    value->getAsUnsignedConstant().value_or(UINT64_MAX));
                if (file != unit.files.end()) {
                  block.file = inputs[file->second].file;
                  block.source_available = metadata.files[block.file].available;
                }
              }
              InlineCall call;
              for (uint64_t parent = current.parent; parent;
                   parent = metadata.blocks[parent].parent)
                if (metadata.blocks[parent].kind ==
                    ct_kernel_source_block_kind::inline_function) {
                  call.owner = parent;
                  break;
                }
              call.function = call.owner
                                  ? metadata.blocks[call.owner].header
                                  : metadata.functions[current.function].name;
              if (const auto value =
                      current.die.find(llvm::dwarf::DW_AT_call_file)) {
                const auto file = unit.files.find(
                    value->getAsUnsignedConstant().value_or(UINT64_MAX));
                if (file != unit.files.end())
                  call.input = file->second;
              }
              if (const auto value =
                      current.die.find(llvm::dwarf::DW_AT_call_line))
                call.line = value->getAsUnsignedConstant().value_or(0);
              if (const auto value =
                      current.die.find(llvm::dwarf::DW_AT_call_column))
                call.column = value->getAsUnsignedConstant().value_or(0);
              const auto caller_row = line_ids.find({call.input, call.line});
              if (caller_row != line_ids.end() &&
                  metadata.lines[caller_row->second].presentation) {
                block.call_line = caller_row->second;
                block.call_column = call.column;
                block.call_function = call.function;
              }
              inline_calls.emplace(block.id, std::move(call));
            }
            current.parent = block.id;
            metadata.blocks.push_back(std::move(block));
            scopes.push_back({current.function, current.parent, current.depth,
                              std::move(ranges)});
          }
        }
      }
      for (auto child : current.die.children())
        pending.push_back({child, current.function_die, current.function,
                           current.parent, current.depth + 1});
    }
  }
  for (auto &function : metadata.functions) {
    if (!function.id)
      continue;
    for (const auto &input : inputs) {
      if (input.file != function.file)
        continue;
      if (const auto signature = input.signatures.find(function.name);
          signature != input.signatures.end())
        function.signature = signature->second;
      if (const auto parameters = input.parameters.find(function.name);
          parameters != input.parameters.end())
        function.parameters = parameters->second;
    }
  }
  struct ScopeRange {
    uint64_t begin, end, prefix_end;
    size_t scope;
  };
  std::map<uint32_t, std::vector<ScopeRange>> scope_index;
  for (size_t index = 0; index < scopes.size(); ++index)
    for (const auto &range : scopes[index].ranges)
      scope_index[range.section].push_back({range.begin, range.end, 0, index});
  for (auto &[section, ranges] : scope_index) {
    std::sort(ranges.begin(), ranges.end(),
              [](const auto &left, const auto &right) {
                return std::tie(left.begin, left.end, left.scope) <
                       std::tie(right.begin, right.end, right.scope);
              });
    uint64_t end = 0;
    for (auto &range : ranges)
      range.prefix_end = end = std::max(end, range.end);
  }
  std::map<std::pair<uint32_t, std::string>,
           std::vector<const KernelSourceCandidate *>>
      candidate_index;
  for (const auto &candidate : candidates)
    candidate_index[{candidate.input, candidate.function}].push_back(
        &candidate);
  std::map<std::tuple<uint64_t, uint64_t, uint64_t>, uint64_t> block_variants;
  for (const auto &site : sites) {
    if (!site.probe)
      continue;
    auto &result = metadata.sites[site.id];
    std::vector<std::pair<unsigned, uint64_t>> active;
    const auto &ranges = scope_index[site.section];
    auto position = std::upper_bound(ranges.begin(), ranges.end(), site.offset,
                                     [](uint64_t offset, const auto &range) {
                                       return offset < range.begin;
                                     });
    while (position != ranges.begin()) {
      --position;
      if (position->prefix_end <= site.offset)
        break;
      if (position->end <= site.offset)
        continue;
      const auto &scope = scopes[position->scope];
      if (!scope.block) {
        if (result.function && result.function != scope.function) {
          result.function = 0;
          active.clear();
          break;
        }
        result.function = scope.function;
      } else {
        active.emplace_back(scope.depth, scope.block);
      }
    }
    std::sort(active.begin(), active.end());
    if (!result.function)
      continue;
    if (result.line) {
      const auto &openings = inputs[site_inputs[site.id]].function_openings;
      const auto opening = openings.find(metadata.lines[result.line].line);
      result.function_opening =
          opening != openings.end() &&
          opening->second == metadata.functions[result.function].name;
    }
    std::vector<uint64_t> inline_path;
    for (const auto &[depth, block] : active)
      if (metadata.blocks[block].function == result.function &&
          metadata.blocks[block].kind ==
              ct_kernel_source_block_kind::inline_function)
        inline_path.push_back(block);
    std::map<uint64_t, std::vector<const KernelSourceCandidate *>> members;
    std::map<uint64_t, std::map<uint64_t, uint64_t>> selected_cases;
    const auto collect_members = [&](uint32_t input,
                                     const std::string &function, uint32_t line,
                                     uint32_t column, uint64_t owner) {
      if (!input || !line)
        return;
      std::set<uint64_t> dispatches;
      if (const auto found = case_rows.find({input, line});
          found != case_rows.end()) {
        for (const auto &item : found->second) {
          if (item.function != function ||
              (column &&
               (column < item.begin_column || column >= item.end_column)) ||
              (!column && item.column_required))
            continue;
          if (!item.label.group_id) {
            dispatches.insert(item.label.switch_id);
            continue;
          }
          const auto id = case_blocks.at(std::make_tuple(
              input, item.label.switch_id, item.label.group_id));
          auto [entry, inserted] =
              selected_cases[owner].emplace(item.label.switch_id, id);
          if (!inserted && entry->second != id)
            entry->second = 0;
        }
      }
      for (const auto *candidate : candidate_index[{input, function}]) {
        const auto &block = candidate->source;
        const uint64_t first_line = block.condition_line  ? block.condition_line
                                    : block.loop_end_line ? block.start_line
                                                          : block.opening_line;
        const uint64_t first_column =
            block.condition_line ? block.condition_column
            : block.loop_end_line
                ? block.loop_start_column
                : block.opening_column +
                      (block.condition_chain_id && !block.body_start_inclusive);
        const uint64_t last_line =
            block.loop_end_line ? block.loop_end_line : block.closing_line;
        const uint64_t last_column =
            block.loop_end_line
                ? block.loop_end_column
                : block.closing_column +
                      (!block.condition_chain_id || block.body_start_inclusive);
        if (dispatches.count(block.switch_id)) {
          // The selector precedes the opening brace but belongs to the same
          // switch scope as the selected case body.
        } else if (line < first_line || line > last_line) {
          continue;
        } else if (!column && (line == first_line || line == last_line)) {
          // A whole header line has no competing outside statement. Preserve
          // loop membership even if the compiler omitted its column number.
          if (line != first_line || first_line == last_line ||
              line > inputs[input].lines.size() ||
              inputs[input].lines[line - 1].find_first_not_of(" \t") + 1 !=
                  first_column)
            continue;
        } else if ((line == first_line && column < first_column) ||
                   (line == last_line && column >= last_column)) {
          continue;
        }
        auto &entries = members[owner];
        if (std::find(entries.begin(), entries.end(), candidate) ==
            entries.end())
          entries.push_back(candidate);
      }
    };
    // DWARF inline call coordinates retain caller scopes while instruction
    // rows switch to the inlined callee's file. No runtime line heuristics.
    for (uint64_t block : inline_path) {
      const auto &call = inline_calls.at(block);
      collect_members(call.input, call.function, call.line, call.column,
                      call.owner);
    }
    if (result.line) {
      const uint64_t owner = inline_path.empty() ? 0 : inline_path.back();
      collect_members(site_inputs[site.id],
                      owner ? metadata.blocks[owner].header
                            : metadata.functions[result.function].name,
                      site_lines[site.id], result.column, owner);
    }
    const auto append_members = [&](uint64_t owner) {
      auto &entries = members[owner];
      std::sort(
          entries.begin(), entries.end(), [](const auto *a, const auto *b) {
            const auto start = [](const auto &scope) {
              return std::pair{scope.condition_line  ? scope.condition_line
                               : scope.loop_end_line ? scope.start_line
                                                     : scope.opening_line,
                               scope.condition_line  ? scope.condition_column
                               : scope.loop_end_line ? scope.loop_start_column
                                                     : scope.opening_column};
            };
            return start(a->source) < start(b->source);
          });
      for (const auto *member : entries) {
        uint64_t id = member->block;
        auto [variant, inserted] = block_variants.emplace(
            std::make_tuple(id, result.function, owner), id);
        if (inserted) {
          if (metadata.blocks[id].function) {
            auto copy = metadata.blocks[id];
            variant->second = copy.id = metadata.blocks.size();
            copy.ranges.clear();
            metadata.blocks.push_back(std::move(copy));
          }
        }
        id = variant->second;
        auto &block = metadata.blocks[id];
        block.function = result.function;
        block.parent = result.blocks.empty() ? 0 : result.blocks.back();
        source_add_range(block.ranges, site.section, site.offset,
                         site.offset + site.original_size);
        result.blocks.push_back(id);
        const auto selected =
            selected_cases[owner].find(member->source.switch_id);
        if (!member->source.switch_id ||
            selected == selected_cases[owner].end() || !selected->second)
          continue;
        uint64_t case_id = selected->second;
        auto [case_variant, case_inserted] = block_variants.emplace(
            std::make_tuple(case_id, result.function, owner), case_id);
        if (case_inserted && metadata.blocks[case_id].function) {
          auto copy = metadata.blocks[case_id];
          case_variant->second = copy.id = metadata.blocks.size();
          copy.ranges.clear();
          metadata.blocks.push_back(std::move(copy));
        }
        case_id = case_variant->second;
        auto &body = metadata.blocks[case_id];
        body.function = result.function;
        body.parent = id;
        source_add_range(body.ranges, site.section, site.offset,
                         site.offset + site.original_size);
        result.blocks.push_back(case_id);
      }
    };
    uint64_t owner = 0;
    append_members(owner);
    for (const auto &[depth, id] : active) {
      const auto &block = metadata.blocks[id];
      if (block.function != result.function)
        continue;
      if (block.kind == ct_kernel_source_block_kind::inline_function) {
        result.blocks.push_back(id);
        owner = id;
        append_members(owner);
      } else if (members[owner].empty()) {
        // Without reliable AST membership retain exact compiler scope ranges.
        result.blocks.push_back(id);
      }
    }
  }

  // Line tables may attribute hoisted preparation to a branch body, and loop
  // initializers may be separated from the natural loop by unrelated work.
  // Refine only uniquely matched source controls using exact original CFG
  // members. Never bridge holes by taking a minimum/maximum PC envelope.
  std::map<uint64_t, const KernelSourceCandidate *> control_sources;
  std::map<uint64_t, uint64_t> control_owners;
  for (const auto &[key, id] : block_variants) {
    const auto candidate = std::find_if(
        candidates.begin(), candidates.end(),
        [&](const auto &item) { return item.block == std::get<0>(key); });
    if (candidate != candidates.end()) {
      control_sources[id] = &*candidate;
      control_owners[id] = std::get<2>(key);
    }
  }
  std::map<uint64_t, std::vector<uint64_t>> refined;
  std::set<uint64_t> ambiguous_controls;
  const auto member = [&](uint64_t id, uint64_t site) {
    return site < metadata.sites.size() &&
           std::find(metadata.sites[site].blocks.begin(),
                     metadata.sites[site].blocks.end(),
                     id) != metadata.sites[site].blocks.end();
  };
  const auto refine = [&](uint64_t id, const std::vector<uint64_t> &members) {
    if (members.empty())
      return;
    const auto owner = control_owners.at(id);
    if (owner &&
        std::any_of(members.begin(), members.end(),
                    [&](uint64_t site) { return !member(owner, site); }))
      return;
    const auto [position, inserted] = refined.emplace(id, members);
    if (!inserted && position->second != members)
      ambiguous_controls.insert(id);
  };
  for (const auto &function : metadata.functions) {
    if (!function.id ||
        std::none_of(control_sources.begin(), control_sources.end(),
                     [&](const auto &entry) {
                       return metadata.blocks[entry.first].function ==
                              function.id;
                     }))
      continue;
    for (const auto &range : function.ranges) {
      std::vector<ct_kernel_flow_region> regions;
      std::string issue;
      if (!ct_kernel_source_flow(image, sites, range.section, range.begin,
                                 range.end, regions, issue))
        continue;
      for (const auto &region : regions) {
        if (!region.branch || region.branch >= metadata.sites.size())
          continue;
        const auto &branch = metadata.sites[region.branch];
        if (!branch.line)
          continue;
        const auto &line = metadata.lines[branch.line];
        if (!region.loop && !region.taken_prefix.empty() &&
            !region.fallthrough_prefix.empty()) {
          std::string branch_owner;
          (void)ct_kernel_source_row(metadata, region.branch, &branch_owner);
          uint64_t false_successor = 0;
          bool conflict = false;
          for (const auto &[id, candidate] : control_sources) {
            const auto &block = metadata.blocks[id];
            const auto &extent = candidate->source;
            if (block.function != function.id || block.file != line.file ||
                block.kind != ct_kernel_source_block_kind::control ||
                extent.switch_id || candidate->function != branch_owner ||
                (extent.condition_chain_id && !extent.condition_line) ||
                line.line < extent.start_line ||
                line.line > extent.opening_line)
              continue;
            const auto classify = [&](const std::vector<uint64_t> &prefix) {
              for (const auto site_id : prefix) {
                if (!site_id || site_id >= metadata.sites.size() ||
                    metadata.sites[site_id].function != function.id)
                  return 0;
                const auto &point = metadata.sites[site_id];
                if (!point.line)
                  continue;
                std::string owner;
                auto row = ct_kernel_source_row(metadata, site_id, &owner);
                uint32_t column = point.column;
                if (!row)
                  return 0;
                if (owner != candidate->function) {
                  row = 0;
                  for (const auto parent : point.blocks) {
                    const auto &scope = metadata.blocks[parent];
                    if (scope.kind ==
                            ct_kernel_source_block_kind::inline_function &&
                        scope.call_function == candidate->function &&
                        scope.call_line &&
                        metadata.lines[scope.call_line].file == block.file) {
                      row = scope.call_line;
                      column = scope.call_column;
                      break;
                    }
                  }
                }
                if (!row || metadata.lines[row].file != block.file)
                  return 0;
                const auto number = metadata.lines[row].line;
                const bool after_open =
                    number > extent.opening_line ||
                    (number == extent.opening_line && column &&
                     (column > extent.opening_column ||
                      (extent.body_start_inclusive &&
                       column == extent.opening_column)));
                if (member(id, site_id) && number >= extent.first_body_line &&
                    (!extent.condition_chain_id || after_open))
                  return 1;
                const auto end = extent.loop_end_line ? extent.loop_end_line
                                                      : extent.closing_line;
                const auto end_column = extent.loop_end_line
                                            ? extent.loop_end_column
                                            : extent.closing_column;
                if (number < extent.start_line || number > end ||
                    (number == end && column && column >= end_column))
                  return -1;
                // A successor still evaluating a short-circuit header is not
                // proof that the logical body was skipped. Only walk its
                // straight prefix; the CFG stops at the next control change.
                if (number > extent.opening_line)
                  return 0;
              }
              return 0;
            };
            const int taken = classify(region.taken_prefix);
            const int following = classify(region.fallthrough_prefix);
            const uint64_t edge = taken == 1 && following == -1
                                      ? region.fallthrough
                                  : taken == -1 && following == 1 ? region.taken
                                                                  : 0;
            if (edge) {
              conflict |= false_successor && false_successor != edge;
              false_successor = edge;
            }
          }
          if (false_successor && !conflict) {
            auto &saved = metadata.sites[region.branch].not_taken_successor;
            saved = !saved || saved == false_successor ? false_successor
                                                       : UINT64_MAX;
          }
        }
        uint64_t selected = 0;
        bool taken = false, ambiguous = false;
        for (const auto &[id, candidate] : control_sources) {
          const auto control = id;
          const auto &block = metadata.blocks[id];
          const auto &source = candidate->source;
          if (block.function != function.id || block.file != line.file ||
              block.kind != ct_kernel_source_block_kind::control ||
              source.switch_id || source.condition_chain_id ||
              (!block.loop && region.loop))
            continue;
          const bool header = line.line >= source.start_line &&
                              line.line <= source.opening_line;
          const bool trailing_test = region.loop &&
                                     line.line == source.loop_end_line &&
                                     block.header.rfind("do", 0) == 0;
          if (!header && !trailing_test)
            continue;
          const auto intersects = [&](const std::vector<uint64_t> &members) {
            return std::any_of(
                members.begin(), members.end(),
                [&](uint64_t site) { return member(control, site); });
          };
          const bool in_taken = intersects(region.taken_members);
          const bool in_fallthrough = intersects(region.fallthrough_members);
          if (region.loop ? !intersects(region.members)
                          : (in_taken == in_fallthrough ||
                             (!block.loop && member(id, region.branch))))
            continue;
          if (selected)
            ambiguous = true;
          selected = id;
          taken = in_taken;
        }
        if (!selected || ambiguous)
          continue;
        uint64_t false_successor = 0;
        if (region.loop) {
          const bool taken_inside = std::binary_search(
              region.members.begin(), region.members.end(), region.taken);
          const bool following_inside = std::binary_search(
              region.members.begin(), region.members.end(), region.fallthrough);
          if (taken_inside != following_inside)
            false_successor = taken_inside ? region.fallthrough : region.taken;
        } else {
          false_successor = taken ? region.fallthrough : region.taken;
        }
        if (false_successor) {
          auto &saved = metadata.sites[region.branch].not_taken_successor;
          saved =
              !saved || saved == false_successor ? false_successor : UINT64_MAX;
        }
        if (region.loop) {
          refine(selected, region.members);
          continue;
        }
        // An initial zero-trip loop guard can sit outside the natural loop.
        // Its false edge is proven above, but it does not redefine loop scope.
        if (metadata.blocks[selected].loop)
          continue;
        refine(selected,
               taken ? region.taken_members : region.fallthrough_members);
        const auto &other =
            taken ? region.fallthrough_members : region.taken_members;
        uint64_t alternative = 0;
        ambiguous = false;
        for (const auto &[id, candidate] : control_sources) {
          const auto control = id;
          const auto &block = metadata.blocks[id];
          if (block.function != function.id || block.file != line.file ||
              block.loop || block.header.rfind("else", 0) != 0 ||
              block.header.rfind("else if", 0) == 0 ||
              control_owners.at(id) != control_owners.at(selected) ||
              other.empty() ||
              !std::all_of(other.begin(), other.end(), [&](uint64_t site) {
                return member(control, site);
              }))
            continue;
          if (alternative)
            ambiguous = true;
          alternative = id;
        }
        if (alternative && !ambiguous)
          refine(alternative, other);
      }
    }
  }
  for (const auto &[id, members] : refined) {
    if (ambiguous_controls.count(id))
      continue;
    const auto owner = control_owners.at(id);
    // The owner is an inline instance, not another refined source control.
    // Recheck before mutating paths so insertion never advances past end().
    if (owner &&
        std::any_of(members.begin(), members.end(),
                    [&](uint64_t site) { return !member(owner, site); }))
      continue;
    auto &block = metadata.blocks[id];
    block.ranges.clear();
    for (auto &site : metadata.sites)
      site.blocks.erase(std::remove(site.blocks.begin(), site.blocks.end(), id),
                        site.blocks.end());
    for (const auto site_id : members) {
      auto &path = metadata.sites[site_id].blocks;
      auto position =
          owner ? std::next(std::find(path.begin(), path.end(), owner))
                : path.begin();
      const auto &source = control_sources.at(id)->source;
      while (position != path.end()) {
        const auto before = control_sources.find(*position);
        if (metadata.blocks[*position].kind ==
                ct_kernel_source_block_kind::inline_function ||
            (before != control_sources.end() &&
             std::tie(source.opening_line, source.opening_column) <
                 std::tie(before->second->source.opening_line,
                          before->second->source.opening_column)))
          break;
        ++position;
      }
      path.insert(position, id);
    }
    for (const auto &site : sites)
      if (site.probe && member(id, site.id))
        source_add_range(block.ranges, site.section, site.offset,
                         site.offset + site.original_size);
  }

  for (auto &block : metadata.blocks)
    source_merge_ranges(block.ranges);
  // Equivalent compiler lexical scope and verified source brace describe one
  // region. Keep the more informative source spelling, not duplicate bars.
  std::set<uint64_t> replaced;
  for (const auto &lexical : metadata.blocks) {
    if (!lexical.id || lexical.kind != ct_kernel_source_block_kind::lexical)
      continue;
    for (const auto &candidate : candidates) {
      const auto &block = metadata.blocks[candidate.block];
      if (block.function != lexical.function ||
          block.ranges.size() != lexical.ranges.size())
        continue;
      bool same = !block.ranges.empty();
      for (size_t index = 0; same && index < block.ranges.size(); ++index)
        same = std::tie(block.ranges[index].section, block.ranges[index].begin,
                        block.ranges[index].end) ==
               std::tie(lexical.ranges[index].section,
                        lexical.ranges[index].begin, lexical.ranges[index].end);
      if (same)
        replaced.insert(lexical.id);
    }
  }
  for (auto &site : metadata.sites)
    if (site.not_taken_successor == UINT64_MAX)
      site.not_taken_successor = 0;
  for (auto &site : metadata.sites)
    site.blocks.erase(
        std::remove_if(site.blocks.begin(), site.blocks.end(),
                       [&](uint64_t id) { return replaced.count(id); }),
        site.blocks.end());
  // AST caller scopes can enclose an inline instance even when DWARF omits
  // that lexical DIE. Record its observed parent only when every site agrees.
  std::map<uint64_t, uint64_t> parents;
  std::set<uint64_t> ambiguous_parents;
  for (const auto &site : metadata.sites) {
    uint64_t parent = 0;
    for (uint64_t id : site.blocks) {
      auto [entry, inserted] = parents.emplace(id, parent);
      if (!inserted && entry->second != parent)
        ambiguous_parents.insert(id);
      parent = id;
    }
  }
  for (const auto &[id, parent] : parents)
    metadata.blocks[id].parent = ambiguous_parents.count(id) ? 0 : parent;
  if (!error.empty()) {
    metadata = {};
    return false;
  }
  if (units.empty() && options.warning)
    options.warning("DWARF not found; source path is unknown");
  return true;
}
