#include <algorithm>
#include <map>
#include <set>
#include <utility>

#include <elf.h>

#include "filter.h"
#include "kernel_policy.h"

static constexpr size_t policy_site_limit = 1000000;
static constexpr size_t policy_pool_limit = 65536;
static constexpr size_t policy_depth_limit = 4096;
static constexpr size_t policy_membership_limit = 1000000;
static constexpr size_t policy_pattern_bytes_limit = 16 * 1024 * 1024;

bool ct_kernel_compile_policy(const ct_kernel_image &image,
                              const std::vector<ct_kernel_site> &sites,
                              const ct_kernel_source_metadata *source,
                              const ct_kernel_policy_options &options,
                              ct_kernel_policy &policy, std::string &error,
                              const std::vector<uint64_t> *scope_sites) {
  policy = {};
  error.clear();
  const auto fail = [&](const char *message) {
    policy = {};
    error = message;
    return false;
  };
  if (sites.empty() || sites.size() > policy_site_limit ||
      image.symbols.size() > policy_site_limit ||
      image.name.find('\0') != std::string::npos ||
      image.path.find('\0') != std::string::npos ||
      (source && (source->blocks.empty() || source->functions.empty() ||
                  source->sites.size() > policy_site_limit + 1 ||
                  source->blocks.size() > policy_site_limit + 1 ||
                  source->functions.size() > policy_site_limit + 1)))
    return fail("kernel policy input exceeds its bounds");
  size_t pattern_bytes = 0;
  for (const auto *patterns :
       {&options.within, &options.into, &options.recurse, &options.over}) {
    if (patterns->size() > policy_pool_limit)
      return fail("kernel policy filter inventory exceeds its bound");
    for (const auto &pattern : *patterns) {
      if (pattern.size() > policy_pattern_bytes_limit - pattern_bytes ||
          pattern.find('\0') != std::string::npos)
        return fail("kernel policy filter text exceeds its bound");
      pattern_bytes += pattern.size();
    }
  }
  ct_filter within, into, recurse, over;
  if (!within.parse(options.within, error) ||
      !into.parse(options.into, error) ||
      !recurse.parse(options.recurse, error) ||
      !over.parse(options.over, error))
    return false;
  const bool filtered = !options.into.empty() || !options.recurse.empty() ||
                        !options.over.empty();
  const bool within_unrestricted =
      options.within.empty() && !options.within_init && !options.within_intr;
  const auto resolve = [&](const std::string &name) {
    const auto match = [&](const ct_filter &filter) {
      return filter.matches(name.c_str(), image.name.c_str(),
                            image.path.c_str(), true);
    };
    kctrace_policy_mode mode = KCTRACE_POLICY_SKIP;
    if (!filtered || match(into))
      mode = KCTRACE_POLICY_INTO;
    if (match(recurse))
      mode = KCTRACE_POLICY_RECURSE;
    if (match(over))
      mode = std::max(mode, KCTRACE_POLICY_OVER);
    return std::make_pair(mode, within_unrestricted || match(within));
  };
  struct FunctionInput {
    ct_kernel_policy_function function;
    std::vector<uint32_t> aliases;
  };
  std::map<std::pair<uint32_t, uint64_t>, FunctionInput> grouped;
  for (size_t index = 0; index < image.symbols.size(); ++index) {
    const auto &symbol = image.symbols[index];
    if (symbol.type != STT_FUNC || !symbol.size ||
        symbol.section >= image.sections.size() ||
        !(image.sections[symbol.section].flags & SHF_EXECINSTR))
      continue;
    const auto &section = image.sections[symbol.section];
    if (symbol.name.find('\0') != std::string::npos ||
        symbol.offset > section.size ||
        symbol.size > section.size - symbol.offset)
      return fail("kernel policy function exceeds its original section");
    const auto key = std::make_pair(symbol.section, symbol.offset);
    if (!grouped.count(key) && grouped.size() + 1 >= policy_pool_limit)
      return fail("kernel policy function inventory exceeds its bound");
    auto [position, inserted] = grouped.try_emplace(key);
    auto &function = position->second.function;
    if (inserted) {
      function.section = symbol.section;
      function.begin = symbol.offset;
      function.end = symbol.offset + symbol.size;
    } else if (function.end != symbol.offset + symbol.size) {
      return fail("ambiguous kernel policy function alias extent");
    }
    const auto decision = resolve(symbol.name);
    function.mode = std::max(function.mode, decision.first);
    function.within |= decision.second;
    // init_module is the module_init ABI alias. Preparation independently
    // verifies __this_module.init points to this exact original entry.
    // Do not give other .init.text functions or inline names this criterion.
    function.within |= options.within_init && symbol.name == "init_module";
    position->second.aliases.push_back(uint32_t(index));
  }
  std::map<std::pair<uint32_t, uint64_t>, uint32_t> function_index;
  for (auto &[address, input] : grouped) {
    function_index.emplace(address, policy.functions.size());
    input.function.first_alias = policy.aliases.size();
    input.function.alias_count = input.aliases.size();
    policy.aliases.insert(policy.aliases.end(), input.aliases.begin(),
                          input.aliases.end());
    policy.functions.push_back(input.function);
  }
  grouped.clear();
  uint64_t maximum = 0;
  for (const auto &site : sites)
    if (site.probe)
      maximum = std::max(maximum, site.id);
  if (!maximum || maximum > policy_site_limit ||
      (scope_sites &&
       (scope_sites->size() != maximum + 1 || (*scope_sites)[0])))
    return fail("kernel policy site identifiers exceed their bound");
  policy.sites.resize(maximum + 1);
  std::vector<const ct_kernel_site *> originals(maximum + 1);
  std::set<std::pair<uint32_t, uint64_t>> addresses;
  for (const auto &site : sites) {
    if (!site.probe)
      continue;
    if (!site.id || originals[site.id] ||
        site.section >= image.sections.size() || !site.original_size ||
        site.original_size > 15 ||
        !addresses.emplace(site.section, site.offset).second)
      return fail("invalid kernel policy instruction identity");
    auto function = function_index.upper_bound({site.section, site.offset});
    if (function == function_index.begin() ||
        (--function)->first.first != site.section)
      return fail("kernel policy instruction has no original function");
    auto &owner = policy.functions[function->second];
    if (site.offset >= owner.end ||
        site.original_size > owner.end - site.offset)
      return fail("kernel policy instruction exceeds its original function");
    policy.sites[site.id].function = function->second;
    originals[site.id] = &site;
    if (!owner.first_probe ||
        site.offset < originals[owner.first_probe]->offset)
      owner.first_probe = site.id;
  }
  std::map<uint64_t, uint32_t> inline_index;
  if (source) {
    size_t range_count = 0;
    for (size_t index = 0; index < source->functions.size(); ++index) {
      const auto &function = source->functions[index];
      if (function.id != index || function.name.find('\0') != std::string::npos)
        return fail("invalid kernel policy source function identity");
      if (function.ranges.size() > policy_membership_limit - range_count)
        return fail("kernel policy source function ranges exceed their bound");
      range_count += function.ranges.size();
      for (const auto &range : function.ranges)
        if (range.section >= image.sections.size() ||
            range.begin >= range.end ||
            range.end > image.sections[range.section].size ||
            !(image.sections[range.section].flags & SHF_EXECINSTR))
          return fail(
              "kernel policy source function exceeds its original section");
    }
    for (auto &function : policy.functions) {
      if (!function.first_probe || function.first_probe >= source->sites.size())
        continue;
      const auto id = source->sites[function.first_probe].function;
      if (id >= source->functions.size())
        return fail("invalid kernel policy physical source owner");
      if (!id)
        continue;
      const auto &physical = source->functions[id];
      const auto &entry = *originals[function.first_probe];
      // A compiler clone can retain its original DWARF name. Require the
      // physical entry's unambiguous owner and an exact section/entry range;
      // do not infer aliases by stripping suffixes or using inline names.
      if (physical.name.empty() || physical.name == "?" ||
          std::none_of(physical.ranges.begin(), physical.ranges.end(),
                       [&](const auto &range) {
                         return range.section == function.section &&
                                range.begin == function.begin &&
                                range.end <= function.end &&
                                entry.offset + entry.original_size <= range.end;
                       }))
        continue;
      const auto decision = resolve(physical.name);
      function.mode = std::max(function.mode, decision.first);
      function.within |= decision.second;
    }
    for (size_t index = 1; index < source->blocks.size(); ++index) {
      const auto &block = source->blocks[index];
      if (block.id != index || block.function >= source->functions.size() ||
          block.parent >= source->blocks.size() ||
          block.kind < ct_kernel_source_block_kind::lexical ||
          block.kind > ct_kernel_source_block_kind::statement_expression)
        return fail("invalid kernel policy source scope identity");
      for (const auto &range : block.ranges)
        if (range.section >= image.sections.size() ||
            range.begin >= range.end ||
            range.end > image.sections[range.section].size ||
            !(image.sections[range.section].flags & SHF_EXECINSTR))
          return fail(
              "kernel policy source scope exceeds its original section");
      if (block.kind != ct_kernel_source_block_kind::inline_function)
        continue;
      if (policy.inlines.size() >= policy_pool_limit ||
          block.header.find('\0') != std::string::npos)
        return fail("kernel policy inline inventory exceeds its bound");
      const auto decision = resolve(block.header);
      inline_index.emplace(index, policy.inlines.size());
      policy.inlines.push_back({index, decision.first, decision.second});
    }
  }
  for (size_t index = 1; index < policy.functions.size(); ++index) {
    auto &function = policy.functions[index];
    for (unsigned flags = 0; flags < 8; ++flags)
      function.states[flags] = kctrace_policy_encode(kctrace_policy_enter(
          kctrace_policy_decode(flags), function.mode, function.within));
  }
  std::map<std::pair<uint32_t, uint32_t>, uint32_t> paths;
  size_t memberships = 0;
  for (size_t index = 1; index < originals.size(); ++index) {
    if (!originals[index]) {
      if (scope_sites && (*scope_sites)[index])
        return fail("kernel policy bridge references an absent instruction");
      continue;
    }
    const auto target = scope_sites ? (*scope_sites)[index] : index;
    if (!target)
      continue;
    if (target >= originals.size() || !originals[target] ||
        policy.sites[target].function != policy.sites[index].function)
      return fail("kernel policy scope bridge leaves its original function");
    if (!source || target >= source->sites.size())
      continue;
    const auto &site = source->sites[target];
    if (site.function >= source->functions.size() ||
        (!site.function && !site.blocks.empty()) ||
        site.blocks.size() > policy_depth_limit ||
        site.blocks.size() > policy_membership_limit - memberships)
      return fail("kernel policy scope membership exceeds its bound");
    memberships += site.blocks.size();
    std::set<uint64_t> seen;
    uint32_t path = 0;
    uint64_t parent = 0;
    for (const auto block : site.blocks) {
      if (!block || block >= source->blocks.size() ||
          !seen.insert(block).second ||
          source->blocks[block].function != site.function)
        return fail("invalid kernel policy scope membership");
      if (source->blocks[block].parent &&
          source->blocks[block].parent != parent)
        return fail("kernel policy scope path is not in parent order");
      parent = block;
      const auto &ranges = source->blocks[block].ranges;
      const auto *original = originals[target];
      if (std::none_of(ranges.begin(), ranges.end(), [&](const auto &range) {
            return range.section == original->section &&
                   range.begin <= original->offset &&
                   original->offset < range.end;
          }))
        return fail("kernel policy scope membership has no original range");
      const auto inlined = inline_index.find(block);
      if (inlined == inline_index.end())
        continue;
      const auto key = std::make_pair(path, inlined->second);
      const auto found = paths.find(key);
      if (found != paths.end()) {
        path = found->second;
      } else {
        if (policy.paths.size() >= policy_membership_limit)
          return fail("kernel policy inline paths exceed their bound");
        const auto id = uint32_t(policy.paths.size());
        ct_kernel_policy_path prepared{path, inlined->second};
        const auto &scope = policy.inlines[inlined->second];
        for (unsigned flags = 0; flags < 8; ++flags) {
          const auto parent = kctrace_policy_decode(
              path ? policy.paths[path].states[flags] : flags);
          prepared.states[flags] = kctrace_policy_encode(
              kctrace_policy_enter(parent, scope.mode, scope.within));
        }
        policy.paths.push_back(prepared);
        paths.emplace(key, id);
        path = id;
      }
    }
    policy.sites[index].path = path;
  }
  return true;
}
