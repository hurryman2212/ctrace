// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_REWRITE_H
#define CTRACE_KERNEL_REWRITE_H

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "image.hh"

struct ct_kernel_policy;

struct ct_kernel_site {
  uint32_t section = 0;
  uint64_t offset = 0, entry = 0, operation = 0;
  uint64_t id = 0;
  uint8_t original_size = 0, emitted_size = 0;
  bool probe = false;
};

enum class ct_kernel_copy_level : uint8_t { arm, perfetto, full };

enum class ct_kernel_copy_failure { none, unsupported, invalid };

struct ct_kernel_copy_address {
  uint32_t section = 0;
  uint64_t offset = 0;
};

struct ct_kernel_copy_location {
  ct_kernel_copy_address entry, operation;
  uint8_t emitted_size = 0;
  bool probe = false;
};

struct ct_kernel_copy_site {
  uint32_t function = 0;
  // The ID and input address always identify the original instruction.
  uint64_t id = 0;
  ct_kernel_copy_address original;
  std::array<ct_kernel_copy_location, 3> levels;
};

struct ct_kernel_copy_section {
  uint32_t index = 0, original_section = 0;
  std::string name;
  uint64_t flags = 0, alignment = 0;
  // Canonical sections retain the original section index. Three-copy bodies
  // have new indexes. SINGLE_FULL combines canonical entries and one body in
  // each original executable section.
  bool canonical = false;
  ct_kernel_copy_level level = ct_kernel_copy_level::arm;
  std::vector<unsigned char> bytes;
};

enum class ct_kernel_copy_relocation_kind : uint8_t {
  address,
  original_symbol,
  selector,
  perfetto_probe,
  full_probe
};

struct ct_kernel_copy_relocation {
  ct_kernel_copy_address source, target;
  ct_kernel_copy_relocation_kind kind = ct_kernel_copy_relocation_kind::address;
  uint32_t type = 0, symbol_table = 0, symbol = 0;
  int64_t addend = 0;
};

struct ct_kernel_copy_symbol {
  uint32_t table = 0, index = 0;
  ct_kernel_copy_address address;
  uint64_t size = 0;
};

enum class ct_kernel_copy_boundary_kind : uint8_t {
  entry,
  scope,
  call_before,
  call_after,
  call_unpaired,
  return_,
  tail,
  indirect,
  unknown_control
};

struct ct_kernel_copy_boundary {
  ct_kernel_copy_boundary_kind kind = ct_kernel_copy_boundary_kind::scope;
  uint32_t function = 0, path = 0, target_function = 0;
  uint64_t site_id = 0, related_site_id = 0;
  uint8_t target_register = 0;
  // Original address-taking establishes a possible indirect interior entry.
  bool address_taken = false;
  ct_kernel_copy_address original, entry, selector_return, call_return;
  std::array<ct_kernel_copy_address, 3> call_returns;
  std::array<ct_kernel_copy_address, 3> continuations;
};

struct ct_kernel_copy_function {
  uint32_t function = 0;
  ct_kernel_copy_address canonical;
  uint64_t size = 0;
  std::array<uint64_t, 3> body_sizes{};
  std::array<ct_kernel_copy_address, 3> bodies;
};

// An offline assembly artifact, deliberately not a loadable ELF or runtime
// ABI. Its section indexes share the input image's index space; new sections
// start at image.sections.size(). Relocations retain ordinary ELF equations.
// Helper imports are typed placeholders until the runtime contract is bound.
// Original nonexecutable sections remain in the input image. Their relocation
// records are included here, while original executable relocations are replaced
// by the per-copy records. Original code symbols are replaced by symbols below.
struct ct_kernel_copies {
  // A single FULL body uses the same policy and boundary representation.
  // All level maps alias that body; no ARM/PERFETTO code is emitted.
  bool single_full = false;
  uint32_t minimum_level = 0;
  // Physical floor indexed by policy function; logical fragments agree.
  std::vector<uint8_t> function_levels;
  struct restriction {
    uint32_t function;
    ct_kernel_copy_address original;
    std::string reason;
  };
  std::vector<restriction> restrictions;
  std::vector<ct_kernel_copy_section> sections;
  std::vector<ct_kernel_copy_site> sites;
  std::vector<ct_kernel_copy_function> functions;
  std::vector<ct_kernel_copy_symbol> symbols;
  std::vector<ct_kernel_copy_relocation> relocations;
  std::vector<ct_kernel_copy_boundary> boundaries;
  // These original sections (and their RELA sections) must be removed before
  // the existing objtool/module-link validation regenerates them. In
  // particular, old ORC records cannot describe any emitted gate or body.
  std::vector<uint32_t> regenerate_sections;
  // Terminal CALLs retain their original instruction and a pending frame.
  // Final objtool validation must prove that this control flow never returns;
  // there is no invented AFTER boundary, trap, or function-completion event.
  bool requires_noreturn_validation = false;
};

struct ct_kernel_xstate_site {
  // A definite kernel_fpu_begin/end region, including directly called bodies.
  bool owned = false;
  // FPU bits match XSAVE; spare bits 3/4 represent TILECFG/TILEDATA (17/18).
  uint8_t components = 0;
};

// Owns only decoded instruction plans, not LLVM objects or an image copy.
// Analysis uses section/offset/id/original_size/probe; the other fields retain
// the projected full layout until separate emitted-copy maps are required.
// emit() requires the same original bytes and inventory passed to prepare().
class ct_kernel_rewrite_plan {
  struct Data;
  std::unique_ptr<Data> data;

public:
  ct_kernel_rewrite_plan();
  ~ct_kernel_rewrite_plan();
  ct_kernel_rewrite_plan(const ct_kernel_rewrite_plan &) = delete;
  ct_kernel_rewrite_plan &operator=(const ct_kernel_rewrite_plan &) = delete;

  bool prepare(const ct_kernel_image &image, std::vector<ct_kernel_site> &sites,
               std::string &error, const std::function<void()> &on_miss = {});
  // Only AMX data sites need a sparse physical-tile mask. Passive scalar
  // components use their architectural bit positions in a separate sparse map;
  // these do not claim floating-point ownership.
  bool xstate_sites(const ct_kernel_image &image,
                    std::vector<ct_kernel_xstate_site> &sites,
                    std::string &error,
                    std::map<uint64_t, uint8_t> *tiles = nullptr,
                    std::map<uint64_t, uint32_t> *scalar = nullptr) const;
  bool emit(const ct_kernel_image &image, std::vector<unsigned char> &output,
            std::string &error,
            const std::function<void()> &on_miss = {}) const;
  // Numeric policy must describe these same original instruction identities.
  // timing_sites adds original probe IDs at display-scope changes within a
  // basic block; no source/decompiler trees are copied into the artifact.
  // noreturn_symbols comes from the selected kernel's objtool inputs, not a
  // built-in name heuristic. Only exact undefined direct-call targets match.
  // Unsupported metadata/control flow is rejected without a partial artifact.
  // A caller may retry unsupported three-copy input with single_full=true;
  // invalid covers malformed facts and internal failures. SINGLE_FULL keeps
  // the same numeric policy/boundaries and one physical FULL body. Neither
  // mode bypasses objtool or final artifact validation.
  // Successful emission does not authorize loading or LEVEL_SELECTION.
  // observation_sites, when supplied, selects FULL body snapshots by original
  // ID. Boundary gates and perfetto/scope leaders remain independently kept.
  bool emit_copies(const ct_kernel_image &image, const ct_kernel_policy &policy,
                   ct_kernel_copies &copies, std::string &error,
                   const std::vector<uint64_t> &timing_sites = {},
                   const std::vector<std::string> &noreturn_symbols = {},
                   ct_kernel_copy_failure *failure = nullptr,
                   bool single_full = false,
                   const std::vector<uint8_t> *observation_sites = nullptr,
                   unsigned minimum_level = 0) const;
};

// Produces the expanded relocatable code and its original-PC map. A later pass
// must bind the manifest/init/exit hooks and verify loader/objtool metadata;
// successful expansion alone never authorizes loading the resulting module.
bool ct_kernel_expand(const ct_kernel_image &image,
                      std::vector<unsigned char> &output,
                      std::vector<ct_kernel_site> &sites, std::string &error,
                      const std::function<void()> &on_miss = {});

#endif
