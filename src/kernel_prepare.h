#ifndef CTRACE_KERNEL_PREPARE_H
#define CTRACE_KERNEL_PREPARE_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "uapi/kctrace.h"

#include "kernel_capture.h"
#include "kernel_image.h"
#include "kernel_rewrite.h"
#include "kernel_trace.h"

struct ct_kernel_decompile_metadata;
struct ct_kernel_interrupt_proof;

struct ct_kernel_prepare_options {
  std::string kernel_build;
  // Flat directory containing unchanged target.c, target.h and kctrace.h.
  std::string resource_root;
  // Identity of the actual loaded runtime, not an installed filename.
  // Empty identity permits preparation but disables persistent template reuse.
  std::string runtime_identity;
  std::function<void(const std::string &)> progress;
  ct_kernel_source_options source;
  // The actual prepared metadata replaces any caller-supplied observations.
  ct_kernel_trace_options observation;
  // Enable the prebuilt three-copy runtime only after capability negotiation.
  bool level_selection = false;
  bool perfetto = false;
  bool decompile = false;
  bool signing = false;
  std::string analysis_helper;
};

struct ct_kernel_prepared {
  std::vector<unsigned char> bytes;
  std::vector<ct_kernel_site> sites;
  std::string module_name, original_digest, template_digest, kernel_identity;
  std::string default_signature_hash;
  uint64_t manifest_offset = 0, probe_count = 0;
  bool cache_hit = false;
  bool level_selection = false;
  uint32_t program_flags = 0;
  // Current Kbuild compiler flags, without ephemeral input/output paths.
  std::vector<std::string> compiler_arguments;
  std::shared_ptr<const ct_kernel_source_metadata> source;
  std::shared_ptr<const ct_kernel_value_metadata> values;
  std::shared_ptr<const ct_kernel_decompile_metadata> decompile;
  std::shared_ptr<const ct_kernel_interrupt_proof> interrupt;
  // Index zero is unavailable; serialized module plans omit that sentinel.
  std::shared_ptr<const std::vector<ct_kernel_capture_plan>> captures;
  // Prepared before any code copy is emitted, including numeric scope policy.
  std::shared_ptr<ct_kernel_trace> trace;
};

// Fully prepares an unsigned relocatable template. Never loads a module.
bool ct_kernel_prepare(const ct_kernel_image &image,
                       const ct_kernel_prepare_options &options,
                       ct_kernel_prepared &prepared, std::string &error);

// Fills the entire zeroed manifest using the kernel-prepared session identity.
// Signing and verification of the final bound bytes remain the loader's job.
bool ct_kernel_bind_prepared(const ct_kernel_prepared &prepared,
                             const kctrace_prepare &session,
                             std::vector<unsigned char> &bound,
                             std::string &error);

#endif
