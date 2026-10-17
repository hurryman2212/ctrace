#ifndef CTRACE_KERNEL_PREPARE_VALIDATE_H
#define CTRACE_KERNEL_PREPARE_VALIDATE_H

#include <array>
#include <cstdint>
#include <string>

#include "kernel_prepare.h"

// Exact Kbuild tuple: sizeof(kernel_param), offsetof(ops),
// sizeof(kernel_param_ops), offsetof(free). No host-kernel layout guesses.
bool ct_kernel_validate_parameters(const ct_kernel_image &image,
                                   const std::array<uint64_t, 4> &layout,
                                   std::string &error);

// Validate the final linked, objtool-checked template again on cache reuse.
// Layout is sizeof(module), offsetof(init), offsetof(exit) from the same kernel
// build. Derive the manifest file offset and template digest from actual bytes.
bool ct_kernel_validate_prepared(
    const ct_kernel_image &original, ct_kernel_prepared &prepared,
    const std::array<uint64_t, 3> &layout,
    const std::array<uint64_t, 4> &parameter_layout, std::string &error,
    const ct_kernel_copies *copies = nullptr);

#endif
