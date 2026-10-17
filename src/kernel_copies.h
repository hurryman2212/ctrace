#ifndef CTRACE_KERNEL_COPIES_H
#define CTRACE_KERNEL_COPIES_H

#include <cstdint>
#include <string>
#include <vector>

struct ct_kernel_image;
struct ct_kernel_policy;
struct ct_kernel_copies;
struct ct_kernel_interrupt_proof;

// Materialize the offline copy graph as an ordinary x86-64 ET_REL object.
// Original section/symbol indexes retain their identities. Success is only an
// assembly step: runtime binding, objtool metadata and final module validation
// remain mandatory before loading the result.
// capture_plans is empty or indexed by original site ID, with element zero
// unused. Only full probes and entry/exit boundary snapshots use these plans.
bool ct_kernel_materialize_copies(
    const ct_kernel_image &image, const ct_kernel_policy &policy,
    const ct_kernel_copies &copies, uint32_t program_flags,
    const std::vector<uint32_t> &capture_plans,
    std::vector<unsigned char> &output, std::string &error,
    const ct_kernel_interrupt_proof *interrupt = nullptr);

#endif
