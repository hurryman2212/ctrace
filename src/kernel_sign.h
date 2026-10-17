#ifndef CTRACE_KERNEL_SIGN_H
#define CTRACE_KERNEL_SIGN_H

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

struct ct_kernel_sign_options {
  std::string kernel_build, key, certificate;
  std::string hash;
};

// Check the appended module_signature trailer and DER SignedData envelope.
// Returns appended bytes including the trailer; does not establish trust or
// cryptographic validity. Input bytes remain unchanged, and failure sets zero.
bool ct_kernel_signature_size(const std::vector<unsigned char> &bytes,
                              size_t &appended_size, std::string &error);

// Extract a canonical digest name (or numeric OID for an unknown digest) from
// one detached CMS SignedData signer. Format validity does not establish
// signing compatibility, cryptographic validity, or certificate trust.
// Failure clears hash; input bytes remain unchanged.
bool ct_kernel_signature_hash(const std::vector<unsigned char> &bytes,
                              std::string &hash, std::string &error);

// Resolve an explicit hash without fallback, or choose a compatible hash in
// original/kernel-default/SHA256/remaining-supported order. Credentials are
// checked in a bounded child; disposable sign-file probes are never cached.
// Only success replaces options.hash with the selected canonical name.
bool ct_kernel_select_sign_hash(ct_kernel_sign_options &options,
                                std::string_view original_hash,
                                std::string_view kernel_hash,
                                std::string &error);

// Sign only the final, session-bound unsigned module. On failure bytes remain
// unchanged. No key/PIN or signed artifact is cached; the kernel decides trust.
bool ct_kernel_sign_module(const ct_kernel_sign_options &options,
                           std::vector<unsigned char> &bytes,
                           std::string &error);

#endif
