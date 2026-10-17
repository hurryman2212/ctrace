#ifndef CTRACE_CACHE_H
#define CTRACE_CACHE_H

#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

// Helper-process cache. Empty CTRACE_CACHE_DIR disables all cache-file access;
// recent artifacts are retained in a bounded compressed table for reuse.
// Eviction never discards prepared caller-owned analysis or execution objects.
// File contents, not pointers or process addresses, belong in these records.
// Disk records are scoped to the helper, client, dependencies, and the runtime
// identified by CTRACE_DYNAMORIO_PATH. DR-specific recipes require that
// identity.
std::string ct_cache_key(std::initializer_list<std::string_view> parts);
std::string ct_cache_file_key(const std::string &path);
// Strict executable build identity, independent of disk-cache configuration.
// Evidence is decimal device:inode:GNU-build-id for the actual loaded images.
// Initial content hashes are retained; any subsequent file change disables
// sharing for this helper. Runtime selection policy is deliberately excluded.
std::string ct_cache_runtime_identity(std::string_view client_evidence,
                                      std::string_view runtime_evidence);
bool ct_cache_read(const char *kind, const std::string &key,
                   std::vector<unsigned char> &data);
void ct_cache_write(const char *kind, const std::string &key,
                    const std::vector<unsigned char> &data);

#endif
