// SPDX-License-Identifier: MIT

#ifndef CTRACE_ANALYSIS_FILES_H
#define CTRACE_ANALYSIS_FILES_H

#include <functional>
#include <memory>
#include <string>
#include <system_error>

#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/VirtualFileSystem.h>

#include "analysis_protocol.hh"

struct ct_analysis_file_result {
  // A successful READ/STATUS transfers ownership of one CLOEXEC descriptor.
  int descriptor = -1;
  std::string path;
  std::error_code error;
};
using ct_analysis_file_callback = std::function<ct_analysis_file_result(
    ct_analysis_file_operation, const std::string &)>;

// Set once when connecting a worker. Without a callback, standalone analysis
// uses its own filesystem; a remote failure never falls back to that namespace.
void ct_analysis_set_filesystem(ct_analysis_file_callback callback);
bool ct_analysis_remote_filesystem();
ct_analysis_file_result ct_analysis_file_access(ct_analysis_file_operation kind,
                                                const std::string &path = {});
llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>>
ct_analysis_read_file(const std::string &path);
std::string ct_analysis_file_key(const std::string &path, bool listing = false);
llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> ct_analysis_filesystem();

#endif
