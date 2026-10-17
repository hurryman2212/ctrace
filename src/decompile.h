#ifndef CTRACE_DECOMPILE_H
#define CTRACE_DECOMPILE_H

#include <cstdint>
#include <vector>

#include "analysis.h"

struct ct_decompile_module;

ct_decompile_module *ct_decompile_open(const char *path, uint64_t link_base,
                                       const char *analysis_identity = nullptr,
                                       int module_fd = -1);
void ct_decompile_close(ct_decompile_module *module);
bool ct_decompile_lookup(ct_decompile_module *module, uint64_t offset,
                         uint32_t level, ct_decompiled_statement *statement);
bool ct_decompile_proof(ct_decompile_module *module, uint64_t offset,
                        uint32_t level, std::vector<unsigned char> &proof);
bool ct_decompile_display(ct_decompile_module *module, uint64_t offset,
                          uint32_t level, ct_decompiled_display *display);
bool ct_decompile_variables(ct_decompile_module *module, uint64_t offset,
                            uint32_t level, ct_decompiled_variables *variables);
const char *ct_decompile_error(const ct_decompile_module *module);

#endif
