// SPDX-License-Identifier: MIT

#ifndef CTRACE_FLOW_H
#define CTRACE_FLOW_H

#include <cstdint>
#include <functional>
#include <map>
#include <vector>

#include <llvm/ADT/ArrayRef.h>

#include "analysis.hh"

struct ct_flow_analysis {
  std::map<uint64_t, uint32_t> roles;
  std::map<uint64_t, uint64_t> groups;
  std::vector<ct_flow_region> regions;
  std::vector<ct_flow_switch> switches;
  std::vector<ct_flow_instruction> instructions;
  std::vector<ct_flow_edge> edges;
  bool complete = false;
};

/* These helpers only read supplied original bytes. They do not load source
 * text, evaluate variables, or invoke a decompiler. */
bool ct_decode_code_range(llvm::ArrayRef<unsigned char> bytes, uint64_t offset,
                          std::vector<ct_decompiled_instruction> &instructions);
bool ct_build_code_proof(
    uint64_t function_offset, uint32_t loaded_level,
    const std::vector<ct_decompiled_range> &ranges,
    const std::vector<ct_decompiled_instruction> &instructions,
    std::vector<unsigned char> &proof);

/* Addresses are object virtual addresses. An undecoded branch frontier never
 * becomes a proven function exit, even with known symbol bounds. Groups map
 * each boundary to the lowest boundary address in its control region. Regions
 * sharing a boundary merge so that an address always has a single color. */
ct_flow_analysis ct_analyze_flow(
    llvm::ArrayRef<unsigned char> bytes, uint64_t begin, uint64_t entry,
    const std::function<bool(uint64_t, size_t, std::vector<unsigned char> &)>
        &read = {});

#endif
