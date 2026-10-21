// SPDX-License-Identifier: MIT

#ifndef CTRACE_KERNEL_SOURCE_FLOW_H
#define CTRACE_KERNEL_SOURCE_FLOW_H

#include <string>
#include <vector>

#include "dwarf/kernel_source.hh"
#include "dwarf/kernel_values.hh"

// Complete absent DWARF rows only when original register dependencies prove
// their owning source statement. Original coordinates and execution scopes
// remain authoritative; undecidable instructions retain an absent row.
bool ct_kernel_complete_source(const ct_kernel_image &image,
                               const std::vector<ct_kernel_site> &sites,
                               const ct_kernel_value_metadata &values,
                               ct_kernel_source_metadata &source,
                               std::string &error);

#endif
