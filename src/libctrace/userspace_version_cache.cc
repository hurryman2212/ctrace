// SPDX-License-Identifier: MIT

#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

#include "analysis.hh"
#include "userspace_version_cache.hh"

struct UserspaceTemplateArchive {
  std::vector<unsigned char> &bytes;
  explicit UserspaceTemplateArchive(std::vector<unsigned char> &storage)
      : bytes(storage) {
    bytes.clear();
  }
  size_t position = 0;
  bool valid = true;

  void put(uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      bytes.push_back(uint8_t(value >> shift));
  }
  uint64_t get() {
    if (!valid || position > bytes.size() || bytes.size() - position < 8) {
      valid = false;
      return 0;
    }
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
      value |= uint64_t(bytes[position++]) << shift;
    return value;
  }
  bool complete() const { return valid && position == bytes.size(); }
  bool load(const char *family, const std::string &key, size_t limit) {
    if (key.empty())
      return false;
    unsigned char *allocation = nullptr;
    size_t size = 0;
    if (!ct_analysis_cache_read(family, key.c_str(), &allocation, &size))
      return false;
    std::unique_ptr<unsigned char, decltype(&std::free)> data(allocation,
                                                              std::free);
    if (!data || !size || size > limit)
      return false;
    bytes.assign(data.get(), data.get() + size);
    return true;
  }
};

bool ct_userspace_template_identify(
    const ct_userspace_version_cache *cache, ct_instrument_level level,
    size_t gate_size, const ct_userspace_version_instruction *instructions,
    size_t count, ct_userspace_template_keys &keys) {
  keys = {};
  if (!cache || !cache->identity || !*cache->identity || !cache->module_base ||
      !cache->module_size ||
      cache->module_size > UINTPTR_MAX - uintptr_t(cache->module_base) ||
      !instructions || !count || !gate_size || gate_size > 64)
    return false;
  UserspaceTemplateArchive image(keys.scratch);
  image.put(cache->module_size);
  image.put(count);
  for (size_t index = 0; index < count; ++index) {
    const auto &instruction = instructions[index];
    if (instruction.pc < cache->module_base || !instruction.length ||
        instruction.length > sizeof(instruction.bytes))
      return false;
    const uint64_t offset = instruction.pc - cache->module_base;
    if (offset >= cache->module_size ||
        instruction.length > cache->module_size - offset)
      return false;
    image.put(offset);
    image.put(instruction.length);
    image.bytes.insert(image.bytes.end(), instruction.bytes,
                       instruction.bytes + instruction.length);
  }
  auto &common = keys.identity;
  common = "userspace-emitter-common:" +
           std::to_string(std::strlen(cache->identity)) + ":" +
           cache->identity + ":amd64:" + std::to_string(sizeof(void *)) + ":" +
           std::to_string(gate_size) + ":" +
           std::to_string(dr_is_fsgsbase_enabled()) + ":" +
           std::to_string(proc_has_feature(FEATURE_AVX)) + ":" +
           std::to_string(proc_has_feature(FEATURE_AVX512F)) + ":";
  if (cache->runtime_identity)
    common += std::to_string(std::strlen(cache->runtime_identity)) + ":" +
              cache->runtime_identity + ":";
  static constexpr char hexadecimal[] = "0123456789abcdef";
  for (const auto byte : image.bytes) {
    common += hexadecimal[byte >> 4];
    common += hexadecimal[byte & 15];
  }
  char digest[65]{};
  if (!ct_analysis_cache_digest(common.c_str(), digest))
    return false;
  keys.common = digest;
  keys.family = std::string("execution/") + ct_instrument_level_name(level);
  const char *policy = cache->policy ? cache->policy : "";
  keys.index = "userspace-emitter-layout:" + keys.common + ":" +
               ct_instrument_level_name(level) + ":" +
               std::to_string(std::strlen(policy)) + ":" + policy + ":";
  for (size_t index = 0; index < count; ++index)
    keys.index += char('0' + unsigned(instructions[index].boundary) +
                       2 * unsigned(instructions[index].call_safe));
  return true;
}

bool ct_userspace_template_load_common(
    const ct_userspace_template_keys &keys,
    const ct_userspace_version_instruction *instructions, size_t count,
    std::vector<ct_userspace_instruction_template> &templates) {
  templates.clear();
  if (!instructions || !count || count > (SIZE_MAX - 16) / (48 + 15 * 8))
    return false;
  UserspaceTemplateArchive record(keys.scratch);
  // Two header words, then six fields and at most fifteen encoding tokens
  // per instruction. Reject oversized generic cache blobs before copying.
  if (!record.load("execution/objects", keys.common,
                   16 + count * (48 + 15 * 8)) ||
      record.get() != UINT64_C(0x00504d5445535543) || record.get() != count)
    return false;
  std::vector<ct_userspace_instruction_template> result(count);
  for (size_t index = 0; index < count; ++index) {
    auto &instruction = result[index];
    const uint64_t flags = record.get(), length = record.get(),
                   kind = record.get(), offset = record.get();
    instruction.target = int64_t(record.get());
    const uint64_t tokens = record.get();
    if (!record.valid || flags > 7 || length > 15 || kind > 2 ||
        offset > length || (tokens && tokens != length))
      return false;
    instruction.dr_only = flags & 1;
    instruction.branch = flags & 2;
    instruction.fallthrough = flags & 4;
    instruction.length = length;
    instruction.relocation =
        ct_userspace_instruction_template::Relocation(kind);
    instruction.relocation_offset = offset;
    if (instruction.dr_only) {
      if (length || kind || tokens || offset || instruction.target)
        return false;
    } else if (!length || (!tokens && length != instructions[index].length) ||
               (instruction.branch !=
                (kind == ct_userspace_instruction_template::InternalBranch)) ||
               (kind && (length < 4 || offset > length - 4)) ||
               (!kind && (offset || instruction.target)) ||
               (kind == ct_userspace_instruction_template::InternalBranch &&
                (instruction.target < 0 ||
                 uint64_t(instruction.target) >= count)) ||
               (kind == ct_userspace_instruction_template::RipRelative &&
                (instruction.target < INT32_MIN ||
                 instruction.target > int64_t(INT32_MAX) + 15)))
      return false;
    for (size_t token = 0; token < tokens; ++token) {
      const uint64_t value = record.get();
      if (!record.valid || value >= 256 + instructions[index].length)
        return false;
      instruction.encoding.push_back(uint16_t(value));
    }
  }
  if (!record.complete())
    return false;
  templates = std::move(result);
  return true;
}

void ct_userspace_template_store_common(
    const ct_userspace_template_keys &keys,
    const std::vector<ct_userspace_instruction_template> &templates) {
  if (keys.common.empty())
    return;
  UserspaceTemplateArchive record(keys.scratch);
  record.put(UINT64_C(0x00504d5445535543));
  record.put(templates.size());
  for (const auto &instruction : templates) {
    record.put((instruction.dr_only ? 1 : 0) | (instruction.branch ? 2 : 0) |
               (instruction.fallthrough ? 4 : 0));
    record.put(instruction.length);
    record.put(instruction.relocation);
    record.put(instruction.relocation_offset);
    record.put(uint64_t(instruction.target));
    record.put(instruction.encoding.size());
    for (const auto token : instruction.encoding)
      record.put(token);
  }
  ct_analysis_cache_write("execution/objects", keys.common.c_str(),
                          record.bytes.data(), record.bytes.size());
}

bool ct_userspace_template_load_layout(
    const ct_userspace_template_keys &keys, ct_instrument_level level,
    size_t gate_size, const ct_userspace_version_instruction *instructions,
    const std::vector<ct_userspace_instruction_template> &templates,
    std::vector<ct_userspace_template_layout> &layout, size_t &used) {
  layout.clear();
  used = 0;
  if (!instructions || templates.empty() ||
      templates.size() > (SIZE_MAX - 104) / 40)
    return false;
  UserspaceTemplateArchive record(keys.scratch);
  // Five header words, a 64-byte digest, and five words per instruction.
  if (!record.load(keys.family.c_str(), keys.index,
                   104 + templates.size() * 40) ||
      record.get() != UINT64_C(0x0059414c45535543) ||
      record.get() != templates.size() || record.get() != uint64_t(level) ||
      record.get() != gate_size)
    return false;
  const uint64_t bytes = record.get();
  if (!record.valid || !bytes || bytes > INT32_MAX ||
      record.bytes.size() - record.position < 64 ||
      std::memcmp(record.bytes.data() + record.position, keys.common.data(),
                  64))
    return false;
  record.position += 64;
  std::vector<ct_userspace_template_layout> result(templates.size());
  size_t previous = 0, copied = 0;
  for (size_t index = 0; index < result.size(); ++index) {
    auto &node = result[index];
    const uint64_t ingress = record.get(), entry = record.get(),
                   operation = record.get(), successor = record.get(),
                   gate = record.get();
    const auto &instruction = templates[index];
    const bool expected_gate =
        instruction.dr_only || instructions[index].boundary;
    if (!record.valid || gate > 2 || bool(gate) != expected_gate ||
        (gate == 2 &&
         (instruction.dr_only || !instructions[index].call_safe)) ||
        ingress != previous || ingress >= bytes || entry >= bytes ||
        operation >= bytes || successor >= bytes)
      return false;
    node = {size_t(ingress), size_t(entry), size_t(operation),
            size_t(successor), uint8_t(gate)};
    previous = ingress + (gate == 2 ? 5 : gate ? gate_size : 0);
    if (instruction.dr_only) {
      if (entry || operation || successor)
        return false;
      continue;
    }
    ++copied;
    if (operation != previous || successor != operation + instruction.length)
      return false;
    previous = successor;
    const bool exits =
        instruction.fallthrough &&
        (index + 1 == templates.size() ||
         instructions[index + 1].pc !=
             instructions[index].pc + instructions[index].length);
    if (exits)
      previous += gate_size;
  }
  if (!copied)
    return false;
  for (size_t index = 0; index < result.size(); ++index) {
    if (templates[index].dr_only)
      continue;
    if (result[index].entry != previous || previous > bytes ||
        bytes - previous < 9)
      return false;
    previous += 9;
  }
  if (previous != bytes || !record.complete())
    return false;
  used = bytes;
  layout = std::move(result);
  return true;
}

void ct_userspace_template_store_layout(
    const ct_userspace_template_keys &keys, ct_instrument_level level,
    size_t gate_size, const std::vector<ct_userspace_template_layout> &layout,
    size_t used) {
  if (keys.index.empty())
    return;
  UserspaceTemplateArchive record(keys.scratch);
  record.put(UINT64_C(0x0059414c45535543));
  record.put(layout.size());
  record.put(uint64_t(level));
  record.put(gate_size);
  record.put(used);
  record.bytes.insert(record.bytes.end(), keys.common.begin(),
                      keys.common.end());
  for (const auto &node : layout) {
    record.put(node.ingress);
    record.put(node.entry);
    record.put(node.operation);
    record.put(node.successor);
    record.put(node.gate);
  }
  ct_analysis_cache_write(keys.family.c_str(), keys.index.c_str(),
                          record.bytes.data(), record.bytes.size());
}
