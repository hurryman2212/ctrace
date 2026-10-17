#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

#include "analysis.h"
#include "execution_cache.h"

static constexpr size_t execution_batch_byte_limit = 4 * 1024 * 1024;
// Schema, entry count, level, original-image digest, and index-policy digest.
static constexpr size_t execution_batch_header_size = 16 + 1 + 64 + 64;

struct ExecutionCacheKeys {
  std::string kind;
  std::string index;
  char object[65]{};
  std::vector<unsigned char> image;
};

static bool
execution_keys(const std::string &identity, const std::string &policy,
               ct_instrument_level level, uint64_t module_size,
               const std::vector<ct_execution_instruction> &instructions,
               ExecutionCacheKeys &keys) {
  if (identity.empty() || policy.empty() || !module_size ||
      instructions.empty() ||
      instructions.size() > ct_execution_instruction_limit)
    return false;
  switch (level) {
  case ct_instrument_level::arm:
  case ct_instrument_level::perfetto:
  case ct_instrument_level::full:
    break;
  default:
    return false;
  }
  keys.kind = std::string("execution/") + ct_instrument_level_name(level);
  const auto number = [&](uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      keys.image.push_back(uint8_t(value >> shift));
  };
  number(1); // Original-instruction image schema, shared by every level.
  number(module_size);
  number(instructions.size());
  for (const auto &instruction : instructions) {
    if (!instruction.length || instruction.length > sizeof(instruction.bytes) ||
        instruction.offset >= module_size ||
        instruction.length > module_size - instruction.offset)
      return false;
    number(instruction.offset);
    keys.image.push_back(instruction.length);
    keys.image.insert(keys.image.end(), instruction.bytes,
                      instruction.bytes + instruction.length);
  }
  std::string key = "execution-image-v1:" + std::to_string(identity.size()) +
                    ":" + identity + ":";
  static constexpr char hexadecimal[] = "0123456789abcdef";
  for (const auto byte : keys.image) {
    key += hexadecimal[byte >> 4];
    key += hexadecimal[byte & 15];
  }
  if (!ct_analysis_cache_digest(key.c_str(), keys.object))
    return false;
  keys.index = "execution-index-v1:" + std::string(keys.object) + ":" +
               std::to_string(policy.size()) + ":" + policy;
  return true;
}

bool ct_execution_cache_load(
    const std::string &identity, const std::string &policy,
    ct_instrument_level level, uint64_t module_size,
    const std::vector<ct_execution_instruction> &instructions,
    std::vector<ct_execution_recipe> &recipes) {
  recipes.clear();
  ExecutionCacheKeys keys;
  if (!execution_keys(identity, policy, level, module_size, instructions, keys))
    return false;
  unsigned char *allocation = nullptr;
  size_t size = 0;
  if (!ct_analysis_cache_read(keys.kind.c_str(), keys.index.c_str(),
                              &allocation, &size))
    return false;
  std::unique_ptr<unsigned char, decltype(&std::free)> index(allocation,
                                                             std::free);
  // Two uint64_t fields, a level byte, and the 64-character object identity.
  const size_t header_size = 16 + 1 + 64;
  if (!index || size != header_size + instructions.size())
    return false;
  size_t position = 0;
  const auto number = [&]() -> uint64_t {
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
      value |= uint64_t(index.get()[position++]) << shift;
    return value;
  };
  if (number() != 1 || number() != instructions.size() ||
      index.get()[position++] != static_cast<uint8_t>(level) ||
      std::memcmp(index.get() + position, keys.object, 64))
    return false;
  position += 64;
  std::vector<ct_execution_recipe> restored;
  restored.reserve(instructions.size());
  for (size_t index_number = 0; index_number < instructions.size();
       ++index_number) {
    const uint8_t flags = index.get()[position++];
    if (flags > 15)
      return false;
    restored.push_back(
        {bool(flags & 1), bool(flags & 2), bool(flags & 4), bool(flags & 8)});
  }
  allocation = nullptr;
  size = 0;
  if (!ct_analysis_cache_read("execution/objects", keys.object, &allocation,
                              &size))
    return false;
  std::unique_ptr<unsigned char, decltype(&std::free)> object(allocation,
                                                              std::free);
  // Compare every offset, length and byte with the currently decoded original
  // image. A valid level index alone never authorizes stale machine code.
  if (!object || size != keys.image.size() ||
      std::memcmp(object.get(), keys.image.data(), size))
    return false;
  recipes = std::move(restored);
  return true;
}

bool ct_execution_cache_store(
    const std::string &identity, const std::string &policy,
    ct_instrument_level level, uint64_t module_size,
    const std::vector<ct_execution_instruction> &instructions,
    const std::vector<ct_execution_recipe> &recipes) {
  if (recipes.size() != instructions.size())
    return false;
  ExecutionCacheKeys keys;
  if (!execution_keys(identity, policy, level, module_size, instructions, keys))
    return false;
  unsigned char *allocation = nullptr;
  size_t size = 0;
  const bool found = ct_analysis_cache_read("execution/objects", keys.object,
                                            &allocation, &size);
  std::unique_ptr<unsigned char, decltype(&std::free)> object(allocation,
                                                              std::free);
  const bool identical = found && object && size == keys.image.size() &&
                         !std::memcmp(object.get(), keys.image.data(), size);
  // The immutable common object is published before its level index. Another
  // level or run reuses it without rewriting the original instruction bytes.
  if (!identical &&
      !ct_analysis_cache_write("execution/objects", keys.object,
                               keys.image.data(), keys.image.size()))
    return false;
  std::vector<unsigned char> index;
  const auto number = [&](uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      index.push_back(uint8_t(value >> shift));
  };
  number(1); // Level-index schema.
  number(instructions.size());
  index.push_back(static_cast<uint8_t>(level));
  index.insert(index.end(), keys.object, keys.object + 64);
  for (const auto &recipe : recipes)
    index.push_back(
        (recipe.quiet_transfer ? 1 : 0) | (recipe.inline_scope ? 2 : 0) |
        (recipe.scope_boundary ? 4 : 0) | (recipe.perfetto_boundary ? 8 : 0));
  return ct_analysis_cache_write(keys.kind.c_str(), keys.index.c_str(),
                                 index.data(), index.size());
}

bool ct_execution_batch_open(const std::string &identity,
                             const std::string &policy,
                             ct_instrument_level level, uint64_t module_size,
                             std::vector<ct_execution_instruction> instructions,
                             ct_execution_batch &batch) {
  batch = {};
  for (size_t index = 1; index < instructions.size(); ++index)
    if (instructions[index - 1].offset >= instructions[index].offset)
      return false;
  ExecutionCacheKeys keys;
  if (!execution_keys(identity, policy, level, module_size, instructions, keys))
    return false;
  batch.key = "execution-batch-v1:" + keys.index;
  if (!ct_analysis_cache_digest(batch.key.c_str(), batch.index_digest))
    return false;
  batch.kind = std::move(keys.kind);
  batch.object = keys.object;
  batch.image = std::move(keys.image);
  batch.instructions = std::move(instructions);
  batch.level = level;
  batch.encoded_size = execution_batch_header_size;
  unsigned char *allocation = nullptr;
  size_t size = 0;
  if (!ct_analysis_cache_read(batch.kind.c_str(), batch.key.c_str(),
                              &allocation, &size))
    return true;
  std::unique_ptr<unsigned char, decltype(&std::free)> index(allocation,
                                                             std::free);
  if (!index || size < execution_batch_header_size ||
      size > execution_batch_byte_limit)
    return true;
  size_t position = 0;
  const auto number = [&](unsigned width) {
    uint64_t value = 0;
    for (unsigned byte = 0; byte < width; ++byte)
      value |= uint64_t(index.get()[position++]) << (byte * 8);
    return value;
  };
  const uint64_t schema = number(8), count = number(8);
  if (schema != 1 || !count || count > ct_execution_instruction_limit ||
      index.get()[position++] != static_cast<uint8_t>(level) ||
      std::memcmp(index.get() + position, batch.object.data(), 64) ||
      std::memcmp(index.get() + position + 64, batch.index_digest, 64))
    return true;
  position += 128;
  std::map<std::string, ct_execution_batch::Entry> entries;
  for (uint64_t entry_number = 0; entry_number < count; ++entry_number) {
    if (size - position < 32 + 8)
      return true;
    const std::string key(reinterpret_cast<char *>(index.get() + position), 32);
    position += 32;
    const uint64_t length = number(8);
    if (!length || length > ct_execution_instruction_limit ||
        length > (size - position) / 5)
      return true;
    ct_execution_batch::Entry entry;
    entry.instructions.reserve(length);
    entry.flags.reserve(length);
    for (uint64_t instruction = 0; instruction < length; ++instruction) {
      const uint32_t original = number(4);
      const uint8_t flags = index.get()[position++];
      if (original >= batch.instructions.size() || flags > 15)
        return true;
      entry.instructions.push_back(original);
      entry.flags.push_back(flags);
    }
    if (!entries.emplace(key, std::move(entry)).second)
      return true;
  }
  if (position != size)
    return true;
  allocation = nullptr;
  size_t image_size = 0;
  if (!ct_analysis_cache_read("execution/objects", batch.object.c_str(),
                              &allocation, &image_size))
    return true;
  std::unique_ptr<unsigned char, decltype(&std::free)> image(allocation,
                                                             std::free);
  if (!image || image_size != batch.image.size() ||
      std::memcmp(image.get(), batch.image.data(), image_size))
    return true;
  batch.entries = std::move(entries);
  batch.encoded_size = size;
  return true;
}

bool ct_execution_batch_lookup(
    const ct_execution_batch &batch, const std::string &key,
    const std::vector<ct_execution_instruction> &instructions,
    std::vector<ct_execution_recipe> &recipes) {
  recipes.clear();
  const auto found = batch.entries.find(key);
  if (key.size() != 32 || found == batch.entries.end() ||
      found->second.instructions.size() != instructions.size())
    return false;
  const auto &entry = found->second;
  for (size_t index = 0; index < instructions.size(); ++index) {
    const auto &expected = batch.instructions[entry.instructions[index]];
    const auto &current = instructions[index];
    if (current.offset != expected.offset ||
        current.length != expected.length ||
        std::memcmp(current.bytes, expected.bytes, expected.length))
      return false;
  }
  recipes.reserve(instructions.size());
  for (uint8_t flags : entry.flags)
    recipes.push_back(
        {bool(flags & 1), bool(flags & 2), bool(flags & 4), bool(flags & 8)});
  return true;
}

bool ct_execution_batch_collect(
    ct_execution_batch &batch, const std::string &key,
    const std::vector<ct_execution_instruction> &instructions,
    const std::vector<ct_execution_recipe> &recipes) {
  if (key.size() != 32 || instructions.empty() ||
      instructions.size() != recipes.size() ||
      instructions.size() > ct_execution_instruction_limit)
    return false;
  const auto previous = batch.entries.find(key);
  const size_t old_size =
      previous == batch.entries.end()
          ? 0
          : 32 + 8 + previous->second.instructions.size() * 5;
  const size_t added_size = 32 + 8 + instructions.size() * 5;
  if ((previous == batch.entries.end() &&
       batch.entries.size() >= ct_execution_instruction_limit) ||
      added_size > execution_batch_byte_limit - (batch.encoded_size - old_size))
    return false;
  ct_execution_batch::Entry entry;
  entry.instructions.reserve(instructions.size());
  entry.flags.reserve(instructions.size());
  for (size_t index = 0; index < instructions.size(); ++index) {
    const auto &current = instructions[index];
    const auto original = std::lower_bound(
        batch.instructions.begin(), batch.instructions.end(), current.offset,
        [](const auto &item, uint64_t offset) { return item.offset < offset; });
    if (original == batch.instructions.end() ||
        original->offset != current.offset ||
        original->length != current.length ||
        std::memcmp(original->bytes, current.bytes, original->length))
      return false;
    entry.instructions.push_back(original - batch.instructions.begin());
    const auto &recipe = recipes[index];
    entry.flags.push_back(recipe.quiet_transfer | (recipe.inline_scope << 1) |
                          (recipe.scope_boundary << 2) |
                          (recipe.perfetto_boundary << 3));
  }
  if (previous != batch.entries.end() &&
      previous->second.instructions == entry.instructions &&
      previous->second.flags == entry.flags)
    return true;
  batch.encoded_size = batch.encoded_size - old_size + added_size;
  batch.entries[key] = std::move(entry);
  batch.dirty = true;
  return true;
}

bool ct_execution_batch_store(const ct_execution_batch &batch) {
  if (!batch.dirty)
    return true;
  if (batch.entries.empty() || batch.encoded_size > execution_batch_byte_limit)
    return false;
  unsigned char *allocation = nullptr;
  size_t size = 0;
  const bool found = ct_analysis_cache_read(
      "execution/objects", batch.object.c_str(), &allocation, &size);
  std::unique_ptr<unsigned char, decltype(&std::free)> object(allocation,
                                                              std::free);
  const bool identical = found && object && size == batch.image.size() &&
                         !std::memcmp(object.get(), batch.image.data(), size);
  if (!identical &&
      !ct_analysis_cache_write("execution/objects", batch.object.c_str(),
                               batch.image.data(), batch.image.size()))
    return false;
  std::vector<unsigned char> index;
  index.reserve(batch.encoded_size);
  const auto number = [&](uint64_t value, unsigned width) {
    for (unsigned byte = 0; byte < width; ++byte)
      index.push_back(uint8_t(value >> (byte * 8)));
  };
  number(1, 8);
  number(batch.entries.size(), 8);
  index.push_back(static_cast<uint8_t>(batch.level));
  index.insert(index.end(), batch.object.begin(), batch.object.end());
  index.insert(index.end(), batch.index_digest, batch.index_digest + 64);
  for (const auto &[key, entry] : batch.entries) {
    index.insert(index.end(), key.begin(), key.end());
    number(entry.instructions.size(), 8);
    for (size_t position = 0; position < entry.instructions.size();
         ++position) {
      number(entry.instructions[position], 4);
      index.push_back(entry.flags[position]);
    }
  }
  return index.size() == batch.encoded_size &&
         ct_analysis_cache_write(batch.kind.c_str(), batch.key.c_str(),
                                 index.data(), index.size());
}
