// SPDX-License-Identifier: BSD-3-Clause AND MIT

/*
 * Text activation is adapted from OverlaySys's x86 patcher_activate_patches
 * (src/patcher/x86/patcher.c): validate preserved text before making a page
 * writable, publish the patch, and restore its original protection. Ctrace
 * selects complete instruction windows or NOP relays for JMP gates. DynamoRIO
 * executes preserved original instructions after the user-space takeover.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <dr_api.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#include "analysis.hh"
#include "shared_digest.hh"
#include "userspace_patch.hh"
#include "userspace_version.hh"

// Fixed buckets keep signal-handler and decoder reads independent of locks.
static constexpr size_t patch_bucket_count = 4096;

struct UserspacePatch;
struct UserspaceGatewayPage;

struct UserspaceByte {
  app_pc pc = nullptr;
  UserspacePatch *patch = nullptr;
  size_t offset = 0;
  size_t instruction_length = 0;
  app_pc logical_pc = nullptr;
  UserspaceByte *next = nullptr;
};

struct UserspacePatch {
  ct_userspace_patch_info information{};
  app_pc begin = nullptr;
  std::vector<byte> original;
  std::vector<byte> replacement;
  size_t readable_size = 0;
  std::vector<UserspaceByte> bytes;
  std::atomic<bool> active{false};
  bool backend_direct = false;
  UserspaceGatewayPage *gateway = nullptr;
  size_t gateway_slot = 0;
  dr_userspace_code_t *call_site = nullptr;
  UserspacePatch *next = nullptr;
};

struct UserspaceGatewayPage {
  app_pc pc = nullptr;
  size_t size = 0;
  // 0 free, 1 reserved, 2 published, 3 retired pending a quiescent reclaim.
  std::vector<unsigned char> slots;
  std::vector<uint64_t> generations;
  UserspaceGatewayPage *next = nullptr;
};

struct UserspaceTextPage {
  app_pc pc;
  uint protection;
};

struct UserspaceInstructionImage {
  app_pc pc;
  size_t length;
  byte original[15];
};

struct UserspaceGatewayReservation {
  UserspaceGatewayPage *page = nullptr;
  size_t slot = 0;
  uint64_t generation = 0;
  std::array<byte, 64> encoding{};
};

struct ct_userspace_patch_plan {
  std::vector<UserspaceInstructionImage> instructions;
  std::vector<UserspaceTextPage> code_pages;
  std::vector<std::unique_ptr<UserspacePatch>> patches;
  std::vector<UserspaceGatewayReservation> gateways;
  std::vector<UserspaceTextPage> pages;
  bool published = false;
  std::array<unsigned char, 32> backend_path{};
  thread_id_t owner = 0;
  ct_userspace_patch_plan *next = nullptr;
};

struct UserspaceGateway {
  UserspacePatch *patch;
  size_t offset;
  app_pc logical_pc;
};

static std::atomic<UserspaceByte *> patch_buckets[patch_bucket_count]{};
static void *patch_lock;
static UserspacePatch *patch_records;
static UserspaceGatewayPage *gateway_pages;
static ct_userspace_patch_plan *gateway_plans;
static thread_id_t gateway_fork_owner;

static std::array<std::atomic<uint64_t>,
                  size_t(ct_userspace_preparation::Count)>
    preparation_statistics{};

void ct_userspace_prepare_note(ct_userspace_preparation event, uint64_t count) {
  preparation_statistics[size_t(event)].fetch_add(count,
                                                  std::memory_order_relaxed);
}

bool ct_userspace_prepare_stat(size_t index, const char **name,
                               uint64_t *count) {
  static constexpr const char *names[] = {"call_selected",
                                          "jmp32_selected",
                                          "jmp8_selected",
                                          "call_stack_unproven",
                                          "call_original_replay_ineligible",
                                          "call_registry_failed",
                                          "call_out_of_reach",
                                          "probe_reused",
                                          "probe_created",
                                          "probe_helpers_direct",
                                          "probe_helpers_indirect",
                                          "probe_address_invalid",
                                          "probe_helpers_unavailable",
                                          "probe_empty_intersection",
                                          "probe_query_failed",
                                          "probe_address_space_occupied",
                                          "probe_allocation_failed",
                                          "probe_encoding_failed",
                                          "probe_protection_failed",
                                          "jmp_slot_reused",
                                          "jmp_page_created",
                                          "jmp_runtime_direct",
                                          "jmp_runtime_indirect",
                                          "jmp_helpers_unavailable",
                                          "jmp_empty_intersection",
                                          "jmp_query_failed",
                                          "jmp_address_space_occupied",
                                          "jmp_allocation_failed",
                                          "jmp_encoding_failed",
                                          "jmp_no_slot",
                                          "patch_window_rejected",
                                          "patch_five_byte_window_rejected",
                                          "patch_two_byte_window_rejected",
                                          "patch_relay_unavailable",
                                          "patch_cached_rejection",
                                          "shared_gates_direct",
                                          "shared_runtime_direct",
                                          "shared_runtime_indirect",
                                          "shared_helpers_unavailable",
                                          "shared_empty_intersection",
                                          "shared_query_failed",
                                          "shared_address_space_occupied",
                                          "shared_allocation_failed"};
  static_assert(std::size(names) == preparation_statistics.size());
  if (index >= std::size(names) || !name || !count)
    return false;
  *name = names[index];
  *count = preparation_statistics[index].load(std::memory_order_relaxed);
  return true;
}

static bool protect_text(app_pc page, size_t size, uint protection) {
  // Temporary protection changes must not initiate an application-code flush:
  // publication and retirement already hold DR's world-stop locks.
  const long prot = (protection & DR_MEMPROT_READ ? PROT_READ : 0) |
                    (protection & DR_MEMPROT_WRITE ? PROT_WRITE : 0) |
                    (protection & DR_MEMPROT_EXEC ? PROT_EXEC : 0);
  long result;
  asm volatile("syscall"
               : "=a"(result)
               : "0"(SYS_mprotect), "D"(page), "S"(size), "d"(prot)
               : "rcx", "r11", "cc", "memory");
  return result == 0;
}

static size_t patch_bucket(app_pc pc) {
  const uintptr_t address = reinterpret_cast<uintptr_t>(pc);
  return ((address >> 4) ^ (address >> 17)) % patch_bucket_count;
}

static UserspaceByte *find_byte(app_pc pc) {
  for (UserspaceByte *byte =
           patch_buckets[patch_bucket(pc)].load(std::memory_order_acquire);
       byte; byte = byte->next)
    if (byte->pc == pc && byte->patch->active.load(std::memory_order_acquire))
      return byte;
  return nullptr;
}

bool ct_userspace_patch_init() {
  if (patch_lock)
    return true;
  patch_lock = dr_mutex_create();
  return patch_lock != nullptr;
}

void ct_userspace_patch_fork_prepare() {
  dr_mutex_lock(patch_lock);
  gateway_fork_owner = dr_get_thread_id(dr_get_current_drcontext());
}

void ct_userspace_patch_fork_parent() { dr_mutex_unlock(patch_lock); }

void ct_userspace_patch_fork_child() {
  // Fork preserves the original image, gateways and cached decoder pointers.
  // Only the copied synchronization object belongs to the new process.
  dr_mutex_reset_after_fork(patch_lock);
  auto **entry = &gateway_plans;
  while (*entry) {
    auto *plan = *entry;
    if (plan->owner == gateway_fork_owner) {
      entry = &plan->next;
      continue;
    }
    for (const auto &reservation : plan->gateways)
      if (reservation.page->slots[reservation.slot] == 1 &&
          reservation.page->generations[reservation.slot] ==
              reservation.generation)
        reservation.page->slots[reservation.slot] = 0;
    for (const auto &patch : plan->patches)
      if (patch->call_site) {
        dr_unregister_userspace_code(patch->call_site);
        patch->call_site = nullptr;
      }
    plan->gateways.clear();
    *entry = plan->next;
    plan->next = nullptr;
  }
}

bool ct_userspace_patch_lookup(app_pc pc,
                               ct_userspace_patch_info *information) {
  UserspaceByte *byte = find_byte(pc);
  if (!byte)
    return false;
  if (information)
    *information = byte->patch->information;
  return true;
}

app_pc ct_userspace_patch_target(app_pc pc) {
  UserspaceByte *byte = find_byte(pc);
  return byte ? byte->logical_pc : nullptr;
}

const byte *ct_userspace_patch_original(app_pc pc, size_t *length) {
  UserspaceByte *byte = find_byte(pc);
  if (!byte || !byte->instruction_length)
    return nullptr;
  if (length)
    *length = byte->instruction_length;
  return byte->patch->original.data() + byte->offset;
}

bool ct_userspace_patch_read_original(app_pc pc, size_t size,
                                      void *destination) {
  if (size > UINTPTR_MAX - reinterpret_cast<uintptr_t>(pc))
    return false;
  size_t read = 0;
  if (!dr_safe_read(pc, size, destination, &read) || read != size)
    return false;
  auto *bytes = static_cast<byte *>(destination);
  for (size_t index = 0; index < size; ++index)
    if (UserspaceByte *original = find_byte(pc + index))
      bytes[index] = original->patch->original[original->offset];
  return true;
}

// These recipes contain offsets and instruction bytes, never executable gateway
// addresses. The helper adds its build identity and verifies the record
// checksum.
static bool recipe_pages(ct_userspace_patch_plan &plan, bool check_bytes) {
  const size_t page_size = dr_page_size();
  std::map<app_pc, uint> pages;
  for (const auto &instruction : plan.instructions) {
    if (check_bytes) {
      byte current[15]{};
      if (!ct_userspace_patch_read_original(instruction.pc, instruction.length,
                                            current) ||
          std::memcmp(current, instruction.original, instruction.length))
        return false;
    }
    uintptr_t page =
        reinterpret_cast<uintptr_t>(instruction.pc) & ~(page_size - 1);
    const uintptr_t finish =
        reinterpret_cast<uintptr_t>(instruction.pc) + instruction.length;
    while (page < finish) {
      const app_pc address = reinterpret_cast<app_pc>(page);
      if (!pages.count(address)) {
        dr_mem_info_t memory{};
        if (!dr_query_memory_ex(address, &memory) ||
            (memory.prot & (DR_MEMPROT_READ | DR_MEMPROT_EXEC)) !=
                (DR_MEMPROT_READ | DR_MEMPROT_EXEC) ||
            (memory.prot & (DR_MEMPROT_WRITE | DR_MEMPROT_SHARED)))
          return false;
        pages.emplace(address, memory.prot);
      }
      page += page_size;
    }
  }
  plan.code_pages.clear();
  for (const auto &page : pages)
    plan.code_pages.push_back({page.first, page.second});
  return true;
}

static void save_recipe(const std::string &key, app_pc module_base,
                        const ct_userspace_patch_plan &plan,
                        const std::vector<UserspaceGateway> &gateways,
                        bool accepted) {
  if (key.empty())
    return;
  std::vector<byte> data;
  const auto number = [&](uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
      data.push_back(byte(value >> shift));
  };
  const auto bytes = [&](const std::vector<byte> &value) {
    number(value.size());
    data.insert(data.end(), value.begin(), value.end());
  };
  number(accepted);
  number(plan.instructions.size());
  for (const auto &instruction : plan.instructions) {
    number(instruction.pc - module_base);
    number(instruction.length);
    data.insert(data.end(), instruction.original,
                instruction.original + instruction.length);
  }
  number(accepted ? plan.patches.size() : 0);
  if (accepted)
    for (const auto &patch : plan.patches) {
      number(patch->begin - module_base);
      number(patch->information.pc - module_base);
      number(patch->information.redirect_pc - module_base);
      number(patch->information.kind);
      number(patch->readable_size);
      bytes(patch->original);
      bytes(patch->replacement);
      number(patch->bytes.size());
      for (const auto &item : patch->bytes) {
        number(item.instruction_length);
        number(item.logical_pc ? uint64_t(item.logical_pc - module_base)
                               : UINT64_MAX);
      }
    }
  number(accepted ? gateways.size() : 0);
  if (accepted)
    for (const auto &gateway : gateways) {
      const auto patch = std::find_if(
          plan.patches.begin(), plan.patches.end(),
          [&](const auto &value) { return value.get() == gateway.patch; });
      number(patch - plan.patches.begin());
      number(gateway.offset);
      number(gateway.logical_pc - module_base);
    }
  ct_analysis_cache_write("userspace-patches", key.c_str(), data.data(),
                          data.size());
}

static bool load_recipe(const std::string &key, app_pc module_base,
                        app_pc begin, app_pc end, ct_userspace_patch_plan &plan,
                        std::vector<UserspaceGateway> &gateways,
                        bool &accepted) {
  unsigned char *allocation = nullptr;
  size_t size = 0;
  if (key.empty() || !ct_analysis_cache_read("userspace-patches", key.c_str(),
                                             &allocation, &size))
    return false;
  std::unique_ptr<unsigned char, decltype(&std::free)> data(allocation,
                                                            std::free);
  size_t position = 0;
  bool valid = true;
  const auto number = [&]() -> uint64_t {
    if (size - position < 8) {
      valid = false;
      return 0;
    }
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 8)
      value |= uint64_t(data.get()[position++]) << shift;
    return value;
  };
  const auto address = [&]() -> app_pc {
    const uint64_t offset = number();
    const uintptr_t base = reinterpret_cast<uintptr_t>(module_base);
    if (offset > UINTPTR_MAX - base || module_base + offset < begin ||
        module_base + offset >= end) {
      valid = false;
      return nullptr;
    }
    return module_base + offset;
  };
  const auto bytes = [&](std::vector<byte> &output) {
    const uint64_t count = number();
    if (!valid || count > size - position) {
      valid = false;
      return;
    }
    output.assign(data.get() + position, data.get() + position + count);
    position += count;
  };
  const uint64_t status = number();
  accepted = status == 1;
  const uint64_t instruction_count = number();
  if (!valid || status > 1 || instruction_count > (size - position) / 17)
    return false;
  for (uint64_t index = 0; index < instruction_count; ++index) {
    UserspaceInstructionImage instruction{};
    instruction.pc = address();
    instruction.length = number();
    if (!valid || !instruction.length || instruction.length > 15 ||
        instruction.length > size_t(end - instruction.pc) ||
        instruction.length > size - position ||
        (!plan.instructions.empty() &&
         plan.instructions.back().pc + plan.instructions.back().length >
             instruction.pc))
      return false;
    std::memcpy(instruction.original, data.get() + position,
                instruction.length);
    position += instruction.length;
    plan.instructions.push_back(instruction);
  }
  const uint64_t patch_count = number();
  if (!valid || (!accepted && patch_count) ||
      patch_count > (size - position) / 80)
    return false;
  for (uint64_t index = 0; index < patch_count; ++index) {
    auto patch = std::make_unique<UserspacePatch>();
    patch->begin = address();
    patch->information.pc = address();
    patch->information.redirect_pc = address();
    const uint64_t kind = number();
    patch->information.kind = unsigned(kind);
    patch->readable_size = number();
    bytes(patch->original);
    bytes(patch->replacement);
    const uint64_t count = number();
    if (!valid || !kind || (kind & ~uint64_t(31)) || !count || count > 129 ||
        count > size_t(end - patch->begin) ||
        patch->original.size() != count + 14 ||
        patch->replacement.size() != count || patch->readable_size < count ||
        patch->readable_size > patch->original.size() ||
        count > (size - position) / 16 ||
        patch->information.pc < patch->begin ||
        patch->information.pc >= patch->begin + count)
      return false;
    std::vector<byte> current(patch->readable_size);
    if (!ct_userspace_patch_read_original(patch->begin, current.size(),
                                          current.data()) ||
        std::memcmp(current.data(), patch->original.data(), current.size()))
      return false;
    for (const auto &previous : plan.patches)
      if (patch->begin < previous->begin + previous->bytes.size() &&
          patch->begin + count > previous->begin)
        return false;
    patch->bytes.resize(count);
    for (size_t offset = 0; offset < count; ++offset) {
      auto &item = patch->bytes[offset];
      item.pc = patch->begin + offset;
      item.patch = patch.get();
      item.offset = offset;
      item.instruction_length = number();
      const uint64_t logical = number();
      if (!valid || !item.instruction_length || item.instruction_length > 15 ||
          find_byte(item.pc))
        return false;
      if (logical != UINT64_MAX) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(module_base);
        if (logical > UINTPTR_MAX - base || module_base + logical < begin ||
            module_base + logical >= end)
          return false;
        item.logical_pc = module_base + logical;
      }
    }
    patch->information.available =
        std::min(sizeof(patch->information.original), size_t(count));
    patch->information.length = count;
    std::memcpy(patch->information.original, patch->original.data(),
                patch->information.available);
    plan.patches.push_back(std::move(patch));
  }
  const uint64_t gateway_count = number();
  if (!valid || (!accepted && gateway_count) || gateway_count > patch_count ||
      gateway_count > (size - position) / 24)
    return false;
  for (uint64_t index = 0; index < gateway_count; ++index) {
    const uint64_t patch = number(), offset = number();
    const app_pc logical = address();
    if (!valid || patch >= plan.patches.size() ||
        offset > plan.patches[patch]->bytes.size() ||
        plan.patches[patch]->bytes.size() - offset < 5)
      return false;
    gateways.push_back({plan.patches[patch].get(), size_t(offset), logical});
  }
  return valid && position == size && recipe_pages(plan, true);
}

ct_userspace_patch_plan *ct_userspace_patch_prepare(
    void *context, const char *identity, app_pc module_base, app_pc begin,
    app_pc end, const ct_userspace_patch_request *requests, size_t count,
    const ct_userspace_patch_instruction *instructions,
    size_t instruction_count, const app_pc *protected_targets,
    size_t target_count) {
  if (!patch_lock || !module_base || !begin || module_base > begin ||
      end <= begin || (!requests && count) || !instructions ||
      !instruction_count || (!protected_targets && target_count))
    return nullptr;
  if (!context)
    context = dr_get_current_drcontext();
  const char *forced = std::getenv("CTRACE_TEST_BACKEND");
  const bool force_jmp8 = forced && !std::strcmp(forced, "jmp8");
  const bool force_jmp32 = forced && !std::strcmp(forced, "jmp32");

  auto plan = std::make_unique<ct_userspace_patch_plan>();
  std::vector<UserspaceGateway> gateways;
  std::vector<UserspaceInstructionImage> inputs;
  inputs.reserve(instruction_count);
  std::string key;
  if (identity && identity[0])
    key = "userspace-patches:" + std::to_string(std::strlen(identity)) + ":" +
          identity + ":";
  static constexpr char hex[] = "0123456789abcdef";
  const auto key_number = [&](uint64_t value) {
    for (int shift = 60; shift >= 0; shift -= 4)
      key.push_back(hex[(value >> shift) & 15]);
  };
  key_number(begin - module_base);
  key_number(end - module_base);
  key_number(force_jmp8 ? 8 : force_jmp32 ? 32 : 0);
  key_number(count);
  for (size_t index = 0; index < count; ++index) {
    if (!requests[index].kind || (requests[index].kind & ~unsigned(31)) ||
        requests[index].pc < begin || requests[index].pc >= end)
      return nullptr;
    key_number(requests[index].pc - module_base);
    key_number(requests[index].kind);
  }
  key_number(instruction_count);
  for (size_t index = 0; index < instruction_count; ++index) {
    const auto &source = instructions[index];
    if (source.pc < begin || source.pc >= end || !source.length ||
        source.length > 15 || source.length > size_t(end - source.pc) ||
        (!inputs.empty() &&
         inputs.back().pc + inputs.back().length > source.pc) ||
        dr_memory_is_dr_internal(source.pc) ||
        dr_memory_is_in_client(source.pc))
      return nullptr;
    UserspaceInstructionImage input{};
    input.pc = source.pc;
    input.length = source.length;
    if (!ct_userspace_patch_read_original(input.pc, input.length,
                                          input.original))
      return nullptr;
    key_number(input.pc - module_base);
    key_number(input.length);
    for (size_t offset = 0; offset < input.length; ++offset) {
      key.push_back(hex[input.original[offset] >> 4]);
      key.push_back(hex[input.original[offset] & 15]);
    }
    inputs.push_back(input);
  }
  // Targets outside this range cannot constrain its patch windows. Excluding
  // their runtime addresses keeps the recipe independent of ASLR.
  for (size_t index = 0; index < target_count; ++index)
    if (protected_targets[index] >= begin && protected_targets[index] < end)
      key_number(protected_targets[index] - module_base);
  if (!identity || !identity[0])
    key.clear();
  bool accepted = false;
  const bool cached =
      load_recipe(key, module_base, begin, end, *plan, gateways, accepted);
  if (cached && !accepted) {
    ct_userspace_prepare_note(ct_userspace_preparation::PatchCachedRejection);
    return nullptr;
  }
  if (!cached) {
    plan = std::make_unique<ct_userspace_patch_plan>();
    gateways.clear();
    bool transient_rejection = false;

    struct Instruction {
      app_pc pc;
      size_t length;
      byte original[15];
      bool transfer;
      bool terminal;
      bool nop;
      bool endbr;
    };
    std::vector<Instruction> decoded;
    decoded.reserve(instruction_count);
    for (size_t index = 0; index < instruction_count; ++index) {
      const auto &source = instructions[index];
      if (source.pc < begin || source.pc >= end || !source.length ||
          source.length > 15 || source.length > size_t(end - source.pc) ||
          (!decoded.empty() &&
           decoded.back().pc + decoded.back().length > source.pc) ||
          dr_memory_is_dr_internal(source.pc) ||
          dr_memory_is_in_client(source.pc))
        return nullptr;
      Instruction item{};
      item.pc = source.pc;
      item.length = source.length;
      std::memcpy(item.original, inputs[index].original, item.length);
      instr_t instruction;
      instr_init(context, &instruction);
      byte *next =
          decode_from_copy(context, item.original, item.pc, &instruction);
      const bool valid = next == item.original + item.length &&
                         instr_valid(&instruction) &&
                         !instr_is_interrupt(&instruction);
      const int opcode = instr_get_opcode(&instruction);
      item.transfer =
          instr_is_cti(&instruction) || instr_is_syscall(&instruction);
      item.terminal = instr_is_return(&instruction) ||
                      instr_is_ubr(&instruction) || instr_is_mbr(&instruction);
      item.nop = opcode == OP_nop || opcode == OP_nop_modrm;
      item.endbr = opcode == OP_endbr64 || opcode == OP_endbr32;
      instr_free(context, &instruction);
      if (!valid)
        return nullptr;
      decoded.push_back(item);
    }

    // CFG walking stops at RET and unconditional branches, while ELF function
    // ranges often include their alignment NOPs. Recover only genuine NOP
    // instructions in those gaps: they can extend a short gate or host a relay.
    // A relay farther than a signed-byte displacement cannot be used here.
    std::vector<Instruction> padded;
    std::vector<UserspaceInstructionImage> padding_probes;
    padded.reserve(decoded.size());
    for (size_t index = 0; index < decoded.size(); ++index) {
      padded.push_back(decoded[index]);
      if (!decoded[index].terminal)
        continue;
      app_pc cursor = decoded[index].pc + decoded[index].length;
      const app_pc stop =
          index + 1 < decoded.size() ? decoded[index + 1].pc : end;
      while (cursor < stop && cursor - decoded[index].pc <= 127) {
        Instruction padding{};
        padding.pc = cursor;
        const size_t available =
            std::min(sizeof(padding.original), size_t(stop - cursor));
        if (!ct_userspace_patch_read_original(cursor, available,
                                              padding.original)) {
          transient_rejection = true;
          break;
        }
        instr_t instruction;
        instr_init(context, &instruction);
        byte *next =
            decode_from_copy(context, padding.original, cursor, &instruction);
        const int opcode = instr_get_opcode(&instruction);
        padding.length = next ? size_t(next - padding.original) : 0;
        padding.nop = opcode == OP_nop || opcode == OP_nop_modrm;
        instr_free(context, &instruction);
        if (!padding.length || padding.length > available || !padding.nop) {
          // A failed NOP probe also affects window selection. Preserve those
          // bytes so a changed padding gap invalidates a cached rejection.
          UserspaceInstructionImage probe{};
          probe.pc = cursor;
          probe.length = available;
          std::memcpy(probe.original, padding.original, available);
          padding_probes.push_back(probe);
          break;
        }
        padded.push_back(padding);
        cursor += padding.length;
      }
    }
    decoded = std::move(padded);
    plan->instructions.reserve(decoded.size());
    for (const auto &instruction : decoded) {
      UserspaceInstructionImage snapshot{};
      snapshot.pc = instruction.pc;
      snapshot.length = instruction.length;
      std::memcpy(snapshot.original, instruction.original, instruction.length);
      plan->instructions.push_back(snapshot);
    }
    plan->instructions.insert(plan->instructions.end(), padding_probes.begin(),
                              padding_probes.end());
    std::sort(
        plan->instructions.begin(), plan->instructions.end(),
        [](const auto &left, const auto &right) { return left.pc < right.pc; });

    std::vector<app_pc> targets;
    if (target_count)
      targets.assign(protected_targets, protected_targets + target_count);
    std::sort(targets.begin(), targets.end());
    std::map<app_pc, unsigned> gates;
    for (size_t index = 0; index < count; ++index) {
      if (!requests[index].kind || requests[index].pc < begin ||
          requests[index].pc >= end)
        return nullptr;
      gates[requests[index].pc] |= requests[index].kind;
    }

    const auto clear_span = [&](size_t first, size_t last, app_pc gate) {
      const app_pc start = decoded[first].pc;
      const app_pc finish = decoded[last].pc + decoded[last].length;
      auto target = std::upper_bound(targets.begin(), targets.end(), start);
      if (target != targets.end() && *target < finish)
        return false;
      const auto requested = gates.find(gate);
      const bool trace = requested != gates.end() &&
                         (requested->second & CT_USERSPACE_GATE_TRACE);
      auto other_gate = gates.lower_bound(start);
      for (; other_gate != gates.end() && other_gate->first < finish;
           ++other_gate)
        if (other_gate->first != gate &&
            (!trace || !(other_gate->second & CT_USERSPACE_GATE_TRACE)))
          return false;
      for (size_t index = first; index <= last; ++index) {
        if (decoded[index].endbr ||
            (index > first &&
             decoded[index - 1].pc + decoded[index - 1].length !=
                 decoded[index].pc))
          return false;
        for (size_t offset = 0; offset < decoded[index].length; ++offset)
          if (find_byte(decoded[index].pc + offset)) {
            transient_rejection = true;
            return false;
          }
      }
      for (const auto &patch : plan->patches)
        if (start < patch->begin + patch->bytes.size() && finish > patch->begin)
          return false;
      return true;
    };

    const auto make_patch = [&](size_t first, size_t last, app_pc redirect,
                                unsigned kind) {
      auto patch = std::make_unique<UserspacePatch>();
      patch->begin = decoded[first].pc;
      const size_t size =
          decoded[last].pc + decoded[last].length - patch->begin;
      patch->original.resize(size);
      patch->bytes.resize(size);
      for (size_t index = first; index <= last; ++index) {
        const size_t offset = decoded[index].pc - patch->begin;
        std::memcpy(patch->original.data() + offset, decoded[index].original,
                    decoded[index].length);
        patch->bytes[offset].instruction_length = decoded[index].length;
      }
      for (size_t offset = 0; offset < size; ++offset) {
        auto &byte = patch->bytes[offset];
        byte.pc = patch->begin + offset;
        byte.patch = patch.get();
        byte.offset = offset;
      }
      patch->replacement = patch->original;
      patch->information.pc = patch->begin;
      patch->information.redirect_pc = redirect;
      patch->information.available =
          std::min(sizeof(patch->information.original), size);
      patch->information.length = size;
      patch->information.kind = kind;
      std::memcpy(patch->information.original, patch->original.data(),
                  patch->information.available);
      // An unexpected indirect entry may start inside an overwritten
      // instruction. Preserve the original decoding there too, rather than
      // exposing E9's displacement bytes as application instructions. Only
      // covered bytes are patched; this trailing lookahead is immutable decoder
      // storage.
      for (size_t offset = 0; offset < 14; ++offset) {
        byte following = 0;
        if (!ct_userspace_patch_read_original(patch->begin + size + offset, 1,
                                              &following))
          break;
        patch->original.push_back(following);
      }
      const size_t readable_size = patch->original.size();
      patch->readable_size = readable_size;
      patch->original.resize(size + 14, 0);
      for (size_t offset = 0; offset < size; ++offset) {
        instr_t instruction;
        instr_init(context, &instruction);
        byte copy[15]{};
        const size_t available = std::min(sizeof(copy), readable_size - offset);
        std::memcpy(copy, patch->original.data() + offset, available);
        byte *next = decode_from_copy(context, copy, patch->begin + offset,
                                      &instruction);
        // An invalid original byte stream must still fail decoding under DR.
        // Returning one preserved byte makes the decoder reject a mismatched
        // length instead of falling through to the patched application text.
        patch->bytes[offset].instruction_length =
            next && size_t(next - copy) <= available ? size_t(next - copy) : 1;
        instr_free(context, &instruction);
      }
      return patch;
    };

    for (const auto &gate : gates) {
      const bool trace = gate.second & CT_USERSPACE_GATE_TRACE;
      // The runtime stays under DR until it has replayed the complete
      // overwritten window, including every logical observation site inside.
      if (trace && std::any_of(plan->patches.begin(), plan->patches.end(),
                               [&](const auto &patch) {
                                 return (patch->information.kind &
                                         CT_USERSPACE_GATE_TRACE) &&
                                        gate.first >= patch->begin &&
                                        gate.first <
                                            patch->begin + patch->bytes.size();
                               }))
        continue;
      auto found =
          std::lower_bound(decoded.begin(), decoded.end(), gate.first,
                           [](const Instruction &instruction, app_pc pc) {
                             return instruction.pc < pc;
                           });
      if (found == decoded.end() || found->pc != gate.first)
        return nullptr;
      size_t gate_index = found - decoded.begin();
      bool entry_prefix = false;
      if (decoded[gate_index].endbr &&
          (gate.second & CT_USERSPACE_GATE_ENTRY)) {
        entry_prefix = true;
        if (++gate_index == decoded.size() ||
            decoded[gate_index - 1].pc + decoded[gate_index - 1].length !=
                decoded[gate_index].pc)
          return nullptr;
      }
      if (decoded[gate_index].endbr)
        return nullptr;

      bool selected = false;
      for (size_t jump_size : {size_t(5), size_t(2)}) {
        if ((force_jmp8 && jump_size != 2) || (force_jmp32 && jump_size != 5))
          continue;
        size_t first = gate_index;
        bool usable_window = false;
        while (true) {
          size_t last = gate_index;
          bool span_valid = true;
          while (decoded[last].pc + decoded[last].length - decoded[first].pc <
                 ptrdiff_t(jump_size)) {
            if (last + 1 == decoded.size() ||
                decoded[last].pc + decoded[last].length !=
                    decoded[last + 1].pc ||
                decoded[last + 1].endbr ||
                (decoded[last + 1].transfer && !trace) ||
                (decoded[trace ? last : gate_index].terminal &&
                 !decoded[last + 1].nop)) {
              span_valid = false;
              break;
            }
            ++last;
          }
          if (span_valid && clear_span(first, last, gate.first)) {
            usable_window = true;
            size_t relay_first = 0, relay_last = 0;
            bool relay_found = jump_size == 5;
            if (!relay_found) {
              for (size_t candidate = 0; candidate < decoded.size();
                   ++candidate) {
                if (!decoded[candidate].nop)
                  continue;
                const intptr_t distance =
                    reinterpret_cast<intptr_t>(decoded[candidate].pc + 2) -
                    reinterpret_cast<intptr_t>(decoded[first].pc + 2);
                if (distance < -128 || distance > 127)
                  continue;
                size_t tail = candidate;
                while (decoded[tail].pc + decoded[tail].length -
                               decoded[candidate].pc <
                           7 &&
                       tail + 1 < decoded.size() && decoded[tail + 1].nop &&
                       decoded[tail].pc + decoded[tail].length ==
                           decoded[tail + 1].pc)
                  ++tail;
                const size_t relay_size = decoded[tail].pc +
                                          decoded[tail].length -
                                          decoded[candidate].pc;
                if (relay_size < 7 || relay_size > 129 ||
                    (decoded[candidate].pc <
                         decoded[last].pc + decoded[last].length &&
                     decoded[tail].pc + decoded[tail].length >
                         decoded[first].pc) ||
                    !clear_span(candidate, tail, nullptr))
                  continue;
                relay_first = candidate;
                relay_last = tail;
                relay_found = true;
                break;
              }
            }
            if (relay_found) {
              const app_pc replay =
                  entry_prefix ? gate.first : decoded[first].pc;
              unsigned kind = gate.second;
              if (trace)
                for (auto covered = gates.lower_bound(decoded[first].pc);
                     covered != gates.end() &&
                     covered->first < decoded[last].pc + decoded[last].length;
                     ++covered)
                  kind |= covered->second;
              auto patch = make_patch(first, last, replay, kind);
              UserspacePatch *primary = patch.get();
              if (entry_prefix) {
                // Keep ENDBR executable for indirect entry, but include it in
                // decoder/userspace-entry exclusion so replay cannot loop back.
                auto extended = make_patch(gate_index - 1, last, replay, kind);
                extended->information.pc = primary->begin;
                primary = extended.get();
                patch = std::move(extended);
              }
              const size_t jump_offset = decoded[first].pc - primary->begin;
              if (jump_size == 5) {
                gateways.push_back({primary, jump_offset, replay});
              } else {
                auto relay = make_patch(relay_first, relay_last,
                                        decoded[relay_first].pc, kind);
                relay->replacement[0] = 0xeb;
                relay->replacement[1] = byte(relay->bytes.size() - 2);
                // Normal NOP fallthrough uses the first short jump and skips
                // this E9. Only the intercepted gate enters at relay + 2, where
                // an asynchronous signal or suspension must recover its PC.
                relay->bytes[2].logical_pc = replay;
                primary->replacement[jump_offset] = 0xeb;
                const intptr_t distance =
                    reinterpret_cast<intptr_t>(relay->begin + 2) -
                    reinterpret_cast<intptr_t>(decoded[first].pc + 2);
                primary->replacement[jump_offset + 1] = byte(int8_t(distance));
                gateways.push_back({relay.get(), 2, replay});
                plan->patches.push_back(std::move(relay));
              }
              plan->patches.push_back(std::move(patch));
              selected = true;
              break;
            }
          }
          if (first == 0 || entry_prefix ||
              decoded[gate_index].pc - decoded[first].pc >=
                  ptrdiff_t(jump_size) ||
              decoded[first - 1].pc + decoded[first - 1].length !=
                  decoded[first].pc ||
              decoded[first - 1].transfer || decoded[first - 1].endbr)
            break;
          --first;
        }
        if (selected)
          break;
        ct_userspace_prepare_note(
            jump_size == 5
                ? ct_userspace_preparation::PatchFiveByteWindowRejected
            : usable_window
                ? ct_userspace_preparation::PatchRelayUnavailable
                : ct_userspace_preparation::PatchTwoByteWindowRejected);
      }
      if (!selected) {
        ct_userspace_prepare_note(
            ct_userspace_preparation::PatchWindowRejected);
        if (!transient_rejection && recipe_pages(*plan, true))
          save_recipe(key, module_base, *plan, gateways, false);
        return nullptr;
      }
    }
  }

  const size_t page_size = dr_page_size();
  if (!recipe_pages(*plan, true))
    return nullptr;
  std::map<app_pc, uint> code_pages;
  for (const auto &page : plan->code_pages)
    code_pages.emplace(page.pc, page.protection);
  std::map<app_pc, uint> pages;
  for (const auto &patch : plan->patches) {
    uintptr_t page =
        reinterpret_cast<uintptr_t>(patch->begin) & ~(page_size - 1);
    const uintptr_t finish =
        reinterpret_cast<uintptr_t>(patch->begin) + patch->bytes.size();
    while (page < finish) {
      const auto protection = code_pages.find(reinterpret_cast<app_pc>(page));
      if (protection == code_pages.end())
        return nullptr;
      pages.emplace(protection->first, protection->second);
      page += page_size;
    }
  }
  for (const auto &page : pages)
    plan->pages.push_back({page.first, page.second});

  if (!cached)
    save_recipe(key, module_base, *plan, gateways, true);

  if (!gateways.empty()) {
    // Reserve slots across function plans. Encoding is staged separately:
    // existing pool pages may already be executing on another thread.
    byte *scratch = static_cast<byte *>(
        dr_nonheap_alloc(64, DR_MEMPROT_READ | DR_MEMPROT_WRITE));
    if (!scratch)
      return nullptr;
    bool ready = true;
    plan->gateways.reserve(gateways.size());
    dr_mutex_lock(patch_lock);
    plan->owner = dr_get_thread_id(context);
    plan->next = gateway_plans;
    gateway_plans = plan.get();
    for (const auto &gate : gateways) {
      const uintptr_t source =
          reinterpret_cast<uintptr_t>(gate.patch->begin + gate.offset + 5);
      // An original direct CALL already writes exactly this stack word. Its
      // five-byte window needs no new red-zone assumption. The common probe
      // always hands originals back to DR to replay the preserved CALL.
      if (!force_jmp32 && !force_jmp8 && !gate.offset &&
          gate.patch->replacement.size() == 5 &&
          gate.patch->original[0] == 0xe8 &&
          gate.logical_pc == gate.patch->begin) {
        const app_pc probe = ct_userspace_call_probe_acquire(gate.patch->begin);
        const int64_t distance =
            int64_t(reinterpret_cast<uintptr_t>(probe)) - int64_t(source);
        if (probe && distance >= INT32_MIN && distance <= INT32_MAX) {
          gate.patch->call_site = dr_register_userspace_call_site(
              reinterpret_cast<app_pc>(source), gate.logical_pc);
          if (gate.patch->call_site) {
            app_pc low = nullptr, high = nullptr;
            gate.patch->backend_direct =
                dr_userspace_call_probe_direct_range(&low, &high) &&
                probe >= low && probe <= high;
            gate.patch->replacement[0] = 0xe8;
            const int32_t relative = int32_t(distance);
            std::memcpy(gate.patch->replacement.data() + 1, &relative,
                        sizeof(relative));
            ct_userspace_prepare_note(ct_userspace_preparation::CallSelected);
            continue;
          }
          ct_userspace_prepare_note(
              ct_userspace_preparation::CallRegistryFailed);
        } else if (probe) {
          ct_userspace_prepare_note(ct_userspace_preparation::CallOutOfReach);
        }
      } else if (!force_jmp32 && !force_jmp8) {
        ct_userspace_prepare_note(
            ct_userspace_preparation::CallOriginalReplayIneligible);
      }
      UserspaceGatewayPage *selected = nullptr;
      size_t slot = 0;
      const uintptr_t runtime =
          reinterpret_cast<uintptr_t>(dr_userspace_gate_entry());
      // A new page with two direct jumps wins over an existing page that would
      // require the runtime-pointer indirection. Within either class, always
      // consume a reusable slot before allocating another page.
      for (bool direct : {true, false}) {
        for (auto *page = gateway_pages; page && !selected; page = page->next) {
          for (size_t index = 0; index < page->slots.size(); ++index) {
            const uintptr_t address =
                reinterpret_cast<uintptr_t>(page->pc + index * 64);
            const int64_t displacement = int64_t(address) - int64_t(source);
            const int64_t onward = int64_t(runtime) - int64_t(address + 28);
            if (!page->slots[index] && displacement >= INT32_MIN &&
                displacement <= INT32_MAX &&
                (!direct ||
                 (runtime && onward >= INT32_MIN && onward <= INT32_MAX))) {
              selected = page;
              slot = index;
              ct_userspace_prepare_note(
                  ct_userspace_preparation::JumpSlotReused);
              break;
            }
          }
        }
        if (selected)
          break;
        uintptr_t lower = std::max<uintptr_t>(
            page_size, source > uintptr_t(INT32_MAX) + 1
                           ? source - (uintptr_t(INT32_MAX) + 1)
                           : 0);
        uintptr_t upper =
            source > UINTPTR_MAX - INT32_MAX ? UINTPTR_MAX : source + INT32_MAX;
        if (direct) {
          if (!runtime) {
            ct_userspace_prepare_note(
                ct_userspace_preparation::JumpHelpersUnavailable);
            continue;
          }
          // The direct runtime jump starts at slot + 23 and ends at slot + 28.
          const int64_t first = int64_t(runtime) - INT32_MAX - 28;
          const int64_t last = int64_t(runtime) - INT32_MIN - 28;
          lower = std::max(lower, uintptr_t(std::max<int64_t>(0, first)));
          upper = std::min(upper, uintptr_t(std::max<int64_t>(0, last)));
        }
        if (lower > upper || lower > UINTPTR_MAX - page_size + 1) {
          ct_userspace_prepare_note(
              ct_userspace_preparation::JumpEmptyIntersection);
          continue;
        }
        auto allocation = std::make_unique<UserspaceGatewayPage>();
        allocation->size = page_size;
        allocation->slots.resize(page_size / 64);
        allocation->generations.resize(page_size / 64);
        const uintptr_t aligned_lower =
            (lower + page_size - 1) & ~(page_size - 1);
        const uintptr_t preferred =
            reinterpret_cast<uintptr_t>(end) & ~(page_size - 1);
        const uintptr_t starts[] = {std::max(preferred, aligned_lower),
                                    aligned_lower};
        bool query_failed = false, allocation_failed = false;
        for (uintptr_t cursor : starts) {
          while (cursor <= upper && page_size <= upper - cursor) {
            dr_mem_info_t memory{};
            if (!dr_query_memory_ex(reinterpret_cast<app_pc>(cursor),
                                    &memory) ||
                !memory.size ||
                memory.size >
                    UINTPTR_MAX - reinterpret_cast<uintptr_t>(memory.base_pc)) {
              query_failed = true;
              ct_userspace_prepare_note(
                  ct_userspace_preparation::JumpQueryFailed);
              break;
            }
            const uintptr_t next =
                reinterpret_cast<uintptr_t>(memory.base_pc) + memory.size;
            if (memory.type == DR_MEMTYPE_FREE && next > cursor &&
                page_size <= next - cursor) {
              allocation->pc = static_cast<app_pc>(dr_custom_alloc(
                  nullptr,
                  dr_alloc_flags_t(DR_ALLOC_NON_HEAP | DR_ALLOC_FIXED_LOCATION),
                  page_size, DR_MEMPROT_READ | DR_MEMPROT_EXEC,
                  reinterpret_cast<void *>(cursor)));
              if (allocation->pc)
                break;
              allocation_failed = true;
              ct_userspace_prepare_note(
                  ct_userspace_preparation::JumpAllocationFailed);
            }
            if (next <= cursor || next > UINTPTR_MAX - page_size + 1)
              break;
            cursor = (next + page_size - 1) & ~(page_size - 1);
          }
          if (allocation->pc)
            break;
        }
        if (!allocation->pc) {
          if (!query_failed && !allocation_failed)
            ct_userspace_prepare_note(
                ct_userspace_preparation::JumpAddressSpaceOccupied);
          continue;
        }
        ct_userspace_prepare_note(ct_userspace_preparation::JumpPageCreated);
        selected = allocation.release();
        selected->next = gateway_pages;
        gateway_pages = selected;
        break;
      }
      if (!selected) {
        ct_userspace_prepare_note(ct_userspace_preparation::JumpNoSlot);
        ready = false;
        break;
      }
      app_pc stub = selected->pc + slot * 64;
      std::memset(scratch, 0x90, 64);
      const intptr_t displacement =
          reinterpret_cast<intptr_t>(stub) -
          reinterpret_cast<intptr_t>(gate.patch->begin + gate.offset + 5);
      if (displacement < INT32_MIN || displacement > INT32_MAX ||
          !dr_encode_userspace_gate_at(scratch, 64, gate.logical_pc, stub)) {
        ct_userspace_prepare_note(ct_userspace_preparation::JumpEncodingFailed);
        ready = false;
        break;
      }
      selected->slots[slot] = 1;
      ++selected->generations[slot];
      plan->gateways.push_back(
          {selected, slot, selected->generations[slot], {}});
      std::memcpy(plan->gateways.back().encoding.data(), scratch, 64);
      gate.patch->backend_direct = scratch[23] == 0xe9;
      ct_userspace_prepare_note(scratch[23] == 0xe9
                                    ? ct_userspace_preparation::JumpDirect
                                    : ct_userspace_preparation::JumpIndirect);
      ct_userspace_prepare_note(gate.offset == 2
                                    ? ct_userspace_preparation::Jump8Selected
                                    : ct_userspace_preparation::Jump32Selected);
      gate.patch->gateway = selected;
      gate.patch->gateway_slot = slot;
      gate.patch->replacement[gate.offset] = 0xe9;
      const int32_t relative = int32_t(displacement);
      std::memcpy(gate.patch->replacement.data() + gate.offset + 1, &relative,
                  sizeof(relative));
    }
    dr_mutex_unlock(patch_lock);
    dr_nonheap_free(scratch, 64);
    if (!ready) {
      ct_userspace_patch_discard(plan.release());
      return nullptr;
    }
  }
  // Match actual routing without incorporating ASLR addresses or live slot
  // reservations. Original bytes and relative logical boundaries distinguish
  // different windows; helper reachability distinguishes direct/indirect gates.
  std::vector<uint64_t> routing{uint64_t(plan->instructions.size()),
                                uint64_t(plan->patches.size()),
                                uint64_t(gateways.size())};
  std::vector<ct_digest_part> parts;
  for (const auto &instruction : plan->instructions) {
    routing.push_back(instruction.pc - module_base);
    routing.push_back(instruction.length);
    parts.push_back({instruction.original, instruction.length});
  }
  for (const auto &patch : plan->patches) {
    routing.push_back(patch->begin - module_base);
    routing.push_back(patch->replacement.size());
    routing.push_back(patch->replacement.empty() ? 0 : patch->replacement[0]);
    routing.push_back(patch->replacement.size() == 2 ? patch->replacement[1]
                                                     : 0);
  }
  for (const auto &gate : gateways) {
    routing.push_back(gate.patch->begin - module_base);
    routing.push_back(gate.logical_pc - module_base);
    routing.push_back(gate.offset);
    routing.push_back(gate.patch->replacement[gate.offset]);
    routing.push_back(gate.patch->backend_direct);
  }
  parts.push_back({routing.data(), routing.size() * sizeof(uint64_t)});
  if (!ct_shared_digest_parts(parts.data(), parts.size(),
                              plan->backend_path.data()))
    plan->backend_path.fill(0);
  return plan.release();
}

const unsigned char *
ct_userspace_patch_backend_path(const ct_userspace_patch_plan *plan) {
  return plan && plan->published ? plan->backend_path.data() : nullptr;
}

bool ct_userspace_patch_publish_all(ct_userspace_patch_plan *const *plans,
                                    size_t count) {
  if (!patch_lock || !plans || !count)
    return false;
  for (size_t index = 0; index < count; ++index)
    if (!plans[index] || plans[index]->published ||
        std::find(plans, plans + index, plans[index]) != plans + index)
      return false;
  dr_mutex_lock(patch_lock);
  bool valid = true;
  // Validate the whole closure before any text changes. Already published
  // entry gates are allowed in a graph, but their actual replacement bytes
  // must still match the registry as well as its preserved original bytes.
  for (size_t index = 0; valid && index < count; ++index) {
    const auto &plan = *plans[index];
    for (const auto &page : plan.code_pages) {
      dr_mem_info_t memory{};
      if (!dr_query_memory_ex(page.pc, &memory) ||
          memory.prot != page.protection ||
          (memory.prot & (DR_MEMPROT_WRITE | DR_MEMPROT_SHARED))) {
        valid = false;
        break;
      }
    }
    for (const auto &instruction : plan.instructions) {
      if (!valid)
        break;
      byte current[15]{};
      size_t read = 0;
      if (!dr_safe_read(instruction.pc, instruction.length, current, &read) ||
          read != instruction.length) {
        valid = false;
        break;
      }
      for (size_t offset = 0; offset < instruction.length; ++offset) {
        UserspaceByte *installed = find_byte(instruction.pc + offset);
        const byte expected =
            installed ? installed->patch->replacement[installed->offset]
                      : instruction.original[offset];
        if (current[offset] != expected ||
            (installed && installed->patch->original[installed->offset] !=
                              instruction.original[offset])) {
          valid = false;
          break;
        }
      }
    }
    for (const auto &patch : plan.patches) {
      if (!valid)
        break;
      for (size_t previous = 0; previous <= index; ++previous)
        for (const auto &other : plans[previous]->patches) {
          if (other.get() == patch.get())
            break;
          if (patch->begin < other->begin + other->bytes.size() &&
              other->begin < patch->begin + patch->bytes.size())
            valid = false;
        }
      for (size_t offset = 0; valid && offset < patch->bytes.size(); ++offset) {
        byte current;
        size_t read = 0;
        if (find_byte(patch->begin + offset) ||
            !dr_safe_read(patch->begin + offset, 1, &current, &read) ||
            read != 1 || current != patch->original[offset])
          valid = false;
      }
    }
  }
  // Avoid allocation while the caller has suspended all application threads.
  // Multiple function plans can share a text page; change it only once.
  const auto prior_page = [&](size_t plan_index, size_t page_index) {
    const app_pc pc = plans[plan_index]->pages[page_index].pc;
    for (size_t index = 0; index <= plan_index; ++index) {
      const auto &pages = plans[index]->pages;
      const size_t end = index == plan_index ? page_index : pages.size();
      for (size_t page = 0; page < end; ++page)
        if (pages[page].pc == pc)
          return true;
    }
    return false;
  };
  const size_t page_size = dr_page_size();
  // All peers are stopped by the caller. Publish staged slots one page at a
  // time without allocating or changing any other plan's live bytes.
  for (size_t index = 0; valid && index < count; ++index) {
    for (size_t slot = 0; valid && slot < plans[index]->gateways.size();
         ++slot) {
      const auto &reservation = plans[index]->gateways[slot];
      bool previous = false;
      for (size_t prior = 0; prior <= index; ++prior) {
        const size_t limit =
            prior == index ? slot : plans[prior]->gateways.size();
        for (size_t item = 0; item < limit; ++item)
          previous |= plans[prior]->gateways[item].page == reservation.page;
      }
      if (previous)
        continue;
      auto &page = *reservation.page;
      dr_mem_info_t memory{};
      if (!dr_query_memory_ex(page.pc, &memory) ||
          memory.prot != (DR_MEMPROT_READ | DR_MEMPROT_EXEC) ||
          !protect_text(page.pc, page.size,
                        DR_MEMPROT_READ | DR_MEMPROT_WRITE)) {
        valid = false;
        break;
      }
      for (size_t plan = index; valid && plan < count; ++plan) {
        for (const auto &item : plans[plan]->gateways) {
          if (item.page != &page)
            continue;
          size_t written = 0;
          if (item.slot >= page.slots.size() || page.slots[item.slot] != 1 ||
              page.generations[item.slot] != item.generation ||
              !dr_safe_write(page.pc + item.slot * 64, item.encoding.size(),
                             item.encoding.data(), &written) ||
              written != item.encoding.size()) {
            valid = false;
            break;
          }
        }
      }
      if (!protect_text(page.pc, page.size, DR_MEMPROT_READ | DR_MEMPROT_EXEC))
        dr_abort();
    }
  }
  size_t writable = 0;
  for (size_t index = 0; valid && index < count; ++index) {
    for (size_t page_index = 0; page_index < plans[index]->pages.size();
         ++page_index) {
      if (prior_page(index, page_index))
        continue;
      const auto &page = plans[index]->pages[page_index];
      dr_mem_info_t memory{};
      if (!dr_query_memory_ex(page.pc, &memory) ||
          memory.prot != page.protection ||
          (memory.prot & (DR_MEMPROT_WRITE | DR_MEMPROT_SHARED)) ||
          !protect_text(page.pc, page_size,
                        page.protection | DR_MEMPROT_WRITE)) {
        valid = false;
        break;
      }
      ++writable;
    }
  }
  if (valid) {
    for (size_t index = 0; index < count; ++index)
      for (const auto &patch : plans[index]->patches) {
        patch->active.store(true, std::memory_order_release);
        for (auto &item : patch->bytes) {
          auto &bucket = patch_buckets[patch_bucket(item.pc)];
          item.next = bucket.load(std::memory_order_relaxed);
          bucket.store(&item, std::memory_order_release);
        }
      }
    for (size_t index = 0; valid && index < count; ++index)
      for (const auto &patch : plans[index]->patches) {
        size_t written = 0;
        if (!dr_safe_write(patch->begin, patch->replacement.size(),
                           patch->replacement.data(), &written) ||
            written != patch->replacement.size()) {
          valid = false;
          break;
        }
      }
    if (!valid)
      for (size_t index = 0; index < count; ++index)
        for (const auto &patch : plans[index]->patches) {
          size_t written = 0;
          if (!dr_safe_write(patch->begin, patch->bytes.size(),
                             patch->original.data(), &written) ||
              written != patch->bytes.size())
            dr_abort();
          patch->active.store(false, std::memory_order_release);
        }
    std::atomic_thread_fence(std::memory_order_seq_cst);
    // Published registry nodes must outlive decoding readers even on rollback.
    for (size_t index = 0; index < count; ++index) {
      auto &plan = *plans[index];
      for (auto &patch : plan.patches) {
        UserspacePatch *record = patch.release();
        record->next = patch_records;
        patch_records = record;
      }
      plan.patches.clear();
      if (valid)
        for (const auto &reservation : plan.gateways)
          reservation.page->slots[reservation.slot] = 2;
      if (valid)
        plan.gateways.clear();
      plan.published = true;
    }
    // Failed publication restored every original byte while peers remained
    // stopped. Its gateway never executed and stays owned by the discarded
    // plan; only the decoder's registry records need indefinite retention.
  }
  for (size_t index = 0; writable && index < count; ++index)
    for (size_t page_index = 0;
         writable && page_index < plans[index]->pages.size(); ++page_index) {
      if (prior_page(index, page_index))
        continue;
      const auto &page = plans[index]->pages[page_index];
      if (!protect_text(page.pc, page_size, page.protection))
        dr_abort();
      --writable;
    }
  dr_mutex_unlock(patch_lock);
  return valid;
}

void ct_userspace_patch_discard(ct_userspace_patch_plan *plan) {
  if (!plan)
    return;
  dr_mutex_lock(patch_lock);
  auto **entry = &gateway_plans;
  while (*entry && *entry != plan)
    entry = &(*entry)->next;
  if (*entry)
    *entry = plan->next;
  for (const auto &reservation : plan->gateways)
    if (reservation.page->slots[reservation.slot] == 1 &&
        reservation.page->generations[reservation.slot] ==
            reservation.generation)
      reservation.page->slots[reservation.slot] = 0;
  for (const auto &patch : plan->patches)
    if (patch->call_site)
      dr_unregister_userspace_code(patch->call_site);
  dr_mutex_unlock(patch_lock);
  delete plan;
}

bool ct_userspace_patch_remove_range(app_pc begin, size_t size, bool mapped) {
  if (!patch_lock || size > UINTPTR_MAX - reinterpret_cast<uintptr_t>(begin))
    return false;
  if (!size)
    return true;
  const uintptr_t start = reinterpret_cast<uintptr_t>(begin);
  const uintptr_t end = start + size;
  const size_t page_size = dr_page_size();
  bool success = true;
  dr_mutex_lock(patch_lock);
  for (UserspacePatch *patch = patch_records; patch; patch = patch->next) {
    const uintptr_t address = reinterpret_cast<uintptr_t>(patch->begin);
    if (address >= end || address + patch->bytes.size() <= start ||
        !patch->active.load(std::memory_order_acquire))
      continue;
    if (mapped) {
      bool owned = true;
      for (size_t offset = 0; offset < patch->replacement.size(); ++offset) {
        byte current = 0;
        size_t read = 0;
        if (!dr_safe_read(patch->begin + offset, 1, &current, &read) ||
            read != 1 || current != patch->replacement[offset]) {
          owned = false;
          break;
        }
      }
      if (!owned) {
        success = false;
        continue;
      }
      uintptr_t first_page = address & ~(page_size - 1);
      const uintptr_t last_page =
          (address + patch->bytes.size() - 1) & ~(page_size - 1);
      // A JMP instruction window is at most a handful of x86 instructions and
      // therefore spans no more than two pages.
      UserspaceTextPage pages[2]{};
      size_t writable = 0;
      for (uintptr_t page = first_page; page <= last_page; page += page_size) {
        dr_mem_info_t memory{};
        if (writable == 2 ||
            !dr_query_memory_ex(reinterpret_cast<app_pc>(page), &memory) ||
            memory.type == DR_MEMTYPE_FREE ||
            !protect_text(reinterpret_cast<app_pc>(page), page_size,
                          memory.prot | DR_MEMPROT_WRITE))
          break;
        pages[writable++] = {reinterpret_cast<app_pc>(page), memory.prot};
      }
      const bool writable_all =
          writable == (last_page - first_page) / page_size + 1;
      size_t written = 0;
      const bool restored = writable_all &&
                            dr_safe_write(patch->begin, patch->bytes.size(),
                                          patch->original.data(), &written) &&
                            written == patch->bytes.size();
      while (writable) {
        const auto &page = pages[--writable];
        if (!protect_text(page.pc, page_size, page.protection))
          dr_abort();
      }
      if (!restored) {
        success = false;
        continue;
      }
    }
    patch->active.store(false, std::memory_order_release);
    if (patch->gateway) {
      patch->gateway->slots[patch->gateway_slot] = 3;
      patch->gateway = nullptr;
    }
  }
  std::atomic_thread_fence(std::memory_order_seq_cst);
  dr_mutex_unlock(patch_lock);
  return success;
}

void ct_userspace_patch_reclaim() {
  if (!patch_lock)
    return;
  dr_mutex_lock(patch_lock);
  for (auto *patch = patch_records; patch; patch = patch->next)
    if (!patch->active.load(std::memory_order_acquire) && patch->call_site) {
      dr_unregister_userspace_code(patch->call_site);
      patch->call_site = nullptr;
    }
  auto **entry = &gateway_pages;
  while (*entry) {
    UserspaceGatewayPage *page = *entry;
    for (auto &slot : page->slots)
      if (slot == 3)
        slot = 0;
    if (std::any_of(page->slots.begin(), page->slots.end(),
                    [](unsigned char slot) { return slot != 0; })) {
      entry = &page->next;
      continue;
    }
    if (!dr_custom_free(
            nullptr,
            dr_alloc_flags_t(DR_ALLOC_NON_HEAP | DR_ALLOC_FIXED_LOCATION),
            page->pc, page->size))
      dr_abort();
    *entry = page->next;
    delete page;
  }
  dr_mutex_unlock(patch_lock);
}

void ct_userspace_patch_exit() {
  if (!patch_lock)
    return;
  for (auto &bucket : patch_buckets)
    bucket.store(nullptr, std::memory_order_release);
  while (patch_records) {
    UserspacePatch *patch = patch_records;
    patch_records = patch->next;
    if (patch->call_site)
      dr_unregister_userspace_code(patch->call_site);
    delete patch;
  }
  while (gateway_pages) {
    UserspaceGatewayPage *page = gateway_pages;
    gateway_pages = page->next;
    dr_custom_free(
        nullptr, dr_alloc_flags_t(DR_ALLOC_NON_HEAP | DR_ALLOC_FIXED_LOCATION),
        page->pc, page->size);
    delete page;
  }
  gateway_plans = nullptr;
  dr_mutex_destroy(patch_lock);
  patch_lock = nullptr;
}
