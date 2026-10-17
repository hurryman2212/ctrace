#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <dr_api.h>
#include <drbbdup.h>
#include <drmgr.h>
#include <drreg.h>
#include <drwrap.h>

#include <linux/sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "analysis.h"
#include "analysis_image.h"
#include "analysis_protocol.h"
#include "assembly.h"
#include "decompiled_record.h"
#include "dr_shared_provider.h"
#include "execution_cache.h"
#include "filter.h"
#include "instrumentation.h"
#include "location_record.h"
#include "output.h"
#include "perfetto.h"
#include "perfetto_scope.h"
#include "shared_digest.h"
#include "shared_objects.h"
#include "shared_objects_platform.h"
#include "signal_info.h"
#include "timing.h"
#include "userspace_patch.h"
#include "userspace_version.h"
#include "values.h"

// Large or unbounded functions retain the existing code-cache execution path.
static constexpr size_t userspace_instruction_limit = 65536;
static constexpr unsigned userspace_retire_attempts = 16;
// Bound queued original-byte proofs; completed batches release their staging
// vectors before collecting another batch of a large executable image.
static constexpr size_t initial_instruction_batch = 16384;
// Bound one original-byte read while amortizing safe-read and mapping lookups.
static constexpr size_t initial_proof_chunk = 4096;

struct UserspaceGraph;

struct UserspaceVersionState {
  std::shared_ptr<UserspaceGraph> graph;
  ct_userspace_version *code = nullptr;
  uint64_t preparation = 0;
  uint64_t source_generation = 0;
  std::string error;
};

struct InitialPreparationState {
  enum Status { Pending, Queued, Ready } status = Pending;
  uint64_t generation = 0;
  uint cookie = 0;
  uint64_t attempted_revision = 0;
  bool recursive_expanded = false;
  std::vector<dr_cache_prepare_span_t> spans;
  std::string reason;
};

struct Module : std::enable_shared_from_this<Module> {
  static inline std::atomic<uint64_t> created{0}, reclaimed{0};
  uint64_t incarnation = created.fetch_add(1, std::memory_order_relaxed) + 1;
  app_pc start, end;
  app_pc entry_point = nullptr;
  std::string path, identity;
  bool active = true;
  bool hooks_retired = false;
  bool is_main = false;
  bool runtime_image = false;
  unsigned char runtime_digest[32]{};
  bool userspace_disabled = false;
  bool userspace_revalidation_pending = false;
  bool code_modified = false;
  bool discovered_before_execution = false;
  uint64_t code_generation = 1;
  uint64_t userspace_binding_generation = 1;
  unsigned pending_code_changes = 0;
  unsigned pending_userspace_changes = 0;
  std::map<uint64_t, std::pair<uint64_t, bool>> decompiled_proofs;
  struct OriginalCodeProof {
    uint64_t end, generation;
    bool valid;
  };
  std::map<uint64_t, OriginalCodeProof> original_code_proofs;
  std::map<std::tuple<uint64_t, uint64_t, uint64_t>, uint64_t>
      original_proof_failures;
  ct_analysis *analysis = nullptr;
  ct_values_module *values = nullptr;
  using LocationKey =
      std::tuple<uint64_t, uint64_t, uint64_t, uint32_t, uint32_t, std::string>;
  std::map<LocationKey, std::vector<std::shared_ptr<const ct_location_record>>>
      locations;
  std::vector<std::pair<app_pc, app_pc>> within_inline_ranges;
  std::vector<std::pair<app_pc, app_pc>> observation_inline_ranges;
  std::vector<std::pair<app_pc, app_pc>> userspace_reentry_inline_ranges;
  std::vector<std::pair<app_pc, app_pc>> executable_ranges;
  std::unordered_map<app_pc, bool> quiet_transfers;
  std::unordered_map<std::string, std::vector<ct_execution_recipe>> dr_recipes;
  std::set<app_pc> detailed_blocks;
  std::set<app_pc> userspace_disabled_blocks;
  std::map<std::pair<app_pc, ct_instrument_level>, InitialPreparationState>
      initial_preparations;
  uint64_t initial_ready_generation = 0;
  bool initial_ready_dirty = false;
  std::map<ct_instrument_level, std::map<app_pc, app_pc>> initial_ready;
  std::map<app_pc, app_pc> userspace_ranges;
  std::unordered_set<app_pc> userspace_instructions;
  std::unordered_set<app_pc> userspace_return_gates;
  std::unordered_set<app_pc> userspace_rejected;
  std::map<app_pc, std::shared_ptr<UserspaceGraph>> userspace_graphs;
  std::unordered_set<app_pc> userspace_graph_failures;
  std::map<std::pair<app_pc, ct_instrument_level>, UserspaceVersionState>
      userspace_versions;
  std::vector<ct_userspace_version *> retired_userspace_versions;
  std::unordered_map<app_pc, bool> userspace_resume_instrumented;
  std::unordered_map<app_pc, std::atomic<uint32_t> *> userspace_attempts;
  std::map<uint64_t, uint64_t> flow_ranges;
  std::unordered_set<uint64_t> flow_requests;
  std::unordered_set<uint64_t> flow_decoded;
  std::unordered_map<app_pc, ct_flow_region> flow_regions;
  std::unordered_map<app_pc, app_pc> flow_updates;
  std::unordered_map<app_pc, app_pc> flow_initializers;
  std::unordered_map<app_pc, std::shared_ptr<const ct_flow_switch>>
      flow_switches;
  std::unordered_set<app_pc> perfetto_boundaries;
  std::map<std::pair<uint64_t, std::string>, std::pair<uint64_t, std::string>>
      decompiled_symbols;
  ~Module() {
    ct_values_close(values);
    ct_analysis_close(analysis);
    reclaimed.fetch_add(1, std::memory_order_relaxed);
  }
};

struct Site : std::enable_shared_from_this<Site> {
  static inline std::atomic<uint64_t> created{0}, reclaimed{0};
  std::shared_ptr<Module> module;
  ct_instruction instruction;
  std::shared_ptr<const ct_location_record> location_owner;
  const ct_location_view &location;
  ct_values_site *values = nullptr, *next_values = nullptr;
  size_t source_generation = 0;
  bool source_allowed = false;
  bool prepared = false;
  uint8_t original_size = 0;
  byte original_bytes[15]{};
  bool values_prepared = false;
  bool decompile_checked = false;
  uint64_t decompile_generation = 0;
  uint32_t display_level = 0;
  uint64_t display_generation = 0;
  std::unique_ptr<const ct_decompiled_display_record> decompiled_display;
  std::unique_ptr<const ct_decompiled_statement_record> decompiled;
  std::shared_ptr<const ct_decompiled_variables_record> decompiled_variables;
  bool loop_update_checked = false;
  bool loop_initializer_checked = false;
  std::string loop_update;
  std::unique_ptr<ct_instruction> loop_update_instruction;
  std::unique_ptr<ct_instruction> loop_initializer_instruction;
  enum Mode { Skip, Over, Into, Recurse } mode = Into;
  Mode physical_mode = Into;
  std::vector<Mode> inline_modes;

  Site(std::shared_ptr<Module> owner,
       std::shared_ptr<const ct_location_record> source)
      : module(std::move(owner)), instruction{},
        location_owner(std::move(source)), location(location_owner->view) {
    created.fetch_add(1, std::memory_order_relaxed);
  }
  ~Site() {
    ct_values_site_free(values);
    ct_values_site_free(next_values);
    reclaimed.fetch_add(1, std::memory_order_relaxed);
  }
};

struct Function : std::enable_shared_from_this<Function> {
  static inline std::atomic<uint64_t> created{0}, reclaimed{0};
  std::shared_ptr<Module> module;
  app_pc pc;
  std::string name;
  ct_function *type = nullptr;
  bool within = false;
  bool init_entry = false;
  bool function_type_reported = false;
  bool initial_filter_checked = false;
  bool observed_execution = false;
  Site::Mode initial_mode = Site::Skip;
  bool initial_recurse = false;
  Function() { created.fetch_add(1, std::memory_order_relaxed); }
  ~Function() {
    ct_function_free(type);
    reclaimed.fetch_add(1, std::memory_order_relaxed);
  }
};

struct ArmingSite {
  Module *module = nullptr;
  std::string physical;
  Site::Mode physical_mode = Site::Skip;
  std::vector<Site::Mode> inline_modes;
  bool plt = false;
};

struct OperandType {
  size_t offset = 0;
  std::string identity, type;
};

using MacroValues =
    std::map<std::pair<std::string, size_t>, std::map<uint32_t, std::string>>;

struct MachineContext;

struct Visit {
  std::shared_ptr<Site> first, last;
  bool source = false, structural = false, summary = false, inlined = false;
  bool have_before = false;
  bool suppress_call_completion = false;
  std::shared_ptr<Function> declared_function;
  bool function_closing = false;
  bool return_void = false;
  bool provisional = false;
  bool control_flow = false;
  bool plt_call = false;
  std::string plt_name;
  app_pc plt_target = nullptr;
  Visit *call_deferred = nullptr;
  bool call_decided = false;
  std::string call_name;
  std::string abi_call_code, abi_call_values;
  std::vector<OperandType> abi_call_types;
  bool header_interruption = false;
  size_t comment_offset = std::string::npos;
  size_t assembly_offset = std::string::npos;
  size_t code_offset = std::string::npos;
  size_t function_offset = std::string::npos, function_length = 0;
  int branch_outcome = -1, arrival_outcome = -1;
  std::unordered_set<app_pc> visited;
  std::unordered_set<uint64_t> completed_source_calls;
  std::string before_line, values, results, expression_result, assignment;
  std::string call_results;
  std::string returned_value;
  std::string closing_context;
  MacroValues macro_values;
  std::vector<OperandType> input_types;
  std::vector<OperandType> visible_declarations;
  Visit *header_continuation = nullptr;
  MachineContext *decompile_machine = nullptr;
};

struct SourceBlock {
  ct_source_block description;
  std::shared_ptr<Site> entry, last;
  Visit result;
  Visit header;
  bool initial_header = true;
};

struct TailSummary {
  Visit visit;
  std::shared_ptr<Function> function;
  std::string arguments;
};

struct TraceScope {
  std::shared_ptr<Module> module;
  std::string function;
  bool initialized = false, recurse = false, blocked = false;
  bool plt = false;
  Site::Mode mode = Site::Skip;
  using CaseKey = std::tuple<uint64_t, uint64_t, uint64_t, uint64_t>;
  std::map<CaseKey, uint64_t> case_groups;
};

struct MachineBlock {
  std::shared_ptr<Site> last;
  app_pc join, repeat;
  std::string opening;
  std::shared_ptr<const ct_flow_switch> switch_region{};
  app_pc case_pc = nullptr;
  uint64_t trace_token = 0;
  std::string trace_name{};
  std::string trace_origin = "recovered";
};

struct RuntimeSourceBlock {
  std::shared_ptr<Site> entry;
  const ct_source_block *description;
  uint64_t token;
};

enum class BranchClosure { None, Close, Else, Condition };
enum class ArrivalAnnotation { None, Call };

struct MachineContext {
  bool timing_only = false;
  bool trace_body = false;
  uint64_t trace_function = 0;
  std::string trace_function_name;
  std::vector<RuntimeSourceBlock> trace_blocks;
  std::string scope_name = "<unknown>";
  std::string function_alias;
  std::shared_ptr<Site> plt_last;
  ct_branch_condition comparison;
  app_pc comparison_pc = nullptr;
  app_pc timing_comparison_next = nullptr;
  ct_branch_condition trace_comparison;
  app_pc trace_comparison_next = nullptr;
  std::vector<MachineBlock> blocks;
  std::vector<Visit> condition_rows;
  std::vector<Visit> decompiled_rows;
  std::shared_ptr<Module> decompiled_module;
  app_pc decompiled_entry = nullptr;
  uint64_t decompiled_stack = 0;
  std::vector<ct_decompiled_operand> decompiled_operands;
  std::shared_ptr<const ct_decompiled_variables_record> decompiled_owner{};
  std::shared_ptr<Module> update_module;
  app_pc update_branch = nullptr, update_next = nullptr;
};

struct DeferredSourceLine {
  std::string text, closing_context;
};

struct SyscallContext {
  int number = -1;
  uint64_t token = 0;
  app_pc pc = nullptr;
  std::string details;
};

struct Call {
  ct_shared_key userspace_waited_key{};
  bool timing_only = false;
  int signal_number = 0;
  uint64_t trace_signal_context = 0;
  SyscallContext interrupted_syscall;
  std::shared_ptr<Function> function, source_function;
  std::shared_ptr<Site> source_call_site;
  const ct_source_call_result *source_call_result = nullptr;
  bool source_policy_seen = false, source_step_over = false;
  bool source_skipped = false;
  bool source_call_ambiguous = false;
  app_pc entry_pc = nullptr;
  app_pc return_pc = nullptr;
  uint64_t entry_sp = 0;
  uint64_t interrupted_sp = 0;
  bool frame_base_restored = false, signal_frame = false;
  bool startup_entry = false;
  bool startup_controlled = false;
  bool signal_handler_active = false;
  bool within = false, within_inline = false, within_synthetic = false;
  bool source_linkage = false, linkage = false, linkage_child = false;
  TraceScope scope;
  Visit deferred_call;
  std::shared_ptr<Site> deferred_target;
  std::shared_ptr<Function> deferred_function;
  Site::Mode deferred_mode = Site::Skip;
  Visit visit;
  Visit summary;
  Visit returning;
  std::vector<std::unique_ptr<SourceBlock>> blocks;
  std::vector<Visit> block_exits;
  std::shared_ptr<Function> returning_function;
  std::string returning_arguments;
  std::vector<DeferredSourceLine> return_lines;
  std::shared_ptr<Function> summary_function;
  std::string summary_arguments;
  std::vector<TailSummary> tail_summaries;
  Visit *parent = nullptr;
  std::string arguments;
  std::string declaration, entry_arguments, invocation;
  std::vector<OperandType> entry_types;
  std::string display_name, display_symbol;
  bool entry_reported = false, decompiled_declaration = false;
  std::shared_ptr<Site> assembly_entry, assembly_last;
  std::string assembly_scope, assembly_invocation;
  ct_provenance provenance;
  MachineContext machine;
};

struct Pending {
  std::shared_ptr<Site> site;
  Visit *visit = nullptr;
  ct_registers before{};
  ct_provenance *provenance = nullptr;
  bool recurse = false, blocked = false;
  bool linkage = false;
  std::vector<ct_decompiled_operand> decompiled_operands{};
  bool timing_only = false, timing_source = false;
  std::shared_ptr<const ct_decompiled_variables_record> decompiled_owner{};
};

struct UserspacePreparation;
struct InitialPreparation;

struct CodeChange {
  std::shared_ptr<Module> module;
  bool original = false;
};

struct Thread {
  process_id_t process = 0;
  thread_id_t tid = 0;
  bool recording = false;
  bool owns_image = false;
  bool new_stack_scope = false, child_new_stack = false;
  bool discovering_modules = false, collecting_initial = false;
  InitialPreparation *initial_build = nullptr;
  std::vector<std::unique_ptr<InitialPreparation>> initial_requests;
  uint64_t exec_ticket = 0;
  ct_shared_channel *shared_channel = nullptr;
  ct_shared_key userspace_waited_key{};
  ct_shared_fork_reservation shared_fork{0, 0, 0, -1};
  bool fork_snapshot_pending = false;
  Thread *fork_vanished = nullptr, *fork_vanished_next = nullptr;
  reg_t shared_child_stack = 0;
  app_pc userspace_step_end = nullptr;
  bool userspace_copy_pending = false;
  ct_instrument_level userspace_copy_level = ct_instrument_level::arm;
  ct_perfetto_timestamp trace_timestamp, trace_signal_timestamp;
  bool resume_quiet_generation = false;
  bool timing_started = false;
  bool resume_quiet_suspension = false;
  unsigned quiet_callback_depth = 0;
  SyscallContext syscall;
  std::vector<std::pair<int, std::vector<CodeChange>>> changing_code;
  std::vector<std::shared_ptr<Module>> preparation_modules;
  std::vector<std::shared_ptr<UserspacePreparation>> arming_preparations;
  int signal_number = 0;
  std::string signal_description;
  Visit deferred_call;
  Visit root;
  TraceScope root_scope;
  ct_provenance root_provenance;
  MachineContext root_machine;
  std::vector<Call *> calls;
  Pending pending;
  dr_mcontext_t context{};
  std::vector<std::unique_ptr<SourceBlock>> blocks;
  app_pc arrival_pc = nullptr;
  app_pc assembly_arrival_pc = nullptr;
  app_pc plt_marker_pc = nullptr;
  int arrival_outcome = -1;
  app_pc annotation_pc = nullptr;
  ArrivalAnnotation arrival_annotation = ArrivalAnnotation::None;
};

struct InitialPreparation {
  struct Scope {
    app_pc pc;
    bool plain, recursive, within;
  };
  std::shared_ptr<Module> module;
  app_pc function = nullptr;
  ct_instrument_level level = ct_instrument_level::full;
  uint64_t generation = 0;
  uint cookie = 0;
  bool early = false;
  uint resume_cookie = 0;
  bool resume_phase = false;
  bool source_mismatch = false;
  size_t generated = 0, reused = 0;
  std::vector<ct_flow_instruction> instructions;
  // Borrow the already interned source records while this bounded batch is
  // being emitted. The userspace collector needs the identical scope view.
  std::vector<std::shared_ptr<const ct_location_record>> locations;
  std::vector<dr_cache_prepare_span_t> spans;
  std::vector<dr_cache_prepare_span_t> resumes;
  std::vector<Scope> scopes;
  std::unique_ptr<ct_execution_batch> execution;
};

static std::vector<std::shared_ptr<Module>> modules;
static std::vector<std::shared_ptr<Function>> functions;
static std::unordered_map<app_pc, std::shared_ptr<Site>> current_sites;
static std::unordered_map<app_pc, std::shared_ptr<Function>> current_functions;
// Generated DR fragments embed these cell addresses. Reuse each original-PC
// cell across mapping incarnations without retaining an entire Module.
static std::unordered_map<app_pc, std::unique_ptr<std::atomic<uint32_t>>>
    userspace_attempt_tokens;
static std::unordered_set<std::string> warnings;
static void *analysis_lock;
static void *module_hook_lock;
static void *display_lock;
static std::unordered_set<std::string> displayed_macros;
static std::unordered_set<std::string> displayed_operand_types;
static int tls_index = -1, syntax = -1;
static bool no_style = false;
static bool decompile = false;
static ct_instrument_level initial_level = ct_instrument_level::full;

static bool structural_instrumentation() { return ct_perfetto_enabled(); }
static bool follow_forks = false, process_recording = true;
static std::atomic<bool> trace_activated{false};
static std::atomic<bool> boundary_observation_started{false};
static_assert(sizeof(trace_activated) == 1 &&
              std::atomic<bool>::is_always_lock_free);
static std::unordered_map<app_pc, ArmingSite> arming_sites;
static bool instrumentation_statistics = false;
static std::atomic<uint64_t> generated_versions[3]{}, executed_versions[3]{};
static std::atomic<uint64_t> generated_userspace_versions[3]{},
    returned_userspace_versions[3]{};
static std::atomic<uint64_t> restored_userspace_templates[3]{},
    restored_userspace_common[3]{}, decoded_userspace_instructions[3]{};
static uint64_t userspace_version_generation = 0;
static uint64_t reclaimed_userspace_versions = 0;
static std::unordered_map<ct_userspace_version *, uint64_t>
    shared_userspace_versions;
static std::vector<uint64_t> released_shared_versions;
static std::atomic<uint64_t> published_shared_versions[3]{},
    restored_shared_versions[3]{}, shared_version_fallbacks[3]{};
static std::string shared_runtime_identity;
static bool shared_dr_enabled = false;
static std::map<std::pair<ct_instrument_level, std::string>, uint64_t>
    userspace_version_fallbacks;
static std::atomic<uint64_t> detailed_fragments{0},
    prehit_detailed_fragments{0}, userspace_graphs_prepared{0},
    prehit_userspace_graphs{0};
static std::atomic<uint64_t> fork_threads_reclaimed{0};
static uint initial_preparation_cookie = 0;
static uint64_t initial_catalog_revision = 1;
static size_t initial_requests_pending = 0;
static std::atomic<void *> initial_context{nullptr};
static process_id_t owner_pid;
static std::string program_name;
static std::unordered_map<thread_id_t, thread_id_t> inherited_thread_ids;
struct SharedOrigin {
  std::vector<std::unique_ptr<Call>> calls;
  bool new_stack_scope = false;
};
static std::unordered_map<reg_t, SharedOrigin> shared_origins;
static std::string source_maps;
static std::string execution_policy;
static ct_filter into_filter, over_filter, recurse_filter, within_filter;
static bool filtered = false, within_enabled = false, duplicate_enabled = false;
static bool within_intr = false, within_init = false;
static bool within_new_stack = false;
static bool within_patterns_enabled = false;
static bool recursive_selection = false;
static reg_id_t within_tls_register;
static uint within_tls_offset;
static uint dispatch_tls_offset;
static app_pc main_start;
static size_t analysis_generation = 1;
static constexpr size_t value_capacity = 16384;
// Bound lookahead across long runs of instructions that preserve a condition.
static constexpr size_t condition_row_limit = 64;
// Caller evidence is limited to the immediate straight-line continuation.
static constexpr size_t return_use_instruction_limit = 32;

struct Lock {
  void *mutex;
  explicit Lock(void *value) : mutex(value) { dr_mutex_lock(mutex); }
  ~Lock() { dr_mutex_unlock(mutex); }
};

// Preparation callbacks can be suspended at DR's NO_LOCKS_NO_XFER safe points.
// Keep their owners in TLS as well as ordinary scopes so a fork child can
// destroy the copied owners belonging to vanished threads.
struct PreparationScope {
  Thread &thread;
  size_t modules, plans;
  explicit PreparationScope(Thread &owner)
      : thread(owner), modules(owner.preparation_modules.size()),
        plans(owner.arming_preparations.size()) {}
  void hold(Module &module) {
    if (std::none_of(thread.preparation_modules.begin() + modules,
                     thread.preparation_modules.end(),
                     [&](const auto &owner) { return owner.get() == &module; }))
      thread.preparation_modules.push_back(module.shared_from_this());
  }
  ~PreparationScope() {
    Lock lock(analysis_lock);
    thread.arming_preparations.resize(plans);
    thread.preparation_modules.resize(modules);
  }
};

// Called only after hooks have been fenced and copied executable bodies have
// been retired. Runtime Sites, Calls and registered producers own any metadata
// still needed by an older mapping incarnation.
static void reclaim_modules() {
  modules.erase(
      std::remove_if(modules.begin(), modules.end(),
                     [](const auto &module) {
                       return !module->active && module->hooks_retired &&
                              module->userspace_versions.empty() &&
                              module->retired_userspace_versions.empty();
                     }),
      modules.end());
}

static bool traced_process() {
  void *context = dr_get_current_drcontext();
  // DR maintains this identity at thread creation and ordinary fork before
  // invoking client callbacks. Avoid a raw getpid syscall at every trace gate.
  const process_id_t process =
      context ? dr_get_process_id_from_drcontext(context) : dr_get_process_id();
  if (process == owner_pid)
    return true;
  if (!context || tls_index < 0)
    return false;
  // CLONE_VM children share client globals but have their own DR context.
  // An ordinary fork does not become active until its fork callback runs.
  auto *thread = static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
  return thread && thread->process == process;
}

// Recording membership is independent of DR ownership and --within. Excluded
// tasks still need the runtime's syscall, signal and shared-text safety hooks.
static bool recording_thread(void *context = nullptr) {
  if (!process_recording)
    return false;
  if (!context)
    context = dr_get_current_drcontext();
  if (!context)
    return false;
  if (tls_index >= 0) {
    const auto *thread =
        static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
    if (thread)
      return thread->recording;
  }
  return follow_forks ||
         context == initial_context.load(std::memory_order_relaxed);
}

static void fail(const char *message) {
  const std::string line = "ctrace: " + std::string(message) + "\n";
  ct_output_write(line.data(), line.size());
  dr_abort();
}

static std::string unstyled(const std::string &text) {
  std::string result;
  for (size_t offset = 0; offset < text.size();) {
    if (text[offset] == '\033' && offset + 1 < text.size() &&
        text[offset + 1] == '[') {
      const size_t end = text.find('m', offset + 2);
      if (end != std::string::npos) {
        offset = end + 1;
        continue;
      }
    }
    result += text[offset++];
  }
  return result;
}

// Keep aggregate/member values and function results intact when combining
// observations. Commas inside a value are not separators between observations.
static std::vector<std::pair<size_t, size_t>>
decompiled_fields(const std::string &text, bool before_only = false) {
  std::vector<std::pair<size_t, size_t>> fields;
  size_t start = 0;
  int depth = 0;
  char quote = 0;
  for (size_t index = 0; index <= text.size(); ++index) {
    const bool result = before_only && !quote && !depth &&
                        (text.compare(index, 4, " -> ") == 0 ||
                         (index < text.size() && text[index] == '\n'));
    if (index == text.size() || result ||
        (!quote && !depth && text[index] == ',')) {
      if (index > start)
        fields.emplace_back(start, index - start);
      if (result)
        break;
      start = index + 1;
      while (start < text.size() && text[start] == ' ')
        ++start;
      continue;
    }
    const char ch = text[index];
    if (ch == '\033' && index + 1 < text.size() && text[index + 1] == '[') {
      const auto end = text.find('m', index + 2);
      if (end != std::string::npos) {
        index = end;
        continue;
      }
    }
    if (quote) {
      if (ch == '\\' && index + 1 < text.size())
        ++index;
      else if (ch == quote)
        quote = 0;
    } else if (ch == '\'' || ch == '"') {
      quote = ch;
    } else if (ch == '(' || ch == '[' || ch == '{') {
      ++depth;
    } else if ((ch == ')' || ch == ']' || ch == '}') && depth) {
      --depth;
    }
  }
  return fields;
}

static std::pair<std::string, size_t>
highlight_step_into_call(const std::string &line, size_t comment_offset,
                         const std::string &name,
                         std::string *expression = nullptr) {
  if (expression)
    expression->clear();
  const size_t separator = line.find(" | ");
  if (separator == std::string::npos || name.empty())
    return {line, comment_offset};
  const size_t begin = separator + 3;
  const size_t end = std::min(comment_offset, line.size());
  std::string code;
  std::vector<size_t> positions;
  for (size_t pos = begin; pos < end;) {
    if (line[pos] == '\033' && pos + 1 < end && line[pos + 1] == '[') {
      const size_t stop = line.find('m', pos + 2);
      if (stop < end) {
        pos = stop + 1;
        continue;
      }
    }
    positions.push_back(pos);
    code += line[pos++];
  }
  auto identifier = [](unsigned char character) {
    return std::isalnum(character) || character == '_';
  };
  std::vector<std::pair<size_t, size_t>> spans;
  char quote = 0;
  for (size_t cursor = 0; cursor < code.size(); ++cursor) {
    const char character = code[cursor];
    if (quote) {
      if (character == '\\' && cursor + 1 < code.size())
        ++cursor;
      else if (character == quote)
        quote = 0;
      continue;
    }
    if (character == '\'' || character == '"') {
      quote = character;
      continue;
    }
    if (code.compare(cursor, 2, "//") == 0 || character == '#')
      break;
    if (code.compare(cursor, 2, "/*") == 0) {
      const size_t stop = code.find("*/", cursor + 2);
      if (stop == std::string::npos)
        break;
      cursor = stop + 1;
      continue;
    }
    if (code.compare(cursor, name.size(), name) != 0 ||
        (cursor && (identifier(code[cursor - 1]) || code[cursor - 1] == ':')))
      continue;
    size_t opening = cursor + name.size();
    while (opening < code.size() &&
           std::isspace(static_cast<unsigned char>(code[opening])))
      ++opening;
    if (opening >= code.size() || code[opening] != '(')
      continue;
    std::vector<char> nesting;
    char literal = 0;
    size_t finish = opening;
    for (; finish < code.size(); ++finish) {
      const char token = code[finish];
      if (literal) {
        if (token == '\\' && finish + 1 < code.size())
          ++finish;
        else if (token == literal)
          literal = 0;
        continue;
      }
      if (token == '\'' || token == '"') {
        literal = token;
        continue;
      }
      if (code.compare(finish, 2, "//") == 0 || token == '#')
        break;
      if (code.compare(finish, 2, "/*") == 0) {
        const size_t stop = code.find("*/", finish + 2);
        if (stop == std::string::npos)
          break;
        finish = stop + 1;
        continue;
      }
      if (token == '(' || token == '[' || token == '{') {
        nesting.push_back(token == '(' ? ')' : token == '[' ? ']' : '}');
      } else if (token == ')' || token == ']' || token == '}') {
        if (nesting.empty() || nesting.back() != token)
          break;
        nesting.pop_back();
        if (nesting.empty()) {
          spans.emplace_back(cursor, finish + 1);
          break;
        }
      }
    }
  }
  // A single recovered statement normally contains one call. Repeated or
  // nested calls with the same spelling need an instruction-backed occurrence
  // before highlighting one of them; the callee name alone is insufficient.
  if (spans.size() != 1)
    return {line, comment_offset};
  const auto [opening, closing] = spans.front();
  if (expression)
    *expression = code.substr(opening, closing - opening);
  const size_t first = positions[opening], last = positions[closing - 1] + 1;
  const std::string replacement = "\033[42;97m" +
                                  code.substr(opening, closing - opening) +
                                  "\033[0m\033[32m";
  std::string result = line;
  result.replace(first, last - first, replacement);
  return {result, comment_offset < line.size()
                      ? comment_offset - (last - first) + replacement.size()
                      : comment_offset};
}

// Observations retain comma delimiters internally for value matching and type
// offsets. Normalize only the final display, preserving nested C expressions.
static std::vector<std::pair<size_t, size_t>>
format_observations(std::string &line, size_t begin) {
  std::vector<std::pair<size_t, size_t>> unavailable;
  std::string formatted = line.substr(0, begin);
  size_t field_begin = begin;
  const auto finish_field = [&](size_t start, bool nested = false) {
    size_t first = start, last = formatted.size();
    while (first < last && std::isspace((unsigned char)formatted[first]))
      ++first;
    while (last > first && std::isspace((unsigned char)formatted[last - 1]))
      --last;
    const std::string field = unstyled(formatted.substr(first, last - first));
    const size_t equals = field.rfind('=');
    if (equals == std::string::npos) {
      if (nested && field == "?")
        unavailable.emplace_back(first, last);
      return;
    }
    size_t value = equals + 1;
    while (value < field.size() && std::isspace((unsigned char)field[value]))
      ++value;
    // A missing type, `(?)`, is different from a missing evaluated value.
    while (value < field.size() && field[value] == '(') {
      size_t depth = 1;
      for (++value; value < field.size() && depth; ++value) {
        if (field[value] == '(')
          ++depth;
        else if (field[value] == ')')
          --depth;
      }
      if (depth)
        return;
      while (value < field.size() && std::isspace((unsigned char)field[value]))
        ++value;
    }
    if (value + 1 == field.size() && field[value] == '?')
      unavailable.emplace_back(first, last);
  };
  size_t depth = 0;
  std::vector<std::pair<size_t, size_t>> aggregate_fields;
  char quote = 0;
  for (size_t offset = begin; offset < line.size();) {
    const char ch = line[offset];
    if (ch == '\033' && offset + 1 < line.size() && line[offset + 1] == '[') {
      const size_t end = line.find('m', offset + 2);
      if (end != std::string::npos) {
        formatted.append(line, offset, end - offset + 1);
        offset = end + 1;
        continue;
      }
    }
    if (quote) {
      formatted += ch;
      ++offset;
      if (ch == '\\' && offset < line.size())
        formatted += line[offset++];
      else if (ch == quote)
        quote = 0;
      continue;
    }
    if (ch == '\'' || ch == '"') {
      quote = ch;
    } else if (line.compare(offset, 2, "/*") == 0) {
      if (!depth)
        finish_field(field_begin);
      const size_t closing = line.find("*/", offset + 2);
      const size_t end =
          closing == std::string::npos ? line.size() : closing + 2;
      formatted.append(line, offset, end - offset);
      offset = end;
      if (!depth)
        field_begin = formatted.size();
      continue;
    } else if (!depth && (ch == ',' || ch == ';' || ch == '\n' ||
                          line.compare(offset, 3, "-> ") == 0)) {
      finish_field(field_begin);
      if (ch == ',') {
        ++offset;
        while (offset < line.size() && line[offset] == ' ')
          ++offset;
        formatted += ' ';
      } else if (ch == '-') {
        formatted += "-> ";
        offset += 3;
      } else {
        formatted += ch;
        ++offset;
      }
      field_begin = formatted.size();
      continue;
    } else if ((ch == ',' || ch == ';') && !aggregate_fields.empty() &&
               aggregate_fields.back().first == depth) {
      finish_field(aggregate_fields.back().second, true);
      aggregate_fields.back().second = formatted.size() + 1;
    } else if (ch == '(' || ch == '[' || ch == '{') {
      ++depth;
      if (ch == '[' || ch == '{')
        aggregate_fields.emplace_back(depth, formatted.size() + 1);
    } else if ((ch == ')' || ch == ']' || ch == '}') && depth) {
      if (!aggregate_fields.empty() && aggregate_fields.back().first == depth) {
        finish_field(aggregate_fields.back().second, true);
        aggregate_fields.pop_back();
      }
      --depth;
    }
    formatted += ch;
    ++offset;
  }
  finish_field(field_begin);
  std::sort(unavailable.begin(), unavailable.end());
  line = std::move(formatted);
  return unavailable;
}

enum class Notification { None, Signal };

static void
write_line(const std::string &input, size_t comment_offset = std::string::npos,
           const ct_location_view *source = nullptr, int branch_outcome = -1,
           size_t assembly_offset = std::string::npos,
           const MacroValues *macro_values = nullptr, int arrival_outcome = -1,
           const std::vector<OperandType> *input_types = nullptr,
           size_t function_offset = std::string::npos,
           size_t function_length = 0, const std::string &closing_context = {},
           const std::vector<OperandType> *declarations = nullptr,
           const std::string &tracked_call = {},
           Notification notification = Notification::None) {
  if (!ct_output_trace_enabled())
    return;
  Lock display(display_lock);
  std::string line = input;
  if (declarations)
    for (auto declaration = declarations->rbegin();
         declaration != declarations->rend(); ++declaration) {
      if (declaration->identity.empty() ||
          (declaration->type.empty() &&
           declaration->offset != std::string::npos) ||
          (declaration->offset != std::string::npos &&
           declaration->offset > line.size()) ||
          !displayed_operand_types.insert(declaration->identity).second ||
          declaration->offset == std::string::npos)
        continue;
      const std::string type = declaration->type + " ";
      line.insert(declaration->offset, type);
      if (comment_offset != std::string::npos &&
          comment_offset >= declaration->offset)
        comment_offset += type.size();
      if (assembly_offset != std::string::npos &&
          assembly_offset >= declaration->offset)
        assembly_offset += type.size();
      if (function_offset != std::string::npos &&
          function_offset >= declaration->offset)
        function_offset += type.size();
    }
  if (comment_offset < line.size() && line.size() - comment_offset >= 2) {
    struct Introduction {
      const OperandType *operand;
      size_t begin, end;
    };
    std::vector<Introduction> insertions;
    const auto fields =
        decompiled_fields(line.substr(comment_offset + 2), true);
    if (input_types)
      for (const auto &operand : *input_types) {
        const auto field =
            std::find_if(fields.begin(), fields.end(), [&](const auto &span) {
              return operand.offset >= span.first &&
                     operand.offset < span.first + span.second;
            });
        if (field != fields.end() && !operand.identity.empty() &&
            displayed_operand_types.insert(operand.identity).second)
          insertions.push_back(
              {&operand, comment_offset + 2 + field->first,
               comment_offset + 2 + field->first + field->second});
      }
    // DWARF call summaries already carry their first-use type spelling.
    // Highlight those complete fields without inserting a second cast.
    for (const auto &[offset, length] : fields) {
      const size_t begin = comment_offset + 2 + offset;
      if (std::any_of(insertions.begin(), insertions.end(),
                      [&](const auto &entry) { return entry.begin == begin; }))
        continue;
      const std::string field = unstyled(line.substr(begin, length));
      const size_t equals = field.find('=');
      if (equals == std::string::npos || equals + 1 >= field.size() ||
          field[equals + 1] != '(')
        continue;
      size_t depth = 0, end = equals + 1;
      bool type = true;
      for (; end < field.size(); ++end) {
        const unsigned char ch = field[end];
        if (ch == '(')
          ++depth;
        else if (ch == ')' && !--depth) {
          ++end;
          break;
        }
        if (!std::isalnum(ch) && !std::isspace(ch) &&
            std::string("_*?()[]").find(ch) == std::string::npos)
          type = false;
      }
      if (type && !depth && end < field.size())
        insertions.push_back({nullptr, begin, begin + length});
    }
    // Choose first use in visible operand order, then insert backwards so
    // offsets remain valid. Delayed instruction rows must not claim it early.
    std::sort(insertions.begin(), insertions.end(),
              [](const auto &left, const auto &right) {
                return left.begin < right.begin;
              });
    for (auto item = insertions.rbegin(); item != insertions.rend(); ++item) {
      if (!no_style)
        line.insert(item->end, "\033[22m");
      if (item->operand)
        line.insert(
            comment_offset + 2 + item->operand->offset,
            "(" + (item->operand->type.empty() ? "?" : item->operand->type) +
                ")");
      if (!no_style)
        line.insert(item->begin, "\033[1m");
    }
  }
  if (source) {
    std::string annotations;
    for (size_t index = 0; index < source->source_macro_count; ++index) {
      const auto &macro = source->source_macros[index];
      if (!macro.identity[0] || !macro.text[0] ||
          !displayed_macros.insert(macro.identity).second)
        continue;
      if (!annotations.empty())
        annotations += ", ";
      std::string text = macro.text;
      if (macro_values && macro.call_count <= std::size(macro.calls)) {
        const auto observed = macro_values->find({macro.identity, index});
        if (observed != macro_values->end()) {
          // All spans refer to the original expansion. Work backwards so
          // addresses from one call cannot shift another call's placeholders.
          const size_t original_size = text.size();
          for (auto value = observed->second.rbegin();
               value != observed->second.rend(); ++value) {
            const auto *call =
                std::find_if(macro.calls, macro.calls + macro.call_count,
                             [&](const ct_macro_call &entry) {
                               return entry.address_begin == value->first;
                             });
            if (call != macro.calls + macro.call_count &&
                value->first < call->address_end &&
                call->address_end <= original_size)
              text.replace(value->first, call->address_end - value->first,
                           value->second);
          }
        }
      }
      annotations += text;
    }
    if (!annotations.empty()) {
      if (comment_offset < line.size()) {
        const size_t position = comment_offset + 2;
        const bool result_only = line.compare(position, 3, "-> ") == 0;
        line.insert(position, annotations + (result_only ? " " : ", "));
      } else {
        const size_t position = line.size() - (line.back() == '\n' ? 1 : 0);
        comment_offset = position + 1;
        line.insert(position, " # " + annotations);
      }
    }
  }
  if (!closing_context.empty()) {
    const size_t position =
        line.size() - (!line.empty() && line.back() == '\n');
    if (comment_offset < line.size()) {
      line.insert(position, "; /* " + closing_context + " */");
    } else {
      comment_offset = position + 1;
      line.insert(position, " # /* " + closing_context + " */");
    }
  }
  if (!no_style && function_length && function_offset < line.size() &&
      function_length <= line.size() - function_offset) {
    const size_t end = function_offset + function_length;
    line.insert(end, "\033[49m");
    line.insert(function_offset, "\033[22;44m");
    const size_t added = std::strlen("\033[22;44m\033[49m");
    if (comment_offset != std::string::npos && comment_offset >= end)
      comment_offset += added;
    if (assembly_offset != std::string::npos && assembly_offset >= end)
      assembly_offset += added;
  }
  if (!no_style && !decompile && arrival_outcome == 1 &&
      line.compare(0, 5, "[tid ") == 0) {
    const size_t tid_end = line.find("] ");
    const size_t begin =
        tid_end == std::string::npos ? line.size() : tid_end + 2;
    const size_t end = line.find(' ', begin);
    if (end != std::string::npos && begin < end && line[begin] == 'L') {
      const std::string style = "\033[22;44m";
      line.insert(end, "\033[49m");
      line.insert(begin, style);
      const size_t added = style.size() + std::strlen("\033[49m");
      if (comment_offset != std::string::npos && comment_offset >= end)
        comment_offset += added;
      if (assembly_offset != std::string::npos && assembly_offset >= end)
        assembly_offset += added;
    }
  }
  if (!no_style && branch_outcome >= 0 && assembly_offset < line.size()) {
    const size_t end = comment_offset < line.size()
                           ? comment_offset - 1
                           : line.size() - (line.back() == '\n' ? 1 : 0);
    if (end > assembly_offset) {
      const std::string assembly =
          line.substr(assembly_offset, end - assembly_offset);
      const size_t opening = assembly.find('"');
      const size_t closing = opening == std::string::npos
                                 ? std::string::npos
                                 : assembly.find('"', opening + 1);
      if (closing != std::string::npos) {
        const std::string style =
            branch_outcome ? "\033[22;44m" : "\033[22;41m";
        std::string replacement = assembly.substr(0, opening + 1) + style;
        for (size_t offset = opening + 1; offset < closing;) {
          if (assembly[offset] == '\033' && offset + 1 < closing &&
              assembly[offset + 1] == '[') {
            const size_t reset = assembly.find('m', offset + 2);
            if (reset < closing) {
              replacement.append(assembly, offset, reset - offset + 1);
              // Preserve the existing foreground, including resolved operands.
              replacement += style;
              offset = reset + 1;
              continue;
            }
          }
          replacement += assembly[offset++];
        }
        replacement += "\033[49m" + assembly.substr(closing);
        line.replace(assembly_offset, end - assembly_offset, replacement);
        if (comment_offset != std::string::npos)
          comment_offset = assembly_offset + replacement.size() + 1;
      }
    }
  }
  if (!no_style && !tracked_call.empty()) {
    auto highlighted =
        highlight_step_into_call(line, comment_offset, tracked_call);
    line = std::move(highlighted.first);
    comment_offset = highlighted.second;
  }
  if (!no_style) {
    const size_t separator = line.find(" | ");
    const size_t begin =
        separator == std::string::npos ? line.size() : separator + 3;
    const size_t end = std::min(comment_offset, line.size());
    if (begin < end) {
      std::string code;
      std::vector<size_t> positions;
      std::vector<std::string> styles;
      std::string style;
      for (size_t index = begin; index < end;) {
        if (line[index] == '\033' && index + 1 < end &&
            line[index + 1] == '[') {
          const size_t stop = line.find('m', index + 2);
          if (stop < end) {
            const std::string sequence = line.substr(index, stop + 1 - index);
            if (sequence == "\033[0m" || sequence == "\033[m")
              style.clear();
            else
              style += sequence;
            index = stop + 1;
            continue;
          }
        }
        code += line[index];
        positions.push_back(index++);
        styles.push_back(style);
      }
      std::vector<bool> highlight(code.size(), false),
          semicolon(code.size(), false);
      char quote = 0;
      bool comment = false;
      for (size_t index = 0; index < code.size(); ++index) {
        const char character = code[index];
        if (quote) {
          if (character == '\\' && index + 1 < code.size())
            ++index;
          else if (character == quote)
            quote = 0;
          continue;
        }
        if (comment) {
          if (code.compare(index, 2, "*/") == 0) {
            comment = false;
            ++index;
          }
          continue;
        }
        if (character == '#' || code.compare(index, 2, "//") == 0)
          break;
        if (code.compare(index, 2, "/*") == 0) {
          comment = true;
          ++index;
        } else if (character == '\'' || character == '"') {
          quote = character;
        } else if (character == '{' || character == '}') {
          highlight[index] = true;
          if (index && code[index - 1] == (character == '{' ? '(' : ')'))
            highlight[index - 1] = true;
          if (character == '}' && index + 1 < code.size() &&
              code[index + 1] == ')')
            highlight[index + 1] = true;
        } else if (character == ';') {
          semicolon[index] = true;
        }
      }
      for (size_t index = positions.size(); index; --index) {
        const size_t token = index - 1;
        if (!highlight[token] && !semicolon[token])
          continue;
        const std::string opening =
            highlight[token] ? "\033[42;97m" : "\033[49m";
        const std::string closing = "\033[0m" + styles[token];
        line.insert(positions[token] + 1, closing);
        line.insert(positions[token], opening);
        if (comment_offset != std::string::npos)
          comment_offset += opening.size() + closing.size();
      }
    }
  }
  std::string styled;
  if (comment_offset < line.size()) {
    const auto unavailable = format_observations(line, comment_offset + 2);
    const bool annotation = line.compare(comment_offset, 4, "# /*") == 0;
    bool explanation = false;
    bool introduction = false;
    bool unknown = false;
    const auto comment_style = [&]() {
      return unknown ? (introduction ? "\033[1;39;41m" : "\033[22;39;41m")
             : introduction ? "\033[1;39;44m"
             : annotation || explanation
                 ? (notification == Notification::Signal ? "\033[1;39;45m"
                                                         : "\033[22;39;45m")
                 : "\033[22;34;49m";
    };
    styled = line.substr(0, comment_offset) + comment_style();
    char quote = 0;
    size_t unavailable_index = 0;
    for (size_t offset = comment_offset; offset < line.size();) {
      while (unavailable_index < unavailable.size() &&
             unavailable[unavailable_index].second <= offset)
        ++unavailable_index;
      const bool missing = unavailable_index < unavailable.size() &&
                           unavailable[unavailable_index].first <= offset;
      if (unknown != missing) {
        unknown = missing;
        styled += comment_style();
      }
      if (line[offset] == '\033' && offset + 1 < line.size() &&
          line[offset + 1] == '[') {
        const size_t end = line.find('m', offset + 2);
        if (end != std::string::npos) {
          // First introductions use blue, unavailable values use red. Preserve
          // their styles through operand colors and embedded resets.
          if (line.compare(offset, end - offset + 1, "\033[1m") == 0)
            introduction = true;
          else if (line.compare(offset, end - offset + 1, "\033[22m") == 0)
            introduction = false;
          styled.append(line, offset, end - offset + 1);
          styled += comment_style();
          offset = end + 1;
          continue;
        }
      }
      if (!quote && !explanation && line.compare(offset, 2, "/*") == 0) {
        explanation = true;
        styled += comment_style();
      } else if (explanation && line.compare(offset, 2, "*/") == 0) {
        styled += "*/";
        offset += 2;
        explanation = false;
        styled += comment_style();
        continue;
      } else if (!explanation) {
        if (quote && line[offset] == '\\' && offset + 1 < line.size()) {
          styled.append(line, offset, 2);
          offset += 2;
          continue;
        }
        if (quote && line[offset] == quote)
          quote = 0;
        else if (!quote && (line[offset] == '\'' || line[offset] == '"'))
          quote = line[offset];
      }
      if (line[offset] == '\n')
        styled += "\033[0m";
      styled += line[offset++];
    }
    if (line.back() != '\n')
      styled += "\033[0m";
  }
  std::string output =
      no_style ? unstyled(line) : (styled.empty() ? line : styled);
  if (output.compare(0, 5, "[tid ") == 0) {
    const size_t end = output.find(']', 5);
    if (end != std::string::npos) {
      const auto tid = static_cast<thread_id_t>(
          std::strtoul(output.c_str() + 5, nullptr, 10));
      const auto inherited = inherited_thread_ids.find(tid);
      if (inherited != inherited_thread_ids.end())
        output.replace(5, end - 5, std::to_string(inherited->second));
    }
    output.insert(0, program_name);
  }
  if (!ct_output_trace_write(output.data(), output.size()))
    dr_abort();
}

static void write_warning(const std::string &input) {
  const std::string plain = unstyled(input);
  const std::string output =
      no_style ? plain : "\033[1;33;49m" + plain + "\033[0m";
  if (!ct_output_write(output.data(), output.size()))
    dr_abort();
}

static void progress_notice(const ct_analysis_progress *progress,
                            void *context) {
  if (!ct_output_trace_enabled() || !progress || !traced_process() ||
      !recording_thread())
    return;
  // Callers hold analysis_lock. This may run while the proxy is waiting for
  // an analysis response: use supplied metadata and cached runtime locations
  // only, since another analysis query here would deadlock.
  const auto plain = [](const char *text, size_t capacity) {
    std::string result;
    for (size_t index = 0; index < capacity && text[index]; ++index) {
      const unsigned char ch = text[index];
      if (ch < ' ' || ch == 127) {
        char escaped[5];
        dr_snprintf(escaped, sizeof(escaped), "\\x%02x", unsigned(ch));
        result += escaped;
      } else {
        result += char(ch);
      }
    }
    return result;
  };
  const auto *module = static_cast<const Module *>(context);
  if (!module) {
    for (const auto &candidate : modules) {
      if (!candidate->active || candidate->path != progress->module)
        continue;
      // Different dlmopen namespaces can map the same file more than once.
      // A path alone must not select an arbitrary runtime load address.
      if (module) {
        module = nullptr;
        break;
      }
      module = candidate.get();
    }
  }
  app_pc pc = nullptr;
  if (module && progress->has_range &&
      progress->begin_offset < uint64_t(module->end - module->start))
    pc = module->start + progress->begin_offset;
  std::string file = plain(progress->file, sizeof(progress->file));
  std::string function = plain(progress->function, sizeof(progress->function));
  uint64_t source_line = progress->line;
  if (const auto found = current_sites.find(pc);
      found != current_sites.end() && found->second->module.get() == module) {
    const auto &location = found->second->location;
    if (file.empty()) {
      file = plain(location.file, std::strlen(location.file));
      source_line = location.line;
    }
    if (function.empty())
      function = location.function[0]
                     ? plain(location.function, std::strlen(location.function))
                     : plain(location.symbol, std::strlen(location.symbol));
  }
  if (function.empty()) {
    const auto found = current_functions.find(pc);
    if (found != current_functions.end() &&
        found->second->module.get() == module)
      function = plain(found->second->name.c_str(), found->second->name.size());
  }
  char address[32] = "?";
  if (pc)
    dr_snprintf(
        address, sizeof(address), "L%llx",
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(pc)));
  const std::string module_path =
      progress->module[0] ? plain(progress->module, sizeof(progress->module))
                          : "?";
  // A relative DWARF path does not identify an absolute source location.
  // Keep it unknown instead of resolving it against the tracer's cwd.
  if (!file.empty() && file.front() != '/')
    file.clear();
  const std::string source_prefix =
      progress->source_prefix[0]
          ? plain(progress->source_prefix, sizeof(progress->source_prefix))
          : "?=?";
  std::string line = "Info: " + module_path + ": source prefix " +
                     source_prefix + ": " + address + " " +
                     (file.empty() ? "?" : file) + ":" +
                     (source_line ? std::to_string(source_line) : "?") + " " +
                     (function.empty() ? "?" : function) + ": " +
                     plain(progress->detail, sizeof(progress->detail));
  if (progress->has_range) {
    char range[80];
    if (progress->end_offset > progress->begin_offset)
      dr_snprintf(range, sizeof(range), " [+0x%llx, +0x%llx)",
                  static_cast<unsigned long long>(progress->begin_offset),
                  static_cast<unsigned long long>(progress->end_offset));
    else
      dr_snprintf(range, sizeof(range), " at +0x%llx",
                  static_cast<unsigned long long>(progress->begin_offset));
    line += range;
  }
  const std::string output =
      no_style ? line + '\n' : "\033[22;34;49m" + line + "\033[0m\n";
  if (!ct_output_trace_write(output.data(), output.size()))
    dr_abort();
}

static std::string location_prefix(void *context, app_pc pc,
                                   const Module &module,
                                   const ct_location_view &location,
                                   const char *function, uint64_t line) {
  char identity[80];
  dr_snprintf(identity, sizeof(identity), "[tid %u] L%llx ",
              static_cast<unsigned>(dr_get_thread_id(context)),
              static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(pc)));
  return std::string(identity) + module.path + " " +
         (location.file[0] ? location.file : "<unknown>") + ":" +
         (line ? std::to_string(line) : "?") +
         (function && function[0] ? " " + std::string(function) : "") + " | ";
}

static bool read_memory(void *, uint64_t address, void *destination,
                        size_t size) {
  size_t count = 0;
  return dr_safe_read(reinterpret_cast<void *>(address), size, destination,
                      &count) &&
         count == size;
}

static ct_registers registers_at(const dr_mcontext_t *context, app_pc pc) {
  ct_registers result{};
  if (!context)
    return result;
  const reg_t values[] = {context->xax,
                          context->xdx,
                          context->xcx,
                          context->xbx,
                          context->xsi,
                          context->xdi,
                          context->xbp,
                          context->xsp,
                          context->r8,
                          context->r9,
                          context->r10,
                          context->r11,
                          context->r12,
                          context->r13,
                          context->r14,
                          context->r15,
                          reinterpret_cast<reg_t>(pc)};
  std::copy(std::begin(values), std::end(values), result.gpr);
  result.have_gpr = true;
  result.flags = context->xflags;
  if ((context->flags & DR_MC_MULTIMEDIA) && dr_mcontext_xmm_fields_valid()) {
    const bool wide = dr_mcontext_zmm_fields_valid();
    result.simd_bytes = wide ? 64 : proc_has_feature(FEATURE_AVX) ? 32 : 16;
    for (size_t index = 0; index < (wide ? 32 : 16); ++index)
      memcpy(result.xmm[index], &context->simd[index], result.simd_bytes);
    if (wide) {
      memcpy(result.opmask, context->opmask, sizeof(result.opmask));
      result.have_opmask = true;
    }
    result.have_xmm = true;
  }
  return result;
}

static Thread *thread_state(void *context) {
  auto *thread = static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
  if (!thread) {
    thread = new Thread;
    thread->process = dr_get_process_id_from_drcontext(context);
    thread->tid = dr_get_thread_id(context);
    thread->owns_image = ct_analysis_object_owner() != 0;
    thread->recording =
        process_recording &&
        (follow_forks ||
         context == initial_context.load(std::memory_order_relaxed));
    drmgr_set_tls_field(context, tls_index, thread);
  }
  return thread;
}

static bool signal_context_active(const Thread &thread) {
  return std::any_of(thread.calls.begin(), thread.calls.end(),
                     [](const Call *call) { return call->signal_frame; });
}

static bool within_call_stack(const Thread &thread) {
  if (!within_enabled || (within_new_stack && thread.new_stack_scope))
    return true;
  for (const Call *call : thread.calls)
    if (call->within || call->within_inline ||
        (within_intr && call->signal_handler_active))
      return true;
  return false;
}

static bool within_active() {
  return recording_thread() &&
         (!within_enabled ||
          *reinterpret_cast<uintptr_t *>(
              static_cast<byte *>(dr_get_dr_segment_base(within_tls_register)) +
              within_tls_offset) != 0);
}

static uintptr_t &execution_mode() {
  return *reinterpret_cast<uintptr_t *>(
      static_cast<byte *>(dr_get_dr_segment_base(within_tls_register)) +
      within_tls_offset);
}

// Stop the coarse clock before any client analysis/output; nested callbacks
// must not rearm it until the outermost callback returns to application code.
struct QuietCallback {
  void *context;
  Thread *thread = nullptr;
  bool resume = false, allow_resume = true;
  explicit QuietCallback(void *value)
      : context(value ? value : dr_get_current_drcontext()) {
    if (ct_perfetto_enabled() && traced_process() &&
        recording_thread(context)) {
      thread = thread_state(context);
      ct_timing_quiet_end(context);
      ++thread->quiet_callback_depth;
    }
  }
  ~QuietCallback() {
    if (thread && !--thread->quiet_callback_depth && allow_resume &&
        thread->timing_started &&
        (resume || !trace_activated.load(std::memory_order_acquire) ||
         (duplicate_enabled && execution_mode() != 1)) &&
        !thread->resume_quiet_generation)
      ct_timing_quiet_begin(context);
  }
};

// A stopped peer may resume into an already cached quiet block with no client
// callback. Restore its coarse clock explicitly after patch work, without
// arming a peer that was already inside a callback or a kernel interval.
static void suspend_thread_timing(void *context) {
  if (!ct_perfetto_enabled())
    return;
  auto *thread = static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
  if (thread)
    thread->resume_quiet_suspension = ct_timing_quiet_active(context);
  ct_timing_quiet_end(context);
  ct_timing_discard(context);
}

static void resume_thread_timing(void *context) {
  if (!ct_perfetto_enabled())
    return;
  auto *thread = static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
  if (thread && thread->resume_quiet_suspension) {
    thread->resume_quiet_suspension = false;
    ct_timing_quiet_begin(context);
  }
}

static void update_within(Thread &thread) {
  if (!duplicate_enabled)
    return;
  if (!thread.recording) {
    execution_mode() = 3;
    return;
  }
  const bool active = within_call_stack(thread);
  auto &enabled = execution_mode();
  const TraceScope &scope =
      thread.calls.empty() ? thread.root_scope : thread.calls.back()->scope;
  enabled = !active ? 0 : scope.initialized && scope.mode != Site::Into ? 2 : 1;
}

static void named_value_types(ct_values_site *site, ct_function *function,
                              const std::string &values,
                              std::vector<OperandType> &types) {
  for (const auto &entry : decompiled_fields(values)) {
    const size_t offset = entry.first, length = entry.second;
    const std::string field = values.substr(offset, length);
    const size_t equals = field.find('=');
    if (equals == std::string::npos ||
        std::any_of(types.begin(), types.end(), [&](const auto &type) {
          return type.offset >= offset && type.offset < offset + length;
        }))
      continue;
    const std::string name = unstyled(field.substr(0, equals));
    ct_variable_description description{};
    if (!(function && ct_function_describe_parameter(function, name.c_str(),
                                                     &description)) &&
        !ct_values_describe_name(site, name.c_str(), &description))
      continue;
    types.push_back({offset + equals + 1,
                     std::to_string(description.module_id) + ":" +
                         std::to_string(description.die_offset) + ":" +
                         description.name,
                     description.type});
  }
}

static std::vector<OperandType> source_declaration_types(const Site &site) {
  std::vector<OperandType> types;
  const auto &source = site.location;
  if (source.source_declarations_size >
      sizeof(ct_location::source_declarations))
    return types;
  for (size_t offset = 0; offset < source.source_declarations_size;) {
    const char *name = source.source_declarations + offset;
    const char *end = static_cast<const char *>(
        std::memchr(name, 0, source.source_declarations_size - offset));
    if (!end)
      break;
    ct_variable_description description{};
    if (ct_values_describe_name(site.values, name, &description))
      types.push_back({std::string::npos,
                       std::to_string(description.module_id) + ":" +
                           std::to_string(description.die_offset) + ":" +
                           description.name,
                       description.type});
    offset += size_t(end - name) + 1;
  }
  return types;
}

static std::string variable_values(const Site &site,
                                   const ct_registers &registers,
                                   std::vector<OperandType> &types) {
  char text[value_capacity];
  ct_values_format_selected(site.values, &registers, read_memory, nullptr,
                            site.location.source_variables,
                            site.location.source_variables_size, text,
                            sizeof(text));
  named_value_types(site.values, nullptr, text, types);
  return text;
}

static void append_result(Visit &visit, const std::string &result) {
  if (result.empty())
    return;
  if (!visit.results.empty())
    visit.results += ", ";
  visit.results += result;
}

static std::string observed_register_key(std::string key) {
  const char *name = key.c_str() + (!key.empty() && key[0] == '%');
  for (unsigned reg = DR_REG_RAX; reg <= DR_REG_R15L; ++reg) {
    const auto id = static_cast<reg_id_t>(reg);
    if (reg_is_gpr(id) && std::strcmp(name, ct_register_name(id)) == 0)
      return ct_register_name(reg_to_pointer_sized(id));
  }
  return key;
}

// Display only observations named by the final C statement, after instruction
// groups and condition rows have been combined. Hidden machine operands must
// not consume a variable's first visible type annotation.
static void filter_decompiled_values(Visit &visit) {
  if (!decompile || visit.source || visit.summary ||
      visit.assembly_offset != std::string::npos ||
      visit.code_offset >= visit.before_line.size())
    return;
  const size_t code_end =
      std::min(visit.comment_offset, visit.before_line.size());
  if (code_end <= visit.code_offset)
    return;
  const std::string code = unstyled(visit.before_line.substr(
      visit.code_offset, code_end - visit.code_offset));
  auto tokenize = [](const std::string &text) {
    std::vector<std::string> tokens;
    for (size_t pos = 0; pos < text.size();) {
      const unsigned char ch = text[pos];
      if (std::isspace(ch)) {
        ++pos;
        continue;
      }
      if (text.compare(pos, 2, "//") == 0)
        break;
      if (text.compare(pos, 2, "/*") == 0) {
        const size_t end = text.find("*/", pos + 2);
        pos = end == std::string::npos ? text.size() : end + 2;
        continue;
      }
      if (ch == '\'' || ch == '"') {
        const char quote = text[pos++];
        while (pos < text.size()) {
          if (text[pos] == '\\' && pos + 1 < text.size())
            pos += 2;
          else if (text[pos++] == quote)
            break;
        }
        tokens.emplace_back("\"\"");
        continue;
      }
      const size_t first = pos++;
      if (std::isalnum(ch) || ch == '_') {
        while (pos < text.size() &&
               (std::isalnum(static_cast<unsigned char>(text[pos])) ||
                text[pos] == '_'))
          ++pos;
      } else if (text.compare(first, 2, "->") == 0) {
        ++pos;
      }
      tokens.push_back(text.substr(first, pos - first));
    }
    return tokens;
  };
  const auto tokens = tokenize(code);
  auto identifier = [](const std::string &token) {
    return !token.empty() &&
           (std::isalpha(static_cast<unsigned char>(token[0])) ||
            token[0] == '_');
  };
  auto closing = [](const std::vector<std::string> &parts, size_t start) {
    size_t depth = 0;
    for (size_t end = start; end < parts.size(); ++end) {
      if (parts[end] == "(")
        ++depth;
      else if (parts[end] == ")" && !--depth)
        return end;
    }
    return parts.size();
  };
  const std::unordered_set<std::string> type_words = {
      "void",     "bool",     "_Bool",     "char",    "signed",    "unsigned",
      "short",    "int",      "long",      "float",   "double",    "const",
      "volatile", "restrict", "struct",    "union",   "enum",      "int8_t",
      "int16_t",  "int32_t",  "int64_t",   "uint8_t", "uint16_t",  "uint32_t",
      "uint64_t", "intptr_t", "uintptr_t", "size_t",  "ptrdiff_t", "_Nullable",
      "_Nonnull"};
  std::vector<bool> type_token(tokens.size());
  for (size_t pos = 0; pos < tokens.size(); ++pos) {
    if (tokens[pos] != "(")
      continue;
    const size_t end = closing(tokens, pos);
    bool type = end < tokens.size(), evidence = false, pointer = false;
    for (size_t item = pos + 1; type && item < end; ++item) {
      if (tokens[item] == "*") {
        pointer = evidence = true;
      } else {
        const bool qualifier =
            tokens[item] == "const" || tokens[item] == "volatile" ||
            tokens[item] == "restrict" || tokens[item] == "__restrict" ||
            tokens[item] == "__restrict__" || tokens[item] == "_Nullable" ||
            tokens[item] == "_Nonnull";
        type = identifier(tokens[item]) && (!pointer || qualifier);
        evidence |= type_words.count(tokens[item]) != 0;
      }
    }
    if (type && evidence)
      for (size_t item = pos + 1; item < end; ++item)
        type_token[item] = true;
  }
  std::unordered_set<std::string> names;
  for (size_t pos = 0; pos < tokens.size(); ++pos)
    if (identifier(tokens[pos]) && !type_token[pos] &&
        !type_words.count(tokens[pos]))
      names.insert(tokens[pos]);
  auto address_key = [&](std::vector<std::string> parts) {
    while (parts.size() > 2 && parts.front() == "(" &&
           closing(parts, 0) == parts.size() - 1) {
      parts.erase(parts.begin());
      parts.pop_back();
    }
    for (size_t pos = 0; pos + 1 < parts.size();) {
      if (parts[pos] == "%" && identifier(parts[pos + 1]))
        parts.erase(parts.begin() + pos);
      else
        ++pos;
    }
    for (auto &part : parts) {
      if (part.empty() || !std::isdigit(static_cast<unsigned char>(part[0])))
        continue;
      char *end = nullptr;
      const uint64_t value = std::strtoull(part.c_str(), &end, 0);
      while (*end == 'u' || *end == 'U' || *end == 'l' || *end == 'L')
        ++end;
      if (!*end)
        part = std::to_string(value);
    }
    // Disassemblers interchange index*scale and scale*index spellings.
    for (size_t pos = 0; pos + 2 < parts.size(); ++pos)
      if (!parts[pos].empty() &&
          std::isdigit(static_cast<unsigned char>(parts[pos][0])) &&
          parts[pos + 1] == "*" && identifier(parts[pos + 2]))
        std::swap(parts[pos], parts[pos + 2]);
    std::string result;
    for (const auto &part : parts)
      result += part + " ";
    return result;
  };
  std::unordered_set<std::string> memory;
  for (size_t pos = 0; pos + 1 < tokens.size(); ++pos) {
    if (tokens[pos] != "*" || type_token[pos] ||
        (pos && (identifier(tokens[pos - 1]) && tokens[pos - 1] != "return")) ||
        (pos && (std::isdigit(static_cast<unsigned char>(tokens[pos - 1][0])) ||
                 tokens[pos - 1] == ")" || tokens[pos - 1] == "]")))
      continue;
    size_t start = pos + 1;
    if (tokens[start] == "(") {
      const size_t end = closing(tokens, start);
      if (start + 1 < type_token.size() && type_token[start + 1])
        start = end < tokens.size() ? end + 1 : tokens.size();
    }
    if (start >= tokens.size())
      continue;
    size_t end = start + 1;
    if (tokens[start] == "(") {
      end = closing(tokens, start);
      if (end == tokens.size())
        continue;
      ++end;
    } else if (!identifier(tokens[start])) {
      continue;
    }
    memory.insert(address_key({tokens.begin() + start, tokens.begin() + end}));
  }
  std::string return_name, return_register;
  const ct_decompiled_variables_view *return_metadata =
      visit.last ? visit.last->decompiled_variables.get() : nullptr;
  if (tokens.size() == 3 && tokens[0] == "return" && identifier(tokens[1]) &&
      tokens[2] == ";" && visit.last && visit.last->instruction.ret &&
      return_metadata && return_metadata->return_known &&
      !return_metadata->return_void && !return_metadata->return_unsupported) {
    return_name = tokens[1];
    return_register = return_metadata->return_register;
    std::transform(return_register.begin(), return_register.end(),
                   return_register.begin(),
                   [](unsigned char ch) { return std::toupper(ch); });
  }
  const std::string original_before =
      visit.have_before && visit.comment_offset < visit.before_line.size()
          ? visit.before_line.substr(visit.comment_offset + 2)
          : std::string{};
  bool named_return = false;
  for (const auto &[offset, length] : decompiled_fields(original_before)) {
    const std::string field = unstyled(original_before.substr(offset, length));
    named_return |=
        !return_name.empty() && field.substr(0, field.find('=')) == return_name;
  }
  auto filter = [&](const std::string &values,
                    std::vector<OperandType> *types) {
    std::string result;
    std::vector<OperandType> kept_types;
    for (const auto &[offset, length] : decompiled_fields(values)) {
      std::string field = values.substr(offset, length);
      const std::string plain = unstyled(field);
      const size_t equals = plain.find('=');
      std::string key = plain.substr(0, equals);
      if (!key.empty() && key[0] == '%')
        key.erase(key.begin());
      bool renamed = false;
      if (!named_return && !return_name.empty() && key == return_register) {
        field = return_name + plain.substr(equals);
        key = return_name;
        renamed = true;
      }
      bool keep = equals == std::string::npos || names.count(key);
      const auto key_tokens = tokenize(key);
      if (!keep && !key_tokens.empty() && identifier(key_tokens.front()) &&
          std::any_of(key_tokens.begin(), key_tokens.end(),
                      [](const auto &part) {
                        return part == "." || part == "->" || part == "[";
                      })) {
        const std::string canonical = address_key(key_tokens);
        for (size_t pos = 0; !keep && pos + key_tokens.size() <= tokens.size();
             ++pos)
          if (!type_token[pos])
            keep = address_key({tokens.begin() + pos,
                                tokens.begin() + pos + key_tokens.size()}) ==
                   canonical;
      }
      if (!keep && key.size() > 2 && key.front() == '[' && key.back() == ']')
        keep =
            memory.count(address_key(tokenize(key.substr(1, key.size() - 2))));
      if (!keep)
        continue;
      if (!result.empty())
        result += ", ";
      if (types)
        for (const auto &type : *types)
          if (type.offset >= offset && type.offset < offset + length) {
            auto copy = type;
            copy.offset = result.size() + type.offset - offset;
            if (renamed) {
              copy.offset = result.size() + return_name.size() + 1;
              bool described = false;
              for (uint32_t index = 0; index < return_metadata->count;
                   ++index) {
                const auto &variable = return_metadata->entries[index];
                if (return_name == variable.name) {
                  copy.identity =
                      visit.last->module->identity + ":decompiled:" +
                      std::to_string(return_metadata->function_offset) + ":" +
                      std::to_string(variable.id);
                  copy.type = variable.type_name;
                  described = true;
                  break;
                }
              }
              if (!described) {
                const auto known = visit.last->module->decompiled_symbols.find(
                    {return_metadata->function_offset, return_name});
                if (known != visit.last->module->decompiled_symbols.end() &&
                    known->second.first) {
                  copy.identity =
                      visit.last->module->identity + ":decompiled:" +
                      std::to_string(return_metadata->function_offset) + ":" +
                      std::to_string(known->second.first);
                  copy.type = known->second.second;
                }
              }
              for (uint32_t index = 0; index < return_metadata->parameter_count;
                   ++index) {
                const auto &parameter = return_metadata->parameters[index];
                if (return_name == parameter.name) {
                  copy.identity =
                      visit.last->module->identity + ":decompiled-parameter:" +
                      std::to_string(return_metadata->function_offset) + ":" +
                      return_name;
                  copy.type = parameter.type_name;
                  break;
                }
              }
            }
            kept_types.push_back(std::move(copy));
          }
      result += field;
    }
    if (types)
      *types = std::move(kept_types);
    return result;
  };
  visit.values = filter(original_before, &visit.input_types);
  visit.have_before = !visit.values.empty();
  visit.before_line.resize(code_end);
  while (!visit.before_line.empty() && visit.before_line.back() == ' ')
    visit.before_line.pop_back();
  visit.comment_offset = std::string::npos;
  if (visit.have_before) {
    visit.comment_offset = visit.before_line.size() + 1;
    visit.before_line += " # " + visit.values;
  }
  visit.results = filter(visit.results, nullptr);
  visit.expression_result = filter(visit.expression_result, nullptr);
  visit.call_results = filter(visit.call_results, nullptr);
}

// Propose declarations from observed type metadata. write_line claims the
// identities atomically when this row becomes visible, alongside # annotations.
static std::vector<OperandType> decompiled_declarations(const Visit &visit) {
  std::vector<OperandType> declarations;
  if (!decompile || visit.source || visit.summary ||
      visit.assembly_offset != std::string::npos ||
      visit.code_offset >= visit.before_line.size())
    return declarations;
  const size_t code_end =
      std::min(visit.comment_offset, visit.before_line.size());
  std::string code;
  std::vector<size_t> original;
  for (size_t pos = visit.code_offset; pos < code_end;) {
    if (visit.before_line[pos] == '\033' && pos + 1 < code_end &&
        visit.before_line[pos + 1] == '[') {
      const size_t end = visit.before_line.find('m', pos + 2);
      if (end < code_end) {
        pos = end + 1;
        continue;
      }
    }
    original.push_back(pos);
    code += visit.before_line[pos++];
  }
  struct Token {
    std::string text;
    size_t offset;
    bool name;
  };
  std::vector<Token> tokens;
  for (size_t pos = 0; pos < code.size();) {
    const unsigned char ch = code[pos];
    if (std::isspace(ch)) {
      ++pos;
      continue;
    }
    if (code.compare(pos, 2, "//") == 0)
      break;
    if (code.compare(pos, 2, "/*") == 0) {
      const size_t end = code.find("*/", pos + 2);
      pos = end == std::string::npos ? code.size() : end + 2;
      continue;
    }
    const size_t start = pos++;
    const bool name = std::isalpha(ch) || ch == '_';
    if (name || std::isdigit(ch)) {
      while (pos < code.size() &&
             (std::isalnum(static_cast<unsigned char>(code[pos])) ||
              code[pos] == '_'))
        ++pos;
    } else if (ch == '\'' || ch == '"') {
      while (pos < code.size()) {
        if (code[pos] == '\\' && pos + 1 < code.size())
          pos += 2;
        else if (code[pos++] == ch)
          break;
      }
    } else if (pos < code.size() &&
               ((code[pos] == '=' &&
                 std::string("=+-*/%&|^!<>").find(ch) != std::string::npos) ||
                (code[pos] == ch && (ch == '+' || ch == '-')))) {
      ++pos;
    }
    tokens.push_back({code.substr(start, pos - start), start, name});
  }
  auto compact = [](std::string type) {
    type.erase(
        std::remove_if(type.begin(), type.end(),
                       [](unsigned char ch) { return std::isspace(ch); }),
        type.end());
    return type;
  };
  std::unordered_set<std::string> proposed;
  for (size_t start = 0; start < tokens.size();) {
    const bool loop = tokens[start].text == "for" &&
                      start + 1 < tokens.size() &&
                      tokens[start + 1].text == "(";
    if (loop)
      start += 2;
    size_t end = start, equals = tokens.size();
    size_t depth = 0;
    for (; end < tokens.size(); ++end) {
      const auto &part = tokens[end].text;
      if (!depth && part == ";")
        break;
      if (!depth && part == "=" && equals == tokens.size())
        equals = end;
      if (part == "(" || part == "[" || part == "{")
        ++depth;
      else if (depth && (part == ")" || part == "]" || part == "}"))
        --depth;
    }
    if (equals > start && equals < end && tokens[equals - 1].name) {
      const size_t lhs = equals - 1;
      const auto &name = tokens[lhs].text;
      // A read before this assignment, or a self-referential initializer,
      // belongs to an existing value and cannot introduce a new C object.
      const bool read =
          std::any_of(tokens.begin(), tokens.begin() + lhs,
                      [&](const auto &token) {
                        return token.name && token.text == name;
                      }) ||
          std::any_of(tokens.begin() + equals + 1, tokens.begin() + end,
                      [&](const auto &token) {
                        return token.name && token.text == name;
                      });
      OperandType declaration;
      bool parameter = false;
      const std::string before =
          visit.have_before && visit.comment_offset < visit.before_line.size()
              ? visit.before_line.substr(visit.comment_offset + 2)
              : std::string{};
      for (const auto &[offset, length] : decompiled_fields(before)) {
        const std::string field = unstyled(before.substr(offset, length));
        std::string key = field.substr(0, field.find('='));
        if (!key.empty() && key[0] == '%')
          key.erase(key.begin());
        if (key != name)
          continue;
        for (const auto &type : visit.input_types)
          if (type.offset >= offset && type.offset < offset + length)
            declaration = type;
      }
      for (const auto &site : {visit.first, visit.last}) {
        const auto *statement = site ? site->decompiled.get() : nullptr;
        if (declaration.identity.empty() && statement &&
            statement->declaration_id && name == statement->declaration_name &&
            statement->declaration_type[0]) {
          declaration.identity =
              site->module->identity +
              ":decompiled:" + std::to_string(statement->function_offset) +
              ":" + std::to_string(statement->declaration_id);
          declaration.type = statement->declaration_type;
        }
        const auto *metadata =
            site ? site->decompiled_variables.get() : nullptr;
        if (!metadata)
          continue;
        for (uint32_t index = 0; index < metadata->parameter_count; ++index)
          parameter |= name == metadata->parameters[index].name;
        if (!declaration.identity.empty())
          continue;
        for (uint32_t index = 0; index < metadata->count; ++index) {
          const auto &variable = metadata->entries[index];
          if (name != variable.name)
            continue;
          const bool scalar =
              variable.type.kind != CT_VALUE_UNKNOWN ||
              std::string(variable.type_name) ==
                  "uint" + std::to_string(variable.size * 8) + "_t";
          if (!scalar || !variable.type_name[0])
            continue;
          declaration.identity =
              site->module->identity +
              ":decompiled:" + std::to_string(metadata->function_offset) + ":" +
              std::to_string(variable.id);
          declaration.type = variable.type_name;
          break;
        }
      }
      std::string prefix;
      for (size_t index = start; index < lhs; ++index)
        prefix += tokens[index].text;
      const bool existing =
          !prefix.empty() && prefix == compact(declaration.type);
      if (!read && !parameter && !declaration.identity.empty() &&
          declaration.identity.compare(0, 9, "register:") != 0 &&
          !declaration.type.empty() && declaration.type != "void" &&
          declaration.type.find_first_of("?([{;") == std::string::npos &&
          (lhs == start || existing) &&
          proposed.insert(declaration.identity).second) {
        declaration.offset =
            existing ? std::string::npos : original[tokens[lhs].offset];
        declarations.push_back(std::move(declaration));
      }
    }
    if (loop || end == tokens.size())
      break;
    start = end + 1;
  }
  return declarations;
}

static void close_visit(Visit &visit, const char *incomplete = nullptr,
                        std::vector<Visit> *deferred = nullptr) {
  if (!visit.first)
    return;
  if (!incomplete && visit.header_continuation && !visit.header_interruption &&
      !visit.provisional) {
    Visit *header = visit.header_continuation;
    visit.header_continuation = nullptr;
    close_visit(*header);
    *header = std::move(visit);
    visit = Visit{};
    return;
  }
  if (visit.header_continuation && visit.header_continuation->first)
    close_visit(*visit.header_continuation);
  if (deferred) {
    deferred->push_back(std::move(visit));
    visit = Visit{};
    return;
  }
  if (visit.decompile_machine) {
    auto &rows = visit.decompile_machine->decompiled_rows;
    const auto *statement = visit.first->decompiled.get();
    bool mapped = statement && !incomplete;
    if (mapped && !rows.empty()) {
      const auto &first = rows.front();
      mapped = first.first->module == visit.first->module &&
               first.first->decompiled->id == statement->id &&
               rows.size() == statement->instruction_index;
    }
    if (!mapped || (!rows.empty() && !statement->instruction_index)) {
      auto original = std::move(rows);
      rows.clear();
      for (auto &row : original) {
        row.decompile_machine = nullptr;
        close_visit(row, incomplete);
      }
      mapped = statement && !incomplete && !statement->instruction_index;
    }
    if (mapped && (!statement->instruction_index || !rows.empty())) {
      rows.push_back(std::move(visit));
      visit = Visit{};
      if (rows.size() < statement->instruction_count)
        return;
      // This exact instruction sequence has completed. Inputs are the first
      // observed reads not produced inside the sequence; outputs are the last
      // observed writes. Never evaluate the reconstructed C against the target.
      std::string before, after;
      std::vector<OperandType> types;
      std::unordered_set<std::string> inputs;
      std::unordered_set<std::string> written;
      std::map<std::string, size_t> outputs;
      std::vector<std::string> final_values;
      for (const auto &row : rows) {
        const std::string values =
            row.have_before && row.comment_offset < row.before_line.size()
                ? row.before_line.substr(row.comment_offset + 2)
                : std::string{};
        for (const auto &[offset, length] : decompiled_fields(values)) {
          const std::string field = values.substr(offset, length);
          const std::string plain = unstyled(field);
          const std::string key = plain.substr(0, plain.find('='));
          if (written.count(observed_register_key(key)) ||
              !inputs.insert(key).second)
            continue;
          if (!before.empty())
            before += ", ";
          for (const auto &type : row.input_types)
            if (type.offset >= offset && type.offset < offset + length) {
              auto copy = type;
              copy.offset = before.size() + type.offset - offset;
              types.push_back(std::move(copy));
            }
          before += field;
        }
        for (const auto &[offset, length] : decompiled_fields(row.results)) {
          const std::string field = row.results.substr(offset, length);
          const std::string plain = unstyled(field);
          const std::string key = plain.substr(0, plain.find('='));
          written.insert(observed_register_key(key));
          auto [position, added] = outputs.emplace(key, final_values.size());
          if (added)
            final_values.push_back(field);
          else
            final_values[position->second] = field;
        }
        // DWARF can name a register write as a variable (v=...) while a later
        // alias read is printed as eax. Track the actual storage as well.
        for (const auto &operand : row.last->instruction.outputs)
          if (opnd_is_reg(operand) && reg_is_gpr(opnd_get_reg(operand)))
            written.insert(
                ct_register_name(reg_to_pointer_sized(opnd_get_reg(operand))));
      }
      for (const auto &field : final_values) {
        if (!after.empty())
          after += ", ";
        after += field;
      }
      const int outcome = rows.back().branch_outcome;
      const std::string returned_value = rows.back().returned_value;
      const bool plt_call = rows.back().plt_call;
      const std::string plt_name = rows.back().plt_name;
      const app_pc plt_target = rows.back().plt_target;
      Visit *const call_deferred = rows.back().call_deferred;
      const auto last = rows.back().last;
      Visit combined = std::move(rows.front());
      rows.clear();
      combined.decompile_machine = nullptr;
      combined.plt_call = plt_call;
      combined.plt_name = plt_name;
      combined.plt_target = plt_target;
      combined.call_deferred = call_deferred;
      combined.returned_value = returned_value;
      combined.last = last;
      combined.results = std::move(after);
      combined.input_types = std::move(types);
      std::string code = statement->text;
      char quote = 0;
      for (size_t cursor = 0; cursor < code.size();) {
        if (quote) {
          if (code[cursor] == '\\' && cursor + 1 < code.size())
            cursor += 2;
          else {
            if (code[cursor] == quote)
              quote = 0;
            ++cursor;
          }
          continue;
        }
        if (code[cursor] == '\'' || code[cursor] == '"') {
          quote = code[cursor++];
          continue;
        }
        if (code.compare(cursor, 2, "@L") != 0) {
          ++cursor;
          continue;
        }
        const size_t end = code.find('@', cursor + 2);
        if (end == std::string::npos)
          break;
        char *tail = nullptr;
        const auto offset = std::strtoull(code.c_str() + cursor + 2, &tail, 16);
        if (tail != code.c_str() + end ||
            offset >= uint64_t(combined.first->module->end -
                               combined.first->module->start)) {
          cursor = end + 1;
          continue;
        }
        char label[32];
        dr_snprintf(label, sizeof(label), "L%llx",
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(
                        combined.first->module->start + offset)));
        std::string replacement = label;
        size_t following = end + 1;
        while (following < code.size() &&
               std::isspace(static_cast<unsigned char>(code[following])))
          ++following;
        const bool identifier =
            !combined.plt_name.empty() &&
            (std::isalpha(static_cast<unsigned char>(combined.plt_name[0])) ||
             combined.plt_name[0] == '_') &&
            std::all_of(combined.plt_name.begin(), combined.plt_name.end(),
                        [](unsigned char character) {
                          return std::isalnum(character) || character == '_';
                        });
        if (combined.plt_call && identifier && following < code.size() &&
            code[following] == '(' &&
            combined.first->module->start + offset == combined.plt_target)
          replacement = combined.plt_name;
        code.replace(cursor, end + 1 - cursor, replacement);
        cursor += replacement.size();
      }
      combined.before_line.resize(combined.code_offset);
      combined.before_line += "\033[32m" + code + "\033[0m";
      combined.have_before = !before.empty();
      combined.comment_offset = std::string::npos;
      if (combined.have_before) {
        combined.comment_offset = combined.before_line.size() + 1;
        combined.before_line += " # " + before;
      }
      combined.assembly_offset = std::string::npos;
      combined.branch_outcome = outcome;
      visit = std::move(combined);
    } else {
      visit.decompile_machine = nullptr;
    }
  }
  if (decompile && !visit.source && !visit.summary &&
      visit.assembly_offset != std::string::npos &&
      !visit.abi_call_code.empty()) {
    visit.before_line.resize(visit.code_offset);
    visit.before_line += "\033[32m" + visit.abi_call_code + "\033[0m";
    visit.values = visit.abi_call_values;
    visit.have_before = !visit.values.empty();
    visit.comment_offset = std::string::npos;
    if (visit.have_before) {
      visit.comment_offset = visit.before_line.size() + 1;
      visit.before_line += " # " + visit.values;
    }
    visit.input_types = visit.abi_call_types;
    visit.results.clear();
    visit.expression_result.clear();
    visit.assembly_offset = std::string::npos;
    visit.branch_outcome = -1;
  }
  if (decompile && visit.plt_call &&
      visit.assembly_offset != std::string::npos) {
    // Keep the observed call visible even when no complete statement was
    // recovered. Arguments remain unspecified rather than guessed from
    // machine temporaries; verified C calls above keep their real arguments.
    std::string name = visit.plt_name;
    if (name.empty() ||
        (!std::isalpha(static_cast<unsigned char>(name[0])) &&
         name[0] != '_') ||
        !std::all_of(name.begin(), name.end(), [](unsigned char character) {
          return std::isalnum(character) || character == '_';
        })) {
      char label[32];
      dr_snprintf(label, sizeof(label), "L%llx",
                  static_cast<unsigned long long>(
                      reinterpret_cast<uintptr_t>(visit.plt_target)));
      name = label;
    }
    const size_t code_end = visit.comment_offset < visit.before_line.size()
                                ? visit.comment_offset - 1
                                : visit.before_line.size();
    const std::string code = "\033[32m" + name + "(...);\033[0m";
    visit.before_line.replace(visit.assembly_offset,
                              code_end - visit.assembly_offset, code);
    if (visit.comment_offset != std::string::npos)
      visit.comment_offset = visit.assembly_offset + code.size() + 1;
    visit.assembly_offset = std::string::npos;
    visit.branch_outcome = -1;
  }
  filter_decompiled_values(visit);
  if (decompile && !visit.source && !visit.summary && visit.last &&
      visit.last->instruction.call &&
      visit.assembly_offset == std::string::npos) {
    // Argument preparation can copy a named input into an ABI register. That
    // observation is not a write to the original C input variable.
    std::unordered_set<std::string> inputs;
    for (const auto &[offset, length] : decompiled_fields(visit.values))
      inputs.insert(unstyled(visit.values.substr(offset, length)));
    std::string changed;
    for (const auto &[offset, length] : decompiled_fields(visit.results)) {
      const std::string field = visit.results.substr(offset, length);
      if (inputs.count(unstyled(field)))
        continue;
      if (!changed.empty())
        changed += ", ";
      changed += field;
    }
    visit.results = std::move(changed);
  }
  if (decompile && !incomplete && visit.call_deferred && !visit.call_decided &&
      !visit.source && !visit.summary &&
      visit.assembly_offset == std::string::npos) {
    // CALL has executed, but a PLT resolver can still stand between this row
    // and the selected callee. Decide its highlight at the actual target.
    Visit *destination = visit.call_deferred;
    visit.call_deferred = nullptr;
    if (destination->first) {
      destination->call_decided = true;
      close_visit(*destination, "call target unavailable");
    }
    *destination = std::move(visit);
    visit = Visit{};
    return;
  }
  auto declarations = visit.visible_declarations;
  const auto inferred_declarations = decompiled_declarations(visit);
  declarations.insert(declarations.end(), inferred_declarations.begin(),
                      inferred_declarations.end());
  const bool empty_instruction =
      decompile && !visit.source && !visit.summary &&
      visit.first == visit.last && visit.last &&
      (visit.last->instruction.opcode == OP_nop ||
       visit.last->instruction.opcode == OP_nop_modrm);
  if (!visit.structural && !empty_instruction &&
      !(visit.source && visit.suppress_call_completion)) {
    const std::string &final_result =
        !incomplete && !visit.expression_result.empty()
            ? visit.expression_result
            : visit.results;
    std::string result = visit.call_results;
    if (!final_result.empty()) {
      if (!result.empty())
        result += ", ";
      result += final_result;
    }
    if (!visit.returned_value.empty()) {
      if (!result.empty())
        result += ", ";
      result += visit.returned_value;
    }
    std::string text = visit.before_line;
    size_t comment_offset = visit.comment_offset;
    if (!text.empty() && !result.empty()) {
      if (!visit.have_before)
        comment_offset = text.size() + 1;
      text += visit.have_before ? " -> " : " # -> ";
      text += result;
    }
    if (!text.empty()) {
      write_line(text + "\n", comment_offset,
                 visit.source && !visit.summary ? &visit.first->location
                                                : nullptr,
                 visit.branch_outcome, visit.assembly_offset,
                 &visit.macro_values, visit.arrival_outcome, &visit.input_types,
                 visit.function_offset, visit.function_length,
                 visit.closing_context, &declarations, visit.call_name);
      if (visit.declared_function)
        visit.declared_function->function_type_reported = true;
    }
  }
  visit = Visit{};
}

static std::pair<std::string, std::string>
deferred_call_expression(Call &call, const ct_location_view *location) {
  Visit &visit = call.deferred_call;
  if (!visit.first)
    return {};
  std::vector<std::string> names{visit.plt_name, call.display_name};
  if (call.function)
    names.push_back(call.function->name);
  if (location) {
    names.emplace_back(location->function);
    names.emplace_back(location->symbol);
    const char *aliases =
        location->inlined ? location->physical_aliases : location->aliases;
    const size_t size = location->inlined ? location->physical_aliases_size
                                          : location->aliases_size;
    for (size_t offset = 0; offset < size;) {
      const char *end = static_cast<const char *>(
          std::memchr(aliases + offset, 0, size - offset));
      if (!end)
        break;
      names.emplace_back(aliases + offset, end);
      offset = static_cast<size_t>(end - aliases) + 1;
    }
  }
  if (call.entry_pc) {
    char label[32];
    dr_snprintf(label, sizeof(label), "L%llx",
                static_cast<unsigned long long>(
                    reinterpret_cast<uintptr_t>(call.entry_pc)));
    names.emplace_back(label);
  }
  for (const auto &name : names) {
    std::string expression;
    highlight_step_into_call(visit.before_line, visit.comment_offset, name,
                             &expression);
    if (!expression.empty())
      return {name, expression};
  }
  // A GOT/function-pointer call has no named function designator in the C
  // text. Its verified statement still identifies a complete postfix call.
  const auto *statement = visit.first->decompiled.get();
  if (statement && visit.last && visit.last->instruction.call &&
      visit.code_offset < visit.before_line.size() &&
      std::none_of(
          visit.last->instruction.operands.begin(),
          visit.last->instruction.operands.end(),
          [](const auto &operand) { return opnd_is_pc(operand.value); })) {
    const size_t end = visit.comment_offset < visit.before_line.size()
                           ? visit.comment_offset - 1
                           : visit.before_line.size();
    std::string code = unstyled(
        visit.before_line.substr(visit.code_offset, end - visit.code_offset));
    const size_t first = code.find_first_not_of(" \t\r\n");
    if (first != std::string::npos)
      code.erase(0, first);
    if (statement->declaration_id && statement->declaration_name[0] &&
        code.compare(0, std::strlen(statement->declaration_name),
                     statement->declaration_name) == 0) {
      const size_t equals = code.find('=');
      if (equals != std::string::npos)
        code.erase(0, equals + 1);
    }
    const size_t start = code.find_first_not_of(" \t\r\n");
    const size_t last = code.find_last_not_of(" \t\r\n");
    if (start != std::string::npos && code[start] == '(' && code[last] == ';') {
      code = code.substr(start, last - start);
      size_t depth = 0, designator_end = std::string::npos;
      char quote = 0;
      for (size_t index = 0; index < code.size(); ++index) {
        const char ch = code[index];
        if (quote) {
          if (ch == '\\' && index + 1 < code.size())
            ++index;
          else if (ch == quote)
            quote = 0;
        } else if (ch == '\'' || ch == '"') {
          quote = ch;
        } else if (ch == '(') {
          ++depth;
        } else if (ch == ')' && depth && !--depth) {
          designator_end = index + 1;
          break;
        }
      }
      if (designator_end != std::string::npos) {
        const std::string designator = code.substr(0, designator_end);
        std::string expression;
        highlight_step_into_call(" | " + code, std::string::npos, designator,
                                 &expression);
        if (!expression.empty() &&
            code.find_first_not_of(" \t\r\n", expression.size()) ==
                std::string::npos)
          return {designator, expression};
      }
    }
  }
  return {};
}

static void close_deferred_call(Call &call, bool entered = false,
                                const ct_location_view *location = nullptr) {
  Visit &visit = call.deferred_call;
  if (!visit.first)
    return;
  visit.call_decided = true;
  if (entered) {
    visit.call_name = deferred_call_expression(call, location).first;
  }
  close_visit(visit);
}

static void flush_decompiled_rows(MachineContext &machine) {
  auto rows = std::move(machine.decompiled_rows);
  machine.decompiled_rows.clear();
  for (auto &row : rows) {
    row.decompile_machine = nullptr;
    close_visit(row);
  }
}

static void flush_machine_rows(MachineContext &machine) {
  for (auto &visit : machine.condition_rows)
    close_visit(visit);
  machine.condition_rows.clear();
  machine.update_module = nullptr;
  machine.update_branch = machine.update_next = nullptr;
}

static Module *module_at(app_pc pc) {
  for (auto &module : modules)
    if (module->active && pc >= module->start && pc < module->end)
      return module.get();
  return nullptr;
}

static bool shared_dr_generation_current(app_pc pc, uint64_t incarnation,
                                         uint64_t generation) {
  Lock lock(analysis_lock);
  const Module *module = module_at(pc);
  return module && module->incarnation == incarnation &&
         module->code_generation == generation && !module->pending_code_changes;
}

static ct_dr_shared_generation
shared_dr_generation_try_current(app_pc pc, uint64_t incarnation,
                                 uint64_t generation) {
  if (!dr_mutex_trylock(analysis_lock))
    return ct_dr_shared_generation::busy;
  const Module *module = module_at(pc);
  const auto state = !module || module->incarnation != incarnation ||
                             module->code_generation != generation
                         ? ct_dr_shared_generation::stale
                     : module->pending_code_changes
                         ? ct_dr_shared_generation::busy
                         : ct_dr_shared_generation::current;
  dr_mutex_unlock(analysis_lock);
  return state;
}

static bool within_inline_at(const Module &module, app_pc pc) {
  auto next = std::upper_bound(
      module.within_inline_ranges.begin(), module.within_inline_ranges.end(),
      pc,
      [](app_pc address, const auto &range) { return address < range.first; });
  return next != module.within_inline_ranges.begin() && pc < (next - 1)->second;
}

static Site::Mode filter_mode(const Module &module, const char *name,
                              const char *aliases = nullptr,
                              size_t aliases_size = 0) {
  if (!filtered)
    return Site::Into;
  Site::Mode mode = Site::Skip;
  const char *soname = ct_analysis_soname(module.analysis);
  size_t offset = 0;
  for (;;) {
    if (recurse_filter.matches(name, soname, module.path.c_str(),
                               module.is_main))
      return Site::Recurse;
    if (into_filter.matches(name, soname, module.path.c_str(), module.is_main))
      mode = Site::Into;
    else if (mode != Site::Into &&
             over_filter.matches(name, soname, module.path.c_str(),
                                 module.is_main))
      mode = Site::Over;
    if (offset >= aliases_size)
      break;
    name = aliases + offset;
    offset += strlen(name) + 1;
  }
  return mode;
}

static void filter_modes(const Module &module, const ct_location_view &location,
                         Site::Mode &mode, Site::Mode &physical_mode,
                         std::vector<Site::Mode> &inline_modes) {
  const char *name = location.symbol[0] ? location.symbol
                     : location.qualified_function[0]
                         ? location.qualified_function
                         : location.function;
  mode = filter_mode(module, name, location.aliases, location.aliases_size);
  physical_mode = mode;
  inline_modes.clear();
  for (size_t offset = 0; offset < location.scope_chain_size;) {
    const char *scope = location.scope_chain + offset;
    const bool physical = offset == 0;
    offset += std::strlen(scope) + 1;
    if (physical)
      physical_mode = filter_mode(module, scope, location.physical_aliases,
                                  location.physical_aliases_size);
    else
      inline_modes.push_back(offset == location.scope_chain_size
                                 ? mode
                                 : filter_mode(module, scope));
  }
}

static Site::Mode enter_scope(Site::Mode mode, bool &recurse, bool &blocked) {
  if (mode == Site::Recurse) {
    recurse = true;
    blocked = false;
    return Site::Into;
  }
  if (mode == Site::Into)
    return Site::Into;
  if (mode == Site::Over) {
    if (blocked)
      return Site::Skip;
    recurse = false;
    blocked = true;
    return Site::Over;
  }
  return recurse && !blocked ? Site::Into : Site::Skip;
}

// Called with analysis_lock held. This predicts the effective body selection
// without creating a source statement, values session, or call-stack frame.
static Site::Mode arming_mode_at(app_pc pc) {
  if (!traced_process() || !recording_thread())
    return Site::Skip;
  Module *module = module_at(pc);
  if (!module)
    return Site::Skip;
  const auto function = current_functions.find(pc);
  const bool entry = function != current_functions.end() &&
                     function->second->module.get() == module;
  if (!within_active() && !(entry && function->second->within) &&
      !within_inline_at(*module, pc))
    return Site::Skip;
  auto [position, inserted] = arming_sites.try_emplace(pc);
  ArmingSite &site = position->second;
  if (inserted || site.module != module) {
    ct_location_view location;
    std::unique_ptr<ct_location> queried;
    const auto prepared = current_sites.find(pc);
    if (prepared != current_sites.end() && prepared->second->prepared &&
        prepared->second->module.get() == module) {
      // Initial full preparation already retained these same symbol/inline
      // fields. Selecting its first execution needs no second analysis RPC.
      location = prepared->second->location;
    } else {
      queried = std::make_unique<ct_location>();
      ct_analysis_lookup_arming(module->analysis, pc - module->start,
                                queried.get());
      location = *queried;
    }
    Site::Mode mode;
    filter_modes(*module, location, mode, site.physical_mode,
                 site.inline_modes);
    site.module = module;
    site.physical =
        location.scope_chain_size ? location.scope_chain : location.symbol;
    site.plt = location.is_plt;
  }
  Thread &thread = *thread_state(dr_get_current_drcontext());
  const TraceScope &scope =
      thread.calls.empty() ? thread.root_scope : thread.calls.back()->scope;
  bool recurse = scope.recurse, blocked = scope.blocked;
  if (thread.pending.site && thread.pending.site->instruction.call) {
    recurse = thread.pending.recurse;
    blocked = thread.pending.blocked;
  }
  Site::Mode mode = scope.initialized && scope.module.get() == module &&
                            scope.function == site.physical && !entry
                        ? scope.mode
                        : enter_scope(site.physical_mode, recurse, blocked);
  for (Site::Mode nested : site.inline_modes)
    mode = enter_scope(nested, recurse, blocked);
  // Linkage transit has no independent source body. A previously observed
  // assembly call may still require its PLT instructions to be displayed.
  if (site.plt)
    return !decompile && thread.pending.site && !thread.pending.timing_only &&
                   mode == Site::Into
               ? Site::Into
               : Site::Skip;
  return mode;
}

static bool detailed_hit_at(app_pc pc) {
  return arming_mode_at(pc) == Site::Into;
}

static ct_values_module *module_values(Module &module) {
  if (!module.values) {
    module.values = ct_values_open_fd(
        module.path.c_str(), reinterpret_cast<uint64_t>(module.start),
        ct_analysis_module_file(module.analysis),
        ct_analysis_debug_file_descriptor(module.analysis),
        ct_analysis_debug_bias_correction(module.analysis));
    const int supplement =
        ct_analysis_supplement_file_descriptor(module.analysis);
    if (supplement >= 0 && module.values &&
        !ct_values_set_supplement_fd(module.values, supplement)) {
      ct_values_close(module.values);
      module.values = nullptr;
    }
    ct_values_set_cache_identity(module.values, module.identity.c_str());
  }
  return module.values;
}

static Visit &current_visit(Thread &thread) {
  return thread.calls.empty() ? thread.root : thread.calls.back()->visit;
}

static ct_provenance &current_provenance(Thread &thread) {
  return thread.calls.empty() ? thread.root_provenance
                              : thread.calls.back()->provenance;
}

static MachineContext &current_machine(Thread &thread) {
  return thread.calls.empty() ? thread.root_machine
                              : thread.calls.back()->machine;
}

static bool vdso_address(app_pc pc) {
  if (!pc)
    return false;
  auto *module = dr_lookup_module(pc);
  const bool vdso = module && module->full_path &&
                    std::strcmp(module->full_path, "[vdso]") == 0;
  if (module)
    dr_free_module_data(module);
  return vdso;
}

static uint64_t begin_trace_context(Thread &thread, app_pc pc,
                                    const char *category, const char *name,
                                    const std::string &details) {
  Module *module = module_at(pc);
  if (!module && vdso_address(pc))
    return 0;
  auto location = std::make_unique<ct_location>();
  if (module)
    ct_analysis_lookup_arming(module->analysis, pc - module->start,
                              location.get());
  return ct_perfetto_begin(thread.trace_timestamp, category, name,
                           module ? module->path.c_str() : "<unknown>",
                           location->file, location->line,
                           reinterpret_cast<uint64_t>(pc), "context",
                           details.c_str());
}

static void close_trace_syscall(Thread &thread, const char *status,
                                const char *details = nullptr) {
  ct_perfetto_end(thread.syscall.token, thread.trace_timestamp, status,
                  details);
  thread.syscall.token = 0;
}

static void end_trace_function(MachineContext &machine,
                               ct_perfetto_timestamp timestamp,
                               const char *status) {
  for (auto block = machine.trace_blocks.rbegin();
       block != machine.trace_blocks.rend(); ++block)
    ct_perfetto_end(block->token, timestamp, status);
  machine.trace_blocks.clear();
  for (auto block = machine.blocks.rbegin(); block != machine.blocks.rend();
       ++block) {
    ct_perfetto_end(block->trace_token, timestamp, status);
    block->trace_token = 0;
  }
  ct_perfetto_end(machine.trace_function, timestamp, status);
  machine.trace_function = 0;
}

// Metadata consumers share one original-byte and mapping-permission check.
// Neither a Ghidra condition nor an original source row may rely on a writable
// executable mapping or on a proof that covers only the unchanged branch.
static bool code_proof_matches(Module &module, const unsigned char *proof,
                               size_t size) {
  if (module.pending_code_changes || !ct_decompiled_proof_valid(proof, size))
    return false;
  ct_decompiled_proof_header header;
  std::memcpy(&header, proof, sizeof(header));
  size_t offset = sizeof(header);
  for (uint32_t index = 0; index < header.range_count; ++index) {
    ct_decompiled_range range;
    std::memcpy(&range, proof + offset, sizeof(range));
    offset += sizeof(range);
    if (range.begin >= range.end ||
        range.end > uint64_t(module.end - module.start))
      return false;
    for (app_pc cursor = module.start + range.begin;
         cursor < module.start + range.end;) {
      dr_mem_info_t memory{};
      if (!dr_query_memory_ex(cursor, &memory) ||
          (memory.prot & (DR_MEMPROT_READ | DR_MEMPROT_EXEC)) !=
              (DR_MEMPROT_READ | DR_MEMPROT_EXEC) ||
          (memory.prot & (DR_MEMPROT_WRITE | DR_MEMPROT_SHARED)) ||
          memory.size >
              UINTPTR_MAX - reinterpret_cast<uintptr_t>(memory.base_pc) ||
          memory.base_pc + memory.size <= cursor)
        return false;
      cursor = memory.base_pc + memory.size;
    }
  }
  for (uint32_t index = 0; index < header.instruction_count; ++index) {
    ct_decompiled_instruction instruction;
    std::memcpy(&instruction, proof + offset, sizeof(instruction));
    offset += sizeof(instruction);
    unsigned char original[15];
    if (!instruction.size || instruction.size > sizeof(original) ||
        instruction.offset >= uint64_t(module.end - module.start) ||
        instruction.size >
            uint64_t(module.end - module.start) - instruction.offset ||
        !ct_userspace_patch_read_original(module.start + instruction.offset,
                                          instruction.size, original) ||
        std::memcmp(original, instruction.bytes, instruction.size))
      return false;
  }
  return true;
}

static bool original_code_matches(Module &module, app_pc address,
                                  const ct_location_view *location = nullptr) {
  if (module.pending_code_changes)
    return false;
  const uint64_t pc = address - module.start;
  auto previous = module.original_code_proofs.upper_bound(pc);
  if (previous != module.original_code_proofs.begin()) {
    --previous;
    if (pc < previous->second.end &&
        previous->second.generation == module.code_generation)
      return previous->second.valid;
  }
  const auto failure =
      std::make_tuple(location ? uint64_t(location->source_id) : 0,
                      location ? uint64_t(location->function_id) : 0,
                      location && location->function_id ? 0 : pc);
  if (const auto known = module.original_proof_failures.find(failure);
      known != module.original_proof_failures.end() &&
      known->second == module.code_generation)
    return false;
  unsigned char *allocation = nullptr;
  size_t size = 0;
  if (!ct_analysis_code_proof(module.analysis, pc, &allocation, &size)) {
    module.original_proof_failures[failure] = module.code_generation;
    return false;
  }
  std::unique_ptr<unsigned char, decltype(&std::free)> proof(allocation,
                                                             std::free);
  if (!ct_decompiled_proof_valid(proof.get(), size))
    return false;
  ct_decompiled_proof_header header;
  ct_decompiled_range range;
  std::memcpy(&header, proof.get(), sizeof(header));
  std::memcpy(&range, proof.get() + sizeof(header), sizeof(range));
  if (header.loaded_level != 0 || header.range_count != 1 ||
      header.function_offset != range.begin || pc < range.begin ||
      pc >= range.end)
    return false;
  const bool valid = code_proof_matches(module, proof.get(), size);
  module.original_code_proofs[header.function_offset] = {
      range.end, module.code_generation, valid};
  return valid;
}

static bool source_available(Site &site) {
  if (site.source_generation != analysis_generation) {
    site.source_allowed = site.location.source_usable &&
                          ct_analysis_source_allowed(site.module->analysis,
                                                     site.location.source_id);
    site.source_generation = analysis_generation;
    if (site.location.source_usable && !site.source_allowed &&
        warnings.insert(site.module->identity + ":source").second) {
      const char *reason = ct_analysis_source_error(site.module->analysis);
      write_warning("Warning: " + site.module->path + ": " +
                    (reason ? reason : "source prefix validation failed") +
                    "\n");
    }
  }
  return site.source_allowed &&
         (!site.module->code_modified ||
          original_code_matches(*site.module, site.instruction.pc,
                                &site.location));
}

// Retain only the decision for this function and executable generation. Code
// proofs and decompiler footprints have separate entries because their ranges
// can differ; neither path retains a complete proof for every instruction.
static bool decompiled_function_matches(Site &site, uint64_t function_offset,
                                        uint32_t level) {
  Module &module = *site.module;
  if (module.pending_code_changes)
    return false;
  auto &verified = module.decompiled_proofs[function_offset];
  if (verified.first == module.code_generation)
    return verified.second;
  verified = {module.code_generation, false};
  unsigned char *allocation = nullptr;
  size_t size = 0;
  if (!ct_analysis_decompile_proof(module.analysis,
                                   site.instruction.pc - module.start, level,
                                   &allocation, &size))
    return false;
  std::unique_ptr<unsigned char, decltype(&std::free)> proof(allocation,
                                                             std::free);
  if (!ct_decompiled_proof_valid(proof.get(), size))
    return false;
  ct_decompiled_proof_header header;
  std::memcpy(&header, proof.get(), sizeof(header));
  if (header.function_offset != function_offset || header.loaded_level < level)
    return false;
  verified.second = code_proof_matches(module, proof.get(), size);
  return verified.second;
}

// Both structural and detailed traces use the same immutable display result.
// Requests at a lower level reuse the fields already loaded for this site.
static const ct_decompiled_display_view *
prepare_decompiled_display(Site &site, ct_instrument_level level) {
  if (!decompile || level == ct_instrument_level::arm || site.location.is_plt ||
      source_available(site))
    return nullptr;
  if (site.display_generation != site.module->code_generation) {
    site.display_generation = site.module->code_generation;
    site.display_level = 0;
    site.decompiled_display.reset();
  }
  if (site.module->pending_code_changes)
    return nullptr;
  const uint32_t requested = level == ct_instrument_level::full
                                 ? CT_DECOMPILE_FULL
                                 : CT_DECOMPILE_PERFETTO;
  if (site.display_level < requested) {
    site.display_level = requested;
    auto display = std::make_unique<ct_decompiled_display>();
    if (!ct_analysis_decompile_display(site.module->analysis,
                                       site.instruction.pc - site.module->start,
                                       requested, display.get()))
      return site.decompiled_display.get();
    const auto &instruction = display->instruction;
    const uint64_t module_size = site.module->end - site.module->start;
    unsigned char original[15];
    if (!instruction.size || instruction.size > sizeof(original) ||
        instruction.offset >= module_size ||
        instruction.size > module_size - instruction.offset ||
        site.module->start + instruction.offset != site.instruction.pc ||
        !ct_userspace_patch_read_original(site.instruction.pc, instruction.size,
                                          original) ||
        std::memcmp(original, instruction.bytes, instruction.size))
      return site.decompiled_display.get();
    if (!decompiled_function_matches(site, display->function_offset, requested))
      return nullptr;
    site.display_level = std::max(site.display_level, display->loaded_level);
    site.decompiled_display =
        std::make_unique<ct_decompiled_display_record>(*display);
  }
  return site.decompiled_display.get();
}

static uint64_t begin_trace_block(const Site &site, const char *name,
                                  unsigned line, const char *origin) {
  if (!ct_perfetto_enabled())
    return 0;
  return ct_perfetto_begin(
      thread_state(dr_get_current_drcontext())->trace_timestamp, "ctrace.block",
      name, site.module->path.c_str(), site.location.file, line,
      reinterpret_cast<uint64_t>(site.instruction.pc), origin);
}

static void trace_source_blocks(MachineContext &machine, Site &site,
                                bool source) {
  if (!ct_perfetto_enabled())
    return;
  const auto &location = site.location;
  const auto executed =
      ct_perfetto_source_scopes(location, source && machine.trace_body);
  size_t shared = 0;
  while (shared < executed.size() && shared < machine.trace_blocks.size()) {
    const auto &active = machine.trace_blocks[shared];
    if (active.entry->module != site.module ||
        active.entry->location.source_id != location.source_id ||
        active.entry->location.function_id != location.function_id ||
        active.description->id != executed[shared]->id)
      break;
    ++shared;
  }
  const ct_perfetto_timestamp timestamp =
      thread_state(dr_get_current_drcontext())->trace_timestamp;
  while (machine.trace_blocks.size() > shared) {
    ct_perfetto_end(machine.trace_blocks.back().token, timestamp, "complete");
    machine.trace_blocks.pop_back();
  }
  for (size_t index = shared; index < executed.size(); ++index) {
    const auto &block = *executed[index];
    const char *name =
        block.opening_context[0] ? block.opening_context : block.opening;
    machine.trace_blocks.push_back(
        {site.shared_from_this(), &block,
         begin_trace_block(site, name, block.opening_line, "source")});
  }
}

static void machine_annotation(MachineContext &machine, const Site &site,
                               const std::string &text,
                               const std::string &closing_context = {},
                               const char *function_override = nullptr,
                               char boundary = '\0') {
  if (machine.timing_only)
    return;
  flush_decompiled_rows(machine);
  const char *function = function_override ? function_override
                         : !machine.function_alias.empty()
                             ? machine.function_alias.c_str()
                         : site.location.function[0] ? site.location.function
                                                     : site.location.symbol;
  if (!function[0])
    function = machine.scope_name.c_str();
  std::string line = location_prefix(
      dr_get_current_drcontext(), site.instruction.pc, *site.module,
      site.location, function, site.location.line);
  if (decompile && !boundary) {
    line += "\033[32m" + text + "\033[0m";
    write_line(line + "\n", std::string::npos, nullptr, -1, std::string::npos,
               nullptr, -1, nullptr, std::string::npos, 0, closing_context);
    return;
  }
  if (boundary) {
    line += "\033[42;97m";
    line += boundary;
    line += "\033[0m ";
  }
  const size_t comment = line.size();
  line += "# /* " + text;
  if (!closing_context.empty())
    line += " // " + closing_context;
  line += " */\n";
  write_line(line, comment);
}

static void close_plt(MachineContext &machine, Visit &visit) {
  if (!machine.plt_last)
    return;
  flush_machine_rows(machine);
  close_visit(visit);
  flush_decompiled_rows(machine);
  machine.plt_last = nullptr;
}

static void close_assembly_function(Call &call) {
  if (!call.assembly_entry || !call.assembly_last)
    return;
  const Site &last = *call.assembly_last;
  std::string text =
      location_prefix(dr_get_current_drcontext(), last.instruction.pc,
                      *last.module, last.location, call.assembly_scope.c_str(),
                      last.location.line) +
      "\033[42;97m}\033[0m";
  write_line(text + "\n", std::string::npos, nullptr, -1, std::string::npos,
             nullptr, -1, nullptr, std::string::npos, 0,
             call.assembly_invocation);
  call.assembly_entry = call.assembly_last = nullptr;
  call.assembly_scope.clear();
  call.assembly_invocation.clear();
}

static void machine_case(MachineContext &machine, Site &site) {
  for (size_t depth = machine.blocks.size(); depth > 0; --depth) {
    auto &block = machine.blocks[depth - 1];
    if (!block.switch_region || block.last->module != site.module ||
        block.case_pc == site.instruction.pc)
      continue;
    const auto &region = *block.switch_region;
    const uint64_t offset = site.instruction.pc - site.module->start;
    const bool matched =
        region.default_offset == offset ||
        std::any_of(region.cases, region.cases + region.case_count,
                    [offset](const ct_flow_case &entry) {
                      return entry.target_offset == offset;
                    });
    if (!matched)
      continue;
    flush_machine_rows(machine);
    // A fallthrough case label follows all work and nested scopes in the
    // preceding case, even when its last instruction was still buffered.
    while (machine.blocks.size() > depth) {
      ct_perfetto_end(machine.blocks.back().trace_token,
                      thread_state(dr_get_current_drcontext())->trace_timestamp,
                      "complete");
      machine_annotation(machine, site, "}", machine.blocks.back().opening);
      machine.blocks.pop_back();
    }
    for (uint32_t index = 0; index < region.case_count; ++index)
      if (region.cases[index].target_offset == offset) {
        machine_annotation(machine, site,
                           "case " + std::to_string(region.cases[index].value) +
                               ":");
      }
    if (region.default_offset == offset)
      machine_annotation(machine, site, "default:");
    block.case_pc = site.instruction.pc;
    return;
  }
}

// A null site closes a frame at its last observed instruction. Otherwise only
// a proven join or a loop's next condition closes the corresponding scopes.
static void close_machine_blocks(MachineContext &machine,
                                 Site *site = nullptr) {
  size_t keep = 0;
  if (site) {
    keep = machine.blocks.size();
    for (size_t index = 0; index < machine.blocks.size(); ++index) {
      const auto &block = machine.blocks[index];
      if (block.last->module == site->module &&
          (block.join == site->instruction.pc ||
           block.repeat == site->instruction.pc)) {
        keep = index;
        break;
      }
    }
  }
  if (!site || machine.blocks.size() > keep)
    flush_machine_rows(machine);
  while (machine.blocks.size() > keep) {
    ct_perfetto_end(machine.blocks.back().trace_token,
                    thread_state(dr_get_current_drcontext())->trace_timestamp,
                    "complete");
    machine_annotation(machine, site ? *site : *machine.blocks.back().last, "}",
                       machine.blocks.back().opening);
    machine.blocks.pop_back();
  }
}

static bool decompiled_condition(MachineContext &machine, Site &site,
                                 Visit &branch, const std::string &code,
                                 const char *result,
                                 const ct_flow_region *counted_loop = nullptr) {
  if (!decompile || branch.branch_outcome < 0 ||
      branch.code_offset == std::string::npos)
    return false;
  const bool expression =
      !machine.comparison.lhs.empty() &&
      ct_format_branch_condition(site.instruction, &machine.comparison) !=
          ct_format_branch_condition(site.instruction);
  Visit comparison;
  if (expression && !machine.condition_rows.empty()) {
    app_pc next = site.instruction.pc;
    for (size_t index = machine.condition_rows.size(); index; --index) {
      const auto &row = machine.condition_rows[index - 1];
      if (!row.first || row.first != row.last || row.source ||
          row.first->module != site.module ||
          row.first->instruction.next != next)
        break;
      const auto &instruction = row.first->instruction;
      if (instruction.pc == machine.comparison_pc &&
          (instruction.opcode == OP_cmp || instruction.opcode == OP_test) &&
          row.code_offset != std::string::npos) {
        comparison = std::move(machine.condition_rows[index - 1]);
        machine.condition_rows.resize(index - 1);
        break;
      }
      if (instruction.opcode != OP_nop && instruction.opcode != OP_nop_modrm)
        break;
      next = instruction.pc;
    }
  }
  std::vector<Visit> effects;
  if (comparison.first && counted_loop && !machine.condition_rows.empty()) {
    const auto &rows = machine.condition_rows;
    const auto first = rows.front().first;
    bool complete =
        first && first->module == site.module &&
        (first->instruction.pc ==
             site.module->start + counted_loop->update_offset ||
         (counted_loop->has_initializer &&
          first->instruction.pc ==
              site.module->start + counted_loop->initializer_offset));
    for (size_t index = 0; complete && index < rows.size(); ++index) {
      const auto &row = rows[index];
      if (!row.first || row.first != row.last || row.source || row.summary ||
          row.first->module != site.module) {
        complete = false;
        break;
      }
      const auto &instruction = row.first->instruction;
      app_pc next = instruction.next;
      if (index) {
        if (instruction.opcode == OP_jmp ||
            instruction.opcode == OP_jmp_short) {
          next = nullptr;
          for (const auto &operand : instruction.operands)
            if (opnd_is_pc(operand.value))
              next = opnd_get_pc(operand.value);
        } else if (instruction.opcode != OP_nop &&
                   instruction.opcode != OP_nop_modrm) {
          complete = false;
        }
      }
      const auto following =
          index + 1 < rows.size() ? rows[index + 1].first : comparison.first;
      complete &= following && next == following->instruction.pc;
    }
    if (complete) {
      effects = std::move(machine.condition_rows);
      machine.condition_rows.clear();
    }
  }
  // Never consume loop updates, arithmetic, or intervening instructions merely
  // because they happened to share the condition lookahead buffer.
  flush_machine_rows(machine);
  flush_decompiled_rows(machine);
  const Visit &inputs = comparison.first ? comparison : branch;
  std::string before, changes;
  std::vector<OperandType> types;
  std::unordered_set<std::string> seen, written;
  std::vector<const Visit *> observations;
  for (const auto &effect : effects)
    observations.push_back(&effect);
  observations.push_back(&inputs);
  for (const Visit *observation : observations) {
    const std::string values =
        observation->have_before &&
                observation->comment_offset < observation->before_line.size()
            ? observation->before_line.substr(observation->comment_offset + 2)
            : std::string{};
    for (const auto &[offset, length] : decompiled_fields(values)) {
      const std::string field = values.substr(offset, length);
      const std::string plain = unstyled(field);
      const std::string name = plain.substr(0, plain.find('='));
      if (name == "RIP" || name == "%RIP")
        continue;
      if (comparison.first && (name == "CF" || name == "PF" || name == "AF" ||
                               name == "ZF" || name == "SF" || name == "OF"))
        continue;
      if (written.count(observed_register_key(name)) ||
          !seen.insert(name).second)
        continue;
      if (!before.empty())
        before += ", ";
      for (const auto &type : observation->input_types)
        if (type.offset >= offset && type.offset < offset + length) {
          auto copy = type;
          copy.offset = before.size() + type.offset - offset;
          types.push_back(std::move(copy));
        }
      before += field;
    }
    if (observation != &inputs) {
      for (const auto &[offset, length] :
           decompiled_fields(observation->results)) {
        const std::string field = observation->results.substr(offset, length);
        const std::string plain = unstyled(field);
        const std::string name = plain.substr(0, plain.find('='));
        if (name == "RIP" || name == "%RIP" || name == "CF" || name == "PF" ||
            name == "AF" || name == "ZF" || name == "SF" || name == "OF")
          continue;
        written.insert(observed_register_key(name));
        if (!changes.empty())
          changes += ", ";
        changes += field;
      }
      for (const auto &operand : observation->last->instruction.outputs)
        if (opnd_is_reg(operand) && reg_is_gpr(opnd_get_reg(operand)))
          written.insert(
              ct_register_name(reg_to_pointer_sized(opnd_get_reg(operand))));
    }
  }
  const std::string prefix = inputs.before_line.substr(0, inputs.code_offset);
  if (comparison.first)
    branch = std::move(comparison);
  branch.last = site.shared_from_this();
  branch.before_line = prefix + "\033[32m" + code + "\033[0m";
  branch.comment_offset = std::string::npos;
  branch.have_before = !before.empty();
  if (branch.have_before) {
    branch.comment_offset = branch.before_line.size() + 1;
    branch.before_line += " # " + before;
  }
  branch.input_types = std::move(types);
  branch.results = changes.empty() ? result : changes + ", " + result;
  branch.expression_result.clear();
  branch.call_results.clear();
  branch.decompile_machine = nullptr;
  branch.assembly_offset = std::string::npos;
  branch.branch_outcome = -1;
  return true;
}

// Cache only instruction structure. These formatters receive no values-site or
// memory reader, so both collectors can recover the same loop label without
// evaluating the induction variable.
static bool prepare_loop_instructions(Site &site, const ct_flow_region &region,
                                      const ct_registers &registers) {
  if (region.kind != CT_FLOW_LOOP)
    return false;
  if (region.has_update && !site.loop_update_checked) {
    site.loop_update_checked = true;
    void *context = dr_get_current_drcontext();
    instr_t update;
    instr_init(context, &update);
    const app_pc update_pc = site.module->start + region.update_offset;
    if (decode(context, update_pc, &update)) {
      instr_set_translation(&update, update_pc);
      site.loop_update_instruction = std::make_unique<ct_instruction>(
          ct_decode_instruction(context, &update));
      site.loop_update =
          ct_format_loop_update(*site.loop_update_instruction, registers);
    }
    instr_free(context, &update);
    if (!site.loop_update.empty()) {
      const auto [existing, inserted] =
          site.module->flow_updates.emplace(update_pc, site.instruction.pc);
      if (!inserted && existing->second != site.instruction.pc)
        site.loop_update.clear();
    }
  }
  const bool counted = !site.loop_update.empty();
  if (counted && region.has_initializer && !site.loop_initializer_checked) {
    site.loop_initializer_checked = true;
    void *context = dr_get_current_drcontext();
    instr_t initializer;
    instr_init(context, &initializer);
    const app_pc initializer_pc =
        site.module->start + region.initializer_offset;
    if (decode(context, initializer_pc, &initializer)) {
      instr_set_translation(&initializer, initializer_pc);
      site.loop_initializer_instruction = std::make_unique<ct_instruction>(
          ct_decode_instruction(context, &initializer));
    }
    instr_free(context, &initializer);
  }
  return counted;
}

// The JSON name is independent of terminal value/provenance formatting. Both
// collectors use the same proven decompiler control and the same fallback.
static void begin_recovered_block(MachineBlock &block, Site &site,
                                  MachineContext &machine,
                                  const ct_registers &registers, bool body,
                                  bool counted) {
  if (!ct_perfetto_enabled() || !machine.trace_body)
    return;
  const auto level =
      ct_required_instrumentation(ct_perfetto_enabled(), !machine.timing_only);
  const auto *display = prepare_decompiled_display(site, level);
  ct_perfetto_flow_label label;
  if (const auto switched =
          site.module->flow_switches.find(site.instruction.pc);
      switched != site.module->flow_switches.end()) {
    label = ct_perfetto_switch_label(switched->second->selector_register,
                                     display ? *display
                                             : ct_decompiled_display_view{});
  } else if (const auto found =
                 site.module->flow_regions.find(site.instruction.pc);
             found != site.module->flow_regions.end()) {
    const auto &region = found->second;
    const bool body_taken =
        region.kind == CT_FLOW_LOOP
            ? region.taken_is_body
            : region.fallthrough_offset == region.join_offset;
    const std::string condition = ct_format_branch_condition(
        site.instruction,
        machine.trace_comparison_next == site.instruction.pc
            ? &machine.trace_comparison
            : nullptr,
        body_taken, false);
    std::string initializer, update;
    if (counted && site.loop_initializer_instruction)
      initializer = ct_format_loop_initializer(
          *site.loop_initializer_instruction, registers);
    if (counted && site.loop_update_instruction)
      update = ct_format_loop_update(*site.loop_update_instruction, registers);
    label = ct_perfetto_recovered_label(
        region, body, condition, initializer, update,
        display ? *display : ct_decompiled_display_view{});
  } else {
    label.text = block.opening;
  }
  block.trace_name = std::move(label.text);
  block.trace_origin = label.origin;
  block.trace_token =
      begin_trace_block(site, block.trace_name.c_str(), site.location.line,
                        block.trace_origin.c_str());
}

static BranchClosure machine_branch(MachineContext &machine, Site &site,
                                    app_pc destination,
                                    const ct_registers &registers,
                                    std::string &closing_context,
                                    Visit &branch) {
  const auto &instruction = site.instruction;
  const bool verified_flow =
      !site.module->code_modified ||
      prepare_decompiled_display(
          site, ct_required_instrumentation(ct_perfetto_enabled(),
                                            !machine.timing_only));
  // The opening comment precedes these observed instructions. Use the first
  // row's complete location, not the later branch that revealed the outcome.
  const Site &opening =
      !machine.condition_rows.empty() && machine.condition_rows.front().first
          ? *machine.condition_rows.front().first
          : site;
  if (const auto found = site.module->flow_switches.find(instruction.pc);
      verified_flow && found != site.module->flow_switches.end()) {
    const auto &region = *found->second;
    const std::string selector =
        machine.comparison_pc == site.module->start + region.selector_offset &&
                !machine.comparison.lhs.empty()
            ? machine.comparison.lhs
            : region.selector_register;
    if (!selector.empty()) {
      const std::string text = "switch (" + selector + ") {";
      if (!decompiled_condition(machine, site, branch, text, ""))
        machine_annotation(machine, opening, text);
      machine.blocks.push_back({site.shared_from_this(),
                                site.module->start + region.join_offset,
                                nullptr, text, found->second});
      if (destination != site.module->start + region.join_offset)
        begin_recovered_block(machine.blocks.back(), site, machine, registers,
                              true, false);
      return BranchClosure::None;
    }
  }
  const std::string predicate = ct_format_branch_condition(
      instruction, &machine.comparison, true, decompile);
  if (predicate.empty())
    return BranchClosure::None;
  const auto found = verified_flow
                         ? site.module->flow_regions.find(instruction.pc)
                         : site.module->flow_regions.end();
  if (found == site.module->flow_regions.end()) {
    for (const auto &operand : instruction.operands) {
      if (!opnd_is_pc(operand.value))
        continue;
      char target[32];
      dr_snprintf(target, sizeof(target), "L%llx",
                  static_cast<unsigned long long>(
                      reinterpret_cast<uintptr_t>(opnd_get_pc(operand.value))));
      closing_context = "if (" + predicate + ") goto " + target + ";";
      if (decompiled_condition(machine, site, branch, closing_context,
                               branch.branch_outcome == 1 ? "true" : "false")) {
        closing_context.clear();
        return BranchClosure::None;
      }
      machine_annotation(machine, opening, closing_context, {}, nullptr, '{');
      return BranchClosure::Condition;
    }
    return BranchClosure::None;
  }
  const auto &region = found->second;
  const auto base = site.module->start;
  if (destination != base + region.taken_offset &&
      destination != base + region.fallthrough_offset)
    return BranchClosure::None;
  const bool loop = region.kind == CT_FLOW_LOOP;
  const bool counted = prepare_loop_instructions(site, region, registers);
  std::string initializer_text;
  if (counted && site.loop_initializer_instruction)
    initializer_text = ct_format_loop_initializer(
        *site.loop_initializer_instruction, registers, site.values, read_memory,
        nullptr, &region.initializer_source, &machine.decompiled_operands);
  std::string update_text = site.loop_update;
  if (counted) {
    // The instruction is immutable, but names depend on the current DWARF PC
    // and frame. Never cache a resolved name across iterations or threads.
    const std::string resolved = ct_format_loop_update(
        *site.loop_update_instruction, registers, site.values, read_memory,
        nullptr, &machine.decompiled_operands);
    if (!resolved.empty())
      update_text = resolved;
  }
  const auto recovered = ct_perfetto_recovered_scope(
      region, destination - base, branch.branch_outcome, counted);
  const bool has_else = recovered.has_else;
  // For two arms, the fallthrough is presented as the first arm. This is a
  // machine-equivalent orientation, not a claim about the original C syntax.
  const bool body_taken = loop
                              ? region.taken_is_body
                              : region.fallthrough_offset == region.join_offset;
  const std::string condition = ct_format_branch_condition(
      instruction, &machine.comparison, body_taken, decompile);
  const bool body = recovered.body;
  std::string text =
      counted ? "for (" + initializer_text + "; " + condition + "; " +
                    update_text + ") {"
              : std::string(loop ? "while (" : "if (") + condition + ") {";
  if (!decompiled_condition(machine, site, branch, text,
                            body ? "true" : "false",
                            counted ? &region : nullptr))
    machine_annotation(machine, opening, text);
  if (recovered.open) {
    machine.blocks.push_back({site.shared_from_this(), base + recovered.join,
                              loop ? base + recovered.repeat : nullptr,
                              body ? text : "else {"});
    begin_recovered_block(machine.blocks.back(), site, machine, registers, body,
                          counted);
  }
  if (!body)
    closing_context = text;
  return body ? BranchClosure::None
              : (has_else ? BranchClosure::Else : BranchClosure::Close);
}

static void defer_return(Thread &thread, Visit &visit) {
  if (thread.calls.empty() || !visit.first || !visit.source || visit.summary ||
      visit.inlined ||
      visit.first->location.expression_kind != CT_EXPRESSION_RETURN)
    return;
  Call &frame = *thread.calls.back();
  if (!frame.function)
    return;
  if (frame.returning.first) {
    if (frame.returning_function != frame.function) {
      // A tail target shares the machine frame, but its return does not
      // replace the source return that transferred control to it.
      frame.tail_summaries.push_back({std::move(frame.returning),
                                      frame.returning_function,
                                      std::move(frame.returning_arguments)});
    } else {
      close_visit(frame.returning, "return path changed");
    }
    for (auto &exit : frame.block_exits)
      close_visit(exit, "return path changed");
    frame.block_exits.clear();
    for (const auto &line : frame.return_lines)
      write_line(line.text, std::string::npos, nullptr, -1, std::string::npos,
                 nullptr, -1, nullptr, std::string::npos, 0,
                 line.closing_context);
    frame.return_lines.clear();
  }
  frame.returning = std::move(visit);
  frame.returning_function = frame.function;
  frame.returning_arguments = frame.arguments;
  visit = Visit{};
}

static bool operand_bytes(opnd_t operand, const ct_registers &registers,
                          unsigned char *bytes, size_t size) {
  if (!opnd_is_reg(operand) || !size)
    return false;
  const reg_id_t reg = opnd_get_reg(operand);
  uint64_t location = 0;
  size_t offset = 0;
  if (reg_is_gpr(reg) && registers.have_gpr &&
      ct_operand_location(operand, registers, &location, &offset) &&
      location < 17 && offset + size <= sizeof(registers.gpr[0])) {
    memcpy(bytes,
           reinterpret_cast<const unsigned char *>(registers.gpr + location) +
               offset,
           size);
    return true;
  }
  if (reg_is_vector_simd(reg) && registers.have_xmm &&
      size <= registers.simd_bytes) {
    const reg_id_t full = reg_resize_to_opsz(reg, OPSZ_64);
    const size_t index = full - DR_REG_ZMM0;
    const size_t count = registers.simd_bytes == 64 ? 32 : 16;
    if (index < count) {
      memcpy(bytes, registers.xmm[index], size);
      return true;
    }
  }
  if (reg_is_opmask(reg) && registers.have_opmask &&
      size <= sizeof(registers.opmask[0])) {
    const size_t index = reg - DR_REG_K0;
    if (index < std::size(registers.opmask)) {
      memcpy(bytes, registers.opmask + index, size);
      return true;
    }
  }
  return false;
}

struct StateOperand {
  opnd_t value;
  bool write = false, raw = false;
};

/* Collect storage read or changed by the instruction. Parent-register writes
 * represent architectural zero extension, not a guessed value calculation. */
static std::vector<StateOperand>
state_operands(const ct_instruction &instruction, const ct_registers &registers,
               bool before) {
  std::vector<StateOperand> result;
  auto add = [&](opnd_t operand, bool write, bool raw = false) {
    if (!opnd_is_reg(operand) && !opnd_is_memory_reference(operand))
      return;
    auto existing =
        std::find_if(result.begin(), result.end(), [&](const auto &entry) {
          return opnd_same(entry.value, operand) &&
                 (instruction.opcode != OP_pop ||
                  !opnd_is_memory_reference(operand) || entry.write == write);
        });
    if (existing == result.end())
      result.push_back({operand, write, raw});
    else
      existing->raw |= raw;
  };
  std::vector<StateOperand> operands;
  if (before) {
    // Data inputs precede the address calculation and the storage it reads.
    // Keep each group in the decoder's operand order.
    for (opnd_t operand : instruction.inputs)
      if (!opnd_is_memory_reference(operand))
        operands.push_back({operand, false});
    for (opnd_t operand : instruction.inputs)
      if (opnd_is_memory_reference(operand))
        operands.push_back({operand, false});
  }
  for (opnd_t operand : instruction.outputs)
    operands.push_back({operand, true});
  for (const auto &entry : operands) {
    const opnd_t operand = entry.value;
    const bool memory = opnd_is_memory_reference(operand);
    if (before && opnd_is_base_disp(operand)) {
      for (reg_id_t reg : {opnd_get_base(operand), opnd_get_index(operand)})
        if (reg != DR_REG_NULL)
          add(opnd_create_reg(reg), false, true);
    }
    if ((!memory || (!entry.write && instruction.reads_memory) ||
         (entry.write && instruction.writes_memory)))
      add(operand, entry.write);
    if (!entry.write || !opnd_is_reg(operand))
      continue;
    const reg_id_t reg = opnd_get_reg(operand);
    if (reg_is_gpr(reg) && opnd_size_in_bytes(opnd_get_size(operand)) == 4)
      add(opnd_create_reg(reg_resize_to_opsz(reg, OPSZ_8)), true, true);
    if (reg_is_vector_simd(reg)) {
      if (opnd_size_in_bytes(opnd_get_size(operand)) <
          opnd_size_in_bytes(reg_get_size(reg)))
        add(opnd_create_reg(reg), true, true);
      const opnd_size_t parent =
          instruction.zeroes_zmmh && registers.simd_bytes >= 64   ? OPSZ_64
          : instruction.zeroes_ymmh && registers.simd_bytes >= 32 ? OPSZ_32
                                                                  : OPSZ_NA;
      if (parent != OPSZ_NA)
        add(opnd_create_reg(reg_resize_to_opsz(reg, parent)), true, true);
    }
  }
  if ((instruction.opcode == OP_vzeroall ||
       instruction.opcode == OP_vzeroupper) &&
      registers.simd_bytes >= 32) {
    const reg_id_t first =
        registers.simd_bytes == 64 ? DR_REG_ZMM0 : DR_REG_YMM0;
    for (int index = 0; index < 16; ++index)
      add(opnd_create_reg(static_cast<reg_id_t>(first + index)), true, true);
  }
  if (instruction.syscall) {
    add(opnd_create_reg(DR_REG_RAX), true, true);
    if (before) {
      for (reg_id_t reg : {DR_REG_RDI, DR_REG_RSI, DR_REG_RDX, DR_REG_R10,
                           DR_REG_R8, DR_REG_R9})
        add(opnd_create_reg(reg), false, true);
    } else {
      add(opnd_create_reg(DR_REG_RCX), true, true);
      add(opnd_create_reg(DR_REG_R11), true, true);
    }
  }
  return result;
}

static std::string
format_operand(const StateOperand &entry, const ct_instruction &instruction,
               const ct_registers &registers,
               const ct_registers &address_registers, ct_values_site *site,
               const ct_provenance *provenance,
               OperandType *display_type = nullptr,
               const std::vector<ct_decompiled_operand> *decompiled = nullptr) {
  const opnd_t operand = entry.value;
  const bool memory = opnd_is_memory_reference(operand);
  const size_t size = opnd_size_in_bytes(opnd_get_size(operand));
  // Bound individual storage snapshots; dynamic unknown-size operands have no
  // complete byte extent that can be sampled here.
  if (!size || size > 64 * 1024)
    return {};
  ct_registers address_state = address_registers;
  if (memory && entry.write && instruction.opcode == OP_pop)
    address_state.gpr[7] += size;
  uint64_t location = 0;
  size_t offset = 0;
  const bool mapped_location = ct_operand_location(
      operand, memory ? address_state : registers, &location, &offset);
  if (memory && !mapped_location) {
    if (!address_state.have_gpr ||
        !(opnd_is_base_disp(operand) || opnd_is_abs_addr(operand) ||
          opnd_is_rel_addr(operand)))
      return {};
    if (opnd_is_base_disp(operand) &&
        ((opnd_get_base(operand) != DR_REG_NULL &&
          !reg_is_gpr(opnd_get_base(operand))) ||
         (opnd_get_index(operand) != DR_REG_NULL &&
          !reg_is_gpr(opnd_get_index(operand)))))
      return {}; // VSIB needs per-lane active-mask address enumeration.
    const reg_id_t segment = opnd_get_segment(operand);
    if (segment != DR_SEG_FS && segment != DR_SEG_GS)
      return {};
    dr_mcontext_t context{};
    context.size = sizeof(context);
    context.flags =
        static_cast<dr_mcontext_flags_t>(DR_MC_INTEGER | DR_MC_CONTROL);
    const reg_id_t regs[] = {DR_REG_RAX, DR_REG_RDX, DR_REG_RCX, DR_REG_RBX,
                             DR_REG_RSI, DR_REG_RDI, DR_REG_RBP, DR_REG_RSP,
                             DR_REG_R8,  DR_REG_R9,  DR_REG_R10, DR_REG_R11,
                             DR_REG_R12, DR_REG_R13, DR_REG_R14, DR_REG_R15};
    for (size_t index = 0; index < std::size(regs); ++index)
      reg_set_value(regs[index], &context, address_state.gpr[index]);
    location =
        reinterpret_cast<uint64_t>(opnd_compute_address(operand, &context));
  }
  std::vector<unsigned char> bytes(size);
  const bool captured =
      memory ? read_memory(nullptr, location, bytes.data(), size)
             : operand_bytes(operand, registers, bytes.data(), size);
  std::vector<char> formatted(value_capacity);
  if (!entry.raw && mapped_location) {
    ct_variable_description description{};
    if (ct_values_format_assembly_operand(
            site, &registers, read_memory, nullptr, memory, location, offset,
            captured ? bytes.data() : nullptr, size, formatted.data(),
            formatted.size(), display_type ? &description : nullptr) &&
        formatted[0]) {
      if (display_type && description.module_id) {
        display_type->identity = std::to_string(description.module_id) + ":" +
                                 std::to_string(description.die_offset) + ":" +
                                 description.name;
        display_type->type = description.type;
      }
      return formatted.data();
    }
  }
  // Match the owning object, not just the scalar slot touched by this
  // instruction. This uses a proven storage extent and a recursive type graph;
  // a type name or a coincidentally equal pointer is insufficient.
  const ct_decompiled_operand *object = nullptr;
  if (!entry.raw && mapped_location && memory && decompiled) {
    for (const auto &candidate : *decompiled) {
      if (!candidate.memory || candidate.subobject || !candidate.type_id ||
          candidate.type_id > candidate.layout.type_count ||
          !candidate.layout.types || location < candidate.location ||
          location - candidate.location > candidate.bytes ||
          size > candidate.bytes - (location - candidate.location) ||
          (entry.write ? !candidate.write : !candidate.read))
        continue;
      const auto &type = candidate.layout.types[candidate.type_id - 1];
      if (type.kind != CT_LAYOUT_STRUCT && type.kind != CT_LAYOUT_ARRAY)
        continue;
      if (object && object->identity != candidate.identity) {
        object = nullptr;
        break;
      }
      object = &candidate;
    }
  }
  if (object) {
    struct Snapshot {
      uint64_t address;
      const unsigned char *data;
      size_t size;
    } snapshot{location, captured ? bytes.data() : nullptr, size};
    const auto read = [](void *argument, uint64_t address, void *destination,
                         size_t count) {
      const auto &snapshot = *static_cast<const Snapshot *>(argument);
      if (count > UINT64_MAX - address ||
          snapshot.size > UINT64_MAX - snapshot.address)
        return false;
      const uint64_t begin = std::max(address, snapshot.address);
      const uint64_t end =
          std::min(address + count, snapshot.address + snapshot.size);
      if (begin >= end)
        return read_memory(nullptr, address, destination, count);
      if (!snapshot.data)
        return false;
      auto *output = static_cast<unsigned char *>(destination);
      if (begin > address &&
          !read_memory(nullptr, address, output, begin - address))
        return false;
      std::memcpy(output + (begin - address),
                  snapshot.data + (begin - snapshot.address), end - begin);
      return end == address + count ||
             read_memory(nullptr, end, output + (end - address),
                         address + count - end);
    };
    if (ct_values_format_layout(object->name.c_str(), &object->layout,
                                object->type_id, nullptr, object->bytes,
                                object->location, true, read, &snapshot,
                                formatted.data(), formatted.size())) {
      if (display_type) {
        display_type->identity = object->identity;
        display_type->type = object->type_name;
      }
      return formatted.data();
    }
  }
  const ct_decompiled_operand *recovered = nullptr;
  if (!entry.raw && mapped_location && decompiled)
    recovered = ct_find_decompiled_operand(*decompiled, operand,
                                           memory ? address_state : registers,
                                           !entry.write, entry.write);
  if (recovered) {
    if (display_type) {
      display_type->identity = recovered->identity;
      display_type->type = recovered->type_name;
    }
    if (!captured)
      return recovered->name + "=?";
    if (recovered->type_id &&
        ct_values_format_layout(recovered->name.c_str(), &recovered->layout,
                                recovered->type_id, bytes.data(), size,
                                location, memory, read_memory, nullptr,
                                formatted.data(), formatted.size()))
      return formatted.data();
    if (ct_values_format_typed(recovered->name.c_str(), &recovered->type,
                               bytes.data(), size, formatted.data(),
                               formatted.size()) &&
        formatted[0])
      return formatted.data();
  }
  if (!captured)
    return {};
  if (!entry.raw && !memory && provenance) {
    const ct_register_origin *origin =
        ct_operand_origin(*provenance, operand, registers);
    if (!recovered && origin &&
        ct_values_format_typed(origin->name.c_str(), &origin->type,
                               bytes.data(), size, formatted.data(),
                               formatted.size()) &&
        formatted[0]) {
      if (display_type &&
          (origin->symbol_module_id || !origin->source_identity.empty())) {
        display_type->identity =
            origin->source_identity.empty()
                ? std::to_string(origin->symbol_module_id) + ":" +
                      std::to_string(origin->symbol_die_offset) + ":" +
                      origin->name
                : origin->source_identity;
        display_type->type = origin->type_name;
      }
      return formatted.data();
    }
  }
  std::string result = recovered ? recovered->name : "\033[31m";
  if (!recovered && memory) {
    std::string expression;
    // A symbolic address always describes the pre-instruction register state
    // used to sample this operand. Keep segmented, absolute, relative and
    // short-address forms as their sampled address rather than guessing.
    if (mapped_location && opnd_is_base_disp(operand) &&
        !opnd_is_disp_short_addr(operand)) {
      const reg_id_t base = opnd_get_base(operand);
      const reg_id_t index = opnd_get_index(operand);
      const int scale = opnd_get_scale(operand);
      if ((base == DR_REG_NULL || reg_is_gpr(base)) &&
          (index == DR_REG_NULL || reg_is_gpr(index)) &&
          (base != DR_REG_NULL || index != DR_REG_NULL)) {
        int64_t displacement = opnd_get_disp(operand);
        if (base != DR_REG_NULL) {
          if (syntax != 1)
            expression += '%';
          expression += ct_register_name(base);
          if (entry.write && instruction.opcode == OP_pop &&
              reg_overlap(base, DR_REG_RSP))
            displacement += size;
        }
        if (index != DR_REG_NULL) {
          if (!expression.empty())
            expression += '+';
          if (syntax != 1)
            expression += '%';
          expression += ct_register_name(index);
          if (scale > 1)
            expression += '*' + std::to_string(scale);
          if (entry.write && instruction.opcode == OP_pop &&
              reg_overlap(index, DR_REG_RSP))
            displacement += size * scale;
        }
        if (displacement) {
          dr_snprintf(formatted.data(), formatted.size(), "%c0x%llx",
                      displacement < 0 ? '-' : '+',
                      static_cast<unsigned long long>(
                          displacement < 0 ? -displacement : displacement));
          expression += formatted.data();
        }
      }
    }
    if (expression.empty()) {
      dr_snprintf(formatted.data(), formatted.size(), "0x%llx",
                  static_cast<unsigned long long>(location));
      expression = formatted.data();
    }
    result += '[' + expression + ']';
  } else if (!recovered) {
    if (syntax != 1)
      result += '%';
    result += ct_register_name(opnd_get_reg(operand));
  }
  result += "=0x";
  static const char hex[] = "0123456789abcdef";
  size_t significant = size;
  while (significant > 1 && bytes[significant - 1] == 0)
    --significant;
  if (bytes[significant - 1] >> 4)
    result += hex[bytes[significant - 1] >> 4];
  result += hex[bytes[significant - 1] & 15];
  for (size_t index = significant - 1; index; --index) {
    result += hex[bytes[index - 1] >> 4];
    result += hex[bytes[index - 1] & 15];
  }
  return result + "\033[0m";
}

static std::string format_flags(const ct_registers &registers, uint mask,
                                bool assignment = false) {
  if (!registers.have_gpr)
    return {};
  const struct {
    uint read;
    unsigned bit;
    const char *name;
  } flags[] = {{EFLAGS_READ_CF, 0, "CF"},  {EFLAGS_READ_PF, 2, "PF"},
               {EFLAGS_READ_AF, 4, "AF"},  {EFLAGS_READ_ZF, 6, "ZF"},
               {EFLAGS_READ_SF, 7, "SF"},  {EFLAGS_READ_TF, 8, "TF"},
               {EFLAGS_READ_IF, 9, "IF"},  {EFLAGS_READ_DF, 10, "DF"},
               {EFLAGS_READ_OF, 11, "OF"}, {EFLAGS_READ_NT, 14, "NT"},
               {EFLAGS_READ_RF, 16, "RF"}, {EFLAGS_READ_AC, 18, "AC"}};
  std::string result;
  for (const auto &flag : flags) {
    if (!(mask & flag.read))
      continue;
    if (!result.empty())
      result += ", ";
    result += flag.name;
    if (assignment)
      result += ':';
    result += (registers.flags & (UINT64_C(1) << flag.bit)) ? "=1" : "=0";
  }
  return result.empty() ? result : "\033[31m" + result + "\033[0m";
}

static void source_assignment_result(Pending &pending,
                                     const ct_registers &after,
                                     ct_values_site *after_values) {
  Visit &visit = *pending.visit;
  Site &site = *pending.site;
  const ct_location_view &source = site.location;
  const char *assignment =
      visit.assignment.empty() ? source.assignment : visit.assignment.c_str();
  const bool expression = !visit.assignment.empty() ||
                          source.expression_kind == CT_EXPRESSION_ASSIGNMENT ||
                          source.expression_kind == CT_EXPRESSION_UPDATE;
  if (expression && site.instruction.conditional)
    visit.expression_result.clear();
  if (!visit.source || visit.function_closing ||
      (expression && !assignment[0]) ||
      (!expression && source.expression_kind != CT_EXPRESSION_NONE) ||
      site.instruction.conditional || site.instruction.call ||
      site.instruction.ret)
    return;
  auto normalized = [](const std::string &text) {
    // Restrict matching to DWARF's simple storage names. Do not transform
    // whitespace inside C character/string literals or evaluate any index.
    if (text.find_first_of("\"'") != std::string::npos)
      return std::string{};
    std::string result;
    for (unsigned char byte : text)
      if (!std::isspace(byte))
        result += static_cast<char>(byte);
    while (result.size() > 2 && result.front() == '(' && result.back() == ')') {
      int depth = 0;
      size_t closing = 0;
      for (; closing < result.size(); ++closing) {
        if (result[closing] == '(')
          ++depth;
        else if (result[closing] == ')' && --depth == 0)
          break;
      }
      if (closing != result.size() - 1)
        break;
      result = result.substr(1, result.size() - 2);
    }
    return result;
  };
  const std::string lhs = normalized(assignment);
  if (expression && lhs.empty())
    return;
  for (opnd_t operand : site.instruction.outputs) {
    const bool memory = opnd_is_memory_reference(operand);
    if (!memory && !opnd_is_reg(operand))
      continue;
    const size_t size = opnd_size_in_bytes(opnd_get_size(operand));
    if (!size || size > 64 * 1024)
      continue;
    ct_registers address = memory ? pending.before : after;
    if (memory && site.instruction.opcode == OP_pop)
      address.gpr[7] += size;
    uint64_t location = 0;
    size_t offset = 0;
    if (!ct_operand_location(operand, address, &location, &offset))
      continue;
    std::vector<unsigned char> bytes(size);
    if (memory ? !read_memory(nullptr, location, bytes.data(), size)
               : !operand_bytes(operand, after, bytes.data(), size))
      continue;
    for (bool before : {false, true}) {
      const ct_registers &registers = before ? pending.before : after;
      ct_values_site *values = before ? site.values : after_values;
      char name[1024]{}, formatted[4096]{};
      if (!ct_values_find_name(values, &registers, read_memory, nullptr, memory,
                               location, offset, size, name, sizeof(name)) ||
          (expression && normalized(name) != lhs) ||
          !ct_values_format_operand(values, &registers, read_memory, nullptr,
                                    memory, location, offset, bytes.data(),
                                    size, formatted, sizeof(formatted)))
        continue;
      const std::string prefix = std::string(name) + '=';
      if (strncmp(formatted, prefix.c_str(), prefix.size()) != 0 ||
          !formatted[prefix.size()])
        continue;
      if (expression) {
        visit.expression_result =
            std::string(assignment) + "=" + (formatted + prefix.size());
        return;
      }
      append_result(visit,
                    std::string(name) + "=" + (formatted + prefix.size()));
      break;
    }
  }
}

static void instruction_results(Pending &pending, const ct_registers &after,
                                ct_values_site *after_values) {
  Site &site = *pending.site;
  Visit &visit = *pending.visit;
  std::unordered_set<std::string> shown;
  for (const auto &entry : state_operands(site.instruction, after, false)) {
    std::string value = format_operand(
        entry, site.instruction, after, pending.before, after_values,
        visit.source ? nullptr : pending.provenance, nullptr,
        visit.source ? nullptr : &pending.decompiled_operands);
    if (shown.insert(unstyled(value.substr(0, value.find('=')))).second)
      append_result(visit, value);
  }
  if (!visit.source && after.have_gpr &&
      (site.instruction.call || site.instruction.branch ||
       site.instruction.ret || site.instruction.syscall)) {
    char text[80];
    dr_snprintf(text, sizeof(text), "\033[31m%sRIP=0x%llx\033[0m",
                syntax == 1 ? "" : "%",
                static_cast<unsigned long long>(after.gpr[16]));
    append_result(visit, text);
  }
}

static std::string register_type_identity(const std::string &name) {
  std::string result = "register:";
  for (unsigned char ch : name)
    result += static_cast<char>(std::toupper(ch));
  return result;
}

static std::string
machine_inputs(Site &site, const ct_registers &registers,
               const ct_provenance &provenance,
               std::vector<OperandType> *input_types = nullptr,
               const std::vector<ct_decompiled_operand> *decompiled = nullptr) {
  const ct_instruction &instruction = site.instruction;
  std::string result;
  std::unordered_set<std::string> shown;
  for (const auto &entry : state_operands(instruction, registers, true)) {
    OperandType display_type;
    const std::string value = format_operand(
        entry, instruction, registers, registers, site.values, &provenance,
        input_types ? &display_type : nullptr, decompiled);
    if (value.empty() ||
        !shown.insert(unstyled(value.substr(0, value.find('=')))).second)
      continue;
    if (input_types && opnd_is_reg(entry.value)) {
      const reg_id_t reg = opnd_get_reg(entry.value);
      const std::string name = ct_register_name(reg);
      std::string label = unstyled(value.substr(0, value.find('=')));
      if (!label.empty() && label.front() == '%')
        label.erase(0, 1);
      if (label == name) {
        display_type.identity = register_type_identity(name);
        if (display_type.type.empty()) {
          const size_t bytes = opnd_size_in_bytes(opnd_get_size(entry.value));
          if ((reg_is_gpr(reg) || reg_is_opmask(reg)) &&
              (bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8))
            display_type.type = "uint" + std::to_string(bytes * 8) + "_t";
        }
      }
    }
    if (!result.empty())
      result += ", ";
    if (input_types && !display_type.identity.empty()) {
      const size_t assignment = value.find('=');
      if (assignment != std::string::npos) {
        display_type.offset = result.size() + assignment + 1;
        input_types->push_back(std::move(display_type));
      }
    }
    result += value;
  }
  const std::string flags =
      format_flags(registers, (instruction.eflags & EFLAGS_READ_ALL) |
                                  EFLAGS_WRITE_TO_READ(instruction.eflags));
  if (!flags.empty()) {
    if (!result.empty())
      result += ", ";
    if (input_types)
      for (const auto &[offset, length] : decompiled_fields(flags)) {
        const std::string field = flags.substr(offset, length);
        const size_t assignment = field.find('=');
        const std::string name = unstyled(field.substr(0, assignment));
        if (assignment != std::string::npos)
          input_types->push_back({result.size() + offset + assignment + 1,
                                  register_type_identity(name), "bool"});
      }
    result += flags;
  }
  if (registers.have_gpr && (instruction.call || instruction.branch ||
                             instruction.ret || instruction.syscall)) {
    char text[80];
    dr_snprintf(text, sizeof(text), "\033[31m%sRIP=0x%llx\033[0m",
                syntax == 1 ? "" : "%",
                static_cast<unsigned long long>(registers.gpr[16]));
    if (!result.empty())
      result += ", ";
    if (input_types)
      input_types->push_back({result.size() + std::string(text).find('=') + 1,
                              register_type_identity("RIP"), "uint64_t"});
    result += text;
  }
  return result;
}

static void capture_abi_call(Visit &visit, Function &callee,
                             const ct_registers &registers) {
  if (!callee.type)
    callee.type = ct_function_prepare(module_values(*callee.module),
                                      reinterpret_cast<uint64_t>(callee.pc));
  size_t count = 0;
  bool variadic = false;
  if (!ct_function_parameters(callee.type, nullptr, 0, &count, &variadic) ||
      count > CT_DECOMPILED_PARAMETER_LIMIT)
    return;
  std::vector<ct_function_parameter> parameters(count);
  if (count && !ct_function_parameters(callee.type, parameters.data(), count,
                                       &count, &variadic))
    return;
  std::string name = callee.name;
  if (name.empty() ||
      (!std::isalpha(static_cast<unsigned char>(name[0])) && name[0] != '_') ||
      !std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return std::isalnum(character) || character == '_';
      })) {
    char label[32];
    dr_snprintf(label, sizeof(label), "L%llx",
                static_cast<unsigned long long>(
                    reinterpret_cast<uintptr_t>(callee.pc)));
    name = label;
  }
  static constexpr reg_id_t general[] = {
      DR_REG_RAX, DR_REG_RDX, DR_REG_RCX, DR_REG_RBX, DR_REG_RSI, DR_REG_RDI,
      DR_REG_RBP, DR_REG_RSP, DR_REG_R8,  DR_REG_R9,  DR_REG_R10, DR_REG_R11,
      DR_REG_R12, DR_REG_R13, DR_REG_R14, DR_REG_R15};
  std::string code = name + "(", values;
  std::vector<OperandType> types;
  for (const auto &parameter : parameters) {
    const size_t bytes = parameter.type.bytes;
    if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
      return;
    unsigned char raw[8]{};
    bool available = false;
    std::string expression, key;
    const bool floating = parameter.type.kind == CT_VALUE_FLOAT;
    if (parameter.on_stack) {
      // Descriptor offsets include the return address. These snapshots are
      // taken before CALL, when that word has not yet been pushed.
      if (parameter.stack_offset < 8)
        return;
      const uint64_t offset = parameter.stack_offset - 8;
      std::string address = "RSP";
      key = "[RSP";
      if (offset) {
        char displacement[32];
        dr_snprintf(displacement, sizeof(displacement), "0x%llx",
                    static_cast<unsigned long long>(offset));
        address += " + " + std::string(displacement);
        key += "+" + std::string(displacement);
      }
      key += "]";
      const std::string type = floating
                                   ? (bytes == 4 ? "float" : "double")
                                   : "uint" + std::to_string(bytes * 8) + "_t";
      expression = "*(" + type + " *)(" + address + ")";
      available = registers.have_gpr &&
                  !(registers.unavailable_gpr & (UINT64_C(1) << 7)) &&
                  offset <= UINT64_MAX - registers.gpr[7] &&
                  read_memory(nullptr, registers.gpr[7] + offset, raw, bytes);
    } else if (floating) {
      if (parameter.reg < 17 || parameter.reg > 24)
        return;
      key = "XMM" + std::to_string(parameter.reg - 17);
      expression =
          "*(" + std::string(bytes == 4 ? "float" : "double") + " *)&" + key;
      available = registers.have_xmm && registers.simd_bytes >= bytes;
      if (available)
        std::memcpy(raw, registers.xmm[parameter.reg - 17], bytes);
    } else {
      if (parameter.reg >= std::size(general))
        return;
      const opnd_size_t width = bytes == 1   ? OPSZ_1
                                : bytes == 2 ? OPSZ_2
                                : bytes == 4 ? OPSZ_4
                                             : OPSZ_8;
      key = ct_register_name(reg_resize_to_opsz(general[parameter.reg], width));
      expression = key;
      available = registers.have_gpr &&
                  !(registers.unavailable_gpr & (UINT64_C(1) << parameter.reg));
      if (available)
        std::memcpy(raw, &registers.gpr[parameter.reg], bytes);
    }
    if (parameter.type.kind == CT_VALUE_POINTER) {
      if (!parameter.type_name[0] ||
          std::strpbrk(parameter.type_name, "?;{}\r\n"))
        return;
      expression = "(" + std::string(parameter.type_name) + ")" + expression;
    }
    if (!values.empty()) {
      code += ", ";
      values += ", ";
    }
    code += expression;
    char formatted[1024]{};
    const std::string value =
        available && ct_values_format_typed(key.c_str(), &parameter.type, raw,
                                            bytes, formatted, sizeof(formatted))
            ? std::string(formatted)
            : key + "=?";
    if (!parameter.on_stack) {
      std::string type = parameter.type_name;
      if (parameter.type.kind == CT_VALUE_SIGNED ||
          parameter.type.kind == CT_VALUE_UNSIGNED)
        type = std::string(parameter.type.kind == CT_VALUE_SIGNED ? "int"
                                                                  : "uint") +
               std::to_string(bytes * 8) + "_t";
      types.push_back({values.size() + key.size() + 1,
                       register_type_identity(key), std::move(type)});
    }
    values += value;
  }
  if (variadic)
    code += parameters.empty() ? "..." : ", ...";
  visit.abi_call_code = code + ");";
  visit.abi_call_values = std::move(values);
  visit.abi_call_types = std::move(types);
}

static void complete_pending(Thread &thread, const ct_registers &after,
                             app_pc observed_pc, bool boundary = false,
                             ct_values_site *observed_values = nullptr) {
  Pending pending = thread.pending;
  if (!pending.site)
    return;
  thread.pending = Pending{};
  Site &site = *pending.site;
  MachineContext &machine = current_machine(thread);
  if (pending.timing_only) {
    // Scope-only records use the actual successor, without reading values or
    // formatting a terminal row. The normal call-stack update still runs in
    // advance() after this completion.
    const bool verified_flow =
        !site.module->code_modified ||
        prepare_decompiled_display(site, ct_instrument_level::perfetto);
    if (machine.trace_body && !pending.timing_source && !site.location.is_plt &&
        verified_flow && site.instruction.branch && !site.instruction.call &&
        !site.instruction.ret) {
      const auto switched =
          site.module->flow_switches.find(site.instruction.pc);
      if (switched != site.module->flow_switches.end()) {
        const auto &region = *switched->second;
        const std::string selector =
            machine.comparison_pc ==
                        site.module->start + region.selector_offset &&
                    !machine.comparison.lhs.empty()
                ? machine.comparison.lhs
                : region.selector_register;
        const std::string name = "switch (" + selector + ") {";
        machine.blocks.push_back({site.shared_from_this(),
                                  site.module->start + region.join_offset,
                                  nullptr, name, switched->second});
        if (observed_pc != site.module->start + region.join_offset)
          begin_recovered_block(machine.blocks.back(), site, machine,
                                pending.before, true, false);
      } else if (const auto found =
                     site.module->flow_regions.find(site.instruction.pc);
                 found != site.module->flow_regions.end() &&
                 observed_pc >= site.module->start &&
                 observed_pc < site.module->end) {
        const auto &region = found->second;
        const bool counted =
            prepare_loop_instructions(site, region, pending.before);
        const auto scope = ct_perfetto_recovered_scope(
            region, observed_pc - site.module->start, -1, counted);
        if (scope.valid && scope.open) {
          const bool body_taken =
              scope.loop ? region.taken_is_body
                         : region.fallthrough_offset == region.join_offset;
          const std::string condition = ct_format_branch_condition(
              site.instruction,
              machine.timing_comparison_next == site.instruction.pc
                  ? &machine.comparison
                  : nullptr,
              body_taken, false);
          std::string initializer;
          if (counted && site.loop_initializer_instruction)
            initializer = ct_format_loop_initializer(
                *site.loop_initializer_instruction, pending.before);
          const std::string opening =
              counted ? "for (" + initializer + "; " + condition + "; " +
                            site.loop_update + ") {"
                      : std::string(scope.loop ? "while (" : "if (") +
                            condition + ") {";
          const std::string name = scope.body ? opening : "else {";
          machine.blocks.push_back(
              {site.shared_from_this(), site.module->start + scope.join,
               scope.loop ? site.module->start + scope.repeat : nullptr, name});
          begin_recovered_block(machine.blocks.back(), site, machine,
                                pending.before, scope.body, counted);
        }
      }
    }
    return;
  }
  const bool assembly =
      pending.visit->first && !pending.visit->source && !pending.visit->summary;
  if (decompile && assembly && site.instruction.call)
    pending.visit->call_deferred = &thread.deferred_call;
  std::string plt_symbol;
  const bool conditional_branch =
      assembly && site.instruction.branch &&
      !ct_format_branch_condition(site.instruction).empty();
  const bool flag_producer = assembly &&
                             (site.instruction.eflags & EFLAGS_WRITE_ALL) &&
                             !site.instruction.call && !site.instruction.ret &&
                             !site.instruction.syscall;
  const bool update_sequence =
      assembly && machine.update_module == site.module &&
      machine.update_next == site.instruction.pc && site.instruction.valid &&
      !site.instruction.call && !site.instruction.ret &&
      !site.instruction.syscall &&
      (!conditional_branch || site.instruction.pc == machine.update_branch);
  bool completed = boundary || observed_pc == site.instruction.next ||
                   site.instruction.branch || site.instruction.call ||
                   site.instruction.ret;
  if (!completed) {
    thread.assembly_arrival_pc = nullptr;
    flush_machine_rows(machine);
    machine.comparison = {};
    close_visit(*pending.visit, "execution left the observed path");
    return;
  }
  thread.arrival_pc = nullptr;
  thread.arrival_outcome = -1;
  thread.assembly_arrival_pc = assembly ? observed_pc : nullptr;
  thread.plt_marker_pc = nullptr;
  thread.annotation_pc = nullptr;
  thread.arrival_annotation = ArrivalAnnotation::None;
  if (site.instruction.call) {
    thread.annotation_pc = observed_pc;
    thread.arrival_annotation = ArrivalAnnotation::Call;
    if (assembly) {
      pending.visit->branch_outcome = -1;
      if (Module *target = module_at(observed_pc)) {
        Site::Mode target_mode = Site::Skip, physical_mode = Site::Skip;
        bool target_plt = false;
        std::vector<Site::Mode> inline_modes;
        const auto cached = current_sites.find(observed_pc);
        if (cached != current_sites.end() && cached->second->prepared) {
          physical_mode = cached->second->physical_mode;
          inline_modes = cached->second->inline_modes;
          target_plt = cached->second->location.is_plt;
          if (target_plt)
            plt_symbol = cached->second->location.plt_symbol;
        } else {
          auto location = std::make_unique<ct_location>();
          ct_analysis_lookup(target->analysis, observed_pc - target->start,
                             location.get());
          filter_modes(*target, *location, target_mode, physical_mode,
                       inline_modes);
          target_plt = location->is_plt;
          if (target_plt)
            plt_symbol = location->plt_symbol;
        }
        if (target_plt) {
          pending.visit->plt_call = true;
          pending.visit->plt_name = plt_symbol;
          pending.visit->plt_target = observed_pc;
          if (!decompile) {
            thread.plt_marker_pc = observed_pc;
            if (plt_symbol.empty()) {
              char label[32];
              dr_snprintf(label, sizeof(label), "L%llx",
                          static_cast<unsigned long long>(
                              reinterpret_cast<uintptr_t>(observed_pc)));
              plt_symbol = label;
            }
          }
        }
        if (decompile && !target_plt) {
          const auto function = current_functions.find(observed_pc);
          if (function != current_functions.end())
            capture_abi_call(*pending.visit, *function->second, pending.before);
        }
        bool recurse = pending.recurse, blocked = pending.blocked;
        target_mode = enter_scope(physical_mode, recurse, blocked);
        for (Site::Mode inline_mode : inline_modes)
          target_mode = enter_scope(inline_mode, recurse, blocked);
        // A completed CALL is blue only if its actual destination is entered.
        // Step-over summaries and skipped targets keep the normal background.
        if (target_plt || target_mode == Site::Into)
          pending.visit->branch_outcome = 1;
      }
    }
  }
  if (assembly && site.instruction.branch && !site.instruction.call) {
    const int outcome =
        ct_observed_branch_outcome(dr_get_current_drcontext(), site.instruction,
                                   pending.before, observed_pc);
    pending.visit->branch_outcome = outcome;
    if (outcome >= 0) {
      thread.arrival_pc = observed_pc;
      thread.arrival_outcome = outcome;
    }
  }
  // Retain only a straight-line condition sequence. Flush before a new flag
  // producer, changed operands, calls, or other externally visible effects.
  if (!update_sequence &&
      (machine.update_module || !assembly || !site.instruction.valid ||
       flag_producer || !site.instruction.outputs.empty() ||
       site.instruction.writes_memory || site.instruction.call ||
       site.instruction.ret || site.instruction.syscall ||
       (site.instruction.branch && !conditional_branch)))
    flush_machine_rows(machine);
  if (update_sequence)
    machine.update_next = observed_pc;
  if (assembly && (site.instruction.opcode == OP_cmp ||
                   site.instruction.opcode == OP_test)) {
    machine.comparison = ct_capture_branch_condition(
        site.instruction, pending.before, site.values, read_memory, nullptr,
        pending.provenance, &pending.decompiled_operands);
    machine.comparison_pc = site.instruction.pc;
  } else if (!assembly || !site.instruction.valid ||
             !site.instruction.outputs.empty() ||
             (site.instruction.eflags & EFLAGS_WRITE_ALL) ||
             site.instruction.call || site.instruction.ret ||
             site.instruction.syscall)
    machine.comparison = {};
  if (pending.provenance) {
    if (pending.provenance != &thread.root_provenance)
      ct_invalidate_provenance_memory(thread.root_provenance, site.instruction,
                                      pending.before);
    for (Call *call : thread.calls)
      if (&call->provenance != pending.provenance)
        ct_invalidate_provenance_memory(call->provenance, site.instruction,
                                        pending.before);
    ct_update_provenance(*pending.provenance, site.instruction, site.values,
                         pending.before, read_memory, nullptr,
                         &pending.decompiled_operands);
  }
  if (!pending.visit->first || pending.visit->summary)
    return;
  if (!decompile && !plt_symbol.empty() &&
      thread.plt_marker_pc == observed_pc) {
    // The completed call proves its actual PLT destination, including an
    // indirect call. Introduce linkage at the caller before printing CALL.
    const std::string prefix =
        pending.visit->before_line.substr(0, pending.visit->code_offset);
    write_line(prefix + "# /* " + plt_symbol + "@plt */\n", prefix.size());
  }
  if (!pending.visit->source)
    pending.visit->values.clear();
  ct_values_site *temporary = nullptr;
  ct_values_site *after_values = observed_values;
  if (!after_values && observed_pc == site.instruction.next)
    after_values = site.next_values;
  if (!after_values) {
    temporary = ct_values_prepare(module_values(*site.module),
                                  reinterpret_cast<uint64_t>(observed_pc));
    after_values = temporary;
  }
  if (pending.visit->source) {
    source_assignment_result(pending, after, after_values);
  } else {
    instruction_results(pending, after, after_values);
    append_result(*pending.visit,
                  format_flags(after,
                               EFLAGS_WRITE_TO_READ(site.instruction.eflags),
                               false));
  }
  ct_values_site_free(temporary);
  const bool returning = site.instruction.ret && !thread.calls.empty() &&
                         !thread.calls.back()->signal_frame;
  BranchClosure closure = BranchClosure::None;
  std::string closing_context;
  if (conditional_branch) {
    closure = machine_branch(machine, site, observed_pc, pending.before,
                             closing_context, *pending.visit);
    flush_machine_rows(machine);
  } else if (assembly && site.instruction.branch) {
    for (auto block = machine.blocks.rbegin(); block != machine.blocks.rend();
         ++block)
      if (block->switch_region && block->last->module == site.module &&
          block->join == observed_pc) {
        machine_annotation(machine, site, "break;");
        break;
      }
  }
  if (!pending.visit->source && !returning) {
    if ((decompile && update_sequence && !conditional_branch) ||
        (!pending.visit->decompile_machine &&
         ((update_sequence && !conditional_branch) || flag_producer ||
          (!machine.condition_rows.empty() && !conditional_branch)))) {
      close_visit(*pending.visit, nullptr, &machine.condition_rows);
      if (machine.condition_rows.size() >= condition_row_limit)
        flush_machine_rows(machine);
    } else {
      close_visit(*pending.visit);
    }
  }
  if (closure == BranchClosure::Condition) {
    machine_annotation(machine, site, closing_context, {}, nullptr, '}');
  } else if (closure != BranchClosure::None) {
    machine_annotation(machine, site, "}", closing_context);
    if (closure == BranchClosure::Else)
      machine_annotation(machine, site, "else {");
  }
}

static std::string block_source(const ct_source_block &block, bool opening) {
  const std::string text = opening ? block.opening : block.closing;
  const size_t begin =
      opening ? block.opening_highlight_begin : block.closing_highlight_begin;
  const size_t end =
      opening ? block.opening_highlight_end : block.closing_highlight_end;
  if (begin >= end || end > text.size())
    return "\033[32m" + text + "\033[0m";
  return "\033[32m" + text.substr(0, begin) + "\033[42;97m" +
         text.substr(begin, end - begin) + "\033[0m\033[32m" +
         text.substr(end) + "\033[0m";
}

static void close_blocks(std::vector<std::unique_ptr<SourceBlock>> &blocks,
                         size_t keep, const char *incomplete = nullptr,
                         Call *frame = nullptr) {
  while (blocks.size() > keep) {
    SourceBlock &block = *blocks.back();
    if (frame && frame->returning.first && block.header.first)
      frame->block_exits.push_back(std::move(block.header));
    else
      close_visit(block.header);
    if (source_available(*block.entry) &&
        block.description.closing_standalone) {
      Visit &result = block.result;
      const auto last = result.last ? result.last : block.last;
      result.first = last;
      result.source = true;
      result.have_before = false;
      result.comment_offset = std::string::npos;
      result.closing_context = block.description.opening_context;
      result.before_line =
          location_prefix(dr_get_current_drcontext(), last->instruction.pc,
                          *block.entry->module, block.entry->location,
                          block.entry->location.function,
                          block.description.closing_line) +
          block_source(block.description, false);
      if (incomplete) {
        result.expression_result.clear();
        result.results.clear();
      }
      if (frame && frame->returning.first)
        frame->block_exits.push_back(std::move(result));
      else
        close_visit(result, incomplete);
    }
    blocks.pop_back();
  }
}

static void
flush_headers_before_body(std::vector<std::unique_ptr<SourceBlock>> &blocks,
                          const Site &site) {
  for (size_t index = 0; index < blocks.size(); ++index) {
    SourceBlock &block = *blocks[index];
    if (!block.header.first ||
        block.description.start_line == site.location.line ||
        block.entry->module != site.module ||
        strcmp(block.entry->location.file, site.location.file) != 0 ||
        strcmp(block.entry->location.function, site.location.function) != 0)
      continue;
    bool inside_expression = false;
    for (size_t nested = index + 1; nested < blocks.size(); ++nested)
      inside_expression |= blocks[nested]->description.kind ==
                           CT_SOURCE_BLOCK_STATEMENT_EXPRESSION;
    if (!inside_expression)
      close_visit(block.header);
  }
}

static bool return_type_evidence(Site &site, const Call *frame,
                                 ct_value_type &type, bool &is_void,
                                 char *spelling, size_t capacity) {
  type = {};
  is_void = false;
  if (capacity)
    spelling[0] = 0;
  bool known = frame && frame->function &&
               frame->function->module == site.module &&
               ct_function_return_type(frame->function->type, &type, &is_void,
                                       spelling, capacity);
  if (!known && frame && frame->function &&
      frame->function->module == site.module &&
      ct_function_return_unsupported(frame->function->type))
    return {};
  if (!known && frame && frame->function &&
      frame->function->module == site.module &&
      frame->source_function == frame->function && frame->source_call_result &&
      frame->source_call_result->return_type.kind != CT_VALUE_UNKNOWN) {
    type = frame->source_call_result->return_type;
    known = true;
    if (type.kind == CT_VALUE_SIGNED || type.kind == CT_VALUE_UNSIGNED)
      std::snprintf(spelling, capacity, "%sint%u_t",
                    type.kind == CT_VALUE_SIGNED ? "" : "u",
                    static_cast<unsigned>(type.bytes * 8));
    else if (type.kind == CT_VALUE_POINTER)
      std::snprintf(spelling, capacity, "void *");
    else if (type.kind == CT_VALUE_BOOLEAN)
      std::snprintf(spelling, capacity, "bool");
    else if (type.kind == CT_VALUE_FLOAT &&
             (type.bytes == 4 || type.bytes == 8))
      std::snprintf(spelling, capacity, "%s",
                    type.bytes == 4 ? "float" : "double");
  }
  if (!known && frame && frame->function &&
      frame->function->module == site.module && !frame->declaration.empty() &&
      !frame->decompiled_declaration)
    return {}; // Known but unsupported return ABIs must not become RAX guesses.
  const auto *function = site.decompiled_variables.get();
  if (!known && function && function->return_known) {
    const auto &instruction = function->instruction;
    unsigned char bytes[15];
    if (instruction.offset ==
            uint64_t(site.instruction.pc - site.module->start) &&
        instruction.size && instruction.size <= sizeof(bytes) &&
        ct_userspace_patch_read_original(site.instruction.pc, instruction.size,
                                         bytes) &&
        std::memcmp(bytes, instruction.bytes, instruction.size) == 0) {
      known = true;
      type = function->return_type;
      is_void = function->return_void;
      std::snprintf(spelling, capacity, "%s", function->return_type_name);
    }
  }
  if (!known && function && function->return_unsupported)
    return {};
  if (!known && frame && frame->return_pc) {
    Module *caller = module_at(frame->return_pc);
    app_pc pc = frame->return_pc;
    void *context = dr_get_current_drcontext();
    for (size_t count = 0; caller && count < return_use_instruction_limit;
         ++count) {
      if (pc < caller->start || pc >= caller->end)
        break;
      unsigned char bytes[15]{};
      const size_t available =
          std::min(sizeof(bytes), size_t(caller->end - pc));
      const size_t copied = available;
      if (!ct_userspace_patch_read_original(pc, copied, bytes) || !copied)
        break;
      instr_t instruction;
      instr_init(context, &instruction);
      byte *end = decode_from_copy(context, bytes, pc, &instruction);
      if (!end || end <= bytes || end > bytes + copied ||
          !instr_valid(&instruction) || instr_is_cti(&instruction) ||
          instr_is_syscall(&instruction) || instr_is_predicated(&instruction)) {
        instr_free(context, &instruction);
        break;
      }
      const int opcode = instr_get_opcode(&instruction);
      bool overwritten = false, invalid = false;
      size_t used = 0;
      // XOR/SUB of a register with itself does not consume its previous value.
      const bool zero = (opcode == OP_xor || opcode == OP_sub) &&
                        instr_num_srcs(&instruction) == 2 &&
                        opnd_same(instr_get_src(&instruction, 0),
                                  instr_get_src(&instruction, 1));
      for (int index = 0; index < instr_num_srcs(&instruction); ++index) {
        const opnd_t operand = instr_get_src(&instruction, index);
        // A floating-point result can be consumed before an unrelated RAX
        // read. Do not reinterpret that later read as an integer return ABI.
        if (opnd_is_reg(operand)) {
          const reg_id_t reg = opnd_get_reg(operand);
          invalid |= reg_is_fp(reg) ||
                     (reg_is_simd(reg) && reg_overlap(reg, DR_REG_XMM0));
        }
        if (opnd_is_reg(operand) && reg_is_gpr(opnd_get_reg(operand)) &&
            reg_overlap(opnd_get_reg(operand), DR_REG_RAX) && !zero) {
          invalid |= opnd_get_reg(operand) == DR_REG_AH;
          used = std::max(used,
                          size_t(opnd_size_in_bytes(opnd_get_size(operand))));
        }
        if (opnd_is_base_disp(operand))
          for (reg_id_t reg : {opnd_get_base(operand), opnd_get_index(operand)})
            if (reg != DR_REG_NULL && reg_overlap(reg, DR_REG_RAX))
              used =
                  std::max(used, size_t(opnd_size_in_bytes(reg_get_size(reg))));
      }
      for (int index = 0; index < instr_num_dsts(&instruction); ++index) {
        const opnd_t operand = instr_get_dst(&instruction, index);
        overwritten |= opnd_is_reg(operand) &&
                       reg_overlap(opnd_get_reg(operand), DR_REG_RAX);
        if (opnd_is_base_disp(operand))
          for (reg_id_t reg : {opnd_get_base(operand), opnd_get_index(operand)})
            if (reg != DR_REG_NULL && reg_overlap(reg, DR_REG_RAX))
              used =
                  std::max(used, size_t(opnd_size_in_bytes(reg_get_size(reg))));
      }
      pc += end - bytes;
      instr_free(context, &instruction);
      if (invalid)
        break;
      if (used == 1 || used == 2 || used == 4 || used == 8) {
        type.bytes = used;
        known = true;
        break;
      }
      if (overwritten)
        break;
    }
  }
  return known;
}

static std::string function_result(const std::shared_ptr<Function> &function,
                                   const ct_registers &registers,
                                   bool allow_raw,
                                   bool allow_type_cast = true) {
  char value[value_capacity]{};
  if (function) {
    ct_function_return(function->type, &registers, read_memory, nullptr, value,
                       sizeof(value));
    if (value[0]) {
      char names[value_capacity]{};
      ct_function_argument_names(function->type, names, sizeof(names));
      char type[1024];
      if (allow_type_cast && !function->function_type_reported &&
          ct_function_pointer_type(function->type, type, sizeof(type))) {
        function->function_type_reported = true;
        const std::string result = "((" + std::string(type) + ")" +
                                   function->name + ")(" + names + ")=" + value;
        return no_style ? result : "\033[1m" + result + "\033[22m";
      }
      return function->name + "(" + names + ")=" + value;
    }
  }
  if (!allow_raw || !registers.have_gpr)
    return {};
  dr_snprintf(value, sizeof(value), "\033[31m%sRAX=0x%llx\033[0m",
              syntax == 1 ? "" : "%",
              static_cast<unsigned long long>(registers.gpr[0]));
  return value;
}

static std::string
typed_source_call_result(const std::shared_ptr<Function> &function,
                         const std::string &expression, const char *callee,
                         std::string result) {
  if (!function || function->function_type_reported || result.empty() ||
      expression.empty() || !callee || !callee[0] ||
      result.compare(0, expression.size(), expression) != 0 ||
      result.size() <= expression.size() || result[expression.size()] != '=')
    return result;
  const size_t first = expression.find_first_not_of(' ');
  const size_t opening = expression.find('(', first);
  if (first == std::string::npos || opening == std::string::npos)
    return result;
  size_t end = opening;
  while (end > first &&
         std::isspace(static_cast<unsigned char>(expression[end - 1])))
    --end;
  const std::string name = expression.substr(first, end - first);
  if (name.empty() ||
      (!std::isalpha(static_cast<unsigned char>(name[0])) && name[0] != '_' &&
       name.compare(0, 2, "::") != 0) ||
      !std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return std::isalnum(character) || character == '_' || character == ':';
      }))
    return result;
  const size_t qualifier = name.rfind("::");
  const std::string unqualified =
      qualifier == std::string::npos ? name : name.substr(qualifier + 2);
  // A macro's source spelling is not a function designator. Keep its own
  // result label rather than casting the macro name as if it were callable.
  if (name != callee && unqualified != callee && name != function->name)
    return result;
  char type[1024];
  if (ct_function_pointer_type(function->type, type, sizeof(type))) {
    result.replace(first, end - first,
                   "((" + std::string(type) + ")" + name + ")");
    function->function_type_reported = true;
    if (!no_style) {
      result.insert(first, "\033[1m");
      result += "\033[22m";
    }
  }
  return result;
}

static void leave_call(Thread &thread, const ct_registers &registers,
                       bool returned) {
  Call *call = thread.calls.back();
  end_trace_function(call->machine, thread.trace_timestamp,
                     returned ? "returned" : "unwind");
  if (call->signal_frame && !returned) {
    close_trace_syscall(thread, "unwind");
    thread.syscall = {};
    ct_perfetto_end(call->trace_signal_context, thread.trace_timestamp,
                    "unwind");
    call->trace_signal_context = 0;
  }
  if (call->timing_only && !call->parent && !call->deferred_call.first &&
      !call->visit.first && !call->summary.first) {
    if (call->signal_frame && returned) {
      // Keep the interrupted-context marker until rt_sigreturn, just as the
      // full tracing path does after the handler's RET.
      call->function = nullptr;
      call->entry_pc = nullptr;
      call->scope = TraceScope{};
      call->within = false;
      call->within_inline = false;
      call->signal_handler_active = false;
      call->entry_sp = registers.gpr[7];
      call->frame_base_restored = false;
      call->machine = MachineContext{};
      update_within(thread);
      return;
    }
    thread.calls.pop_back();
    current_machine(thread).comparison = {};
    // A lightweight callee can still have an observed assembly caller. Its
    // volatile-register provenance cannot survive a skipped body.
    if (!current_machine(thread).timing_only) {
      auto &provenance = current_provenance(thread);
      for (size_t index = 0; index < provenance.registers.size(); ++index) {
        const bool callee_saved =
            index == 3 || index == 6 || (index >= 12 && index <= 15);
        const int source = provenance.registers[index].source_register;
        const bool source_saved = source < 0 || source == 3 || source == 6 ||
                                  (source >= 12 && source <= 15);
        if (!returned || !callee_saved || !source_saved)
          provenance.registers[index] = {};
      }
    }
    delete call;
    update_within(thread);
    return;
  }
  if (returned && call->deferred_call.first && call->deferred_target) {
    // Use the original target's contract even when it tail-calls another
    // function. The retained row belongs to the caller, not the callee's PC.
    Site &target = *call->deferred_target;
    auto &function = call->deferred_function;
    // A quiet gate can observe the callee after its prologue, without an
    // entry wrapper. Use its already recovered enclosing range to locate the
    // original function contract, even if the frame has since tail-called.
    app_pc target_entry = target.instruction.pc;
    const uint64_t target_offset = target_entry - target.module->start;
    auto range = target.module->flow_ranges.upper_bound(target_offset);
    if (range != target.module->flow_ranges.begin()) {
      --range;
      if (target_offset < range->second)
        target_entry = target.module->start + range->first;
    }
    if (!function || function->module != target.module ||
        function->pc != target_entry) {
      const auto entry = current_functions.find(target_entry);
      function = entry != current_functions.end() &&
                         entry->second->module == target.module
                     ? entry->second
                     : nullptr;
    }
    if (function && !function->type)
      function->type =
          ct_function_prepare(module_values(*function->module),
                              reinterpret_cast<uint64_t>(function->pc));
    const auto [name, expression] =
        deferred_call_expression(*call, &target.location);
    bool return_void = false;
    char value[value_capacity]{};
    if (function && call->deferred_mode != Site::Skip)
      ct_function_return(function->type, &registers, read_memory, nullptr,
                         value, sizeof(value));
    if (call->deferred_mode == Site::Skip) {
      ct_value_type type{};
      char spelling[512]{};
      bool is_void = false;
      return_void = function &&
                    ct_function_return_type(function->type, &type, &is_void,
                                            spelling, sizeof(spelling)) &&
                    is_void;
    } else if (!value[0]) {
      ct_value_type type{};
      bool is_void = false;
      char spelling[512]{};
      Call evidence;
      evidence.function = function;
      evidence.return_pc = call->return_pc;
      evidence.source_function = call->source_function;
      evidence.source_call_result = call->source_call_result;
      if (call->function == function) {
        evidence.declaration = call->declaration;
        evidence.decompiled_declaration = call->decompiled_declaration;
      }
      bool known = return_type_evidence(target, &evidence, type, is_void,
                                        spelling, sizeof(spelling));
      if (!known &&
          !(function && ct_function_return_unsupported(function->type)) &&
          !target.decompiled_variables) {
        auto metadata = std::make_unique<ct_decompiled_variables>();
        if (ct_analysis_decompile_variables(
                target.module->analysis,
                target.instruction.pc - target.module->start, CT_DECOMPILE_FULL,
                metadata.get()) &&
            decompiled_function_matches(target, metadata->function_offset,
                                        CT_DECOMPILE_FULL))
          target.decompiled_variables =
              std::make_shared<ct_decompiled_variables_record>(*metadata);
        known = return_type_evidence(target, &evidence, type, is_void, spelling,
                                     sizeof(spelling));
      }
      if (known && !is_void) {
        const unsigned char *bytes = nullptr;
        if (type.kind == CT_VALUE_FLOAT) {
          if (registers.have_xmm && type.bytes <= registers.simd_bytes)
            bytes = registers.xmm[0];
        } else if (registers.have_gpr && !(registers.unavailable_gpr & 1) &&
                   type.bytes <= sizeof(registers.gpr[0])) {
          bytes = reinterpret_cast<const unsigned char *>(&registers.gpr[0]);
        }
        char formatted[value_capacity]{};
        if (bytes && ct_values_format_typed("value", &type, bytes, type.bytes,
                                            formatted, sizeof(formatted)))
          std::snprintf(value, sizeof(value), "%s", formatted + 6);
        else
          std::snprintf(value, sizeof(value), "?");
      }
      return_void = is_void;
    }
    if (!expression.empty() && !return_void) {
      Visit &visit = call->deferred_call;
      const auto *statement = visit.first->decompiled.get();
      std::string assignment;
      if (statement && statement->declaration_id &&
          statement->declaration_name[0]) {
        const size_t end = visit.comment_offset < visit.before_line.size()
                               ? visit.comment_offset - 1
                               : visit.before_line.size();
        const std::string code = unstyled(visit.before_line.substr(
            visit.code_offset, end - visit.code_offset));
        const size_t equals = code.find('=');
        if (equals != std::string::npos &&
            code.find(';', equals) != std::string::npos) {
          std::string lhs = code.substr(0, equals);
          std::string rhs =
              code.substr(equals + 1, code.rfind(';') - equals - 1);
          const auto trim = [](std::string &part) {
            const size_t first = part.find_first_not_of(" \t\r\n");
            part = first == std::string::npos
                       ? std::string{}
                       : part.substr(first, part.find_last_not_of(" \t\r\n") -
                                                first + 1);
          };
          trim(lhs);
          trim(rhs);
          while (rhs != expression && rhs.size() > 2 && rhs.front() == '(' &&
                 rhs.back() == ')') {
            rhs = rhs.substr(1, rhs.size() - 2);
            trim(rhs);
          }
          if (lhs == statement->declaration_name && rhs == expression)
            assignment = std::move(lhs);
        }
      }
      if (!assignment.empty()) {
        // A named CALL output is observed at the caller continuation, after
        // the return ABI has produced it. Do not read its stale pre-call slot
        // or evaluate a compound C expression using the callee's return value.
        std::string observed = assignment + "=?";
        auto metadata = std::make_unique<ct_decompiled_variables>();
        Module &caller = *visit.first->module;
        if (call->return_pc >= caller.start && call->return_pc < caller.end &&
            ct_analysis_decompile_variables(
                caller.analysis, call->return_pc - caller.start,
                CT_DECOMPILE_FULL, metadata.get())) {
          for (uint32_t index = 0; index < metadata->count; ++index) {
            const auto &variable = metadata->entries[index];
            if (variable.id != statement->declaration_id ||
                assignment != variable.name ||
                variable.kind != CT_DECOMPILED_REGISTER || !variable.size ||
                variable.size > 8)
              continue;
            reg_id_t reg = DR_REG_NULL;
            for (int candidate = DR_REG_RAX;
                 candidate <= DR_REG_LAST_VALID_ENUM; ++candidate)
              if (std::strcmp(variable.register_name,
                              get_register_name(
                                  static_cast<reg_id_t>(candidate))) == 0) {
                reg = static_cast<reg_id_t>(candidate);
                break;
              }
            unsigned char bytes[8]{};
            char formatted[value_capacity]{};
            if (reg != DR_REG_NULL &&
                operand_bytes(opnd_create_reg(reg), registers, bytes,
                              variable.size) &&
                ct_values_format_typed(assignment.c_str(), &variable.type,
                                       bytes, variable.size, formatted,
                                       sizeof(formatted)))
              observed = formatted;
            break;
          }
        }
        visit.returned_value = std::move(observed);
      } else {
        std::string result =
            expression + "=" +
            (call->deferred_mode == Site::Skip || !value[0] ? "?" : value);
        if (call->deferred_mode == Site::Over)
          result = typed_source_call_result(function, expression, name.c_str(),
                                            std::move(result));
        visit.returned_value = std::move(result);
      }
    }
  }
  close_deferred_call(*call);
  flush_machine_rows(call->machine);
  defer_return(thread, call->visit);
  const bool source_return = call->returning.first != nullptr;
  bool return_announced = false;
  if (call->returning.first) {
    if (returned && call->returning_function &&
        source_available(*call->returning.first)) {
      call->returning.expression_result = function_result(
          call->returning_function, registers, false,
          call->returning.declared_function != call->returning_function);
      return_announced = !call->returning.expression_result.empty();
    }
    close_visit(call->returning, returned ? nullptr : "stack unwind");
    for (auto &exit : call->block_exits)
      close_visit(exit, returned ? nullptr : "stack unwind");
    call->block_exits.clear();
    if (call->visit.header_continuation)
      close_visit(call->visit, returned ? nullptr : "stack unwind");
    close_blocks(call->blocks, 0, returned ? nullptr : "stack unwind");
    for (const auto &line : call->return_lines)
      write_line(line.text, std::string::npos, nullptr, -1, std::string::npos,
                 nullptr, -1, nullptr, std::string::npos, 0,
                 line.closing_context);
    call->return_lines.clear();
  }
  std::string result;
  if (returned &&
      ((call->summary.first && call->summary_function == call->function) ||
       (call->parent && call->parent->first && !call->parent->summary &&
        !call->source_step_over &&
        (!call->parent->source ||
         call->parent->first->location.expression_kind ==
             CT_EXPRESSION_NONE)))) {
    const bool source_assignment =
        call->parent && call->parent->source &&
        call->parent->first->location.expression_kind ==
            CT_EXPRESSION_ASSIGNMENT;
    result = function_result(call->function, registers,
                             !call->parent || !call->parent->source,
                             !source_assignment);
  }
  if (call->summary.first && returned) {
    call->summary.values.clear();
    append_result(call->summary,
                  !result.empty() && call->summary_function == call->function
                      ? result
                      : function_result(call->summary_function, registers,
                                        !call->summary.source));
  }
  if (returned && call->visit.first && !call->visit.source &&
      call->visit.last->instruction.ret && !call->visit.return_void) {
    if (decompile) {
      ct_value_type type{};
      bool is_void = false;
      char spelling[512]{};
      if (return_type_evidence(*call->visit.last, call, type, is_void, spelling,
                               sizeof(spelling)) &&
          !is_void &&
          (type.bytes == 1 || type.bytes == 2 || type.bytes == 4 ||
           type.bytes == 8)) {
        const unsigned char *bytes = nullptr;
        if (type.kind == CT_VALUE_FLOAT && registers.have_xmm &&
            registers.simd_bytes >= type.bytes)
          bytes = registers.xmm[0];
        else if (type.kind != CT_VALUE_FLOAT && registers.have_gpr &&
                 !(registers.unavailable_gpr & 1))
          bytes = reinterpret_cast<const unsigned char *>(&registers.gpr[0]);
        char value[1024]{};
        if (bytes && ct_values_format_typed("value", &type, bytes, type.bytes,
                                            value, sizeof(value))) {
          std::string invocation = call->invocation;
          if (invocation.empty() && call->function)
            invocation = call->function->name + "(...)";
          if (!invocation.empty()) {
            call->visit.returned_value = invocation + "=" + (value + 6);
            return_announced = true;
          }
        }
      }
    } else {
      append_result(call->visit,
                    function_result(call->function, registers, true));
    }
  }
  if (call->parent && call->parent->source && call->visit.source)
    call->visit.expression_result.clear();
  if (returned && !source_return && call->visit.first &&
      call->visit.function_closing && !call->visit.inlined &&
      call->visit.last->instruction.ret && source_available(*call->visit.first))
    call->visit.expression_result =
        function_result(call->function, registers, false, false);
  close_visit(call->visit, returned ? nullptr : "stack unwind");
  flush_decompiled_rows(call->machine);
  close_plt(call->machine, call->visit);
  close_machine_blocks(call->machine);
  close_blocks(call->blocks, 0, returned ? nullptr : "stack unwind");
  close_assembly_function(*call);
  close_visit(call->summary, returned ? nullptr : "stack unwind");
  for (auto entry = call->tail_summaries.rbegin();
       entry != call->tail_summaries.rend(); ++entry) {
    if (returned) {
      if (entry->visit.summary) {
        entry->visit.values.clear();
        append_result(entry->visit, function_result(entry->function, registers,
                                                    !entry->visit.source));
      } else {
        entry->visit.expression_result =
            function_result(entry->function, registers, false,
                            entry->visit.declared_function != entry->function);
      }
    }
    close_visit(entry->visit, returned ? nullptr : "stack unwind");
  }
  if (call->parent && call->parent->first && !call->parent->summary) {
    if (returned) {
      Visit &parent = *call->parent;
      const ct_location_view &location = parent.first->location;
      const auto same_call_expression = [&](const char *expression) {
        size_t begin = 0, end = std::strlen(location.expression);
        const size_t length = std::strlen(expression);
        for (;;) {
          while (begin < end && std::isspace(static_cast<unsigned char>(
                                    location.expression[begin])))
            ++begin;
          while (end > begin && std::isspace(static_cast<unsigned char>(
                                    location.expression[end - 1])))
            --end;
          if (end - begin == length && std::strncmp(location.expression + begin,
                                                    expression, length) == 0)
            return true;
          // Clang identifies the full expression as a call. Ignore outer
          // grouping when matching that call, but not its nested arguments.
          if (end - begin < 2 || location.expression[begin] != '(' ||
              location.expression[end - 1] != ')')
            return false;
          ++begin;
          --end;
        }
      };
      const bool call_assignment =
          parent.source && call->source_call_result &&
          location.expression_kind == CT_EXPRESSION_ASSIGNMENT &&
          location.expression_is_call && location.assignment[0] &&
          same_call_expression(call->source_call_result->text) &&
          source_available(*parent.first);
      bool expression_call =
          parent.source && location.expression_kind == CT_EXPRESSION_CALL &&
          location.expression_is_call && location.expression_callee[0] &&
          call->function && source_available(*parent.first) &&
          !call->source_call_ambiguous &&
          (!call->source_call_result ||
           same_call_expression(call->source_call_result->text));
      bool source_return = false;
      if (expression_call) {
        auto callee_storage = std::make_unique<ct_location>();
        ct_location &callee = *callee_storage;
        ct_analysis_lookup(call->function->module->analysis,
                           call->function->pc - call->function->module->start,
                           &callee);
        expression_call =
            strcmp(callee.symbol, location.expression_callee) == 0;
        for (size_t offset = 0;
             !expression_call && offset < callee.aliases_size;) {
          const char *alias = callee.aliases + offset;
          expression_call = strcmp(alias, location.expression_callee) == 0;
          offset += strlen(alias) + 1;
        }
        source_return = expression_call && !callee.function_id;
      }
      if (expression_call) {
        if (return_announced && parent.provisional)
          parent.suppress_call_completion = true;
        char value[value_capacity]{};
        if (call->source_skipped)
          std::snprintf(value, sizeof(value), "?");
        else
          ct_function_return(call->function->type, &registers, read_memory,
                             nullptr, value, sizeof(value));
        if (value[0])
          parent.expression_result =
              std::string(location.expression) + "=" + value;
        else if (source_return) {
          // A verified call-site declaration can supply the scalar SysV ABI
          // even when the called library has no function DWARF. Use the actual
          // return registers; never label an untyped RAX value as a C result.
          const ct_value_type &type = location.expression_return_type;
          const unsigned char *bytes = nullptr;
          if (type.kind == CT_VALUE_FLOAT) {
            if (registers.have_xmm && type.bytes <= registers.simd_bytes)
              bytes = registers.xmm[0];
          } else if (registers.have_gpr && !(registers.unavailable_gpr & 1)) {
            bytes = reinterpret_cast<const unsigned char *>(&registers.gpr[0]);
          }
          if (bytes && ct_values_format_typed(location.expression, &type, bytes,
                                              type.bytes, value, sizeof(value)))
            parent.expression_result = value;
        }
        if (call->source_step_over) {
          const char *callee = call->source_call_result &&
                                       call->source_call_result->display_name[0]
                                   ? call->source_call_result->display_name
                                   : location.expression_callee;
          parent.expression_result = typed_source_call_result(
              call->function, location.expression, callee,
              std::move(parent.expression_result));
        }
      } else if (parent.source && !call_assignment &&
                 (call->source_step_over || call->source_skipped) &&
                 call->source_function && source_available(*parent.first) &&
                 (call->source_call_result || call->source_call_ambiguous ||
                  location.expression_kind != CT_EXPRESSION_CALL)) {
        std::string observed;
        if (call->source_call_result && call->source_call_site &&
            source_available(*call->source_call_site)) {
          const auto &expression = *call->source_call_result;
          char value[value_capacity]{};
          if (call->source_skipped)
            std::snprintf(value, sizeof(value), "?");
          else
            ct_function_return(call->source_function->type, &registers,
                               read_memory, nullptr, value, sizeof(value));
          if (value[0]) {
            observed = std::string(expression.text) + "=" + value;
          } else {
            const auto &type = expression.return_type;
            const unsigned char *bytes = nullptr;
            if (type.kind == CT_VALUE_FLOAT) {
              if (registers.have_xmm && type.bytes <= registers.simd_bytes)
                bytes = registers.xmm[0];
            } else if (registers.have_gpr && !(registers.unavailable_gpr & 1)) {
              bytes =
                  reinterpret_cast<const unsigned char *>(&registers.gpr[0]);
            }
            if (bytes &&
                ct_values_format_typed(expression.text, &type, bytes,
                                       type.bytes, value, sizeof(value)))
              observed = value;
          }
          if (call->source_step_over)
            observed = typed_source_call_result(
                call->source_function, expression.text,
                expression.display_name[0] ? expression.display_name
                                           : expression.callee,
                std::move(observed));
        } else {
          observed =
              call->source_skipped
                  ? call->source_function->name + "(...)=?"
                  : function_result(call->source_function, registers, false);
        }
        if (!observed.empty()) {
          if (!parent.call_results.empty())
            parent.call_results += ", ";
          parent.call_results += observed;
        }
      } else if (!parent.source ||
                 location.expression_kind == CT_EXPRESSION_NONE) {
        append_result(parent, result);
      }
      if (call_assignment) {
        // An optimized assignment may use the returned register directly,
        // with no following MOV. Discard intermediate argument temporaries;
        // only the caller's post-return DWARF storage can prove the result.
        parent.expression_result.clear();
        const auto &type = call->source_call_result->return_type;
        if (type.kind != CT_VALUE_UNKNOWN && type.bytes && type.bytes <= 8) {
          ct_registers caller = registers;
          caller.gpr[16] = reinterpret_cast<uint64_t>(call->return_pc);
          caller.unavailable_gpr = 0;
          auto *values = ct_values_prepare(module_values(*parent.first->module),
                                           caller.gpr[16]);
          const unsigned reg = type.kind == CT_VALUE_FLOAT ? 17 : 0;
          char name[1024]{}, value[value_capacity]{};
          if (ct_values_find_name(values, &caller, read_memory, nullptr, false,
                                  reg, 0, type.bytes, name, sizeof(name)) &&
              std::strcmp(name, location.assignment) == 0 &&
              ct_values_read_operand(values, &caller, read_memory, nullptr,
                                     false, reg, 0, type.bytes, value,
                                     sizeof(value)))
            parent.expression_result = value;
          ct_values_site_free(values);
        }
      }
      if (!call->parent->source)
        close_visit(*call->parent);
      else if (call->source_call_result)
        parent.completed_source_calls.insert(call->source_call_result->id);
    } else {
      close_visit(*call->parent, "call did not return normally");
    }
  }
  if (call->signal_frame && returned) {
    // The handler's actual RET ends its tracing scope. Keep only the signal
    // frame marker until rt_sigreturn restores the interrupted call stack.
    call->function = nullptr;
    call->entry_pc = nullptr;
    call->arguments.clear();
    call->scope = TraceScope{};
    call->within = false;
    call->within_inline = false;
    call->signal_handler_active = false;
    call->entry_sp = registers.gpr[7];
    call->frame_base_restored = false;
    call->returning_function = nullptr;
    call->returning_arguments.clear();
    call->summary_function = nullptr;
    call->summary_arguments.clear();
    call->tail_summaries.clear();
    call->provenance = ct_provenance{};
    call->machine = MachineContext{};
    update_within(thread);
    return;
  }
  thread.calls.pop_back();
  current_machine(thread).comparison = {};
  ct_provenance &caller_provenance = current_provenance(thread);
  for (size_t index = 0; index < caller_provenance.registers.size(); ++index) {
    const bool callee_saved =
        index == 3 || index == 6 || (index >= 12 && index <= 15);
    const int source = caller_provenance.registers[index].source_register;
    const bool source_saved = source < 0 || source == 3 || source == 6 ||
                              (source >= 12 && source <= 15);
    if (!returned || !callee_saved || !source_saved)
      caller_provenance.registers[index] = {};
  }
  delete call;
  update_within(thread);
}

static bool startup_owns_instruction(const Call &frame, const Site &site) {
  if (!frame.startup_entry || !frame.function ||
      frame.function->module != site.module)
    return false;
  const Module &module = *site.module;
  if (!module.active || site.instruction.pc < module.start ||
      site.instruction.pc >= module.end)
    return false;
  // Exact entry starts in DR with CALL/RET boundaries armed. Until this
  // frame itself enters native code, its top-frame control history supplies
  // ownership even when a stripped entry has no static function extent.
  if (frame.startup_controlled)
    return true;
  const auto entry = uint64_t(frame.function->pc - module.start);
  auto range = module.flow_ranges.upper_bound(entry);
  if (range == module.flow_ranges.begin())
    return false;
  --range;
  const auto pc = uint64_t(site.instruction.pc - module.start);
  return entry < range->second && pc >= range->first && pc < range->second;
}

static void advance(Thread &thread, const ct_registers &registers, app_pc pc,
                    ct_values_site *values = nullptr) {
  Pending previous = thread.pending;
  ct_registers after = registers;
  if (!thread.calls.empty()) {
    Call &frame = *thread.calls.back();
    if (previous.site) {
      const ct_instruction &instruction = previous.site->instruction;
      if (instruction.opcode == OP_leave ||
          (instruction.opcode == OP_pop &&
           std::any_of(instruction.outputs.begin(), instruction.outputs.end(),
                       [](opnd_t operand) {
                         return opnd_is_reg(operand) &&
                                reg_overlap(opnd_get_reg(operand), DR_REG_XBP);
                       })))
        frame.frame_base_restored = true;
    }
    if (frame.frame_base_restored)
      after.unavailable_gpr |= UINT64_C(1) << 6;
  }
  complete_pending(thread, after, pc, false, values);
  if (previous.site && previous.site->instruction.call) {
    auto *call = new Call;
    call->timing_only = previous.timing_only;
    call->deferred_call = std::move(thread.deferred_call);
    thread.deferred_call = Visit{};
    call->source_call_site = previous.site;
    call->entry_pc = pc;
    call->return_pc = previous.site->instruction.next;
    call->entry_sp = registers.gpr[7];
    call->parent = !previous.timing_only && previous.visit &&
                           previous.visit->first && previous.visit->source
                       ? previous.visit
                       : nullptr;
    if (previous.provenance)
      call->provenance = *previous.provenance;
    for (auto &origin : call->provenance.registers)
      if (!origin.source_identity.empty())
        origin = {};
    call->scope.recurse = previous.recurse;
    call->scope.blocked = previous.blocked;
    call->linkage_child = previous.linkage;
    thread.calls.push_back(call);
  } else if (previous.site && previous.site->instruction.ret &&
             !thread.calls.empty() &&
             (thread.calls.back()->startup_entry
                  ? startup_owns_instruction(*thread.calls.back(),
                                             *previous.site)
                  : registers.gpr[7] > thread.calls.back()->entry_sp)) {
    Call *call = thread.calls.back();
    // A return-site gate can expose a raw nested callee whose CALL never
    // created a tracing frame. Its RET must not remove the recorded ancestor
    // until the stack actually rises above that ancestor's entry position.
    // Startup has no return slot: only its own proven RET ends that root.
    const bool returned = call->signal_frame || call->return_pc == pc;
    leave_call(thread, registers, returned);
  }
  // Unobserved callees can return directly from original text: there need not
  // be a RET callback. A saved return PC together with the caller's restored
  // stack proves completion without guessing from a function-name change.
  while (!thread.calls.empty() && !thread.calls.back()->signal_frame &&
         pc == thread.calls.back()->return_pc &&
         registers.gpr[7] > thread.calls.back()->entry_sp)
    leave_call(thread, registers, true);
  // A non-local jump can skip several returns. Do not reuse their pending
  // values.
  if (!thread.calls.empty() && !thread.calls.back()->startup_entry &&
      registers.gpr[7] > thread.calls.back()->entry_sp &&
      pc != thread.calls.back()->return_pc &&
      !(previous.site && previous.site->instruction.branch &&
        previous.site->instruction.opcode == OP_jmp_ind)) {
    // An unrecorded raw unwinder can restore the caller's stack before its
    // final indirect jump. At the jump gate we are still in the unwinder;
    // prune only at its actual successor, when Pending records that jump.
    // A JMP patch can borrow a preceding instruction, so inspect the whole
    // preserved gate window rather than only its first replayed instruction.
    ct_userspace_patch_info gate{};
    const bool patched = ct_userspace_patch_lookup(pc, &gate);
    const app_pc limit =
        patched ? std::min(gate.pc, gate.redirect_pc) + gate.length : pc + 15;
    app_pc cursor = pc;
    while (cursor < limit) {
      instr_t instruction;
      instr_init(dr_get_current_drcontext(), &instruction);
      const app_pc next =
          decode(dr_get_current_drcontext(), cursor, &instruction);
      const bool indirect = instr_get_opcode(&instruction) == OP_jmp_ind;
      const bool transfer =
          instr_is_cti(&instruction) || instr_is_syscall(&instruction);
      instr_free(dr_get_current_drcontext(), &instruction);
      if (indirect)
        return;
      if (!patched || !next || next <= cursor || transfer)
        break;
      cursor = next;
    }
    // An unwinder restores RSP before its final jump. Until control actually
    // leaves that function, the restored stack does not make the current
    // instruction part of the caller. Defer pruning to the jump's successor.
    const Call &frame = *thread.calls.back();
    const app_pc entry = frame.function ? frame.function->pc : frame.entry_pc;
    Module *module = module_at(entry);
    if (module && module_at(pc) == module) {
      const uint64_t offset = entry - module->start;
      auto range = module->flow_ranges.upper_bound(offset);
      if (range != module->flow_ranges.begin()) {
        --range;
        if (offset < range->second &&
            uint64_t(pc - module->start) >= range->first &&
            uint64_t(pc - module->start) < range->second)
          return;
      }
    }
  }
  while (!thread.calls.empty() && !thread.calls.back()->startup_entry &&
         registers.gpr[7] > thread.calls.back()->entry_sp &&
         pc != thread.calls.back()->return_pc)
    if (thread.calls.back()->signal_frame &&
        registers.gpr[7] < thread.calls.back()->interrupted_sp)
      break;
    else
      leave_call(thread, registers, false);
}

static void collect_flow_region(const ct_flow_region *region, void *argument) {
  auto &module = *static_cast<Module *>(argument);
  const auto size = static_cast<uint64_t>(module.end - module.start);
  if (region->branch_offset >= size || region->taken_offset >= size ||
      region->fallthrough_offset >= size || region->join_offset >= size ||
      (region->kind == CT_FLOW_LOOP && region->loop_header_offset >= size) ||
      (region->has_update && region->update_offset >= size) ||
      (region->has_initializer && region->initializer_offset >= size))
    return;
  module.flow_regions.emplace(module.start + region->branch_offset, *region);
  for (uint64_t offset : {region->branch_offset, region->taken_offset,
                          region->fallthrough_offset, region->join_offset})
    module.perfetto_boundaries.insert(module.start + offset);
  if (region->kind == CT_FLOW_LOOP)
    module.perfetto_boundaries.insert(module.start +
                                      region->loop_header_offset);
  if (region->has_update)
    module.perfetto_boundaries.insert(module.start + region->update_offset);
  if (region->has_initializer)
    module.perfetto_boundaries.insert(module.start +
                                      region->initializer_offset);
  if (region->has_initializer)
    module.flow_initializers.emplace(module.start + region->initializer_offset,
                                     module.start + region->branch_offset);
}

static void collect_flow_switch(const ct_flow_switch *region, void *argument) {
  auto &module = *static_cast<Module *>(argument);
  const auto size = static_cast<uint64_t>(module.end - module.start);
  if (!region->case_count || region->case_count > CT_FLOW_SWITCH_CASE_LIMIT ||
      region->guard_offset >= size || region->dispatch_offset >= size ||
      region->selector_offset >= size || region->join_offset >= size ||
      region->default_offset >= size)
    return;
  for (uint32_t index = 0; index < region->case_count; ++index)
    if (region->cases[index].target_offset >= size)
      return;
  module.flow_switches.emplace(module.start + region->guard_offset,
                               std::make_shared<ct_flow_switch>(*region));
  for (uint64_t offset :
       {region->guard_offset, region->dispatch_offset, region->selector_offset,
        region->join_offset, region->default_offset})
    module.perfetto_boundaries.insert(module.start + offset);
  for (uint32_t index = 0; index < region->case_count; ++index)
    module.perfetto_boundaries.insert(module.start +
                                      region->cases[index].target_offset);
}

static void collect_flow_instruction(const ct_flow_instruction *instruction,
                                     void *argument) {
  auto &module = *static_cast<Module *>(argument);
  const uint64_t size = module.end - module.start;
  if (instruction->offset < size && instruction->size &&
      instruction->size <= size - instruction->offset &&
      !(instruction->flags & CT_FLOW_FRONTIER))
    module.flow_decoded.insert(instruction->offset);
}

static void prepare_flow(Module &module, uint64_t offset) {
  const auto following = module.flow_ranges.upper_bound(offset);
  if ((following != module.flow_ranges.begin() &&
       offset < std::prev(following)->second) ||
      module.flow_decoded.count(offset) ||
      !module.flow_requests.insert(offset).second)
    return;
  ct_flow_range range{};
  if (!ct_analysis_flow(module.analysis, offset, &range, nullptr,
                        collect_flow_region, collect_flow_switch, &module))
    return;
  if (range.bounded && range.begin_offset < range.end_offset) {
    module.flow_ranges[range.begin_offset] = range.end_offset;
  } else if (range.complete) {
    // Reuse only actually decoded PCs. Treating the unbounded snapshot's end
    // as a function end would invent a scope and hide unrelated entry points.
    // An incomplete root has no recovered regions: a later suffix entry must
    // still get its own chance to prove a complete local control-flow graph.
    ct_analysis_code_graph(module.analysis, offset, &range,
                           collect_flow_instruction, nullptr, &module);
  }
}

static std::shared_ptr<const ct_location_record>
intern_location(Module &module, const ct_location &location) {
  const auto key = std::make_tuple(
      location.source_id, location.function_id, location.line, location.column,
      location.discriminator,
      std::string(location.symbol,
                  strnlen(location.symbol, sizeof(location.symbol))));
  auto &candidates = module.locations[key];
  // The row is only a candidate key. Entry signatures, inline aliases and
  // case-specific source fragments must also agree before sharing storage.
  for (const auto &candidate : candidates)
    if (candidate->matches(location))
      return candidate;
  auto record = std::make_shared<ct_location_record>(location);
  candidates.push_back(record);
  return record;
}

static std::shared_ptr<const ct_location_record>
prepare_location(Module &module, app_pc pc) {
  auto location = std::make_unique<ct_location>();
  ct_analysis_lookup(module.analysis, pc - module.start, location.get());
  return intern_location(module, *location);
}

// One initial collection owns at most one bounded packed batch and one compact
// scratch row. Calls return only after the proxy has validated every member and
// released its transport lock, so Site preparation can issue further RPCs.
struct InitialLocationBatch {
  std::vector<uint64_t> offsets;
  bool arming = false;
  size_t index = 0, available = 0, position = 0;
  std::unique_ptr<unsigned char, decltype(&std::free)> bytes{nullptr,
                                                             std::free};
  std::unique_ptr<ct_arming_location> compact;

  bool read_next(ct_analysis *analysis, ct_location &location) {
    if (index >= offsets.size())
      return false;
    if (index == available) {
      bytes.reset();
      unsigned char *allocation = nullptr;
      size_t size = 0;
      const size_t count = std::min(size_t(CT_LOCATION_BATCH_COUNT_LIMIT),
                                    offsets.size() - index);
      if (!ct_analysis_lookup_batch(analysis, offsets.data() + index, count,
                                    arming, &allocation, &size))
        return false;
      bytes.reset(allocation);
      ct_location_batch_header header;
      std::memcpy(&header, bytes.get(), sizeof(header));
      available = index + header.count;
      position = sizeof(header);
    }
    ct_location_batch_record record;
    std::memcpy(&record, bytes.get() + position, sizeof(record));
    position += sizeof(record);
    bool valid;
    if (arming) {
      if (!compact)
        compact = std::make_unique<ct_arming_location>();
      valid = ct_analysis_record_unpack(compact.get(), sizeof(*compact),
                                        bytes.get() + position, record.size);
      if (valid)
        ct_arming_location_unpack(&location, compact.get());
    } else {
      valid = ct_analysis_record_unpack(&location, sizeof(location),
                                        bytes.get() + position, record.size);
    }
    position += record.size;
    return valid && record.offset == offsets[index++];
  }
};

static void prepare_site(Site &site, void *context, bool values = true,
                         const ct_flow_instruction *original = nullptr) {
  if (!site.prepared) {
    instr_t instruction;
    instr_init(context, &instruction);
    if (original) {
      byte bytes[15]{};
      std::memcpy(bytes, original->bytes, original->size);
      byte *next =
          decode_from_copy(context, bytes, site.instruction.pc, &instruction);
      if (!next || next - bytes != original->size ||
          !instr_valid(&instruction)) {
        instr_free(context, &instruction);
        return;
      }
    } else {
      decode(context, site.instruction.pc, &instruction);
    }
    instr_set_translation(&instruction, site.instruction.pc);
    site.instruction = ct_decode_instruction(context, &instruction);
    instr_free(context, &instruction);
    if (site.instruction.next > site.instruction.pc &&
        size_t(site.instruction.next - site.instruction.pc) <=
            sizeof(site.original_bytes)) {
      site.original_size = site.instruction.next - site.instruction.pc;
      if (!ct_userspace_patch_read_original(
              site.instruction.pc, site.original_size, site.original_bytes))
        site.original_size = 0;
    }
    const uint64_t offset = site.instruction.pc - site.module->start;
    prepare_flow(*site.module, offset);
    filter_modes(*site.module, site.location, site.mode, site.physical_mode,
                 site.inline_modes);
    site.prepared = true;
  }
  if (values && !site.values_prepared) {
    site.values =
        ct_values_prepare(module_values(*site.module),
                          reinterpret_cast<uint64_t>(site.instruction.pc));
    // RET resumes at the caller, not the adjacent bytes, which can belong to
    // an unselected function. Completion resolves its actual destination.
    if (!site.instruction.ret)
      site.next_values =
          ct_values_prepare(module_values(*site.module),
                            reinterpret_cast<uint64_t>(site.instruction.next));
    site.values_prepared = true;
  }
}

static bool decompile_site(Site &site, void *context) {
  if (!decompile || site.location.is_plt)
    return false;
  if (site.decompile_generation != site.module->code_generation) {
    site.decompile_generation = site.module->code_generation;
    site.decompile_checked = false;
    site.decompiled.reset();
    site.decompiled_variables.reset();
  }
  if (site.module->pending_code_changes)
    return false;
  if (!site.decompile_checked) {
    site.decompile_checked = true;
    auto statement = std::make_unique<ct_decompiled_statement>();
    if (ct_analysis_decompile(site.module->analysis,
                              site.instruction.pc - site.module->start,
                              CT_DECOMPILE_FULL, statement.get())) {
      bool valid =
          statement->instruction_count &&
          statement->instruction_count <= CT_DECOMPILED_INSTRUCTION_LIMIT &&
          statement->instruction_index < statement->instruction_count &&
          decompiled_function_matches(site, statement->function_offset,
                                      CT_DECOMPILE_FULL);
      std::vector<reg_id_t> written_registers;
      for (uint32_t index = 0; valid && index < statement->instruction_count;
           ++index) {
        const auto &entry = statement->instructions[index];
        const uint64_t module_size = site.module->end - site.module->start;
        valid = entry.size && entry.size <= sizeof(entry.bytes) &&
                entry.offset < module_size &&
                entry.size <= module_size - entry.offset;
        if (!valid)
          break;
        instr_t decoded;
        instr_init(context, &decoded);
        byte *end =
            decode_from_copy(context, const_cast<byte *>(entry.bytes),
                             site.module->start + entry.offset, &decoded);
        const bool terminal = index + 1 == statement->instruction_count;
        valid = end == entry.bytes + entry.size && instr_valid(&decoded) &&
                !instr_is_cbr(&decoded) && !instr_is_ubr(&decoded) &&
                !instr_is_syscall(&decoded) &&
                !instr_get_prefix_flag(&decoded, PREFIX_LOCK) &&
                !(instr_get_opcode(&decoded) == OP_xchg &&
                  instr_writes_memory(&decoded)) &&
                (terminal ||
                 (!instr_is_call(&decoded) && !instr_is_return(&decoded))) &&
                (instr_is_call(&decoded) || instr_is_return(&decoded) ||
                 !instr_writes_to_reg(&decoded, DR_REG_RSP, DR_QUERY_DEFAULT));
        // A symbolic address such as [rax] would otherwise refer to different
        // storage at different points within one before/after snapshot.
        for (int operand = 0; valid && operand < instr_num_srcs(&decoded) +
                                                     instr_num_dsts(&decoded);
             ++operand) {
          const opnd_t value =
              operand < instr_num_srcs(&decoded)
                  ? instr_get_src(&decoded, operand)
                  : instr_get_dst(&decoded, operand - instr_num_srcs(&decoded));
          if (!opnd_is_base_disp(value))
            continue;
          for (const auto reg : written_registers)
            if ((opnd_get_base(value) != DR_REG_NULL &&
                 reg_overlap(reg, opnd_get_base(value))) ||
                (opnd_get_index(value) != DR_REG_NULL &&
                 reg_overlap(reg, opnd_get_index(value))))
              valid = false;
        }
        // A partial GPR write preserves high bits that a later read may use.
        // Keep those sequences explicit rather than merging partial values.
        if (statement->instruction_count > 1)
          for (int output = 0; valid && output < instr_num_dsts(&decoded);
               ++output) {
            const opnd_t destination = instr_get_dst(&decoded, output);
            if (opnd_is_reg(destination) &&
                reg_is_gpr(opnd_get_reg(destination))) {
              written_registers.push_back(opnd_get_reg(destination));
              if (opnd_size_in_bytes(opnd_get_size(destination)) < 4)
                valid = false;
            }
          }
        instr_free(context, &decoded);
        if (index && statement->instructions[index - 1].offset +
                             statement->instructions[index - 1].size !=
                         entry.offset)
          valid = false;
      }
      if (valid) {
        if (statement->declaration_id && statement->declaration_name[0]) {
          const auto key =
              std::make_pair(statement->function_offset,
                             std::string(statement->declaration_name));
          auto [known, inserted] = site.module->decompiled_symbols.emplace(
              key, std::make_pair(statement->declaration_id,
                                  std::string(statement->declaration_type)));
          if (!inserted &&
              (known->second.first != statement->declaration_id ||
               known->second.second != statement->declaration_type))
            known->second = {};
        }
        site.decompiled =
            std::make_unique<ct_decompiled_statement_record>(*statement);
      }
    } else {
      const char *error = ct_analysis_decompile_error(site.module->analysis);
      if (error && error[0] &&
          warnings.insert(site.module->identity + ":decompile:" + error).second)
        write_warning("Warning: " + site.module->path +
                      ": decompilation unavailable: " + error +
                      "; using instruction-level output\n");
    }
    auto variables = std::make_unique<ct_decompiled_variables>();
    if (ct_analysis_decompile_variables(
            site.module->analysis, site.instruction.pc - site.module->start,
            CT_DECOMPILE_FULL, variables.get()) &&
        decompiled_function_matches(site, variables->function_offset,
                                    CT_DECOMPILE_FULL) &&
        (variables->count || variables->return_known ||
         variables->return_unsupported || variables->parameters_known))
      site.decompiled_variables =
          std::make_shared<ct_decompiled_variables_record>(*variables);
  }
  if (!site.decompiled)
    return false;
  const auto &entry =
      site.decompiled->instructions[site.decompiled->instruction_index];
  unsigned char current[15];
  if (site.module->start + entry.offset != site.instruction.pc ||
      !ct_userspace_patch_read_original(site.instruction.pc, entry.size,
                                        current) ||
      std::memcmp(current, entry.bytes, entry.size))
    return false;
  return true;
}

static void resolve_decompiled_operands(MachineContext &machine, Site &site,
                                        const ct_registers &registers,
                                        const Call *frame,
                                        ct_provenance &provenance) {
  machine.decompiled_operands.clear();
  machine.decompiled_owner = site.decompiled_variables;
  const auto *variables = machine.decompiled_owner.get();
  if (!variables)
    return;
  const auto &instruction = variables->instruction;
  unsigned char bytes[15];
  if (!instruction.size || instruction.size > sizeof(bytes) ||
      instruction.offset !=
          uint64_t(site.instruction.pc - site.module->start) ||
      !ct_userspace_patch_read_original(site.instruction.pc, instruction.size,
                                        bytes) ||
      std::memcmp(bytes, instruction.bytes, instruction.size))
    return;
  const uint64_t module_size = site.module->end - site.module->start;
  if (variables->function_offset >= module_size)
    return;
  const app_pc entry = site.module->start + variables->function_offset;
  const bool new_function = machine.decompiled_module != site.module ||
                            machine.decompiled_entry != entry;
  if (new_function) {
    machine.decompiled_module = site.module;
    machine.decompiled_entry = entry;
    machine.decompiled_stack = 0;
    if (registers.have_gpr && site.instruction.pc == entry)
      machine.decompiled_stack = registers.gpr[7];
    else if (frame && frame->entry_pc == entry)
      machine.decompiled_stack = frame->entry_sp;
  }
  for (uint32_t index = 0;
       index < variables->count && index < CT_DECOMPILED_VARIABLE_LIMIT;
       ++index) {
    const auto &variable = variables->entries[index];
    ct_decompiled_operand operand;
    operand.memory = variable.kind != CT_DECOMPILED_REGISTER;
    operand.read = (variable.access & CT_DECOMPILED_READ) != 0;
    operand.write = (variable.access & CT_DECOMPILED_WRITE) != 0;
    operand.bytes = variable.size;
    operand.name = variable.name;
    operand.type_name = variable.type_name;
    operand.type = variable.type;
    operand.type_id = variable.type_id;
    operand.layout = {variables->types.data(), variables->type_count,
                      variables->members.data(), variables->member_count};
    // Ghidra's undefinedN describes a byte width, not a recovered C type.
    if (operand.type.kind == CT_VALUE_UNKNOWN &&
        operand.type_name.compare(0, 9, "undefined") == 0 &&
        std::all_of(operand.type_name.begin() + 9, operand.type_name.end(),
                    [](unsigned char ch) { return std::isdigit(ch); }))
      operand.type_name.clear();
    operand.identity = site.module->identity + ":decompiled:" +
                       std::to_string(variables->function_offset) + ":" +
                       std::to_string(variable.id);
    for (uint32_t parameter = 0; parameter < variables->parameter_count;
         ++parameter)
      if (operand.name == variables->parameters[parameter].name) {
        const auto &entry_parameter = variables->parameters[parameter];
        operand.identity = site.module->identity + ":decompiled-parameter:" +
                           std::to_string(variables->function_offset) + ":" +
                           entry_parameter.name;
        break;
      }
    if (variable.register_alias)
      operand.identity = register_type_identity(operand.name);
    if (variable.kind == CT_DECOMPILED_STACK) {
      if (!machine.decompiled_stack)
        continue;
      const uint64_t displacement = variable.stack_offset < 0
                                        ? -uint64_t(variable.stack_offset)
                                        : uint64_t(variable.stack_offset);
      if (variable.stack_offset < 0) {
        if (displacement > machine.decompiled_stack)
          continue;
        operand.location = machine.decompiled_stack - displacement;
      } else {
        if (displacement > UINT64_MAX - machine.decompiled_stack)
          continue;
        operand.location = machine.decompiled_stack + displacement;
      }
    } else if (variable.kind == CT_DECOMPILED_GLOBAL) {
      if (variable.offset >= module_size ||
          variable.size > module_size - variable.offset)
        continue;
      operand.location =
          reinterpret_cast<uint64_t>(site.module->start) + variable.offset;
      operand.identity = site.module->identity + ":decompiled-global:" +
                         std::to_string(variable.offset) + ":" + variable.name;
    } else {
      std::string name = variable.register_name;
      std::transform(name.begin(), name.end(), name.begin(),
                     [](unsigned char ch) { return std::tolower(ch); });
      reg_id_t reg = DR_REG_NULL;
      for (int candidate = DR_REG_RAX; candidate <= DR_REG_STOP_8; ++candidate)
        if (name == get_register_name(static_cast<reg_id_t>(candidate))) {
          reg = static_cast<reg_id_t>(candidate);
          break;
        }
      if (reg == DR_REG_NULL)
        for (int candidate = DR_REG_XMM0; candidate <= DR_REG_XMM15;
             ++candidate)
          if (name == get_register_name(static_cast<reg_id_t>(candidate))) {
            reg = static_cast<reg_id_t>(candidate);
            break;
          }
      if (reg == DR_REG_NULL ||
          !ct_operand_location(opnd_create_reg(reg), registers,
                               &operand.location, &operand.byte_offset))
        continue;
    }
    machine.decompiled_operands.push_back(std::move(operand));
  }
  // Keep exact member bindings for the C/asm expression while the observation
  // formatter uses the enclosing object. Derive only the member touched by an
  // actual operand, so large arrays do not produce a binding per element.
  const size_t objects = machine.decompiled_operands.size();
  std::vector<opnd_t> accesses = site.instruction.inputs;
  accesses.insert(accesses.end(), site.instruction.outputs.begin(),
                  site.instruction.outputs.end());
  for (const opnd_t access : accesses) {
    if (!opnd_is_memory_reference(access))
      continue;
    uint64_t address = 0;
    size_t byte_offset = 0;
    const size_t bytes = opnd_size_in_bytes(opnd_get_size(access));
    if (!bytes ||
        !ct_operand_location(access, registers, &address, &byte_offset))
      continue;
    for (size_t index = 0; index < objects; ++index) {
      const auto &object = machine.decompiled_operands[index];
      if (!object.memory || !object.type_id || address < object.location ||
          address - object.location > object.bytes ||
          bytes > object.bytes - (address - object.location))
        continue;
      uint32_t type_id = object.type_id;
      size_t offset = address - object.location;
      std::string name = object.name;
      bool matched = false;
      // Match the formatter's recursion bound, including malformed cycles.
      for (unsigned depth = 0; depth < 64; ++depth) {
        if (!type_id || type_id > object.layout.type_count)
          break;
        const auto &type = object.layout.types[type_id - 1];
        if (type.guarded || offset > type.bytes || bytes > type.bytes - offset)
          break;
        if (!offset && bytes == type.bytes) {
          matched = true;
          break;
        }
        if (type.kind == CT_LAYOUT_ARRAY) {
          if (!type.element_stride || !type.element_type ||
              type.element_type > object.layout.type_count)
            break;
          const size_t element = offset / type.element_stride;
          if (element >= type.element_count)
            break;
          name += "[" + std::to_string(element) + "]";
          offset %= type.element_stride;
          type_id = type.element_type;
        } else if (type.kind == CT_LAYOUT_STRUCT) {
          if (type.first_member > object.layout.member_count ||
              type.member_count >
                  object.layout.member_count - type.first_member)
            break;
          const ct_value_layout_member *found = nullptr;
          for (size_t member_index = 0; member_index < type.member_count;
               ++member_index) {
            const auto &member =
                object.layout.members[type.first_member + member_index];
            if (!member.available || !member.type ||
                member.type > object.layout.type_count ||
                offset < member.offset)
              continue;
            const auto &child = object.layout.types[member.type - 1];
            if (offset - member.offset > child.bytes ||
                bytes > child.bytes - (offset - member.offset))
              continue;
            if (found) {
              found = nullptr;
              break;
            }
            found = &member;
          }
          if (!found)
            break;
          if (found->name[0])
            name += "." + std::string(found->name);
          offset -= found->offset;
          type_id = found->type;
        } else {
          break;
        }
      }
      if (!matched || name == object.name)
        continue;
      ct_decompiled_operand member = object;
      member.location = address;
      member.bytes = bytes;
      member.name = std::move(name);
      member.type_id = type_id;
      member.subobject = true;
      member.identity +=
          ":member:" + std::to_string(address - object.location) + ":" +
          std::to_string(bytes);
      const auto &type = object.layout.types[type_id - 1];
      member.type = type.scalar;
      member.type.bytes = bytes;
      member.type_name.clear();
      if (type.kind == CT_LAYOUT_POINTER) {
        member.type.kind = CT_VALUE_POINTER;
      } else if (type.kind == CT_LAYOUT_SCALAR) {
        if (type.scalar.kind == CT_VALUE_SIGNED ||
            type.scalar.kind == CT_VALUE_UNSIGNED)
          member.type_name =
              std::string(type.scalar.kind == CT_VALUE_SIGNED ? "int"
                                                              : "uint") +
              std::to_string(bytes * 8) + "_t";
        else if (type.scalar.kind == CT_VALUE_BOOLEAN)
          member.type_name = "bool";
        else if (type.scalar.kind == CT_VALUE_FLOAT)
          member.type_name = bytes == 4 ? "float" : bytes == 8 ? "double" : "";
      }
      const bool duplicate = std::any_of(
          machine.decompiled_operands.begin(),
          machine.decompiled_operands.end(), [&](const auto &known) {
            return known.identity == member.identity &&
                   known.name == member.name &&
                   known.location == member.location &&
                   known.bytes == member.bytes;
          });
      if (!duplicate)
        machine.decompiled_operands.push_back(std::move(member));
    }
  }
  // Incoming parameters can be spilled several instructions after entry.
  // Seed move-only provenance only after rejecting ambiguous register names.
  if (new_function && site.instruction.pc == entry)
    for (const auto &operand : machine.decompiled_operands) {
      if (operand.memory || !operand.read || operand.write ||
          operand.byte_offset ||
          operand.location >= provenance.registers.size() ||
          !provenance.registers[operand.location].name.empty())
        continue;
      const bool ambiguous = std::any_of(
          machine.decompiled_operands.begin(),
          machine.decompiled_operands.end(), [&](const auto &other) {
            return !other.memory && other.read &&
                   other.location == operand.location &&
                   (other.identity != operand.identity ||
                    other.name != operand.name ||
                    other.bytes != operand.bytes ||
                    other.byte_offset != operand.byte_offset);
          });
      if (ambiguous)
        continue;
      auto &origin = provenance.registers[operand.location];
      origin.name = operand.name;
      origin.source_identity = operand.identity;
      origin.type_name = operand.type_name;
      origin.type = operand.type;
      origin.bytes = operand.bytes;
      origin.source_register = static_cast<int>(operand.location);
    }
}

static std::string decompiled_return(Site &site, const Call *frame,
                                     const ct_registers &registers,
                                     std::string &value,
                                     OperandType &display_type) {
  if (!site.instruction.ret || site.instruction.opcode != OP_ret)
    return {};
  ct_value_type type{};
  char spelling[512]{};
  bool is_void = false;
  if (!return_type_evidence(site, frame, type, is_void, spelling,
                            sizeof(spelling)))
    return {};
  if (is_void)
    return "return;";
  if (type.bytes != 1 && type.bytes != 2 && type.bytes != 4 && type.bytes != 8)
    return {};
  const bool floating = type.kind == CT_VALUE_FLOAT;
  if (floating && type.bytes != 4 && type.bytes != 8)
    return {};
  const char *reg = floating          ? "XMM0"
                    : type.bytes == 1 ? "AL"
                    : type.bytes == 2 ? "AX"
                    : type.bytes == 4 ? "EAX"
                                      : "RAX";
  const unsigned char *bytes =
      floating
          ? (registers.have_xmm ? registers.xmm[0] : nullptr)
          : (registers.have_gpr
                 ? reinterpret_cast<const unsigned char *>(&registers.gpr[0])
                 : nullptr);
  if (bytes) {
    char formatted[2048];
    if (type.kind != CT_VALUE_UNKNOWN &&
        ct_values_format_typed(reg, &type, bytes, type.bytes, formatted,
                               sizeof(formatted)))
      value = formatted;
    else {
      uint64_t raw = 0;
      std::memcpy(&raw, bytes, type.bytes);
      dr_snprintf(formatted, sizeof(formatted), "%s=0x%llx", reg,
                  static_cast<unsigned long long>(raw));
      value = formatted;
    }
    display_type.identity = register_type_identity(reg);
    display_type.type = spelling;
    if (type.kind == CT_VALUE_UNKNOWN || display_type.type.empty())
      display_type.type = "uint" + std::to_string(type.bytes * 8) + "_t";
  }
  if (floating)
    return "return *(" + std::string(type.bytes == 4 ? "float" : "double") +
           " *)&XMM0;";
  const bool declared = frame && !frame->declaration.empty();
  const bool cast = type.kind != CT_VALUE_UNKNOWN && spelling[0] &&
                    (!declared || type.kind == CT_VALUE_POINTER);
  return "return " + (cast ? "(" + std::string(spelling) + ")" : "") + reg +
         ";";
}

static void decompiled_entry(Site &site, Call &frame,
                             const ct_registers &registers) {
  const auto *function = site.decompiled_variables.get();
  if (!decompile || !function || site.location.is_plt ||
      !frame.declaration.empty() ||
      function->function_offset !=
          uint64_t(site.instruction.pc - site.module->start) ||
      function->parameter_count > CT_DECOMPILED_PARAMETER_LIMIT)
    return;
  unsigned char bytes[15];
  const auto &instruction = function->instruction;
  if (!instruction.size || instruction.size > sizeof(bytes) ||
      instruction.offset != function->function_offset ||
      !ct_userspace_patch_read_original(site.instruction.pc, instruction.size,
                                        bytes) ||
      std::memcmp(bytes, instruction.bytes, instruction.size))
    return;
  ct_value_type result{};
  char result_name[512]{};
  bool is_void = false;
  const bool known = return_type_evidence(site, &frame, result, is_void,
                                          result_name, sizeof(result_name));
  if (function->return_unsupported ||
      (frame.function && ct_function_return_unsupported(frame.function->type)))
    return;
  std::string return_name = known ? result_name : "?";
  if (known && is_void)
    return_name = "void";
  else if (known && (result.kind == CT_VALUE_UNKNOWN || return_name.empty() ||
                     return_name == "?"))
    return_name = "uint" + std::to_string(result.bytes * 8) + "_t";
  else if (known && result.kind == CT_VALUE_POINTER &&
           return_name.find_first_of("([") != std::string::npos)
    return_name = "uintptr_t";
  const std::string name = !frame.display_name.empty() ? frame.display_name
                           : frame.function            ? frame.function->name
                                            : std::string(site.location.symbol);
  if (name.empty())
    return;
  std::string parameters, arguments, positional;
  if (!function->parameters_known) {
    parameters = positional = "...";
  } else {
    for (uint32_t index = 0; index < function->parameter_count; ++index) {
      const auto &parameter = function->parameters[index];
      if (!parameters.empty()) {
        parameters += ", ";
        arguments += ", ";
        positional += ", ";
      }
      parameters += std::string(parameter.type_name) + " " + parameter.name;
      unsigned char data[8]{};
      bool available = parameter.size && parameter.size <= sizeof(data);
      if (available && parameter.kind == CT_DECOMPILED_STACK) {
        available =
            registers.have_gpr && parameter.stack_offset >= 8 &&
            uint64_t(parameter.stack_offset) <= UINT64_MAX - registers.gpr[7] &&
            read_memory(nullptr, registers.gpr[7] + parameter.stack_offset,
                        data, parameter.size);
      } else if (available && parameter.kind == CT_DECOMPILED_REGISTER) {
        const std::string reg_name = parameter.register_name;
        reg_id_t reg = DR_REG_NULL;
        for (int candidate = DR_REG_RAX; candidate <= DR_REG_STOP_8;
             ++candidate)
          if (reg_name == get_register_name(static_cast<reg_id_t>(candidate))) {
            reg = static_cast<reg_id_t>(candidate);
            break;
          }
        if (reg == DR_REG_NULL)
          for (int candidate = DR_REG_XMM0; candidate <= DR_REG_XMM7;
               ++candidate)
            if (reg_name ==
                get_register_name(static_cast<reg_id_t>(candidate))) {
              reg = static_cast<reg_id_t>(candidate);
              break;
            }
        available =
            reg != DR_REG_NULL && operand_bytes(opnd_create_reg(reg), registers,
                                                data, parameter.size);
      } else {
        available = false;
      }
      char formatted[1024]{};
      const std::string value =
          available && ct_values_format_typed(parameter.name, &parameter.type,
                                              data, parameter.size, formatted,
                                              sizeof(formatted))
              ? std::string(formatted)
              : std::string(parameter.name) + "=?";
      frame.entry_types.push_back(
          {arguments.size() + value.find('=') + 1,
           site.module->identity + ":decompiled-parameter:" +
               std::to_string(function->function_offset) + ":" + parameter.name,
           parameter.type_name});
      arguments += value;
      positional += value.substr(value.find('=') + 1);
    }
    if (function->variadic) {
      parameters += parameters.empty() ? "..." : ", ...";
      positional += positional.empty() ? "..." : ", ...";
    } else if (parameters.empty()) {
      parameters = "void";
    }
  }
  frame.declaration = return_name + " " + name + "(" + parameters + ")";
  frame.decompiled_declaration = true;
  frame.entry_arguments = std::move(arguments);
  frame.invocation = name + "(" + positional + ")";
}

static void suspend_observation(Thread &thread) {
  execution_mode() = 2;
  for (auto &origin : thread.root_provenance.registers)
    if (origin.memory_bytes)
      origin = {};
  for (Call *call : thread.calls)
    for (auto &origin : call->provenance.registers)
      if (origin.memory_bytes)
        origin = {};
  current_provenance(thread) = {};
}

// Retain immutable Sites owned by active observations, but rebuild every index
// whose interpretation depends on this module's original instruction bytes.
// Callers hold analysis_lock; cache retirement is a separate operation.
static void invalidate_original_metadata(Module &module) {
  ++module.code_generation;
  module.code_modified = true;
  module.dr_recipes.clear();
  module.original_code_proofs.clear();
  module.original_proof_failures.clear();
  module.decompiled_proofs.clear();
  module.decompiled_symbols.clear();
  module.quiet_transfers.clear();
  module.flow_ranges.clear();
  module.flow_requests.clear();
  module.flow_decoded.clear();
  module.flow_regions.clear();
  module.flow_updates.clear();
  module.flow_initializers.clear();
  module.flow_switches.clear();
  module.perfetto_boundaries.clear();
  module.initial_ready.clear();
  module.initial_ready_dirty = true;
  for (auto site = current_sites.begin(); site != current_sites.end();) {
    if (site->second->module.get() == &module)
      site = current_sites.erase(site);
    else
      ++site;
  }
}

// Mapping/permission transitions validate the complete bounded snapshot.
// Ordinary BB preparation compares instructions, not unrelated mutable data.
static bool runtime_image_matches(const Module &module) {
  std::vector<byte> bytes(module.end - module.start);
  unsigned char digest[32];
  return ct_userspace_patch_read_original(module.start, bytes.size(),
                                          bytes.data()) &&
         ct_shared_platform_digest(bytes.data(), bytes.size(), digest) &&
         std::memcmp(digest, module.runtime_digest, sizeof(digest)) == 0;
}

// Runtime snapshots have no symbol hooks. Keep older observations' shared
// owners intact while excluding this incarnation from new preparation.
static void retire_runtime_image(Module &module) {
  invalidate_original_metadata(module);
  module.active = false;
  module.hooks_retired = true;
  module.locations.clear();
  for (auto site = arming_sites.begin(); site != arming_sites.end();) {
    if (site->second.module == &module)
      site = arming_sites.erase(site);
    else
      ++site;
  }
  ++initial_catalog_revision;
  ++analysis_generation;
}

// A runtime image is an analysis snapshot, never a claimed function extent.
// Code outside a proven CFG continues through DR's consistency machinery.
static Module *discover_runtime_image(void *context, app_pc pc) {
  if (Module *known = module_at(pc))
    return known;
  if (!pc || dr_get_isa_mode(context) != DR_ISA_AMD64 ||
      dr_memory_is_dr_internal(pc) || dr_memory_is_in_client(pc))
    return nullptr;
  if (auto *loaded = dr_lookup_module(pc)) {
    dr_free_module_data(loaded);
    return nullptr; // The ELF load callback owns this image's registration.
  }
  dr_mem_info_t memory{};
  if (!dr_query_memory_ex(pc, &memory) || !(memory.prot & DR_MEMPROT_EXEC) ||
      memory.base_pc > pc ||
      memory.size > UINTPTR_MAX - uintptr_t(memory.base_pc) ||
      memory.base_pc + memory.size <= pc)
    return nullptr;
  const size_t chunk = CT_ANALYSIS_IMAGE_LIMIT;
  app_pc begin = memory.base_pc + (size_t(pc - memory.base_pc) / chunk) * chunk;
  app_pc end =
      begin + std::min(chunk, size_t(memory.base_pc + memory.size - begin));
  // Permission changes can split and later merge a VMA. Existing snapshots
  // of its neighbors remain valid; never register an overlapping incarnation.
  for (const auto &existing : modules) {
    if (!existing->active)
      continue;
    if (existing->end <= pc)
      begin = std::max(begin, existing->end);
    else if (existing->start > pc)
      end = std::min(end, existing->start);
  }
  size_t size = end - begin;
  std::vector<byte> bytes(size), checked(size);
  bool unstable = false;
  if (!ct_userspace_patch_read_original(begin, size, bytes.data()) ||
      !ct_userspace_patch_read_original(begin, size, checked.data())) {
    // A neighboring page may disappear while the instruction at PC remains
    // readable. Retain minimal DR observation instead of requiring the entire
    // window to survive. Never claim a function extent for this short image.
    begin = pc;
    size = std::min(size_t(15), size_t(end - pc));
    while (size && !ct_userspace_patch_read_original(begin, size, bytes.data()))
      --size;
    if (!size)
      return nullptr;
    bytes.resize(size);
    unstable = true;
  } else {
    unstable = bytes != checked;
  }
  char identity[65]{};
  const int descriptor =
      ct_analysis_image_create(bytes.data(), size, pc - begin, identity);
  if (descriptor < 0)
    return nullptr;
  reclaim_modules();
  auto module = std::make_shared<Module>();
  module->start = begin;
  module->end = begin + size;
  module->runtime_image = true;
  if (!ct_shared_platform_digest(bytes.data(), bytes.size(),
                                 module->runtime_digest)) {
    ct_shared_platform_close(descriptor);
    return nullptr;
  }
  // Mutable neighboring data must not suppress observation of stable code.
  // Treat a changing snapshot as unproven: C/CFG consumers still validate
  // their exact instruction proofs, and assembly uses current DR decoding.
  module->code_modified =
      unstable || (memory.prot & (DR_MEMPROT_WRITE | DR_MEMPROT_SHARED)) != 0;
  module->executable_ranges.emplace_back(begin, begin + size);
  module->path = "[anonymous:" + std::string(identity) + "]";
  module->analysis = ct_analysis_open_fd(module->path.c_str(),
                                         source_maps.c_str(), descriptor);
  ct_shared_platform_close(descriptor);
  module->identity =
      module->path + ":" + ct_analysis_identity(module->analysis);
  ++initial_catalog_revision;
  ++analysis_generation;
  Module *result = module.get();
  modules.push_back(std::move(module));
  return result;
}

static void code_change(void *context, app_pc start, size_t size) {
  if (!traced_process() || !process_recording || !size ||
      size > UINTPTR_MAX - reinterpret_cast<uintptr_t>(start))
    return;
  QuietCallback quiet(context);
  Lock lock(analysis_lock);
  // DR reports a proven original-byte change before rebuilding the fragment.
  // This callback must only invalidate metadata: flushing or stopping peers
  // here would recurse into the consistency operation that notified us.
  for (auto &module : modules)
    if (module->active && start < module->end && start + size > module->start) {
      if (module->runtime_image)
        retire_runtime_image(*module);
      else
        invalidate_original_metadata(*module);
    }
}

static void observe_instruction(app_pc pc, bool inline_scope,
                                bool entry_boundary) {
  QuietCallback quiet(dr_get_current_drcontext());
  if (!traced_process() || !recording_thread() ||
      (!structural_instrumentation() && !within_active() && !inline_scope))
    return;
  if (!structural_instrumentation() && duplicate_enabled &&
      execution_mode() == 2 && !entry_boundary && !inline_scope)
    return;
  void *context = dr_get_current_drcontext();
  Thread &thread = *thread_state(context);
  if (ct_perfetto_enabled()) {
    thread.trace_timestamp = ct_perfetto_now(ct_timing_sample(context));
    thread.trace_signal_timestamp = {};
  }
  thread.userspace_copy_pending = false;
  const app_pc step_end = thread.userspace_step_end;
  thread.userspace_step_end = nullptr;
  if (step_end && thread.pending.site && !thread.pending.timing_only &&
      thread.pending.site->instruction.pc == pc &&
      thread.pending.site->instruction.next == step_end) {
    // Another thread's patch publication can cancel original-code entry before
    // this instruction runs. Keep its original before snapshot on DR replay.
    return;
  }
  thread.context.size = sizeof(thread.context);
  const Call *value_frame =
      thread.calls.empty() ? nullptr : thread.calls.back();
  const bool needs_return_values =
      value_frame &&
      (value_frame->parent || value_frame->summary.first ||
       value_frame->visit.first || value_frame->returning.first ||
       value_frame->deferred_call.first);
  const bool scope_context =
      duplicate_enabled && !needs_return_values &&
      (!within_active() || execution_mode() != 1) &&
      (!thread.pending.site || thread.pending.timing_only);
  thread.context.flags =
      scope_context
          ? static_cast<dr_mcontext_flags_t>(DR_MC_CONTROL | DR_MC_INTEGER)
          : DR_MC_ALL;
  if (!dr_get_mcontext(context, &thread.context))
    fail("application context unavailable");
  ct_registers registers = registers_at(&thread.context, pc);
  Lock lock(analysis_lock);
  const auto previous_site = thread.pending.site;
  auto found = current_sites.find(pc);
  if (found != current_sites.end() && found->second->module->code_modified &&
      found->second->original_size) {
    Site &cached = *found->second;
    byte original[15];
    if (!ct_userspace_patch_read_original(pc, cached.original_size, original) ||
        std::memcmp(original, cached.original_bytes, cached.original_size)) {
      // Retirement erases current_sites and may release this Site. Keep its
      // owner alive until the replacement snapshot has been registered.
      auto owner = cached.module;
      if (owner->runtime_image) {
        retire_runtime_image(*owner);
        discover_runtime_image(context, pc);
      } else {
        invalidate_original_metadata(*owner);
      }
      found = current_sites.end();
    }
  }
  advance(thread, registers, pc,
          found != current_sites.end() ? found->second->values : nullptr);
  const int arrival_outcome =
      thread.arrival_pc == pc ? thread.arrival_outcome : -1;
  const bool assembly_arrival = thread.assembly_arrival_pc == pc;
  thread.assembly_arrival_pc = nullptr;
  const bool plt_marker_reported = thread.plt_marker_pc == pc;
  thread.plt_marker_pc = nullptr;
  const ArrivalAnnotation arrival_annotation = thread.annotation_pc == pc
                                                   ? thread.arrival_annotation
                                                   : ArrivalAnnotation::None;
  thread.arrival_pc = nullptr;
  thread.arrival_outcome = -1;
  thread.annotation_pc = nullptr;
  thread.arrival_annotation = ArrivalAnnotation::None;
  if (within_enabled) {
    if (!within_active() && inline_scope &&
        (!structural_instrumentation() || thread.calls.empty())) {
      auto *root = new Call;
      root->entry_sp = registers.gpr[7];
      root->within_synthetic = true;
      thread.calls.push_back(root);
    }
    if (!thread.calls.empty())
      thread.calls.back()->within_inline = inline_scope;
    update_within(thread);
    if (!within_active() && !thread.calls.empty() &&
        thread.calls.back()->within_synthetic)
      leave_call(thread, registers, false);
  }
  if (!within_active() && !structural_instrumentation())
    return;
  if (!structural_instrumentation() &&
      !trace_activated.load(std::memory_order_acquire)) {
    const Site::Mode selected = arming_mode_at(pc);
    // Skipped bodies can still own --within. Record their control boundaries
    // before the first detailed observation so a tail or RET ends that scope.
    if (selected == Site::Skip && !entry_boundary)
      return;
    if (selected == Site::Into)
      trace_activated.store(true, std::memory_order_release);
  }
  std::shared_ptr<Site> site;
  if (found != current_sites.end()) {
    site = found->second;
  } else {
    Module *module = discover_runtime_image(context, pc);
    if (!module) {
      if (!thread.calls.empty())
        close_deferred_call(*thread.calls.back());
      close_plt(current_machine(thread), current_visit(thread));
      return;
    }
    site = std::make_shared<Site>(module->shared_from_this(),
                                  prepare_location(*module, pc));
    site->instruction.pc = pc;
    current_sites.emplace(pc, site);
  }
  prepare_site(*site, context, false);
  MachineContext &observed_machine = current_machine(thread);
  if (ct_perfetto_enabled()) {
    if (observed_machine.trace_comparison_next != pc) {
      observed_machine.trace_comparison = {};
      observed_machine.trace_comparison_next = nullptr;
    }
    if (site->instruction.opcode == OP_cmp ||
        site->instruction.opcode == OP_test) {
      observed_machine.trace_comparison =
          ct_capture_branch_condition(site->instruction, registers);
      observed_machine.trace_comparison_next = site->instruction.next;
    }
  }
  if (observed_machine.plt_last &&
      (!site->location.is_plt ||
       observed_machine.plt_last->module != site->module))
    close_plt(observed_machine, current_visit(thread));
  // Assembly traces show the transit instructions, while decompiled traces
  // fold linkage into the call like verified source traces. Neither policy
  // changes the actual callee's inherited filter state.
  const bool visible_plt = !decompile && site->location.is_plt &&
                           (assembly_arrival || observed_machine.plt_last);
  if (!thread.calls.empty() && thread.calls.back()->frame_base_restored)
    registers.unavailable_gpr |= UINT64_C(1) << 6;
  Visit &body = current_visit(thread);
  TraceScope &scope =
      thread.calls.empty() ? thread.root_scope : thread.calls.back()->scope;
  const char *physical_name = site->location.scope_chain_size
                                  ? site->location.scope_chain
                                  : site->location.symbol;
  if (!thread.calls.empty()) {
    Call &frame = *thread.calls.back();
    const bool source_linkage = frame.parent && frame.parent->first &&
                                frame.parent->source &&
                                source_available(*frame.parent->first);
    if (site->location.is_plt && !visible_plt && !frame.linkage_child &&
        (decompile || source_linkage)) {
      frame.source_linkage |= source_linkage;
      frame.linkage = true;
    }
    if (frame.linkage && !site->location.is_plt &&
        registers.gpr[7] == frame.entry_sp && previous_site &&
        previous_site->instruction.branch) {
      const char *previous_name = previous_site->location.scope_chain_size
                                      ? previous_site->location.scope_chain
                                      : previous_site->location.symbol;
      // The lazy resolver restores both PLT-pushed words before tail-jumping
      // to the target. The original stack position also identifies targets
      // without symbols; merely restoring RSP inside the resolver does not.
      if (previous_site->location.is_plt ||
          previous_site->module != site->module ||
          strcmp(previous_name, physical_name) != 0)
        frame.linkage = false;
    }
    if (frame.linkage || frame.linkage_child) {
      close_plt(current_machine(thread), body);
      defer_return(thread, body);
      close_visit(body);
      flush_decompiled_rows(current_machine(thread));
      thread.pending = Pending{
          site,          &body,         registers, &current_provenance(thread),
          scope.recurse, scope.blocked, true};
      if (duplicate_enabled) {
        suspend_observation(thread);
        if (!site->instruction.call && !site->instruction.ret &&
            !site->instruction.branch)
          thread.pending = {};
      }
      return;
    }
  }
  const bool entering_scope =
      !scope.initialized || scope.module != site->module ||
      scope.function != physical_name || scope.plt != site->location.is_plt;
  if (within_enabled && entering_scope && !site->location.is_plt &&
      !thread.calls.empty()) {
    Call &frame = *thread.calls.back();
    const bool startup_tail =
        previous_site && startup_owns_instruction(frame, *previous_site) &&
        previous_site->instruction.branch && !previous_site->instruction.call &&
        !previous_site->instruction.ret;
    if ((frame.within || (within_intr && frame.signal_handler_active)) &&
        frame.function &&
        (startup_tail ||
         (!frame.startup_entry && registers.gpr[7] >= frame.entry_sp))) {
      // Not every tail target starts at a wrapped entry. Compare physical
      // identities as well so a jump into another function's interior cannot
      // keep the departed matching frame active. A deeper original-code
      // callee can have no recorded frame, so its different identity alone
      // does not prove that this matching ancestor departed.
      auto entry = std::make_unique<ct_location>();
      ct_analysis_lookup(frame.function->module->analysis,
                         frame.function->pc - frame.function->module->start,
                         entry.get());
      const char *entry_name =
          entry->scope_chain_size ? entry->scope_chain : entry->symbol;
      if (frame.function->module != site->module ||
          (entry_name[0] && physical_name[0] &&
           std::strcmp(entry_name, physical_name) != 0)) {
        frame.within = false;
        frame.signal_handler_active = false;
        update_within(thread);
        if (!within_active() && !structural_instrumentation()) {
          end_trace_function(frame.machine, thread.trace_timestamp,
                             "tail_transfer");
          thread.pending = Pending{};
          if (!frame.signal_frame)
            leave_call(thread, registers, false);
          return;
        }
      }
    }
  }
  if (entering_scope) {
    const bool nested_userspace_transit =
        !thread.calls.empty() &&
        registers.gpr[7] < thread.calls.back()->entry_sp;
    // A raw nested callee may have no tracing frame of its own. Keep the
    // recorded ancestor's function slice open while execution remains below
    // its entry stack position. A real tail transfer restores that position.
    if (scope.initialized && !nested_userspace_transit)
      end_trace_function(current_machine(thread), thread.trace_timestamp,
                         "tail_transfer");
    if (scope.initialized) {
      flush_machine_rows(current_machine(thread));
      flush_decompiled_rows(current_machine(thread));
      if (!current_machine(thread).blocks.empty())
        close_visit(body);
      close_machine_blocks(current_machine(thread));
      current_machine(thread).comparison = {};
    }
    scope.case_groups.clear();
    auto &blocks =
        thread.calls.empty() ? thread.blocks : thread.calls.back()->blocks;
    if (scope.initialized && !blocks.empty()) {
      defer_return(thread, body);
      close_visit(body);
      close_blocks(blocks, 0, nullptr,
                   thread.calls.empty() ? nullptr : thread.calls.back());
    }
    // A changed physical function with the same machine call frame is a
    // tail transfer. Its inherited recursive scope lasts until this frame
    // returns; an explicit step-over can still hide that tail subtree.
    scope.initialized = true;
    scope.module = site->module;
    scope.function = physical_name;
    scope.plt = site->location.is_plt;
    scope.mode = decompile && site->location.is_plt ? Site::Skip
                 : visible_plt                      ? Site::Into
                               : enter_scope(site->physical_mode, scope.recurse,
                                             scope.blocked);
  }
  Site::Mode mode = scope.mode;
  bool recurse = scope.recurse, blocked = scope.blocked;
  if (!site->location.is_plt && !thread.calls.empty()) {
    Call &frame = *thread.calls.back();
    if (!frame.source_policy_seen && frame.parent && frame.parent->source) {
      frame.source_policy_seen = true;
      frame.source_step_over = scope.mode == Site::Over;
      frame.source_skipped = scope.mode == Site::Skip;
    }
  }
  // Inline scopes have no machine call frame: apply their policy only while
  // the instruction belongs to that chain, including calls made inside it.
  for (Site::Mode inline_mode : site->inline_modes)
    mode = enter_scope(inline_mode, recurse, blocked);
  if (!within_active())
    mode = Site::Skip;
  // Source-call folding below suppresses duplicate terminal summaries; it
  // must not change which function Perfetto records. Body scopes follow the
  // same effective filter decision, independently of the prepared code level.
  const Site::Mode trace_mode = mode;
  current_machine(thread).trace_body = trace_mode == Site::Into;
  if (ct_perfetto_enabled() && !within_active())
    end_trace_function(current_machine(thread), thread.trace_timestamp,
                       "scope_exit");
  const bool quiet_body = duplicate_enabled && !site->location.is_plt &&
                          (mode == Site::Skip || mode == Site::Over);
  if (quiet_body && within_active()) {
    suspend_observation(thread);
  } else if (duplicate_enabled && within_active()) {
    execution_mode() = 1;
  }
  // A folded PLT call already has a source row with its observed arguments
  // and result. Keep step-over's body policy without a duplicate summary.
  if (mode == Site::Over && !thread.calls.empty() &&
      thread.calls.back()->source_linkage)
    mode = Site::Skip;
  if (mode == Site::Over && !thread.calls.empty() &&
      thread.calls.back()->parent && thread.calls.back()->parent->source)
    mode = Site::Skip;
  if (!site->location.is_plt && !thread.calls.empty()) {
    Call &call = *thread.calls.back();
    if (call.deferred_call.first && !call.deferred_target) {
      call.deferred_target = site;
      call.deferred_function = call.function;
      call.deferred_mode = mode;
    }
    if (mode == Site::Into)
      close_deferred_call(call, true, &site->location);
    else if (mode == Site::Over && call.deferred_call.first)
      mode = Site::Skip; // The caller row owns this call's completion summary.
  }
  if (mode == Site::Into && !thread.calls.empty()) {
    const Call &frame = *thread.calls.back();
    Visit *parent = frame.parent;
    if (frame.returning.first && frame.returning_function != frame.function)
      parent = &thread.calls.back()->returning;
    if (parent && parent->first && parent->source && !parent->summary &&
        !parent->function_closing && !parent->provisional &&
        !parent->before_line.empty() && source_available(*parent->first)) {
      // The destination is known here even for indirect and PLT calls.
      // Apply the effective stepping policy before printing any callee rows.
      const char *name = !frame.display_name.empty()
                             ? frame.display_name.c_str()
                         : site->location.function[0] ? site->location.function
                                                      : site->location.symbol;
      auto highlighted = highlight_step_into_call(parent->before_line,
                                                  parent->comment_offset, name);
      if (!parent->have_before)
        highlighted.second = highlighted.first.size() + 1;
      highlighted.first += parent->have_before ? " -> ..." : " # -> ...";
      write_line(highlighted.first + "\n", highlighted.second,
                 &parent->first->location, -1, std::string::npos,
                 &parent->macro_values, -1, &parent->input_types,
                 std::string::npos, 0, parent->closing_context,
                 &parent->visible_declarations);
      if (parent->declared_function)
        parent->declared_function->function_type_reported = true;
      parent->provisional = true;
    }
  }
  if (mode != Site::Skip && scope.mode == Site::Over &&
      site->location.inlined && !thread.calls.empty()) {
    Call &frame = *thread.calls.back();
    if (frame.function && frame.function->module == site->module &&
        !frame.summary.first) {
      // An optimized function can enter directly in an inline child. Keep
      // the physical call summary independent from that child's selection;
      // the text is a summary, not a recovered source declaration.
      Visit &summary = frame.summary;
      summary.first = summary.last = site;
      summary.summary = true;
      summary.values = frame.arguments;
      named_value_types(nullptr, frame.function->type, summary.values,
                        summary.input_types);
      summary.have_before = !summary.values.empty();
      frame.summary_function = frame.function;
      frame.summary_arguments = frame.arguments;
      summary.before_line =
          location_prefix(context, frame.function->pc, *frame.function->module,
                          site->location, frame.function->name.c_str(),
                          site->location.line) +
          frame.function->name + "(...)";
      if (summary.have_before) {
        summary.comment_offset = summary.before_line.size() + 1;
        summary.before_line += " # " + summary.values;
      }
    }
  }
  if (body.summary && body.inlined && body.first &&
      (body.first->module != site->module ||
       body.first->location.function_id != site->location.function_id))
    close_visit(body);
  if (ct_perfetto_enabled() && !site->location.is_plt &&
      trace_mode != Site::Skip && !current_machine(thread).trace_function) {
    const Call *frame = thread.calls.empty() ? nullptr : thread.calls.back();
    const auto level =
        ct_required_instrumentation(ct_perfetto_enabled(), mode == Site::Into);
    const auto *display = trace_mode == Site::Into
                              ? prepare_decompiled_display(*site, level)
                              : nullptr;
    std::string name = display && display->function_name[0]
                           ? display->function_name
                           : physical_name;
    if (!display && frame && frame->function &&
        frame->function->module == site->module &&
        !frame->display_name.empty() &&
        (!physical_name[0] || frame->display_symbol == physical_name))
      name = frame->display_name;
    if (name.empty()) {
      char label[32];
      dr_snprintf(label, sizeof(label), "L%llx",
                  static_cast<unsigned long long>(
                      reinterpret_cast<uintptr_t>(site->instruction.pc)));
      name = label;
    }
    current_machine(thread).trace_function_name = name;
    current_machine(thread).trace_function = ct_perfetto_begin(
        thread.trace_timestamp, "ctrace.function", name.c_str(),
        site->module->path.c_str(), site->location.file, site->location.line,
        reinterpret_cast<uint64_t>(site->instruction.pc),
        source_available(*site) ? "source"
        : display               ? "decompiled"
                                : "machine",
        display && display->prototype[0] ? display->prototype : nullptr);
  }
  const bool summary_started =
      !thread.calls.empty() && thread.calls.back()->summary.first;
  if (structural_instrumentation() &&
      (mode == Site::Skip || (mode == Site::Over && summary_started))) {
    MachineContext &machine = current_machine(thread);
    machine.timing_only = true;
    const bool source = !site->location.is_plt && source_available(*site);
    // Only an immediately preceding observed CMP/TEST can name this branch's
    // predicate. Other paths retain the flags expression instead of carrying
    // a stale comparison through writes or a jump into the conditional branch.
    if (machine.timing_comparison_next != pc) {
      machine.comparison = {};
      machine.timing_comparison_next = nullptr;
    }
    if (machine.trace_body && !source &&
        (site->instruction.opcode == OP_cmp ||
         site->instruction.opcode == OP_test)) {
      machine.comparison =
          ct_capture_branch_condition(site->instruction, registers);
      machine.comparison_pc = pc;
      machine.timing_comparison_next = site->instruction.next;
    }
    if (source || !machine.trace_body) {
      close_machine_blocks(machine);
    } else {
      machine_case(machine, *site);
      close_machine_blocks(machine, site.get());
      for (auto &block : machine.blocks)
        block.last = site;
    }
    trace_source_blocks(machine, *site, source);
    if (!thread.calls.empty() && !thread.calls.back()->visit.first &&
        !thread.calls.back()->summary.first)
      thread.calls.back()->timing_only = true;
    thread.pending = {};
    if (site->instruction.call || site->instruction.ret ||
        site->instruction.branch) {
      thread.pending.site = site;
      thread.pending.visit = &body;
      thread.pending.before = registers;
      thread.pending.recurse = within_active() && recurse;
      thread.pending.blocked = within_active() && blocked;
      thread.pending.timing_only = true;
      thread.pending.timing_source = source;
    }
    return;
  }
  if (mode == Site::Skip) {
    close_plt(current_machine(thread), body);
    flush_machine_rows(current_machine(thread));
    if (!body.summary) {
      defer_return(thread, body);
      close_visit(body);
    }
    flush_decompiled_rows(current_machine(thread));
    close_machine_blocks(current_machine(thread));
    current_machine(thread).comparison = {};
    thread.pending = Pending{
        site, &body, registers, &current_provenance(thread), recurse, blocked};
    if (quiet_body && !site->instruction.call && !site->instruction.ret &&
        !site->instruction.branch)
      thread.pending = {};
    return;
  }
  current_machine(thread).timing_only = false;
  if (!thread.calls.empty())
    thread.calls.back()->timing_only = false;
  prepare_site(*site, context, true);
  if (scope_context) {
    thread.context.flags = DR_MC_ALL;
    if (!dr_get_mcontext(context, &thread.context))
      fail("application context unavailable");
    registers = registers_at(&thread.context, pc);
  }
  const bool summary = mode == Site::Over;
  const bool separate_summary =
      summary && !site->location.inlined && !thread.calls.empty();
  // Signal restorers can execute in the synthetic handler frame. Its saved
  // function belongs to the handler, not to a restorer in another module.
  std::shared_ptr<Function> summary_function =
      separate_summary && thread.calls.back()->function &&
              thread.calls.back()->function->module == site->module
          ? thread.calls.back()->function
          : nullptr;
  if (separate_summary) {
    Call &frame = *thread.calls.back();
    const bool changed =
        frame.summary_function || summary_function
            ? frame.summary_function != summary_function
            : frame.summary.first &&
                  (frame.summary.first->module != site->module ||
                   frame.summary.first->location.function_id !=
                       site->location.function_id ||
                   strcmp(frame.summary.first->location.function,
                          site->location.function) != 0);
    if (frame.summary.first && changed) {
      frame.tail_summaries.push_back({std::move(frame.summary),
                                      frame.summary_function,
                                      std::move(frame.summary_arguments)});
      frame.summary = Visit{};
    }
  }
  Visit &visit = separate_summary ? thread.calls.back()->summary : body;
  const bool source = !visible_plt && source_available(*site);
  MachineContext &machine = current_machine(thread);
  bool decompiled = !source && !summary && decompile_site(*site, context);
  if (decompiled && site->instruction.ret && !thread.calls.empty()) {
    const auto &function = thread.calls.back()->function;
    if ((function && function->module == site->module &&
         ct_function_return_unsupported(function->type)) ||
        (site->decompiled_variables &&
         site->decompiled_variables->return_unsupported))
      decompiled = false;
  }
  if (!decompiled)
    flush_decompiled_rows(machine);
  const Call *display_frame =
      thread.calls.empty() ? nullptr : thread.calls.back();
  machine.decompiled_operands.clear();
  machine.decompiled_owner.reset();
  if (decompile && !source && !summary)
    resolve_decompiled_operands(machine, *site, registers, display_frame,
                                current_provenance(thread));
  machine.function_alias.clear();
  if (display_frame && display_frame->function &&
      display_frame->function->module == site->module &&
      !site->location.inlined && !site->location.is_plt &&
      !display_frame->display_name.empty() &&
      (!physical_name[0] || display_frame->display_symbol == physical_name))
    machine.function_alias = display_frame->display_name;
  if (!machine.function_alias.empty())
    machine.scope_name = machine.function_alias;
  else if (site->location.function[0] || site->location.symbol[0])
    machine.scope_name = site->location.function[0] ? site->location.function
                                                    : site->location.symbol;
  else if (display_frame && display_frame->function &&
           display_frame->function->module == site->module)
    machine.scope_name = display_frame->function->name;
  else if (display_frame && display_frame->entry_pc) {
    char label[32];
    dr_snprintf(label, sizeof(label), "L%llx",
                static_cast<unsigned long long>(
                    reinterpret_cast<uintptr_t>(display_frame->entry_pc)));
    machine.scope_name = label;
  } else
    machine.scope_name = "<unknown>";
  if (source || summary) {
    close_plt(machine, body);
    close_machine_blocks(machine);
    machine.comparison = {};
  } else {
    machine_case(machine, *site);
    close_machine_blocks(machine, site.get());
    const auto update = site->module->flow_updates.find(pc);
    const auto initializer = site->module->flow_initializers.find(pc);
    if (update != site->module->flow_updates.end() ||
        initializer != site->module->flow_initializers.end()) {
      flush_machine_rows(machine);
      machine.update_module = site->module;
      machine.update_branch = update != site->module->flow_updates.end()
                                  ? update->second
                                  : initializer->second;
      machine.update_next = pc;
    }
    for (auto &block : machine.blocks)
      block.last = site;
  }
  trace_source_blocks(machine, *site, source && !summary);
  if (source && !summary && site->location.entry_declaration[0] &&
      !site->location.declaration[0] &&
      (thread.calls.empty() || !thread.calls.back()->entry_reported)) {
    // Optimized entries can share their PC with the first executable line.
    // Display the declaration without replacing that instruction's source.
    close_visit(visit);
    std::string text =
        location_prefix(context, site->instruction.pc, *site->module,
                        site->location, site->location.function,
                        site->location.entry_declaration_line) +
        "\033[42;97m" + site->location.entry_declaration + "\033[0m";
    size_t comment = std::string::npos;
    if (!thread.calls.empty() && !site->location.inlined) {
      Call &frame = *thread.calls.back();
      if (!frame.entry_arguments.empty()) {
        comment = text.size() + 1;
        text += " # " + frame.entry_arguments;
      }
      frame.entry_reported = true;
    }
    std::vector<OperandType> parameter_types, declarations;
    if (!site->location.inlined && !thread.calls.empty()) {
      Call &frame = *thread.calls.back();
      named_value_types(site->values,
                        frame.function ? frame.function->type : nullptr,
                        frame.entry_arguments, frame.entry_types);
      parameter_types = frame.entry_types;
      declarations = parameter_types;
      for (auto &entry : declarations)
        entry.offset = std::string::npos;
    }
    write_line(text + "\n", comment, nullptr, -1, std::string::npos, nullptr,
               -1, &parameter_types, std::string::npos, 0, {}, &declarations);
    if (!site->location.inlined && !thread.calls.empty()) {
      const auto &function = thread.calls.back()->function;
      if (function && function->module == site->module)
        function->function_type_reported = true;
    }
  }
  std::vector<const ct_source_case *> case_labels;
  if (source && !summary && site->location.source_case_count) {
    std::set<std::pair<TraceScope::CaseKey, uint64_t>> entered;
    for (uint32_t index = 0; index < site->location.source_case_count;
         ++index) {
      const auto &label = site->location.source_cases[index];
      const TraceScope::CaseKey key{
          site->module->incarnation, site->location.source_id,
          site->location.function_id, label.switch_id};
      auto &current = scope.case_groups[key];
      if (!label.group_id) {
        // An observed dispatch resets only this switch. Missing annotations
        // on optimized instructions or inline calls do not imply a re-entry.
        current = 0;
        continue;
      }
      if (current != label.group_id) {
        current = label.group_id;
        entered.emplace(key, label.group_id);
      }
      if (label.text[0] && entered.count({key, label.group_id}))
        case_labels.push_back(&label);
    }
  }
  auto &blocks =
      thread.calls.empty() ? thread.blocks : thread.calls.back()->blocks;
  std::vector<const ct_source_block *> current_blocks;
  if (source && !summary)
    for (size_t index = 0; index < site->location.source_block_count; ++index) {
      const auto &block = site->location.source_blocks[index];
      if (block.opening_line < block.closing_line &&
          site->location.line <= block.closing_line)
        current_blocks.push_back(&block);
    }
  // A changed line number alone is not a lexical exit: schedulers move
  // unrelated instructions between a block's computation and final store.
  // Only bridge observed fallthrough inside its source-associated PC extent;
  // this never opens an unobserved block or crosses a taken branch.
  size_t prefix = 0;
  while (prefix < current_blocks.size() && prefix < blocks.size() &&
         blocks[prefix]->entry->module == site->module &&
         strcmp(blocks[prefix]->entry->location.file, site->location.file) ==
             0 &&
         strcmp(blocks[prefix]->entry->location.function,
                site->location.function) == 0 &&
         blocks[prefix]->description.id == current_blocks[prefix]->id)
    ++prefix;
  if (!summary && prefix == current_blocks.size()) {
    for (size_t index = prefix; index < blocks.size(); ++index) {
      const SourceBlock &block = *blocks[index];
      const ct_source_block &description = block.description;
      const auto offset = static_cast<uint64_t>(pc - site->module->start);
      if (block.entry->module != site->module ||
          !source_available(*block.entry) || !description.has_address_range ||
          offset < description.begin_offset ||
          offset >= description.end_offset ||
          block.last->instruction.next != pc ||
          (block.last->instruction.branch &&
           !block.last->instruction.conditional) ||
          block.last->instruction.ret)
        break;
      current_blocks.push_back(&description);
    }
  }
  const size_t block_count = current_blocks.size();
  size_t shared_blocks = 0;
  while (shared_blocks < blocks.size() && shared_blocks < block_count) {
    const SourceBlock &block = *blocks[shared_blocks];
    const bool retained = &block.description == current_blocks[shared_blocks];
    if (block.entry->module != site->module ||
        (!retained &&
         (strcmp(block.entry->location.file, site->location.file) != 0 ||
          strcmp(block.entry->location.function, site->location.function) !=
              0)) ||
        block.description.id != current_blocks[shared_blocks]->id)
      break;
    ++shared_blocks;
  }
  const bool blocks_changed =
      shared_blocks != blocks.size() || shared_blocks != block_count;
  if (blocks_changed) {
    // Complete the preceding source line before emitting its lexical exit.
    // Block state belongs to this call frame, so callees cannot close it.
    defer_return(thread, visit);
    close_visit(visit);
    close_blocks(blocks, shared_blocks, nullptr,
                 thread.calls.empty() ? nullptr : thread.calls.back());
  }
  if (source && !summary) {
    for (size_t index = 0; index < blocks.size(); ++index) {
      SourceBlock &block = *blocks[index];
      Visit &header = block.header;
      if (!header.first)
        continue;
      const bool same_header =
          block.entry->module == site->module &&
          strcmp(block.entry->location.file, site->location.file) == 0 &&
          strcmp(block.entry->location.function, site->location.function) ==
              0 &&
          block.description.start_line == site->location.line;
      if (same_header && !header.header_interruption && !header.provisional &&
          !header.visited.count(pc)) {
        // Resume this iteration's saved increment at its condition check.
        // Inputs/results retain their original snapshots; no value-based
        // deduplication is involved.
        close_visit(visit);
        visit = std::move(header);
        header = Visit{};
        visit.header_continuation = &header;
      } else if (same_header) {
        close_visit(header);
      }
    }
    flush_headers_before_body(blocks, *site);
  }
  if (!case_labels.empty()) {
    defer_return(thread, visit);
    close_visit(visit);
    flush_headers_before_body(blocks, *site);
    for (const auto *label : case_labels)
      write_line(location_prefix(context, site->instruction.pc, *site->module,
                                 site->location, site->location.function,
                                 label->line) +
                 "\033[42;97m" + label->text + "\033[0m\n");
  }
  if (blocks_changed) {
    for (size_t index = shared_blocks; index < block_count; ++index) {
      auto block = std::make_unique<SourceBlock>();
      block->description = *current_blocks[index];
      block->entry = block->last = site;
      const ct_source_block &description = block->description;
      if (description.opening_standalone ||
          description.kind == CT_SOURCE_BLOCK_STATEMENT_EXPRESSION) {
        std::string text =
            location_prefix(context, site->instruction.pc, *site->module,
                            site->location, site->location.function,
                            description.opening_line) +
            block_source(description, true);
        char values[value_capacity]{};
        ct_values_format_selected(site->values, &registers, read_memory,
                                  nullptr, description.variables,
                                  description.variables_size, values,
                                  sizeof(values));
        size_t comment = std::string::npos;
        if (values[0]) {
          comment = text.size() + 1;
          text += " # " + std::string(values);
        }
        std::vector<OperandType> input_types;
        named_value_types(site->values, nullptr, values, input_types);
        const auto declarations =
            site->location.line == description.opening_line
                ? source_declaration_types(*site)
                : std::vector<OperandType>{};
        write_line(text + "\n", comment, nullptr, -1, std::string::npos,
                   nullptr, -1, &input_types, std::string::npos, 0, {},
                   &declarations);
      }
      block->result.source = true;
      block->result.assignment = description.assignment;
      blocks.push_back(std::move(block));
    }
  }
  SourceBlock *boundary = nullptr;
  for (auto &block : blocks) {
    block->last = site;
    const ct_source_block &description = block->description;
    if (!source ||
        strcmp(block->entry->location.file, site->location.file) != 0 ||
        strcmp(block->entry->location.function, site->location.function) != 0)
      continue;
    if ((description.opening_line == site->location.line &&
         (description.opening_standalone ||
          description.kind == CT_SOURCE_BLOCK_STATEMENT_EXPRESSION)) ||
        (description.closing_line == site->location.line &&
         description.closing_standalone))
      boundary = block.get();
  }
  if (boundary) {
    // GCC commonly attributes the final destination store of ({ ... }) to
    // its opening line. Observe that store, but print it on the closing row.
    defer_return(thread, visit);
    close_visit(visit);
    Visit &result = boundary->result;
    if (boundary->description.kind == CT_SOURCE_BLOCK_STATEMENT_EXPRESSION) {
      result.source = true;
      result.assignment = boundary->description.assignment;
      if (!result.first)
        result.first = site;
      result.last = site;
      thread.pending =
          Pending{site,    &result, registers, &current_provenance(thread),
                  recurse, blocked};
    } else {
      thread.pending =
          Pending{site,    &body,  registers, &current_provenance(thread),
                  recurse, blocked};
    }
    return;
  }
  if (source && visit.first && visit.last && visit.source && !visit.summary &&
      !visit.provisional && !visit.control_flow &&
      visit.last->instruction.next == pc &&
      visit.first->module == site->module &&
      strcmp(visit.first->location.file, site->location.file) == 0 &&
      strcmp(visit.first->location.function, site->location.function) == 0) {
    for (const auto &block : blocks) {
      const ct_source_block &description = block->description;
      if (description.has_for_initializer && block->initial_header &&
          block->entry == visit.first &&
          visit.first->location.line == description.start_line &&
          site->location.line < description.start_line) {
        // An initial header fragment was hoisted ahead of pre-loop source
        // statements. Its state was observed by advance(); print the header
        // when execution actually reaches its control flow, not twice.
        visit = Visit{};
        block->initial_header = false;
        break;
      }
    }
  }
  bool continuation =
      visit.first &&
      (summary
           ? visit.summary
           : (visit.source && source && !visit.summary &&
              visit.first->module == site->module &&
              (visit.first->location.line == site->location.line ||
               (visit.first->location.declaration[0] &&
                site->location.declaration[0] &&
                visit.first->location.declaration_line ==
                    site->location.declaration_line)) &&
              strcmp(visit.first->location.file, site->location.file) == 0 &&
              strcmp(visit.first->location.function, site->location.function) ==
                  0 &&
              !visit.visited.count(site->instruction.pc)));
  // A C++ epilogue may revisit the return line after running destructors.
  // Resume the same evaluation instead of sampling its inputs a second time.
  if (!continuation && !summary && source && !thread.calls.empty()) {
    Call &frame = *thread.calls.back();
    const auto first = frame.returning.first;
    if (first && source_available(*first) && first->module == site->module &&
        first->location.line == site->location.line &&
        first->location.function_id == site->location.function_id &&
        strcmp(first->location.file, site->location.file) == 0 &&
        strcmp(first->location.expression, site->location.expression) == 0 &&
        !frame.returning.visited.count(site->instruction.pc)) {
      close_visit(visit);
      visit = std::move(frame.returning);
      frame.returning = Visit{};
      continuation = true;
    }
  }
  if (!continuation) {
    defer_return(thread, visit);
    Call *frame = thread.calls.empty() ? nullptr : thread.calls.back();
    const bool deferred_structure =
        source && !summary && site->location.structural && frame &&
        frame->returning.first && frame->returning_function == frame->function;
    // A source evaluation is emitted as one complete record when its outcome
    // is known, even when other threads or callees run in the meantime.
    close_visit(visit);
    if (source && !summary)
      flush_headers_before_body(blocks, *site);
    visit.first = site;
    visit.arrival_outcome = arrival_outcome;
    visit.source = source;
    visit.summary = summary;
    if (source && !summary) {
      for (size_t index = 0; index < site->location.source_closure_count;
           ++index) {
        const auto &closure = site->location.source_closures[index];
        visit.function_closing |=
            closure.function_body && site->location.structural;
        if (!closure.opening[0])
          continue;
        if (!visit.closing_context.empty())
          visit.closing_context += "; ";
        visit.closing_context +=
            closure.function_body
                ? (frame && !site->location.inlined &&
                           !frame->invocation.empty()
                       ? frame->invocation
                       : std::string(site->location.function) + "(?)")
                : closure.opening;
      }
      for (auto &block : blocks) {
        if (block->description.kind == CT_SOURCE_BLOCK_CONTROL &&
            block->description.start_line == site->location.line &&
            block->entry->module == site->module &&
            strcmp(block->entry->location.file, site->location.file) == 0 &&
            strcmp(block->entry->location.function, site->location.function) ==
                0) {
          visit.header_continuation = &block->header;
          break;
        }
      }
    }
    visit.inlined = site->location.inlined;
    visit.structural =
        !summary && source &&
        (site->location.structural || site->location.source_case_label_only);
    visit.values =
        source
            ? variable_values(*site, registers, visit.input_types)
            : machine_inputs(*site, registers, current_provenance(thread),
                             summary ? nullptr : &visit.input_types,
                             summary ? nullptr : &machine.decompiled_operands);
    if (source && !summary)
      visit.visible_declarations = source_declaration_types(*site);
    if (summary_function) {
      visit.values = thread.calls.back()->arguments;
      visit.input_types.clear();
      named_value_types(nullptr, summary_function->type, visit.values,
                        visit.input_types);
      thread.calls.back()->summary_function = summary_function;
      thread.calls.back()->summary_arguments = thread.calls.back()->arguments;
    } else if (separate_summary) {
      thread.calls.back()->summary_function = nullptr;
      thread.calls.back()->summary_arguments.clear();
    }
    const bool inline_definition_entry =
        source && !summary && frame && frame->function &&
        !site->location.inlined && !frame->entry_reported &&
        !site->location.declaration[0] &&
        site->instruction.pc == frame->function->pc &&
        std::any_of(site->location.source_closures.begin(),
                    site->location.source_closures.end(),
                    [](const ct_source_closure &closure) {
                      return closure.function_body;
                    });
    if (inline_definition_entry) {
      // A whole definition on one source line still begins before its
      // prologue has established the DWARF local-storage locations.
      visit.values = frame->entry_arguments;
      visit.input_types = frame->entry_types;
      for (auto entry : frame->entry_types) {
        entry.offset = std::string::npos;
        visit.visible_declarations.push_back(std::move(entry));
      }
      frame->entry_reported = true;
    }
    const uint64_t display_line = source && site->location.declaration[0]
                                      ? site->location.declaration_line
                                      : site->location.line;
    const char *display_function =
        summary_function                  ? summary_function->name.c_str()
        : !machine.function_alias.empty() ? machine.function_alias.c_str()
        : site->location.function[0]      ? site->location.function
                                          : machine.scope_name.c_str();
    const bool source_declaration = source && site->location.declaration[0];
    std::string text =
        location_prefix(context, site->instruction.pc, *site->module,
                        site->location, display_function, display_line);
    if (!source && !summary && arrival_annotation == ArrivalAnnotation::Call) {
      visit.function_length = std::strlen(display_function);
      // location_prefix ends with the function name followed by " | ".
      // Keep the exact span: C++ names can themselves contain spaces.
      visit.function_offset = text.size() - 3 - visit.function_length;
    }
    if (!source && !summary && frame && frame->function &&
        !frame->entry_reported && site->instruction.pc == frame->function->pc &&
        site->module == frame->function->module)
      decompiled_entry(*site, *frame, registers);
    if (!source && !summary && frame && frame->function &&
        !site->location.is_plt && !frame->entry_reported &&
        !frame->declaration.empty() &&
        site->instruction.pc == frame->function->pc &&
        site->module == frame->function->module) {
      flush_decompiled_rows(machine);
      named_value_types(site->values, frame->function->type,
                        frame->entry_arguments, frame->entry_types);
      std::string entry =
          text + "\033[42;97m" + frame->declaration + " {\033[0m";
      size_t comment = std::string::npos;
      if (!frame->entry_arguments.empty()) {
        comment = entry.size() + 1;
        entry += " # " + frame->entry_arguments;
      }
      auto declarations = frame->entry_types;
      for (auto &declaration : declarations)
        declaration.offset = std::string::npos;
      write_line(entry + "\n", comment, nullptr, -1, std::string::npos, nullptr,
                 -1, &frame->entry_types, std::string::npos, 0, {},
                 &declarations);
      if (frame->declaration.find('?') == std::string::npos)
        frame->function->function_type_reported = true;
      frame->entry_reported = true;
      frame->assembly_entry = frame->assembly_last = site;
      frame->assembly_scope = display_function;
      frame->assembly_invocation = frame->invocation;
    }
    if (!source && !summary && frame && frame->assembly_entry)
      frame->assembly_last = site;
    if (separate_summary) {
      text += std::string(display_function) + "(...)";
    } else if (source) {
      const char *code = site->location.declaration[0]
                             ? site->location.declaration
                             : site->location.text;
      while (std::isspace(static_cast<unsigned char>(*code)))
        ++code;
      if (source_declaration || inline_definition_entry) {
        if (!summary && frame && frame->function && !site->location.inlined &&
            frame->function->module == site->module)
          visit.declared_function = frame->function;
        const char *brace = std::strchr(code, '{');
        if (brace) {
          text += "\033[42;97m";
          text.append(code, brace - code);
          text += "\033[0m\033[42;97m{\033[0m";
          code = brace + 1;
          text += code;
        } else {
          text += "\033[42;97m";
          text += code;
          text += "\033[0m";
        }
      } else {
        text += "\033[32m";
        size_t offset = 0;
        const size_t length = std::strlen(code);
        for (size_t index = 0; index < site->location.source_highlight_count;
             ++index) {
          const ct_source_highlight &span =
              site->location.source_highlights[index];
          if (span.begin < offset || span.begin >= span.end ||
              span.end > length)
            continue;
          text.append(code + offset, span.begin - offset);
          text += "\033[42;97m";
          text.append(code + span.begin, span.end - span.begin);
          text += "\033[0m\033[32m";
          offset = span.end;
        }
        text += code + offset;
        text += "\033[0m";
      }
      if (site->location.conversion_error[0] &&
          warnings
              .insert(site->module->identity + ":asm:" + site->location.file +
                      ":" + std::to_string(site->location.line))
              .second)
        write_warning("Warning: " + site->module->path + ": " +
                      site->location.conversion_error + "\n");
    } else {
      std::string target_name;
      if (site->instruction.call) {
        for (const auto &operand : site->instruction.operands) {
          if (!opnd_is_pc(operand.value))
            continue;
          app_pc target = opnd_get_pc(operand.value);
          auto function = current_functions.find(target);
          if (function == current_functions.end())
            continue;
          auto target_storage = std::make_unique<ct_location>();
          ct_location &target_location = *target_storage;
          ct_analysis_lookup(function->second->module->analysis,
                             target - function->second->module->start,
                             &target_location);
          target_name = target_location.symbol[0] ? target_location.symbol
                                                  : function->second->name;
          break;
        }
      }
      const std::string assembly = ct_format_assembly(
          site->instruction, site->values, site->next_values, registers,
          read_memory, nullptr, syntax, nullptr, &current_provenance(thread),
          target_name.c_str(), &machine.decompiled_operands);
      if (site->location.is_plt && !assembly.empty()) {
        if (!machine.plt_last && !plt_marker_reported) {
          flush_machine_rows(machine);
          flush_decompiled_rows(machine);
          std::string name = site->location.plt_symbol;
          if (name.empty()) {
            char label[32];
            dr_snprintf(label, sizeof(label), "L%llx",
                        static_cast<unsigned long long>(
                            reinterpret_cast<uintptr_t>(site->instruction.pc)));
            name = label;
          }
          std::string marker =
              location_prefix(context, site->instruction.pc, *site->module,
                              site->location, display_function, display_line);
          const size_t comment = marker.size();
          marker += "# /* " + name + "@plt */\n";
          write_line(marker, comment);
        }
        machine.plt_last = site;
      }
      visit.code_offset = text.size();
      std::string code =
          decompile && !site->location.is_plt
              ? ct_format_decompiled_instruction(
                    site->instruction, site->values, site->next_values,
                    registers, read_memory, nullptr, nullptr,
                    &current_provenance(thread), &machine.decompiled_operands)
              : std::string{};
      if (decompile && !site->location.is_plt && code.empty() &&
          (site->instruction.opcode == OP_jmp ||
           site->instruction.opcode == OP_jmp_short)) {
        for (const auto &operand : site->instruction.operands)
          if (opnd_is_pc(operand.value)) {
            char label[32];
            dr_snprintf(
                label, sizeof(label), "L%llx",
                static_cast<unsigned long long>(
                    reinterpret_cast<uintptr_t>(opnd_get_pc(operand.value))));
            code = "goto " + std::string(label) + ";";
            break;
          }
      }
      if (decompile && !site->location.is_plt && code.empty() &&
          (site->instruction.opcode == OP_nop ||
           site->instruction.opcode == OP_nop_modrm))
        code = ";";
      if (decompile && !site->location.is_plt && code.empty() &&
          site->instruction.ret) {
        std::string value;
        OperandType display_type;
        code = decompiled_return(*site, frame, registers, value, display_type);
        visit.return_void = code == "return;";
        if (!value.empty()) {
          if (!visit.values.empty())
            visit.values += ", ";
          if (!display_type.identity.empty()) {
            display_type.offset = visit.values.size() + value.find('=') + 1;
            visit.input_types.push_back(std::move(display_type));
          }
          visit.values += value;
        }
      }
      if (code.empty()) {
        visit.assembly_offset = text.size();
        text += assembly;
      } else {
        text += "\033[32m" + code + "\033[0m";
      }
      if (decompiled)
        visit.decompile_machine = &machine;
    }
    if (!visit.structural) {
      visit.have_before = !visit.values.empty();
      if (visit.have_before) {
        visit.comment_offset = text.size() + 1;
        text += " # " + visit.values;
      }
      visit.before_line = std::move(text);
    } else {
      if (site->location.source_case_label_only) {
        // The synthetic label already covers this source-only row.
      } else if (source_declaration && frame && frame->entry_reported &&
                 !site->location.inlined) {
        // Optimized prologue fragments can revisit the same declaration.
      } else if (deferred_structure)
        frame->return_lines.push_back({text + "\n", visit.closing_context});
      else if (visit.function_closing) {
        // Optimized epilogues can map to the closing brace rather than a
        // return statement. Keep this row until RET supplies the typed result.
        visit.structural = false;
        visit.values.clear();
        visit.before_line = std::move(text);
      } else {
        size_t comment = std::string::npos;
        if (source_declaration && frame && !site->location.inlined &&
            !frame->entry_reported) {
          if (!frame->entry_arguments.empty()) {
            comment = text.size() + 1;
            text += " # " + frame->entry_arguments;
          }
          visit.input_types = frame->entry_types;
          for (auto entry : frame->entry_types) {
            entry.offset = std::string::npos;
            visit.visible_declarations.push_back(std::move(entry));
          }
          frame->entry_reported = true;
        }
        write_line(text + "\n", comment, nullptr, -1, std::string::npos,
                   nullptr, visit.arrival_outcome, &visit.input_types,
                   std::string::npos, 0, visit.closing_context,
                   &visit.visible_declarations);
        if (source_declaration && frame && frame->function &&
            !site->location.inlined && frame->function->module == site->module)
          frame->function->function_type_reported = true;
      }
    }
  }
  visit.last = site;
  visit.control_flow |= site->instruction.branch || site->instruction.call ||
                        site->instruction.ret || site->instruction.syscall;
  visit.header_interruption |= site->instruction.call ||
                               site->instruction.ret ||
                               site->instruction.syscall;
  for (auto &block : blocks)
    if (visit.control_flow ||
        (site->location.line >= block->description.first_body_line &&
         site->location.line <= block->description.closing_line))
      block->initial_header = false;
  if (!summary)
    visit.visited.insert(site->instruction.pc);
  thread.pending = Pending{site,      separate_summary ? &body : &visit,
                           registers, &current_provenance(thread),
                           recurse,   blocked};
  if (!source && !summary) {
    thread.pending.decompiled_operands = machine.decompiled_operands;
    thread.pending.decompiled_owner = machine.decompiled_owner;
  }
  if (quiet_body && !site->instruction.call && !site->instruction.ret &&
      !site->instruction.branch)
    thread.pending = {};
}

enum UserspaceRole : unsigned {
  UserspaceCall = 1,
  UserspaceReturn = 2,
  UserspaceSyscall = 4,
  UserspaceBranch = 8,
  UserspaceConditional = 16,
  UserspaceDirect = 32,
  UserspaceOrdinaryReturn = 64,
  UserspaceCompare = 128,
};

struct UserspaceInstruction {
  app_pc pc = nullptr;
  size_t length = 0;
  unsigned role = 0;
  intptr_t target_delta = 0;
  byte original[15]{};
  bool writes_sp = false, writes_bp = false;
  unsigned sp_source = 0, bp_source = 0, stack_write_base = 0;
  int64_t sp_adjust = 0, bp_adjust = 0, stack_write_offset = 0;
  size_t stack_write_size = 0;
};

struct UserspaceGraph {
  Module *module = nullptr;
  uint64_t generation = 0;
  app_pc begin = nullptr, end = nullptr;
  std::map<app_pc, UserspaceInstruction> instructions;
  std::set<app_pc> targets;
};

// Only stack/frame-pointer relationships are tracked. Unknown write addresses
// can alias the saved return slot and conservatively require a return gate.
static void describe_userspace_stack(instr_t &decoded,
                                     UserspaceInstruction &instruction) {
  const int opcode = instr_get_opcode(&decoded);
  unsigned stack_destinations = 0;
  bool full_stack = false, full_frame = false;
  size_t pushed = 0, popped = 0;
  for (int index = 0; index < instr_num_dsts(&decoded); ++index) {
    const opnd_t operand = instr_get_dst(&decoded, index);
    if (opnd_is_reg(operand)) {
      const reg_id_t reg = opnd_get_reg(operand);
      if (reg_overlap(reg, DR_REG_RSP)) {
        instruction.writes_sp = true;
        full_stack |= reg == DR_REG_RSP;
        ++stack_destinations;
      }
      if (reg_overlap(reg, DR_REG_RBP)) {
        instruction.writes_bp = true;
        full_frame |= reg == DR_REG_RBP;
      }
    } else if (opnd_is_base_disp(operand)) {
      const reg_id_t base = opnd_get_base(operand),
                     index = opnd_get_index(operand);
      const bool stack = base != DR_REG_NULL && reg_overlap(base, DR_REG_RSP);
      const bool frame = base != DR_REG_NULL && reg_overlap(base, DR_REG_RBP);
      const bool indexed =
          index != DR_REG_NULL &&
          (reg_overlap(index, DR_REG_RSP) || reg_overlap(index, DR_REG_RBP));
      if (stack || frame || indexed) {
        const size_t size = opnd_size_in_bytes(opnd_get_size(operand));
        const bool simple = index == DR_REG_NULL &&
                            opnd_get_segment(operand) == DR_REG_NULL && size &&
                            (base == DR_REG_RSP || base == DR_REG_RBP);
        if (instruction.stack_write_base || !simple || opcode == OP_pop) {
          instruction.stack_write_base = 3;
        } else {
          instruction.stack_write_base = stack ? 1 : 2;
          instruction.stack_write_offset = opnd_get_disp(operand);
          instruction.stack_write_size = size;
        }
        if (stack)
          pushed = size;
      } else if (base != DR_REG_NULL || index != DR_REG_NULL) {
        // This also catches a return-slot address copied from RSP into a
        // general register. Do not assume arbitrary pointer stores miss it.
        instruction.stack_write_base = 3;
      }
    } else if (opnd_is_memory_reference(operand) &&
               !opnd_is_rel_addr(operand) && !opnd_is_abs_addr(operand)) {
      instruction.stack_write_base = 3;
    }
  }
  for (int index = 0; index < instr_num_srcs(&decoded); ++index) {
    const opnd_t operand = instr_get_src(&decoded, index);
    if (opnd_is_base_disp(operand) && opnd_get_base(operand) == DR_REG_RSP &&
        opnd_get_index(operand) == DR_REG_NULL)
      popped = opnd_size_in_bytes(opnd_get_size(operand));
  }
  if (instruction.role & UserspaceCall) {
    // A normal ABI call's fallthrough has the original RSP/RBP. Its explicit
    // pushed return address above is still checked against this frame's slot.
    instruction.writes_sp = false;
    instruction.writes_bp = false;
    return;
  }
  if (instruction.role & UserspaceReturn)
    return;
  if ((opcode == OP_push || opcode == OP_push_imm || opcode == OP_pushf) &&
      full_stack && (pushed == 8 || pushed == 2)) {
    instruction.sp_source = 1;
    instruction.sp_adjust = -int64_t(pushed);
  } else if ((opcode == OP_pop || opcode == OP_popf) && full_stack &&
             stack_destinations == 1 && (popped == 8 || popped == 2)) {
    instruction.sp_source = 1;
    instruction.sp_adjust = int64_t(popped);
  } else if (opcode == OP_leave && full_stack && full_frame) {
    bool pointer_read = false;
    for (int index = 0; index < instr_num_srcs(&decoded); ++index) {
      const opnd_t operand = instr_get_src(&decoded, index);
      pointer_read |= opnd_is_memory_reference(operand) &&
                      opnd_size_in_bytes(opnd_get_size(operand)) == 8;
    }
    if (pointer_read) {
      instruction.sp_source = 2;
      instruction.sp_adjust = 8;
    }
  } else if ((opcode == OP_mov_ld || opcode == OP_mov_st || opcode == OP_lea) &&
             instr_num_dsts(&decoded) == 1 && instr_num_srcs(&decoded) == 1) {
    const opnd_t source = instr_get_src(&decoded, 0);
    unsigned base = 0;
    int64_t displacement = 0;
    if (opcode != OP_lea && opnd_is_reg(source)) {
      const reg_id_t reg = opnd_get_reg(source);
      base = reg == DR_REG_RSP ? 1 : reg == DR_REG_RBP ? 2 : 0;
    } else if (opcode == OP_lea && opnd_is_base_disp(source) &&
               opnd_get_index(source) == DR_REG_NULL &&
               opnd_get_segment(source) == DR_REG_NULL) {
      const reg_id_t reg = opnd_get_base(source);
      base = reg == DR_REG_RSP ? 1 : reg == DR_REG_RBP ? 2 : 0;
      displacement = opnd_get_disp(source);
    }
    if (full_stack) {
      instruction.sp_source = base;
      instruction.sp_adjust = displacement;
    }
    if (full_frame) {
      instruction.bp_source = base;
      instruction.bp_adjust = displacement;
    }
  } else if ((opcode == OP_add || opcode == OP_sub) &&
             instr_num_dsts(&decoded) == 1 && instr_num_srcs(&decoded) == 2 &&
             (full_stack || full_frame)) {
    for (int index = 0; index < instr_num_srcs(&decoded); ++index) {
      const opnd_t operand = instr_get_src(&decoded, index);
      if (!opnd_is_immed_int(operand))
        continue;
      const int64_t immediate = opnd_get_immed_int(operand);
      if (immediate < INT32_MIN || immediate > INT32_MAX)
        continue;
      const int64_t adjustment = opcode == OP_add ? immediate : -immediate;
      if (full_stack) {
        instruction.sp_source = 1;
        instruction.sp_adjust = adjustment;
      }
      if (full_frame) {
        instruction.bp_source = 2;
        instruction.bp_adjust = adjustment;
      }
    }
  }
}

static void prove_userspace_returns(UserspaceGraph &graph) {
  struct StackState {
    bool sp_known = false, bp_known = false, return_changed = false;
    int64_t sp = 0, bp = 0;
  };
  std::map<app_pc, StackState> states;
  std::vector<app_pc> work;
  const auto merge = [&](app_pc pc, const StackState &incoming) {
    if (!graph.instructions.count(pc))
      return;
    auto [found, inserted] = states.emplace(pc, incoming);
    StackState &state = found->second;
    bool changed = inserted;
    if (!inserted) {
      if (state.sp_known && (!incoming.sp_known || state.sp != incoming.sp)) {
        state.sp_known = false;
        changed = true;
      }
      if (state.bp_known && (!incoming.bp_known || state.bp != incoming.bp)) {
        state.bp_known = false;
        changed = true;
      }
      if (!state.return_changed && incoming.return_changed) {
        state.return_changed = true;
        changed = true;
      }
    }
    if (changed)
      work.push_back(pc);
  };
  merge(graph.begin, {true, false, false, 0, 0});
  // Normally only graph.begin is an entry. A disconnected current PC may have
  // arrived through an indirect transfer: it must start with unknown stack
  // facts.
  for (const auto &root : graph.instructions) {
    if (work.empty() && !states.count(root.first))
      merge(root.first, {});
    while (!work.empty()) {
      const app_pc pc = work.back();
      work.pop_back();
      const auto &instruction = graph.instructions.at(pc);
      const StackState before = states.at(pc);
      StackState after = before;
      if (instruction.stack_write_base) {
        const bool sp = instruction.stack_write_base == 1;
        const bool known = sp ? before.sp_known : before.bp_known;
        const int64_t base = sp ? before.sp : before.bp;
        const int64_t displacement = instruction.stack_write_offset;
        if (instruction.stack_write_base == 3 || !known ||
            (displacement > 0 && base > INT64_MAX - displacement) ||
            (displacement < 0 && base < INT64_MIN - displacement)) {
          after.return_changed = true;
        } else {
          const int64_t offset = base + displacement;
          // The saved x86-64 return address occupies [entry RSP, entry RSP+8).
          if (offset < 8 && (offset >= 0 || uint64_t(-(offset + 1)) + 1 <
                                                instruction.stack_write_size))
            after.return_changed = true;
        }
      }
      const auto assign = [&](unsigned source, int64_t adjustment, bool &known,
                              int64_t &offset) {
        known = source == 1 ? before.sp_known : source == 2 && before.bp_known;
        if (!known)
          return;
        const int64_t base = source == 1 ? before.sp : before.bp;
        if ((adjustment > 0 && base > INT64_MAX - adjustment) ||
            (adjustment < 0 && base < INT64_MIN - adjustment)) {
          known = false;
          return;
        }
        offset = base + adjustment;
      };
      if (instruction.writes_sp)
        assign(instruction.sp_source, instruction.sp_adjust, after.sp_known,
               after.sp);
      if (instruction.writes_bp)
        assign(instruction.bp_source, instruction.bp_adjust, after.bp_known,
               after.bp);
      const unsigned role = instruction.role;
      if (role & UserspaceReturn)
        continue;
      if ((role & UserspaceBranch) && !(role & UserspaceCall) &&
          (role & UserspaceDirect))
        merge(pc + instruction.target_delta, after);
      if (!(role & UserspaceBranch) ||
          (role & (UserspaceCall | UserspaceConditional)))
        merge(pc + instruction.length, after);
    }
  }
  for (auto &entry : graph.instructions) {
    auto &instruction = entry.second;
    if (!(instruction.role & UserspaceReturn))
      continue;
    const auto state = states.find(entry.first);
    if (state != states.end() && state->second.sp_known &&
        state->second.sp == 0 && !state->second.return_changed)
      instruction.role |= UserspaceOrdinaryReturn;
  }
}

// Userspace copies, JMP gates and eagerly prepared shared DR fragments require
// private original text. An RX shared mapping can change through another alias
// or process without any protection fault or local mapping syscall.
static bool private_executable_mapping(app_pc begin, app_pc end) {
  for (app_pc cursor = begin; cursor < end;) {
    dr_mem_info_t memory{};
    if (!dr_query_memory_ex(cursor, &memory) || memory.base_pc > cursor ||
        (memory.prot & (DR_MEMPROT_READ | DR_MEMPROT_EXEC)) !=
            (DR_MEMPROT_READ | DR_MEMPROT_EXEC) ||
        (memory.prot & (DR_MEMPROT_WRITE | DR_MEMPROT_SHARED)) ||
        memory.size > UINTPTR_MAX - uintptr_t(memory.base_pc) ||
        memory.base_pc + memory.size <= cursor)
      return false;
    cursor = std::min(memory.base_pc + memory.size, end);
  }
  return begin < end;
}

// The stored graph is independent of runtime addresses and stepping policy.
// Reclassify its destinations against the current module/filter tables after
// loading. Every reachable instruction is revalidated again at publication.
static bool userspace_graph(void *context, app_pc pc, UserspaceGraph &graph) {
  userspace_graphs_prepared.fetch_add(1, std::memory_order_relaxed);
  if (!trace_activated.load(std::memory_order_acquire))
    prehit_userspace_graphs.fetch_add(1, std::memory_order_relaxed);
  Module *module = module_at(pc);
  if (!module || module->userspace_disabled || module->path.empty() ||
      module->path[0] != '/')
    return false;
  // Mapping changes may leave an unchanged function safely executable again.
  // Reuse its ELF boundaries only after a complete original-byte/RX proof;
  // modified or writable code continues through DR's consistency handling.
  if (module->code_modified && !original_code_matches(*module, pc))
    return false;
  const uint64_t offset = pc - module->start;
  auto known = module->flow_ranges.upper_bound(offset);
  if (known == module->flow_ranges.begin() ||
      offset >= std::prev(known)->second) {
    if (!module->flow_requests.insert(offset).second)
      return false;
    ct_flow_range range{};
    if (!ct_analysis_flow(module->analysis, offset, &range, nullptr,
                          collect_flow_region, collect_flow_switch, module) ||
        !range.bounded || range.begin_offset >= range.end_offset ||
        range.end_offset > uint64_t(module->end - module->start))
      return false;
    module->flow_ranges[range.begin_offset] = range.end_offset;
    known = module->flow_ranges.upper_bound(offset);
  }
  --known;
  graph.module = module;
  graph.generation = module->code_generation;
  graph.begin = module->start + known->first;
  graph.end = module->start + known->second;
  if (pc < graph.begin || pc >= graph.end ||
      size_t(graph.end - graph.begin) > userspace_instruction_limit * 15)
    return false;
  std::vector<byte> image(graph.end - graph.begin);
  if (!ct_userspace_patch_read_original(graph.begin, image.size(),
                                        image.data()))
    return false;
  if (!private_executable_mapping(graph.begin, graph.end))
    return false;
  std::string key =
      "userspace-flow:5:" + std::to_string(module->identity.size()) + ":" +
      module->identity + ":" + std::to_string(known->first) + ":" +
      std::to_string(known->second) + ":" + std::to_string(offset) + ":";
  static constexpr char hex[] = "0123456789abcdef";
  for (byte value : image) {
    key += hex[value >> 4];
    key += hex[value & 15];
  }
  graph.targets = {graph.begin, pc};
  for (const auto &entry : current_functions)
    if (entry.first >= graph.begin && entry.first < graph.end)
      graph.targets.insert(entry.first);
  unsigned char *allocation = nullptr;
  size_t size = 0;
  if (!module->identity.empty() &&
      ct_analysis_cache_read("userspace-flow", key.c_str(), &allocation,
                             &size)) {
    std::unique_ptr<unsigned char, decltype(&std::free)> bytes(allocation,
                                                               std::free);
    size_t position = 0;
    bool valid = allocation != nullptr;
    const auto number = [&]() -> uint64_t {
      if (!valid || size - position < 8) {
        valid = false;
        return 0;
      }
      uint64_t value = 0;
      for (unsigned shift = 0; shift < 64; shift += 8)
        value |= uint64_t(bytes.get()[position++]) << shift;
      return value;
    };
    const uint64_t schema = number(), accepted = number(), count = number();
    valid &=
        schema == 5 && accepted <= 1 && count <= userspace_instruction_limit;
    if (valid && !accepted && !count && position == size)
      return false;
    valid &= accepted == 1 && count > 0 && count <= (size - position) / 41;
    for (uint64_t index = 0; valid && index < count; ++index) {
      const uint64_t relative = number(), length = number(), role = number();
      const int64_t delta = int64_t(number());
      const uint64_t stack = number();
      const int64_t sp_adjust = stack & 1 ? int64_t(number()) : 0;
      const int64_t bp_adjust = stack & 2 ? int64_t(number()) : 0;
      const int64_t write_offset = stack & 0xc0 ? int64_t(number()) : 0;
      const uint64_t write_size = stack & 0xc0 ? number() : 0;
      if (!valid || relative >= image.size() || !length || length > 15 ||
          length > image.size() - relative || length > size - position ||
          role > 255 || stack > 255 || ((stack >> 2) & 3) > 2 ||
          ((stack >> 4) & 3) > 2 || (!(stack & 1) && (stack & 0xc)) ||
          (!(stack & 2) && (stack & 0x30)) ||
          ((role & UserspaceOrdinaryReturn) && !(role & UserspaceReturn)) ||
          ((role & UserspaceDirect) &&
           (delta < int64_t(INT32_MIN) + int64_t(length) ||
            delta > int64_t(INT32_MAX) + int64_t(length))) ||
          (!(role & UserspaceDirect) && delta != 0) ||
          std::memcmp(bytes.get() + position, image.data() + relative,
                      length)) {
        valid = false;
        break;
      }
      UserspaceInstruction instruction{};
      instruction.pc = graph.begin + relative;
      instruction.length = length;
      instruction.role = unsigned(role);
      instruction.target_delta = delta;
      instruction.writes_sp = stack & 1;
      instruction.writes_bp = stack & 2;
      instruction.sp_source = (stack >> 2) & 3;
      instruction.bp_source = (stack >> 4) & 3;
      instruction.stack_write_base = (stack >> 6) & 3;
      instruction.sp_adjust = sp_adjust;
      instruction.bp_adjust = bp_adjust;
      instruction.stack_write_offset = write_offset;
      instruction.stack_write_size = write_size;
      std::memcpy(instruction.original, image.data() + relative, length);
      position += length;
      if ((!graph.instructions.empty() &&
           graph.instructions.rbegin()->first +
                   graph.instructions.rbegin()->second.length >
               instruction.pc) ||
          !graph.instructions.emplace(instruction.pc, instruction).second)
        valid = false;
    }
    if (valid && position == size && graph.instructions.count(pc)) {
      for (const auto &entry : graph.instructions) {
        const auto &instruction = entry.second;
        if (instruction.role & UserspaceDirect)
          graph.targets.insert(instruction.pc + instruction.target_delta);
        if (instruction.role & UserspaceCall)
          graph.targets.insert(instruction.pc + instruction.length);
      }
      return true;
    }
    graph.instructions.clear();
  }
  bool valid = true;
  std::vector<app_pc> work{graph.begin, pc};
  while (valid && !work.empty()) {
    app_pc cursor = work.back();
    work.pop_back();
    while (cursor >= graph.begin && cursor < graph.end &&
           !graph.instructions.count(cursor)) {
      if (graph.instructions.size() >= userspace_instruction_limit) {
        valid = false;
        break;
      }
      const size_t available = std::min(size_t(15), size_t(graph.end - cursor));
      byte bytes[15]{};
      std::memcpy(bytes, image.data() + (cursor - graph.begin), available);
      instr_t decoded;
      instr_init(context, &decoded);
      byte *next = decode_from_copy(context, bytes, cursor, &decoded);
      const size_t length = next ? size_t(next - bytes) : 0;
      const int opcode = instr_get_opcode(&decoded);
      valid = length && length <= available && instr_valid(&decoded) &&
              !instr_is_far_cti(&decoded) && !instr_is_interrupt(&decoded) &&
              opcode != OP_xbegin && opcode != OP_xend && opcode != OP_xabort &&
              opcode != OP_xtest && opcode != OP_wrfsbase &&
              opcode != OP_wrgsbase && opcode != OP_rdgsbase &&
              opcode != OP_swapgs &&
              !instr_writes_to_reg(&decoded, DR_SEG_FS, DR_QUERY_DEFAULT) &&
              !instr_writes_to_reg(&decoded, DR_SEG_GS, DR_QUERY_DEFAULT);
      for (int index = 0;
           valid && index < instr_num_srcs(&decoded) + instr_num_dsts(&decoded);
           ++index) {
        const opnd_t operand =
            index < instr_num_srcs(&decoded)
                ? instr_get_src(&decoded, index)
                : instr_get_dst(&decoded, index - instr_num_srcs(&decoded));
        if (opnd_is_memory_reference(operand) &&
            opnd_get_segment(operand) == DR_SEG_GS)
          valid = false;
      }
      auto following = graph.instructions.lower_bound(cursor);
      if ((following != graph.instructions.end() &&
           cursor + length > following->first) ||
          (following != graph.instructions.begin() &&
           std::prev(following)->first + std::prev(following)->second.length >
               cursor))
        valid = false;
      if (!valid) {
        instr_free(context, &decoded);
        break;
      }
      UserspaceInstruction instruction{};
      instruction.pc = cursor;
      instruction.length = length;
      std::memcpy(instruction.original, bytes, length);
      const bool call = instr_is_call(&decoded);
      const bool ret = instr_is_return(&decoded);
      const bool conditional = instr_is_cbr(&decoded);
      const bool branch =
          conditional || instr_is_ubr(&decoded) || instr_is_mbr(&decoded);
      instruction.role =
          (call ? unsigned(UserspaceCall) : 0u) |
          (ret ? unsigned(UserspaceReturn) : 0u) |
          (branch ? unsigned(UserspaceBranch) : 0u) |
          (conditional ? unsigned(UserspaceConditional) : 0u) |
          (instr_is_syscall(&decoded) ? unsigned(UserspaceSyscall) : 0u) |
          (opcode == OP_cmp || opcode == OP_test ? unsigned(UserspaceCompare)
                                                 : 0u);
      if ((call || branch) && !ret) {
        const opnd_t target = instr_get_target(&decoded);
        if (opnd_is_pc(target)) {
          const app_pc destination = opnd_get_pc(target);
          instruction.role |= UserspaceDirect;
          instruction.target_delta = destination - cursor;
          graph.targets.insert(destination);
          if (branch && !call && destination >= graph.begin &&
              destination < graph.end)
            work.push_back(destination);
        }
      }
      if (call)
        graph.targets.insert(cursor + length);
      describe_userspace_stack(decoded, instruction);
      graph.instructions.emplace(cursor, instruction);
      instr_free(context, &decoded);
      if (ret || (branch && !call && !conditional))
        break;
      cursor += length;
    }
  }
  valid &= graph.instructions.count(pc) != 0;
  if (valid)
    prove_userspace_returns(graph);
  if (!module->identity.empty()) {
    std::vector<byte> data;
    const auto number = [&](uint64_t value) {
      for (unsigned shift = 0; shift < 64; shift += 8)
        data.push_back(byte(value >> shift));
    };
    number(5);
    number(valid);
    number(valid ? graph.instructions.size() : 0);
    if (valid)
      for (const auto &entry : graph.instructions) {
        const auto &instruction = entry.second;
        number(instruction.pc - graph.begin);
        number(instruction.length);
        number(instruction.role);
        number(uint64_t(instruction.target_delta));
        number(unsigned(instruction.writes_sp) |
               (unsigned(instruction.writes_bp) << 1) |
               (instruction.sp_source << 2) | (instruction.bp_source << 4) |
               (instruction.stack_write_base << 6));
        if (instruction.writes_sp)
          number(uint64_t(instruction.sp_adjust));
        if (instruction.writes_bp)
          number(uint64_t(instruction.bp_adjust));
        if (instruction.stack_write_base) {
          number(uint64_t(instruction.stack_write_offset));
          number(instruction.stack_write_size);
        }
        data.insert(data.end(), instruction.original,
                    instruction.original + instruction.length);
      }
    ct_analysis_cache_write("userspace-flow", key.c_str(), data.data(),
                            data.size());
  }
  return valid;
}

// Shared by all execution levels and the original-address arm fallback. No
// discarded source/value state is recreated merely because the selected level
// changes. An indirect entry outside known reachable instructions expands only
// this actually reached physical range.
static std::shared_ptr<UserspaceGraph>
userspace_function_graph(void *context, Module &module, app_pc pc) {
  std::shared_ptr<UserspaceGraph> previous;
  auto range = module.flow_ranges.upper_bound(pc - module.start);
  if (range != module.flow_ranges.begin()) {
    --range;
    if (uint64_t(pc - module.start) < range->second) {
      const auto known =
          module.userspace_graphs.find(module.start + range->first);
      if (known != module.userspace_graphs.end() && known->second &&
          known->second->generation == module.code_generation) {
        previous = known->second;
        if (previous->instructions.count(pc))
          return previous;
      }
    }
  }
  if (module.userspace_graph_failures.count(pc))
    return {};
  auto graph = std::make_shared<UserspaceGraph>();
  if (!userspace_graph(context, pc, *graph)) {
    module.userspace_graph_failures.insert(pc);
    return {};
  }
  if (previous && previous->begin == graph->begin &&
      previous->end == graph->end) {
    // Discovering another indirect entry must extend this generation's graph.
    // Replacing it with just {function entry, current PC} would repeatedly
    // retire the same copies when execution alternates between old entries.
    bool valid = true;
    for (const auto &[address, instruction] : previous->instructions) {
      byte bytes[15];
      if (!ct_userspace_patch_read_original(address, instruction.length,
                                            bytes) ||
          std::memcmp(bytes, instruction.original, instruction.length)) {
        valid = false;
        break;
      }
      const auto next = graph->instructions.lower_bound(address);
      if (next != graph->instructions.end() && next->first == address) {
        if (next->second.length == instruction.length &&
            !std::memcmp(next->second.original, instruction.original,
                         instruction.length))
          continue;
        valid = false;
        break;
      }
      if (graph->instructions.size() == userspace_instruction_limit ||
          (next != graph->instructions.end() &&
           address + instruction.length > next->first) ||
          (next != graph->instructions.begin() &&
           std::prev(next)->first + std::prev(next)->second.length > address)) {
        valid = false;
        break;
      }
      graph->instructions.emplace_hint(next, address, instruction);
    }
    if (!valid) {
      module.userspace_graph_failures.insert(pc);
      return {};
    }
    graph->targets.insert(previous->targets.begin(), previous->targets.end());
    // A new path can invalidate a formerly proven return-slot relationship.
    for (auto &[address, instruction] : graph->instructions)
      instruction.role &= ~UserspaceOrdinaryReturn;
    prove_userspace_returns(*graph);
  }
  module.userspace_graphs[graph->begin] = graph;
  return graph;
}

struct UserspacePreparation {
  UserspaceGraph graph;
  uint64_t binding_generation = 0;
  bool body = false;
  bool keep_returns = false;
  app_pc patch_end = nullptr;
  std::unique_ptr<ct_userspace_patch_plan,
                  decltype(&ct_userspace_patch_discard)>
      plan{nullptr, ct_userspace_patch_discard};
};

static bool prepare_userspace_graph(void *context,
                                    UserspacePreparation &prepared, app_pc gate,
                                    bool keep_returns) {
  auto &graph = prepared.graph;
  prepared.keep_returns = keep_returns;
  Module &module = *graph.module;
  prepared.binding_generation = module.userspace_binding_generation;
  std::map<app_pc, unsigned> gates;
  if (gate)
    gates[gate] = CT_USERSPACE_GATE_ENTRY;
  std::vector<std::pair<app_pc, app_pc>> boundaries;
  if (prepared.body) {
    auto location = std::make_unique<ct_location>();
    ct_analysis_lookup_arming(module.analysis, graph.begin - module.start,
                              location.get());
    Site::Mode mode, physical_mode;
    std::vector<Site::Mode> inline_modes;
    filter_modes(module, *location, mode, physical_mode, inline_modes);
    const bool within_function =
        within_enabled &&
        std::any_of(current_functions.begin(), current_functions.end(),
                    [&](const auto &entry) {
                      return entry.first >= graph.begin &&
                             entry.first < graph.end &&
                             entry.second->module.get() == &module &&
                             entry.second->within;
                    });
    for (const auto &range : module.observation_inline_ranges) {
      if (range.first >= graph.end || range.second <= graph.begin)
        continue;
      if (physical_mode != Site::Over ||
          std::any_of(module.userspace_reentry_inline_ranges.begin(),
                      module.userspace_reentry_inline_ranges.end(),
                      [&](const auto &entry) {
                        return range.first < entry.second &&
                               range.second > entry.first;
                      }))
        boundaries.push_back(range);
    }
    for (const auto &range : module.within_inline_ranges)
      if (range.first < graph.end && range.second > graph.begin)
        boundaries.push_back(range);
    for (const auto &range : boundaries) {
      graph.targets.insert(range.first);
      graph.targets.insert(range.second);
    }
    for (const auto &item : graph.instructions) {
      const auto &instruction = item.second;
      const app_pc pc = item.first;
      const unsigned role = instruction.role;
      if (pc != graph.begin && current_functions.count(pc))
        gates[pc] |= CT_USERSPACE_GATE_ENTRY;
      for (const auto &range : boundaries)
        if (pc == range.first || pc == range.second)
          gates[pc] |= CT_USERSPACE_GATE_ENTRY;
      if (role & UserspaceSyscall)
        gates[pc] |= CT_USERSPACE_GATE_SYSCALL;
      if (role & UserspaceReturn) {
        if (keep_returns || !(role & UserspaceOrdinaryReturn))
          gates[pc] |= CT_USERSPACE_GATE_RETURN;
        continue;
      }
      if (role & (UserspaceCall | UserspaceBranch)) {
        const app_pc destination =
            role & UserspaceDirect ? pc + instruction.target_delta : nullptr;
        const bool internal = !(role & UserspaceCall) && destination &&
                              destination >= graph.begin &&
                              destination < graph.end &&
                              (!current_functions.count(destination) ||
                               destination == graph.begin);
        if (internal) {
          for (const auto &range : boundaries)
            if ((pc >= range.first && pc < range.second) !=
                (destination >= range.first && destination < range.second))
              gates[pc] |= CT_USERSPACE_GATE_BRANCH;
        } else if (!(role & UserspaceCall) && within_enabled &&
                   (within_function || within_inline_at(module, pc))) {
          // A tail transfer leaves the matching frame without a RET. Re-enter
          // DR before executing the branch so its successor is observed before
          // the destination's prologue can lower RSP and resemble a nested
          // call.
          gates[pc] |= CT_USERSPACE_GATE_BRANCH;
        } else {
          // Leave at the transfer itself. Its destination is prepared only
          // when actually reached, never by walking an unexecuted call tree.
          gates[pc] |= CT_USERSPACE_GATE_BRANCH;
        }
      }
      const bool terminal = (role & UserspaceBranch) &&
                            !(role & (UserspaceCall | UserspaceConditional));
      if (!terminal && pc + instruction.length == graph.end)
        gates[pc] |= CT_USERSPACE_GATE_BRANCH;
    }
  }
  std::vector<ct_userspace_patch_request> requests;
  for (const auto &entry : gates) {
    ct_userspace_patch_info installed{};
    if (ct_userspace_patch_lookup(entry.first, &installed)) {
      if ((entry.second & CT_USERSPACE_GATE_TRACE) &&
          (installed.kind & CT_USERSPACE_GATE_TRACE) &&
          graph.instructions.count(entry.first))
        continue;
      // Entering an overwritten window must replay this exact instruction.
      if ((entry.second & CT_USERSPACE_GATE_ENTRY)
              ? installed.redirect_pc != entry.first
              : installed.pc != entry.first)
        return false;
      continue;
    }
    requests.push_back({entry.first, entry.second});
    if (entry.second & CT_USERSPACE_GATE_ENTRY)
      graph.targets.insert(entry.first);
  }
  std::vector<ct_userspace_patch_instruction> decoded;
  for (const auto &instruction : graph.instructions)
    decoded.push_back({instruction.first, instruction.second.length});
  app_pc padding_end = graph.end;
  while (padding_end < module.end && padding_end - graph.end < 15 &&
         !current_functions.count(padding_end) &&
         !graph.targets.count(padding_end)) {
    byte bytes[15]{};
    const size_t available =
        std::min(sizeof(bytes), size_t(module.end - padding_end));
    if (!ct_userspace_patch_read_original(padding_end, available, bytes))
      break;
    instr_t padding;
    instr_init(context, &padding);
    byte *next = decode_from_copy(context, bytes, padding_end, &padding);
    const size_t length = next ? size_t(next - bytes) : 0;
    const int opcode = instr_get_opcode(&padding);
    const bool nop = length && length <= available &&
                     (opcode == OP_nop || opcode == OP_nop_modrm);
    instr_free(context, &padding);
    if (!nop)
      break;
    auto target = graph.targets.upper_bound(padding_end);
    if ((target != graph.targets.end() && *target < padding_end + length) ||
        std::any_of(current_functions.begin(), current_functions.end(),
                    [&](const auto &entry) {
                      return entry.first > padding_end &&
                             entry.first < padding_end + length;
                    }))
      break;
    decoded.push_back({padding_end, length});
    padding_end += length;
  }
  prepared.patch_end = padding_end;
  std::vector<app_pc> targets(graph.targets.begin(), graph.targets.end());
  prepared.plan.reset(ct_userspace_patch_prepare(
      context, module.identity.c_str(), module.start, graph.begin, padding_end,
      requests.data(), requests.size(), decoded.data(), decoded.size(),
      targets.data(), targets.size()));
  return prepared.plan != nullptr;
}

static void try_userspace_arm(app_pc pc, std::atomic<uint32_t> *attempt) {
  if (!duplicate_enabled || !traced_process() || !recording_thread())
    return;
  // A vfork parent is blocked until this shared-image child execs or exits.
  // World-stop patch publication cannot wait for that parent to resume. Run
  // this short shared-image lifetime under DR; exec initializes its own gates.
  if (!thread_state(dr_get_current_drcontext())->owns_image)
    return;
  if (attempt)
    attempt->store(0, std::memory_order_release);
  void *context = dr_get_current_drcontext();
  const uint64 generation = dr_userspace_execution_generation(context);
  bool ready = false;
  Module *candidate = nullptr;
  app_pc candidate_begin = nullptr, requested_return = nullptr;
  {
    Thread &thread = *thread_state(context);
    PreparationScope owners(thread);
    std::vector<UserspacePreparation *> preparations;
    QuietCallback quiet(context);
    {
      Lock lock(analysis_lock);
      candidate = module_at(pc);
      if (!candidate || candidate->userspace_disabled ||
          candidate->path.empty() || candidate->path[0] != '/' ||
          candidate->userspace_rejected.count(pc) ||
          ct_userspace_patch_lookup(pc, nullptr))
        return;
      owners.hold(*candidate);
      const uint64_t offset = pc - candidate->start;
      auto flow = candidate->flow_ranges.upper_bound(offset);
      if (flow != candidate->flow_ranges.begin()) {
        --flow;
        // A rejected function stays on DR at every observation site. Do not
        // rebuild and revalidate its graph just to rediscover that decision.
        if (offset < flow->second &&
            candidate->userspace_rejected.count(candidate->start + flow->first))
          return;
      }
      std::shared_ptr<UserspacePreparation> initial;
      const auto existing = candidate->userspace_ranges.upper_bound(pc);
      const bool prepared = existing != candidate->userspace_ranges.begin() &&
                            pc < std::prev(existing)->second &&
                            candidate->userspace_instructions.count(pc);
      if (prepared) {
        candidate_begin = std::prev(existing)->first;
      } else {
        auto graph = userspace_function_graph(context, *candidate, pc);
        if (!graph) {
          candidate->userspace_rejected.insert(pc);
          return;
        }
        initial = std::make_shared<UserspacePreparation>();
        initial->body = true;
        initial->graph = *graph;
        candidate_begin = initial->graph.begin;
      }
      if (candidate->userspace_rejected.count(candidate_begin))
        return;
      ready =
          prepared && candidate->userspace_return_gates.count(candidate_begin);
      bool return_guard = false;
      if (!ready && !structural_instrumentation()) {
        Thread &thread = *thread_state(context);
        if (!thread.calls.empty()) {
          const Call &frame = *thread.calls.back();
          // A signal frame resumes through rt_sigreturn. Its return_pc is the
          // interrupted context, not the handler's RET destination.
          if (!frame.signal_frame && frame.entry_pc == candidate_begin &&
              frame.return_pc) {
            requested_return = frame.return_pc;
            ct_userspace_patch_info installed{};
            if (ct_userspace_patch_lookup(requested_return, &installed)) {
              return_guard = installed.redirect_pc == requested_return;
            } else {
              auto continuation = std::make_shared<UserspacePreparation>();
              if (userspace_graph(context, requested_return,
                                  continuation->graph) &&
                  prepare_userspace_graph(context, *continuation,
                                          requested_return, false)) {
                return_guard = true;
                owners.hold(*continuation->graph.module);
                preparations.push_back(continuation.get());
                thread.arming_preparations.push_back(std::move(continuation));
              }
            }
          }
        }
        if (prepared) {
          // Readiness is shared across threads, but a raw RET's destination is
          // specific to this invocation. Never reuse another caller's guard.
          if (!return_guard)
            return;
          ready = preparations.empty();
        }
      }
      if (!prepared) {
        if (!prepare_userspace_graph(context, *initial, nullptr,
                                     !return_guard)) {
          candidate->userspace_rejected.insert(candidate_begin);
          candidate->userspace_rejected.insert(pc);
          return;
        }
        preparations.push_back(initial.get());
        thread.arming_preparations.push_back(std::move(initial));
      }
    }
    if (!preparations.empty()) {
      std::vector<ct_userspace_patch_plan *> plans;
      for (auto &prepared : preparations)
        plans.push_back(prepared->plan.get());
      for (unsigned retry = 0; retry < userspace_retire_attempts && !ready;
           ++retry) {
        void **contexts = nullptr;
        uint suspended = 0, unsuspended = 0;
        const bool stopped = dr_suspend_all_other_threads_ex(
            &contexts, &suspended, &unsuspended, DR_SUSPEND_NATIVE);
        bool safe = stopped && !unsuspended;
        for (uint index = 0; index < suspended; ++index) {
          suspend_thread_timing(contexts[index]);
          safe &= dr_cancel_suspended_userspace_execution(contexts[index]);
        }
        const bool retry_stop = !safe;
        if (safe) {
          Lock lock(analysis_lock);
          for (const auto &prepared : preparations)
            safe &= prepared->graph.module->active &&
                    !prepared->graph.module->userspace_disabled &&
                    prepared->binding_generation ==
                        prepared->graph.module->userspace_binding_generation;
          ct_userspace_patch_info installed{};
          const bool guard =
              requested_return &&
              ct_userspace_patch_lookup(requested_return, &installed) &&
              installed.redirect_pc == requested_return;
          const auto existing = candidate->userspace_ranges.upper_bound(pc);
          ready = safe && existing != candidate->userspace_ranges.begin() &&
                  pc < std::prev(existing)->second &&
                  candidate->userspace_instructions.count(pc) &&
                  (guard ||
                   candidate->userspace_return_gates.count(candidate_begin));
          if (!ready && safe &&
              ct_userspace_patch_publish_all(plans.data(), plans.size())) {
            for (const auto &prepared : preparations) {
              if (!prepared->body)
                continue;
              Module &module = *prepared->graph.module;
              module.userspace_ranges[prepared->graph.begin] =
                  prepared->patch_end;
              for (const auto &instruction : prepared->graph.instructions)
                module.userspace_instructions.insert(instruction.first);
              if (prepared->keep_returns)
                module.userspace_return_gates.insert(prepared->graph.begin);
              else
                module.userspace_return_gates.erase(prepared->graph.begin);
            }
            if (structural_instrumentation())
              for (const auto &prepared : preparations) {
                if (!prepared->body)
                  continue;
                for (auto &entry : prepared->graph.module->userspace_attempts)
                  if (prepared->graph.instructions.count(entry.first) &&
                      !ct_userspace_patch_lookup(entry.first, nullptr))
                    entry.second->store(1, std::memory_order_release);
              }
            ready = true;
          } else if (!ready && candidate->active &&
                     !candidate->userspace_instructions.count(pc)) {
            candidate->userspace_rejected.insert(candidate_begin);
            candidate->userspace_rejected.insert(pc);
          }
        }
        for (uint index = 0; index < suspended; ++index)
          resume_thread_timing(contexts[index]);
        if (!dr_resume_all_other_threads(contexts, suspended))
          fail("cannot resume threads after userspace JMP publication");
        if (!retry_stop)
          break;
        dr_thread_yield();
      }
      if (ct_userspace_patch_lookup(pc, nullptr))
        ready = false;
    }
  }
  if (ready) {
    dr_mcontext_t state{};
    state.size = sizeof(state);
    state.flags = DR_MC_ALL;
    if (!dr_get_mcontext(context, &state))
      return;
    state.pc = pc;
    if (attempt)
      attempt->store(1, std::memory_order_release);
    if (ct_perfetto_enabled())
      ct_timing_quiet_begin(context);
    Thread &thread = *thread_state(context);
    if (!thread.calls.empty() && thread.calls.back()->startup_entry)
      thread.calls.back()->startup_controlled = false;
    dr_redirect_userspace_execution(&state, generation);
  }
}

// The temporary owns unpublished code and its broker reference. Declare it
// before the publication lock so all cleanup runs after releasing that lock.
struct SharedVersionPreparation {
  std::unique_ptr<ct_userspace_version, decltype(&ct_userspace_version_discard)>
      code{nullptr, ct_userspace_version_discard};
  ct_shared_channel *channel = nullptr;
  uint64_t object = 0;
  bool abandoned = false;
  std::shared_ptr<UserspaceGraph> graph;
  std::vector<ct_userspace_version_instruction> instructions;
  std::vector<byte> payload;
  std::string error;
  ct_shared_file file{-1, 0, 0};
  ct_shared_result result{};
  SharedVersionPreparation() { result.fd = -1; }
  ~SharedVersionPreparation() {
    if (abandoned) {
      // The version registry reclaims vanished producers in the fork child.
      [[maybe_unused]] auto *abandoned_code = code.release();
      return;
    }
    code.reset();
    if (object && channel)
      ct_shared_release(channel, object);
    if (file.fd >= 0)
      ct_shared_file_close(&file);
    if (result.fd >= 0)
      ct_shared_result_close(&result);
  }
};

static std::map<void *, std::unique_ptr<SharedVersionPreparation>>
    version_preparations;

struct VersionPreparationScope {
  void *context = nullptr;
  ~VersionPreparationScope() {
    if (!context)
      return;
    std::unique_ptr<SharedVersionPreparation> preparation;
    {
      Lock lock(analysis_lock);
      auto found = version_preparations.find(context);
      if (found != version_preparations.end()) {
        preparation = std::move(found->second);
        version_preparations.erase(found);
      }
    }
    // Releasing broker ownership can perform IPC. Never hold analysis_lock.
  }
};

static void prepare_userspace_version(
    void *context, Thread &thread, ct_instrument_level level,
    uint64_t generation,
    const std::vector<ct_userspace_version_instruction> &instructions,
    const ct_userspace_version_cache &cache, SharedVersionPreparation &prepared,
    std::string &error) {
  const auto diagnostic = [&](const char *stage) {
    if (instrumentation_statistics && ct_output_trace_enabled())
      ct_output_printf(
          "ctrace userspace sharing fallback: level=%s module=%s offset=0x%llx "
          "stage=%s reason=%s\n",
          ct_instrument_level_name(level),
          cache.identity ? cache.identity : "?",
          static_cast<unsigned long long>(instructions.empty()
                                              ? 0
                                              : instructions.front().pc -
                                                    cache.module_base),
          stage, error.empty() ? "unavailable" : error.c_str());
  };
  const auto local = [&] {
    prepared.code.reset(ct_userspace_version_prepare(
        context, level, generation, instructions.data(), instructions.size(),
        error, &cache));
  };
  ct_shared_key key{};
  if (!ct_userspace_version_shared_key(&cache, level, instructions.data(),
                                       instructions.size(), key, error)) {
    diagnostic("identity");
    local();
    return;
  }
  if (!thread.shared_channel)
    thread.shared_channel = ct_shared_open();
  prepared.channel = thread.shared_channel;
  const auto fallback = [&](const char *stage) {
    diagnostic(stage);
    shared_version_fallbacks[static_cast<unsigned>(level)].fetch_add(
        1, std::memory_order_relaxed);
    local();
  };
  auto &result = prepared.result;
  if (!prepared.channel ||
      !ct_shared_acquire(prepared.channel, &key, &result)) {
    fallback("acquire");
    return;
  }
  if (result.status == CT_SHARED_WAIT) {
    const uint64_t ticket = result.token;
    // Bound blocking to one wait for this object in the current call. Full
    // DR observation can revisit this path at every instruction; later probes
    // must still adopt READY without paying another blocking wait.
    auto &waited = thread.calls.empty()
                       ? thread.userspace_waited_key
                       : thread.calls.back()->userspace_waited_key;
    const int timeout = std::memcmp(&waited, &key, sizeof(key)) == 0 ? 0 : 50;
    waited = key;
    if (!ct_shared_wait(prepared.channel, ticket, timeout, &result)) {
      ct_shared_cancel_wait(prepared.channel, ticket);
      fallback("wait");
      return;
    }
    if (result.status == CT_SHARED_WAIT) {
      ct_shared_cancel_wait(prepared.channel, ticket);
      error.clear();
      return;
    }
  }
  if (result.status == CT_SHARED_READY) {
    prepared.object = result.object.object_id;
    prepared.code.reset(ct_userspace_version_restore(
        context, level, generation, instructions.data(), instructions.size(),
        key, result.fd, result.object.payload_offset,
        result.object.payload_size, error));
    ct_shared_result_close(&result);
    if (prepared.code)
      return;
    ct_shared_release(prepared.channel, prepared.object);
    prepared.object = 0;
    fallback("restore");
    return;
  }
  if (result.status != CT_SHARED_CREATE) {
    ct_shared_result_close(&result);
    fallback("acquire status");
    return;
  }
  const uint64_t lease = result.token;
  prepared.code.reset(ct_userspace_version_prepare(
      context, level, generation, instructions.data(), instructions.size(),
      error, &cache, true));
  if (!prepared.code) {
    ct_shared_fail(prepared.channel, lease);
    fallback("prepare");
    return;
  }
  auto &payload = prepared.payload;
  size_t rx_offset = 0;
  auto &file = prepared.file;
  if (!ct_userspace_version_export(prepared.code.get(), key, payload, rx_offset,
                                   error) ||
      !ct_shared_file_create(&key, payload.data(), payload.size(), &file)) {
    ct_shared_fail(prepared.channel, lease);
    diagnostic("export");
    shared_version_fallbacks[static_cast<unsigned>(level)].fetch_add(
        1, std::memory_order_relaxed);
    error.clear();
    return; // The complete unpublished private version remains usable.
  }
  const bool published =
      ct_shared_publish(prepared.channel, lease, &file, &result);
  ct_shared_file_close(&file);
  if (!published || result.status != CT_SHARED_READY) {
    diagnostic("publish");
    ct_shared_fail(prepared.channel, lease);
    ct_shared_result_close(&result);
    shared_version_fallbacks[static_cast<unsigned>(level)].fetch_add(
        1, std::memory_order_relaxed);
    error.clear();
    return;
  }
  prepared.object = result.object.object_id;
  const bool mapped =
      rx_offset <= UINT64_MAX - result.object.payload_offset &&
      ct_userspace_version_map_shared(prepared.code.get(), result.fd,
                                      result.object.payload_offset + rx_offset);
  if (mapped &&
      !ct_userspace_version_adopt_metadata(prepared.code.get(), key, result.fd,
                                           result.object.payload_offset,
                                           result.object.payload_size, error))
    shared_version_fallbacks[static_cast<unsigned>(level)].fetch_add(
        1, std::memory_order_relaxed);
  if (mapped)
    error.clear();
  ct_shared_result_close(&result);
  if (!mapped) {
    prepared.code.reset();
    ct_shared_release(prepared.channel, prepared.object);
    prepared.object = 0;
    fallback("map");
  }
}

static void release_shared_versions(Thread &thread) {
  // A CLONE_VM child can retire shared-image code, but only the image owner
  // holds the catalog references. Leave its release queue for that owner.
  if (!thread.owns_image)
    return;
  std::vector<uint64_t> objects;
  {
    Lock lock(analysis_lock);
    // Nested PID namespaces can give parent and child the same numeric PID.
    // The session's kernel socket credentials distinguish its actual owner.
    if (released_shared_versions.empty() || !ct_analysis_object_owner())
      return;
    objects.swap(released_shared_versions);
  }
  if (objects.empty())
    return;
  if (!thread.shared_channel)
    thread.shared_channel = ct_shared_open();
  if (thread.shared_channel)
    for (uint64_t object : objects)
      ct_shared_release(thread.shared_channel, object);
  // A failed channel leaves at most a session-owned reference. Never retry a
  // possibly acknowledged decrement; image exit cleans remaining ownership.
}

// The caller holds analysis_lock and pins the preparation job. Borrow only the
// source record prepared for these exact original bytes; no pointer escapes
// the caller's synchronous scope comparison.
static bool initial_source_location(const InitialPreparation *job,
                                    Module &module, app_pc pc, size_t size,
                                    const byte *bytes,
                                    ct_location_view &location) {
  if (!job || job->module.get() != &module || !module.active ||
      job->generation != module.code_generation ||
      module.pending_code_changes || module.pending_userspace_changes ||
      pc < module.start || pc >= module.end || !size || size > 15 ||
      size > size_t(module.end - pc) ||
      job->locations.size() != job->instructions.size())
    return false;
  const uint64_t offset = pc - module.start;
  const auto instruction = std::lower_bound(
      job->instructions.begin(), job->instructions.end(), offset,
      [](const auto &entry, uint64_t value) { return entry.offset < value; });
  if (instruction == job->instructions.end() || instruction->offset != offset ||
      instruction->size != size || std::memcmp(instruction->bytes, bytes, size))
    return false;
  const auto &record = job->locations[instruction - job->instructions.begin()];
  if (!record)
    return false;
  location = record->view;
  // Opening another module can reject a source prefix after this immutable
  // record was prepared. The text/display are fixed for the analysis lifetime;
  // rejection can only narrow their use. Never modify the shared record.
  if (location.source_usable &&
      !ct_analysis_source_allowed(module.analysis, location.source_id)) {
    location.source_usable = false;
    location.source_verified = false;
  }
  return true;
}

static app_pc
prepare_userspace_copy(void *context, app_pc pc, ct_instrument_level level,
                       std::atomic<uint32_t> *attempt = nullptr,
                       const InitialPreparation *selection = nullptr) {
  Thread &thread = *thread_state(context);
  if (!thread.owns_image)
    return nullptr;
  app_pc entry = nullptr;
  {
    QuietCallback quiet(context);
    release_shared_versions(thread);
    PreparationScope owners(thread);
    Module *module = nullptr;
    UserspaceGraph *graph = nullptr;
    std::vector<ct_userspace_version_instruction> instructions;
    std::pair<app_pc, ct_instrument_level> key;
    uint64_t preparation = 0, code_generation = 0, binding_generation = 0;
    VersionPreparationScope preparation_scope;
    SharedVersionPreparation *prepared_code = nullptr;
    {
      Lock lock(analysis_lock);
      module = module_at(pc);
      if (!module || !module->active || module->userspace_disabled ||
          module->path.empty() || module->path[0] != '/')
        return nullptr;
      owners.hold(*module);
      auto graph_owner = userspace_function_graph(context, *module, pc);
      graph = graph_owner.get();
      if (!graph) {
        if (attempt)
          attempt->store(0, std::memory_order_release);
        return nullptr;
      }
      key = std::make_pair(graph->begin, level);
      code_generation = module->code_generation;
      binding_generation = module->userspace_binding_generation;
      auto &prepared = module->userspace_versions[key];
      if (prepared.graph != graph_owner ||
          (prepared.code && prepared.source_generation != code_generation)) {
        if (prepared.code)
          module->retired_userspace_versions.push_back(prepared.code);
        prepared = {};
        prepared.graph = graph_owner;
      }
      // Another thread is preparing this exact level. Continue with DR's
      // equivalent level rather than generating or executing a lower copy.
      if (prepared.preparation)
        return nullptr;
      if (!prepared.code && prepared.error.empty()) {
        instructions.reserve(graph->instructions.size());
        std::set<app_pc> boundaries;
        for (const auto &range : module->within_inline_ranges) {
          boundaries.insert(range.first);
          boundaries.insert(range.second);
        }
        for (const auto &range : module->observation_inline_ranges) {
          boundaries.insert(range.first);
          boundaries.insert(range.second);
        }
        // A direct branch may land inside an inline range, rather than at its
        // first instruction. Observe the destination only when its policy can
        // differ; ordinary loops in an unselected body retain their raw
        // branches.
        for (const auto &item : graph->instructions) {
          const auto &instruction = item.second;
          if (!(instruction.role & UserspaceDirect))
            continue;
          const app_pc destination = item.first + instruction.target_delta;
          if (!graph->instructions.count(destination))
            continue;
          for (const auto *ranges : {&module->within_inline_ranges,
                                     &module->observation_inline_ranges})
            for (const auto &range : *ranges)
              if ((item.first >= range.first && item.first < range.second) !=
                  (destination >= range.first && destination < range.second))
                boundaries.insert(destination);
        }
        std::string previous_scope;
        app_pc previous_end = nullptr;
        for (auto item = graph->instructions.begin();
             item != graph->instructions.end(); ++item) {
          const auto &instruction = item->second;
          if (selection) {
            const uint64_t offset = item->first - module->start;
            const auto selected = std::lower_bound(
                selection->instructions.begin(), selection->instructions.end(),
                offset, [](const auto &entry, uint64_t value) {
                  return entry.offset < value;
                });
            if (selected == selection->instructions.end() ||
                selected->offset != offset)
              continue;
          }
          ct_userspace_version_instruction input;
          input.pc = item->first;
          input.length = instruction.length;
          std::memcpy(input.bytes, instruction.original, instruction.length);
          input.boundary = current_functions.count(item->first) ||
                           boundaries.count(item->first);
          if (previous_end) {
            const auto transition = boundaries.lower_bound(previous_end);
            input.boundary |=
                transition != boundaries.end() && *transition <= item->first;
          }
          if (level == ct_instrument_level::perfetto) {
            std::unique_ptr<ct_location> query;
            ct_location_view location;
            if (!initial_source_location(selection, *module, input.pc,
                                         input.length, input.bytes, location)) {
              query = std::make_unique<ct_location>();
              ct_analysis_lookup(module->analysis, item->first - module->start,
                                 query.get());
              location = *query;
            }
            std::string scope = std::to_string(location.source_id) + ":" +
                                std::to_string(location.function_id) + ":" +
                                location.scope_chain + ":" + location.symbol;
            for (const auto *source :
                 ct_perfetto_source_scopes(location, location.source_usable))
              scope += ":" + std::to_string(source->id);
            input.boundary |=
                previous_scope != scope ||
                module->perfetto_boundaries.count(item->first) ||
                (instruction.role & (UserspaceCall | UserspaceReturn |
                                     UserspaceSyscall | UserspaceBranch));
            auto successor = std::next(item);
            input.boundary |=
                (instruction.role & UserspaceCompare) &&
                successor != graph->instructions.end() &&
                successor->first == item->first + instruction.length &&
                (successor->second.role & UserspaceConditional);
            previous_scope = std::move(scope);
          }
          previous_end = item->first + instruction.length;
          instructions.push_back(input);
        }

        preparation = prepared.preparation = ++userspace_version_generation;
        auto job = std::make_unique<SharedVersionPreparation>();
        job->graph = std::move(graph_owner);
        job->instructions = std::move(instructions);
        prepared_code = job.get();
        if (!version_preparations.emplace(context, std::move(job)).second) {
          prepared.preparation = 0;
          return nullptr;
        }
        preparation_scope.context = context;
      }
    }
    if (preparation) {
      // Module identities and graph snapshots outlive unload. Do disk I/O,
      // decoding and executable allocation without the client analysis lock:
      // producers in another thread must be able to make progress here.
      char runtime_identity[65]{};
      const bool compatible = !shared_runtime_identity.empty() &&
                              ct_analysis_runtime_identity(runtime_identity) &&
                              shared_runtime_identity == runtime_identity;
      if (!compatible)
        shared_version_fallbacks[static_cast<unsigned>(level)].fetch_add(
            1, std::memory_order_relaxed);
      const ct_userspace_version_cache cache{
          module->identity.c_str(), module->start,
          size_t(module->end - module->start), execution_policy.c_str(),
          compatible ? runtime_identity : ""};
      prepare_userspace_version(context, thread, level, preparation,
                                prepared_code->instructions, cache,
                                *prepared_code, prepared_code->error);
    }
    Lock lock(analysis_lock);
    auto found = module->userspace_versions.find(key);
    if (found == module->userspace_versions.end())
      return nullptr;
    auto &prepared = found->second;
    if (!module->active || module->userspace_disabled ||
        module->code_generation != code_generation ||
        module->userspace_binding_generation != binding_generation ||
        prepared.graph.get() != graph) {
      if (preparation && prepared.preparation == preparation)
        prepared.preparation = 0;
      return nullptr;
    }
    if (preparation) {
      auto &code = prepared_code->code;
      auto &error = prepared_code->error;
      if (prepared.preparation != preparation || prepared.graph.get() != graph)
        return nullptr;
      prepared.preparation = 0;
      // Mapping mutations and original JMP publication take this same lock.
      // Validate the unchanged, non-writable original before publishing RX.
      if (code && (!private_executable_mapping(graph->begin, graph->end) ||
                   !ct_userspace_version_validate(
                       code.get(), ct_userspace_patch_read_original))) {
        code.reset();
        error = "original code changed before userspace publication";
      }
      prepared.error = std::move(error);
      if (code) {
        ct_userspace_version_mark_published(code.get());
        if (prepared_code->object) {
          shared_userspace_versions.emplace(code.get(), prepared_code->object);
          prepared_code->object = 0;
          auto &counter = ct_userspace_version_shared_restored(code.get())
                              ? restored_shared_versions
                              : published_shared_versions;
          counter[static_cast<unsigned>(level)].fetch_add(
              1, std::memory_order_relaxed);
        }
        if (instrumentation_statistics) {
          const auto index = static_cast<unsigned>(level);
          generated_userspace_versions[index].fetch_add(
              1, std::memory_order_relaxed);
          restored_userspace_templates[index].fetch_add(
              ct_userspace_version_restored(code.get()),
              std::memory_order_relaxed);
          restored_userspace_common[index].fetch_add(
              ct_userspace_version_common_restored(code.get()),
              std::memory_order_relaxed);
          decoded_userspace_instructions[index].fetch_add(
              ct_userspace_version_decoded_count(code.get()),
              std::memory_order_relaxed);
        }
        prepared.code = code.release();
        prepared.source_generation = code_generation;
      }
      if (instrumentation_statistics && !prepared.error.empty())
        ++userspace_version_fallbacks[{level, prepared.error}];
    }
    if (prepared.code) {
      entry = ct_userspace_version_entry(prepared.code, pc);
      if (attempt)
        attempt->store(entry ? 1 : 0, std::memory_order_release);
      if (!entry)
        return nullptr;
    } else {
      if (attempt && level != ct_instrument_level::arm)
        attempt->store(0, std::memory_order_release);
    }
  }
  return entry;
}

static void try_userspace(app_pc pc, std::atomic<uint32_t> *attempt = nullptr) {
  if (!duplicate_enabled || !traced_process() || !recording_thread())
    return;
  void *context = dr_get_current_drcontext();
  Thread &thread = *thread_state(context);
  if (!thread.owns_image)
    return;
  dr_mcontext_t state{};
  state.size = sizeof(state);
  state.flags = DR_MC_ALL;
  if (!dr_get_mcontext(context, &state) || (state.xflags & 0x100))
    return;
  const uint64 generation = dr_userspace_execution_generation(context);
  ct_instrument_level level;
  app_pc step_end = nullptr;
  {
    Lock lock(analysis_lock);
    const bool step_into = detailed_hit_at(pc);
    level = ct_required_instrumentation(ct_perfetto_enabled(), step_into);
    // Runtime entry needs a captured before-state; code preparation does not.
    if (step_into && (!thread.pending.site || thread.pending.timing_only ||
                      thread.pending.site->instruction.pc != pc ||
                      current_functions.count(pc)))
      return;
    if (step_into)
      step_end = thread.pending.site->instruction.next;
  }
  const app_pc entry = prepare_userspace_copy(context, pc, level, attempt);
  if (entry) {
    state.pc = entry;
    thread.userspace_step_end = step_end;
    thread.userspace_copy_level = level;
    thread.userspace_copy_pending = true;
    if (ct_perfetto_enabled())
      ct_timing_quiet_begin(context);
    if (!thread.calls.empty() && thread.calls.back()->startup_entry)
      thread.calls.back()->startup_controlled = false;
    dr_redirect_userspace_execution(&state, generation);
    thread.userspace_copy_pending = false;
    thread.userspace_step_end = nullptr;
  } else if (level == ct_instrument_level::arm) {
    thread.userspace_copy_pending = false;
    try_userspace_arm(pc, attempt);
  }
}

static void observe(app_pc pc, bool inline_scope, bool entry_boundary) {
  {
    QuietCallback quiet(dr_get_current_drcontext());
    ct_dr_shared_service(dr_get_current_drcontext());
  }
  observe_instruction(pc, inline_scope, entry_boundary);
  try_userspace(pc);
}

static void function_enter(void *wrap_context, void **user_data) {
  QuietCallback quiet(drwrap_get_drcontext(wrap_context));
  auto function = static_cast<Function *>(*user_data)->shared_from_this();
  *user_data = nullptr;
  if (!traced_process() || !recording_thread() ||
      (!structural_instrumentation() && within_enabled && !function->within &&
       !within_active()))
    return;
  Thread &thread = *thread_state(drwrap_get_drcontext(wrap_context));
  if (thread.calls.empty())
    thread.userspace_waited_key = {};
  if (ct_perfetto_enabled()) {
    thread.trace_timestamp =
        ct_perfetto_now(ct_timing_sample(drwrap_get_drcontext(wrap_context)));
    thread.trace_signal_timestamp = {};
  }
  Lock lock(analysis_lock);
  const auto current = current_functions.find(function->pc);
  if (!function->module->active || current == current_functions.end() ||
      current->second != function)
    return;
  ct_registers registers = registers_at(
      drwrap_get_mcontext_ex(wrap_context, DR_MC_ALL), function->pc);
  const auto previous = thread.pending.site;
  const bool observed_call = previous && previous->instruction.call;
  const bool observed_transfer =
      previous && (previous->instruction.call || previous->instruction.branch ||
                   previous->instruction.ret);
  advance(thread, registers, function->pc);
  const app_pc return_pc = drwrap_get_retaddr(wrap_context);
  const bool possible_raw_call =
      !thread.calls.empty() &&
      (thread.calls.back()->startup_entry
           ? !observed_transfer
           : registers.gpr[7] < thread.calls.back()->entry_sp);
  bool executable_return = false;
  if (possible_raw_call || function->init_entry) {
    dr_mem_info_t memory{};
    executable_return = return_pc && dr_query_memory_ex(return_pc, &memory) &&
                        (memory.prot & DR_MEMPROT_EXEC) &&
                        !dr_memory_is_dr_internal(return_pc) &&
                        !dr_memory_is_in_client(return_pc);
  }
  if (possible_raw_call && executable_return && module_at(return_pc)) {
    // A raw unobserved CALL can reach a selected entry gate without leaving a
    // Pending instruction. The entry wrapper supplies its actual saved return
    // PC; accept a new frame only when that PC belongs to executable app text.
    auto *call = new Call;
    call->entry_pc = function->pc;
    call->entry_sp = registers.gpr[7];
    call->return_pc = return_pc;
    call->scope.recurse = within_active() && thread.calls.back()->scope.recurse;
    call->scope.blocked = within_active() && thread.calls.back()->scope.blocked;
    call->timing_only = structural_instrumentation();
    thread.calls.push_back(call);
  }
  if (function->init_entry && !observed_call && !executable_return &&
      thread.calls.size() == 1) {
    const Call &frame = *thread.calls.back();
    // Structural tracing may retain the interpreter's initial pseudo-frame.
    // Its unchanged argc word is not a caller of the executable's entry.
    if (!frame.signal_frame && !frame.startup_entry && frame.function &&
        frame.function->module != function->module &&
        frame.entry_sp == registers.gpr[7] && frame.return_pc == return_pc)
      leave_call(thread, registers, false);
  }
  if (within_enabled && !thread.calls.empty()) {
    Call &frame = *thread.calls.back();
    const bool startup_tail =
        previous && startup_owns_instruction(frame, *previous) &&
        previous->instruction.branch && !previous->instruction.call &&
        !previous->instruction.ret;
    if (startup_tail)
      frame.entry_sp = registers.gpr[7];
    if (frame.startup_entry && frame.function && frame.function != function &&
        !startup_tail)
      return;
    if ((startup_tail ||
         (!frame.startup_entry && frame.entry_sp == registers.gpr[7])) &&
        frame.function && frame.function != function) {
      // A tail jump replaces this physical frame; the previous function is
      // no longer on the active call stack. Matching ancestors remain valid.
      frame.within = function->within;
      frame.within_inline = false;
      frame.signal_handler_active = false;
      update_within(thread);
      if (!within_active() && !structural_instrumentation()) {
        end_trace_function(frame.machine, thread.trace_timestamp,
                           "tail_transfer");
        thread.pending = Pending{};
        if (!frame.signal_frame)
          leave_call(thread, registers, false);
        return;
      }
    }
  }
  if (within_enabled && function->within) {
    if (thread.calls.empty() ||
        thread.calls.back()->entry_sp != registers.gpr[7]) {
      auto *root = new Call;
      root->entry_pc = function->pc;
      root->entry_sp = registers.gpr[7];
      // ELF startup has argc at RSP, not an ordinary saved return address.
      // A later real CALL to the same exact entry keeps normal frame rules.
      root->startup_entry =
          function->init_entry && !observed_call && !executable_return;
      root->startup_controlled = root->startup_entry;
      root->return_pc = root->startup_entry ? nullptr : return_pc;
      thread.calls.push_back(root);
    }
    thread.calls.back()->within = true;
    if (!function->init_entry)
      *user_data = reinterpret_cast<void *>(registers.gpr[7]);
    else
      // The ELF entry uses no drwrap post hook, including later ordinary
      // calls. Keep RET/tail bookkeeping active even when its body is skipped.
      boundary_observation_started.store(true, std::memory_order_release);
    update_within(thread);
  }
  if (thread.calls.empty() &&
      (structural_instrumentation() ||
       (within_active() && arming_mode_at(function->pc) != Site::Skip))) {
    auto *root = new Call;
    root->entry_pc = function->pc;
    root->entry_sp = registers.gpr[7];
    root->return_pc = drwrap_get_retaddr(wrap_context);
    root->timing_only = true;
    thread.calls.push_back(root);
  }
  if (thread.calls.empty())
    return;
  Call *call = thread.calls.back();
  if (registers.gpr[7] != call->entry_sp)
    return;
  // A tail entry may reuse the physical Call, including a self-tail call.
  call->userspace_waited_key = {};
  if (call->linkage) {
    auto location_storage = std::make_unique<ct_location>();
    ct_location &location = *location_storage;
    ct_analysis_lookup_arming(function->module->analysis,
                              function->pc - function->module->start,
                              &location);
    if (!location.is_plt)
      call->linkage = false;
  }
  if (call->linkage_child)
    return;
  if (call->assembly_entry) {
    flush_machine_rows(call->machine);
    close_visit(call->visit);
    close_plt(call->machine, call->visit);
    close_machine_blocks(call->machine);
    close_assembly_function(*call);
  }
  if (call->function && call->function != function) {
    defer_return(thread, call->visit);
    for (auto &origin : call->provenance.registers)
      if (!origin.source_identity.empty())
        origin = {};
  }
  call->function = function;
  call->frame_base_restored = false;
  if (within_active())
    execution_mode() = detailed_hit_at(function->pc) ? 1 : 2;
  if ((!call->parent || !call->parent->first) && !call->deferred_call.first) {
    auto location = std::make_unique<ct_location>();
    ct_analysis_lookup_arming(function->module->analysis,
                              function->pc - function->module->start,
                              location.get());
    Site::Mode mode, physical_mode;
    std::vector<Site::Mode> inline_modes;
    filter_modes(*function->module, *location, mode, physical_mode,
                 inline_modes);
    bool recurse = call->scope.recurse, blocked = call->scope.blocked;
    mode = enter_scope(physical_mode, recurse, blocked);
    for (Site::Mode inline_mode : inline_modes)
      mode = enter_scope(inline_mode, recurse, blocked);
    if (!within_active() || mode == Site::Skip) {
      call->timing_only = true;
      return;
    }
  }
  boundary_observation_started.store(true, std::memory_order_release);
  if (detailed_hit_at(function->pc))
    trace_activated.store(true, std::memory_order_release);
  call->timing_only = false;
  call->entry_reported = false;
  call->decompiled_declaration = false;
  call->declaration.clear();
  call->entry_arguments.clear();
  call->entry_types.clear();
  call->display_name.clear();
  call->display_symbol.clear();
  if (!function->type)
    function->type =
        ct_function_prepare(module_values(*function->module),
                            reinterpret_cast<uint64_t>(function->pc));
  char snapshot[value_capacity]{};
  if (ct_function_declaration(function->type, function->name.c_str(), snapshot,
                              sizeof(snapshot)))
    call->declaration = snapshot;
  if (ct_function_entry_arguments(function->type, &registers, read_memory,
                                  nullptr, snapshot, sizeof(snapshot)))
    call->entry_arguments = snapshot;
  const bool have_entry_values =
      ct_function_argument_values(function->type, &registers, read_memory,
                                  nullptr, snapshot, sizeof(snapshot));
  call->invocation =
      function->name + "(" + (have_entry_values ? snapshot : "?") + ")";
  Visit *parent = call->parent;
  if (parent && parent->source && parent->first &&
      source_available(*parent->first)) {
    auto target = std::make_unique<ct_location>();
    ct_analysis_lookup(function->module->analysis,
                       function->pc - function->module->start, target.get());
    const auto matches_callee = [&](const char *callee) {
      if (callee == function->name ||
          (!target->inlined && std::strcmp(callee, target->symbol) == 0) ||
          (target->scope_chain_size &&
           std::strcmp(callee, target->scope_chain) == 0))
        return true;
      const char *aliases =
          target->inlined ? target->physical_aliases : target->aliases;
      const size_t aliases_size = target->inlined
                                      ? target->physical_aliases_size
                                      : target->aliases_size;
      for (size_t offset = 0; offset < aliases_size;) {
        const char *alias = aliases + offset;
        if (std::strcmp(callee, alias) == 0)
          return true;
        offset += std::strlen(alias) + 1;
      }
      return false;
    };
    if (!target->is_plt && !call->source_function) {
      call->source_function = function;
      if (call->source_call_site && source_available(*call->source_call_site)) {
        const auto &location = call->source_call_site->location;
        const ct_source_call_result *only = nullptr, *exact = nullptr,
                                    *covering = nullptr;
        size_t matches = 0, exact_matches = 0, covering_matches = 0;
        if (location.source_call_result_count <=
            std::size(location.source_call_results))
          for (size_t index = 0; index < location.source_call_result_count;
               ++index) {
            const auto &candidate = location.source_call_results[index];
            if (!candidate.text[0] || !candidate.callee[0] ||
                !matches_callee(candidate.callee))
              continue;
            only = &candidate;
            ++matches;
            if (location.column && location.column == candidate.begin_column) {
              exact = &candidate;
              ++exact_matches;
            }
            if (location.column && location.column >= candidate.begin_column &&
                location.column < candidate.end_column) {
              covering = &candidate;
              ++covering_matches;
            }
          }
        // The call instruction's DWARF column identifies repeated/nested
        // expressions. Never assume source order equals evaluation order.
        if (exact_matches == 1)
          call->source_call_result = exact;
        else if (!exact_matches && covering_matches == 1)
          call->source_call_result = covering;
        else if (!exact_matches && !covering_matches && matches == 1)
          call->source_call_result = only;
        while (call->source_call_result) {
          const auto &selected = *call->source_call_result;
          const ct_source_call_result *dependency = nullptr;
          bool ambiguous = false;
          for (size_t index = 0; index < location.source_call_result_count;
               ++index) {
            const auto &nested = location.source_call_results[index];
            if (nested.id == selected.id || !matches_callee(nested.callee) ||
                nested.begin_column < selected.begin_column ||
                nested.end_column > selected.end_column ||
                parent->completed_source_calls.count(nested.id))
              continue;
            if (!dependency ||
                (nested.begin_column <= dependency->begin_column &&
                 nested.end_column >= dependency->end_column)) {
              dependency = &nested;
            } else if (nested.begin_column < dependency->begin_column ||
                       nested.end_column > dependency->end_column) {
              ambiguous = true;
            }
          }
          if (!dependency)
            break;
          // GCC can give an entire nested call chain the outer call's column.
          // A sole call argument must complete before its enclosing call.
          // Other shapes may contain optional/unevaluated calls or sibling
          // arguments whose evaluation order cannot be inferred here.
          const std::string text = selected.text;
          const size_t begin = dependency->begin_column - selected.begin_column;
          const size_t end = dependency->end_column - selected.begin_column;
          const size_t opening = text.find('(');
          bool direct = !ambiguous && opening != std::string::npos && opening &&
                        begin > opening && end <= text.size() && begin < end &&
                        text.compare(begin, end - begin, dependency->text) == 0;
          for (size_t index = 0; direct && index < opening; ++index) {
            const unsigned char character = text[index];
            direct = std::isalnum(character) || character == '_' ||
                     character == ':' || std::isspace(character);
          }
          size_t parentheses = 1;
          for (size_t index = opening + 1; direct && index < begin; ++index) {
            const unsigned char character = text[index];
            if (character == '(')
              ++parentheses;
            else if (!std::isspace(character))
              direct = false;
          }
          for (size_t index = end; direct && index < text.size(); ++index) {
            const unsigned char character = text[index];
            if (character == ')' && parentheses)
              --parentheses;
            else if (!std::isspace(character))
              direct = false;
          }
          call->source_call_result =
              direct && !parentheses ? dependency : nullptr;
        }
        call->source_call_ambiguous = matches > 1 && !call->source_call_result;
      }
    }
    if (call->source_function == function && call->source_call_result &&
        call->source_call_result->display_name[0] && !target->is_plt) {
      call->display_name = call->source_call_result->display_name;
      call->display_symbol =
          target->scope_chain_size ? target->scope_chain : target->symbol;
    }
    for (size_t macro_index = 0;
         macro_index < parent->first->location.source_macro_count;
         ++macro_index) {
      const auto &macro = parent->first->location.source_macros[macro_index];
      if (!macro.identity[0] || macro.call_count > std::size(macro.calls) ||
          macro.callees_size > sizeof(macro.callees))
        continue;
      const size_t text_size = std::strlen(macro.text);
      for (size_t index = 0; index < macro.call_count; ++index) {
        const auto &candidate = macro.calls[index];
        if (!candidate.runtime_address || target->is_plt ||
            candidate.callee_offset >= macro.callees_size ||
            candidate.address_begin >= candidate.address_end ||
            candidate.address_end > text_size)
          continue;
        const char *callee = macro.callees + candidate.callee_offset;
        if (!callee[0] ||
            !std::memchr(callee, '\0',
                         macro.callees_size - candidate.callee_offset))
          continue;
        if (!matches_callee(callee))
          continue;
        // Repeated references and ELF aliases name this same observed entry;
        // no per-call argument values are inferred from that shared identity.
        char address[32];
        dr_snprintf(address, sizeof(address), "0x%llx",
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(function->pc)));
        parent->macro_values[{macro.identity, macro_index}].emplace(
            candidate.address_begin, address);
      }
    }
    const ct_location_view &source = parent->first->location;
    if (!target->is_plt && !target->function_id &&
        source.source_call_count <= std::size(source.source_calls) &&
        source.call_parameter_count <= std::size(source.call_parameters)) {
      const ct_source_call *signature = nullptr;
      size_t matches = 0;
      for (size_t index = 0; index < source.source_call_count; ++index) {
        const auto &candidate = source.source_calls[index];
        if (!candidate.callee[0] ||
            candidate.parameter_begin > source.call_parameter_count ||
            candidate.parameter_count >
                source.call_parameter_count - candidate.parameter_begin ||
            !matches_callee(candidate.callee))
          continue;
        signature = &candidate;
        ++matches;
      }
      if (matches == 1) {
        const auto *parameters =
            signature->parameter_count
                ? &source.call_parameters[signature->parameter_begin]
                : nullptr;
        bool valid = true;
        for (size_t index = 0; index < signature->parameter_count; ++index) {
          const auto &type = parameters[index].type;
          valid &= type.kind != CT_VALUE_UNKNOWN && type.bytes &&
                   type.bytes <= 8 &&
                   (type.kind != CT_VALUE_FLOAT || type.bytes == 4 ||
                    type.bytes == 8);
        }
        if (valid) {
          std::string named, positional;
          if (call->declaration.empty() && signature->declaration[0])
            call->declaration = signature->declaration;
          // A verified declaration supplies names and scalar ABI slots, not
          // local storage locations. Track entry-register values as snapshots.
          // Copies remain meaningful if the original argument register changes.
          const unsigned integer_registers[] = {5, 4, 1, 2, 8, 9};
          size_t integers = 0, vectors = 0, stack_offset = 8;
          call->provenance = {};
          for (size_t index = 0; index < signature->parameter_count; ++index) {
            const auto &parameter = parameters[index];
            const bool floating = parameter.type.kind == CT_VALUE_FLOAT;
            size_t reg = call->provenance.registers.size();
            unsigned char bytes[8]{};
            bool observed = false;
            if (floating && vectors < 8) {
              const size_t slot = vectors++;
              if (registers.have_xmm &&
                  parameter.type.bytes <= registers.simd_bytes) {
                reg = 17 + slot;
                std::memcpy(bytes, registers.xmm[slot], parameter.type.bytes);
                observed = true;
              }
            } else if (!floating && integers < std::size(integer_registers)) {
              const unsigned slot = integer_registers[integers++];
              if (registers.have_gpr &&
                  !(registers.unavailable_gpr & (UINT64_C(1) << slot))) {
                reg = slot;
                std::memcpy(bytes, &registers.gpr[slot], parameter.type.bytes);
                observed = true;
              }
            } else {
              if (registers.have_gpr &&
                  registers.gpr[7] <= UINT64_MAX - stack_offset)
                observed = read_memory(nullptr, registers.gpr[7] + stack_offset,
                                       bytes, parameter.type.bytes);
              stack_offset += 8;
            }
            char formatted[1024]{};
            std::string value = "?";
            if (observed &&
                ct_values_format_typed("value", &parameter.type, bytes,
                                       parameter.type.bytes, formatted,
                                       sizeof(formatted)))
              value = formatted + 6;
            if (index) {
              named += ", ";
              positional += ", ";
            }
            const std::string parameter_name =
                parameter.name[0] ? parameter.name
                                  : "arg" + std::to_string(index + 1);
            const std::string identity =
                "parameter:" + function->module->identity + ":" +
                std::to_string(reinterpret_cast<uintptr_t>(function->pc)) +
                ":" + std::to_string(index) + ":" + parameter_name + ":" +
                parameter.type_name;
            if (!have_entry_values)
              call->entry_types.push_back(
                  {named.size() + parameter_name.size() + 1, identity,
                   parameter.type_name});
            named += parameter_name + "=" + value;
            positional += value;
            // Stack-passed parameters need a separate memory-lifetime proof.
            if (reg == call->provenance.registers.size() || !parameter.name[0])
              continue;
            auto &origin = call->provenance.registers[reg];
            origin.name = parameter.name;
            origin.type_name = parameter.type_name;
            origin.type = parameter.type;
            origin.bytes = parameter.type.bytes;
            origin.source_identity = identity;
          }
          if (!have_entry_values) {
            if (signature->variadic)
              positional += positional.empty() ? "..." : ", ...";
            call->entry_arguments = std::move(named);
            call->invocation = function->name + "(" + positional + ")";
          }
        }
      }
    }
  }
  if (!call->display_name.empty()) {
    if (ct_function_declaration(function->type, call->display_name.c_str(),
                                snapshot, sizeof(snapshot)))
      call->declaration = snapshot;
    const std::string prefix = function->name + "(";
    if (call->invocation.compare(0, prefix.size(), prefix) == 0)
      call->invocation.replace(0, function->name.size(), call->display_name);
  }
  if (!function->type)
    function->type =
        ct_function_prepare(module_values(*function->module),
                            reinterpret_cast<uint64_t>(function->pc));
  char arguments[value_capacity];
  ct_function_arguments(function->type, &registers, read_memory, nullptr,
                        arguments, sizeof(arguments));
  call->arguments = arguments;
  named_value_types(nullptr, function->type, call->entry_arguments,
                    call->entry_types);
}

static void within_exit(void *wrap_context, void *user_data) {
  QuietCallback quiet(dr_get_current_drcontext());
  if (!user_data || !traced_process() || !recording_thread())
    return;
  void *context = dr_get_current_drcontext();
  Thread &thread = *thread_state(context);
  if (ct_perfetto_enabled())
    thread.trace_timestamp = ct_perfetto_now(ct_timing_sample(context));
  Lock lock(analysis_lock);
  if (wrap_context) {
    dr_mcontext_t *machine = drwrap_get_mcontext_ex(wrap_context, DR_MC_ALL);
    advance(thread, registers_at(machine, machine->pc), machine->pc);
  } else {
    const uintptr_t entry_sp = reinterpret_cast<uintptr_t>(user_data);
    dr_mcontext_t machine{};
    machine.size = sizeof(machine);
    machine.flags = DR_MC_CONTROL;
    // drwrap can infer an unwind from return-site bookkeeping that raw nested
    // calls bypassed. A still-deeper actual stack disproves that inference.
    // If a machine context is unavailable, retain the frame until a normal
    // observation or signal transfer establishes its lifetime.
    if (!dr_get_mcontext(context, &machine) || machine.xsp <= entry_sp)
      return;
    while (!thread.calls.empty() && thread.calls.back()->entry_sp <= entry_sp) {
      // drwrap's cleanup can observe the signal-restorer stack as an
      // unwind. Only the kernel's signal-return notification owns that
      // marker and the interrupted frames beneath it.
      if (thread.calls.back()->signal_frame ||
          thread.calls.back()->startup_entry)
        break;
      if (thread.pending.site)
        thread.pending = Pending{};
      leave_call(thread, ct_registers{}, false);
    }
  }
  update_within(thread);
}

static bool within_matches(const Module &module, const char *name) {
  return within_filter.matches(name, ct_analysis_soname(module.analysis),
                               module.path.c_str(), module.is_main);
}

static void collect_function(uint64_t offset, const char *name, void *context) {
  auto *module = static_cast<Module *>(context);
  app_pc pc = module->start + offset;
  if (pc < module->start || pc >= module->end)
    return;
  if (current_functions.count(pc))
    return;
  auto function = std::make_shared<Function>();
  function->module = module->shared_from_this();
  function->pc = pc;
  function->name = name;
  function->init_entry =
      within_init && module->is_main && pc == module->entry_point;
  function->within = function->init_entry;
  if (within_patterns_enabled && !function->within) {
    auto location_storage = std::make_unique<ct_location>();
    ct_location &location = *location_storage;
    ct_analysis_lookup_arming(module->analysis, offset, &location);
    function->within = within_matches(*module, name);
    const char *aliases =
        location.inlined ? location.physical_aliases : location.aliases;
    const size_t aliases_size = location.inlined
                                    ? location.physical_aliases_size
                                    : location.aliases_size;
    if (location.scope_chain_size)
      function->within |= within_matches(*module, location.scope_chain);
    for (size_t index = 0; !function->within && index < aliases_size;) {
      const char *alias = aliases + index;
      function->within = within_matches(*module, alias);
      index += strlen(alias) + 1;
    }
  }
  current_functions[pc] = function;
  functions.push_back(std::move(function));
}

static void collect_inline_scope(uint64_t begin, uint64_t end, const char *name,
                                 void *context) {
  auto &module = *static_cast<Module *>(context);
  if (begin >= end || end > static_cast<uint64_t>(module.end - module.start))
    return;
  if (filtered)
    module.observation_inline_ranges.emplace_back(module.start + begin,
                                                  module.start + end);
  const bool within = within_enabled && within_matches(module, name);
  const Site::Mode mode = filter_mode(module, name);
  if (within || mode == Site::Into || mode == Site::Recurse)
    module.userspace_reentry_inline_ranges.emplace_back(module.start + begin,
                                                        module.start + end);
  if (within)
    module.within_inline_ranges.emplace_back(module.start + begin,
                                             module.start + end);
}

struct OriginalCodeInstruction {
  uint64_t offset;
  size_t size;
  const byte *bytes;
};

// Both the CFG export and a published userspace graph have sorted, disjoint
// original instructions. View their existing storage without copying a proof.
template <typename Iterator, typename View>
static bool original_instructions_current(const Module &module, Iterator first,
                                          Iterator last, View view,
                                          bool *bytes_changed = nullptr) {
  if (bytes_changed)
    *bytes_changed = false;
  const uint64_t module_size = module.end - module.start;
  app_pc verified_end = nullptr;
  uint64_t previous_end = 0;
  for (auto index = first; index != last;) {
    const uint64_t begin = view(*index).offset;
    if (begin < previous_end || begin >= module_size)
      return false;
    auto next = index;
    uint64_t end = begin;
    do {
      const auto instruction = view(*next);
      if (!instruction.size || instruction.size > 15 || !instruction.bytes ||
          instruction.size > module_size - end)
        return false;
      if (instruction.size > initial_proof_chunk - (end - begin))
        break;
      end += instruction.size;
      ++next;
    } while (next != last && view(*next).offset == end);
    const app_pc pc = module.start + begin;
    const app_pc limit = module.start + end;
    for (app_pc cursor = pc; cursor < limit;) {
      // The proof is rebuilt on every invocation. Reuse only the RX mapping
      // extent checked in this invocation, never across source generations.
      if (cursor < verified_end) {
        cursor = verified_end;
        continue;
      }
      dr_mem_info_t memory{};
      if (!dr_query_memory_ex(cursor, &memory) ||
          (memory.prot & (DR_MEMPROT_READ | DR_MEMPROT_EXEC)) !=
              (DR_MEMPROT_READ | DR_MEMPROT_EXEC) ||
          (memory.prot & DR_MEMPROT_WRITE) || memory.base_pc > cursor ||
          memory.size > UINTPTR_MAX - uintptr_t(memory.base_pc) ||
          memory.base_pc + memory.size <= cursor)
        return false;
      cursor = verified_end = memory.base_pc + memory.size;
    }
    byte bytes[initial_proof_chunk];
    if (!ct_userspace_patch_read_original(pc, end - begin, bytes))
      return false;
    for (; index != next; ++index) {
      const auto instruction = view(*index);
      if (std::memcmp(bytes + (instruction.offset - begin), instruction.bytes,
                      instruction.size)) {
        if (bytes_changed)
          *bytes_changed = true;
        return false;
      }
    }
    previous_end = end;
  }
  return true;
}

// These checks do not change active call-stack selection. A generation can be
// prepared for a future selected call while current execution remains arm.
static bool initial_bytes_current(const InitialPreparation &job,
                                  app_pc begin = nullptr,
                                  app_pc end = nullptr) {
  const Module &module = *job.module;
  if (!module.active || module.pending_code_changes ||
      module.code_generation != job.generation)
    return false;
  auto first = job.instructions.begin(), last = job.instructions.end();
  if (begin || end) {
    if (begin < module.start || end > module.end || begin >= end)
      return false;
    const auto offset_before = [](const auto &instruction, uint64_t offset) {
      return instruction.offset < offset;
    };
    first = std::lower_bound(first, last, uint64_t(begin - module.start),
                             offset_before);
    last = std::lower_bound(first, last, uint64_t(end - module.start),
                            offset_before);
    if (first == last || first->offset != uint64_t(begin - module.start) ||
        std::prev(last)->offset + std::prev(last)->size !=
            uint64_t(end - module.start))
      return false;
    uint64_t expected = begin - module.start;
    for (auto instruction = first; instruction != last; ++instruction) {
      if (instruction->offset != expected)
        return false;
      expected += instruction->size;
    }
  }
  return original_instructions_current(
      module, first, last, [](const auto &instruction) {
        return OriginalCodeInstruction{instruction.offset, instruction.size,
                                       instruction.bytes};
      });
}

// A pre-syscall stop has cancelled all copied PCs and pending redirects. Keep
// copies unavailable until every overlapping mapping transaction has ended.
// Failed syscalls can still leave changed permissions, so failure alone never
// authorizes reuse. A successful source mutation invalidates the generation.
static void revalidate_userspace_versions(Module &module) {
  if (!module.userspace_revalidation_pending ||
      module.pending_userspace_changes || module.pending_code_changes)
    return;
  std::map<const UserspaceGraph *, bool> checked;
  for (auto item = module.userspace_versions.begin();
       item != module.userspace_versions.end();) {
    auto &version = item->second;
    bool valid = module.active && version.code && !version.preparation &&
                 version.source_generation == module.code_generation &&
                 version.graph;
    if (valid) {
      const auto [proof, inserted] =
          checked.emplace(version.graph.get(), false);
      if (inserted)
        proof->second =
            private_executable_mapping(version.graph->begin,
                                       version.graph->end) &&
            original_instructions_current(
                module, version.graph->instructions.begin(),
                version.graph->instructions.end(),
                [&](const auto &instruction) {
                  return OriginalCodeInstruction{
                      uint64_t(instruction.first - module.start),
                      instruction.second.length, instruction.second.original};
                });
      valid = proof->second;
    }
    if (valid) {
      ++item;
    } else {
      if (version.code)
        module.retired_userspace_versions.push_back(version.code);
      item = module.userspace_versions.erase(item);
    }
  }
  module.userspace_graphs.clear();
  for (const auto &[key, version] : module.userspace_versions)
    module.userspace_graphs.emplace(key.first, version.graph);
  module.userspace_revalidation_pending = false;
}

// Called without client locks at a nolinking callback. Even a partial stop
// owns suspension resources: resume those peers before retrying or failing.
static void
retire_userspace_gates(const std::vector<std::pair<Module *, bool>> &affected) {
  bool retired = false;
  for (unsigned attempt = 0; attempt < userspace_retire_attempts && !retired;
       ++attempt) {
    void **contexts = nullptr;
    uint suspended = 0, unsuspended = 0;
    const bool stopped = dr_suspend_all_other_threads_ex(
        &contexts, &suspended, &unsuspended, DR_SUSPEND_NATIVE);
    bool safe = stopped && unsuspended == 0;
    for (uint index = 0; index < suspended; ++index) {
      suspend_thread_timing(contexts[index]);
      safe &= dr_cancel_suspended_userspace_execution(contexts[index]);
    }
    if (safe) {
      Lock lock(analysis_lock);
      for (const auto &[module, original] : affected) {
        // A modified image falls back to DR's code consistency
        // handling.
        module->userspace_ranges.clear();
        module->userspace_return_gates.clear();
        module->userspace_instructions.clear();
        module->userspace_rejected.clear();
        if (original) {
          module->userspace_graphs.clear();
          module->userspace_graph_failures.clear();
          module->userspace_revalidation_pending = true;
          for (auto item = module->userspace_versions.begin();
               item != module->userspace_versions.end();) {
            auto &version = item->second;
            if (version.code && !version.preparation && version.graph) {
              // Published immutable bodies cannot be entered while
              // disabled. Retain their exact graph until the syscall
              // outcome and complete original-byte proof are known.
              module->userspace_graphs.emplace(version.graph->begin,
                                               version.graph);
              ++item;
            } else {
              if (version.code)
                module->retired_userspace_versions.push_back(version.code);
              item = module->userspace_versions.erase(item);
            }
          }
        }
        // Copied versions contain only this module's original
        // instructions. CALL/RET/syscall/indirect or external branches
        // leave through DR original-PC gates; only internal branches
        // link copied nodes. Unchanged published copies therefore do
        // not depend on the retired cross-module original JMP graph.
        safe &= ct_userspace_patch_remove_range(
            module->start, size_t(module->end - module->start), true);
      }
      if (safe) {
        // All peers have abandoned copied PCs and pending redirects.
        // Copies execute CALL/RET under DR, and delivered signal frames
        // contain original PCs, so no saved application continuation
        // points into these bodies. Reclaim while peers remain stopped
        // and selection is locked, including older unload generations.
        ct_userspace_patch_reclaim();
        for (auto &module : modules) {
          for (auto *code : module->retired_userspace_versions) {
            if (!ct_userspace_version_discard(code))
              fail("cannot reclaim retired userspace execution version");
            auto shared = shared_userspace_versions.find(code);
            if (shared != shared_userspace_versions.end()) {
              released_shared_versions.push_back(shared->second);
              shared_userspace_versions.erase(shared);
            }
            ++reclaimed_userspace_versions;
          }
          module->retired_userspace_versions.clear();
        }
        reclaim_modules();
      }
    }
    for (uint index = 0; index < suspended; ++index)
      resume_thread_timing(contexts[index]);
    if (!dr_resume_all_other_threads(contexts, suspended))
      fail("cannot resume threads after userspace gate retirement");
    retired = safe;
    // A userspace gateway may have been interrupted on DR's stack.
    // Let it finish its redirect before retiring its active gate
    // record.
    if (!retired)
      dr_thread_yield();
  }
  if (!retired)
    fail("cannot safely retire userspace execution gates");
}

static bool initial_request_range_current(void *context, app_pc begin,
                                          app_pc end, void *data) {
  QuietCallback quiet(context);
  auto &job = *static_cast<InitialPreparation *>(data);
  Lock lock(analysis_lock);
  const auto position =
      job.module->initial_preparations.find({job.function, job.level});
  if (!process_recording || !job.module->active ||
      position == job.module->initial_preparations.end() ||
      position->second.cookie != job.cookie ||
      job.module->code_generation != job.generation ||
      job.module->pending_code_changes || job.module->pending_userspace_changes)
    return false;
  const bool current = initial_bytes_current(job, begin, end);
  job.source_mismatch |= !current;
  // Shared originals need thread-private sandbox fragments, which the eager
  // preparation API cannot publish. An eligibility cancellation is not a byte
  // mismatch: mapping transactions already retire copies and source
  // generations.
  return current &&
         ((begin || end)
              ? private_executable_mapping(begin, end)
              : std::all_of(
                    job.spans.begin(), job.spans.end(), [](const auto &span) {
                      return private_executable_mapping(span.start, span.end);
                    }));
}

// A changed alias can alter an R-X mapping without an application mapping
// syscall. Cancelled preparation must withdraw the already published userspace
// copy and partial DR emission before dispatch can select either one again.
static void initial_request_cancel(void *context, void *data) {
  auto &job = *static_cast<InitialPreparation *>(data);
  QuietCallback quiet(context);
  PreparationScope owners(*thread_state(context));
  std::vector<std::pair<Module *, bool>> affected;
  {
    Lock lock(analysis_lock);
    Module &source = *job.module;
    const auto state =
        source.initial_preparations.find({job.function, job.level});
    if (!job.source_mismatch || !process_recording || !source.active ||
        source.code_generation != job.generation ||
        source.pending_code_changes || source.pending_userspace_changes ||
        state == source.initial_preparations.end() ||
        state->second.cookie != job.cookie)
      return;
    invalidate_original_metadata(source);
    for (auto &module : modules) {
      if (!module->active)
        continue;
      owners.hold(*module);
      module->userspace_disabled = true;
      ++module->userspace_binding_generation;
      for (auto &attempt : module->userspace_attempts)
        attempt.second->store(0, std::memory_order_release);
      affected.emplace_back(module.get(), module.get() == &source);
    }
    // Publication is disabled before removal. Keep the immutable mappings
    // alive until suspended peers have abandoned copied PCs and redirects.
    for (auto &[key, version] : source.userspace_versions)
      if (version.code)
        source.retired_userspace_versions.push_back(version.code);
    source.userspace_versions.clear();
  }
  retire_userspace_gates(affected);
  if (!dr_unlink_flush_region(job.module->start,
                              size_t(job.module->end - job.module->start)))
    fail("cannot retire cancelled initial preparation");
  {
    Lock lock(analysis_lock);
    for (const auto &[module, original] : affected) {
      if (!module->active || module->pending_code_changes ||
          module->pending_userspace_changes)
        continue;
      revalidate_userspace_versions(*module);
      module->userspace_disabled = false;
      for (auto &attempt : module->userspace_attempts)
        attempt.second->store(1, std::memory_order_release);
    }
  }
}

static bool initial_request_current(void *context, void *data) {
  return initial_request_range_current(context, nullptr, nullptr, data);
}

static std::string execution_source_scope(const ct_location_view &location) {
  std::string scope = std::to_string(location.source_id) + ":" +
                      std::to_string(location.function_id) + ":" +
                      location.scope_chain + ":" + location.symbol;
  for (const auto *source :
       ct_perfetto_source_scopes(location, location.source_usable))
    scope += ":" + std::to_string(source->id);
  return scope;
}

static void initial_request_begin(void *context, uint cookie, void *data) {
  auto &job = *static_cast<InitialPreparation *>(data);
  thread_state(context)->initial_build = &job;
  job.resume_phase = cookie == job.resume_cookie;
  if (job.resume_phase)
    return;
  // This builds/publishes an immutable copy without evaluating live values,
  // redirecting execution, or installing an original-address patch.
  if (job.level == ct_instrument_level::full && ct_perfetto_enabled())
    prepare_userspace_copy(context, job.function,
                           ct_instrument_level::perfetto);
  prepare_userspace_copy(context,
                         job.module->start + job.instructions.front().offset,
                         job.level, nullptr, &job);
  if (job.level == ct_instrument_level::full) {
    Lock lock(analysis_lock);
    const auto version =
        job.module->userspace_versions.find({job.function, job.level});
    if (version != job.module->userspace_versions.end() &&
        version->second.code) {
      std::set<app_pc> exits;
      ct_userspace_version_exits(
          version->second.code,
          [](app_pc pc, void *data) {
            static_cast<std::set<app_pc> *>(data)->insert(pc);
          },
          &exits);
      for (app_pc pc : exits) {
        const uint64_t offset = pc - job.module->start;
        const auto instruction =
            std::lower_bound(job.instructions.begin(), job.instructions.end(),
                             offset, [](const auto &item, uint64_t value) {
                               return item.offset < value;
                             });
        if (instruction == job.instructions.end() ||
            instruction->offset != offset ||
            std::any_of(job.spans.begin(), job.spans.end(),
                        [&](const auto &span) { return span.start == pc; }))
          continue;
        job.resumes.push_back({pc, pc + instruction->size});
      }
    }
  }
  {
    Lock lock(analysis_lock);
    if (job.instructions.size() > ct_execution_instruction_limit)
      return;
    const bool structural =
        ct_perfetto_enabled() || job.level == ct_instrument_level::perfetto;
    const std::string policy = execution_policy +
                               (job.module->is_main ? ":main:" : ":library:") +
                               std::to_string(structural);
    unsigned char digest[32];
    const ct_digest_part policy_part{policy.data(), policy.size()};
    if (!ct_shared_digest_parts(&policy_part, 1, digest))
      return;
    std::vector<ct_execution_instruction> image;
    image.reserve(job.instructions.size());
    for (size_t index = 0; index < job.instructions.size(); ++index) {
      const auto &instruction = job.instructions[index];
      ct_execution_instruction original{};
      original.offset = instruction.offset;
      original.length = instruction.size;
      std::memcpy(original.bytes, instruction.bytes, original.length);
      image.push_back(original);
      if (!structural)
        continue;
      const app_pc pc = job.module->start + instruction.offset;
      ct_location_view location;
      if (job.locations.size() == job.instructions.size()) {
        location = job.locations[index]->view;
      } else {
        const auto site = current_sites.find(pc);
        if (site == current_sites.end() || site->second->module != job.module)
          return; // Keep the existing per-BB cache when no common view exists.
        location = site->second->location;
      }
      const auto scope = execution_source_scope(location);
      // Fold one row at a time: repeated long inline-scope strings must not
      // turn a bounded instruction job into an unbounded policy allocation.
      const uint64_t framing[] = {instruction.offset, scope.size(),
                                  job.module->perfetto_boundaries.count(pc)};
      const ct_digest_part parts[] = {{digest, sizeof(digest)},
                                      {framing, sizeof(framing)},
                                      {scope.data(), scope.size()}};
      if (!ct_shared_digest_parts(parts, std::size(parts), digest))
        return;
    }
    static constexpr char hexadecimal[] = "0123456789abcdef";
    std::string policy_digest;
    for (unsigned char byte : digest) {
      policy_digest += hexadecimal[byte >> 4];
      policy_digest += hexadecimal[byte & 15];
    }
    auto batch = std::make_unique<ct_execution_batch>();
    if (ct_execution_batch_open(job.module->identity, policy_digest, job.level,
                                job.module->end - job.module->start,
                                std::move(image), *batch))
      job.execution = std::move(batch);
  }
}

static bool initial_request_wait(void *context, app_pc next, void *data) {
  const auto &job = *static_cast<const InitialPreparation *>(data);
  const auto *thread =
      static_cast<const Thread *>(drmgr_get_tls_field(context, tls_index));
  if (!thread || !thread->recording)
    return false;
  const auto scope = std::lower_bound(
      job.scopes.begin(), job.scopes.end(), next,
      [](const auto &item, app_pc pc) { return item.pc < pc; });
  if (scope == job.scopes.end() || scope->pc != next)
    return false;
  if (job.level == ct_instrument_level::perfetto)
    return ct_perfetto_enabled();
  const bool active = within_call_stack(*thread) || scope->within;
  if (!active)
    return false;
  const TraceScope &caller =
      thread->calls.empty() ? thread->root_scope : thread->calls.back()->scope;
  bool recurse = caller.recurse && !caller.blocked;
  if (thread->pending.site && thread->pending.site->instruction.call)
    recurse = thread->pending.recurse && !thread->pending.blocked;
  return recurse ? scope->recursive : scope->plain;
}

static void queue_initial_preparations(void *context);

static void initial_request_complete(void *, const dr_cache_prepare_result_t *,
                                     void *);

// Enqueue only; the caller holds analysis_lock to make queue ownership transfer
// atomic with an ordinary fork snapshot. DR emits code after the lock is gone.
static bool submit_initial_request(InitialPreparation &job,
                                   bool resume = false) {
  dr_cache_prepare_request_t request{};
  request.struct_size = sizeof(request);
  const auto &spans = resume ? job.resumes : job.spans;
  request.spans = spans.data();
  request.count = spans.size();
  request.cookie = resume ? job.resume_cookie : job.cookie;
  request.user_data = &job;
  request.is_current = initial_request_current;
  request.is_range_current = initial_request_range_current;
  request.begin = initial_request_begin;
  request.requires_wait = initial_request_wait;
  request.complete = initial_request_complete;
  request.cancel = initial_request_cancel;
  if (!dr_request_cache_preparation(&request))
    return false;
  ++initial_requests_pending;
  return true;
}

// analysis_lock protects publication and queries. Merge overlapping/adjacent
// ranges at each level so aliases and inline selections preserve their union.
static void
index_initial_ready(Module &module, ct_instrument_level level,
                    const std::vector<dr_cache_prepare_span_t> &spans) {
  auto &ranges = module.initial_ready[level];
  for (const auto &span : spans) {
    app_pc begin = span.start, end = span.end;
    auto next = ranges.lower_bound(begin);
    if (next != ranges.begin()) {
      const auto previous = std::prev(next);
      if (previous->second >= begin)
        next = previous;
    }
    while (next != ranges.end() && next->first <= end) {
      begin = std::min(begin, next->first);
      end = std::max(end, next->second);
      next = ranges.erase(next);
    }
    ranges.emplace_hint(next, begin, end);
  }
}

static void initial_request_complete(void *context,
                                     const dr_cache_prepare_result_t *result,
                                     void *data) {
  QuietCallback quiet(context);
  std::unique_ptr<InitialPreparation> job(
      static_cast<InitialPreparation *>(data));
  auto *thread = static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
  if (thread && thread->initial_build == job.get())
    thread->initial_build = nullptr;
  {
    Lock lock(analysis_lock);
    if (initial_requests_pending)
      --initial_requests_pending;
    auto position =
        job->module->initial_preparations.find({job->function, job->level});
    if (position == job->module->initial_preparations.end() ||
        position->second.cookie != job->cookie) {
      job.reset();
    } else {
      auto &state = position->second;
      // DR's final whole-request proof is the authoritative byte check. Every
      // mismatch it observes runs cancel at a safe retirement point before
      // complete. Recheck only lifecycle state here: a new byte proof would
      // create another cancellation path after that retirement opportunity.
      bool ready = result->status == DR_CACHE_PREPARE_READY &&
                   job->module->active &&
                   job->module->code_generation == job->generation &&
                   !job->module->pending_code_changes &&
                   !job->module->pending_userspace_changes;
      job->generated += result->generated;
      job->reused += result->reused;
      if (ready && !job->resume_phase && !job->resumes.empty()) {
        if (++initial_preparation_cookie == 0)
          fail("initial resume preparation cookie exhausted");
        job->resume_cookie = initial_preparation_cookie;
        if (submit_initial_request(*job, true)) {
          [[maybe_unused]] auto *queued_job = job.release();
          return;
        }
        ready = false;
      }
      state.status = ready ? InitialPreparationState::Ready
                           : InitialPreparationState::Pending;
      state.reason =
          ready ? "" : "source generation cancelled or preparation failed";
      if (ready) {
        if (job->execution)
          ct_execution_batch_store(*job->execution);
        state.spans = job->spans;
        if (!job->module->initial_ready_dirty &&
            job->module->initial_ready_generation == job->generation)
          index_initial_ready(*job->module, job->level, state.spans);
        else
          job->module->initial_ready_dirty = true;
      }
      if (instrumentation_statistics && ct_output_trace_enabled() &&
          recording_thread(context)) {
        const auto function = current_functions.find(job->function);
        const auto userspace =
            job->module->userspace_versions.find({job->function, job->level});
        ct_output_printf(
            "ctrace initial preparation: module=%s function=%s level=%s "
            "status=%s early=%u generated=%zu reused=%zu cookie=%u "
            "before_first_execution=%u userspace_ready=%u resume_spans=%zu\n",
            job->module->path.c_str(),
            function == current_functions.end()
                ? "?"
                : function->second->name.c_str(),
            ct_instrument_level_name(job->level), ready ? "ready" : "pending",
            unsigned(job->early), job->generated, job->reused, job->cookie,
            unsigned(function != current_functions.end() &&
                     !function->second->observed_execution),
            unsigned(userspace != job->module->userspace_versions.end() &&
                     userspace->second.code),
            job->resumes.size());
      }
    }
    // Module/value metadata destructors are serialized by analysis_lock.
    job.reset();
  }
  queue_initial_preparations(context);
}

static ct_instrument_level initial_level_at(void *context, Module &module,
                                            app_pc pc) {
  ct_instrument_level level = ct_instrument_level::arm;
  // An anonymous entry has no advertised function extent to prepare at load
  // time. Once this code is actually discovered, apply the requested initial
  // level to its selected block before any of its instructions execute.
  if (module.runtime_image && initial_level != ct_instrument_level::arm &&
      arming_mode_at(pc) == Site::Into)
    level = initial_level;
  const auto *thread =
      static_cast<const Thread *>(drmgr_get_tls_field(context, tls_index));
  if (thread && thread->initial_build) {
    const auto &job = *thread->initial_build;
    const auto next = std::upper_bound(
        job.spans.begin(), job.spans.end(), pc,
        [](app_pc address, const auto &span) { return address < span.start; });
    if (job.module.get() == &module &&
        job.generation == module.code_generation && next != job.spans.begin() &&
        pc < std::prev(next)->end)
      level = job.level;
    if (level == ct_instrument_level::full)
      return level;
  }
  if (module.initial_ready_dirty ||
      module.initial_ready_generation != module.code_generation) {
    module.initial_ready.clear();
    module.initial_ready_generation = module.code_generation;
    for (const auto &[key, state] : module.initial_preparations)
      if (state.status == InitialPreparationState::Ready &&
          state.generation == module.code_generation)
        index_initial_ready(module, key.second, state.spans);
    module.initial_ready_dirty = false;
  }
  for (const auto &[prepared, ranges] : module.initial_ready) {
    if (prepared <= level)
      continue;
    const auto next = ranges.upper_bound(pc);
    if (next != ranges.begin() && pc < std::prev(next)->second)
      level = prepared;
  }
  return level;
}

// ELF metadata supplies only the unchanged containing-function bounds here.
// A modified generation must derive instruction bytes and edges from its live
// R-X image, never from the helper's immutable ELF instruction graph. Replies
// stop at a transfer or the same bounded chunk used by the analysis protocol;
// the caller follows known in-function frontiers and checks overlap globally.
static bool initial_live_graph(void *context, Module &module, uint64_t entry,
                               const ct_flow_range &bounds,
                               std::vector<ct_flow_instruction> &instructions,
                               std::vector<ct_flow_edge> &edges) {
  if (!bounds.bounded || bounds.begin_offset >= bounds.end_offset ||
      bounds.end_offset > uint64_t(module.end - module.start) ||
      entry < bounds.begin_offset || entry >= bounds.end_offset)
    return false;
  app_pc verified_end = nullptr;
  uint64_t offset = entry;
  while (instructions.size() < CT_FLOW_GRAPH_INSTRUCTION_LIMIT) {
    const app_pc pc = module.start + offset;
    ct_flow_instruction instruction{};
    instruction.offset = offset;
    const size_t available =
        std::min(sizeof(instruction.bytes), size_t(bounds.end_offset - offset));
    for (app_pc cursor = pc; cursor < pc + available;) {
      if (cursor < verified_end) {
        cursor = verified_end;
        continue;
      }
      dr_mem_info_t memory{};
      if (!dr_query_memory_ex(cursor, &memory) || memory.base_pc > cursor ||
          memory.size > UINTPTR_MAX - uintptr_t(memory.base_pc) ||
          memory.base_pc + memory.size <= cursor ||
          (memory.prot & (DR_MEMPROT_READ | DR_MEMPROT_EXEC)) !=
              (DR_MEMPROT_READ | DR_MEMPROT_EXEC) ||
          (memory.prot & DR_MEMPROT_WRITE))
        return false;
      cursor = verified_end = memory.base_pc + memory.size;
    }
    if (!ct_userspace_patch_read_original(pc, available, instruction.bytes))
      return false;
    instr_t decoded;
    instr_init(context, &decoded);
    byte *next = decode_from_copy(context, instruction.bytes, pc, &decoded);
    bool valid = next && next > instruction.bytes &&
                 next <= instruction.bytes + available &&
                 instr_valid(&decoded) && !instr_is_far_cti(&decoded);
    const bool call = valid && instr_is_call(&decoded);
    const bool ret = valid && instr_is_return(&decoded);
    const bool conditional = valid && instr_is_cbr(&decoded);
    const bool branch =
        valid && !call && !ret &&
        (conditional || instr_is_ubr(&decoded) || instr_is_mbr(&decoded));
    const bool syscall = valid && instr_is_syscall(&decoded);
    valid &= !instr_is_interrupt(&decoded) || syscall;
    if (valid) {
      instruction.size = next - instruction.bytes;
      instruction.flags = (call ? CT_FLOW_CALL : 0) |
                          (ret ? CT_FLOW_RETURN : 0) |
                          (branch ? CT_FLOW_BRANCH : 0) |
                          (conditional ? CT_FLOW_CONDITIONAL : 0) |
                          (syscall ? CT_FLOW_SYSCALL : 0);
      if (call || branch) {
        const opnd_t target = instr_get_target(&decoded);
        if (opnd_is_pc(target)) {
          const app_pc destination = opnd_get_pc(target);
          // A known external tail destination ends this bounded function.
          // CALL records only fallthrough, matching the ELF graph contract.
          if (branch && destination >= module.start && destination < module.end)
            edges.push_back({offset, uint64_t(destination - module.start)});
        } else {
          instruction.flags |= CT_FLOW_INDIRECT;
          valid = call; // An opaque branch has no provable reachable frontier.
        }
      }
      if (valid && !ret && (!branch || conditional)) {
        const uint64_t successor = offset + instruction.size;
        valid = successor <= bounds.end_offset;
        if (valid)
          edges.push_back({offset, successor});
      }
    }
    instr_free(context, &decoded);
    if (!valid)
      return false;
    instructions.push_back(instruction);
    if (call || ret || branch || syscall ||
        offset + instruction.size == bounds.end_offset)
      break;
    offset += instruction.size;
  }
  return !instructions.empty();
}

static void queue_initial_preparations(void *context) {
  if (!context || !process_recording ||
      initial_level == ct_instrument_level::arm)
    return;
  QuietCallback quiet(context);
  Thread &thread = *thread_state(context);
  if (!thread.owns_image || thread.collecting_initial || thread.initial_build)
    return;
  thread.collecting_initial = true;
  struct CollectionScope {
    Thread &thread;
    ~CollectionScope() { thread.collecting_initial = false; }
  } collecting{thread};
  PreparationScope owners(thread);
  // Keep not-yet-submitted owners in TLS: a fork child can discard the copied
  // requests of vanished peers instead of leaking owners on their old stacks.
  auto &jobs = thread.initial_requests;
  {
    Lock lock(analysis_lock);
    if (initial_requests_pending)
      return;
    const bool anchor =
        !within_enabled || within_intr || (within_new_stack && follow_forks) ||
        std::any_of(functions.begin(), functions.end(),
                    [](const auto &function) {
                      return function->module->active && function->within;
                    }) ||
        std::any_of(modules.begin(), modules.end(), [](const auto &module) {
          return module->active && !module->within_inline_ranges.empty();
        });
    if (!anchor)
      return;
    struct Candidate {
      std::shared_ptr<Function> function;
      bool recurse;
      ct_instrument_level level;
    };
    // A loader can expose ELF metadata before its text mapping is executable.
    // Defer expensive per-function analysis until that mapping is R-X. This
    // collection-local extent is only a cheap eligibility check: the complete
    // expected-byte/permission proof still runs before and during preparation.
    dr_mem_info_t candidate_mapping{};
    const auto executable = [&](app_pc pc) {
      if (!candidate_mapping.size || pc < candidate_mapping.base_pc ||
          pc >= candidate_mapping.base_pc + candidate_mapping.size) {
        candidate_mapping = {};
        if (!dr_query_memory_ex(pc, &candidate_mapping) ||
            candidate_mapping.base_pc > pc ||
            candidate_mapping.size >
                UINTPTR_MAX - uintptr_t(candidate_mapping.base_pc) ||
            candidate_mapping.base_pc + candidate_mapping.size <= pc) {
          candidate_mapping = {};
          return false;
        }
      }
      return (candidate_mapping.prot & (DR_MEMPROT_READ | DR_MEMPROT_EXEC)) ==
                 (DR_MEMPROT_READ | DR_MEMPROT_EXEC) &&
             !(candidate_mapping.prot & DR_MEMPROT_WRITE);
    };
    std::vector<Candidate> work;
    for (const auto &function : functions) {
      if (!function->module->active || function->module->pending_code_changes ||
          function->module->pending_userspace_changes ||
          !executable(function->pc))
        continue;
      if (!function->initial_filter_checked) {
        auto location = std::make_unique<ct_location>();
        ct_analysis_lookup_arming(function->module->analysis,
                                  function->pc - function->module->start,
                                  location.get());
        Site::Mode mode, physical;
        std::vector<Site::Mode> inlined;
        filter_modes(*function->module, *location, mode, physical, inlined);
        function->initial_mode = location->is_plt ? Site::Skip : physical;
        function->initial_filter_checked = true;
      }
      const bool detailed = anchor && (function->initial_mode == Site::Into ||
                                       function->initial_mode == Site::Recurse);
      if (detailed || (anchor && function->initial_recurse))
        work.push_back({function, function->initial_recurse, initial_level});
    }
    for (const auto &module : modules) {
      if (!anchor || !module->active || module->pending_code_changes ||
          module->pending_userspace_changes)
        continue;
      for (const auto &inline_range : module->userspace_reentry_inline_ranges) {
        if (!executable(inline_range.first))
          continue;
        auto location = std::make_unique<ct_location>();
        ct_analysis_lookup_arming(module->analysis,
                                  inline_range.first - module->start,
                                  location.get());
        Site::Mode mode, physical;
        std::vector<Site::Mode> inlined;
        filter_modes(*module, *location, mode, physical, inlined);
        bool recurse = false, blocked = false;
        mode = enter_scope(physical, recurse, blocked);
        for (Site::Mode nested : inlined)
          mode = enter_scope(nested, recurse, blocked);
        if (mode != Site::Into)
          continue;
        ct_flow_range range{};
        if (!ct_analysis_flow(module->analysis,
                              inline_range.first - module->start, &range,
                              nullptr, nullptr, nullptr, nullptr) ||
            !range.bounded)
          continue;
        const auto function =
            current_functions.find(module->start + range.begin_offset);
        if (function != current_functions.end())
          work.push_back({function->second, false, initial_level});
      }
    }
    std::set<std::tuple<app_pc, bool, ct_instrument_level>> visited;
    size_t staged_instructions = 0;
    for (size_t next = 0; next < work.size(); ++next) {
      const auto function = work[next].function;
      const bool inherited_recurse = work[next].recurse;
      const ct_instrument_level level = work[next].level;
      Module &module = *function->module;
      if (!visited.emplace(function->pc, inherited_recurse, level).second ||
          !module.active || module.pending_code_changes ||
          module.pending_userspace_changes || !executable(function->pc))
        continue;
      owners.hold(module);
      const auto key = std::make_pair(function->pc, level);
      auto &state = module.initial_preparations[key];
      if (state.generation != module.code_generation) {
        state = {};
        state.generation = module.code_generation;
      }
      const bool expand_existing =
          inherited_recurse && !state.recursive_expanded &&
          state.status != InitialPreparationState::Pending;
      if (state.status != InitialPreparationState::Pending && !expand_existing)
        continue;
      if (!expand_existing &&
          state.attempted_revision == initial_catalog_revision)
        continue;
      state.attempted_revision = initial_catalog_revision;
      std::map<uint64_t, ct_flow_instruction> cover;
      std::vector<ct_flow_edge> edges;
      std::vector<uint64_t> frontiers{uint64_t(function->pc - module.start)};
      std::set<uint64_t> requested;
      ct_flow_range bounds{};
      bool live = false, valid = true;
      for (;;) {
        while (valid && !frontiers.empty()) {
          const uint64_t entry = frontiers.back();
          frontiers.pop_back();
          if (cover.count(entry) || !requested.insert(entry).second)
            continue;
          struct GraphResponse {
            std::vector<ct_flow_instruction> instructions;
            std::vector<ct_flow_edge> edges;
          } response;
          ct_flow_range range{};
          if (live) {
            range = bounds;
            valid = initial_live_graph(context, module, entry, bounds,
                                       response.instructions, response.edges);
          } else {
            valid = ct_analysis_code_graph(
                        module.analysis, entry, &range,
                        [](const ct_flow_instruction *instruction, void *data) {
                          static_cast<GraphResponse *>(data)
                              ->instructions.push_back(*instruction);
                        },
                        [](const ct_flow_edge *edge, void *data) {
                          static_cast<GraphResponse *>(data)->edges.push_back(
                              *edge);
                        },
                        &response) &&
                    range.bounded && range.begin_offset < range.end_offset &&
                    range.end_offset <= uint64_t(module.end - module.start);
          }
          if (!valid)
            break;
          if (requested.size() == 1)
            bounds = range;
          valid = range.begin_offset == bounds.begin_offset &&
                  range.end_offset == bounds.end_offset;
          for (const auto &instruction : response.instructions) {
            auto [position, inserted] =
                cover.emplace(instruction.offset, instruction);
            valid &=
                inserted || (position->second.size == instruction.size &&
                             !std::memcmp(position->second.bytes,
                                          instruction.bytes, instruction.size));
          }
          edges.insert(edges.end(), response.edges.begin(),
                       response.edges.end());
          for (const auto &edge : response.edges) {
            if (edge.to_offset == UINT64_MAX) {
              valid = false;
            } else if (edge.to_offset >= bounds.begin_offset &&
                       edge.to_offset < bounds.end_offset &&
                       !cover.count(edge.to_offset)) {
              frontiers.push_back(edge.to_offset);
            }
          }
        }
        uint64_t previous_end = 0;
        for (const auto &[offset, instruction] : cover) {
          valid &= offset >= previous_end;
          previous_end = offset + instruction.size;
        }
        if (live || !module.code_modified || cover.empty())
          break;
        // A missing whole-function proof is not evidence of changed code.
        // Preserve helper-resolved switch/indirect edges when these decoded
        // bytes match. Only an actual byte mismatch selects the live decoder;
        // inaccessible mappings still fail the later mandatory selected proof.
        bool changed = false;
        original_instructions_current(
            module, cover.begin(), cover.end(),
            [](const auto &entry) {
              return OriginalCodeInstruction{
                  entry.second.offset, entry.second.size, entry.second.bytes};
            },
            &changed);
        if (!changed)
          break;
        live = true;
        valid = bounds.bounded && bounds.begin_offset < bounds.end_offset &&
                bounds.end_offset <= uint64_t(module.end - module.start);
        cover.clear();
        edges.clear();
        requested.clear();
        frontiers = {uint64_t(function->pc - module.start)};
      }
      if (!valid || cover.empty()) {
        state.reason = "unbounded, overlapping, or unresolved code frontier";
        continue;
      }
      auto job = std::make_unique<InitialPreparation>();
      job->module = function->module;
      job->function = function->pc;
      job->level = level;
      job->generation = module.code_generation;
      job->early = module.discovered_before_execution;
      auto location = std::make_unique<ct_location>();
      std::set<uint64_t> entries{bounds.begin_offset};
      for (const auto &edge : edges) {
        const auto source = cover.find(edge.from_offset);
        if (edge.to_offset != UINT64_MAX && source != cover.end() &&
            (source->second.flags &
             (CT_FLOW_CALL | CT_FLOW_BRANCH | CT_FLOW_SYSCALL)))
          entries.insert(edge.to_offset);
      }
      InitialLocationBatch arming_locations;
      arming_locations.arming = true;
      arming_locations.offsets.reserve(cover.size());
      for (const auto &entry : cover)
        arming_locations.offsets.push_back(entry.first);
      uint32_t previous_flags = 0;
      for (const auto &[offset, instruction] : cover) {
        const app_pc pc = module.start + offset;
        if (!arming_locations.read_next(module.analysis, *location)) {
          valid = false;
          break;
        }
        Site::Mode mode, physical;
        std::vector<Site::Mode> inlined;
        filter_modes(module, *location, mode, physical, inlined);
        const auto select = [&](bool recurse) {
          bool blocked = false;
          Site::Mode effective = enter_scope(physical, recurse, blocked);
          for (Site::Mode nested : inlined)
            effective = enter_scope(nested, recurse, blocked);
          return std::make_pair(effective == Site::Into, recurse && !blocked);
        };
        const auto plain = select(false), recursive = select(true);
        const auto selected = inherited_recurse ? recursive : plain;
        // Initial levels prepare selected bodies. Function summaries and
        // signal/syscall boundaries retain their ordinary arm/lazy handling;
        // enabling Perfetto does not select every body in every loaded DSO.
        if (location->is_plt || !selected.first)
          continue;
        job->instructions.push_back(instruction);
        const bool within = function->within || within_inline_at(module, pc);
        const bool transition =
            !job->scopes.empty() &&
            (job->scopes.back().plain != plain.first ||
             job->scopes.back().recursive != recursive.first ||
             job->scopes.back().within != within);
        job->scopes.push_back({pc, plain.first, recursive.first, within});
        if (selected.second && (instruction.flags & CT_FLOW_CALL) &&
            !(instruction.flags & CT_FLOW_INDIRECT)) {
          instr_t decoded;
          instr_init(context, &decoded);
          byte bytes[15];
          std::memcpy(bytes, instruction.bytes, sizeof(bytes));
          if (decode_from_copy(context, bytes, pc, &decoded) &&
              instr_valid(&decoded)) {
            const opnd_t target = instr_get_target(&decoded);
            if (opnd_is_pc(target)) {
              const auto callee = current_functions.find(opnd_get_pc(target));
              if (callee != current_functions.end()) {
                callee->second->initial_recurse = true;
                work.push_back({callee->second, true, level});
              }
            }
          }
          instr_free(context, &decoded);
        }
        if (job->spans.empty() || job->spans.back().end != pc || transition ||
            entries.count(offset) || current_functions.count(pc) ||
            (previous_flags & (CT_FLOW_CALL | CT_FLOW_RETURN | CT_FLOW_BRANCH |
                               CT_FLOW_SYSCALL | CT_FLOW_FRONTIER)))
          job->spans.push_back({pc, pc + instruction.size});
        else
          job->spans.back().end = pc + instruction.size;
        previous_flags = instruction.flags;
      }
      arming_locations = {};
      if (!valid) {
        state.reason = "initial arming location batch unavailable";
        continue;
      }
      if (job->instructions.empty()) {
        if (state.status == InitialPreparationState::Ready)
          module.initial_ready_dirty = true;
        module.initial_preparations.erase(key);
        continue;
      }
      if (expand_existing &&
          std::all_of(
              job->spans.begin(), job->spans.end(), [&](const auto &span) {
                return std::any_of(state.spans.begin(), state.spans.end(),
                                   [&](const auto &prior) {
                                     return prior.start <= span.start &&
                                            prior.end >= span.end;
                                   });
              })) {
        state.recursive_expanded = true;
        continue;
      }
      if (expand_existing)
        state.cookie =
            0; // A larger inline-selected cover needs a new policy cookie.
      if (!std::all_of(
              job->spans.begin(), job->spans.end(), [](const auto &span) {
                return private_executable_mapping(span.start, span.end);
              })) {
        state.reason = "original mapping requires runtime sandbox (shared or "
                       "not read-only executable)";
        continue;
      }
      if (!initial_bytes_current(*job)) {
        state.reason =
            "mapped R-X original bytes not ready (mapping or relocation)";
        continue;
      }
      InitialLocationBatch source_locations;
      for (const auto &instruction : job->instructions) {
        const auto site = current_sites.find(module.start + instruction.offset);
        if (level == ct_instrument_level::perfetto ||
            site == current_sites.end() || !site->second ||
            site->second->module.get() != &module)
          source_locations.offsets.push_back(instruction.offset);
      }
      bool prepared = true;
      for (const auto &instruction : job->instructions) {
        const app_pc pc = module.start + instruction.offset;
        if (level == ct_instrument_level::perfetto) {
          // Prepare shared source/structural metadata, not a persistent Site
          // and libdw values handle for every instruction in nontraced
          // libraries.
          if (!source_locations.read_next(module.analysis, *location)) {
            prepared = false;
            break;
          }
          auto source = intern_location(module, *location);
          job->locations.push_back(source);
          if (decompile && !source->view.source_usable) {
            auto site =
                std::make_shared<Site>(function->module, std::move(source));
            site->instruction.pc = pc;
            prepare_site(*site, context, false, &instruction);
            prepared &= site->prepared;
            prepare_decompiled_display(*site, level);
          }
          continue;
        }
        auto &site = current_sites[pc];
        if (!site || site->module.get() != &module) {
          if (!source_locations.read_next(module.analysis, *location)) {
            prepared = false;
            break;
          }
          site = std::make_shared<Site>(function->module,
                                        intern_location(module, *location));
        }
        site->instruction.pc = pc;
        prepare_site(*site, context, level == ct_instrument_level::full,
                     &instruction);
        prepared &= site->prepared && site->original_size == instruction.size;
        if (decompile && !source_available(*site)) {
          prepare_decompiled_display(*site, level);
          if (level == ct_instrument_level::full)
            decompile_site(*site, context);
        }
      }
      if (!prepared) {
        state.reason = "source/operand instruction preparation incomplete";
        continue;
      }
      if (!state.cookie) {
        if (++initial_preparation_cookie == 0)
          fail("initial preparation cookie exhausted");
        state.cookie = initial_preparation_cookie;
      }
      job->cookie = state.cookie;
      if (state.status == InitialPreparationState::Ready)
        module.initial_ready_dirty = true;
      state.status = InitialPreparationState::Queued;
      state.recursive_expanded = inherited_recurse;
      state.spans = job->spans;
      state.reason.clear();
      jobs.push_back(std::move(job));
      staged_instructions += jobs.back()->instructions.size();
      if (staged_instructions >= initial_instruction_batch)
        break;
    }
  }
  for (auto &job : jobs) {
    Lock lock(analysis_lock);
    if (submit_initial_request(*job)) {
      // Enqueue only (no BB building or waiting). Keep ownership transfer under
      // the same client lock checked by the fork snapshot callback.
      [[maybe_unused]] auto *queued_job = job.release();
    } else {
      auto &state =
          job->module->initial_preparations[{job->function, job->level}];
      state.status = InitialPreparationState::Pending;
      state.reason = "DR preparation queue rejected runtime configuration";
      job.reset();
    }
  }
  jobs.clear();
}

static void module_load(void *context, const module_data_t *data, bool) {
  QuietCallback quiet(context);
  // Excluded fork/exec images never need new tracing metadata. A pthread or
  // CLONE_VM child still shares the recording parent's module table, so use
  // the image policy here rather than this particular thread's membership.
  if (!traced_process() || !process_recording)
    return;
  if (ct_perfetto_enabled()) {
    ct_timing_kernel_end(context ? context : dr_get_current_drcontext());
    ct_timing_discard(context ? context : dr_get_current_drcontext());
  }
  if (dr_memory_is_dr_internal(data->start) ||
      dr_memory_is_in_client(data->start) ||
      (data->full_path && std::strcmp(data->full_path, "[vdso]") == 0))
    return;
  {
    Lock hook_lock(module_hook_lock);
    std::vector<std::shared_ptr<Function>> new_functions;
    {
      Lock lock(analysis_lock);
      for (auto &existing : modules)
        if (existing->active && existing->runtime_image &&
            existing->start < data->end && existing->end > data->start)
          retire_runtime_image(*existing);
      reclaim_modules();
      if (module_at(data->start))
        return;
      auto module = std::make_shared<Module>();
      module->start = data->start;
      module->end = data->end;
      for (uint index = 0; index < data->num_segments; ++index)
        if (data->segments[index].prot & DR_MEMPROT_EXEC)
          module->executable_ranges.emplace_back(data->segments[index].start,
                                                 data->segments[index].end);
      for (const auto &range : module->executable_ranges)
        for (app_pc cursor = range.first; cursor < range.second;) {
          dr_mem_info_t memory{};
          if (!dr_query_memory_ex(cursor, &memory) || memory.base_pc > cursor ||
              memory.size > UINTPTR_MAX - uintptr_t(memory.base_pc) ||
              memory.base_pc + memory.size <= cursor)
            break;
          module->code_modified |= (memory.prot & DR_MEMPROT_SHARED) != 0;
          cursor = std::min(memory.base_pc + memory.size, range.second);
        }
      module->path = data->full_path ? data->full_path : "<unknown>";
      module->is_main = data->start == main_start;
      // DynamoRIO exposes the ELF e_entry with the load bias already applied.
      // The interpreter's entry belongs to its own module, never to MAIN.
      if (module->is_main &&
          std::any_of(module->executable_ranges.begin(),
                      module->executable_ranges.end(), [&](const auto &range) {
                        return data->entry_point >= range.first &&
                               data->entry_point < range.second;
                      }))
        module->entry_point = data->entry_point;
      if (context)
        module->discovered_before_execution =
            thread_state(context)->discovering_modules;
      // execveat can load a file with no usable pathname in this namespace.
      // Analyze the same borrowed ELF descriptor that DR mapped for the image.
      const file_t application_file =
          module->is_main ? dr_get_application_file() : INVALID_FILE;
      module->analysis =
          application_file != INVALID_FILE
              ? ct_analysis_open_fd(module->path.c_str(), source_maps.c_str(),
                                    application_file)
              : ct_analysis_open(module->path.c_str(), source_maps.c_str());
      module->identity =
          module->path + ":" + ct_analysis_identity(module->analysis);
      ++initial_catalog_revision;
      ++analysis_generation;
      const char *reason = ct_analysis_source_error(module->analysis);
      if (recording_thread(context) && reason &&
          warnings.insert(module->identity + ":source").second)
        write_warning("Warning: " + module->path + ": " + reason + "\n");
      const size_t first_function = functions.size();
      ct_analysis_functions(module->analysis, collect_function, module.get());
      if (within_init && module->entry_point &&
          !current_functions.count(module->entry_point)) {
        // An ELF entry can be stripped, untyped, or inside a symbol. Register
        // this exact boundary without inventing a containing function range.
        const uint64_t offset = module->entry_point - module->start;
        auto location = std::make_unique<ct_location>();
        ct_analysis_lookup_arming(module->analysis, offset, location.get());
        char label[32];
        dr_snprintf(label, sizeof(label), "L%llx",
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(module->entry_point)));
        collect_function(offset, location->symbol[0] ? location->symbol : label,
                         module.get());
      }
      if (duplicate_enabled) {
        ct_analysis_inline_scopes(module->analysis, collect_inline_scope,
                                  module.get());
        auto &ranges = module->within_inline_ranges;
        std::sort(ranges.begin(), ranges.end());
        size_t count = 0;
        for (const auto &range : ranges) {
          if (count && range.first <= ranges[count - 1].second)
            ranges[count - 1].second =
                std::max(ranges[count - 1].second, range.second);
          else
            ranges[count++] = range;
        }
        ranges.resize(count);
      }
      for (size_t index = first_function; index < functions.size(); ++index)
        new_functions.push_back(functions[index]);
      modules.push_back(std::move(module));
    }
    if (!new_functions.empty()) {
      Lock lock(analysis_lock);
      auto progress = std::make_unique<ct_analysis_progress>();
      std::strcpy(progress->stage, "instrumentation");
      dr_snprintf(progress->module, sizeof(progress->module), "%s",
                  new_functions.front()->module->path.c_str());
      dr_snprintf(progress->detail, sizeof(progress->detail),
                  "Loading caches (%zu functions)", new_functions.size());
      progress->has_range = true;
      progress->end_offset = data->end - data->start;
      progress_notice(progress.get(), new_functions.front()->module.get());
    }
    for (const auto &function : new_functions)
      drwrap_wrap_ex(function->pc, function_enter,
                     function->within && !function->init_entry ? within_exit
                                                               : nullptr,
                     function.get(), DRWRAP_FLAGS_NONE);
  }
  queue_initial_preparations(context ? context : dr_get_current_drcontext());
}

static void module_unload(void *context, const module_data_t *data) {
  QuietCallback quiet(context);
  if (!traced_process())
    return;
  if (ct_perfetto_enabled()) {
    ct_timing_kernel_end(context ? context : dr_get_current_drcontext());
    ct_timing_discard(context ? context : dr_get_current_drcontext());
  }
  // Serializing both load and unload prevents an old unwrap from disabling
  // a newly loaded function at the same address. This lock always precedes
  // analysis_lock and is never acquired from drwrap's entry callback.
  Lock hook_lock(module_hook_lock);
  std::vector<std::shared_ptr<Function>> removed;
  std::shared_ptr<Module> retired;
  {
    Lock lock(analysis_lock);
    if (Module *module = module_at(data->start)) {
      retired = module->shared_from_this();
      // Prepared callers may enter this module directly without a CALL gate.
      // The matching mapping syscall retires the shared graph before execution
      // resumes; no new original-code entry may use that graph in the meantime.
      for (auto &dependent : modules) {
        dependent->userspace_disabled = true;
        ++dependent->userspace_binding_generation;
        for (auto &attempt : dependent->userspace_attempts)
          attempt.second->store(0, std::memory_order_release);
      }
      ct_userspace_patch_remove_range(
          module->start, size_t(module->end - module->start), false);
      for (auto &entry : module->userspace_versions)
        if (entry.second.code)
          module->retired_userspace_versions.push_back(entry.second.code);
      module->userspace_versions.clear();
      module->userspace_graphs.clear();
      module->active = false;
      // These are preparation indexes, not runtime owners. Sites and pending
      // frames retain their own immutable records until their observations end.
      module->locations.clear();
      module->dr_recipes.clear();
      module->quiet_transfers.clear();
      for (const auto &function : functions)
        if (function->module.get() == module) {
          current_functions.erase(function->pc);
          removed.push_back(function);
        }
      for (auto iterator = current_sites.begin();
           iterator != current_sites.end();) {
        if (iterator->second->module.get() == module)
          iterator = current_sites.erase(iterator);
        else
          ++iterator;
      }
      for (auto iterator = arming_sites.begin();
           iterator != arming_sites.end();) {
        if (iterator->second.module == module)
          iterator = arming_sites.erase(iterator);
        else
          ++iterator;
      }
    }
  }
  // drwrap invokes entry callbacks while holding its wrap lock. Never acquire
  // it while holding analysis_lock, and retain userdata for in-flight calls.
  for (const auto &function : removed)
    drwrap_unwrap(function->pc, function_enter,
                  function->within && !function->init_entry ? within_exit
                                                            : nullptr);
  {
    Lock lock(analysis_lock);
    // With ordinary drwrap flags, unwrap takes the same wrap_lock held around
    // pre callbacks. Post callbacks store only the invocation's SP, so no
    // drwrap userdata can still refer to these Function objects after fencing.
    if (retired) {
      retired->hooks_retired = true;
      functions.erase(std::remove_if(functions.begin(), functions.end(),
                                     [&](const auto &function) {
                                       return function->module == retired;
                                     }),
                      functions.end());
    }
    reclaim_modules();
    // Values/DWARF reference counters are protected by analysis_lock. The
    // callback fence makes these temporary vectors the possible final owners.
    removed.clear();
    retired.reset();
  }
}

static void discover_initial_modules(void *context) {
  if (!context || !process_recording)
    return;
  Thread &thread = *thread_state(context);
  if (!thread.owns_image || thread.discovering_modules || thread.initial_build)
    return;
  thread.discovering_modules = true;
  // The iterator owns a snapshot, not the DR module-table lock. Module load
  // serializes client catalog changes and rechecks identities independently.
  auto *iterator = dr_module_iterator_start();
  while (dr_module_iterator_hasnext(iterator)) {
    module_data_t *data = dr_module_iterator_next(iterator);
    module_load(context, data, true);
    dr_free_module_data(data);
  }
  dr_module_iterator_stop(iterator);
  thread.discovering_modules = false;
  queue_initial_preparations(context);
}

static dr_emit_flags_t insert_breakpoint_resumes(void *context, void *,
                                                 instrlist_t *block, bool,
                                                 bool) {
  if (!traced_process())
    return DR_EMIT_DEFAULT;
  for (instr_t *instruction = instrlist_first_app(block); instruction;
       instruction = instr_get_next_app(instruction)) {
    const app_pc pc = instr_get_app_pc(instruction);
    const int opcode = instr_get_opcode(instruction);
    if (pc && (opcode == OP_int3 ||
               (opcode == OP_int && instr_num_srcs(instruction) == 1 &&
                opnd_is_immed_int(instr_get_src(instruction, 0)) &&
                opnd_get_immed_int(instr_get_src(instruction, 0)) == 3))) {
      // A breakpoint saves the next PC. Keep that address outside the following
      // clean call's setup, whose saved application context is not ready yet.
      // Run after insertion so shared drbbdup terminators get one anchor, even
      // in unselected copies and when rebuilding translations.
      instr_t *resume = INSTR_CREATE_nop(context);
      instr_set_translation(resume, pc + instr_length(context, instruction));
      instrlist_meta_postinsert(block, instruction, resume);
    }
  }
  if (ct_perfetto_enabled() && recording_thread(context)) {
    Thread &thread = *thread_state(context);
    const bool resume = thread.resume_quiet_generation;
    thread.resume_quiet_generation = false;
    if (resume && thread.timing_started && !thread.quiet_callback_depth)
      ct_timing_quiet_begin(context);
  }
  return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t begin_code_generation(void *context, void *,
                                             instrlist_t *block, bool,
                                             bool translating) {
  if (traced_process() && ct_perfetto_enabled() && recording_thread(context)) {
    Thread &thread = *thread_state(context);
    thread.resume_quiet_generation |= ct_timing_quiet_active(context);
    ct_timing_quiet_end(context);
    ct_timing_discard(context);
  }
  if (!translating && traced_process() && process_recording) {
    Lock lock(analysis_lock);
    // A loader can discover an ELF before mapping its executable segments.
    // Shared originals always need byte proofs, even before their first write.
    // Actual changes arrive through code_change; discovery is not a generation.
    dr_mem_info_t memory{};
    for (instr_t *instruction = instrlist_first_app(block); instruction;
         instruction = instr_get_next_app(instruction)) {
      const app_pc pc = instr_get_app_pc(instruction);
      Module *module = discover_runtime_image(context, pc);
      if (module && module->runtime_image && module->code_modified) {
        // Check newly discovered instructions too, before any Site exists.
        // Comparing the whole window here would recreate analysis objects
        // whenever unrelated mutable data beside stable code changes.
        const app_pc next = decode_next_pc(context, pc);
        byte original[15];
        if (next && next > pc && next <= module->end && next - pc <= 15 &&
            ct_userspace_patch_read_original(pc, next - pc, original) &&
            !ct_analysis_image_matches(
                ct_analysis_module_file(module->analysis), pc - module->start,
                original, next - pc)) {
          retire_runtime_image(*module);
          module = discover_runtime_image(context, pc);
        }
      }
      if (!module || module->code_modified)
        continue;
      // Overapproximate the x86-64 instruction extent without letting a
      // length query cache a new encoding in the live application IR.
      const size_t size = 15;
      if (size > UINTPTR_MAX - uintptr_t(pc))
        continue;
      for (app_pc cursor = pc; cursor < pc + size;) {
        if (!memory.size || cursor < memory.base_pc ||
            cursor >= memory.base_pc + memory.size) {
          memory = {};
          if (!dr_query_memory_ex(cursor, &memory) || memory.base_pc > cursor ||
              memory.size > UINTPTR_MAX - uintptr_t(memory.base_pc) ||
              memory.base_pc + memory.size <= cursor) {
            memory = {};
            break;
          }
        }
        module->code_modified |= (memory.prot & DR_MEMPROT_SHARED) != 0;
        cursor = std::min(memory.base_pc + memory.size, pc + size);
      }
    }
  }
  return DR_EMIT_DEFAULT;
}

static void quiet_transfer(app_pc pc, bool inline_scope) {
  QuietCallback quiet(dr_get_current_drcontext());
  ct_dr_shared_service(dr_get_current_drcontext());
  if (!structural_instrumentation() && !inline_scope &&
      !boundary_observation_started.load(std::memory_order_acquire))
    return;
  observe_instruction(pc, inline_scope, true);
  if (within_active()) {
    // Force observation of the actual successor, including unknown stripped
    // call targets and non-local transfers. That one boundary resolves the
    // current stack and selects the next body's mode.
    quiet.resume = execution_mode() == 2;
    execution_mode() = 4;
  }
}

static bool quiet_boundary(instr_t *instruction) {
  const app_pc pc = instr_get_app_pc(instruction);
  bool transfer = instr_is_call(instruction) || instr_is_return(instruction);
  if (instr_is_cbr(instruction) || instr_is_ubr(instruction) ||
      instr_is_mbr(instruction)) {
    transfer = true;
    const opnd_t target = instr_get_target(instruction);
    if (opnd_is_pc(target)) {
      Lock lock(analysis_lock);
      Module *module = module_at(pc);
      const app_pc destination = opnd_get_pc(target);
      if (module && module_at(destination) == module) {
        if (module->code_modified && !original_code_matches(*module, pc))
          return transfer;
        // Translation must reconstruct the instrumentation originally emitted,
        // even if lazy flow analysis has learned more about this function.
        const auto cached = module->quiet_transfers.find(pc);
        if (cached != module->quiet_transfers.end())
          return cached->second;
        // Symbol extents can overlap. A known entry remains a call-stack
        // boundary even when it lies inside the current flow range.
        if (current_functions.count(destination)) {
          module->quiet_transfers.emplace(pc, true);
          return true;
        }
        // A branch can enter/leave an inline scope without crossing a physical
        // function boundary. Only scope transitions need a quiet-path hook.
        if (std::any_of(module->observation_inline_ranges.begin(),
                        module->observation_inline_ranges.end(),
                        [&](const auto &range) {
                          return (pc >= range.first && pc < range.second) !=
                                 (destination >= range.first &&
                                  destination < range.second);
                        })) {
          module->quiet_transfers.emplace(pc, true);
          return true;
        }
        const uint64_t offset = pc - module->start;
        auto range = module->flow_ranges.upper_bound(offset);
        if (range != module->flow_ranges.begin()) {
          --range;
          if (offset < range->second &&
              uint64_t(destination - module->start) >= range->first &&
              uint64_t(destination - module->start) < range->second)
            transfer = false;
        }
        if (transfer) {
          auto origin = std::make_unique<ct_location>();
          auto target_location = std::make_unique<ct_location>();
          ct_analysis_lookup_arming(module->analysis, offset, origin.get());
          ct_analysis_lookup_arming(module->analysis,
                                    destination - module->start,
                                    target_location.get());
          transfer = origin->is_plt || target_location->is_plt ||
                     !origin->function_id ||
                     origin->function_id != target_location->function_id;
        }
        module->quiet_transfers.emplace(pc, transfer);
      }
    }
  }
  return transfer;
}

struct ExecutionBlock {
  ct_instrument_level level = ct_instrument_level::arm;
  std::vector<std::pair<app_pc, ct_execution_recipe>> recipes;
  unsigned char provenance[32]{}, cases[7]{};
  uint64_t incarnation = 0, generation = 0;
  bool shareable = false, stamped = false;
  bool structural = false;
  bool within_entry = false;

  const ct_execution_recipe *recipe_at(app_pc pc) const {
    const auto found = std::lower_bound(recipes.begin(), recipes.end(), pc,
                                        [](const auto &entry, app_pc address) {
                                          return entry.first < address;
                                        });
    return found != recipes.end() && found->first == pc ? &found->second
                                                        : nullptr;
  }
};

static void analyze_execution_block(void *context, void *tag,
                                    instrlist_t *block, void *, void **result) {
  if (!process_recording) {
    *result = nullptr;
    return;
  }
  PreparationScope owners(*thread_state(context));
  auto prepared = std::make_unique<ExecutionBlock>();
  {
    Lock lock(analysis_lock);
    Module *module = module_at(static_cast<app_pc>(tag));
    const auto initial =
        module ? initial_level_at(context, *module, static_cast<app_pc>(tag))
               : ct_instrument_level::arm;
    prepared->level = ct_required_instrumentation(
        ct_perfetto_enabled(),
        module && (module->detailed_blocks.count(static_cast<app_pc>(tag)) ||
                   initial == ct_instrument_level::full));
    prepared->level = std::max(prepared->level, initial);
    prepared->structural =
        structural_instrumentation() ||
        (module && initial_level == ct_instrument_level::perfetto &&
         initial != ct_instrument_level::arm);
  }
  std::vector<ct_execution_instruction> instructions;
  std::vector<instr_t *> decoded;
  Module *module = nullptr;
  std::string policy = execution_policy, memory_key, original_flow;
  std::vector<bool> structural;
  std::string previous_scope;
  {
    Lock lock(analysis_lock);
    for (instr_t *instruction = instrlist_first_app(block); instruction;
         instruction = instr_get_next_app(instruction)) {
      const app_pc pc = instr_get_app_pc(instruction);
      if (const auto function = current_functions.find(pc);
          function != current_functions.end())
        prepared->within_entry |= function->second->within;
      Module *current = module_at(pc);
      if (!current || (module && module != current)) {
        *result = prepared.release();
        return;
      }
      module = current;
      owners.hold(*module);
      if (instructions.empty()) {
        prepared->incarnation = module->incarnation;
        prepared->generation = module->code_generation;
      }
      const app_pc next = decode_next_pc(context, pc);
      if (!next || next <= pc || next - pc > 15 || next > module->end) {
        *result = prepared.release();
        return;
      }
      ct_execution_instruction image{};
      image.offset = pc - module->start;
      image.length = next - pc;
      if (!ct_userspace_patch_read_original(pc, image.length, image.bytes)) {
        *result = prepared.release();
        return;
      }
      memory_key.append(reinterpret_cast<const char *>(&image.offset),
                        sizeof(image.offset));
      memory_key.push_back(image.length);
      memory_key.append(reinterpret_cast<const char *>(image.bytes),
                        image.length);
      if (module->code_modified)
        original_flow.push_back(original_code_matches(*module, pc) ? '1' : '0');
      bool boundary = false;
      // Scope-only copies need these boundaries even when the same block also
      // has a full copy. Initial preparation does not select the running level.
      if (prepared->structural) {
        prepare_flow(*module, image.offset);
        std::unique_ptr<ct_location> query;
        ct_location_view location;
        if (!initial_source_location(thread_state(context)->initial_build,
                                     *module, pc, image.length, image.bytes,
                                     location)) {
          query = std::make_unique<ct_location>();
          ct_analysis_lookup(module->analysis, image.offset, query.get());
          location = *query;
        }
        std::string scope = execution_source_scope(location);
        boundary = decoded.empty() || scope != previous_scope ||
                   module->perfetto_boundaries.count(pc);
        instr_t *successor = instr_get_next_app(instruction);
        const int opcode = instr_get_opcode(instruction);
        boundary |= (opcode == OP_cmp || opcode == OP_test) && successor &&
                    instr_is_cbr(successor) &&
                    instr_get_app_pc(successor) == next;
        previous_scope = std::move(scope);
        // Source can change when checksum checking is explicitly bypassed.
        // Include the current scope sequence rather than trusting ELF identity.
        policy += ":" + std::to_string(previous_scope.size()) + ":" +
                  previous_scope + ":" + std::to_string(boundary);
      }
      structural.push_back(boundary);
      instructions.push_back(image);
      decoded.push_back(instruction);
    }
  }
  if (!module || instructions.empty()) {
    *result = prepared.release();
    return;
  }
  // The same bytes can move from private to shared original mappings. A
  // cached recipe must not restore quiet-flow decisions whose whole-function
  // proof is no longer valid, including private blocks beside a shared page.
  if (!original_flow.empty())
    policy += ":original-flow:" + original_flow;
  policy += module->is_main ? ":main" : ":library";
  memory_key = std::string(ct_instrument_level_name(prepared->level)) + ":" +
               std::to_string(instructions.size()) + ":" + memory_key + policy;
  // Long byte sequences and filter/scope descriptions are preparation data.
  // Retaining them again for every reached block can exceed the recipes
  // themselves. Keep only their content digest in the module's lookup table.
  unsigned char recipe_digest[32];
  const ct_digest_part recipe_part{memory_key.data(), memory_key.size()};
  const bool cache_recipe =
      ct_shared_digest_parts(&recipe_part, 1, recipe_digest);
  const std::string recipe_key =
      cache_recipe ? std::string(reinterpret_cast<const char *>(recipe_digest),
                                 sizeof(recipe_digest))
                   : std::string();
  std::vector<ct_execution_recipe> recipes;
  const auto *job = thread_state(context)->initial_build;
  ct_execution_batch *batch = cache_recipe && job &&
                                      job->module.get() == module &&
                                      job->generation == prepared->generation &&
                                      job->level == prepared->level
                                  ? job->execution.get()
                                  : nullptr;
  if (cache_recipe) {
    Lock lock(analysis_lock);
    const auto cached = module->dr_recipes.find(recipe_key);
    if (cached != module->dr_recipes.end())
      recipes = cached->second;
  }
  bool generated = false;
  if (recipes.empty() &&
      !(batch ? ct_execution_batch_lookup(*batch, recipe_key, instructions,
                                          recipes)
              : ct_execution_cache_load(
                    module->identity, policy, prepared->level,
                    module->end - module->start, instructions, recipes))) {
    recipes.resize(instructions.size());
    for (size_t index = 0; index < instructions.size(); ++index) {
      auto &recipe = recipes[index];
      instr_t *instruction = decoded[index];
      const app_pc pc = module->start + instructions[index].offset;
      recipe.quiet_transfer = quiet_boundary(instruction);
      recipe.perfetto_boundary = structural[index] ||
                                 instr_is_cti(instruction) ||
                                 instr_is_syscall(instruction);
      Lock lock(analysis_lock);
      recipe.inline_scope = within_enabled && within_inline_at(*module, pc);
      recipe.scope_boundary = std::any_of(
          module->observation_inline_ranges.begin(),
          module->observation_inline_ranges.end(), [&](const auto &range) {
            return pc == range.first || pc == range.second;
          });
    }
    generated = true;
  }
  if (batch ? !ct_execution_batch_collect(*batch, recipe_key, instructions,
                                          recipes)
            : generated)
    ct_execution_cache_store(module->identity, policy, prepared->level,
                             module->end - module->start, instructions,
                             recipes);
  {
    Lock lock(analysis_lock);
    if (shared_dr_enabled && module->active && !module->pending_code_changes &&
        module->code_generation == prepared->generation &&
        !shared_runtime_identity.empty() && !module->identity.empty()) {
      // The original byte/RVA sequence is already framed in memory_key.
      // Hash semantic recipe fields, never padding, pointers or local module
      // generation counters. Runtime identity includes generator/ABI inputs.
      std::vector<unsigned char> recipe_bits;
      recipe_bits.reserve(recipes.size());
      for (const auto &recipe : recipes)
        recipe_bits.push_back(
            recipe.quiet_transfer | (recipe.inline_scope << 1) |
            (recipe.scope_boundary << 2) | (recipe.perfetto_boundary << 3));
      const uint64_t framing[] = {
          1,
          shared_runtime_identity.size(),
          module->identity.size(),
          memory_key.size(),
          recipe_bits.size(),
          static_cast<uint64_t>(module->end - module->start),
          static_cast<uint64_t>(prepared->level),
          ct_perfetto_enabled(),
          instrumentation_statistics};
      const ct_digest_part parts[] = {
          {framing, sizeof(framing)},
          {shared_runtime_identity.data(), shared_runtime_identity.size()},
          {module->identity.data(), module->identity.size()},
          {memory_key.data(), memory_key.size()},
          {recipe_bits.data(), recipe_bits.size()}};
      prepared->shareable =
          ct_shared_digest_parts(parts, std::size(parts), prepared->provenance);
    }
    if (cache_recipe)
      module->dr_recipes.emplace(recipe_key, recipes);
  }
  prepared->recipes.reserve(instructions.size());
  for (size_t index = 0; index < instructions.size(); ++index)
    prepared->recipes.emplace_back(module->start + instructions[index].offset,
                                   recipes[index]);
  std::stable_sort(prepared->recipes.begin(), prepared->recipes.end(),
                   [](const auto &left, const auto &right) {
                     return left.first < right.first;
                   });
  prepared->recipes.erase(std::unique(prepared->recipes.begin(),
                                      prepared->recipes.end(),
                                      [](const auto &left, const auto &right) {
                                        return left.first == right.first;
                                      }),
                          prepared->recipes.end());
  *result = prepared.release();
}

static void analyze_execution_case(void *, void *, instrlist_t *,
                                   uintptr_t encoding, void *,
                                   void *original_data, void **case_data) {
  *case_data = nullptr;
  auto *prepared = static_cast<ExecutionBlock *>(original_data);
  if (!prepared || !prepared->shareable)
    return;
  // All case analyses complete before insertion begins. Capture the actual
  // ordered compiled set, not a second lookup of concurrently changing hit
  // state. The final case is the default even when duplication is disabled.
  if (encoding > 5 || prepared->cases[0] == std::size(prepared->cases) - 1) {
    prepared->shareable = false;
    return;
  }
  prepared->cases[++prepared->cases[0]] = encoding;
}

static dr_emit_flags_t insert_instruction(void *context, instrlist_t *block,
                                          instr_t *instruction, instr_t *where,
                                          bool translating) {
  if ((!duplicate_enabled && !ct_perfetto_enabled() && translating) ||
      !instr_is_app(instruction) || !traced_process())
    return DR_EMIT_DEFAULT;
  if (ct_perfetto_enabled())
    ct_timing_discard(context);
  app_pc pc = instr_get_app_pc(instruction);
  bool inline_scope = false,
       boundary = instruction == instrlist_first_app(block);
  if (duplicate_enabled)
    drbbdup_is_first_instr(context, instruction, &boundary);
  {
    Lock lock(analysis_lock);
    Module *module = module_at(pc);
    if (!module)
      return DR_EMIT_DEFAULT;
    inline_scope = within_enabled && within_inline_at(*module, pc);
    boundary |= std::any_of(module->observation_inline_ranges.begin(),
                            module->observation_inline_ranges.end(),
                            [&](const auto &range) {
                              return pc == range.first || pc == range.second;
                            });
  }
  if (duplicate_enabled && quiet_boundary(instruction)) {
    dr_insert_clean_call_ex(
        context, block, where, reinterpret_cast<void *>(quiet_transfer),
        static_cast<dr_cleancall_save_t>(DR_CLEANCALL_SAVE_FLOAT |
                                         DR_CLEANCALL_READS_APP_CONTEXT |
                                         DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
        2, OPND_CREATE_INTPTR(pc), OPND_CREATE_INT32(inline_scope));
  } else {
    dr_insert_clean_call_ex(
        context, block, where, reinterpret_cast<void *>(observe),
        static_cast<dr_cleancall_save_t>(DR_CLEANCALL_SAVE_FLOAT |
                                         DR_CLEANCALL_READS_APP_CONTEXT |
                                         DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
        3, OPND_CREATE_INTPTR(pc), OPND_CREATE_INT32(inline_scope),
        OPND_CREATE_INT32(boundary));
  }
  if (ct_perfetto_enabled())
    ct_timing_start(context, block, where);
  // drbbdup needs the reconstructed instruction list to restore its spills on
  // a fault. Stored translation tables omit that list; regenerate these same
  // clean calls during translation so the cache and application PCs line up.
  return duplicate_enabled || ct_perfetto_enabled()
             ? DR_EMIT_DEFAULT
             : DR_EMIT_STORE_TRANSLATIONS;
}

static dr_emit_flags_t instrument(void *context, void *, instrlist_t *block,
                                  instr_t *instruction, bool, bool translating,
                                  void *) {
  return insert_instruction(context, block, instruction, instruction,
                            translating);
}

static dr_emit_flags_t stop_timing(void *context, void *, instrlist_t *block,
                                   instr_t *instruction, bool, bool translating,
                                   void *) {
  if (ct_perfetto_enabled() && instr_is_app(instruction) && traced_process()) {
    ct_timing_discard(context);
    ct_timing_stop(context, block, instruction);
  }
  return DR_EMIT_DEFAULT;
}

static uintptr_t setup_within_block(void *duplicate_context, void *, void *tag,
                                    instrlist_t *block, bool *duplicates,
                                    bool *dynamic, void *) {
  *dynamic = false;
  *duplicates = process_recording;
  if (!process_recording)
    return 3;
  const auto add_case = [&](uintptr_t encoding) {
    if (drbbdup_register_case_encoding(duplicate_context, encoding) !=
        DRBBDUP_SUCCESS)
      fail("instrumentation version registration failed");
  };
  if (!follow_forks)
    add_case(3);
  add_case(0);
  add_case(2);
  {
    Lock lock(analysis_lock);
    instr_t *first = instrlist_first_app(block);
    Module *module = first ? module_at(instr_get_app_pc(first)) : nullptr;
    if (module && module->userspace_disabled)
      module->userspace_disabled_blocks.insert(static_cast<app_pc>(tag));
    if (module) {
      const auto ready = initial_level_at(dr_get_current_drcontext(), *module,
                                          static_cast<app_pc>(tag));
      if (module->detailed_blocks.count(static_cast<app_pc>(tag)) ||
          ready == ct_instrument_level::full)
        add_case(1);
      if (!ct_perfetto_enabled() &&
          initial_level == ct_instrument_level::perfetto &&
          ready != ct_instrument_level::arm)
        add_case(5);
    }
  }
  // Only missing full versions reach this arming copy. A known entry or inline
  // scope never forces the same physical block's subsequent calls to stay full.
  return 4;
}

static void select_execution_version(app_pc tag, app_pc pc, bool within_entry) {
  QuietCallback quiet(dr_get_current_drcontext());
  ct_dr_shared_service(dr_get_current_drcontext(), false, tag);
  uintptr_t selected = 3;
  if (recording_thread()) {
    Lock lock(analysis_lock);
    if (const auto function = current_functions.find(pc);
        function != current_functions.end()) {
      function->second->observed_execution = true;
      within_entry |= function->second->within;
    }
    Thread &thread = *thread_state(dr_get_current_drcontext());
    dr_mcontext_t state{};
    state.size = sizeof(state);
    state.flags = DR_MC_ALL;
    if (!thread.calls.empty() &&
        dr_get_mcontext(dr_get_current_drcontext(), &state) &&
        state.xsp > thread.calls.back()->entry_sp) {
      if (ct_perfetto_enabled())
        thread.trace_timestamp =
            ct_perfetto_now(ct_timing_sample(dr_get_current_drcontext()));
      advance(thread, registers_at(&state, pc), pc);
    }
    const bool step_into = detailed_hit_at(pc);
    if (execution_mode() == 4)
      execution_mode() = step_into ? 1 : 2;
    // The entry wrapper activates within after this dispatch. Its block needs
    // CALL/RET bookkeeping immediately, including when step filters skip it.
    selected = ct_required_instrumentation(ct_perfetto_enabled(), step_into) ==
                       ct_instrument_level::full
                   ? 1
               : execution_mode() == 0 && !within_entry ? 0
                                                        : 2;
  }
  *reinterpret_cast<uintptr_t *>(
      static_cast<byte *>(dr_get_dr_segment_base(within_tls_register)) +
      dispatch_tls_offset) = selected;
}

static void encode_execution_version(void *context, void *tag,
                                     instrlist_t *block, instr_t *where, void *,
                                     void *original_data) {
  instr_t *first = instrlist_first_app(block);
  const app_pc first_pc = first ? instr_get_app_pc(first) : nullptr;
  // DR's rewritten branch/REP fragments can start with an application-marked
  // instruction without a translation PC. Their original BB tag still names
  // the exact policy lookup address; nullptr would incorrectly select arm.
  const app_pc pc = first_pc ? first_pc : static_cast<app_pc>(tag);
  const bool within_entry =
      original_data &&
      static_cast<ExecutionBlock *>(original_data)->within_entry;
  bool boundary = within_entry;
  {
    Lock lock(analysis_lock);
    boundary |= current_functions.count(pc);
    if (Module *module = module_at(pc)) {
      for (const auto &range : module->observation_inline_ranges)
        boundary |= pc >= range.first && pc <= range.second;
      for (const auto &range : module->within_inline_ranges)
        boundary |= pc >= range.first && pc <= range.second;
    }
  }
  if (boundary) {
    dr_insert_clean_call_ex(
        context, block, where,
        reinterpret_cast<void *>(select_execution_version),
        static_cast<dr_cleancall_save_t>(DR_CLEANCALL_SAVE_FLOAT |
                                         DR_CLEANCALL_READS_APP_CONTEXT |
                                         DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
        3, OPND_CREATE_INTPTR(tag), OPND_CREATE_INTPTR(pc),
        OPND_CREATE_INT32(within_entry));
    return;
  }
  reg_id_t scratch = DR_REG_NULL;
  if (drreg_reserve_register(context, block, where, nullptr, &scratch) !=
      DRREG_SUCCESS)
    fail("instrumentation dispatch register reservation failed");
  dr_insert_read_raw_tls(context, block, where, within_tls_register,
                         within_tls_offset, scratch);
  if (drreg_reserve_aflags(context, block, where) != DRREG_SUCCESS)
    fail("instrumentation successor flags reservation failed");
  instr_t *known = INSTR_CREATE_label(context);
  instr_t *done = INSTR_CREATE_label(context);
  instrlist_meta_preinsert(
      block, where,
      INSTR_CREATE_cmp(context, opnd_create_reg(scratch), OPND_CREATE_INT8(4)));
  instrlist_meta_preinsert(
      block, where,
      INSTR_CREATE_jcc(context, OP_jnz, opnd_create_instr(known)));
  dr_insert_clean_call_ex(
      context, block, where, reinterpret_cast<void *>(select_execution_version),
      static_cast<dr_cleancall_save_t>(
          DR_CLEANCALL_SAVE_FLOAT | DR_CLEANCALL_READS_APP_CONTEXT |
          DR_CLEANCALL_MULTIPATH | DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
      3, OPND_CREATE_INTPTR(tag), OPND_CREATE_INTPTR(pc),
      OPND_CREATE_INT32(within_entry));
  instrlist_meta_preinsert(block, where,
                           INSTR_CREATE_jmp(context, opnd_create_instr(done)));
  instrlist_meta_preinsert(block, where, known);
  dr_insert_write_raw_tls(context, block, where, within_tls_register,
                          dispatch_tls_offset, scratch);
  instrlist_meta_preinsert(block, where, done);
  if (drreg_unreserve_aflags(context, block, where) != DRREG_SUCCESS)
    fail("instrumentation successor flags restoration failed");
  if (drreg_unreserve_register(context, block, where, scratch) !=
          DRREG_SUCCESS ||
      drreg_restore_all(context, block, where) != DRREG_SUCCESS)
    fail("instrumentation dispatch register restoration failed");
}

static void arm_detailed_block(app_pc tag, app_pc pc) {
  void *context = dr_get_current_drcontext();
  dr_mcontext_t state{};
  state.size = sizeof(state);
  state.flags = DR_MC_ALL;
  {
    QuietCallback quiet(context);
    ct_dr_shared_service(context, false, tag);
    Lock lock(analysis_lock);
    Module *module = module_at(pc);
    if (!module || !dr_get_mcontext(context, &state))
      return;
    Thread &thread = *thread_state(context);
    if (!thread.calls.empty() && state.xsp > thread.calls.back()->entry_sp) {
      // Resolve a return before testing its caller's inherited policy. The
      // departed callee may have blocked recursive tracing with step-over.
      if (ct_perfetto_enabled()) {
        thread.trace_timestamp = ct_perfetto_now(ct_timing_sample(context));
        thread.trace_signal_timestamp = {};
      }
      advance(thread, registers_at(&state, pc), pc);
    }
    const bool step_into = detailed_hit_at(pc);
    if (ct_required_instrumentation(ct_perfetto_enabled(), step_into) !=
        ct_instrument_level::full)
      return;
    module->detailed_blocks.insert(tag);
    module->detailed_blocks.insert(pc);
    if (step_into)
      trace_activated.store(true, std::memory_order_release);
    // Redirection does not unwind this frame. Leave every RAII scope before
    // flushing, and keep code generation outside the application clock.
    quiet.allow_resume = false;
  }
  state.pc = pc;
  // Only the selected execution must switch before its next instruction.
  // Other threads may finish their old arming fragment. Unlinking prevents
  // new entries without waiting for a vfork parent suspended in the kernel.
  if (!dr_unlink_flush_region(pc, 1))
    fail("detailed block activation flush failed");
  dr_redirect_execution(&state);
}

static void insert_detailed_arm(void *context, void *tag, instrlist_t *block,
                                instr_t *where, app_pc pc, bool boundary) {
  reg_id_t scratch = DR_REG_NULL;
  instr_t *skip = nullptr;
  if (!boundary) {
    if (drreg_reserve_aflags(context, block, where) != DRREG_SUCCESS ||
        drreg_reserve_register(context, block, where, nullptr, &scratch) !=
            DRREG_SUCCESS)
      fail("detailed block arming register reservation failed");
    skip = INSTR_CREATE_label(context);
    dr_insert_read_raw_tls(context, block, where, within_tls_register,
                           within_tls_offset, scratch);
    instrlist_meta_preinsert(block, where,
                             INSTR_CREATE_cmp(context, opnd_create_reg(scratch),
                                              OPND_CREATE_INT8(1)));
    instrlist_meta_preinsert(
        block, where,
        INSTR_CREATE_jcc(context, OP_jnz, opnd_create_instr(skip)));
  }
  dr_insert_clean_call_ex(
      context, block, where, reinterpret_cast<void *>(arm_detailed_block),
      static_cast<dr_cleancall_save_t>(
          DR_CLEANCALL_SAVE_FLOAT | DR_CLEANCALL_READS_APP_CONTEXT |
          DR_CLEANCALL_MULTIPATH | DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
      2, OPND_CREATE_INTPTR(tag), OPND_CREATE_INTPTR(pc));
  if (skip) {
    instrlist_meta_preinsert(block, where, skip);
    if (drreg_unreserve_register(context, block, where, scratch) !=
            DRREG_SUCCESS ||
        drreg_unreserve_aflags(context, block, where) != DRREG_SUCCESS ||
        drreg_restore_all(context, block, where) != DRREG_SUCCESS)
      fail("detailed block arming register restoration failed");
  }
}

static void userspace_entry(app_pc pc, std::atomic<uint32_t> *attempt) {
  if (!structural_instrumentation() && execution_mode() == 1)
    observe_instruction(pc, false, true);
  try_userspace(pc, attempt);
}

static void insert_userspace_attempt(void *context, instrlist_t *block,
                                     instr_t *instruction, instr_t *where) {
  const app_pc pc = instr_get_app_pc(instruction);
  std::atomic<uint32_t> *attempt;
  {
    Lock lock(analysis_lock);
    Module *module = module_at(pc);
    if (!module)
      return;
    auto &entry = module->userspace_attempts[pc];
    if (!entry) {
      const auto range = module->userspace_ranges.upper_bound(pc);
      const bool prepared = range != module->userspace_ranges.begin() &&
                            pc < std::prev(range)->second &&
                            module->userspace_instructions.count(pc) &&
                            !ct_userspace_patch_lookup(pc, nullptr);
      auto &token = userspace_attempt_tokens[pc];
      if (!token)
        token = std::make_unique<std::atomic<uint32_t>>(0);
      entry = token.get();
      entry->store(!module->userspace_disabled &&
                           (!structural_instrumentation() || prepared)
                       ? 1
                       : 0,
                   std::memory_order_release);
    }
    attempt = entry;
  }
  // Both paths share the same spill/restore sequence. MULTIPATH restores the
  // application context for the clean call without changing the skipped path.
  reg_id_t scratch = DR_REG_NULL;
  if (drreg_reserve_aflags(context, block, where) != DRREG_SUCCESS ||
      drreg_reserve_register(context, block, where, nullptr, &scratch) !=
          DRREG_SUCCESS)
    fail("userspace attempt guard register reservation failed");
  instr_t *skip = INSTR_CREATE_label(context);
  instr_t *resolve = INSTR_CREATE_label(context);
  if (!structural_instrumentation()) {
    dr_insert_read_raw_tls(context, block, where, within_tls_register,
                           within_tls_offset, scratch);
    instrlist_meta_preinsert(block, where,
                             INSTR_CREATE_cmp(context, opnd_create_reg(scratch),
                                              OPND_CREATE_INT8(1)));
    instrlist_meta_preinsert(
        block, where,
        INSTR_CREATE_jcc(context, OP_jz, opnd_create_instr(resolve)));
  }
  instrlist_meta_preinsert(block, where,
                           INSTR_CREATE_mov_imm(context,
                                                opnd_create_reg(scratch),
                                                OPND_CREATE_INTPTR(attempt)));
  instrlist_meta_preinsert(block, where,
                           INSTR_CREATE_cmp(context,
                                            OPND_CREATE_MEM32(scratch, 0),
                                            OPND_CREATE_INT8(0)));
  instrlist_meta_preinsert(
      block, where, INSTR_CREATE_jcc(context, OP_jz, opnd_create_instr(skip)));
  instrlist_meta_preinsert(block, where, resolve);
  dr_insert_clean_call_ex(
      context, block, where, reinterpret_cast<void *>(userspace_entry),
      static_cast<dr_cleancall_save_t>(
          DR_CLEANCALL_SAVE_FLOAT | DR_CLEANCALL_READS_APP_CONTEXT |
          DR_CLEANCALL_MULTIPATH | DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
      2, OPND_CREATE_INTPTR(pc), OPND_CREATE_INTPTR(attempt));
  instrlist_meta_preinsert(block, where, skip);
  if (drreg_unreserve_register(context, block, where, scratch) !=
          DRREG_SUCCESS ||
      drreg_unreserve_aflags(context, block, where) != DRREG_SUCCESS ||
      drreg_restore_all(context, block, where) != DRREG_SUCCESS)
    fail("userspace attempt guard register restoration failed");
}

// Diagnostic-only counters record the body actually entered, after an arming
// callback has had the opportunity to redirect before any original instruction.
static void count_execution_version(uintptr_t level) {
  if (recording_thread() && level < 3)
    executed_versions[level].fetch_add(1, std::memory_order_relaxed);
}

static dr_emit_flags_t instrument_within(void *context, void *tag,
                                         instrlist_t *block,
                                         instr_t *instruction, instr_t *where,
                                         bool for_trace, bool translating,
                                         uintptr_t encoding, void *,
                                         void *original_data, void *case_data) {
  auto *prepared = static_cast<ExecutionBlock *>(original_data);
  const bool structural = structural_instrumentation() || encoding == 5;
  if (prepared && prepared->shareable && !prepared->stamped) {
    prepared->stamped = true;
    unsigned char provenance[32];
    const ct_digest_part parts[] = {
        {prepared->provenance, sizeof(prepared->provenance)},
        {prepared->cases, sizeof(prepared->cases)}};
    const bool full =
        std::find(prepared->cases + 1, prepared->cases + 1 + prepared->cases[0],
                  1) != prepared->cases + 1 + prepared->cases[0];
    if (ct_shared_digest_parts(parts, std::size(parts), provenance))
      ct_dr_shared_stamp(
          context, block, provenance,
          std::max(ct_required_instrumentation(ct_perfetto_enabled(), full),
                   prepared->level),
          prepared->incarnation, prepared->generation);
  }
  if (encoding == 3)
    return drwrap_invoke_insert_cleanup_only(context, tag, block, instruction,
                                             where, for_trace, translating,
                                             case_data);
  bool cold_boundary = false, within_entry = false;
  bool within_inline_boundary = false;
  if ((encoding == 0 || encoding == 2 || encoding == 4) &&
      instr_is_app(instruction) && traced_process()) {
    const app_pc pc = instr_get_app_pc(instruction);
    bool first = false;
    drbbdup_is_first_nonlabel_instr(context, instruction, &first);
    {
      Lock lock(analysis_lock);
      cold_boundary = current_functions.count(pc);
      if (const auto function = current_functions.find(pc);
          function != current_functions.end())
        within_entry = function->second->within;
      if (Module *module = module_at(pc)) {
        cold_boundary |= std::any_of(
            module->observation_inline_ranges.begin(),
            module->observation_inline_ranges.end(), [&](const auto &range) {
              return pc == range.first || pc == range.second;
            });
        within_inline_boundary = std::any_of(
            module->within_inline_ranges.begin(),
            module->within_inline_ranges.end(), [&](const auto &range) {
              return pc == range.first || pc == range.second;
            });
        if (first) {
          within_inline_boundary |= within_inline_at(*module, pc);
          cold_boundary |= std::any_of(
              module->observation_inline_ranges.begin(),
              module->observation_inline_ranges.end(), [&](const auto &range) {
                return pc >= range.first && pc < range.second;
              });
        }
        cold_boundary |= within_inline_boundary;
      }
    }
    // Keep the entry wrapper behind the arm: replay must invoke it only once.
    // Inline scopes can begin partway through a BB, so arm those exact PCs.
    if ((encoding == 4 && first) || cold_boundary)
      insert_detailed_arm(context, tag, block, where, pc, cold_boundary);
  }
  if (instrumentation_statistics && instr_is_app(instruction)) {
    bool first = false;
    drbbdup_is_first_nonlabel_instr(context, instruction, &first);
    if (first) {
      const auto level = ct_required_instrumentation(structural, encoding == 1);
      const uintptr_t index = static_cast<uintptr_t>(level);
      if (!translating &&
          !(encoding == 4 && level == ct_instrument_level::full))
        generated_versions[index].fetch_add(1, std::memory_order_relaxed);
      dr_insert_clean_call_ex(
          context, block, where,
          reinterpret_cast<void *>(count_execution_version),
          static_cast<dr_cleancall_save_t>(DR_CLEANCALL_ALWAYS_OUT_OF_LINE), 1,
          OPND_CREATE_INTPTR(index));
    }
  }
  // The inactive copy executes application instructions without observation or
  // TSC probes. Previously generated detailed copies are selected again only
  // after a matching call-stack frame activates this thread's TLS flag.
  if (!encoding || encoding == 2 || encoding == 4 || encoding == 5) {
    if (encoding == 5 && instr_is_app(instruction))
      ct_timing_stop(context, block, where);
    dr_emit_flags_t flags =
        !encoding && !structural && !within_entry
            ? drwrap_invoke_insert_cleanup_only(context, tag, block,
                                                instruction, where, for_trace,
                                                translating, case_data)
            : drwrap_invoke_insert(context, tag, block, instruction, where,
                                   for_trace, translating, case_data);
    if (!instr_is_app(instruction) || !traced_process())
      return flags;
    const app_pc pc = instr_get_app_pc(instruction);
    const ct_execution_recipe *recipe = nullptr;
    // Materialization can precede a stopped peer's cold-fragment translation.
    // Its original instrumentation used raw CTIs, even if analysis now has a
    // detailed recipe for the same tag.
    if (original_data && (encoding != 4 || structural))
      recipe = static_cast<ExecutionBlock *>(original_data)->recipe_at(pc);
    const bool transfer = recipe          ? recipe->quiet_transfer
                          : encoding == 4 ? instr_is_cti(instruction)
                                          : quiet_boundary(instruction);
    bool first = false;
    drbbdup_is_first_nonlabel_instr(context, instruction, &first);
    bool inline_scope = recipe && recipe->inline_scope;
    if (!recipe) {
      Lock lock(analysis_lock);
      if (Module *module = module_at(pc))
        inline_scope = within_enabled && within_inline_at(*module, pc);
    }
    if (structural) {
      // Full timeline coverage needs scope boundaries, not value observation at
      // every instruction. Unknown recipes conservatively retain coverage.
      if (first || !recipe || recipe->perfetto_boundary ||
          recipe->scope_boundary)
        dr_insert_clean_call_ex(
            context, block, where, reinterpret_cast<void *>(observe),
            static_cast<dr_cleancall_save_t>(DR_CLEANCALL_SAVE_FLOAT |
                                             DR_CLEANCALL_READS_APP_CONTEXT |
                                             DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
            3, OPND_CREATE_INTPTR(pc), OPND_CREATE_INT32(inline_scope),
            OPND_CREATE_INT32(true));
      else {
        // A gate installed after this BB was compiled may replay several
        // original instructions here. Its last instruction can extend past a
        // five-byte JMP by at most fourteen bytes, plus an ENDBR prefix. Arm
        // these resume guards only after publishing a complete safe plan.
        const auto *analysis = static_cast<ExecutionBlock *>(original_data);
        bool possible = true, known = false, resume = false, decided = false;
        {
          Lock lock(analysis_lock);
          if (Module *module = module_at(pc)) {
            const auto prior = module->userspace_resume_instrumented.find(pc);
            if (prior != module->userspace_resume_instrumented.end()) {
              resume = prior->second;
              decided = true;
            }
            auto flow = module->flow_ranges.upper_bound(pc - module->start);
            possible = !module->userspace_disabled &&
                       !module->userspace_rejected.count(pc);
            if (flow != module->flow_ranges.begin()) {
              --flow;
              if (uint64_t(pc - module->start) < flow->second)
                possible &= !module->userspace_rejected.count(module->start +
                                                              flow->first);
            }
            auto range = module->userspace_ranges.upper_bound(pc);
            known = range != module->userspace_ranges.begin() &&
                    pc < std::prev(range)->second &&
                    module->userspace_instructions.count(pc);
            if (!decided && possible && known) {
              instr_t *previous = instr_get_prev_app(instruction);
              resume = previous &&
                       ct_userspace_patch_lookup(instr_get_app_pc(previous),
                                                 nullptr) &&
                       !ct_userspace_patch_lookup(pc, nullptr);
            }
          } else {
            possible = false;
          }
        }
        // Most later BBs are generated after preparation. Emit just the known
        // window exit there, and no guards at all for rejected regions. Only
        // the first, still-unprepared BB needs speculative resume positions.
        for (instr_t *previous = !decided && possible && !known
                                     ? instr_get_prev_app(instruction)
                                     : nullptr;
             previous; previous = instr_get_prev_app(previous)) {
          const app_pc previous_pc = instr_get_app_pc(previous);
          if (pc <= previous_pc || pc - previous_pc > 5 + 14 + 4)
            break;
          const auto *previous_recipe = analysis->recipe_at(previous_pc);
          bool previous_first = false;
          drbbdup_is_first_nonlabel_instr(context, previous, &previous_first);
          if (previous_first || !previous_recipe ||
              previous_recipe->perfetto_boundary ||
              previous_recipe->scope_boundary) {
            resume = true;
            break;
          }
        }
        if (!decided) {
          Lock lock(analysis_lock);
          if (Module *module = module_at(pc)) {
            // Signal/fault translation must regenerate the original spills
            // and clean calls even after preparation or rejection changed.
            // Keep the first decision stable for this module's lifetime.
            resume = module->userspace_resume_instrumented.emplace(pc, resume)
                         .first->second;
          }
        }
        if (resume)
          insert_userspace_attempt(context, block, instruction, where);
      }
      if (encoding == 5)
        ct_timing_start(context, block, where);
      return flags;
    }
    if ((encoding == 4 && cold_boundary && !transfer) ||
        (!encoding && within_inline_boundary)) {
      // A skipped inline anchor still owns dynamic --within membership for
      // selected calls beneath it. Update only its exact entry/exit boundaries.
      dr_insert_clean_call_ex(
          context, block, where, reinterpret_cast<void *>(observe),
          static_cast<dr_cleancall_save_t>(DR_CLEANCALL_SAVE_FLOAT |
                                           DR_CLEANCALL_READS_APP_CONTEXT |
                                           DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
          3, OPND_CREATE_INTPTR(pc), OPND_CREATE_INT32(inline_scope),
          OPND_CREATE_INT32(true));
    }
    if (first && (!encoding || !transfer))
      insert_userspace_attempt(context, block, instruction, where);
    if (encoding && transfer) {
      reg_id_t scratch = DR_REG_NULL;
      instr_t *skip = nullptr;
      if (encoding == 4) {
        // Before activation, CALL/RET bookkeeping has no observed values to
        // complete. Keep the cold path in the cache instead of entering a
        // clean call at each branch just to return immediately.
        if (drreg_reserve_aflags(context, block, where) != DRREG_SUCCESS ||
            drreg_reserve_register(context, block, where, nullptr, &scratch) !=
                DRREG_SUCCESS)
          fail("quiet arming register reservation failed");
        skip = INSTR_CREATE_label(context);
        instrlist_meta_preinsert(
            block, where,
            INSTR_CREATE_mov_imm(
                context, opnd_create_reg(scratch),
                OPND_CREATE_INTPTR(&boundary_observation_started)));
        instrlist_meta_preinsert(block, where,
                                 INSTR_CREATE_cmp(context,
                                                  OPND_CREATE_MEM8(scratch, 0),
                                                  OPND_CREATE_INT8(0)));
        instrlist_meta_preinsert(
            block, where,
            INSTR_CREATE_jcc(context, OP_jz, opnd_create_instr(skip)));
      }
      dr_insert_clean_call_ex(
          context, block, where, reinterpret_cast<void *>(quiet_transfer),
          static_cast<dr_cleancall_save_t>(
              DR_CLEANCALL_SAVE_FLOAT | DR_CLEANCALL_READS_APP_CONTEXT |
              DR_CLEANCALL_MULTIPATH | DR_CLEANCALL_ALWAYS_OUT_OF_LINE),
          2, OPND_CREATE_INTPTR(pc), OPND_CREATE_INT32(inline_scope));
      if (skip) {
        instrlist_meta_preinsert(block, where, skip);
        if (drreg_unreserve_register(context, block, where, scratch) !=
                DRREG_SUCCESS ||
            drreg_unreserve_aflags(context, block, where) != DRREG_SUCCESS ||
            drreg_restore_all(context, block, where) != DRREG_SUCCESS)
          fail("quiet arming register restoration failed");
      }
    }
    return flags;
  }
  if (ct_perfetto_enabled() && instr_is_app(instruction) && traced_process()) {
    ct_timing_discard(context);
    ct_timing_stop(context, block, where);
  }
  dr_emit_flags_t flags =
      drwrap_invoke_insert(context, tag, block, instruction, where, for_trace,
                           translating, case_data);
  if (!translating && instr_is_app(instruction)) {
    bool first = false;
    drbbdup_is_first_nonlabel_instr(context, instruction, &first);
    if (first) {
      detailed_fragments.fetch_add(1, std::memory_order_relaxed);
      if (!trace_activated.load(std::memory_order_acquire))
        prehit_detailed_fragments.fetch_add(1, std::memory_order_relaxed);
    }
  }
  return static_cast<dr_emit_flags_t>(
      flags |
      insert_instruction(context, block, instruction, where, translating));
}

static std::pair<const char *, unsigned> syscall_signature(int number) {
  switch (number) {
#define SYSCALL_SIGNATURE(name, count)                                         \
  case SYS_##name:                                                             \
    return {#name, count}
    SYSCALL_SIGNATURE(read, 3);
    SYSCALL_SIGNATURE(write, 3);
    SYSCALL_SIGNATURE(open, 3);
    SYSCALL_SIGNATURE(openat, 4);
    SYSCALL_SIGNATURE(close, 1);
    SYSCALL_SIGNATURE(stat, 2);
    SYSCALL_SIGNATURE(fstat, 2);
    SYSCALL_SIGNATURE(newfstatat, 4);
    SYSCALL_SIGNATURE(lseek, 3);
    SYSCALL_SIGNATURE(mmap, 6);
    SYSCALL_SIGNATURE(mprotect, 3);
    SYSCALL_SIGNATURE(munmap, 2);
    SYSCALL_SIGNATURE(brk, 1);
    SYSCALL_SIGNATURE(madvise, 3);
    SYSCALL_SIGNATURE(rt_sigaction, 4);
    SYSCALL_SIGNATURE(rt_sigprocmask, 4);
    SYSCALL_SIGNATURE(rt_sigreturn, 0);
    SYSCALL_SIGNATURE(rt_sigsuspend, 2);
    SYSCALL_SIGNATURE(rt_sigtimedwait, 4);
    SYSCALL_SIGNATURE(rt_sigpending, 2);
    SYSCALL_SIGNATURE(sigaltstack, 2);
    SYSCALL_SIGNATURE(ioctl, 3);
    SYSCALL_SIGNATURE(pread64, 4);
    SYSCALL_SIGNATURE(pwrite64, 4);
    SYSCALL_SIGNATURE(readv, 3);
    SYSCALL_SIGNATURE(writev, 3);
    SYSCALL_SIGNATURE(access, 2);
    SYSCALL_SIGNATURE(pipe, 1);
    SYSCALL_SIGNATURE(pipe2, 2);
    SYSCALL_SIGNATURE(poll, 3);
    SYSCALL_SIGNATURE(ppoll, 5);
    SYSCALL_SIGNATURE(select, 5);
    SYSCALL_SIGNATURE(pselect6, 6);
    SYSCALL_SIGNATURE(dup, 1);
    SYSCALL_SIGNATURE(dup2, 2);
    SYSCALL_SIGNATURE(dup3, 3);
    SYSCALL_SIGNATURE(fcntl, 3);
    SYSCALL_SIGNATURE(sched_yield, 0);
    SYSCALL_SIGNATURE(nanosleep, 2);
    SYSCALL_SIGNATURE(clock_nanosleep, 4);
    SYSCALL_SIGNATURE(clock_gettime, 2);
    SYSCALL_SIGNATURE(gettimeofday, 2);
    SYSCALL_SIGNATURE(alarm, 1);
    SYSCALL_SIGNATURE(setitimer, 3);
    SYSCALL_SIGNATURE(getpid, 0);
    SYSCALL_SIGNATURE(gettid, 0);
    SYSCALL_SIGNATURE(getppid, 0);
    SYSCALL_SIGNATURE(kill, 2);
    SYSCALL_SIGNATURE(tgkill, 3);
    SYSCALL_SIGNATURE(futex, 6);
    SYSCALL_SIGNATURE(clone, 5);
    SYSCALL_SIGNATURE(clone3, 2);
    SYSCALL_SIGNATURE(fork, 0);
    SYSCALL_SIGNATURE(vfork, 0);
    SYSCALL_SIGNATURE(execve, 3);
    SYSCALL_SIGNATURE(execveat, 5);
    SYSCALL_SIGNATURE(exit, 1);
    SYSCALL_SIGNATURE(exit_group, 1);
    SYSCALL_SIGNATURE(wait4, 4);
    SYSCALL_SIGNATURE(socket, 3);
    SYSCALL_SIGNATURE(connect, 3);
    SYSCALL_SIGNATURE(accept, 3);
    SYSCALL_SIGNATURE(bind, 3);
    SYSCALL_SIGNATURE(listen, 2);
    SYSCALL_SIGNATURE(sendto, 6);
    SYSCALL_SIGNATURE(recvfrom, 6);
    SYSCALL_SIGNATURE(sendmsg, 3);
    SYSCALL_SIGNATURE(recvmsg, 3);
    SYSCALL_SIGNATURE(getrandom, 3);
#undef SYSCALL_SIGNATURE
  default:
    return {"?", 0};
  }
}

static std::string syscall_trace_name(int number) {
  const char *name = syscall_signature(number).first;
  return "[SYS_" +
         (std::strcmp(name, "?") == 0 ? std::to_string(number)
                                      : std::string(name)) +
         "]";
}

static bool filter_syscall(void *, int) {
  // The filter is evaluated while generating code, not on each execution.
  // Within membership must therefore be checked by the runtime callbacks.
  return true;
}

static void prepare_shared_child(void *context, int number) {
  uint64_t flags = 0;
  reg_t stack = 0;
  bool creates = number == SYS_fork || number == SYS_vfork;
  if (number == SYS_vfork)
    flags = CLONE_VM | CLONE_VFORK;
  if (number == SYS_clone) {
    creates = true;
    flags = dr_syscall_get_param(context, 0);
    stack = dr_syscall_get_param(context, 1);
  } else if (number == SYS_clone3) {
    struct clone_args arguments{};
    const size_t size =
        std::min(size_t(dr_syscall_get_param(context, 1)), sizeof(arguments));
    if (size < offsetof(clone_args, tls) ||
        !dr_safe_read(
            reinterpret_cast<void *>(dr_syscall_get_param(context, 0)), size,
            &arguments, nullptr))
      return;
    creates = true;
    flags = arguments.flags;
    if (arguments.stack_size > UINTPTR_MAX - arguments.stack)
      return;
    stack = arguments.stack ? arguments.stack + arguments.stack_size : 0;
  }
  if (!creates)
    return;
  Thread &thread = *thread_state(context);
  // Private-address-space clones inherit this TLS field into fork_child.
  // Shared-address-space children consume a separate origin at their initial
  // application RSP before executing any application instructions.
  thread.child_new_stack = within_new_stack && stack != 0;
  if (!(flags & CLONE_VM) ||
      (stack ? !within_new_stack : (flags & CLONE_THREAD) != 0))
    return;
  const bool separate_stack = stack != 0;
  if (!stack) {
    dr_mcontext_t state{};
    state.size = sizeof(state);
    state.flags = DR_MC_CONTROL;
    if (!dr_get_mcontext(context, &state))
      return;
    stack = state.xsp;
  }
  Lock lock(analysis_lock);
  SharedOrigin origin;
  origin.new_stack_scope = separate_stack || thread.new_stack_scope;
  // A separate stack has no active caller frames or inherited step-filter
  // recursion. A shared current stack retains its existing within selection.
  if (!separate_stack) {
    origin.calls.reserve(thread.calls.size());
    for (const Call *call : thread.calls) {
      // Frame boundaries expire through the ordinary return/unwind handling.
      // The child owns fresh markers, never the parent's output or trace
      // tokens.
      auto inherited = std::make_unique<Call>();
      inherited->timing_only = true;
      inherited->entry_pc = call->entry_pc;
      inherited->entry_sp = call->entry_sp;
      inherited->return_pc = call->return_pc;
      inherited->function = call->function;
      inherited->scope = call->scope;
      inherited->within = call->within;
      inherited->within_inline = call->within_inline;
      inherited->within_synthetic = call->within_synthetic;
      inherited->startup_entry = call->startup_entry;
      inherited->startup_controlled = call->startup_controlled;
      inherited->signal_frame = call->signal_frame;
      inherited->signal_handler_active = call->signal_handler_active;
      inherited->signal_number = call->signal_number;
      inherited->interrupted_sp = call->interrupted_sp;
      origin.calls.push_back(std::move(inherited));
    }
  }
  shared_origins.insert_or_assign(stack, std::move(origin));
  thread.shared_child_stack = stack;
}

static void fork_prepare(void *context) {
  // DR has quiesced every peer before this callback. Verify/drain each client
  // channel while the snapshot is stable, releasing all locks before returning
  // to DR or executing the actual fork syscall.
  std::vector<uint64_t> objects;
  ct_dr_shared_fork_prepare(context, objects);
  Lock lock(analysis_lock);
  Thread &thread = *thread_state(context);
  if (!shared_userspace_versions.empty() || !objects.empty()) {
    if (!thread.shared_channel)
      thread.shared_channel = ct_shared_open();
    objects.reserve(objects.size() + shared_userspace_versions.size());
    for (const auto &entry : shared_userspace_versions)
      objects.push_back(entry.second);
    if (!thread.shared_channel ||
        !ct_shared_fork_reserve_selected(thread.shared_channel, objects.data(),
                                         objects.size(), &thread.shared_fork))
      fail("cannot preserve shared execution objects across fork");
  }
  ct_perfetto_fork_prepare();
  ct_analysis_fork_prepare();
  dr_mutex_lock(display_lock);
  if (duplicate_enabled)
    ct_userspace_patch_fork_prepare();
  ct_output_fork_prepare();
  ct_output_fork_parent();
  if (duplicate_enabled)
    ct_userspace_patch_fork_parent();
  dr_mutex_unlock(display_lock);
  ct_analysis_fork_parent();
  ct_perfetto_fork_parent();
  // Per-caller state distinguishes ordinary-fork cleanup from shared-image
  // vfork/CLONE_VM exits, including simultaneous forks in different threads.
  thread.fork_snapshot_pending = true;
}

static void fork_parent(void *context) {
  Thread &thread = *thread_state(context);
  thread.fork_snapshot_pending = false;
  if (thread.shared_fork.fd >= 0 &&
      !ct_shared_fork_parent_done(&thread.shared_fork))
    fail("cannot complete shared execution fork reservation");
  ct_dr_shared_fork_parent_done(context);
}

static void prepare_exec(void *context, int number) {
  if (number != SYS_execve && number != SYS_execveat)
    return;
  std::vector<ct_exec_timestamp> timestamps;
  if (ct_perfetto_enabled()) {
    const auto snapshots = ct_timing_snapshot_process();
    const uint64_t wall = ct_analysis_wall_nanoseconds();
    if (!wall)
      fail("cannot sample the Perfetto exec boundary clock");
    for (const auto &snapshot : snapshots)
      if (snapshot.track_token)
        timestamps.push_back(
            {snapshot.track_token, snapshot.nanoseconds, wall});
  }
  Thread &thread = *thread_state(context);
  thread.exec_ticket = ct_analysis_prepare_exec(
      recording_thread(context), timestamps.data(), timestamps.size());
  if (!thread.exec_ticket ||
      !dr_set_exec_client_data(context, thread.exec_ticket))
    fail("cannot preserve tracing policy across exec");
}

static bool pre_syscall(void *context, int number) {
  QuietCallback quiet(context);
  if (!traced_process())
    return true;
  ct_dr_shared_service(context);
  if (duplicate_enabled) {
    const bool memory_change =
        number == SYS_munmap || number == SYS_mprotect || number == SYS_mremap
#ifdef SYS_pkey_mprotect
        || number == SYS_pkey_mprotect
#endif
        ||
        (number == SYS_mmap && (dr_syscall_get_param(context, 3) & MAP_FIXED));
    if (memory_change) {
      std::vector<std::pair<uintptr_t, size_t>> changes{
          {dr_syscall_get_param(context, 0), dr_syscall_get_param(context, 1)}};
      if (number == SYS_mremap &&
          (dr_syscall_get_param(context, 3) & MREMAP_FIXED))
        changes.emplace_back(dr_syscall_get_param(context, 4),
                             dr_syscall_get_param(context, 2));
      {
        std::vector<std::pair<Module *, bool>> affected;
        {
          Lock lock(analysis_lock);
          std::set<Module *> original_changes;
          for (auto &module : modules) {
            if (!module->active)
              continue;
            bool executable_change = false;
            for (const auto &change : changes) {
              if (!change.second || change.second > UINTPTR_MAX - change.first)
                continue;
              for (const auto &range : module->executable_ranges)
                executable_change |=
                    change.first < reinterpret_cast<uintptr_t>(range.second) &&
                    change.first + change.second >
                        reinterpret_cast<uintptr_t>(range.first);
            }
            if (executable_change) {
              // Also invalidate plans not yet published. A syscall approved
              // before their publication must not change a validated body.
              original_changes.insert(module.get());
            }
          }
          if (!original_changes.empty()) {
            auto &change = thread_state(context)->changing_code.emplace_back(
                number, std::vector<CodeChange>{});
            // Direct userspace calls can cross module boundaries. Retire the
            // complete prepared graph before any callee's text can change.
            for (auto &module : modules) {
              if (!module->active)
                continue;
              module->userspace_disabled = true;
              ++module->userspace_binding_generation;
              ++module->pending_userspace_changes;
              const bool original = original_changes.count(module.get()) != 0;
              if (original)
                ++module->pending_code_changes;
              change.second.push_back({module, original});
              // Retiring a cross-module execution graph does not change every
              // instruction's source/value plan. Reuse proven snapshots;
              // observe_instruction replaces a Site only when its bytes
              // actually differ. Otherwise repeated permission changes would
              // accumulate another complete set of historical Sites.
              for (auto site = current_sites.begin();
                   site != current_sites.end();) {
                if (original && site->second->module == module &&
                    !site->second->original_size)
                  site = current_sites.erase(site);
                else
                  ++site;
              }
              for (auto &attempt : module->userspace_attempts)
                attempt.second->store(0, std::memory_order_release);
              affected.emplace_back(module.get(), original);
            }
          }
        }
        if (!affected.empty()) {
          retire_userspace_gates(affected);
        }
      }
    }
  }
  release_shared_versions(*thread_state(context));
  if (!ct_perfetto_enabled() || !recording_thread(context)) {
    prepare_shared_child(context, number);
    prepare_exec(context, number);
    return true;
  }
  Thread &thread = *thread_state(context);
  // An ignored signal has no handler-entry/return notification. Reaching a
  // later application syscall proves it did not terminate this thread; do not
  // truncate the execution bar at that old signal when normal exit follows.
  thread.trace_signal_timestamp = {};
  thread.trace_timestamp = ct_perfetto_now(ct_timing_sample(context));
  {
    Lock lock(analysis_lock);
    close_trace_syscall(thread, "interrupted");
    thread.syscall = {};
    thread.syscall.number = number;
    dr_mcontext_t state{};
    state.size = sizeof(state);
    state.flags = DR_MC_CONTROL;
    if (dr_get_mcontext(context, &state))
      thread.syscall.pc = state.pc;
    if (thread.pending.site && thread.pending.site->instruction.syscall)
      thread.syscall.pc = thread.pending.site->instruction.pc;
    if (within_call_stack(thread) || signal_context_active(thread)) {
      const auto [name, count] = syscall_signature(number);
      thread.syscall.details =
          "name=" + std::string(name) + " number=" + std::to_string(number);
      for (unsigned index = 0; index < count; ++index) {
        char argument[64];
        dr_snprintf(argument, sizeof(argument), " arg%u=0x%llx", index,
                    static_cast<unsigned long long>(
                        dr_syscall_get_param(context, index)));
        thread.syscall.details += argument;
      }
      thread.syscall.token = begin_trace_context(
          thread, thread.syscall.pc, "ctrace.syscall",
          syscall_trace_name(number).c_str(), thread.syscall.details);
    }
  }
  // Exit cleanup and sigreturn are handled by DR without a normal post event.
  // Do not charge its shutdown/context-restoration work as kernel residence.
  prepare_shared_child(context, number);
  prepare_exec(context, number);
  if (number != SYS_exit && number != SYS_exit_group &&
      number != SYS_rt_sigreturn)
    ct_timing_kernel_begin(context);
  else
    quiet.allow_resume = false;
  return true;
}

static void post_syscall(void *context, int number) {
  Thread *state =
      static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
  QuietCallback quiet(context);
  if (state && !state->changing_code.empty() &&
      state->changing_code.back().first == number) {
    std::vector<std::pair<app_pc, size_t>> rearm;
    const bool succeeded =
        static_cast<int64_t>(dr_syscall_get_result(context)) >= 0;
    {
      Lock lock(analysis_lock);
      for (const auto &change : state->changing_code.back().second) {
        const auto &module = change.module;
        if (change.original) {
          if (module->pending_code_changes)
            --module->pending_code_changes;
          if (module->runtime_image && module->active) {
            bool valid =
                !(succeeded && (number == SYS_mmap || number == SYS_munmap ||
                                number == SYS_mremap));
            bool mutable_code = false;
            for (app_pc cursor = module->start;
                 valid && cursor < module->end;) {
              dr_mem_info_t memory{};
              valid = dr_query_memory_ex(cursor, &memory) &&
                      memory.base_pc <= cursor &&
                      memory.size <= UINTPTR_MAX - uintptr_t(memory.base_pc) &&
                      memory.base_pc + memory.size > cursor &&
                      (memory.prot & DR_MEMPROT_EXEC);
              if (valid) {
                mutable_code |=
                    (memory.prot & (DR_MEMPROT_WRITE | DR_MEMPROT_SHARED)) != 0;
                cursor = std::min(module->end, memory.base_pc + memory.size);
              }
            }
            if (valid) {
              // Even a failed mprotect can have changed a prefix before a
              // hole. Check actual permissions and bytes, not just errno.
              valid = runtime_image_matches(*module);
            }
            if (!valid)
              retire_runtime_image(*module);
            else {
              // An unchanged byte snapshot can survive permission changes,
              // but a proof made while it was private RX cannot survive a
              // writable/shared interval (including partial syscall failure).
              ++module->code_generation;
              module->code_modified |= mutable_code;
              module->original_code_proofs.clear();
              module->original_proof_failures.clear();
              module->decompiled_proofs.clear();
              module->dr_recipes.clear();
            }
          } else if (succeeded && !module->runtime_image) {
            ++module->code_generation;
            module->code_modified = true;
            module->dr_recipes.clear();
          }
        }
        if (module->pending_userspace_changes)
          --module->pending_userspace_changes;
        if (module->active && !module->pending_userspace_changes) {
          revalidate_userspace_versions(*module);
          module->userspace_disabled = false;
          for (auto &[key, preparation] : module->initial_preparations)
            if (preparation.status == InitialPreparationState::Pending)
              preparation.attempted_revision = 0;
          for (auto &attempt : module->userspace_attempts)
            attempt.second->store(1, std::memory_order_release);
          // Retiring cross-module userspace bindings does not invalidate an
          // unchanged module's full DR copies. Only BBs generated during the
          // disabled interval need their original-address entry gates rearmed.
          for (app_pc pc : module->userspace_disabled_blocks)
            rearm.emplace_back(pc, 1);
          module->userspace_disabled_blocks.clear();
        }
      }
      state->changing_code.pop_back();
      reclaim_modules();
    }
    // Peers may have generated DR-only blocks while the mapping syscall was
    // pending. Rebuild their arming gates without holding a lock needed by
    // another thread's callback: unlinking may wait for that callback.
    for (const auto &range : rearm)
      if (!dr_unlink_flush_region(range.first, range.second))
        fail("cannot rearm userspace entry after mapping change");
    if (!succeeded)
      queue_initial_preparations(context);
  }
  if ((number == SYS_mmap || number == SYS_mprotect || number == SYS_mremap
#ifdef SYS_pkey_mprotect
       || number == SYS_pkey_mprotect
#endif
       ) &&
      static_cast<int64_t>(dr_syscall_get_result(context)) >= 0)
    discover_initial_modules(context);
  if (number == SYS_setns &&
      static_cast<int64_t>(dr_syscall_get_result(context)) == 0 &&
      !ct_analysis_refresh_clock())
    fail("cannot normalize the Perfetto clock after setns");
  const bool timed =
      traced_process() && ct_perfetto_enabled() && recording_thread(context);
  const ct_perfetto_timestamp timestamp =
      timed ? ct_perfetto_now(ct_timing_kernel_end(context))
            : ct_perfetto_timestamp{};
  if (state && state->exec_ticket &&
      (number == SYS_execve || number == SYS_execveat)) {
    // A successful exec starts a new client. Only a failed attempt reaches
    // this callback, so release its ticket without changing the live image.
    if (!ct_analysis_cancel_exec(state->exec_ticket) ||
        !dr_set_exec_client_data(context, 0))
      fail("cannot release failed exec tracing policy");
    state->exec_ticket = 0;
  }
  if (state &&
      (number == SYS_vfork || number == SYS_clone || number == SYS_clone3)) {
    state->child_new_stack = false;
    Lock lock(analysis_lock);
    if (state->shared_child_stack &&
        static_cast<int64_t>(dr_syscall_get_result(context)) < 0)
      shared_origins.erase(state->shared_child_stack);
    state->shared_child_stack = 0;
  }
  if (!timed)
    return;
  Thread &thread = *thread_state(context);
  thread.trace_timestamp = timestamp;
  if (thread.syscall.number != number)
    return;
  Lock lock(analysis_lock);
  const auto result = static_cast<int64_t>(dr_syscall_get_result(context));
  std::string details = "result=" + std::to_string(result);
  if (result < 0 && result >= -4095)
    details += " errno=" + std::to_string(-result);
  close_trace_syscall(thread, "returned", details.c_str());
  thread.syscall = {};
}

static void thread_init(void *context) {
  Thread &thread = *thread_state(context);
  if (duplicate_enabled)
    execution_mode() = thread.recording ? (within_enabled ? 0 : 1) : 3;
  if (!thread.owns_image || within_new_stack) {
    dr_mcontext_t state{};
    state.size = sizeof(state);
    state.flags = DR_MC_CONTROL;
    if (dr_get_mcontext(context, &state)) {
      Lock lock(analysis_lock);
      const auto origin = shared_origins.find(state.xsp);
      if (origin != shared_origins.end()) {
        thread.new_stack_scope = origin->second.new_stack_scope;
        if (thread.calls.empty()) {
          thread.calls.reserve(origin->second.calls.size());
          for (auto &call : origin->second.calls)
            thread.calls.push_back(call.release());
        }
        shared_origins.erase(origin);
      }
    }
  }
  update_within(thread);
  if (!ct_perfetto_enabled() || !thread.recording)
    return;
  ct_timing_register_thread(context);
  ct_perfetto_thread_begin(context);
  thread.timing_started = true;
  ct_timing_quiet_begin(context);
}

static void fork_child(void *context) {
  Thread &thread = *thread_state(context);
  bool recover_initial = false;
  thread.fork_snapshot_pending = false;
  const thread_id_t parent_tid = thread.tid;
  // Immutable sites and code-cache references retain their addresses in the
  // child. Rebind only process-local ownership, connections and runtime clocks.
  owner_pid = dr_get_process_id();
  process_recording = follow_forks;
  thread.recording = follow_forks;
  thread.process = owner_pid;
  thread.owns_image = false;
  thread.exec_ticket = 0;
  thread.shared_child_stack = 0;
  thread.userspace_step_end = nullptr;
  thread.userspace_copy_pending = false;
  thread.initial_build = nullptr;
  thread.collecting_initial = false;
  thread.discovering_modules = false;
  dr_mutex_reset_after_fork(analysis_lock);
  dr_mutex_reset_after_fork(module_hook_lock);
  dr_mutex_reset_after_fork(display_lock);
  ct_output_fork_child();
  if (duplicate_enabled)
    ct_userspace_patch_fork_child();
  const thread_id_t tid = dr_get_thread_id(context);
  initial_context.store(context, std::memory_order_relaxed);
  thread.tid = tid;
  for (auto &entry : inherited_thread_ids)
    entry.second = tid;
  if (parent_tid)
    inherited_thread_ids[parent_tid] = tid;
  for (auto &module : modules) {
    const bool pending_change = module->pending_code_changes != 0;
    if (module->pending_userspace_changes)
      module->pending_userspace_changes = 0;
    // Ordinary fork preserves unchanged executable pages, cookies and prepared
    // metadata. Only an interrupted mapping transaction needs a new proof.
    if (pending_change) {
      module->pending_code_changes = 0;
      ++module->code_generation;
      module->code_modified = true;
      module->dr_recipes.clear();
      recover_initial = true;
    }
    // Producers suspended in other parent threads do not survive fork. Avoid
    // dirtying inherited metadata pages for already completed versions.
    for (auto &version : module->userspace_versions)
      if (version.second.preparation)
        version.second.preparation = 0;
  }
  shared_origins.clear();
  if (!ct_analysis_fork_child())
    fail("cannot connect child analysis session");
  thread.owns_image = ct_analysis_object_owner() != 0;
  if (thread.shared_channel) {
    ct_shared_fork_forget_channel(thread.shared_channel);
    thread.shared_channel = nullptr;
  }
  if (thread.shared_fork.fd >= 0) {
    thread.shared_channel = ct_shared_open();
    if (!thread.shared_channel ||
        !ct_shared_fork_claim(thread.shared_channel, &thread.shared_fork))
      fail("cannot claim inherited shared execution objects");
  }
  ct_dr_shared_fork_child(context);
  // The fork reservation includes only published local views. Discard jobs
  // owned by vanished producers without touching their already-closed FDs.
  for (auto &job : version_preparations) {
    job.second->abandoned = true;
    // This pointer borrows the owning Thread's wrapper. Forget that wrapper
    // once below, without closing a descriptor DR may already have reused.
    job.second->channel = nullptr;
  }
  version_preparations.clear();
  {
    Lock lock(analysis_lock);
    thread.changing_code.clear();
    while (thread.fork_vanished) {
      Thread *vanished = thread.fork_vanished;
      thread.fork_vanished = vanished->fork_vanished_next;
      if (vanished->shared_channel &&
          !ct_shared_fork_forget_channel(vanished->shared_channel))
        fail("cannot forget an inherited thread channel");
      vanished->shared_channel = nullptr;
      // Reservation liveness descriptors explicitly survive fork, unlike the
      // ordinary channel/temporary FDs. Release only this child's unused copy.
      if (vanished->shared_fork.fd >= 0) {
        if (!vanished->shared_fork.token ||
            vanished->shared_fork.owner_process !=
                static_cast<uint64_t>(vanished->process) ||
            !vanished->shared_fork.owner_session ||
            vanished->shared_fork.owner_session == ct_analysis_object_owner())
          fail("invalid inherited thread fork reservation");
        dr_close_file(vanished->shared_fork.fd);
        vanished->shared_fork.fd = -1;
      }
      // No trace completion, broker release, or dead DR-context access: these
      // frames exist only as copied C++ owners and never executed in the child.
      for (Call *call : vanished->calls)
        delete call;
      for (auto &job : vanished->initial_requests) {
        if (!job)
          continue;
        auto position =
            job->module->initial_preparations.find({job->function, job->level});
        if (position != job->module->initial_preparations.end() &&
            position->second.cookie == job->cookie &&
            position->second.status == InitialPreparationState::Queued) {
          position->second.status = InitialPreparationState::Pending;
          position->second.reason = "unsubmitted fork producer disappeared";
          recover_initial = true;
        }
      }
      delete vanished;
      fork_threads_reclaimed.fetch_add(1, std::memory_order_relaxed);
    }
  }
  ct_userspace_version_fork_child(context);
  released_shared_versions.clear();
  if (thread.child_new_stack) {
    // clone without CLONE_VM copies client state, but an explicit child stack
    // does not copy the caller's active frames. Discard their output tokens
    // without emitting completions or inheriting recursive step selection.
    thread.new_stack_scope = true;
    for (Call *call : thread.calls)
      delete call;
    thread.calls.clear();
    thread.pending = {};
    thread.deferred_call = {};
    thread.root = {};
    thread.root_scope = {};
    thread.root_provenance = {};
    thread.root_machine = {};
    thread.blocks.clear();
    thread.syscall = {};
    thread.signal_number = 0;
    thread.signal_description.clear();
    thread.arrival_pc = thread.assembly_arrival_pc = thread.plt_marker_pc =
        thread.annotation_pc = nullptr;
    thread.arrival_outcome = -1;
    thread.arrival_annotation = ArrivalAnnotation::None;
  }
  thread.child_new_stack = false;
  process_recording = follow_forks || ct_analysis_recording_allowed();
  thread.recording = process_recording;
  ct_timing_after_fork(context);
  thread.trace_timestamp = thread.trace_signal_timestamp = {};
  thread.quiet_callback_depth = 0;
  thread.resume_quiet_generation = thread.resume_quiet_suspension = false;
  if (!ct_perfetto_fork_child(context, thread.recording))
    fail("cannot initialize child Perfetto recording");
  if (!thread.recording) {
    thread.timing_started = false;
    if (duplicate_enabled)
      execution_mode() = 3;
    return;
  }
  if (ct_perfetto_enabled())
    ct_timing_register_thread(context);
  if (ct_perfetto_enabled())
    thread.trace_timestamp = ct_perfetto_now(0);
  const auto reopen = [&](MachineContext &machine, app_pc pc) {
    if (machine.trace_function)
      machine.trace_function = begin_trace_context(
          thread, pc, "ctrace.function", machine.trace_function_name.c_str(),
          "inherited after fork");
    for (auto &block : machine.trace_blocks) {
      if (!block.token)
        continue;
      const auto &description = *block.description;
      block.token = begin_trace_block(*block.entry,
                                      description.opening_context[0]
                                          ? description.opening_context
                                          : description.opening,
                                      description.opening_line, "source");
    }
    for (auto &block : machine.blocks)
      if (block.trace_token)
        block.trace_token = begin_trace_block(
            *block.last,
            block.trace_name.empty() ? block.opening.c_str()
                                     : block.trace_name.c_str(),
            block.last->location.line, block.trace_origin.c_str());
  };
  reopen(thread.root_machine, main_start);
  for (Call *call : thread.calls) {
    if (call->trace_signal_context)
      call->trace_signal_context = begin_trace_context(
          thread, call->entry_pc, "ctrace.signal",
          ("[" + ct_signal_name(call->signal_number) + "]").c_str(),
          "inherited after fork");
    call->interrupted_syscall.token = 0;
    reopen(call->machine, call->entry_pc);
  }
  if (thread.syscall.token)
    thread.syscall.token =
        begin_trace_context(thread, thread.syscall.pc, "ctrace.syscall",
                            syscall_trace_name(thread.syscall.number).c_str(),
                            thread.syscall.details);
  update_within(thread);
  thread.timing_started = ct_perfetto_enabled();
  ct_timing_quiet_begin(context);
  if (recover_initial)
    queue_initial_preparations(context);
}

static void close_shared_thread(void *context, Thread &thread) {
  std::unique_ptr<SharedVersionPreparation> preparation;
  {
    Lock lock(analysis_lock);
    auto found = version_preparations.find(context);
    if (found != version_preparations.end()) {
      preparation = std::move(found->second);
      version_preparations.erase(found);
    }
  }
  ct_shared_channel *cleanup = nullptr;
  if (preparation && context != dr_get_current_drcontext()) {
    if (preparation->object)
      cleanup = ct_shared_open();
    preparation->channel = cleanup;
  }
  preparation.reset();
  ct_userspace_version_thread_exit(context);
  if (cleanup)
    ct_shared_close(cleanup);
  if (thread.shared_fork.fd >= 0)
    ct_shared_fork_parent_done(&thread.shared_fork);
  if (thread.shared_channel) {
    ct_shared_close_quiescent(thread.shared_channel);
    thread.shared_channel = nullptr;
  }
}

static void thread_exit(void *context) {
  auto *thread = static_cast<Thread *>(drmgr_get_tls_field(context, tls_index));
  if (!traced_process()) {
    // DR retires vanished peer contexts before invoking fork_child. Preserve
    // their client-owned state without allocation until the new session and
    // locks are ready; DR may free CONTEXT immediately after this callback.
    auto *survivor = static_cast<Thread *>(
        drmgr_get_tls_field(dr_get_current_drcontext(), tls_index));
    if (thread && survivor && thread != survivor &&
        survivor->fork_snapshot_pending &&
        survivor->process != dr_get_process_id()) {
      thread->fork_vanished_next = survivor->fork_vanished;
      survivor->fork_vanished = thread;
      drmgr_set_tls_field(context, tls_index, nullptr);
    }
    return;
  }
  if (!thread)
    return;
  void *initial = context;
  initial_context.compare_exchange_strong(initial, nullptr,
                                          std::memory_order_relaxed);
  if (!thread->recording) {
    ct_timing_unregister_thread(context);
    close_shared_thread(context, *thread);
    Lock lock(analysis_lock);
    for (Call *call : thread->calls)
      delete call;
    delete thread;
    drmgr_set_tls_field(context, tls_index, nullptr);
    return;
  }
  if (ct_perfetto_enabled()) {
    thread->timing_started = false;
    ct_timing_quiet_end(context);
    const uint64_t final_timestamp = ct_timing_kernel_end(context);
    thread->trace_timestamp =
        thread->trace_signal_timestamp.wall_nanoseconds
            ? thread->trace_signal_timestamp
            : ct_perfetto_now(context == dr_get_current_drcontext()
                                  ? ct_timing_sample(context)
                                  : final_timestamp);
    close_trace_syscall(*thread, "no_return", "return=?");
    thread->syscall = {};
    ct_perfetto_thread_end(context, thread->trace_timestamp,
                           thread->trace_signal_timestamp.wall_nanoseconds
                               ? "interrupted"
                               : "thread_exit");
  }
  ct_timing_unregister_thread(context);
  close_shared_thread(context, *thread);
  Lock lock(analysis_lock);
  close_visit(thread->deferred_call, "thread exited before completion");
  for (auto iterator = thread->calls.rbegin(); iterator != thread->calls.rend();
       ++iterator) {
    close_deferred_call(**iterator);
    flush_machine_rows((*iterator)->machine);
    close_visit((*iterator)->returning, "thread exited before completion");
    for (auto &exit : (*iterator)->block_exits)
      close_visit(exit, "thread exited before completion");
    for (const auto &line : (*iterator)->return_lines)
      write_line(line.text, std::string::npos, nullptr, -1, std::string::npos,
                 nullptr, -1, nullptr, std::string::npos, 0,
                 line.closing_context);
    close_visit((*iterator)->visit, "thread exited before completion");
    close_plt((*iterator)->machine, (*iterator)->visit);
    close_machine_blocks((*iterator)->machine);
    close_blocks((*iterator)->blocks, 0, "thread exited before completion");
    // These frames never returned. Teardown must not synthesize a function
    // closing brace, especially after a fatal signal's diagnostic.
    close_visit((*iterator)->summary, "thread exited before completion");
    for (auto &tail : (*iterator)->tail_summaries)
      close_visit(tail.visit, "thread exited before completion");
    flush_decompiled_rows((*iterator)->machine);
    delete *iterator;
  }
  flush_machine_rows(thread->root_machine);
  close_visit(thread->root, "thread exited before completion");
  close_plt(thread->root_machine, thread->root);
  close_machine_blocks(thread->root_machine);
  close_blocks(thread->blocks, 0, "thread exited before completion");
  flush_decompiled_rows(thread->root_machine);
  close_visit(thread->deferred_call, "thread exited before completion");
  delete thread;
  drmgr_set_tls_field(context, tls_index, nullptr);
}

static dr_signal_action_t signal_event(void *context,
                                       dr_siginfo_t *information) {
  QuietCallback quiet(context);
  if (!traced_process() || !recording_thread(context))
    return DR_SIGNAL_DELIVER;
  Thread &thread = *thread_state(context);
  if (ct_perfetto_enabled() && dr_is_client_userspace(context))
    ct_perfetto_userspace_span(false);
  thread.userspace_step_end = nullptr;
  if (ct_perfetto_enabled()) {
    ct_timing_kernel_end(context);
    ct_timing_discard(context);
    thread.trace_timestamp = ct_perfetto_now(ct_timing_sample(context));
  }
  Lock lock(analysis_lock);
  thread.assembly_arrival_pc = nullptr;
  flush_machine_rows(current_machine(thread));
  thread.arrival_pc = nullptr;
  thread.arrival_outcome = -1;
  thread.annotation_pc = nullptr;
  thread.arrival_annotation = ArrivalAnnotation::None;
  current_machine(thread).comparison = {};
  if (thread.pending.site && information->mcontext &&
      information->mcontext->pc == thread.pending.site->instruction.pc) {
    close_visit(*thread.pending.visit, "instruction interrupted by signal");
    thread.pending = Pending{};
  }
  flush_decompiled_rows(current_machine(thread));

  siginfo_t snapshot{};
  const bool have_information =
      dr_get_signal_siginfo(information, &snapshot, sizeof(snapshot));
  // User-sent blocked faults can be reported again when unblocked. A blocked
  // synchronous fault, however, may terminate immediately without a second
  // delivery event, so its only notification must remain visible.
  if (information->blocked && have_information && snapshot.si_code <= 0)
    return DR_SIGNAL_DELIVER;

  close_trace_syscall(thread, "interrupted", "return=?");

  const app_pc pc = information->mcontext ? information->mcontext->pc : nullptr;
  if (have_information && pc && snapshot.si_code > 0 &&
      snapshot.si_code < SI_KERNEL) {
    const bool instruction_fault =
        snapshot.si_signo == SIGILL || snapshot.si_signo == SIGFPE ||
        (snapshot.si_signo == SIGTRAP &&
         (snapshot.si_code == TRAP_BRKPT || snapshot.si_code == TRAP_TRACE ||
          snapshot.si_code == TRAP_BRANCH || snapshot.si_code == TRAP_HWBKPT
#ifdef TRAP_UNK
          || snapshot.si_code == TRAP_UNK
#endif
          ));
    // These si_addr values identify the faulting instruction, whose original
    // kernel address can still be in DR's code cache at this callback. Do not
    // touch data-fault addresses, perf sample addresses, or sender/value
    // unions.
    if (instruction_fault)
      snapshot.si_addr = pc;
  }

  const std::string signal_description = ct_format_signal_info(
      information->sig, have_information ? &snapshot : nullptr);
  thread.signal_number = information->sig;
  thread.signal_description = signal_description;
  if (ct_perfetto_enabled())
    thread.trace_signal_timestamp = thread.trace_timestamp;
  // vDSO has no analysis Module, but its interrupted PC is still known to DR.
  // Retain delivery/context state without emitting an unknown-location row.
  if (vdso_address(pc))
    return DR_SIGNAL_DELIVER;

  std::string prefix;
  if (Module *module = module_at(pc)) {
    auto location = std::make_unique<ct_location>();
    ct_analysis_lookup_arming(module->analysis, pc - module->start,
                              location.get());
    const char *function =
        location->function[0] ? location->function : location->symbol;
    const TraceScope &scope =
        thread.calls.empty() ? thread.root_scope : thread.calls.back()->scope;
    const char *physical =
        location->scope_chain_size ? location->scope_chain : location->symbol;
    const auto &machine = current_machine(thread);
    if (scope.module.get() == module && scope.function == physical &&
        !machine.function_alias.empty())
      function = machine.function_alias.c_str();
    prefix = location_prefix(context, pc, *module, *location, function,
                             location->line);
  } else {
    char unknown[160];
    dr_snprintf(
        unknown, sizeof(unknown),
        "[tid %u] L%llx <unknown> <unknown>:? <unknown> | ",
        static_cast<unsigned>(dr_get_thread_id(context)),
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(pc)));
    prefix = unknown;
  }
  const size_t comment = prefix.size();
  if (ct_perfetto_enabled()) {
    const std::string signal_name = ct_signal_name(information->sig);
    ct_perfetto_instant(thread.trace_timestamp, signal_name.c_str(),
                        signal_description.c_str(),
                        reinterpret_cast<uint64_t>(pc));
  }
  prefix += "# /* " + signal_description + " */\n";
  write_line(prefix, comment, nullptr, -1, std::string::npos, nullptr, -1,
             nullptr, std::string::npos, 0, {}, nullptr, {},
             Notification::Signal);
  return DR_SIGNAL_DELIVER;
}

static void kernel_transfer(void *context, const dr_kernel_xfer_info_t *info) {
  QuietCallback quiet(context);
  if (traced_process() && info->type == DR_XFER_CLIENT_USERSPACE_GATE) {
    Thread &thread = *thread_state(context);
    if (!thread.recording) {
      thread.userspace_step_end = nullptr;
      if (duplicate_enabled)
        execution_mode() = 3;
      return;
    }
    quiet.allow_resume = !within_active();
    const bool copied = thread.userspace_copy_pending;
    if (copied && instrumentation_statistics)
      returned_userspace_versions[static_cast<unsigned>(
                                      thread.userspace_copy_level)]
          .fetch_add(1, std::memory_order_relaxed);
    if (ct_perfetto_enabled()) {
      ct_perfetto_userspace_span(
          true, copied
                    ? thread.userspace_copy_level == ct_instrument_level::full
                    : thread.userspace_step_end &&
                          thread.userspace_step_end == info->target_pc);
      ct_timing_discard(context);
      thread_state(context)->trace_timestamp =
          ct_perfetto_now(ct_timing_sample(context));
    }
    thread.userspace_step_end = nullptr;
    thread.userspace_copy_pending = false;
    if (duplicate_enabled && within_active())
      execution_mode() = 4;
    return;
  }
  if (!traced_process() || !recording_thread(context) ||
      (info->type != DR_XFER_SIGNAL_DELIVERY &&
       info->type != DR_XFER_SIGNAL_RETURN))
    return;
  Thread &thread = *thread_state(context);
  thread.userspace_copy_pending = false;
  if (ct_perfetto_enabled()) {
    ct_timing_kernel_end(context);
    ct_timing_discard(context);
    thread.trace_timestamp = ct_perfetto_now(ct_timing_sample(context));
    thread.trace_signal_timestamp = {};
  }
  Lock lock(analysis_lock);
  thread.assembly_arrival_pc = nullptr;
  thread.arrival_pc = nullptr;
  thread.arrival_outcome = -1;
  thread.annotation_pc = nullptr;
  thread.arrival_annotation = ArrivalAnnotation::None;
  if (info->type == DR_XFER_SIGNAL_DELIVERY) {
    close_trace_syscall(thread, "interrupted", "return=?");
    flush_machine_rows(current_machine(thread));
    if (info->source_mcontext) {
      app_pc pc = info->source_mcontext->pc;
      ct_registers registers = registers_at(info->source_mcontext, pc);
      if (thread.pending.site && thread.pending.site->instruction.pc == pc) {
        close_visit(*thread.pending.visit, "instruction interrupted by signal");
        thread.pending = Pending{};
      } else {
        advance(thread, registers, pc);
      }
    }
    flush_machine_rows(current_machine(thread));
    flush_decompiled_rows(current_machine(thread));
    current_machine(thread).comparison = {};
    thread.arrival_pc = nullptr;
    thread.arrival_outcome = -1;
    thread.annotation_pc = nullptr;
    thread.arrival_annotation = ArrivalAnnotation::None;
    // Interrupted calls can still return after the handler. Keep their
    // completion rows attached to their original frames until then.
    close_visit(thread.deferred_call, "signal interrupted call entry");
    auto *frame = new Call;
    frame->interrupted_syscall = std::move(thread.syscall);
    thread.syscall = {};
    frame->signal_frame = true;
    frame->signal_handler_active = true;
    frame->signal_number = info->sig;
    frame->entry_pc = info->target_pc;
    frame->entry_sp = info->target_xsp;
    frame->interrupted_sp =
        info->source_mcontext ? info->source_mcontext->xsp : 0;
    frame->return_pc =
        info->source_mcontext ? info->source_mcontext->pc : nullptr;
    // Context events remain visible independently of function/body filters.
    // The handler still evaluates its own step policy in this new frame.
    thread.calls.push_back(frame);
    update_within(thread);
    if (ct_perfetto_enabled()) {
      const std::string details =
          thread.signal_number == info->sig
              ? thread.signal_description
              : ct_format_signal_info(info->sig, nullptr);
      frame->trace_signal_context = begin_trace_context(
          thread, info->target_pc, "ctrace.signal",
          ("[" + ct_signal_name(info->sig) + "]").c_str(), details);
    }
  } else {
    close_trace_syscall(thread, "signal_return", "return=?");
    thread.syscall = {};
    thread.pending = Pending{};
    while (!thread.calls.empty()) {
      Call *frame = thread.calls.back();
      end_trace_function(frame->machine, thread.trace_timestamp,
                         "signal_return");
      close_deferred_call(*frame);
      flush_machine_rows(frame->machine);
      close_visit(frame->returning, "signal return");
      for (auto &exit : frame->block_exits)
        close_visit(exit, "signal return");
      for (const auto &line : frame->return_lines)
        write_line(line.text, std::string::npos, nullptr, -1, std::string::npos,
                   nullptr, -1, nullptr, std::string::npos, 0,
                   line.closing_context);
      close_visit(frame->visit,
                  frame->signal_frame ? nullptr : "signal return");
      close_plt(frame->machine, frame->visit);
      close_machine_blocks(frame->machine);
      close_blocks(frame->blocks, 0, "signal return");
      close_assembly_function(*frame);
      close_visit(frame->summary, "signal return");
      for (auto &tail : frame->tail_summaries)
        close_visit(tail.visit, "signal return");
      flush_decompiled_rows(frame->machine);
      bool done = frame->signal_frame;
      if (done) {
        ct_perfetto_end(frame->trace_signal_context, thread.trace_timestamp,
                        "signal_return");
        thread.syscall = std::move(frame->interrupted_syscall);
      }
      thread.calls.pop_back();
      delete frame;
      if (done)
        break;
    }
    current_machine(thread).comparison = {};
    close_visit(thread.deferred_call, "signal return");
    update_within(thread);
  }
}

static void finish() {
  // The exit event belongs to the whole address space, even when its final
  // task is a CLONE_VM child whose original owner has already exited.
  const bool owns_descriptors = ct_analysis_object_owner() != 0;
  ct_dr_shared_service(dr_get_current_drcontext(), true);
  thread_exit(dr_get_current_drcontext());
  if (instrumentation_statistics && ct_output_trace_enabled()) {
    for (const auto &module : modules)
      for (const auto &[key, state] : module->initial_preparations)
        if (module->active && state.generation == module->code_generation &&
            state.status != InitialPreparationState::Ready) {
          const auto function = current_functions.find(key.first);
          ct_output_printf("ctrace initial pending: module=%s function=%s "
                           "level=%s reason=%s\n",
                           module->path.c_str(),
                           function == current_functions.end()
                               ? "?"
                               : function->second->name.c_str(),
                           ct_instrument_level_name(key.second),
                           state.reason.empty() ? "request not completed"
                                                : state.reason.c_str());
        }
    const uint64_t created = Site::created.load(std::memory_order_relaxed);
    const uint64_t reclaimed = Site::reclaimed.load(std::memory_order_relaxed);
    ct_output_printf(
        "ctrace site lifetime: created=%llu reclaimed=%llu retained=%llu\n",
        static_cast<unsigned long long>(created),
        static_cast<unsigned long long>(reclaimed),
        static_cast<unsigned long long>(created - reclaimed));
    ct_output_printf(
        "ctrace fork lifetime: vanished_threads_reclaimed=%llu\n",
        static_cast<unsigned long long>(
            fork_threads_reclaimed.load(std::memory_order_relaxed)));
    for (const auto &entry :
         {std::make_tuple("module", Module::created.load(),
                          Module::reclaimed.load()),
          std::make_tuple("function", Function::created.load(),
                          Function::reclaimed.load())})
      ct_output_printf(
          "ctrace %s lifetime: created=%llu reclaimed=%llu retained=%llu\n",
          std::get<0>(entry),
          static_cast<unsigned long long>(std::get<1>(entry)),
          static_cast<unsigned long long>(std::get<2>(entry)),
          static_cast<unsigned long long>(std::get<1>(entry) -
                                          std::get<2>(entry)));
    ct_output_printf("ctrace userspace gate tokens: retained=%zu\n",
                     userspace_attempt_tokens.size());
    for (unsigned index = 0; index < 3; ++index)
      ct_output_printf(
          "ctrace instrumentation stats: level=%s generated=%llu "
          "executed=%llu\n",
          ct_instrument_level_name(static_cast<ct_instrument_level>(index)),
          static_cast<unsigned long long>(generated_versions[index].load()),
          static_cast<unsigned long long>(executed_versions[index].load()));
    for (unsigned index = 0; index < 3; ++index)
      ct_output_printf(
          "ctrace userspace stats: level=%s generated=%llu returned=%llu\n",
          ct_instrument_level_name(static_cast<ct_instrument_level>(index)),
          static_cast<unsigned long long>(
              generated_userspace_versions[index].load()),
          static_cast<unsigned long long>(
              returned_userspace_versions[index].load()));
    for (unsigned index = 0; index < 3; ++index)
      ct_output_printf(
          "ctrace userspace cache: level=%s restored=%llu common_restored=%llu "
          "decoded_instructions=%llu\n",
          ct_instrument_level_name(static_cast<ct_instrument_level>(index)),
          static_cast<unsigned long long>(
              restored_userspace_templates[index].load()),
          static_cast<unsigned long long>(
              restored_userspace_common[index].load()),
          static_cast<unsigned long long>(
              decoded_userspace_instructions[index].load()));
    for (unsigned index = 0; index < 3; ++index)
      ct_output_printf(
          "ctrace userspace sharing: level=%s published=%llu restored=%llu "
          "fallbacks=%llu\n",
          ct_instrument_level_name(static_cast<ct_instrument_level>(index)),
          static_cast<unsigned long long>(
              published_shared_versions[index].load()),
          static_cast<unsigned long long>(
              restored_shared_versions[index].load()),
          static_cast<unsigned long long>(
              shared_version_fallbacks[index].load()));
    for (const auto &entry : userspace_version_fallbacks)
      ct_output_printf(
          "ctrace userspace fallback: level=%s count=%llu reason=%s\n",
          ct_instrument_level_name(entry.first.first),
          static_cast<unsigned long long>(entry.second),
          entry.first.second.c_str());
    size_t retained_versions = 0, retired_versions = 0, retained_bytes = 0;
    for (const auto &module : modules) {
      for (const auto &entry : module->userspace_versions)
        if (entry.second.code) {
          ++retained_versions;
          retained_bytes += ct_userspace_version_size(entry.second.code);
        }
      for (const auto *code : module->retired_userspace_versions) {
        ++retired_versions;
        retained_bytes += ct_userspace_version_size(code);
      }
    }
    ct_output_printf(
        "ctrace userspace lifetime: reclaimed=%llu retained=%zu retired=%zu "
        "retained_bytes=%zu\n",
        static_cast<unsigned long long>(reclaimed_userspace_versions),
        retained_versions, retired_versions, retained_bytes);
    ct_output_printf(
        "ctrace lazy stats: detailed_fragments=%llu "
        "prehit_detailed_fragments=%llu userspace_graphs=%llu "
        "prehit_userspace_graphs=%llu\n",
        static_cast<unsigned long long>(detailed_fragments.load()),
        static_cast<unsigned long long>(prehit_detailed_fragments.load()),
        static_cast<unsigned long long>(userspace_graphs_prepared.load()),
        static_cast<unsigned long long>(prehit_userspace_graphs.load()));
  }
  ct_perfetto_exit();
  if (duplicate_enabled) {
    dr_register_userspace_gate_target(nullptr);
    dr_register_userspace_gate_decoder(nullptr);
    ct_userspace_patch_exit();
  }
  {
    Lock lock(analysis_lock);
    current_sites.clear();
    current_functions.clear();
    for (auto &module : modules) {
      for (auto &entry : module->userspace_versions)
        if (entry.second.code &&
            !ct_userspace_version_discard(entry.second.code))
          fail("cannot release userspace execution version");
      for (auto *code : module->retired_userspace_versions)
        if (!ct_userspace_version_discard(code))
          fail("cannot release retired userspace execution version");
      module->userspace_versions.clear();
      module->retired_userspace_versions.clear();
    }
    if (!version_preparations.empty() || !ct_userspace_version_exit())
      fail("userspace execution versions remain active during exit");
  }
  // Every RX mapping is now gone. A temporary image-owned channel can release
  // the views even after their original producer threads have exited.
  if (owns_descriptors && (!shared_userspace_versions.empty() ||
                           !released_shared_versions.empty())) {
    if (auto *channel = ct_shared_open()) {
      for (const auto &entry : shared_userspace_versions)
        ct_shared_release(channel, entry.second);
      for (uint64_t object : released_shared_versions)
        ct_shared_release(channel, object);
      ct_shared_close(channel);
    }
  }
  shared_userspace_versions.clear();
  released_shared_versions.clear();
  if (!ct_dr_shared_exit(dr_get_current_drcontext()))
    fail("shared DR service remains active during exit");
  {
    Lock lock(analysis_lock);
    functions.clear();
    modules.clear();
  }
  ct_analysis_disconnect();
  drmgr_unregister_bb_instru2instru_event(insert_breakpoint_resumes);
  drwrap_exit();
  if (duplicate_enabled) {
    drbbdup_exit();
    drreg_exit();
    dr_raw_tls_cfree(within_tls_offset, 2);
  }
  userspace_attempt_tokens.clear();
  ct_timing_exit();
  drmgr_unregister_tls_field(tls_index);
  drmgr_exit();
  dr_mutex_destroy(analysis_lock);
  dr_mutex_destroy(module_hook_lock);
  dr_mutex_destroy(display_lock);
  ct_output_exit(owns_descriptors);
}

DR_EXPORT void dr_client_main(client_id_t, int argc, const char *argv[]) {
  int output_fd = -1;
  for (int index = 1; index + 1 < argc; ++index)
    if (strcmp(argv[index], "--output-fd") == 0)
      output_fd = atoi(argv[++index]);
  if (!ct_output_init(output_fd))
    dr_abort();
  display_lock = dr_mutex_create();
  if (!display_lock)
    dr_abort();
  instrumentation_statistics = std::getenv("CTRACE_LAZY_STATS") != nullptr;
  program_name = dr_get_application_name();
  dr_app_arg_t argument{};
  if (dr_get_app_args(&argument, 1) == 1 && argument.size < SIZE_MAX) {
    std::vector<char> text(argument.size + 1, '\0');
    const char *value = dr_app_arg_as_cstring(&argument, nullptr, 0);
    if (value && dr_safe_read(value, argument.size, text.data(), nullptr))
      program_name = text.data();
  }
  const size_t separator = program_name.rfind('/');
  if (separator != std::string::npos)
    program_name.erase(0, separator + 1);
  for (char &ch : program_name)
    if (static_cast<unsigned char>(ch) < 0x20 || ch == '\x7f')
      ch = '?';
  int analysis_fd = -1;
  bool perfetto_requested = false, perfetto_only = false;
  bool skip_source_checksum = false;
  std::vector<std::string> into_patterns, over_patterns, recurse_patterns,
      within_patterns;
  for (int index = 1; index < argc; ++index) {
    if (strcmp(argv[index], "--skip-src-checksum") == 0) {
      skip_source_checksum = true;
      continue;
    }
    if (strcmp(argv[index], "--no-style") == 0) {
      no_style = true;
      continue;
    }
    if (strcmp(argv[index], "--perfetto") == 0) {
      perfetto_requested = true;
      continue;
    }
    if (strcmp(argv[index], "--perfetto-only") == 0) {
      perfetto_only = true;
      continue;
    }
    if (strcmp(argv[index], "--decompile") == 0) {
      decompile = true;
      continue;
    }
    if (strcmp(argv[index], "--follow-forks") == 0) {
      follow_forks = true;
      continue;
    }
    if (strcmp(argv[index], "--within-intr") == 0) {
      within_intr = true;
      continue;
    }
    if (strcmp(argv[index], "--within-init") == 0) {
      within_init = true;
      continue;
    }
    if (strcmp(argv[index], "--within-new-stack") == 0) {
      within_new_stack = true;
      continue;
    }
    if (index + 1 >= argc)
      fail("invalid internal client arguments");
    const char *option = argv[index++];
    if (strcmp(option, "--src-map") == 0)
      source_maps = argv[index];
    else if (strcmp(option, "--init-instrument") == 0) {
      if (strcmp(argv[index], "arm") == 0)
        initial_level = ct_instrument_level::arm;
      else if (strcmp(argv[index], "perfetto") == 0)
        initial_level = ct_instrument_level::perfetto;
      else if (strcmp(argv[index], "full") == 0)
        initial_level = ct_instrument_level::full;
      else
        fail("invalid initial instrumentation level");
    } else if (strcmp(option, "--output-fd") == 0) {
      no_style = true;
    } else if (strcmp(option, "--analysis-fd") == 0)
      analysis_fd = atoi(argv[index]);
    else if (strcmp(option, "--x86-syntax") == 0)
      syntax = strcmp(argv[index], "intel") == 0 ? 1 : 0;
    else if (strcmp(option, "--step-into") == 0)
      into_patterns.emplace_back(argv[index]);
    else if (strcmp(option, "--step-over") == 0)
      over_patterns.emplace_back(argv[index]);
    else if (strcmp(option, "--recurse-step-into") == 0)
      recurse_patterns.emplace_back(argv[index]);
    else if (strcmp(option, "--within") == 0)
      within_patterns.emplace_back(argv[index]);
    else
      fail("unknown internal client option");
  }
  if (perfetto_only && !perfetto_requested)
    fail("--perfetto-only requires --perfetto");
  ct_output_set_trace_enabled(!perfetto_only);
  filtered = !into_patterns.empty() || !over_patterns.empty() ||
             !recurse_patterns.empty();
  recursive_selection = !recurse_patterns.empty();
  within_patterns_enabled = !within_patterns.empty();
  within_enabled =
      within_patterns_enabled || within_intr || within_init || within_new_stack;
  // The DR gate selects FSGSBASE or arch_prctl once during runtime startup.
  // Both implementations preserve the same application context.
  // Initial preparation and per-thread scope selection are independent of
  // the supported TLS switch mechanism.
  duplicate_enabled = true;
  execution_policy =
      "execution-v7:" + source_maps + ":" + std::to_string(syntax) + ":" +
      std::to_string(skip_source_checksum) + ":" + std::to_string(decompile) +
      ":" + std::to_string(follow_forks) + ":" + std::to_string(within_intr) +
      ":" + std::to_string(within_init) + ":" +
      std::to_string(within_new_stack);
  for (const auto *patterns :
       {&within_patterns, &into_patterns, &over_patterns, &recurse_patterns}) {
    execution_policy += ":" + std::to_string(patterns->size());
    for (const auto &pattern : *patterns)
      execution_policy += ":" + std::to_string(pattern.size()) + ":" + pattern;
  }
  std::string filter_error;
  if (!into_filter.parse(into_patterns, filter_error) ||
      !over_filter.parse(over_patterns, filter_error) ||
      !recurse_filter.parse(recurse_patterns, filter_error) ||
      !within_filter.parse(within_patterns, filter_error))
    fail(filter_error.c_str());
  if (analysis_fd < 0 || !ct_analysis_connect(analysis_fd))
    fail("analysis connection unavailable");
  if (!dr_set_exec_resource_service(analysis_fd))
    fail("exec resource handoff unavailable");
  if (!dr_set_thread_suspend_service(analysis_fd))
    write_warning("Warning: thread suspension service unavailable; shared "
                  "address spaces with separate task groups cannot be "
                  "suspended safely\n");
  char runtime_identity[65]{};
  if (ct_analysis_runtime_identity(runtime_identity))
    shared_runtime_identity = runtime_identity;
  process_recording = follow_forks || ct_analysis_recording_allowed();
  initial_context.store(dr_get_current_drcontext(), std::memory_order_relaxed);
  ct_analysis_set_syntax(syntax);
  ct_analysis_set_source_bypass(skip_source_checksum);
  owner_pid = dr_get_process_id();
  ct_analysis_set_progress_callback(progress_notice, nullptr);
  analysis_lock = dr_mutex_create();
  module_hook_lock = dr_mutex_create();
  ct_userspace_version_init();
  if (!drmgr_init())
    fail("DynamoRIO extensions unavailable");
  if (duplicate_enabled && !ct_userspace_patch_init())
    fail("userspace execution patch registry unavailable");
  if (duplicate_enabled &&
      !dr_register_userspace_gate_decoder(ct_userspace_patch_original))
    fail("userspace execution original-instruction decoder unavailable");
  if (duplicate_enabled &&
      !dr_register_userspace_gate_target(ct_userspace_patch_target))
    fail("userspace execution relay address resolver unavailable");
  if (duplicate_enabled && !drwrap_set_global_flags(DRWRAP_INVERT_CONTROL))
    fail("within function wrapping unavailable");
  if (!drwrap_init())
    fail("DynamoRIO function wrapping unavailable");
  if (perfetto_requested && process_recording &&
      (!ct_timing_init() ||
       !ct_perfetto_init(ct_timing_frequency(), initial_level,
                         program_name.c_str())))
    fail("Perfetto trace timing initialization failed");
  if (!perfetto_requested && process_recording &&
      initial_level == ct_instrument_level::perfetto && !ct_timing_init())
    fail("initial Perfetto timing preparation unavailable");
  tls_index = drmgr_register_tls_field();
  if (tls_index < 0)
    fail("thread storage unavailable");
  if (!shared_runtime_identity.empty())
    shared_dr_enabled = ct_dr_shared_init(shared_dr_generation_current,
                                          shared_dr_generation_try_current);
  module_data_t *main = dr_get_main_module();
  if (!main)
    fail("main executable unavailable");
  main_start = main->start;
  drmgr_register_exit_event(finish);
  drmgr_register_thread_init_event(thread_init);
  drmgr_register_thread_exit_event(thread_exit);
  dr_register_fork_init_event(fork_child);
  dr_register_fork_prepare_event(fork_prepare);
  dr_register_fork_parent_event(fork_parent);
  drmgr_register_module_load_event(module_load);
  drmgr_register_module_unload_event(module_unload);
  dr_register_code_change_event(code_change);
  drmgr_register_signal_event(signal_event);
  drmgr_register_kernel_xfer_event(kernel_transfer);
  if ((duplicate_enabled || ct_perfetto_enabled()) &&
      (!drmgr_register_filter_syscall_event(filter_syscall) ||
       !drmgr_register_pre_syscall_event(pre_syscall) ||
       !drmgr_register_post_syscall_event(post_syscall)))
    fail("Perfetto syscall instrumentation unavailable");
  drmgr_priority_t priority = {sizeof(priority), "ctrace", nullptr, nullptr,
                               DRMGR_PRIORITY_INSERT_DRWRAP + 1};
  drmgr_priority_t timing_priority = {sizeof(timing_priority), "ctrace_timing",
                                      nullptr, nullptr,
                                      DRMGR_PRIORITY_INSERT_DRWRAP - 1};
  if (ct_perfetto_enabled() && !duplicate_enabled &&
      !drmgr_register_bb_instrumentation_event(nullptr, stop_timing,
                                               &timing_priority))
    fail("Perfetto timing instrumentation unavailable");
  if (duplicate_enabled) {
    drreg_options_t register_options{};
    register_options.struct_size = sizeof(register_options);
    register_options.num_spill_slots = 2;
    register_options.conservative = true;
    if (drreg_init(&register_options) != DRREG_SUCCESS)
      fail("userspace attempt guard register management unavailable");
    if (!dr_raw_tls_calloc(&within_tls_register, &within_tls_offset, 2, 0))
      fail("within thread storage unavailable");
    dispatch_tls_offset = within_tls_offset + sizeof(uintptr_t);
    drbbdup_options_t options{};
    options.struct_size = sizeof(options);
    options.set_up_bb_dups = setup_within_block;
    options.analyze_orig = analyze_execution_block;
    options.analyze_case = analyze_execution_case;
    options.insert_encode = encode_execution_version;
    options.destroy_orig_analysis = [](void *, void *, void *data) {
      delete static_cast<ExecutionBlock *>(data);
    };
    options.instrument_instr_ex = instrument_within;
    options.runtime_case_opnd = dr_raw_tls_opnd(
        dr_get_current_drcontext(), within_tls_register, dispatch_tls_offset);
    options.non_default_case_limit = follow_forks ? 4 : 5;
    options.max_case_encoding = 5;
    options.never_enable_dynamic_handling = true;
    options.preserve_app_context = true;
    if (drbbdup_init(&options) != DRBBDUP_SUCCESS)
      fail("within block duplication unavailable");
    execution_mode() = process_recording ? (within_enabled ? 0 : 1) : 3;
  } else if (!drmgr_register_bb_instrumentation_event(nullptr, instrument,
                                                      &priority)) {
    fail("instruction instrumentation unavailable");
  }
  drmgr_priority_t generation_priority = {
      sizeof(generation_priority), "ctrace_quiet_generation",
      duplicate_enabled ? DRMGR_PRIORITY_APP2APP_NAME_DRBBDUP : nullptr,
      nullptr, DRMGR_PRIORITY_APP2APP_DRBBDUP - 1};
  if (!drmgr_register_bb_app2app_event(begin_code_generation,
                                       &generation_priority))
    fail("original code generation callback unavailable");
  if (!drmgr_register_bb_instru2instru_event(insert_breakpoint_resumes,
                                             nullptr))
    fail("breakpoint translation unavailable");
  dr_free_module_data(main);
  discover_initial_modules(dr_get_current_drcontext());
}
