/* Bounded, read-only DWARF value interpreter. Not a C expression evaluator.
 * Unknown locations/opcodes/types stay unavailable: no register/stack guesses.
 * libdw reads metadata. Callbacks supply original application machine state.
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <gelf.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "analysis.h"
#include "values.h"
#define NVAR 256
#define NBYTE 256
#define NSTACK 64
#define MAX_OPS 512
#define MAX_DEPTH 64
#define PREPARED_CACHE_BUCKETS 257
#define MAX_VALUES_CACHE_BYTES 65536

typedef struct {
  char *name;
  Dwarf_Die die, type;
  bool have_type;
  bool global;
} variable;
typedef struct variable_set {
  variable *vars;
  size_t count;
  uint64_t hash;
  struct variable_set *next;
} variable_set;
typedef struct prepared_values {
  uint64_t pc;
  ct_values_site *site;
  ct_function *function;
  struct prepared_values *next;
} prepared_values;
typedef struct {
  uint64_t begin, end;
} module_range;
struct ct_values_module {
  uint64_t instance_id;
  Dwfl *session;
  Dwfl_Module *module;
  Dwarf *dw;
  Dwarf_CFI *eh;
  uint64_t bias, elf_bias;
  Elf *memory_elf;
  void *module_mapping, *debug_mapping;
  size_t module_size, debug_size;
  Dwarf *supplement_dw;
  Elf *supplement_elf;
  void *supplement_mapping;
  size_t supplement_size;
  char *debug_path;
  char *cache_identity;
  module_range *ranges;
  size_t range_count;
  prepared_values *prepared[PREPARED_CACHE_BUCKETS];
  variable_set *variables[PREPARED_CACHE_BUCKETS];
};
static _Atomic uint64_t next_module_instance;
struct ct_values_site {
  ct_values_module *module;
  uint64_t pc;
  variable *vars;
  size_t nvars;
  bool shared_variables;
  bool truncated;
  const char *error;
  Dwarf_Attribute frame;
  bool have_frame;
  Dwarf_Op *cfa;
  size_t ncfa;
  Dwarf_Die frame_die;
  size_t references;
};
typedef struct {
  Dwarf_Die die, type;
  char *name;
  size_t bytes;
  unsigned reg;
  uint64_t stack_offset;
  bool on_stack;
} parameter;
struct ct_function {
  ct_values_site site;
  Dwarf_Die declaration;
  parameter *parameters;
  size_t count;
  Dwarf_Die return_type;
  Dwarf_Op *return_ops;
  size_t return_count, return_bytes;
  const char *error, *argument_error, *return_error;
  bool is_void, variadic;
  size_t references;
};
typedef ct_value_buffer buffer;
static void put(buffer *b, const char *fmt, ...) {
  if (!b->size || b->used >= b->size - 1) {
    b->truncated = true;
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(b->p + b->used, b->size - b->used, fmt, ap);
  va_end(ap);
  if (n < 0)
    return;
  if ((size_t)n >= b->size - b->used) {
    b->used = b->size - 1;
    b->truncated = true;
  } else
    b->used += (size_t)n;
}
static Dwarf_Attribute *attr(Dwarf_Die *d, unsigned code, Dwarf_Attribute *a) {
  return dwarf_attr_integrate(d, code, a);
}
static bool uint_attr(Dwarf_Die *d, unsigned code, uint64_t *v) {
  Dwarf_Attribute a;
  Dwarf_Word w;
  if (!attr(d, code, &a) || dwarf_formudata(&a, &w) != 0)
    return false;
  *v = w;
  return true;
}
static bool bool_attr(Dwarf_Die *d, unsigned code) {
  Dwarf_Attribute a;
  bool v = false;
  return attr(d, code, &a) && dwarf_formflag(&a, &v) == 0 && v;
}
static bool type_of(Dwarf_Die *d, Dwarf_Die *t) {
  Dwarf_Attribute a;
  return attr(d, DW_AT_type, &a) && dwarf_formref_die(&a, t);
}
static const char *die_name(Dwarf_Die *d) {
  Dwarf_Attribute a;
  return attr(d, DW_AT_name, &a) ? dwarf_formstring(&a) : NULL;
}
static int find_debug_file(Dwfl_Module *module, void **userdata,
                           const char *module_name, Dwarf_Addr base,
                           const char *file_name, const char *debuglink_file,
                           GElf_Word debuglink_crc, char **file) {
  (void)module;
  (void)module_name;
  (void)base;
  (void)file_name;
  (void)debuglink_file;
  (void)debuglink_crc;
  const ct_values_module *m = *userdata;
  if (!m || !m->debug_path || !m->debug_path[0])
    return -1;
  /* The helper already validated build-ID/debuglink. Never invoke libdwfl's
   * debuginfod/dlopen path inside DynamoRIO's private loader. */
  int fd = open(m->debug_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  *file = strdup(m->debug_path);
  if (!*file) {
    close(fd);
    return -1;
  }
  return fd;
}

ct_values_module *ct_values_open(const char *path, uint64_t mapped_base,
                                 const char *debug_path) {
  static const Dwfl_Callbacks callbacks = {.find_debuginfo = find_debug_file};
  ct_values_module *m = calloc(1, sizeof(*m));
  if (!m)
    return NULL;
  m->instance_id = atomic_fetch_add_explicit(&next_module_instance, 1,
                                             memory_order_relaxed) +
                   1;
  if (debug_path && debug_path[0]) {
    m->debug_path = strdup(debug_path);
    if (!m->debug_path) {
      ct_values_close(m);
      return NULL;
    }
  }
  m->session = dwfl_begin(&callbacks);
  if (!m->session) {
    ct_values_close(m);
    return NULL;
  }
  m->module = dwfl_report_elf(m->session, path, path, -1, mapped_base, false);
  if (!m->module || dwfl_report_end(m->session, NULL, NULL) != 0) {
    ct_values_close(m);
    return NULL;
  }
  void **userdata;
  dwfl_module_info(m->module, &userdata, NULL, NULL, NULL, NULL, NULL, NULL);
  *userdata = m;
  GElf_Addr bias;
  GElf_Ehdr header;
  Elf *elf = dwfl_module_getelf(m->module, &bias);
  if (!elf || !gelf_getehdr(elf, &header) || gelf_getclass(elf) != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64) {
    ct_values_close(m);
    return NULL;
  }
  Dwarf_Addr dwarf_bias;
  m->dw = dwfl_module_getdwarf(m->module, &dwarf_bias);
  m->bias = m->dw ? dwarf_bias : bias;
  m->elf_bias = bias;
  size_t headers;
  if (elf_getphdrnum(elf, &headers) == 0 &&
      headers <= SIZE_MAX / sizeof(*m->ranges)) {
    m->ranges = calloc(headers, sizeof(*m->ranges));
    if (m->ranges)
      for (size_t index = 0; index < headers; ++index) {
        GElf_Phdr segment;
        if (gelf_getphdr(elf, index, &segment) && segment.p_type == PT_LOAD &&
            segment.p_memsz && segment.p_vaddr <= UINT64_MAX - segment.p_memsz)
          m->ranges[m->range_count++] = (module_range){
              segment.p_vaddr, segment.p_vaddr + segment.p_memsz};
      }
  }
  if (m->dw)
    m->eh = dwarf_getcfi_elf(elf);
  return m;
}

static bool map_values_file(int fd, void **mapping, size_t *size) {
  struct stat status;
  const int seals = fcntl(fd, F_GET_SEALS);
  const int required = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
  if (seals < 0 || (seals & required) != required || fstat(fd, &status) != 0 ||
      !S_ISREG(status.st_mode) || status.st_size <= 0 ||
      (uintmax_t)status.st_size > SIZE_MAX)
    return false;
  void *bytes =
      mmap(NULL, (size_t)status.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (bytes == MAP_FAILED)
    return false;
  const size_t length = (size_t)status.st_size;
  Elf64_Ehdr header;
  if (length < sizeof(header)) {
    munmap(bytes, length);
    return false;
  }
  memcpy(&header, bytes, sizeof(header));
  if (memcmp(header.e_ident, ELFMAG, SELFMAG) ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_ident[EI_VERSION] != EV_CURRENT ||
      header.e_ehsize != sizeof(header)) {
    munmap(bytes, length);
    return false;
  }
  Elf64_Shdr first = {0};
  uint64_t sections = header.e_shnum;
  if (header.e_shoff) {
    if (header.e_shoff < sizeof(header) ||
        header.e_shentsize != sizeof(first) || header.e_shoff > length ||
        sizeof(first) > length - header.e_shoff ||
        header.e_shnum >= SHN_LORESERVE) {
      munmap(bytes, length);
      return false;
    }
    memcpy(&first, (const char *)bytes + header.e_shoff, sizeof(first));
    if (!sections)
      sections = first.sh_size;
    const uint64_t strings =
        header.e_shstrndx == SHN_XINDEX ? first.sh_link : header.e_shstrndx;
    if (!sections || sections > (length - header.e_shoff) / sizeof(first) ||
        strings >= sections) {
      munmap(bytes, length);
      return false;
    }
  } else if (sections || header.e_shstrndx != SHN_UNDEF ||
             header.e_phnum == PN_XNUM) {
    munmap(bytes, length);
    return false;
  }
  const uint64_t programs =
      header.e_phnum == PN_XNUM ? first.sh_info : header.e_phnum;
  if (programs &&
      (header.e_phoff < sizeof(header) ||
       header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phoff > length ||
       programs > (length - header.e_phoff) / sizeof(Elf64_Phdr))) {
    munmap(bytes, length);
    return false;
  }
  // elf_memory borrows section headers directly. Decompression changes their
  // size/flags, so only metadata pages may become private writable copies.
  // Untouched file-backed pages remain physically shared and read-only.
  const long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0 ||
      mprotect(bytes, sizeof(header), PROT_READ | PROT_WRITE) != 0) {
    munmap(bytes, length);
    return false;
  }
  if (sections) {
    const uint64_t begin = header.e_shoff / (uint64_t)page_size * page_size;
    const uint64_t end = header.e_shoff + sections * sizeof(first);
    if (mprotect((char *)bytes + begin, (size_t)(end - begin),
                 PROT_READ | PROT_WRITE) != 0) {
      munmap(bytes, length);
      return false;
    }
  }
  *mapping = bytes;
  *size = length;
  return true;
}

static int no_debug_file(Dwfl_Module *module, void **userdata,
                         const char *module_name, Dwarf_Addr base,
                         const char *file_name, const char *debuglink_file,
                         GElf_Word debuglink_crc, char **file) {
  (void)module;
  (void)userdata;
  (void)module_name;
  (void)base;
  (void)file_name;
  (void)debuglink_file;
  (void)debuglink_crc;
  *file = NULL;
  return -1;
}

ct_values_module *ct_values_open_fd(const char *path, uint64_t mapped_base,
                                    int module_fd, int debug_fd,
                                    int64_t dwarf_bias_correction) {
  static const Dwfl_Callbacks callbacks = {.find_debuginfo = no_debug_file};
  ct_values_module *m = calloc(1, sizeof(*m));
  if (!m)
    return NULL;
  m->instance_id = atomic_fetch_add_explicit(&next_module_instance, 1,
                                             memory_order_relaxed) +
                   1;
  if (elf_version(EV_CURRENT) == EV_NONE ||
      !map_values_file(module_fd, &m->module_mapping, &m->module_size) ||
      (debug_fd >= 0 &&
       !map_values_file(debug_fd, &m->debug_mapping, &m->debug_size))) {
    ct_values_close(m);
    return NULL;
  }
  m->memory_elf = elf_memory(m->module_mapping, m->module_size);
  GElf_Ehdr header;
  if (!m->memory_elf || !gelf_getehdr(m->memory_elf, &header) ||
      gelf_getclass(m->memory_elf) != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 ||
      (header.e_type != ET_EXEC && header.e_type != ET_DYN)) {
    ct_values_close(m);
    return NULL;
  }
  size_t headers;
  if (elf_getphdrnum(m->memory_elf, &headers) != 0 || !headers ||
      headers > SIZE_MAX / sizeof(*m->ranges) ||
      !(m->ranges = calloc(headers, sizeof(*m->ranges)))) {
    ct_values_close(m);
    return NULL;
  }
  uint64_t link_base = 0;
  bool have_base = false;
  for (size_t index = 0; index < headers; ++index) {
    GElf_Phdr segment;
    if (!gelf_getphdr(m->memory_elf, index, &segment)) {
      ct_values_close(m);
      return NULL;
    }
    if (segment.p_type != PT_LOAD)
      continue;
    if (segment.p_vaddr > UINT64_MAX - segment.p_memsz ||
        (segment.p_align && (segment.p_align & (segment.p_align - 1)))) {
      ct_values_close(m);
      return NULL;
    }
    if (!have_base) {
      link_base = segment.p_align > 1 ? segment.p_vaddr & ~(segment.p_align - 1)
                                      : segment.p_vaddr;
      have_base = true;
    }
    if (segment.p_memsz)
      m->ranges[m->range_count++] =
          (module_range){segment.p_vaddr, segment.p_vaddr + segment.p_memsz};
  }
  if (!have_base || !m->range_count) {
    ct_values_close(m);
    return NULL;
  }
  // Match dwfl_report_elf(..., add_p_vaddr=false): ET_EXEC ignores BASE;
  // ET_DYN places its first load segment at BASE, including prelinked files.
  m->elf_bias = header.e_type == ET_EXEC ? 0 : mapped_base - link_base;
  m->bias = m->elf_bias + (uint64_t)dwarf_bias_correction;
  m->session = dwfl_begin(&callbacks);
  if (!m->session) {
    ct_values_close(m);
    return NULL;
  }
  // Report the selected DWARF image itself so its DIEs and return-value ABI
  // belong to the same DWFL module. The main image remains separately mapped
  // for EH CFI and its load ranges. No descriptor is owned by either Elf.
  void *bytes = m->debug_mapping ? m->debug_mapping : m->module_mapping;
  const size_t size = m->debug_mapping ? m->debug_size : m->module_size;
  const char *name = path && path[0] ? path : "ctrace sealed image";
  m->module = dwfl_report_offline_memory(m->session, name, name, bytes, size);
  if (!m->module || dwfl_report_end(m->session, NULL, NULL) != 0) {
    ct_values_close(m);
    return NULL;
  }
  GElf_Addr ignored_bias;
  Elf *selected = dwfl_module_getelf(m->module, &ignored_bias);
  GElf_Ehdr debug_header;
  if (!selected || !gelf_getehdr(selected, &debug_header) ||
      gelf_getclass(selected) != ELFCLASS64 ||
      debug_header.e_ident[EI_DATA] != ELFDATA2LSB ||
      debug_header.e_machine != header.e_machine ||
      debug_header.e_type != header.e_type) {
    ct_values_close(m);
    return NULL;
  }
  Dwarf_Addr ignored_dwarf_bias;
  m->dw = dwfl_module_getdwarf(m->module, &ignored_dwarf_bias);
  if (m->dw)
    m->eh = dwarf_getcfi_elf(m->memory_elf);
  return m;
}

bool ct_values_set_supplement_fd(ct_values_module *m, int fd) {
  if (!m || !m->dw || m->supplement_dw)
    return false;
  // libdw requires this association before any alternate FORM is resolved.
  // Prepared DIEs and types must never outlive or change their supplementary
  // session, so attaching/replacing it after value preparation is forbidden.
  for (size_t bucket = 0; bucket < PREPARED_CACHE_BUCKETS; ++bucket)
    if (m->prepared[bucket])
      return false;
  void *mapping = NULL;
  size_t size = 0;
  if (!map_values_file(fd, &mapping, &size))
    return false;
  Elf *elf = elf_memory(mapping, size);
  Dwarf *dw = elf ? dwarf_begin_elf(elf, DWARF_C_READ, NULL) : NULL;
  if (!dw) {
    if (elf)
      elf_end(elf);
    munmap(mapping, size);
    return false;
  }
  // Identity was checked by the helper against the selected main/debug image.
  // Keep these pages and both handles until after the referring session ends.
  dwarf_setalt(m->dw, dw);
  m->supplement_dw = dw;
  m->supplement_elf = elf;
  m->supplement_mapping = mapping;
  m->supplement_size = size;
  return true;
}

void ct_values_close(ct_values_module *m) {
  if (!m)
    return;
  for (size_t bucket = 0; bucket < PREPARED_CACHE_BUCKETS; ++bucket) {
    prepared_values *entry = m->prepared[bucket];
    while (entry) {
      prepared_values *next = entry->next;
      ct_values_site_free(entry->site);
      ct_function_free(entry->function);
      free(entry);
      entry = next;
    }
    variable_set *variables = m->variables[bucket];
    while (variables) {
      variable_set *next = variables->next;
      for (size_t index = 0; index < variables->count; ++index)
        free(variables->vars[index].name);
      free(variables->vars);
      free(variables);
      variables = next;
    }
  }
  free(m->cache_identity);
  free(m->ranges);
  if (m->eh)
    dwarf_cfi_end(m->eh);
  if (m->session)
    dwfl_end(m->session);
  if (m->supplement_dw)
    dwarf_end(m->supplement_dw);
  if (m->supplement_elf)
    elf_end(m->supplement_elf);
  if (m->supplement_mapping)
    munmap(m->supplement_mapping, m->supplement_size);
  if (m->memory_elf)
    elf_end(m->memory_elf);
  if (m->debug_mapping)
    munmap(m->debug_mapping, m->debug_size);
  if (m->module_mapping)
    munmap(m->module_mapping, m->module_size);
  free(m->debug_path);
  free(m);
}
void ct_values_set_cache_identity(ct_values_module *m, const char *identity) {
  if (!m)
    return;
  free(m->cache_identity);
  m->cache_identity = identity && identity[0] ? strdup(identity) : NULL;
}

static prepared_values *prepared_at(ct_values_module *m, uint64_t pc) {
  size_t bucket = pc % PREPARED_CACHE_BUCKETS;
  for (prepared_values *entry = m->prepared[bucket]; entry; entry = entry->next)
    if (entry->pc == pc)
      return entry;
  prepared_values *entry = calloc(1, sizeof(*entry));
  if (!entry)
    return NULL;
  entry->pc = pc;
  entry->next = m->prepared[bucket];
  m->prepared[bucket] = entry;
  return entry;
}

static char *prepared_key(ct_values_module *m, uint64_t pc) {
  bool in_module = false;
  const uint64_t link_pc = pc + (m->bias - m->elf_bias);
  for (size_t index = 0; index < m->range_count; ++index)
    if (link_pc >= m->ranges[index].begin && link_pc < m->ranges[index].end) {
      in_module = true;
      break;
    }
  /* A caller's next PC can already belong to another module after a return.
   * Such requests remain RAM-only: their relative PC changes with ASLR. */
  if (!in_module)
    return NULL;
  char *key = NULL;
  if (!m->cache_identity ||
      asprintf(&key, "%s-%" PRIx64, m->cache_identity, pc) < 0)
    return NULL;
  return key;
}

/* Disk recipes contain only little-endian integers and offsets in this exact
 * debug object. libdw handles, relocated PCs, register values and pointers
 * into mapped DWARF sections are never written to disk. */
typedef struct {
  unsigned char *data;
  size_t size, position;
  bool valid;
} values_cache;

static void cache_put(values_cache *cache, uint64_t value) {
  if (!cache->valid || cache->position > cache->size ||
      cache->size - cache->position < 8) {
    cache->valid = false;
    return;
  }
  for (unsigned byte = 0; byte < 8; ++byte)
    cache->data[cache->position++] = (unsigned char)(value >> (byte * 8));
}

static uint64_t cache_get(values_cache *cache) {
  if (!cache->valid || cache->position > cache->size ||
      cache->size - cache->position < 8) {
    cache->valid = false;
    return 0;
  }
  uint64_t value = 0;
  for (unsigned byte = 0; byte < 8; ++byte)
    value |= (uint64_t)cache->data[cache->position++] << (byte * 8);
  return value;
}

static void cache_put_die(values_cache *cache, ct_values_module *m,
                          Dwarf_Die *die) {
  if (!die->addr) {
    cache_put(cache, 0);
    cache_put(cache, 0);
    return;
  }
  Dwarf_Die restored;
  Dwarf_Off offset = dwarf_dieoffset(die);
  if (dwarf_cu_getdwarf(die->cu) != m->dw) {
    cache->valid = false; /* Alternate/split debug ownership is not guessed. */
    return;
  }
  bool info =
      dwarf_offdie(m->dw, offset, &restored) && restored.addr == die->addr;
  if (!info && (!dwarf_offdie_types(m->dw, offset, &restored) ||
                restored.addr != die->addr)) {
    cache->valid = false;
    return;
  }
  cache_put(cache, info ? 1 : 2);
  cache_put(cache, offset);
}

static bool cache_get_die(values_cache *cache, ct_values_module *m,
                          Dwarf_Die *die) {
  uint64_t section = cache_get(cache), offset = cache_get(cache);
  *die = (Dwarf_Die){0};
  if (!cache->valid || section > 2 || (!section && offset)) {
    cache->valid = false;
    return false;
  }
  if (!section)
    return true;
  if (!(section == 1 ? dwarf_offdie(m->dw, offset, die)
                     : dwarf_offdie_types(m->dw, offset, die))) {
    cache->valid = false;
    return false;
  }
  return true;
}

static bool portable_operation(unsigned atom) {
  if ((atom >= DW_OP_lit0 && atom <= DW_OP_breg31) ||
      (atom >= DW_OP_const1u && atom <= DW_OP_rot) ||
      (atom >= DW_OP_abs && atom <= DW_OP_skip))
    return true;
  switch (atom) {
  case DW_OP_addr:
  case DW_OP_deref:
  case DW_OP_regx:
  case DW_OP_fbreg:
  case DW_OP_bregx:
  case DW_OP_piece:
  case DW_OP_deref_size:
  case DW_OP_nop:
  case DW_OP_bit_piece:
  case DW_OP_call_frame_cfa:
  case DW_OP_stack_value:
    return true;
  default:
    return false;
  }
}

static void cache_put_operations(values_cache *cache, const Dwarf_Op *ops,
                                 size_t count) {
  cache_put(cache, count);
  for (size_t index = 0; index < count; ++index) {
    if (!portable_operation(ops[index].atom)) {
      cache->valid = false;
      return;
    }
    cache_put(cache, ops[index].atom);
    cache_put(cache, ops[index].number);
    cache_put(cache, ops[index].number2);
    cache_put(cache, ops[index].offset);
  }
}

static bool cache_get_operations(values_cache *cache, Dwarf_Op **ops,
                                 size_t *count) {
  uint64_t length = cache_get(cache);
  if (!cache->valid || length > MAX_OPS ||
      length > (cache->size - cache->position) / 32) {
    cache->valid = false;
    return false;
  }
  *ops = length ? calloc(length, sizeof(**ops)) : NULL;
  *count = length;
  if (length && !*ops) {
    cache->valid = false;
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    uint64_t atom = cache_get(cache);
    if (atom > UINT8_MAX || !portable_operation((unsigned)atom)) {
      cache->valid = false;
      return false;
    }
    (*ops)[index] = (Dwarf_Op){.atom = atom,
                               .number = cache_get(cache),
                               .number2 = cache_get(cache),
                               .offset = cache_get(cache)};
  }
  return cache->valid;
}

static bool find_cu(ct_values_module *m, uint64_t pc, Dwarf_Die *cu) {
  if (dwarf_addrdie(m->dw, pc, cu))
    return true;
  /* Clang and some linkers omit .debug_aranges. */
  Dwarf_Off off = 0, next;
  size_t hdr;
  while (dwarf_nextcu(m->dw, off, &next, &hdr, NULL, NULL, NULL) == 0) {
    if (dwarf_offdie(m->dw, off + hdr, cu)) {
      if (dwarf_haspc(cu, pc) == 1)
        return true;
      Dwarf_Die *scopes = NULL;
      int n = dwarf_getscopes(cu, pc, &scopes);
      free(scopes);
      if (n > 1)
        return true;
    }
    if (next <= off)
      break;
    off = next;
  }
  return false;
}

typedef struct {
  Dwarf_Addr pc;
  Dwarf_Die function;
  bool found, ambiguous;
} scope_query;

static int match_function(Dwarf_Die *function, void *argument) {
  scope_query *query = argument;
  if (dwarf_haspc(function, query->pc) != 1)
    return DWARF_CB_OK;
  if (query->found) {
    query->ambiguous = true;
    return DWARF_CB_ABORT;
  }
  query->function = *function;
  query->found = true;
  return DWARF_CB_OK;
}

static int find_scopes(Dwarf_Die *cu, Dwarf_Addr pc, Dwarf_Die **scopes) {
  int count = dwarf_getscopes(cu, pc, scopes);
  if (count != 0)
    return count;
  /* libdw's PC lookup can skip namespace-contained subprograms. Its function
   * walker and DIE-parent lookup still see them; retain their real scopes. */
  scope_query query = {.pc = pc};
  if (dwarf_getfuncs(cu, match_function, &query, 0) < 0 || !query.found ||
      query.ambiguous)
    return 0;
  Dwarf_Die scope = query.function;
  for (unsigned depth = 0; depth < 64; ++depth) { /* Bound malformed nesting. */
    Dwarf_Die child, inner;
    bool found = false;
    if (dwarf_child(&scope, &child) == 0)
      do {
        int tag = dwarf_tag(&child);
        if ((tag != DW_TAG_lexical_block && tag != DW_TAG_inlined_subroutine &&
             tag != DW_TAG_try_block && tag != DW_TAG_catch_block &&
             tag != DW_TAG_with_stmt) ||
            dwarf_haspc(&child, pc) != 1)
          continue;
        if (found)
          return 0;
        inner = child;
        found = true;
      } while (dwarf_siblingof(&child, &child) == 0);
    if (!found)
      return dwarf_getscopes_die(&scope, scopes);
    scope = inner;
  }
  return 0;
}

static void add_variable(ct_values_site *s, Dwarf_Die *d, bool global) {
  const char *name = die_name(d);
  if (!name || !name[0] || bool_attr(d, DW_AT_declaration))
    return;
  for (size_t i = 0; i < s->nvars; i++)
    if (!strcmp(s->vars[i].name, name))
      return;
  if (s->nvars == NVAR) {
    s->truncated = true;
    return;
  }
  variable *v = &s->vars[s->nvars];
  v->name = strdup(name);
  if (!v->name) {
    s->error = "allocation failed";
    return;
  }
  /* Keep output one physical line even for unusual DWARF names. */
  for (char *p = v->name; *p; p++)
    if ((unsigned char)*p < 32)
      *p = '?';
  v->die = *d;
  v->have_type = type_of(d, &v->type);
  v->global = global;
  s->nvars++;
}
static ct_values_site *prepare_values(ct_values_module *m,
                                      uint64_t runtime_pc) {
  ct_values_site *s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;
  s->module = m;
  if (!m || !m->dw) {
    s->error = "DWARF variable information unavailable";
    return s;
  }
  s->pc = runtime_pc - m->bias;
  Dwarf_Die cu, *scopes = NULL;
  if (!find_cu(m, s->pc, &cu)) {
    s->error = "no DWARF scope at PC";
    return s;
  }
  int n = find_scopes(&cu, s->pc, &scopes);
  if (n <= 0) {
    free(scopes);
    s->error = "no DWARF scope at PC";
    return s;
  }
  s->vars = calloc(NVAR, sizeof(variable));
  if (!s->vars) {
    free(scopes);
    s->error = "allocation failed";
    return s;
  }
  /* Frame base belongs to the physical function, even within inline scopes. */
  for (int i = 0; i < n; i++) {
    if (dwarf_tag(&scopes[i]) == DW_TAG_subprogram &&
        attr(&scopes[i], DW_AT_frame_base, &s->frame)) {
      s->have_frame = true;
      s->frame_die = scopes[i];
      break;
    }
  }
  /* Only the current source function and its enclosing lexical blocks.
   * Do not pretend inlined caller locals or all globals are current locals. */
  for (int i = 0; i < n; i++) {
    int tag = dwarf_tag(&scopes[i]);
    if (tag == DW_TAG_compile_unit || tag == DW_TAG_namespace)
      break;
    Dwarf_Die d;
    if (dwarf_child(&scopes[i], &d) == 0)
      do {
        int t = dwarf_tag(&d);
        if (t == DW_TAG_variable || t == DW_TAG_formal_parameter)
          add_variable(s, &d, false);
      } while (dwarf_siblingof(&d, &d) == 0);
    if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine)
      break;
  }
  /* File-scope variables are children of the compile unit rather than the
   * active function scope. Include them so source expressions such as
   * `a + b + global_value` can show the global operand when its DWARF location
   * is readable. */
  Dwarf_Die global;
  if (dwarf_child(&cu, &global) == 0)
    do {
      Dwarf_Attribute global_location;
      if (dwarf_tag(&global) == DW_TAG_variable &&
          attr(&global, DW_AT_location, &global_location))
        add_variable(s, &global, true);
    } while (dwarf_siblingof(&global, &global) == 0);
  free(scopes);
  Dwarf_CFI *cfis[2] = {m->eh, dwarf_getcfi(m->dw)};
  for (int i = 0; i < 2; i++) {
    Dwarf_Frame *f = NULL;
    Dwarf_Op *ops = NULL;
    size_t count = 0;
    const uint64_t pc = i ? s->pc : runtime_pc - m->elf_bias;
    if (!cfis[i] || dwarf_cfi_addrframe(cfis[i], pc, &f) != 0)
      continue;
    if (dwarf_frame_cfa(f, &ops, &count) == 0 && count && count <= MAX_OPS) {
      s->cfa = malloc(count * sizeof(*ops));
      if (s->cfa) {
        memcpy(s->cfa, ops, count * sizeof(*ops));
        s->ncfa = count;
      } else
        s->error = "allocation failed";
    }
    free(f);
    if (s->ncfa)
      break;
  }
  if (s->nvars) {
    variable *compact = realloc(s->vars, s->nvars * sizeof(variable));
    if (compact)
      s->vars = compact;
  } else {
    free(s->vars);
    s->vars = NULL;
  }
  return s;
}
static ct_values_site *read_values_cache(ct_values_module *m, uint64_t pc,
                                         const char *key) {
  values_cache cache = {.valid = true};
  if (!ct_analysis_cache_read("values", key, &cache.data, &cache.size))
    return NULL;
  ct_values_site *site = calloc(1, sizeof(*site));
  if (!site) {
    free(cache.data);
    return NULL;
  }
  site->module = m;
  site->pc = pc;
  uint64_t version = cache_get(&cache), stored_pc = cache_get(&cache);
  uint64_t status = cache_get(&cache), count = cache_get(&cache);
  uint64_t truncated = cache_get(&cache);
  if (version != 1 || stored_pc != pc || status > 2 || count > NVAR ||
      truncated > 1 || (status && (count || truncated)) ||
      !cache_get_die(&cache, m, &site->frame_die))
    goto invalid;
  site->truncated = truncated;
  if (status)
    site->error = status == 1 ? "DWARF variable information unavailable"
                              : "no DWARF scope at PC";
  if (site->frame_die.addr) {
    if (status || dwarf_tag(&site->frame_die) != DW_TAG_subprogram ||
        !attr(&site->frame_die, DW_AT_frame_base, &site->frame))
      goto invalid;
    site->have_frame = true;
  }
  site->vars = count ? calloc(count, sizeof(*site->vars)) : NULL;
  if (count && !site->vars)
    goto invalid;
  for (size_t index = 0; index < count; ++index) {
    Dwarf_Die die, type;
    if (!cache_get_die(&cache, m, &die) || !die.addr ||
        !cache_get_die(&cache, m, &type))
      goto invalid;
    uint64_t global = cache_get(&cache);
    int tag = dwarf_tag(&die);
    if (global > 1 ||
        (tag != DW_TAG_variable && tag != DW_TAG_formal_parameter))
      goto invalid;
    add_variable(site, &die, global);
    if (site->nvars != index + 1 ||
        site->vars[index].have_type != (type.addr != NULL) ||
        (type.addr && site->vars[index].type.addr != type.addr))
      goto invalid;
  }
  if (!cache_get_operations(&cache, &site->cfa, &site->ncfa) ||
      (status && site->ncfa) || !cache.valid || cache.position != cache.size)
    goto invalid;
  free(cache.data);
  return site;
invalid:
  free(cache.data);
  ct_values_site_free(site);
  return NULL;
}

static void write_values_cache(ct_values_site *site, const char *key) {
  unsigned status = 0;
  if (site->error) {
    if (!strcmp(site->error, "DWARF variable information unavailable"))
      status = 1;
    else if (!strcmp(site->error, "no DWARF scope at PC"))
      status = 2;
    else
      return; /* Allocation failures are not reusable analysis results. */
  }
  values_cache cache = {.data = malloc(MAX_VALUES_CACHE_BYTES),
                        .size = MAX_VALUES_CACHE_BYTES,
                        .valid = true};
  if (!cache.data)
    return;
  cache_put(&cache, 1);
  cache_put(&cache, site->pc);
  cache_put(&cache, status);
  cache_put(&cache, site->nvars);
  cache_put(&cache, site->truncated);
  cache_put_die(&cache, site->module, &site->frame_die);
  for (size_t index = 0; index < site->nvars; ++index) {
    variable *v = &site->vars[index];
    cache_put_die(&cache, site->module, &v->die);
    Dwarf_Die type = v->have_type ? v->type : (Dwarf_Die){0};
    cache_put_die(&cache, site->module, &type);
    cache_put(&cache, v->global);
  }
  cache_put_operations(&cache, site->cfa, site->ncfa);
  if (cache.valid)
    ct_analysis_cache_write("values", key, cache.data, cache.position);
  free(cache.data);
}

static void share_variables(ct_values_site *site) {
  if (!site || !site->module || !site->nvars || site->error)
    return;
  // PCs retain separate location-list/CFA evaluation. Only the immutable
  // ordered variable descriptions of an identical lexical scope are shared.
  uint64_t hash = UINT64_C(14695981039346656037);
  for (size_t index = 0; index < site->nvars; ++index) {
    const variable *value = &site->vars[index];
    const uintptr_t identity[] = {
        (uintptr_t)value->die.addr,
        (uintptr_t)value->die.cu,
        value->have_type ? (uintptr_t)value->type.addr : 0,
        value->have_type ? (uintptr_t)value->type.cu : 0,
        value->have_type,
        value->global};
    const unsigned char *bytes = (const unsigned char *)identity;
    for (size_t offset = 0; offset < sizeof(identity); ++offset)
      hash = (hash ^ bytes[offset]) * UINT64_C(1099511628211);
    for (const char *name = value->name; *name; ++name)
      hash = (hash ^ (unsigned char)*name) * UINT64_C(1099511628211);
  }
  variable_set **bucket =
      &site->module->variables[hash % PREPARED_CACHE_BUCKETS];
  for (variable_set *known = *bucket; known; known = known->next) {
    if (known->hash != hash || known->count != site->nvars)
      continue;
    bool equal = true;
    for (size_t index = 0; index < site->nvars && equal; ++index) {
      const variable *left = &known->vars[index], *right = &site->vars[index];
      equal = left->die.addr == right->die.addr &&
              left->die.cu == right->die.cu &&
              left->have_type == right->have_type &&
              (!left->have_type || (left->type.addr == right->type.addr &&
                                    left->type.cu == right->type.cu)) &&
              left->global == right->global && !strcmp(left->name, right->name);
    }
    if (!equal)
      continue;
    for (size_t index = 0; index < site->nvars; ++index)
      free(site->vars[index].name);
    free(site->vars);
    site->vars = known->vars;
    site->shared_variables = true;
    return;
  }
  variable_set *created = malloc(sizeof(*created));
  if (created) {
    *created = (variable_set){site->vars, site->nvars, hash, *bucket};
    *bucket = created;
    site->shared_variables = true;
  }
}

ct_values_site *ct_values_prepare(ct_values_module *m, uint64_t runtime_pc) {
  if (!m)
    return prepare_values(m, runtime_pc);
  uint64_t pc = runtime_pc - m->bias;
  prepared_values *entry = prepared_at(m, pc);
  if (entry && entry->site) {
    ++entry->site->references;
    return entry->site;
  }
  char *key = prepared_key(m, pc);
  ct_values_site *site = key && m->dw ? read_values_cache(m, pc, key) : NULL;
  if (!site) {
    site = prepare_values(m, runtime_pc);
    if (site && key && m->dw)
      write_values_cache(site, key);
  }
  free(key);
  share_variables(site);
  if (site && entry &&
      (!site->error || strcmp(site->error, "allocation failed"))) {
    site->references =
        2; /* Module cache and the caller own one reference each. */
    entry->site = site;
  }
  return site;
}

bool ct_values_has_scope(const ct_values_site *s) { return s && !s->error; }

void ct_values_site_free(ct_values_site *s) {
  if (!s || (s->references && --s->references))
    return;
  if (!s->shared_variables) {
    for (size_t i = 0; i < s->nvars; i++)
      free(s->vars[i].name);
    free(s->vars);
  }
  free(s->cfa);
  free(s);
}

typedef enum { LOC_NUMBER, LOC_REGISTER, LOC_VALUE, LOC_BYTES } loc_kind;
typedef struct {
  loc_kind kind;
  uint64_t v;
  const unsigned char *bytes;
  size_t n;
} item;
typedef struct {
  ct_values_site *s;
  const ct_registers *r;
  ct_read_memory read;
  void *arg;
  uint64_t cfa, frame;
  bool have_cfa, have_frame;
  const char *error;
} eval_context;
typedef struct {
  unsigned char bytes[NBYTE];
  size_t n;
  bool composite;
  item loc;
} result;
static bool reg_bytes(eval_context *c, unsigned reg, void *dst, size_t n) {
  if (reg < 17 && c->r->have_gpr &&
      !(c->r->unavailable_gpr & (UINT64_C(1) << reg)) && n <= 8) {
    memcpy(dst, &c->r->gpr[reg], n);
    return true;
  }
  if (reg >= 17 && reg < 33 && c->r->have_xmm && n <= 16) {
    memcpy(dst, c->r->xmm[reg - 17], n);
    return true;
  }
  c->error = "unsupported/unavailable register";
  return false;
}
static bool numeric(eval_context *c, item x, uint64_t *v) {
  if (x.kind == LOC_REGISTER) {
    *v = 0;
    if (x.v > 32) {
      c->error = "unsupported register";
      return false;
    }
    return reg_bytes(c, (unsigned)x.v, v, 8);
  }
  if (x.kind == LOC_BYTES) {
    c->error = "non-scalar expression";
    return false;
  }
  *v = x.v;
  return true;
}
static bool materialize(eval_context *c, item x, void *dst, size_t n) {
  if (n > NBYTE) {
    c->error = "value too large";
    return false;
  }
  if (x.kind == LOC_REGISTER) {
    if (x.v > 32) {
      c->error = "unsupported register";
      return false;
    }
    return reg_bytes(c, (unsigned)x.v, dst, n);
  }
  if (x.kind == LOC_VALUE) {
    if (n > 8) {
      c->error = "scalar size mismatch";
      return false;
    }
    memcpy(dst, &x.v, n);
    return true;
  }
  if (x.kind == LOC_BYTES) {
    if (n > x.n) {
      c->error = "short implicit value";
      return false;
    }
    memcpy(dst, x.bytes, n);
    return true;
  }
  if (n && !c->read(c->arg, x.v, dst, n)) {
    c->error = "unreadable memory";
    return false;
  }
  return true;
}
/* Bounded interpreter for common GCC/Clang scalar/stack/register locations. */
static bool eval(eval_context *c, Dwarf_Attribute *attribute, Dwarf_Op *ops,
                 size_t nops, result *out) {
  item stack[NSTACK];
  size_t sp = 0, steps = 0, pieces = 0;
  memset(out, 0, sizeof(*out));
  if (!nops) {
    c->error = "no location at PC";
    return false;
  }
  if (nops > MAX_OPS) {
    c->error = "expression too long";
    return false;
  }
#define PUSH(x)                                                                \
  do {                                                                         \
    if (sp == NSTACK)                                                          \
      goto malformed;                                                          \
    stack[sp++] = (x);                                                         \
  } while (0)
#define NEED(n)                                                                \
  do {                                                                         \
    if (sp < (n))                                                              \
      goto malformed;                                                          \
  } while (0)
#define NUMTOP(v)                                                              \
  do {                                                                         \
    NEED(1);                                                                   \
    if (!numeric(c, stack[sp - 1], &(v)))                                      \
      return false;                                                            \
  } while (0)
  for (size_t ip = 0; ip < nops; ip++) {
    if (++steps > MAX_OPS) {
      c->error = "expression budget exceeded";
      return false;
    }
    Dwarf_Op *o = &ops[ip];
    unsigned op = o->atom;
    uint64_t a, b, v;
    if (op >= DW_OP_lit0 && op <= DW_OP_lit31) {
      PUSH(((item){LOC_NUMBER, op - DW_OP_lit0, 0, 0}));
      continue;
    }
    if (op >= DW_OP_reg0 && op <= DW_OP_reg31) {
      PUSH(((item){LOC_REGISTER, op - DW_OP_reg0, 0, 0}));
      continue;
    }
    if (op >= DW_OP_breg0 && op <= DW_OP_breg31) {
      v = 0;
      if (!reg_bytes(c, op - DW_OP_breg0, &v, 8))
        return false;
      PUSH(((item){LOC_NUMBER, v + o->number, 0, 0}));
      continue;
    }
    switch (op) {
    case DW_OP_addr:
      PUSH(((item){LOC_NUMBER, o->number + c->s->module->bias, 0, 0}));
      break;
    case DW_OP_addrx:
    case DW_OP_GNU_addr_index: {
      Dwarf_Attribute address_attr;
      Dwarf_Addr address;
      if (!attribute ||
          dwarf_getlocation_attr(attribute, o, &address_attr) != 0 ||
          dwarf_formaddr(&address_attr, &address) != 0)
        goto malformed;
      PUSH(((item){LOC_NUMBER, address + c->s->module->bias, 0, 0}));
      break;
    }
    case DW_OP_constx:
    case DW_OP_GNU_const_index: {
      Dwarf_Attribute constant_attr;
      Dwarf_Word constant;
      if (!attribute ||
          dwarf_getlocation_attr(attribute, o, &constant_attr) != 0 ||
          dwarf_formudata(&constant_attr, &constant) != 0)
        goto malformed;
      PUSH(((item){LOC_NUMBER, constant, 0, 0}));
      break;
    }
    case DW_OP_const1u:
    case DW_OP_const1s:
    case DW_OP_const2u:
    case DW_OP_const2s:
    case DW_OP_const4u:
    case DW_OP_const4s:
    case DW_OP_const8u:
    case DW_OP_const8s:
    case DW_OP_constu:
    case DW_OP_consts:
      PUSH(((item){LOC_NUMBER, o->number, 0, 0}));
      break;
    case DW_OP_regx:
      PUSH(((item){LOC_REGISTER, o->number, 0, 0}));
      break;
    case DW_OP_bregx:
      if (o->number > UINT_MAX)
        goto malformed;
      v = 0;
      if (!reg_bytes(c, (unsigned)o->number, &v, 8))
        return false;
      PUSH(((item){LOC_NUMBER, v + o->number2, 0, 0}));
      break;
    case DW_OP_fbreg:
      if (!c->have_frame) {
        c->error = "frame base unavailable";
        return false;
      }
      PUSH(((item){LOC_NUMBER, c->frame + o->number, 0, 0}));
      break;
    case DW_OP_call_frame_cfa:
      if (!c->have_cfa) {
        c->error = "CFA unavailable";
        return false;
      }
      PUSH(((item){LOC_NUMBER, c->cfa, 0, 0}));
      break;
    case DW_OP_dup:
      NEED(1);
      {
        item x = stack[sp - 1];
        PUSH(x);
      }
      break;
    case DW_OP_drop:
      NEED(1);
      --sp;
      break;
    case DW_OP_over:
      NEED(2);
      {
        item x = stack[sp - 2];
        PUSH(x);
      }
      break;
    case DW_OP_pick:
      if (o->number >= sp)
        goto malformed;
      {
        item x = stack[sp - 1 - o->number];
        PUSH(x);
      }
      break;
    case DW_OP_swap:
      NEED(2);
      {
        item x = stack[sp - 1];
        stack[sp - 1] = stack[sp - 2];
        stack[sp - 2] = x;
      }
      break;
    case DW_OP_rot:
      NEED(3);
      {
        item x = stack[sp - 1];
        stack[sp - 1] = stack[sp - 2];
        stack[sp - 2] = stack[sp - 3];
        stack[sp - 3] = x;
      }
      break;
    case DW_OP_deref:
    case DW_OP_deref_size:
      NUMTOP(a);
      b = op == DW_OP_deref ? 8 : o->number;
      v = 0;
      if (!b || b > 8)
        goto malformed;
      if (!c->read(c->arg, a, &v, (size_t)b)) {
        c->error = "unreadable dereference";
        return false;
      }
      stack[sp - 1] = (item){LOC_NUMBER, v, 0, 0};
      break;
    case DW_OP_plus_uconst:
      NUMTOP(a);
      stack[sp - 1] = (item){LOC_NUMBER, a + o->number, 0, 0};
      break;
    case DW_OP_abs:
    case DW_OP_neg:
    case DW_OP_not:
      NUMTOP(a);
      v = op == DW_OP_not   ? ~a
          : op == DW_OP_neg ? 0 - a
                            : ((int64_t)a < 0 ? 0 - a : a);
      stack[sp - 1] = (item){LOC_NUMBER, v, 0, 0};
      break;
    case DW_OP_plus:
    case DW_OP_minus:
    case DW_OP_mul:
    case DW_OP_div:
    case DW_OP_mod:
    case DW_OP_and:
    case DW_OP_or:
    case DW_OP_xor:
    case DW_OP_shl:
    case DW_OP_shr:
    case DW_OP_shra:
    case DW_OP_eq:
    case DW_OP_ne:
    case DW_OP_lt:
    case DW_OP_le:
    case DW_OP_gt:
    case DW_OP_ge:
      NEED(2);
      if (!numeric(c, stack[sp - 2], &a) || !numeric(c, stack[sp - 1], &b))
        return false;
      switch (op) {
      case DW_OP_plus:
        v = a + b;
        break;
      case DW_OP_minus:
        v = a - b;
        break;
      case DW_OP_mul:
        v = a * b;
        break;
      case DW_OP_div:
        if (!b || (a == UINT64_C(0x8000000000000000) && b == UINT64_MAX))
          goto malformed;
        v = (int64_t)a / (int64_t)b;
        break;
      case DW_OP_mod:
        if (!b)
          goto malformed;
        v = a % b;
        break;
      case DW_OP_and:
        v = a & b;
        break;
      case DW_OP_or:
        v = a | b;
        break;
      case DW_OP_xor:
        v = a ^ b;
        break;
      case DW_OP_shl:
        if (b >= 64)
          goto malformed;
        v = a << b;
        break;
      case DW_OP_shr:
        if (b >= 64)
          goto malformed;
        v = a >> b;
        break;
      case DW_OP_shra:
        if (b >= 64)
          goto malformed;
        v = (int64_t)a >> b;
        break;
      case DW_OP_eq:
        v = a == b;
        break;
      case DW_OP_ne:
        v = a != b;
        break;
      case DW_OP_lt:
        v = (int64_t)a < (int64_t)b;
        break;
      case DW_OP_le:
        v = (int64_t)a <= (int64_t)b;
        break;
      case DW_OP_gt:
        v = (int64_t)a > (int64_t)b;
        break;
      default:
        v = (int64_t)a >= (int64_t)b;
      }
      --sp;
      stack[sp - 1] = (item){LOC_NUMBER, v, 0, 0};
      break;
    case DW_OP_stack_value:
      NUMTOP(v);
      stack[sp - 1] = (item){LOC_VALUE, v, 0, 0};
      break;
    case DW_OP_implicit_value: {
      Dwarf_Block block;
      if (!attribute ||
          dwarf_getlocation_implicit_value(attribute, o, &block) != 0)
        goto malformed;
      PUSH(((item){LOC_BYTES, 0, block.data, (size_t)block.length}));
      break;
    }
    case DW_OP_piece: {
      if (o->number > NBYTE - pieces) {
        c->error = "pieces too large";
        return false;
      }
      if (!sp) {
        c->error = "partially unavailable value";
        return false;
      }
      if (!materialize(c, stack[sp - 1], out->bytes + pieces,
                       (size_t)o->number))
        return false;
      pieces += (size_t)o->number;
      sp = 0;
      out->composite = true;
      break;
    }
    case DW_OP_nop:
      break;
    case DW_OP_entry_value:
    case DW_OP_GNU_entry_value:
      c->error = "entry value not recorded";
      return false;
    case DW_OP_GNU_uninit:
      c->error = "uninitialized (DWARF)";
      return false;
    default:
      c->error = "unsupported DWARF operation";
      return false;
    }
  }
  if (out->composite) {
    if (sp)
      goto malformed;
    out->n = pieces;
    return true;
  }
  if (sp != 1)
    goto malformed;
  out->loc = stack[0];
  return true;
malformed:
  c->error = "malformed/unsupported expression";
  return false;
#undef PUSH
#undef NEED
#undef NUMTOP
}
static bool eval_attribute(eval_context *c, Dwarf_Attribute *a, result *r) {
  Dwarf_Op *ops[2];
  size_t counts[2];
  int n = dwarf_getlocation_addr(a, c->s->pc, ops, counts, 2);
  if (n < 0) {
    c->error = "location decode failed";
    return false;
  }
  if (n == 0) {
    c->error = "no location at PC (optimized out/not live)";
    return false;
  }
  if (n != 1) {
    c->error = "ambiguous locations at PC";
    return false;
  }
  return eval(c, a, ops[0], counts[0], r);
}
static void bases(eval_context *c) {
  result r;
  if (c->s->ncfa && eval(c, NULL, c->s->cfa, c->s->ncfa, &r) && !r.composite)
    c->have_cfa = numeric(c, r.loc, &c->cfa);
  if (c->s->have_frame && eval_attribute(c, &c->s->frame, &r) && !r.composite)
    c->have_frame = numeric(c, r.loc, &c->frame);
}
static bool peel(Dwarf_Die *type, Dwarf_Die *t, bool *vol) {
  *t = *type;
  *vol = false;
  for (int i = 0; i < 32; i++) {
    int tag = dwarf_tag(t);
    if (tag == DW_TAG_volatile_type || tag == DW_TAG_atomic_type)
      *vol = true;
    if (tag != DW_TAG_typedef && tag != DW_TAG_const_type &&
        tag != DW_TAG_volatile_type && tag != DW_TAG_restrict_type &&
        tag != DW_TAG_atomic_type)
      return tag > 0;
    Dwarf_Die next;
    if (!type_of(t, &next))
      return false;
    *t = next;
  }
  return false;
}
static bool type_size(Dwarf_Die *t, size_t *size) {
  Dwarf_Word n;
  if (dwarf_aggregate_size(t, &n) == 0 && n <= SIZE_MAX) {
    *size = (size_t)n;
    return true;
  }
  int tag = dwarf_tag(t);
  if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
      tag == DW_TAG_rvalue_reference_type) {
    *size = 8;
    return true;
  }
  return false;
}
/* Conservative: do not read an aggregate containing volatile/atomic storage.
 * Do not recurse through pointers: pointer bytes are not the pointee storage.
 */
static bool guarded_storage(Dwarf_Die *orig, int depth) {
  Dwarf_Die t;
  bool vol;
  if (depth > 16 || !peel(orig, &t, &vol))
    return true;
  if (vol)
    return true;
  int tag = dwarf_tag(&t);
  if (tag == DW_TAG_array_type) {
    Dwarf_Die e;
    return !type_of(&t, &e) || guarded_storage(&e, depth + 1);
  }
  if (tag == DW_TAG_structure_type || tag == DW_TAG_class_type ||
      tag == DW_TAG_union_type) {
    Dwarf_Die ch;
    if (dwarf_child(&t, &ch) == 0)
      do {
        int ctag = dwarf_tag(&ch);
        if (ctag != DW_TAG_member && ctag != DW_TAG_inheritance)
          continue;
        if (bool_attr(&ch, DW_AT_external) || bool_attr(&ch, DW_AT_declaration))
          continue;
        Dwarf_Die mt;
        if (!type_of(&ch, &mt) || guarded_storage(&mt, depth + 1))
          return true;
      } while (dwarf_siblingof(&ch, &ch) == 0);
  }
  return false;
}
typedef ct_value_view value_view;

static Dwarf_Die format_die(ct_value_format_ref ref) {
  return (Dwarf_Die){.addr = (void *)ref.identity,
                     .cu = (struct Dwarf_CU *)ref.context};
}

static ct_value_format_ref format_ref(const Dwarf_Die *die) {
  return (ct_value_format_ref){.identity = die->addr, .context = die->cu};
}

static bool dwarf_value_shape(const void *arg, ct_value_format_ref *ref,
                              ct_value_layout_node *shape,
                              ct_value_format_ref *element) {
  (void)arg;
  *shape = (ct_value_layout_node){0};
  *element = (ct_value_format_ref){0};
  Dwarf_Die original = format_die(*ref), element_type = {0};
  Dwarf_Die type;
  bool vol;
  if (!original.addr || !peel(&original, &type, &vol) || vol ||
      !type_size(&type, &shape->bytes))
    return false;
  *ref = (ct_value_format_ref){
      .identity = type.addr, .context = type.cu, .dimension = ref->dimension};
  shape->complete = !bool_attr(&type, DW_AT_declaration);
  int tag = dwarf_tag(&type);
  if (tag == DW_TAG_structure_type || tag == DW_TAG_class_type) {
    shape->kind = CT_LAYOUT_STRUCT;
    return true;
  }
  if (tag == DW_TAG_array_type) {
    Dwarf_Die base;
    if (!type_of(&type, &element_type) || !peel(&element_type, &base, &vol) ||
        !type_size(&base, &shape->element_stride) || !shape->element_stride)
      return false;
    *element = format_ref(&element_type);
    shape->kind = CT_LAYOUT_ARRAY;
    /* A DWARF array has one element type plus one subrange per dimension.
     * Preserve nested array shape instead of flattening all dimensions. */
    Dwarf_Die range;
    unsigned dimension = 0;
    size_t following = 1;
    bool have_count = false;
    if (dwarf_child(&type, &range) == 0)
      do {
        if (dwarf_tag(&range) != DW_TAG_subrange_type)
          continue;
        uint64_t count, upper, lower = 0;
        if (!uint_attr(&range, DW_AT_count, &count)) {
          uint_attr(&range, DW_AT_lower_bound, &lower);
          if (!uint_attr(&range, DW_AT_upper_bound, &upper) || upper < lower ||
              upper - lower == UINT64_MAX)
            return false;
          count = upper - lower + 1;
        }
        if (count > SIZE_MAX)
          return false;
        if (dimension == ref->dimension) {
          shape->element_count = (size_t)count;
          have_count = true;
        } else if (dimension > ref->dimension) {
          if (count && following > SIZE_MAX / (size_t)count)
            return false;
          following *= (size_t)count;
        }
        if (++dimension >= MAX_DEPTH)
          return false;
      } while (dwarf_siblingof(&range, &range) == 0);
    if (!have_count) {
      if (dimension || ref->dimension)
        return false;
      shape->element_count = shape->bytes / shape->element_stride;
    } else {
      if (following && shape->element_stride > SIZE_MAX / following)
        return false;
      shape->element_stride *= following;
      if (shape->element_count &&
          shape->element_stride > SIZE_MAX / shape->element_count)
        return false;
      shape->bytes = shape->element_count * shape->element_stride;
      if (dimension > ref->dimension + 1) {
        *element = *ref;
        ++element->dimension;
      }
    }
    return true;
  }
  if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
      tag == DW_TAG_rvalue_reference_type) {
    shape->kind = CT_LAYOUT_POINTER;
    type_of(&type, &element_type);
    *element = format_ref(&element_type);
    return true;
  }
  uint64_t encoding = 0;
  if (tag == DW_TAG_enumeration_type) {
    if (!uint_attr(&type, DW_AT_encoding, &encoding)) {
      Dwarf_Die original, base;
      if (type_of(&type, &original) && peel(&original, &base, &vol))
        uint_attr(&base, DW_AT_encoding, &encoding);
      if (!encoding)
        encoding = DW_ATE_signed;
    }
  } else if (tag != DW_TAG_base_type ||
             !uint_attr(&type, DW_AT_encoding, &encoding))
    return false;
  shape->kind = CT_LAYOUT_SCALAR;
  shape->scalar.bytes = shape->bytes;
  if (encoding == DW_ATE_signed || encoding == DW_ATE_signed_char)
    shape->scalar.kind = CT_VALUE_SIGNED;
  else if (encoding == DW_ATE_unsigned || encoding == DW_ATE_unsigned_char ||
           encoding == DW_ATE_UTF)
    shape->scalar.kind = CT_VALUE_UNSIGNED;
  else if (encoding == DW_ATE_boolean)
    shape->scalar.kind = CT_VALUE_BOOLEAN;
  else if (encoding == DW_ATE_float)
    shape->scalar.kind = CT_VALUE_FLOAT;
  else
    return false;
  return true;
}

static ct_value_member_status
dwarf_value_member(const void *arg, ct_value_format_ref ref, size_t index,
                   ct_value_format_ref *cursor,
                   ct_value_format_member *member) {
  (void)arg;
  Dwarf_Die parent = format_die(ref), child = format_die(*cursor);
  if (index ? dwarf_siblingof(&child, &child) != 0
            : dwarf_child(&parent, &child) != 0)
    return CT_VALUE_MEMBER_END;
  *cursor = format_ref(&child);
  int tag = dwarf_tag(&child);
  if ((tag != DW_TAG_member && tag != DW_TAG_inheritance) ||
      bool_attr(&child, DW_AT_external) || bool_attr(&child, DW_AT_declaration))
    return CT_VALUE_MEMBER_SKIP;
  uint64_t offset = 0, bits;
  Dwarf_Die type = {0};
  member->available = !uint_attr(&child, DW_AT_bit_size, &bits) &&
                      uint_attr(&child, DW_AT_data_member_location, &offset) &&
                      offset <= SIZE_MAX && type_of(&child, &type);
  member->offset = (size_t)offset;
  member->type = format_ref(&type);
  member->name = die_name(&child);
  if (!member->name && tag == DW_TAG_inheritance && type.addr)
    member->name = die_name(&type);
  return CT_VALUE_MEMBER_ITEM;
}

static bool format_type(eval_context *c, buffer *out, Dwarf_Die *orig,
                        value_view value) {
  const ct_value_provider provider = {.shape = dwarf_value_shape,
                                      .member = dwarf_value_member};
  return ct_values_format_object(&provider, format_ref(orig), value, c->read,
                                 c->arg, out);
}

/* Construct an abstract declarator rather than flattening pointees: char **,
 * const char *restrict, arrays and function pointers must retain their shape.
 * Keep recursive declarator buffers off DynamoRIO's instrumentation stack. */
static bool assembly_type_name(Dwarf_Die *original, const char *declarator,
                               buffer *out, unsigned depth) {
  if (depth >= MAX_DEPTH)
    return false;
  Dwarf_Die type = *original;
  bool is_const = false, is_volatile = false, is_restrict = false,
       is_atomic = false;
  int tag;
  for (;;) {
    tag = dwarf_tag(&type);
    if (tag != DW_TAG_const_type && tag != DW_TAG_volatile_type &&
        tag != DW_TAG_restrict_type && tag != DW_TAG_atomic_type)
      break;
    is_const |= tag == DW_TAG_const_type;
    is_volatile |= tag == DW_TAG_volatile_type;
    is_restrict |= tag == DW_TAG_restrict_type;
    is_atomic |= tag == DW_TAG_atomic_type;
    Dwarf_Die next;
    if (++depth >= MAX_DEPTH || !type_of(&type, &next))
      return false;
    type = next;
  }
  char qualifiers[48];
  snprintf(qualifiers, sizeof(qualifiers), "%s%s%s%s", is_const ? "const " : "",
           is_volatile ? "volatile " : "", is_restrict ? "restrict " : "",
           is_atomic ? "_Atomic " : "");
  const char *name = die_name(&type);
  if (name && name[0] && !strpbrk(name, "\r\n\t") &&
      (tag == DW_TAG_base_type || tag == DW_TAG_typedef ||
       tag == DW_TAG_structure_type || tag == DW_TAG_class_type ||
       tag == DW_TAG_union_type || tag == DW_TAG_enumeration_type ||
       tag == DW_TAG_unspecified_type)) {
    const char *prefix = tag == DW_TAG_structure_type     ? "struct "
                         : tag == DW_TAG_class_type       ? "class "
                         : tag == DW_TAG_union_type       ? "union "
                         : tag == DW_TAG_enumeration_type ? "enum "
                                                          : "";
    put(out, "%s%s%s%s%s", qualifiers, prefix, name, declarator[0] ? " " : "",
        declarator);
    return !out->truncated;
  }
  if (tag != DW_TAG_pointer_type && tag != DW_TAG_reference_type &&
      tag != DW_TAG_rvalue_reference_type && tag != DW_TAG_array_type &&
      tag != DW_TAG_subroutine_type && tag != DW_TAG_subprogram)
    return false;
  char *nested = calloc(1, sizeof(((ct_variable_description *)0)->type));
  if (!nested)
    return false;
  buffer declaration = {nested, sizeof(((ct_variable_description *)0)->type), 0,
                        false};
  Dwarf_Die inner;
  Dwarf_Attribute type_attribute;
  bool have_inner = type_of(&type, &inner);
  bool valid = have_inner || !attr(&type, DW_AT_type, &type_attribute);
  if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
      tag == DW_TAG_rvalue_reference_type) {
    Dwarf_Die peeled;
    bool vol;
    bool parentheses = have_inner && peel(&inner, &peeled, &vol) &&
                       (dwarf_tag(&peeled) == DW_TAG_array_type ||
                        dwarf_tag(&peeled) == DW_TAG_subroutine_type);
    const char *symbol = tag == DW_TAG_pointer_type     ? "*"
                         : tag == DW_TAG_reference_type ? "&"
                                                        : "&&";
    put(&declaration, "%s%s%s%s%s%s", parentheses ? "(" : "", symbol,
        qualifiers[0] ? " " : "", qualifiers, declarator,
        parentheses ? ")" : "");
  } else if (tag == DW_TAG_array_type) {
    put(&declaration, "%s", declarator);
    Dwarf_Die dimension;
    bool have_dimension = false;
    if (dwarf_child(&type, &dimension) == 0) {
      size_t inspected = 0;
      do {
        if (++inspected > NVAR) {
          valid = false;
          break;
        }
        if (dwarf_tag(&dimension) != DW_TAG_subrange_type)
          continue;
        have_dimension = true;
        uint64_t count, upper, lower = 0;
        if (uint_attr(&dimension, DW_AT_count, &count))
          put(&declaration, "[%" PRIu64 "]", count);
        else if (uint_attr(&dimension, DW_AT_upper_bound, &upper)) {
          uint_attr(&dimension, DW_AT_lower_bound, &lower);
          if (upper < lower || upper - lower == UINT64_MAX) {
            valid = false;
            break;
          }
          put(&declaration, "[%" PRIu64 "]", upper - lower + 1);
        } else
          put(&declaration, "[]");
      } while (dwarf_siblingof(&dimension, &dimension) == 0);
    }
    if (!have_dimension)
      put(&declaration, "[]");
    if (qualifiers[0])
      put(out, "%s", qualifiers);
    if (!have_inner)
      valid = false;
  } else {
    put(&declaration, "%s(", declarator);
    Dwarf_Die parameter_die;
    size_t parameters = 0, inspected = 0;
    if (qualifiers[0])
      valid = false;
    if (dwarf_child(&type, &parameter_die) == 0) {
      do {
        if (++inspected > NVAR) {
          valid = false;
          break;
        }
        int parameter_tag = dwarf_tag(&parameter_die);
        if (parameter_tag != DW_TAG_formal_parameter &&
            parameter_tag != DW_TAG_unspecified_parameters)
          continue;
        if (parameters++)
          put(&declaration, ", ");
        if (parameter_tag == DW_TAG_unspecified_parameters)
          put(&declaration, "...");
        else {
          Dwarf_Die parameter_type;
          const char *parameter_name = die_name(&parameter_die);
          if (parameter_name && strpbrk(parameter_name, "\r\n\t"))
            parameter_name = NULL;
          if (!type_of(&parameter_die, &parameter_type) ||
              !assembly_type_name(&parameter_type,
                                  parameter_name ? parameter_name : "",
                                  &declaration, depth + 1)) {
            valid = false;
            break;
          }
        }
      } while (dwarf_siblingof(&parameter_die, &parameter_die) == 0);
    }
    if (!parameters && bool_attr(&type, DW_AT_prototyped))
      put(&declaration, "void");
    put(&declaration, ")");
  }
  valid = valid && !declaration.truncated;
  if (valid && have_inner)
    valid = assembly_type_name(&inner, nested, out, depth + 1);
  else if (valid &&
           (tag == DW_TAG_pointer_type || tag == DW_TAG_subroutine_type ||
            tag == DW_TAG_subprogram)) {
    /* Omitted DW_AT_type explicitly denotes void for these DWARF tags. */
    put(out, "void %s", nested);
    valid = !out->truncated;
  } else
    valid = false;
  free(nested);
  return valid;
}

static bool format_named(eval_context *eval, buffer *out, const char *name,
                         Dwarf_Die *type, value_view value) {
  buffer previous = *out;
  if (out->used)
    put(out, ", ");
  put(out, "%s=", name);
  if ((!type || !format_type(eval, out, type, value)) && !out->truncated)
    put(out, "?");
  if (!out->truncated)
    return true;
  *out = previous;
  if (out->size)
    out->p[out->used] = 0;
  return false;
}
static void format_variable(eval_context *c, variable *v, buffer *out) {
  Dwarf_Die type;
  bool vol;
  size_t bytes;
  if (!v->have_type || !peel(&v->type, &type, &vol) ||
      !type_size(&type, &bytes) || vol) {
    format_named(c, out, v->name, NULL, (value_view){0});
    return;
  }
  size_t take = bytes < NBYTE ? bytes : NBYTE;
  unsigned char raw[NBYTE] = {0};
  Dwarf_Attribute a;
  bool ok = false;
  result r;
  c->error = NULL;
  if (attr(&v->die, DW_AT_location, &a)) {
    if (eval_attribute(c, &a, &r)) {
      if (!r.composite && r.loc.kind == LOC_NUMBER) {
        value_view value = {.size = bytes, .address = r.loc.v, .memory = true};
        format_named(c, out, v->name, &v->type, value);
        return;
      }
      if (guarded_storage(&v->type, 0)) {
        format_named(c, out, v->name, NULL, (value_view){0});
        return;
      }
      if (r.composite) {
        if (take <= r.n) {
          memcpy(raw, r.bytes, take);
          ok = true;
        } else
          c->error = "incomplete pieces";
      } else
        ok = materialize(c, r.loc, raw, take);
    }
  } else if (attr(&v->die, DW_AT_const_value, &a)) {
    Dwarf_Block block;
    Dwarf_Sword sv;
    Dwarf_Word uv;
    if (dwarf_formblock(&a, &block) == 0 && take <= block.length) {
      memcpy(raw, block.data, take);
      ok = true;
    } else if (take <= 8 && dwarf_formsdata(&a, &sv) == 0) {
      memcpy(raw, &sv, take);
      ok = true;
    } else if (take <= 8 && dwarf_formudata(&a, &uv) == 0) {
      memcpy(raw, &uv, take);
      ok = true;
    } else
      c->error = "unsupported constant";
  } else
    c->error = "no location/constant (optimized out)";
  format_named(c, out, v->name, &v->type,
               (value_view){.raw = ok ? raw : NULL, .size = ok ? take : 0});
}

void ct_values_format(ct_values_site *s, const ct_registers *regs,
                      ct_read_memory read, void *arg, char *out, size_t size) {
  buffer b = {out, size, 0, false};
  if (size)
    out[0] = 0;
  if (!s || s->error || !s->nvars || !regs || !size)
    return;
  eval_context c = {.s = s, .r = regs, .read = read, .arg = arg};
  bases(&c);
  for (size_t i = 0; i < s->nvars; ++i)
    format_variable(&c, &s->vars[i], &b);
}

static bool valid_name_list(const char *names, size_t size) {
  if (!names || !size)
    return false;
  for (size_t offset = 0; offset < size;) {
    const char *end = memchr(names + offset, 0, size - offset);
    if (!end)
      return false;
    offset = (size_t)(end - names) + 1;
  }
  return true;
}

void ct_values_format_selected(ct_values_site *s, const ct_registers *regs,
                               ct_read_memory read, void *arg,
                               const char *names, size_t names_size, char *out,
                               size_t size) {
  buffer b = {out, size, 0, false};
  if (size)
    out[0] = 0;
  if (!s || s->error || !s->nvars || !regs || !size ||
      !valid_name_list(names, names_size))
    return;
  eval_context c = {.s = s, .r = regs, .read = read, .arg = arg};
  bases(&c);
  bool shown[NVAR] = {0};
  for (size_t offset = 0; offset < names_size;
       offset += strlen(names + offset) + 1) {
    for (size_t i = 0; i < s->nvars; ++i) {
      if (shown[i] || strcmp(names + offset, s->vars[i].name))
        continue;
      shown[i] = true;
      format_variable(&c, &s->vars[i], &b);
      break;
    }
  }
}

/* Only fixed member offsets and complete array elements are named. No parser,
 * dynamic inheritance, bitfield, union-member, or general expression guesses.
 */
static bool storage_type(Dwarf_Die *original, uint64_t offset, size_t bytes,
                         Dwarf_Die *matched, char *suffix, size_t capacity) {
  Dwarf_Die type;
  bool vol;
  size_t width;
  if (!peel(original, &type, &vol) || vol || !type_size(&type, &width) ||
      offset > width || bytes > width - offset || guarded_storage(original, 0))
    return false;
  suffix[0] = 0;
  if (!offset && width == bytes) {
    *matched = *original;
    return true;
  }
  int tag = dwarf_tag(&type);
  if (tag == DW_TAG_array_type) {
    Dwarf_Die element, base;
    size_t stride;
    if (!type_of(&type, &element) || !peel(&element, &base, &vol) ||
        !type_size(&base, &stride) || stride != bytes || offset % stride)
      return false;
    int n = snprintf(suffix, capacity, "[%" PRIu64 "]", offset / stride);
    if (n < 0 || (size_t)n >= capacity)
      return false;
    *matched = element;
    return true;
  }
  if (tag != DW_TAG_structure_type && tag != DW_TAG_class_type)
    return false;
  Dwarf_Die member;
  bool found = false;
  if (dwarf_child(&type, &member) != 0)
    return false;
  size_t inspected = 0;
  do {
    uint64_t member_offset, bits;
    Dwarf_Die member_type, base;
    if (++inspected > NVAR)
      return false;
    if (dwarf_tag(&member) != DW_TAG_member ||
        uint_attr(&member, DW_AT_bit_size, &bits) ||
        !uint_attr(&member, DW_AT_data_member_location, &member_offset) ||
        member_offset != offset || !type_of(&member, &member_type) ||
        !peel(&member_type, &base, &vol) || !type_size(&base, &width) ||
        width != bytes)
      continue;
    const char *name = die_name(&member);
    if (!name || !name[0] || strpbrk(name, "\r\n\t"))
      continue;
    if (found)
      return false;
    int n = snprintf(suffix, capacity, ".%s", name);
    if (n < 0 || (size_t)n >= capacity)
      return false;
    *matched = member_type;
    found = true;
  } while (dwarf_siblingof(&member, &member) == 0);
  return found;
}

static bool find_storage(eval_context *c, bool memory, uint64_t location,
                         size_t byte_offset, size_t bytes, Dwarf_Die *type,
                         char *name, size_t capacity, Dwarf_Die *variable_die) {
  ct_values_site *s = c->s;
  if (!s || s->error || byte_offset || !bytes || !capacity)
    return false;
  if (!memory && location < 17 &&
      (c->r->unavailable_gpr & (UINT64_C(1) << location)))
    return false;
  bases(c);
  /* Prefer a direct object or member over aliases through local pointers. */
  for (int indirect = 0; indirect <= (memory ? 1 : 0); ++indirect) {
    bool found = false;
    for (size_t i = 0; i < s->nvars; ++i) {
      variable *v = &s->vars[i];
      Dwarf_Attribute a;
      Dwarf_Die original, base, matched;
      bool vol;
      result r;
      if (!v->have_type || !peel(&v->type, &base, &vol) || vol ||
          !attr(&v->die, DW_AT_location, &a) || !eval_attribute(c, &a, &r) ||
          r.composite)
        continue;
      original = v->type;
      uint64_t address = r.loc.v;
      bool reference = false;
      if (indirect) {
        int tag = dwarf_tag(&base);
        size_t width;
        reference =
            tag == DW_TAG_reference_type || tag == DW_TAG_rvalue_reference_type;
        if ((tag != DW_TAG_pointer_type && !reference) ||
            !type_size(&base, &width) || width != sizeof(address) ||
            !type_of(&base, &original) ||
            !materialize(c, r.loc, &address, sizeof(address)))
          continue;
      } else if (r.loc.kind != (memory ? LOC_NUMBER : LOC_REGISTER))
        continue;
      if (memory ? location < address : location != address)
        continue;
      char suffix[256];
      if (!storage_type(&original, memory ? location - address : 0, bytes,
                        &matched, suffix, sizeof(suffix)))
        continue;
      if (found)
        return false;
      int n = indirect && !reference
                  ? snprintf(name, capacity, "(*%s)%s", v->name, suffix)
                  : snprintf(name, capacity, "%s%s", v->name, suffix);
      if (n < 0 || (size_t)n >= capacity)
        return false;
      *type = matched;
      if (variable_die)
        *variable_die = v->die;
      found = true;
    }
    if (found)
      return true;
  }
  return false;
}

/* A memory operand inside a declared aggregate selects that whole object for
 * annotations. The instruction itself still uses find_storage's leaf name. */
static bool find_aggregate_storage(eval_context *c, uint64_t location,
                                   size_t byte_offset, size_t bytes,
                                   Dwarf_Die *type, Dwarf_Die *variable_die,
                                   char *name, size_t capacity,
                                   uint64_t *object_address,
                                   size_t *object_size) {
  ct_values_site *site = c->s;
  if (!site || site->error || byte_offset || !bytes || !capacity)
    return false;
  bases(c);
  for (int indirect = 0; indirect <= 1; ++indirect) {
    bool found = false;
    for (size_t i = 0; i < site->nvars; ++i) {
      variable *value = &site->vars[i];
      Dwarf_Die base, original;
      Dwarf_Attribute attribute;
      result storage;
      bool vol;
      if (!value->have_type || !peel(&value->type, &base, &vol) || vol ||
          !attr(&value->die, DW_AT_location, &attribute) ||
          !eval_attribute(c, &attribute, &storage) || storage.composite)
        continue;
      original = value->type;
      uint64_t address = storage.loc.v;
      bool reference = false;
      if (indirect) {
        int tag = dwarf_tag(&base);
        size_t width;
        reference =
            tag == DW_TAG_reference_type || tag == DW_TAG_rvalue_reference_type;
        if ((tag != DW_TAG_pointer_type && !reference) ||
            !type_size(&base, &width) || width != sizeof(address) ||
            !type_of(&base, &original) ||
            !materialize(c, storage.loc, &address, sizeof(address)) ||
            !peel(&original, &base, &vol) || vol)
          continue;
      } else if (storage.loc.kind != LOC_NUMBER)
        continue;
      int tag = dwarf_tag(&base);
      size_t width;
      if ((tag != DW_TAG_structure_type && tag != DW_TAG_class_type &&
           tag != DW_TAG_array_type) ||
          !type_size(&base, &width) || location < address ||
          location - address > width || bytes > width - (location - address))
        continue;
      if (found)
        return false;
      int length = snprintf(
          name, capacity, indirect && !reference ? "(*%s)" : "%s", value->name);
      if (length < 0 || (size_t)length >= capacity)
        return false;
      *type = original;
      *variable_die = value->die;
      *object_address = address;
      *object_size = width;
      found = true;
    }
    if (found)
      return true;
  }
  return false;
}

bool ct_values_find_name(ct_values_site *s, const ct_registers *regs,
                         ct_read_memory read, void *arg, bool memory,
                         uint64_t location, size_t byte_offset, size_t bytes,
                         char *out, size_t size) {
  if (size)
    out[0] = 0;
  eval_context c = {.s = s, .r = regs, .read = read, .arg = arg};
  Dwarf_Die type;
  bool found = find_storage(&c, memory, location, byte_offset, bytes, &type,
                            out, size, NULL);
  if (!found && size)
    out[0] = 0;
  return found;
}

typedef struct {
  ct_read_memory read;
  void *arg;
  uint64_t address;
  size_t bytes;
  const unsigned char *raw;
} operand_memory;

static bool read_outside_operand(void *arg, uint64_t address, void *out,
                                 size_t bytes) {
  operand_memory *memory = arg;
  if (memory->bytes && bytes &&
      (address >= memory->address ? address - memory->address < memory->bytes
                                  : memory->address - address < bytes))
    return false;
  return memory->read && memory->read(memory->arg, address, out, bytes);
}

/* A full aggregate may overlap an already captured operand. Copy those bytes
 * from the snapshot, never reread them after the instruction has changed them.
 * A failed operand capture remains unavailable, while siblings are readable. */
static bool read_with_operand_capture(void *arg, uint64_t address, void *out,
                                      size_t bytes) {
  operand_memory *memory = arg;
  if (bytes > UINT64_MAX - address ||
      memory->bytes > UINT64_MAX - memory->address)
    return false;
  uint64_t end = address + bytes;
  uint64_t captured_end = memory->address + memory->bytes;
  if (!memory->bytes || end <= memory->address || address >= captured_end)
    return memory->read && memory->read(memory->arg, address, out, bytes);
  if (!memory->raw)
    return false;
  size_t prefix =
      address < memory->address ? (size_t)(memory->address - address) : 0;
  uint64_t overlap = address + prefix;
  size_t count = (size_t)((end < captured_end ? end : captured_end) - overlap);
  if (prefix &&
      (!memory->read || !memory->read(memory->arg, address, out, prefix)))
    return false;
  memcpy((unsigned char *)out + prefix,
         memory->raw + (overlap - memory->address), count);
  size_t suffix = bytes - prefix - count;
  return !suffix ||
         (memory->read &&
          memory->read(memory->arg, overlap + count,
                       (unsigned char *)out + prefix + count, suffix));
}

static void describe_variable(ct_values_site *s, Dwarf_Die *variable_die,
                              Dwarf_Die *type, const char *name,
                              ct_variable_description *description) {
  if (!description)
    return;
  Dwarf_Die identity = *variable_die;
  for (unsigned depth = 0; depth < MAX_DEPTH; ++depth) {
    Dwarf_Attribute link;
    Dwarf_Die next;
    Dwarf_Attribute *origin =
        dwarf_attr(&identity, DW_AT_abstract_origin, &link);
    if (!origin)
      origin = dwarf_attr(&identity, DW_AT_specification, &link);
    if (!origin || !dwarf_formref_die(origin, &next) ||
        dwarf_dieoffset(&next) == dwarf_dieoffset(&identity))
      break;
    identity = next;
  }
  *description = (ct_variable_description){
      .module_id = s->module ? s->module->instance_id : 0,
      .die_offset = dwarf_dieoffset(&identity)};
  int n = snprintf(description->name, sizeof(description->name), "%s", name);
  if (n < 0 || (size_t)n >= sizeof(description->name)) {
    *description = (ct_variable_description){0};
    return;
  }
  buffer spelling = {description->type, sizeof(description->type), 0, false};
  if (!type || !assembly_type_name(type, "", &spelling, 0))
    description->type[0] = 0;
  else
    while (spelling.used && description->type[spelling.used - 1] == ' ')
      description->type[--spelling.used] = 0;
}

bool ct_values_describe_name(ct_values_site *s, const char *name,
                             ct_variable_description *description) {
  if (!description)
    return false;
  *description = (ct_variable_description){0};
  if (!s || s->error || !name || !name[0])
    return false;
  for (size_t index = 0; index < s->nvars; ++index) {
    variable *value = &s->vars[index];
    if (!strcmp(name, value->name)) {
      describe_variable(s, &value->die, value->have_type ? &value->type : NULL,
                        name, description);
      return description->name[0] != 0;
    }
  }
  return false;
}

bool ct_values_describe_operand(ct_values_site *s, const ct_registers *regs,
                                ct_read_memory read, void *arg, bool memory,
                                uint64_t location, size_t byte_offset,
                                size_t bytes,
                                ct_variable_description *description) {
  if (!description)
    return false;
  *description = (ct_variable_description){0};
  operand_memory captured = {.read = read,
                             .arg = arg,
                             .address = location,
                             .bytes = memory ? bytes : 0};
  eval_context c = {
      .s = s, .r = regs, .read = read_outside_operand, .arg = &captured};
  Dwarf_Die type, variable_die;
  char name[sizeof(description->name)];
  if (!regs || !find_storage(&c, memory, location, byte_offset, bytes, &type,
                             name, sizeof(name), &variable_die))
    return false;
  describe_variable(s, &variable_die, &type, name, description);
  return description->name[0] != 0;
}

bool ct_values_format_assembly_operand(
    ct_values_site *s, const ct_registers *regs, ct_read_memory read, void *arg,
    bool memory, uint64_t location, size_t byte_offset,
    const unsigned char *raw, size_t bytes, char *out, size_t size,
    ct_variable_description *description) {
  if (size)
    out[0] = 0;
  if (description)
    *description = (ct_variable_description){0};
  operand_memory captured = {.read = read,
                             .arg = arg,
                             .address = location,
                             .bytes = memory ? bytes : 0,
                             .raw = raw};
  eval_context c = {
      .s = s, .r = regs, .read = read_outside_operand, .arg = &captured};
  Dwarf_Die type, variable_die;
  char name[sizeof(((ct_variable_description *)0)->name)];
  if (!regs || !size)
    return false;
  uint64_t object_address = 0;
  size_t object_size = 0;
  bool aggregate =
      memory && find_aggregate_storage(&c, location, byte_offset, bytes, &type,
                                       &variable_die, name, sizeof(name),
                                       &object_address, &object_size);
  if (!aggregate && !find_storage(&c, memory, location, byte_offset, bytes,
                                  &type, name, sizeof(name), &variable_die))
    return false;
  if (aggregate)
    c.read = read_with_operand_capture;
  buffer output = {out, size, 0, false};
  put(&output, "%s=", name);
  value_view value = aggregate ? (value_view){.size = object_size,
                                              .address = object_address,
                                              .memory = true}
                               : (value_view){.raw = raw, .size = bytes};
  if (!format_type(&c, &output, &type, value) && !output.truncated)
    put(&output, "?");
  if (output.truncated) {
    out[0] = 0;
    return false;
  }
  describe_variable(s, &variable_die, &type, name, description);
  return true;
}

bool ct_values_format_operand(ct_values_site *s, const ct_registers *regs,
                              ct_read_memory read, void *arg, bool memory,
                              uint64_t location, size_t byte_offset,
                              const unsigned char *raw, size_t bytes, char *out,
                              size_t size) {
  if (size)
    out[0] = 0;
  operand_memory captured = {.read = read,
                             .arg = arg,
                             .address = location,
                             .bytes = memory ? bytes : 0};
  eval_context c = {
      .s = s, .r = regs, .read = read_outside_operand, .arg = &captured};
  Dwarf_Die type;
  char name[1024];
  if (!raw || !size ||
      !find_storage(&c, memory, location, byte_offset, bytes, &type, name,
                    sizeof(name), NULL))
    return false;
  buffer b = {out, size, 0, false};
  return format_named(&c, &b, name, &type,
                      (value_view){.raw = raw, .size = bytes});
}

bool ct_values_read_operand(ct_values_site *s, const ct_registers *regs,
                            ct_read_memory read, void *arg, bool memory,
                            uint64_t location, size_t byte_offset, size_t bytes,
                            char *out, size_t size) {
  if (size)
    out[0] = 0;
  eval_context c = {.s = s, .r = regs, .read = read, .arg = arg};
  Dwarf_Die type;
  char name[1024];
  unsigned char raw[NBYTE];
  if (!size || !bytes || bytes > sizeof(raw) ||
      !find_storage(&c, memory, location, byte_offset, bytes, &type, name,
                    sizeof(name), NULL))
    return false;
  item storage = {.kind = memory ? LOC_NUMBER : LOC_REGISTER, .v = location};
  if (!materialize(&c, storage, raw, bytes))
    return false;
  buffer output = {out, size, 0, false};
  return format_named(&c, &output, name, &type,
                      (value_view){.raw = raw, .size = bytes});
}

static bool scalar_value_type(Dwarf_Die *original, ct_value_type *type) {
  if (!type)
    return false;
  *type = (ct_value_type){0};
  Dwarf_Die scalar;
  bool vol;
  size_t width;
  if (!peel(original, &scalar, &vol) || vol || !type_size(&scalar, &width) ||
      !width || width > 8)
    return false;
  int tag = dwarf_tag(&scalar);
  ct_value_kind kind = CT_VALUE_UNKNOWN;
  if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
      tag == DW_TAG_rvalue_reference_type) {
    if (width == 8)
      kind = CT_VALUE_POINTER;
  } else {
    uint64_t encoding = 0;
    if (tag == DW_TAG_enumeration_type) {
      if (!uint_attr(&scalar, DW_AT_encoding, &encoding)) {
        Dwarf_Die underlying;
        if (type_of(&scalar, &underlying) && peel(&underlying, &scalar, &vol))
          uint_attr(&scalar, DW_AT_encoding, &encoding);
        if (!encoding)
          encoding = DW_ATE_signed;
      }
    } else if (tag == DW_TAG_base_type) {
      uint_attr(&scalar, DW_AT_encoding, &encoding);
    }
    if (encoding == DW_ATE_signed || encoding == DW_ATE_signed_char)
      kind = CT_VALUE_SIGNED;
    else if (encoding == DW_ATE_unsigned || encoding == DW_ATE_unsigned_char ||
             encoding == DW_ATE_UTF)
      kind = CT_VALUE_UNSIGNED;
    else if (encoding == DW_ATE_boolean)
      kind = CT_VALUE_BOOLEAN;
    else if (encoding == DW_ATE_float && (width == 4 || width == 8))
      kind = CT_VALUE_FLOAT;
  }
  if (kind == CT_VALUE_UNKNOWN)
    return false;
  *type = (ct_value_type){kind, width};
  return true;
}

bool ct_values_operand_type(ct_values_site *s, const ct_registers *regs,
                            ct_read_memory read, void *arg, bool memory,
                            uint64_t location, size_t byte_offset, size_t bytes,
                            ct_value_type *type) {
  if (!type)
    return false;
  *type = (ct_value_type){0};
  eval_context c = {.s = s, .r = regs, .read = read, .arg = arg};
  Dwarf_Die original;
  char name[1024];
  ct_value_type scalar;
  if (!find_storage(&c, memory, location, byte_offset, bytes, &original, name,
                    sizeof(name), NULL) ||
      !scalar_value_type(&original, &scalar) || scalar.bytes != bytes)
    return false;
  *type = scalar;
  return true;
}

bool ct_values_initializer_declaration(
    ct_values_site *s, const ct_registers *regs, ct_read_memory read, void *arg,
    bool memory, uint64_t location, size_t byte_offset, size_t bytes,
    const ct_initializer_source *source, char *out, size_t size) {
  if (size)
    out[0] = 0;
  if (!s || !s->module || !s->module->dw || !regs || !size || !source ||
      !source->valid || !source->line)
    return false;
  operand_memory captured = {.read = read, .arg = arg};
  char name[1024];
  ct_value_type scalar;
  if (!ct_values_find_name(s, regs, read_outside_operand, &captured, memory,
                           location, byte_offset, bytes, name, sizeof(name)) ||
      !ct_values_operand_type(s, regs, read_outside_operand, &captured, memory,
                              location, byte_offset, bytes, &scalar) ||
      (scalar.kind != CT_VALUE_SIGNED && scalar.kind != CT_VALUE_UNSIGNED &&
       scalar.kind != CT_VALUE_BOOLEAN))
    return false;
  eval_context context = {
      .s = s, .r = regs, .read = read_outside_operand, .arg = &captured};
  bases(&context);
  for (size_t index = 0; index < s->nvars; ++index) {
    variable *v = &s->vars[index];
    if (v->global || !v->have_type || strcmp(name, v->name) ||
        dwarf_tag(&v->die) != DW_TAG_variable ||
        bool_attr(&v->die, DW_AT_external))
      continue;
    Dwarf_Attribute attribute;
    result storage;
    size_t variable_bytes = 0;
    if (!type_size(&v->type, &variable_bytes) || variable_bytes != bytes ||
        byte_offset || !attr(&v->die, DW_AT_location, &attribute) ||
        !eval_attribute(&context, &attribute, &storage) || storage.composite ||
        storage.loc.kind != (memory ? LOC_NUMBER : LOC_REGISTER) ||
        storage.loc.v != location)
      continue;
    uint64_t declaration_line = 0, declaration_file = 0;
    Dwarf_Die cu;
    if (!dwarf_diecu(&v->die, &cu, NULL, NULL) ||
        dwarf_dieoffset(&cu) != source->cu_die_offset ||
        !uint_attr(&v->die, DW_AT_decl_file, &declaration_file) ||
        !uint_attr(&v->die, DW_AT_decl_line, &declaration_line) ||
        declaration_file != source->file_index ||
        declaration_line != source->line)
      return false;
    // Only frame-backed memory or register storage establishes an automatic
    // local here. Static/TLS addresses and unfamiliar expressions retain an
    // assignment without claiming a declaration.
    if (memory) {
      Dwarf_Op *operations[2];
      size_t counts[2];
      if (dwarf_getlocation_addr(&attribute, s->pc, operations, counts, 2) != 1)
        return false;
      bool frame_backed = false;
      for (size_t op = 0; op < counts[0]; ++op) {
        const Dwarf_Op *operation = &operations[0][op];
        switch (operation->atom) {
        case DW_OP_fbreg:
        case DW_OP_call_frame_cfa:
        case DW_OP_breg6:
        case DW_OP_breg7:
          frame_backed = true;
          break;
        case DW_OP_bregx:
          frame_backed |= operation->number == 6 || operation->number == 7;
          break;
        case DW_OP_addr:
        case DW_OP_addrx:
        case DW_OP_GNU_addr_index:
        case DW_OP_form_tls_address:
        case DW_OP_GNU_push_tls_address:
          return false;
        }
      }
      if (!frame_backed)
        return false;
    }
    Dwarf_Die type = v->type;
    const char *type_name = NULL;
    bool is_enum = false, is_const = false;
    for (unsigned depth = 0; depth < MAX_DEPTH; ++depth) {
      int tag = dwarf_tag(&type);
      if (tag == DW_TAG_typedef || tag == DW_TAG_base_type ||
          tag == DW_TAG_enumeration_type) {
        type_name = die_name(&type);
        is_enum = tag == DW_TAG_enumeration_type;
        break;
      }
      if (tag != DW_TAG_const_type && tag != DW_TAG_restrict_type)
        return false;
      is_const |= tag == DW_TAG_const_type;
      Dwarf_Die next;
      if (!type_of(&type, &next))
        return false;
      type = next;
    }
    if (!type_name || !type_name[0] || strpbrk(type_name, "\r\n\t"))
      return false;
    int written = snprintf(out, size, "%s%s%s %s", is_const ? "const " : "",
                           is_enum ? "enum " : "", type_name, name);
    if (written < 0 || (size_t)written >= size) {
      out[0] = 0;
      return false;
    }
    return true;
  }
  return false;
}

/* Scalars need no aggregate classification: each consumes one INTEGER or SSE
 * argument slot. Refuse all other types before assigning subsequent slots. */
static bool abi_scalar(Dwarf_Die *original, size_t *bytes, bool *sse) {
  Dwarf_Die type;
  bool vol;
  if (!peel(original, &type, &vol) || vol || !type_size(&type, bytes) ||
      !*bytes || *bytes > 8)
    return false;
  *sse = false;
  int tag = dwarf_tag(&type);
  if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
      tag == DW_TAG_rvalue_reference_type)
    return *bytes == 8;
  if (tag == DW_TAG_enumeration_type)
    return true;
  uint64_t encoding;
  if (tag != DW_TAG_base_type || !uint_attr(&type, DW_AT_encoding, &encoding))
    return false;
  if (encoding == DW_ATE_float) {
    *sse = true;
    return *bytes == 4 || *bytes == 8;
  }
  return encoding == DW_ATE_signed || encoding == DW_ATE_signed_char ||
         encoding == DW_ATE_unsigned || encoding == DW_ATE_unsigned_char ||
         encoding == DW_ATE_boolean || encoding == DW_ATE_UTF;
}

static bool function_entry_at(Dwarf_Die *function, Dwarf_Addr pc) {
  Dwarf_Addr entry;
  if (dwarf_entrypc(function, &entry) == 0)
    return entry == pc;
  if (dwarf_hasattr(function, DW_AT_entry_pc) ||
      dwarf_hasattr(function, DW_AT_low_pc))
    return false;
  /* Split hot/cold functions can describe their entry only through ranges.
   * Preserve the declared order: the cold range may have a lower address.
   * A malformed explicit entry must not become a guessed range entry. */
  Dwarf_Addr base, end;
  return dwarf_ranges(function, 0, &base, &entry, &end) > 0 && entry < end &&
         entry == pc;
}

static ct_function *prepare_function(ct_values_module *m, uint64_t runtime_pc) {
  ct_function *fn = calloc(1, sizeof(*fn));
  if (!fn)
    return NULL;
  fn->site.module = m;
  if (!m || !m->dw) {
    fn->error = "function DWARF unavailable";
    return fn;
  }
  fn->site.pc = runtime_pc - m->bias;
  Dwarf_Die cu, die, *scopes = NULL;
  bool have_cu = find_cu(m, fn->site.pc, &cu);
  int count = have_cu ? find_scopes(&cu, fn->site.pc, &scopes) : 0;
  bool found = false;
  for (int i = 0; i < count; ++i) {
    if (dwarf_tag(&scopes[i]) == DW_TAG_subprogram &&
        function_entry_at(&scopes[i], fn->site.pc)) {
      die = scopes[i];
      found = true;
      break;
    }
  }
  free(scopes);
  if (!found && have_cu) {
    /* An entry instruction can belong to an inline child whose PC scope
     * chain omits the physical function. Recover only an unambiguous real
     * subprogram whose entry address is exactly the requested call target. */
    scope_query query = {.pc = fn->site.pc};
    if (dwarf_getfuncs(&cu, match_function, &query, 0) >= 0 && query.found &&
        !query.ambiguous && dwarf_tag(&query.function) == DW_TAG_subprogram &&
        function_entry_at(&query.function, fn->site.pc)) {
      die = query.function;
      found = true;
    }
  }
  if (!found) {
    fn->error = "function entry/type unavailable";
    return fn;
  }
  fn->declaration = die;
  uint64_t convention;
  if (uint_attr(&die, DW_AT_calling_convention, &convention) &&
      convention != DW_CC_normal) {
    fn->error = "unsupported calling convention";
    return fn;
  }
  Dwarf_Attribute return_attribute;
  fn->is_void = !attr(&die, DW_AT_type, &return_attribute);
  if (!fn->is_void) {
    bool sse;
    if (!type_of(&die, &fn->return_type) ||
        !abi_scalar(&fn->return_type, &fn->return_bytes, &sse)) {
      fn->return_error =
          "unsupported return ABI (aggregate or non-scalar type)";
      /* An unsupported return can introduce a hidden structure-return pointer.
       */
      fn->argument_error = "unsupported return ABI affects argument locations";
    } else {
      const Dwarf_Op *ops = NULL;
      int n = dwfl_module_return_value_location(m->module, &die, &ops);
      if (n <= 0 || n > MAX_OPS)
        fn->return_error = "return location unavailable";
      else {
        fn->return_ops = malloc((size_t)n * sizeof(*ops));
        if (!fn->return_ops)
          fn->return_error = "return metadata allocation failed";
        else {
          memcpy(fn->return_ops, ops, (size_t)n * sizeof(*ops));
          fn->return_count = (size_t)n;
        }
      }
    }
  }
  if (fn->argument_error)
    return fn;
  /* AMD64 DWARF numbers for rdi,rsi,rdx,rcx,r8,r9; SSE slots are xmm0..7. */
  static const unsigned integer_registers[] = {5, 4, 1, 2, 8, 9};
  unsigned integers = 0, vectors = 0;
  uint64_t stack_offset = 8; /* Entry RSP points to the return address. */
  Dwarf_Die child;
  if (dwarf_child(&die, &child) == 0) {
    do {
      int tag = dwarf_tag(&child);
      if (tag == DW_TAG_unspecified_parameters) {
        fn->variadic = true;
        continue;
      }
      if (tag != DW_TAG_formal_parameter)
        continue;
      if (fn->count == NVAR) {
        fn->argument_error = "argument limit exceeded";
        break;
      }
      parameter value = {.die = child};
      bool sse;
      if (!type_of(&child, &value.type) ||
          !abi_scalar(&value.type, &value.bytes, &sse)) {
        fn->argument_error =
            "unsupported argument ABI (aggregate or non-scalar type)";
        break;
      }
      if (sse && vectors < 8)
        value.reg = 17 + vectors++;
      else if (!sse && integers < 6)
        value.reg = integer_registers[integers++];
      else {
        value.on_stack = true;
        value.stack_offset = stack_offset;
        stack_offset += 8;
      }
      const char *name = die_name(&child);
      if (name) {
        value.name = strdup(name);
        if (!value.name) {
          fn->argument_error = "argument metadata allocation failed";
          break;
        }
        for (char *p = value.name; *p; ++p)
          if ((unsigned char)*p < 32)
            *p = '?';
      }
      parameter *parameters =
          realloc(fn->parameters, (fn->count + 1) * sizeof(*parameters));
      if (!parameters) {
        free(value.name);
        fn->argument_error = "argument metadata allocation failed";
        break;
      }
      fn->parameters = parameters;
      fn->parameters[fn->count++] = value;
    } while (dwarf_siblingof(&child, &child) == 0);
  }
  return fn;
}

/* Error codes are part of the disk recipe, rather than addresses of the
 * diagnostic strings. Transient allocation failures are never persisted. */
static const char *const function_cache_errors[] = {
    NULL,
    "function DWARF unavailable",
    "function entry/type unavailable",
    "unsupported calling convention",
    "unsupported return ABI (aggregate or non-scalar type)",
    "unsupported return ABI affects argument locations",
    "return location unavailable",
    "argument limit exceeded",
    "unsupported argument ABI (aggregate or non-scalar type)"};

static void cache_put_error(values_cache *cache, const char *error) {
  if (!error) {
    cache_put(cache, 0);
    return;
  }
  for (size_t index = 1;
       index < sizeof(function_cache_errors) / sizeof(*function_cache_errors);
       ++index)
    if (!strcmp(error, function_cache_errors[index])) {
      cache_put(cache, index);
      return;
    }
  cache->valid = false;
}

static const char *cache_get_error(values_cache *cache) {
  uint64_t index = cache_get(cache);
  if (index >= sizeof(function_cache_errors) / sizeof(*function_cache_errors)) {
    cache->valid = false;
    return NULL;
  }
  return function_cache_errors[index];
}

static ct_function *read_function_cache(ct_values_module *m, uint64_t pc,
                                        const char *key) {
  values_cache cache = {.valid = true};
  if (!ct_analysis_cache_read("functions", key, &cache.data, &cache.size))
    return NULL;
  ct_function *fn = calloc(1, sizeof(*fn));
  if (!fn) {
    free(cache.data);
    return NULL;
  }
  fn->site.module = m;
  fn->site.pc = pc;
  uint64_t version = cache_get(&cache), stored_pc = cache_get(&cache);
  fn->error = cache_get_error(&cache);
  fn->argument_error = cache_get_error(&cache);
  fn->return_error = cache_get_error(&cache);
  uint64_t is_void = cache_get(&cache), variadic = cache_get(&cache);
  uint64_t count = cache_get(&cache);
  if (version != 1 || stored_pc != pc || is_void > 1 || variadic > 1 ||
      count > NVAR || !cache_get_die(&cache, m, &fn->declaration) ||
      !cache_get_die(&cache, m, &fn->return_type))
    goto invalid;
  fn->is_void = is_void;
  fn->variadic = variadic;
  fn->return_bytes = cache_get(&cache);
  if (fn->declaration.addr) {
    Dwarf_Addr entry;
    if (dwarf_tag(&fn->declaration) != DW_TAG_subprogram ||
        dwarf_entrypc(&fn->declaration, &entry) != 0 || entry != pc)
      goto invalid;
  } else if (!fn->error)
    goto invalid;
  if (!fn->error) {
    Dwarf_Die type;
    Dwarf_Attribute attribute;
    bool declared_void = !attr(&fn->declaration, DW_AT_type, &attribute);
    if (fn->is_void != declared_void ||
        (declared_void && (fn->return_type.addr || fn->return_bytes)))
      goto invalid;
    if (fn->return_type.addr) {
      size_t bytes = 0;
      bool sse;
      if (!type_of(&fn->declaration, &type) ||
          type.addr != fn->return_type.addr)
        goto invalid;
      bool scalar = abi_scalar(&type, &bytes, &sse);
      if (bytes != fn->return_bytes || (!scalar && !fn->return_error))
        goto invalid;
    } else if (!declared_void && !fn->return_error)
      goto invalid;
  }
  fn->parameters = count ? calloc(count, sizeof(*fn->parameters)) : NULL;
  if (count && !fn->parameters)
    goto invalid;
  for (size_t index = 0; index < count; ++index) {
    parameter *value = &fn->parameters[index];
    if (!cache_get_die(&cache, m, &value->die) || !value->die.addr ||
        dwarf_tag(&value->die) != DW_TAG_formal_parameter ||
        !cache_get_die(&cache, m, &value->type) || !value->type.addr)
      goto invalid;
    uint64_t bytes = cache_get(&cache), reg = cache_get(&cache);
    uint64_t stack_offset = cache_get(&cache), on_stack = cache_get(&cache);
    Dwarf_Die type;
    size_t actual_bytes;
    bool sse;
    if (on_stack > 1 || !type_of(&value->die, &type) ||
        type.addr != value->type.addr ||
        !abi_scalar(&type, &actual_bytes, &sse) || bytes != actual_bytes ||
        (on_stack ? (stack_offset < 8 || stack_offset > (NVAR + 1) * 8 ||
                     stack_offset % 8 != 0)
                  : (sse ? (reg < 17 || reg >= 25)
                         : (reg != 5 && reg != 4 && reg != 1 && reg != 2 &&
                            reg != 8 && reg != 9))))
      goto invalid;
    value->bytes = bytes;
    value->reg = reg;
    value->stack_offset = stack_offset;
    value->on_stack = on_stack;
    fn->count = index + 1;
    const char *name = die_name(&value->die);
    if (name) {
      value->name = strdup(name);
      if (!value->name)
        goto invalid;
      for (char *ch = value->name; *ch; ++ch)
        if ((unsigned char)*ch < 32)
          *ch = '?';
    }
  }
  if (!cache_get_operations(&cache, &fn->return_ops, &fn->return_count) ||
      !cache.valid || cache.position != cache.size)
    goto invalid;
  free(cache.data);
  return fn;
invalid:
  free(cache.data);
  ct_function_free(fn);
  return NULL;
}

static void write_function_cache(ct_function *fn, const char *key) {
  values_cache cache = {.data = malloc(MAX_VALUES_CACHE_BYTES),
                        .size = MAX_VALUES_CACHE_BYTES,
                        .valid = true};
  if (!cache.data)
    return;
  cache_put(&cache, 1);
  cache_put(&cache, fn->site.pc);
  cache_put_error(&cache, fn->error);
  cache_put_error(&cache, fn->argument_error);
  cache_put_error(&cache, fn->return_error);
  cache_put(&cache, fn->is_void);
  cache_put(&cache, fn->variadic);
  cache_put(&cache, fn->count);
  cache_put_die(&cache, fn->site.module, &fn->declaration);
  cache_put_die(&cache, fn->site.module, &fn->return_type);
  cache_put(&cache, fn->return_bytes);
  for (size_t index = 0; index < fn->count; ++index) {
    parameter *value = &fn->parameters[index];
    cache_put_die(&cache, fn->site.module, &value->die);
    cache_put_die(&cache, fn->site.module, &value->type);
    cache_put(&cache, value->bytes);
    cache_put(&cache, value->reg);
    cache_put(&cache, value->stack_offset);
    cache_put(&cache, value->on_stack);
  }
  cache_put_operations(&cache, fn->return_ops, fn->return_count);
  if (cache.valid)
    ct_analysis_cache_write("functions", key, cache.data, cache.position);
  free(cache.data);
}

ct_function *ct_function_prepare(ct_values_module *m, uint64_t runtime_pc) {
  if (!m)
    return prepare_function(m, runtime_pc);
  uint64_t pc = runtime_pc - m->bias;
  prepared_values *entry = prepared_at(m, pc);
  if (entry && entry->function) {
    ++entry->function->references;
    return entry->function;
  }
  char *key = prepared_key(m, pc);
  ct_function *fn = key && m->dw ? read_function_cache(m, pc, key) : NULL;
  if (!fn) {
    fn = prepare_function(m, runtime_pc);
    if (fn && key && m->dw)
      write_function_cache(fn, key);
  }
  free(key);
  if (fn && entry &&
      (!fn->return_error || !strstr(fn->return_error, "allocation failed")) &&
      (!fn->argument_error ||
       !strstr(fn->argument_error, "allocation failed"))) {
    fn->references = 2;
    entry->function = fn;
  }
  return fn;
}

bool ct_function_parameters(ct_function *fn, ct_function_parameter *out,
                            size_t capacity, size_t *count, bool *variadic) {
  if (count)
    *count = 0;
  if (variadic)
    *variadic = false;
  if (!fn || !count || !variadic || fn->error || fn->argument_error ||
      !fn->declaration.addr || (!out && capacity) ||
      (out && fn->count > capacity))
    return false;
  ct_function_parameter *parameters =
      fn->count ? calloc(fn->count, sizeof(*parameters)) : NULL;
  if (fn->count && !parameters)
    return false;
  for (size_t index = 0; index < fn->count; ++index) {
    parameter *source = &fn->parameters[index];
    ct_function_parameter *target = &parameters[index];
    if (!scalar_value_type(&source->type, &target->type) ||
        target->type.bytes != source->bytes ||
        (source->bytes != 1 && source->bytes != 2 && source->bytes != 4 &&
         source->bytes != 8) ||
        (source->name && strlen(source->name) >= sizeof(target->name))) {
      free(parameters);
      return false;
    }
    if (source->name)
      memcpy(target->name, source->name, strlen(source->name) + 1);
    buffer spelling = {target->type_name, sizeof(target->type_name), 0, false};
    if (!assembly_type_name(&source->type, "", &spelling, 0) ||
        spelling.truncated) {
      free(parameters);
      return false;
    }
    target->reg = source->reg;
    target->stack_offset = source->stack_offset;
    target->on_stack = source->on_stack;
  }
  if (out && fn->count)
    memcpy(out, parameters, fn->count * sizeof(*out));
  free(parameters);
  *count = fn->count;
  *variadic = fn->variadic;
  return true;
}

bool ct_function_return_type(ct_function *fn, ct_value_type *type,
                             bool *is_void, char *spelling, size_t capacity) {
  if (type)
    *type = (ct_value_type){0};
  if (is_void)
    *is_void = false;
  if (spelling && capacity)
    spelling[0] = 0;
  if (!fn || !type || !is_void || !spelling || !capacity || fn->error ||
      fn->return_error)
    return false;
  if (fn->is_void) {
    if (capacity < sizeof("void"))
      return false;
    memcpy(spelling, "void", sizeof("void"));
    *is_void = true;
    return true;
  }
  ct_value_type scalar;
  if (!scalar_value_type(&fn->return_type, &scalar) ||
      scalar.bytes != fn->return_bytes ||
      (scalar.bytes != 1 && scalar.bytes != 2 && scalar.bytes != 4 &&
       scalar.bytes != 8) ||
      fn->return_count != 1)
    return false;
  /* Only one low scalar register is consumed by the caller. Reject pieces,
   * hidden result pointers and architecture-specific return expressions. */
  const Dwarf_Op *location = fn->return_ops;
  unsigned expected = scalar.kind == CT_VALUE_FLOAT ? 17 : 0;
  if (!location ||
      !((location->atom == DW_OP_reg0 + expected) ||
        (location->atom == DW_OP_regx && location->number == expected)))
    return false;
  buffer text = {spelling, capacity, 0, false};
  if (!assembly_type_name(&fn->return_type, "", &text, 0)) {
    text.used = 0;
    text.truncated = false;
    spelling[0] = 0;
    put(&text, "?");
  }
  if (text.truncated) {
    spelling[0] = 0;
    return false;
  }
  *type = scalar;
  return true;
}

bool ct_function_return_unsupported(ct_function *fn) {
  if (!fn || fn->error || fn->is_void || !fn->return_type.addr)
    return false;
  ct_value_type scalar;
  if (fn->return_error || !scalar_value_type(&fn->return_type, &scalar) ||
      (scalar.bytes != 1 && scalar.bytes != 2 && scalar.bytes != 4 &&
       scalar.bytes != 8) ||
      fn->return_count != 1 || !fn->return_ops)
    return true;
  unsigned expected = scalar.kind == CT_VALUE_FLOAT ? 17 : 0;
  return fn->return_ops->atom != DW_OP_reg0 + expected &&
         !(fn->return_ops->atom == DW_OP_regx &&
           fn->return_ops->number == expected);
}

static bool function_type_name(Dwarf_Die *original, char *out, size_t size) {
  Dwarf_Die type, pointee;
  bool vol;
  if (!peel(original, &type, &vol) || !size)
    return false;
  int tag = dwarf_tag(&type);
  const char *name = die_name(&type);
  if (tag == DW_TAG_pointer_type || tag == DW_TAG_reference_type ||
      tag == DW_TAG_rvalue_reference_type) {
    if (!type_of(&type, &pointee))
      return false;
    char nested[256];
    if (!function_type_name(&pointee, nested, sizeof(nested)))
      return false;
    return snprintf(out, size, "%s *", nested) > 0;
  }
  if (!name || !name[0]) {
    if (tag == DW_TAG_structure_type)
      name = "struct";
    else if (tag == DW_TAG_class_type)
      name = "class";
    else if (tag == DW_TAG_subroutine_type)
      name = "function";
    else
      name = "void";
  }
  return snprintf(out, size, "%s", name) > 0;
}

bool ct_function_pointer_type(ct_function *fn, char *out, size_t size) {
  if (!fn || !out || !size || fn->error || fn->argument_error ||
      (!fn->is_void && !fn->return_type.addr))
    return false;
  char return_name[256] = "void";
  if (!fn->is_void &&
      !function_type_name(&fn->return_type, return_name, sizeof(return_name)))
    return false;
  int used = snprintf(out, size, "%s (*)(", return_name);
  if (used < 0 || (size_t)used >= size)
    return false;
  for (size_t index = 0; index < fn->count; ++index) {
    char parameter_type[256];
    if (!function_type_name(&fn->parameters[index].type, parameter_type,
                            sizeof(parameter_type)))
      return false;
    int written =
        snprintf(out + used, size - (size_t)used, "%s%s%s", index ? ", " : "",
                 parameter_type, fn->parameters[index].name ? " " : "");
    if (written < 0 || (size_t)written >= size - (size_t)used)
      return false;
    used += written;
    if (fn->parameters[index].name) {
      written = snprintf(out + used, size - (size_t)used, "%s",
                         fn->parameters[index].name);
      if (written < 0 || (size_t)written >= size - (size_t)used)
        return false;
      used += written;
    }
  }
  if (fn->variadic) {
    int written = snprintf(out + used, size - (size_t)used, "%s...",
                           fn->count ? ", " : "");
    if (written < 0 || (size_t)written >= size - (size_t)used)
      return false;
    used += written;
  }
  return snprintf(out + used, size - (size_t)used, ")") >= 0;
}

bool ct_function_declaration(ct_function *fn, const char *display_name,
                             char *out, size_t size) {
  if (!out || !size)
    return false;
  out[0] = 0;
  if (!fn || fn->error || !fn->declaration.addr || !display_name ||
      !display_name[0] || strpbrk(display_name, "\r\n\t"))
    return false;
  buffer declaration = {out, size, 0, false};
  if (!assembly_type_name(&fn->declaration, display_name, &declaration, 0) ||
      declaration.truncated) {
    out[0] = 0;
    return false;
  }
  return true;
}

void ct_function_free(ct_function *fn) {
  if (!fn || (fn->references && --fn->references))
    return;
  for (size_t i = 0; i < fn->count; ++i)
    free(fn->parameters[i].name);
  free(fn->parameters);
  free(fn->return_ops);
  free(fn);
}

bool ct_function_argument_names(ct_function *fn, char *out, size_t size) {
  if (!out || !size)
    return false;
  out[0] = 0;
  if (!fn || fn->error)
    return false;
  buffer names = {out, size, 0, false};
  for (size_t index = 0; index < fn->count; ++index) {
    const char *name = fn->parameters[index].name;
    if (name && *name)
      put(&names, "%s%s", names.used ? ", " : "", name);
  }
  if (names.truncated || (fn->argument_error && !names.used)) {
    out[0] = 0;
    return false;
  }
  return true;
}

bool ct_function_describe_parameter(ct_function *fn, const char *name,
                                    ct_variable_description *description) {
  if (!description)
    return false;
  *description = (ct_variable_description){0};
  if (!fn || fn->error || !name || !name[0])
    return false;
  for (size_t index = 0; index < fn->count; ++index) {
    parameter *value = &fn->parameters[index];
    char unnamed[32];
    snprintf(unnamed, sizeof(unnamed), "arg%zu", index + 1);
    const char *parameter_name =
        value->name && value->name[0] ? value->name : unnamed;
    if (!strcmp(name, parameter_name)) {
      describe_variable(&fn->site, &value->die, &value->type, name,
                        description);
      return description->name[0] != 0;
    }
  }
  return false;
}

static bool format_parameter(eval_context *c, parameter *p, buffer *out,
                             bool named) {
  if (!c->r || (named && !p->name))
    return false;
  unsigned char raw[8];
  bool ok;
  if (p->on_stack) {
    ok = c->r->have_gpr && c->r->gpr[7] <= UINT64_MAX - p->stack_offset &&
         c->read &&
         c->read(c->arg, c->r->gpr[7] + p->stack_offset, raw, p->bytes);
    c->error = "stack argument unavailable";
  } else
    ok = reg_bytes(c, p->reg, raw, p->bytes);
  if (!ok)
    return false;
  value_view value = {.raw = raw, .size = p->bytes};
  if (named)
    return format_named(c, out, p->name, &p->type, value);
  return format_type(c, out, &p->type, value);
}

void ct_function_arguments(ct_function *fn, const ct_registers *regs,
                           ct_read_memory read, void *arg, char *out,
                           size_t size) {
  buffer b = {out, size, 0, false};
  if (size)
    out[0] = 0;
  if (!fn || fn->error || !regs || !size)
    return;
  eval_context c = {.s = &fn->site, .r = regs, .read = read, .arg = arg};
  for (size_t i = 0; i < fn->count; ++i)
    format_parameter(&c, &fn->parameters[i], &b, true);
}

static bool function_entry_values(ct_function *fn, const ct_registers *regs,
                                  ct_read_memory read, void *arg, bool named,
                                  char *out, size_t size) {
  if (!out || !size)
    return false;
  out[0] = 0;
  if (!fn || fn->error || !fn->declaration.addr)
    return false;
  buffer values = {out, size, 0, false};
  eval_context context = {.s = &fn->site, .r = regs, .read = read, .arg = arg};
  Dwarf_Die child;
  size_t fixed = 0, inspected = 0;
  if (dwarf_child(&fn->declaration, &child) == 0) {
    do {
      if (++inspected > NVAR) {
        out[0] = 0;
        return false;
      }
      int tag = dwarf_tag(&child);
      if (tag == DW_TAG_unspecified_parameters && !named) {
        put(&values, "%s...", values.used ? ", " : "");
        continue;
      }
      if (tag != DW_TAG_formal_parameter)
        continue;
      if (values.used)
        put(&values, ", ");
      if (named) {
        const char *name = die_name(&child);
        if (name && name[0] && !strpbrk(name, "\r\n\t"))
          put(&values, "%s=", name);
        else
          put(&values, "arg%zu=", fixed + 1);
      }
      /* Preparation retains only the prefix with proven ABI locations.
       * Preserve the remaining declared slots without guessing their ABI. */
      if (fixed >= fn->count ||
          !format_parameter(&context, &fn->parameters[fixed], &values, false))
        put(&values, "?");
      ++fixed;
    } while (dwarf_siblingof(&child, &child) == 0);
  }
  if (values.truncated) {
    out[0] = 0;
    return false;
  }
  return true;
}

bool ct_function_argument_values(ct_function *fn, const ct_registers *regs,
                                 ct_read_memory read, void *arg, char *out,
                                 size_t size) {
  return function_entry_values(fn, regs, read, arg, false, out, size);
}

bool ct_function_entry_arguments(ct_function *fn, const ct_registers *regs,
                                 ct_read_memory read, void *arg, char *out,
                                 size_t size) {
  return function_entry_values(fn, regs, read, arg, true, out, size);
}

void ct_function_arguments_selected(ct_function *fn, const ct_registers *regs,
                                    ct_read_memory read, void *arg,
                                    const char *names, size_t names_size,
                                    char *out, size_t size) {
  buffer b = {out, size, 0, false};
  if (size)
    out[0] = 0;
  if (!fn || fn->error || !regs || !size || !valid_name_list(names, names_size))
    return;
  eval_context c = {.s = &fn->site, .r = regs, .read = read, .arg = arg};
  bool shown[NVAR] = {0};
  for (size_t offset = 0; offset < names_size;
       offset += strlen(names + offset) + 1) {
    for (size_t i = 0; i < fn->count; ++i) {
      parameter *p = &fn->parameters[i];
      if (shown[i] || !p->name || strcmp(names + offset, p->name))
        continue;
      shown[i] = true;
      format_parameter(&c, p, &b, true);
      break;
    }
  }
}

void ct_function_return(ct_function *fn, const ct_registers *regs,
                        ct_read_memory read, void *arg, char *out,
                        size_t size) {
  buffer b = {out, size, 0, false};
  if (size)
    out[0] = 0;
  if (!fn || fn->error || fn->return_error || fn->is_void || !regs || !size)
    return;
  eval_context c = {.s = &fn->site, .r = regs, .read = read, .arg = arg};
  result r;
  unsigned char raw[8];
  bool ok = eval(&c, NULL, fn->return_ops, fn->return_count, &r);
  if (ok && r.composite) {
    ok = fn->return_bytes <= r.n;
    if (ok)
      memcpy(raw, r.bytes, fn->return_bytes);
    else
      c.error = "incomplete return location";
  } else if (ok)
    ok = materialize(&c, r.loc, raw, fn->return_bytes);
  if (ok) {
    format_type(&c, &b, &fn->return_type,
                (value_view){.raw = raw, .size = fn->return_bytes});
  }
}
