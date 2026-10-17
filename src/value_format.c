#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "values.h"

/* Bound application reads and recursive metadata traversal for each value. */
enum { FORMAT_DEPTH = 64 };
static const size_t format_bytes = 65536, format_nodes = 4096;

static bool scalar_type_valid(const ct_value_type *type,
                              const unsigned char *raw, size_t bytes) {
  return type && raw && bytes && bytes <= 8 && bytes == type->bytes &&
         type->kind >= CT_VALUE_UNKNOWN && type->kind <= CT_VALUE_POINTER &&
         (type->kind != CT_VALUE_POINTER || bytes == 8) &&
         (type->kind != CT_VALUE_FLOAT || bytes == 4 || bytes == 8);
}

int ct_values_format_scalar(const ct_value_type *type, const unsigned char *raw,
                            size_t bytes, char *out, size_t size) {
  if ((!out && size) || !scalar_type_valid(type, raw, bytes))
    return -1;
  uint64_t value = 0;
  memcpy(&value, raw, bytes);
  switch (type->kind) {
  case CT_VALUE_SIGNED:
    if (bytes < 8 && (value & (UINT64_C(1) << (8 * bytes - 1))))
      value |= UINT64_MAX << (8 * bytes);
    return snprintf(out, size, "%" PRId64, (int64_t)value);
  case CT_VALUE_UNSIGNED:
    return snprintf(out, size, "%" PRIu64, value);
  case CT_VALUE_BOOLEAN:
    return snprintf(out, size, "%s", value ? "true" : "false");
  case CT_VALUE_POINTER:
  case CT_VALUE_UNKNOWN:
    return snprintf(out, size, "0x%" PRIx64, value);
  case CT_VALUE_FLOAT:
    if (bytes == 4) {
      float floating;
      memcpy(&floating, raw, sizeof(floating));
      return snprintf(out, size, "%.9g", (double)floating);
    } else {
      double floating;
      memcpy(&floating, raw, sizeof(floating));
      return snprintf(out, size, "%.17g", floating);
    }
  }
  return -1;
}

bool ct_values_format_typed(const char *name, const ct_value_type *type,
                            const unsigned char *raw, size_t bytes, char *out,
                            size_t size) {
  if (out && size)
    out[0] = 0;
  if (!name || !name[0] || !out || !size ||
      !scalar_type_valid(type, raw, bytes))
    return false;
  const int prefix = snprintf(out, size, "%s=", name);
  if (prefix < 0 || (size_t)prefix >= size) {
    out[0] = 0;
    return false;
  }
  const int written =
      ct_values_format_scalar(type, raw, bytes, out + prefix, size - prefix);
  if (written < 0 || (size_t)written >= size - (size_t)prefix) {
    out[0] = 0;
    return false;
  }
  return true;
}

typedef struct {
  const ct_value_provider *provider;
  ct_read_memory read;
  void *arg;
  size_t bytes_left, nodes_left, path_size;
  struct {
    uint64_t address;
    const void *type;
    unsigned dimension;
  } path[FORMAT_DEPTH];
} format_context;

static void put(ct_value_buffer *b, const char *fmt, ...) {
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
static bool read_value(format_context *c, ct_value_view value, void *out,
                       size_t size) {
  if (size > value.size)
    return false;
  if (value.raw) {
    memcpy(out, value.raw, size);
    return true;
  }
  if (!value.memory || !c->read || size > c->bytes_left ||
      size > UINT64_MAX - value.address)
    return false;
  c->bytes_left -= size;
  return c->read(c->arg, value.address, out, size);
}

static bool member_view(ct_value_view object, size_t offset,
                        ct_value_view *member) {
  if (offset >= object.size ||
      (object.memory && offset > UINT64_MAX - object.address))
    return false;
  *member = object;
  member->size -= offset;
  if (member->raw)
    member->raw += offset;
  if (member->memory)
    member->address += offset;
  return true;
}

static bool format_scalar(ct_value_buffer *out, const ct_value_type *type,
                          const unsigned char *raw, size_t bytes) {
  const size_t available = out->used < out->size ? out->size - out->used : 0;
  const int written = ct_values_format_scalar(
      type, raw, bytes, available ? out->p + out->used : NULL, available);
  if (written < 0)
    return false;
  if ((size_t)written >= available) {
    if (out->size)
      out->used = out->size - 1;
    out->truncated = true;
  } else {
    out->used += (size_t)written;
  }
  return !out->truncated;
}

static bool format_value(format_context *c, ct_value_buffer *out,
                         ct_value_format_ref ref, ct_value_view value,
                         size_t depth) {
  ct_value_buffer initial = *out;
  if (!c->nodes_left)
    return false;
  --c->nodes_left;
  ct_value_layout_node shape;
  ct_value_format_ref element;
  if (!c->provider->shape(c->provider->arg, &ref, &shape, &element))
    return false;
  if (value.size > shape.bytes)
    value.size = shape.bytes;
  bool array = shape.kind == CT_LAYOUT_ARRAY;
  if (array || shape.kind == CT_LAYOUT_STRUCT) {
    if (depth >= FORMAT_DEPTH || !c->nodes_left || !c->bytes_left) {
      put(out, "%s", array ? "[...]" : "{...}");
      goto finish;
    }
    const void *identity = ref.identity;
    if (value.memory) {
      for (size_t i = 0; i < c->path_size; ++i)
        if (c->path[i].address == value.address &&
            c->path[i].type == identity &&
            c->path[i].dimension == ref.dimension) {
          put(out, "0x%" PRIx64, value.address);
          goto finish;
        }
      c->path[c->path_size].address = value.address;
      c->path[c->path_size].type = identity;
      c->path[c->path_size++].dimension = ref.dimension;
    }
    /* Reserve balanced closing syntax and an explicit budget marker. */
    size_t capacity = out->size;
    if (out->used + 8 >= capacity) {
      if (value.memory)
        --c->path_size;
      out->truncated = true;
      goto omit;
    }
    put(out, "%c", array ? '[' : '{');
    out->size -= 6;
    size_t n = 0;
    bool more = !shape.complete;
    ct_value_format_ref cursor = {0};
    for (size_t index = 0;; ++index) {
      ct_value_format_ref member_type = {0};
      const char *name = NULL;
      size_t offset = 0;
      bool available = true;
      if (array) {
        if (index >= shape.element_count)
          break;
        member_type = element;
        available =
            shape.element_stride && index <= SIZE_MAX / shape.element_stride;
        if (available)
          offset = index * shape.element_stride;
      } else {
        ct_value_format_member member = {0};
        ct_value_member_status status =
            c->provider->member(c->provider->arg, ref, index, &cursor, &member);
        if (status == CT_VALUE_MEMBER_END)
          break;
        if (status == CT_VALUE_MEMBER_SKIP)
          continue;
        if (status != CT_VALUE_MEMBER_ITEM) {
          more = true;
          break;
        }
        member_type = member.type;
        name = member.name;
        offset = member.offset;
        available = member.available;
      }
      if (!c->nodes_left || !c->bytes_left) {
        more = true;
        break;
      }
      ct_value_view member = {0};
      available = available && member_view(value, offset, &member);
      ct_value_buffer previous = *out;
      if (n)
        put(out, ", ");
      if (name && name[0])
        put(out, "%s=", name);
      if (!available || !format_value(c, out, member_type, member, depth + 1)) {
        if (out->truncated) {
          *out = previous;
          out->p[out->used] = 0;
          more = true;
          break;
        }
        put(out, "?");
      }
      if (out->truncated) {
        *out = previous;
        out->p[out->used] = 0;
        more = true;
        break;
      }
      ++n;
    }
    out->size = capacity;
    if (more)
      put(out, "%s...", n ? ", " : "");
    put(out, "%c", array ? ']' : '}');
    if (value.memory)
      --c->path_size;
    goto finish;
  }
  if (shape.kind != CT_LAYOUT_SCALAR && shape.kind != CT_LAYOUT_POINTER)
    return false;
  unsigned char raw[8];
  if (!shape.bytes || shape.bytes > sizeof(raw) ||
      !read_value(c, value, raw, shape.bytes))
    return false;
  if (shape.kind == CT_LAYOUT_POINTER) {
    if (shape.bytes != 8)
      return false;
    uint64_t address;
    memcpy(&address, raw, sizeof(address));
    ct_value_layout_node target_shape;
    ct_value_format_ref ignored;
    if (address && depth < FORMAT_DEPTH && c->nodes_left && c->bytes_left &&
        c->provider->shape(c->provider->arg, &element, &target_shape,
                           &ignored) &&
        (target_shape.kind == CT_LAYOUT_STRUCT ||
         target_shape.kind == CT_LAYOUT_ARRAY)) {
      ct_value_view target = {
          .size = target_shape.bytes, .address = address, .memory = true};
      if (format_value(c, out, element, target, depth + 1))
        goto finish;
      *out = initial;
      if (out->size)
        out->p[out->used] = 0;
    }
    put(out, "0x%" PRIx64, address);
  } else if (shape.kind != CT_LAYOUT_SCALAR ||
             !format_scalar(out, &shape.scalar, raw, shape.bytes))
    return false;
finish:
  if (!out->truncated && out->used > initial.used)
    return true;
omit:
  initial.truncated = initial.truncated || out->truncated;
  *out = initial;
  if (out->size)
    out->p[out->used] = 0;
  return false;
}

bool ct_values_format_object(const ct_value_provider *provider,
                             ct_value_format_ref type, ct_value_view value,
                             ct_read_memory read, void *arg,
                             ct_value_buffer *out) {
  if (!provider || !provider->shape || !provider->member || !out || !out->p ||
      !out->size || out->used >= out->size || out->truncated)
    return false;
  format_context context = {.provider = provider,
                            .read = read,
                            .arg = arg,
                            .bytes_left = format_bytes,
                            .nodes_left = format_nodes};
  return format_value(&context, out, type, value, 0);
}

static bool layout_shape(const void *arg, ct_value_format_ref *ref,
                         ct_value_layout_node *shape,
                         ct_value_format_ref *element) {
  const ct_value_layout *layout = arg;
  if (!ref->id || ref->id > layout->type_count || !layout->types)
    return false;
  *shape = layout->types[ref->id - 1];
  ref->identity = &layout->types[ref->id - 1];
  *element = (ct_value_format_ref){.id = shape->element_type};
  return !shape->guarded;
}

static ct_value_member_status
layout_member(const void *arg, ct_value_format_ref ref, size_t index,
              ct_value_format_ref *cursor, ct_value_format_member *member) {
  const ct_value_layout *layout = arg;
  (void)cursor;
  if (!ref.id || ref.id > layout->type_count || !layout->types)
    return CT_VALUE_MEMBER_INVALID;
  const ct_value_layout_node *shape = &layout->types[ref.id - 1];
  if (index >= shape->member_count)
    return CT_VALUE_MEMBER_END;
  if (!layout->members || shape->first_member > layout->member_count ||
      index >= layout->member_count - shape->first_member)
    return CT_VALUE_MEMBER_INVALID;
  const ct_value_layout_member *source =
      &layout->members[shape->first_member + index];
  member->type = (ct_value_format_ref){.id = source->type};
  member->name =
      memchr(source->name, 0, sizeof(source->name)) ? source->name : "?";
  member->offset = source->offset;
  member->available = source->available;
  return CT_VALUE_MEMBER_ITEM;
}

bool ct_values_format_layout(const char *name, const ct_value_layout *layout,
                             uint32_t type_id, const unsigned char *raw,
                             size_t bytes, uint64_t address, bool memory,
                             ct_read_memory read, void *arg, char *out,
                             size_t size) {
  if (out && size)
    out[0] = 0;
  if (!name || !name[0] || !layout || !type_id ||
      type_id > layout->type_count || !layout->types || !out || !size)
    return false;
  const ct_value_provider provider = {
      .arg = layout, .shape = layout_shape, .member = layout_member};
  ct_value_buffer output = {out, size, 0, false};
  put(&output, "%s=", name);
  ct_value_view value = {
      .raw = raw, .size = bytes, .address = address, .memory = memory};
  if (!ct_values_format_object(&provider, (ct_value_format_ref){.id = type_id},
                               value, read, arg, &output)) {
    if (output.truncated) {
      out[0] = 0;
      return false;
    }
    put(&output, "?");
  }
  if (output.truncated) {
    out[0] = 0;
    return false;
  }
  return true;
}
