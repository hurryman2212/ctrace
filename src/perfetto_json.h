#ifndef CTRACE_PERFETTO_JSON_H
#define CTRACE_PERFETTO_JSON_H

#include <string>

// Escape both UTF-8 text and arbitrary Linux path bytes into valid JSON.
std::string ct_perfetto_json_string(const char *text);

#endif
