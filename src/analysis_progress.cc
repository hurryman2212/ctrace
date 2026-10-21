// SPDX-License-Identifier: MIT

#include "analysis.hh"

static void (*progress_callback)(const ct_analysis_progress *, void *);
static void *progress_context;

void ct_analysis_set_progress_callback(
    void (*callback)(const ct_analysis_progress *, void *), void *context) {
  progress_callback = callback;
  progress_context = context;
}

void ct_analysis_report_progress(const ct_analysis_progress *progress) {
  if (progress_callback)
    progress_callback(progress, progress_context);
}
