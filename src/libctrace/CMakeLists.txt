# SPDX-License-Identifier: MIT

# DynamoRIO adjusts directory compiler flags and per-source properties. Keep
# these changes local to the client so shared sources retain ordinary compiler
# settings when built into the analysis and kernel helpers.
add_library(
  ctrace_client SHARED
  client.cc
  backend.cc
  compiler_hooks.cc
  assembly.cc
  execution_cache.cc
  ../filter.cc
  ../c_cpp_access.cc
  location_record.cc
  decompiled_record.cc
  userspace_patch.cc
  userspace_version.cc
  userspace_version_cache.cc
  analysis_image.cc
  analysis_proxy.cc
  ../shared_objects.cc
  shared_digest.cc
  dr_shared_provider.cc
  shared_objects_runtime.cc
  output.cc
  perfetto.cc
  ../perfetto_json.cc
  perfetto_scope.cc
  timing.cc
  ../c_cpp_value_format.cc
  ../dwarf/values.cc
  signal_info.cc)

# The compiler driver accepts -fuse-ld=lld, but DynamoRIO also invokes the
# linker directly to inspect ELF linker options.
get_filename_component(CTRACE_LINKER_NAME "${CMAKE_LINKER}" NAME)
if(CTRACE_LINKER_NAME STREQUAL "lld")
  get_filename_component(CTRACE_LINKER_DIRECTORY "${CMAKE_LINKER}" DIRECTORY)
  find_program(
    CTRACE_ELF_LINKER
    NAMES ld.lld
    HINTS "${CTRACE_LINKER_DIRECTORY}" REQUIRED)
  set(CMAKE_LINKER "${CTRACE_ELF_LINKER}")
endif()

# DynamoRIO's package still probes a C driver even for C++-only clients. Supply
# dependency metadata only in this directory; ctrace enables only C++.
set(CMAKE_C_COMPILER "${DYNAMORIO_C_COMPILER}")
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_COMPILER_IS_GNUCC TRUE)
endif()
find_package(DynamoRIO CONFIG REQUIRED)
configure_dynamorio_client(ctrace_client)
use_dynamorio_extension(ctrace_client drmgr)
use_dynamorio_extension(ctrace_client drwrap)
use_dynamorio_extension(ctrace_client drbbdup)
use_dynamorio_extension(ctrace_client drreg)
# Extensions are configured before their libraries exist on a clean build.
target_include_directories(ctrace_client SYSTEM
                           PRIVATE "${DYNAMORIO_BUILD_DIR}/ext/include")

set_target_properties(
  ctrace_client
  PROPERTIES OUTPUT_NAME ctrace
             BUILD_WITH_INSTALL_RPATH ON
             INSTALL_RPATH "$ORIGIN;$ORIGIN/dynamorio/lib64/release")
target_include_directories(ctrace_client
                           PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_compile_options(ctrace_client PRIVATE -Wextra -Wno-unused-parameter)
# DynamoRIO uses the plain target_link_libraries signature for this target.
target_link_libraries(ctrace_client PkgConfig::DW PkgConfig::MD)
# Keep bundled extensions' transitive dependencies discoverable by the loader.
target_link_options(ctrace_client PRIVATE -Wl,--disable-new-dtags)
add_dependencies(ctrace_client ctrace_dynamorio)

install(TARGETS ctrace_client LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
