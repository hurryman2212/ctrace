# SPDX-License-Identifier: MIT

# Sources shared by the standalone analysis and kernel preparation programs.
set(PROJECT_LIBRARIES clang-cpp LLVM)

# Declare project for this scope.
project(${ROOT_PROJECT_NAME}_tools LANGUAGES CXX)

add_library(
  ctrace_common OBJECT
  shared_objects_digest.cc
  analysis_progress.cc
  analysis_files.cc
  cache.cc
  c_cpp_source.cc
  c_cpp_access.cc
  c/source.cc
  cpp/source.cc
  dwarf/language.cc
  flow.cc
  decompile_view.cc)
target_include_directories(ctrace_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(ctrace_common SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_link_libraries(ctrace_common PUBLIC ${PROJECT_LIBRARIES})
target_compile_options(ctrace_common PRIVATE -Wextra -Wno-unused-parameter)

add_subdirectory(ctrace_analyze)
add_subdirectory(ctrace_kernel)

# DynamoRIO compiler adjustments stay isolated from the helper targets.
add_subdirectory(libctrace)
