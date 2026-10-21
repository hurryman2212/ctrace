# SPDX-License-Identifier: MIT

add_executable(
  ctrace_analyze
  server.cc
  exec_resources.cc
  thread_suspend_server.cc
  ../shared_objects.cc
  shared_objects_host.cc
  shared_objects_server.cc
  ../dwarf/analysis.cc
  disassemble.cc
  decompile.cc
  decompile_provider.cc
  kernel_decompile_worker.cc)
target_link_libraries(ctrace_analyze PRIVATE ctrace_common)
target_include_directories(ctrace_analyze SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_options(ctrace_analyze PRIVATE -Wextra -Wno-unused-parameter)

target_include_directories(ctrace_analyze SYSTEM
                           PRIVATE ${DynamoRIO_INCLUDE_DIRS})
target_link_libraries(ctrace_analyze PRIVATE PkgConfig::DW)
install(TARGETS ctrace_analyze RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
