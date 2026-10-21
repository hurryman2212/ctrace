# SPDX-License-Identifier: MIT

add_executable(
  ctrace_kernel
  kernel.cc
  image.cc
  object.cc
  sign.cc
  rewrite.cc
  gate.cc
  interrupt.cc
  copies.cc
  prepare.cc
  prepare_validate.cc
  trace.cc
  policy.cc
  ../dwarf/kernel_source.cc
  source_flow.cc
  ../dwarf/kernel_values.cc
  ../dwarf/kernel_capture.cc
  capture.cc
  decompile.cc
  decompile_image.cc
  decompile_transport.cc
  flow.cc
  perfetto.cc
  ../c_cpp_value_format.cc
  ../perfetto_json.cc
  load.cc
  lifetime.cc
  guardian.cc
  ../filter.cc)
target_link_libraries(ctrace_kernel PRIVATE ctrace_common)
target_compile_definitions(
  ctrace_kernel PRIVATE "KCTRACE_CONTRACT_HEX=\"${KCTRACE_CONTRACT_HEX}\""
                        "KCTRACE_CONTRACT_BYTES={${KCTRACE_CONTRACT_BYTES}}")
target_include_directories(ctrace_kernel SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_options(ctrace_kernel PRIVATE -Wextra -Wno-unused-parameter)

target_include_directories(
  ctrace_kernel PRIVATE "${CMAKE_SOURCE_DIR}/include"
                        "${CMAKE_SOURCE_DIR}/module/include/uapi")
target_link_libraries(ctrace_kernel PRIVATE PkgConfig::MODULE_COMPRESSION
                                            OpenSSL::Crypto)

install(TARGETS ctrace_kernel RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
