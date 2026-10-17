cmake_minimum_required(VERSION 3.20)
project(ctrace LANGUAGES C CXX)
include(GNUInstallDirs)
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/ctrace")

set(CTRACE_KERNEL_OUTPUT "${CTRACE_OUTPUT_DIR}")
if(NOT CTRACE_KERNEL_OUTPUT)
  set(CTRACE_KERNEL_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}")
endif()
foreach(CTRACE_KERNEL_SOURCE target.c target.h)
  configure_file(
    "module/${CTRACE_KERNEL_SOURCE}"
    "${CTRACE_KERNEL_OUTPUT}/lib/ctrace/kernel/${CTRACE_KERNEL_SOURCE}"
    COPYONLY)
endforeach()
configure_file(include/uapi/kctrace.h
               "${CTRACE_KERNEL_OUTPUT}/lib/ctrace/kernel/kctrace.h" COPYONLY)
file(MAKE_DIRECTORY "${CTRACE_KERNEL_OUTPUT}/bin")
file(CREATE_LINK "../lib/ctrace/kernel"
     "${CTRACE_KERNEL_OUTPUT}/bin/ctrace_kernel_data" SYMBOLIC)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      Release
      CACHE STRING "Build type" FORCE)
endif()

find_package(LLVM CONFIG REQUIRED)
find_package(Clang CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
pkg_check_modules(DW REQUIRED IMPORTED_TARGET libdw libelf)
# libmd-dev supplies the small local SHA-256 implementation used by runtime
# publication callbacks, where starting or waiting for a helper is unsafe.
pkg_check_modules(MD REQUIRED IMPORTED_TARGET libmd)
pkg_check_modules(MODULE_COMPRESSION REQUIRED IMPORTED_TARGET zlib liblzma
                  libzstd>=1.4.0)

if(NOT CTRACE_DYNAMORIO_READY)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/dynamorio/CMakeLists.txt")
    message(
      FATAL_ERROR
        "Initialize DynamoRIO first: git submodule update --init --recursive")
  endif()

  include(ExternalProject)
  # DynamoRIO's exported release targets use the RelWithDebInfo configuration.
  ExternalProject_Add(
    ctrace_dynamorio
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dynamorio"
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/dynamorio"
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=RelWithDebInfo
               -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
               -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
               -DBUILD_TESTS=OFF
               -DBUILD_SAMPLES=OFF
               -DBUILD_CLIENTS=OFF
               -DBUILD_DOCS=OFF
               -DDISABLE_DRGUI=ON
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target drrun dynamorio
                  drmgr drwrap drbbdup drreg
    BUILD_ALWAYS TRUE
    INSTALL_COMMAND "")

  ExternalProject_Add(
    ctrace_components
    DEPENDS ctrace_dynamorio
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/client"
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND "" CONFIGURE_HANDLED_BY_BUILD TRUE
    CMAKE_ARGS -DCTRACE_DYNAMORIO_READY=ON
               -DCTRACE_OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}
               -DDynamoRIO_DIR=${CMAKE_CURRENT_BINARY_DIR}/dynamorio/cmake
               -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
               -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
               -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
               -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
               -DCMAKE_EXPORT_COMPILE_COMMANDS=${CMAKE_EXPORT_COMPILE_COMMANDS}
               -DCMAKE_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}
               -DCMAKE_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}
               -DLLVM_DIR=${LLVM_DIR}
               -DClang_DIR=${Clang_DIR}
    BUILD_ALWAYS TRUE
    BUILD_BYPRODUCTS
      "${CMAKE_CURRENT_BINARY_DIR}/lib/libctrace.so"
      "${CMAKE_CURRENT_BINARY_DIR}/bin/ctrace_analyze"
      "${CMAKE_CURRENT_BINARY_DIR}/bin/ctrace_kernel"
    INSTALL_COMMAND "")

  configure_file(ctrace bin/ctrace COPYONLY)
  configure_file(decompile/ctrace_decompile lib/ctrace/ctrace_decompile
                 COPYONLY)
  configure_file(decompile/CtraceDecompileServer.java
                 lib/ctrace/CtraceDecompileServer.java COPYONLY)
  file(CREATE_LINK "../lib/ctrace/ctrace_decompile"
       "${CMAKE_CURRENT_BINARY_DIR}/bin/ctrace_decompile" SYMBOLIC)
  file(RELATIVE_PATH CTRACE_DECOMPILE_LINK "${CMAKE_INSTALL_FULL_BINDIR}"
       "${CMAKE_INSTALL_FULL_LIBDIR}/ctrace/ctrace_decompile")
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/install-bin")
  file(CREATE_LINK "${CTRACE_DECOMPILE_LINK}"
       "${CMAKE_CURRENT_BINARY_DIR}/install-bin/ctrace_decompile" SYMBOLIC)
  file(RELATIVE_PATH CTRACE_KERNEL_LINK "${CMAKE_INSTALL_FULL_BINDIR}"
       "${CMAKE_INSTALL_FULL_LIBDIR}/ctrace/kernel")
  file(CREATE_LINK "${CTRACE_KERNEL_LINK}"
       "${CMAKE_CURRENT_BINARY_DIR}/install-bin/ctrace_kernel_data" SYMBOLIC)
  set(CTRACE_DRRUN_RELATIVE "../lib/dynamorio/bin64/drrun")
  configure_file(cmake/drrun.sh.in bin/drrun @ONLY)
  file(RELATIVE_PATH CTRACE_DRRUN_RELATIVE "${CMAKE_INSTALL_FULL_BINDIR}"
       "${CMAKE_INSTALL_FULL_LIBDIR}/dynamorio/bin64/drrun")
  configure_file(cmake/drrun.sh.in install-bin/drrun @ONLY)
  file(
    CHMOD
    "${CMAKE_CURRENT_BINARY_DIR}/bin/ctrace"
    "${CMAKE_CURRENT_BINARY_DIR}/lib/ctrace/ctrace_decompile"
    "${CMAKE_CURRENT_BINARY_DIR}/bin/drrun"
    "${CMAKE_CURRENT_BINARY_DIR}/install-bin/drrun"
    PERMISSIONS
    OWNER_READ
    OWNER_WRITE
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE)
  configure_file(cmake/ldconfig.cmake.in ldconfig.cmake @ONLY)
  configure_file(cmake/uninstall.cmake.in uninstall.cmake @ONLY)
  add_custom_target(
    ctrace_runtime ALL
    DEPENDS ctrace_components
    COMMAND
      ${CMAKE_COMMAND} -E make_directory
      "${CMAKE_CURRENT_BINARY_DIR}/lib/dynamorio/bin64"
      "${CMAKE_CURRENT_BINARY_DIR}/lib/dynamorio/lib64/release"
    COMMAND
      ${CMAKE_COMMAND} -E copy_if_different
      "${CMAKE_CURRENT_BINARY_DIR}/dynamorio/bin64/drrun"
      "${CMAKE_CURRENT_BINARY_DIR}/lib/dynamorio/bin64/drrun"
    COMMAND
      ${CMAKE_COMMAND} -E copy_if_different
      "${CMAKE_CURRENT_BINARY_DIR}/dynamorio/lib64/release/libdynamorio.so"
      "${CMAKE_CURRENT_BINARY_DIR}/lib/dynamorio/lib64/release/libdynamorio.so"
    COMMAND
      ${CMAKE_COMMAND} -E copy_if_different
      "${CMAKE_CURRENT_BINARY_DIR}/dynamorio/ext/lib64/release/libdrmgr.so"
      "${CMAKE_CURRENT_BINARY_DIR}/dynamorio/ext/lib64/release/libdrwrap.so"
      "${CMAKE_CURRENT_BINARY_DIR}/dynamorio/ext/lib64/release/libdrbbdup.so"
      "${CMAKE_CURRENT_BINARY_DIR}/dynamorio/ext/lib64/release/libdrreg.so"
      "${CMAKE_CURRENT_BINARY_DIR}/lib"
    VERBATIM)
  add_custom_target(
    uninstall COMMAND ${CMAKE_COMMAND} -P
                      "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake")

  install(
    PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/bin/ctrace"
             "${CMAKE_CURRENT_BINARY_DIR}/install-bin/ctrace_decompile"
             "${CMAKE_CURRENT_BINARY_DIR}/install-bin/drrun"
    DESTINATION "${CMAKE_INSTALL_BINDIR}")
  install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/client/cmake_install.cmake")
  install(
    DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib/dynamorio"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    USE_SOURCE_PERMISSIONS)
  install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/ctrace/CtraceDecompileServer.java"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/ctrace")
  install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/lib/ctrace/ctrace_decompile"
          DESTINATION "${CMAKE_INSTALL_LIBDIR}/ctrace")
  install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib/ctrace/kernel/"
          DESTINATION "${CMAKE_INSTALL_LIBDIR}/ctrace/kernel")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/install-bin/ctrace_kernel_data"
          DESTINATION "${CMAKE_INSTALL_BINDIR}")
  install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/lib/libdrmgr.so"
          "${CMAKE_CURRENT_BINARY_DIR}/lib/libdrwrap.so"
          "${CMAKE_CURRENT_BINARY_DIR}/lib/libdrbbdup.so"
          "${CMAKE_CURRENT_BINARY_DIR}/lib/libdrreg.so"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
  install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/ldconfig.cmake")
  return()
endif()

find_package(DynamoRIO CONFIG REQUIRED)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CTRACE_OUTPUT_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CTRACE_OUTPUT_DIR}/bin")

add_library(
  ctrace_client SHARED
  src/client.cc
  src/assembly.cc
  src/execution_cache.cc
  src/filter.cc
  src/location_record.cc
  src/decompiled_record.cc
  src/userspace_patch.cc
  src/userspace_version.cc
  src/userspace_version_cache.cc
  src/analysis_image.c
  src/analysis_proxy.c
  src/shared_objects.c
  src/shared_digest.c
  src/dr_shared_provider.cc
  src/shared_objects_runtime.c
  src/output.c
  src/perfetto.cc
  src/perfetto_json.cc
  src/perfetto_scope.cc
  src/timing.cc
  src/value_format.c
  src/values.c
  src/signal_info.cc)
configure_dynamorio_client(ctrace_client)
use_dynamorio_extension(ctrace_client drmgr)
use_dynamorio_extension(ctrace_client drwrap)
use_dynamorio_extension(ctrace_client drbbdup)
use_dynamorio_extension(ctrace_client drreg)
set_target_properties(
  ctrace_client
  PROPERTIES OUTPUT_NAME ctrace
             BUILD_WITH_INSTALL_RPATH ON
             INSTALL_RPATH "$ORIGIN;$ORIGIN/dynamorio/lib64/release"
             C_STANDARD 11
             C_STANDARD_REQUIRED ON
             CXX_STANDARD 17
             CXX_STANDARD_REQUIRED ON)
target_compile_options(ctrace_client PRIVATE -Wall -Wextra
                                             -Wno-unused-parameter)
target_link_libraries(ctrace_client PkgConfig::DW PkgConfig::MD)

add_executable(
  ctrace_analyze
  src/analysis_server.cc
  src/exec_resources.cc
  src/thread_suspend_server.cc
  src/shared_objects.c
  src/shared_objects_host.cc
  src/shared_objects_digest.cc
  src/shared_objects_server.cc
  src/analysis.cc
  src/analysis_progress.cc
  src/analysis_files.cc
  src/cache.cc
  src/disassemble.cc
  src/source_asm.cc
  src/flow.cc
  src/decompile.cc
  src/decompile_provider.cc
  src/decompile_view.cc
  src/kernel_decompile_worker.cc)
set_target_properties(ctrace_analyze PROPERTIES CXX_STANDARD 17
                                                CXX_STANDARD_REQUIRED ON)
target_include_directories(ctrace_analyze SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_include_directories(ctrace_analyze SYSTEM
                           PRIVATE ${DynamoRIO_INCLUDE_DIRS})
target_compile_options(ctrace_analyze PRIVATE -Wall -Wextra
                                              -Wno-unused-parameter)
# DynamoRIO moves ordinary directory flags into its client source properties.
# Preserve the original flags for the standalone analysis executable as well.
string(TOUPPER "${CMAKE_BUILD_TYPE}" CTRACE_BUILD_TYPE)
separate_arguments(
  CTRACE_ANALYSIS_FLAGS NATIVE_COMMAND
  "${ORIG_CMAKE_CXX_FLAGS} ${ORIG_CMAKE_CXX_FLAGS_${CTRACE_BUILD_TYPE}}")
target_compile_options(ctrace_analyze PRIVATE ${CTRACE_ANALYSIS_FLAGS})
target_link_libraries(ctrace_analyze PRIVATE clang-cpp LLVM PkgConfig::DW)

add_executable(
  ctrace_kernel
  src/kernel.cc
  src/kernel_image.cc
  src/kernel_object.cc
  src/kernel_sign.cc
  src/kernel_rewrite.cc
  src/kernel_gate.cc
  src/kernel_interrupt.cc
  src/kernel_copies.cc
  src/kernel_prepare.cc
  src/kernel_prepare_validate.cc
  src/kernel_trace.cc
  src/kernel_policy.cc
  src/kernel_source.cc
  src/kernel_values.cc
  src/kernel_capture.cc
  src/kernel_decompile.cc
  src/kernel_decompile_image.cc
  src/kernel_decompile_transport.cc
  src/kernel_flow.cc
  src/decompile_view.cc
  src/shared_objects_digest.cc
  src/flow.cc
  src/kernel_perfetto.cc
  src/value_format.c
  src/perfetto_json.cc
  src/kernel_load.cc
  src/kernel_lifetime.cc
  src/kernel_guardian.cc
  src/analysis_progress.cc
  src/analysis_files.cc
  src/source_asm.cc
  src/filter.cc
  src/cache.cc)
set_target_properties(ctrace_kernel PROPERTIES CXX_STANDARD 17
                                               CXX_STANDARD_REQUIRED ON)
target_include_directories(ctrace_kernel
                           PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(ctrace_kernel SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_options(ctrace_kernel PRIVATE -Wall -Wextra
                                             ${CTRACE_ANALYSIS_FLAGS})
target_link_libraries(
  ctrace_kernel PRIVATE clang-cpp LLVM PkgConfig::MODULE_COMPRESSION
                        OpenSSL::Crypto)
# Keep the bundled DynamoRIO extensions' transitive dependencies discoverable.
target_link_options(ctrace_client PRIVATE -Wl,--disable-new-dtags)
install(
  TARGETS ctrace_client ctrace_analyze ctrace_kernel
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
