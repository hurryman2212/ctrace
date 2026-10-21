# SPDX-License-Identifier: MIT

# Set root project name
set(ROOT_PROJECT_NAME ctrace)

# Set root language standards
set(ROOT_CXX_EXTENSIONS TRUE)
set(ROOT_CXX_STANDARD "20")

# DO NOT EDIT THE BELOW!

# Set minimum CMake version required
cmake_minimum_required(VERSION 3.21)
cmake_policy(SET CMP0126 NEW)
macro(override_default var override)
  get_property(
    CURRENT_TYPE
    CACHE ${var}
    PROPERTY TYPE)
  if(NOT DEFINED CURRENT_TYPE)
    set(${var} ${override})
  endif()
endmacro()
macro(update_cache var type)
  get_property(
    CURRENT_TYPE
    CACHE ${var}
    PROPERTY TYPE)
  if(DEFINED CURRENT_TYPE)
    set(type ${CURRENT_TYPE})
  endif()
  get_property(
    CURRENT_HELPSTRING
    CACHE ${var}
    PROPERTY HELPSTRING)
  set(${var}
      ${${var}}
      CACHE ${type} "${CURRENT_HELPSTRING}" FORCE)
endmacro()

# Override default generator
if(CMAKE_GENERATOR STREQUAL "Ninja")
  configure_file(${CMAKE_SOURCE_DIR}/Makefile ./Makefile COPYONLY)
endif()
override_default(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

# Configure ctrace as C++; the separately configured DynamoRIO still needs C.
override_default(CMAKE_CXX_COMPILER "clang++")
if(DEFINED CMAKE_C_COMPILER AND NOT DEFINED DYNAMORIO_C_COMPILER)
  set(DYNAMORIO_C_COMPILER
      "${CMAKE_C_COMPILER}"
      CACHE FILEPATH "C compiler for the DynamoRIO dependency")
endif()
# Drop the legacy top-level C compiler cache so dependency checks use C++.
unset(CMAKE_C_COMPILER CACHE)
unset(CMAKE_C_COMPILER)
if(CMAKE_CXX_COMPILER MATCHES "(^|/|-)g\\+\\+")
  find_program(DYNAMORIO_C_COMPILER NAMES gcc REQUIRED)
else()
  find_program(DYNAMORIO_C_COMPILER NAMES clang REQUIRED)
endif()

# Override the default C++ standard and extensions.
override_default(CMAKE_CXX_EXTENSIONS ${ROOT_CXX_EXTENSIONS})
override_default(CMAKE_CXX_STANDARD ${ROOT_CXX_STANDARD})

# Set our default C++ compiler options.
set(CXX_FLAGS -frecord-gcc-switches -save-temps=obj -fverbose-asm -Wall -Werror)
if(CMAKE_CXX_COMPILER MATCHES ".*clang.*")
  list(APPEND CXX_FLAGS -fcolor-diagnostics -Xclang -gsrc-hash=none)
  set(CXX_FLAGS_LTO -flto=full -ffat-lto-objects)
else()
  list(APPEND CXX_FLAGS -fdiagnostics-color=always)
  set(CXX_FLAGS_LTO -flto -ffat-lto-objects)
endif()

set(CXX_FLAGS_DEBUG -Og -g3 -gdwarf-5)
set(CXX_FLAGS_REL_COMMON -DNDEBUG -march=native -ftree-vectorize)
if(CMAKE_CXX_COMPILER MATCHES "(^|/|-)g\\+\\+")
  list(APPEND CXX_FLAGS_REL_COMMON -fvect-cost-model=very-cheap)
endif()
set(CXX_FLAGS_RELEASE -O2 ${CXX_FLAGS_REL_COMMON} ${CXX_FLAGS_LTO})
set(CXX_FLAGS_MINSIZEREL
    -Os -fmerge-all-constants -ffunction-sections -fdata-sections
    ${CXX_FLAGS_REL_COMMON} ${CXX_FLAGS_LTO})
set(CXX_FLAGS_RELWITHDEBINFO -O2 ${CXX_FLAGS_DEBUG} ${CXX_FLAGS_REL_COMMON}
                             ${CXX_FLAGS_LTO})

# Set our linker flags
override_default(CMAKE_LINKER "lld")
set(LINKER_FLAGS_COMMON -fuse-ld=${CMAKE_LINKER} -Wl,--as-needed
                        -Wl,--gc-sections -Wl,--no-whole-archive)
set(LINKER_FLAGS_DEBUG -Wl,--export-dynamic)
set(LINKER_FLAGS_RELEASE -Wl,--strip-all)

# Handle build type
override_default(CMAKE_BUILD_TYPE "Debug")
string(REPLACE ";" " " CXX_FLAGS "${CXX_FLAGS}")
string(REPLACE ";" " " CXX_FLAGS_DEBUG "${CXX_FLAGS_DEBUG}")
string(REPLACE ";" " " CXX_FLAGS_RELEASE "${CXX_FLAGS_RELEASE}")
string(REPLACE ";" " " CXX_FLAGS_MINSIZEREL "${CXX_FLAGS_MINSIZEREL}")
string(REPLACE ";" " " CXX_FLAGS_RELWITHDEBINFO "${CXX_FLAGS_RELWITHDEBINFO}")
string(REPLACE ";" " " LINKER_FLAGS_COMMON "${LINKER_FLAGS_COMMON}")
string(REPLACE ";" " " LINKER_FLAGS_DEBUG "${LINKER_FLAGS_DEBUG}")
string(REPLACE ";" " " LINKER_FLAGS_RELEASE "${LINKER_FLAGS_RELEASE}")
override_default(CMAKE_CXX_FLAGS ${CXX_FLAGS})
override_default(CMAKE_CXX_FLAGS_DEBUG ${CXX_FLAGS_DEBUG})
override_default(CMAKE_CXX_FLAGS_RELEASE ${CXX_FLAGS_RELEASE})
override_default(CMAKE_CXX_FLAGS_MINSIZEREL ${CXX_FLAGS_MINSIZEREL})
override_default(CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CXX_FLAGS_RELWITHDEBINFO})
override_default(CMAKE_EXE_LINKER_FLAGS ${LINKER_FLAGS_COMMON})
override_default(CMAKE_EXE_LINKER_FLAGS_DEBUG ${LINKER_FLAGS_DEBUG})
override_default(CMAKE_EXE_LINKER_FLAGS_RELEASE ${LINKER_FLAGS_RELEASE})
override_default(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL ${LINKER_FLAGS_RELEASE})
override_default(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO ${LINKER_FLAGS_DEBUG})
override_default(CMAKE_SHARED_LINKER_FLAGS ${LINKER_FLAGS_COMMON})
override_default(CMAKE_SHARED_LINKER_FLAGS_DEBUG ${LINKER_FLAGS_DEBUG})
override_default(CMAKE_SHARED_LINKER_FLAGS_RELEASE ${LINKER_FLAGS_RELEASE})
override_default(CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL ${LINKER_FLAGS_RELEASE})
override_default(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO ${LINKER_FLAGS_DEBUG})
override_default(CMAKE_MODULE_LINKER_FLAGS ${LINKER_FLAGS_COMMON})
override_default(CMAKE_MODULE_LINKER_FLAGS_DEBUG ${LINKER_FLAGS_DEBUG})
override_default(CMAKE_MODULE_LINKER_FLAGS_RELEASE ${LINKER_FLAGS_RELEASE})
override_default(CMAKE_MODULE_LINKER_FLAGS_MINSIZEREL ${LINKER_FLAGS_RELEASE})
override_default(CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO ${LINKER_FLAGS_DEBUG})

# Set output path
override_default(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
override_default(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
override_default(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# Set install path
override_default(CMAKE_INSTALL_PREFIX "/usr/local")

# Declare top-level project
project(${ROOT_PROJECT_NAME} LANGUAGES CXX)

# Update cache values at once after project initialization
update_cache(CMAKE_ARCHIVE_OUTPUT_DIRECTORY PATH)
update_cache(CMAKE_BUILD_TYPE STRING)
update_cache(CMAKE_CXX_COMPILER FILEPATH)
update_cache(CMAKE_CXX_EXTENSIONS BOOL)
update_cache(CMAKE_CXX_FLAGS STRING)
update_cache(CMAKE_CXX_FLAGS_DEBUG STRING)
update_cache(CMAKE_CXX_FLAGS_MINSIZEREL STRING)
update_cache(CMAKE_CXX_FLAGS_RELEASE STRING)
update_cache(CMAKE_CXX_FLAGS_RELWITHDEBINFO STRING)
update_cache(CMAKE_CXX_STANDARD STRING)
update_cache(CMAKE_EXE_LINKER_FLAGS STRING)
update_cache(CMAKE_EXE_LINKER_FLAGS_DEBUG STRING)
update_cache(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL STRING)
update_cache(CMAKE_EXE_LINKER_FLAGS_RELEASE STRING)
update_cache(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO STRING)
update_cache(CMAKE_EXPORT_COMPILE_COMMANDS BOOL)
update_cache(CMAKE_INSTALL_PREFIX PATH)
update_cache(CMAKE_LIBRARY_OUTPUT_DIRECTORY PATH)
update_cache(CMAKE_LINKER FILEPATH)
update_cache(CMAKE_MODULE_LINKER_FLAGS STRING)
update_cache(CMAKE_MODULE_LINKER_FLAGS_DEBUG STRING)
update_cache(CMAKE_MODULE_LINKER_FLAGS_MINSIZEREL STRING)
update_cache(CMAKE_MODULE_LINKER_FLAGS_RELEASE STRING)
update_cache(CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO STRING)
update_cache(CMAKE_RUNTIME_OUTPUT_DIRECTORY PATH)
update_cache(CMAKE_SHARED_LINKER_FLAGS STRING)
update_cache(CMAKE_SHARED_LINKER_FLAGS_DEBUG STRING)
update_cache(CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL STRING)
update_cache(CMAKE_SHARED_LINKER_FLAGS_RELEASE STRING)
update_cache(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO STRING)

include(GNUInstallDirs)

# System dependencies; Ghidra and Java are discovered only at runtime.
find_package(LLVM CONFIG REQUIRED)
find_package(Clang CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
pkg_check_modules(DW REQUIRED IMPORTED_TARGET libdw libelf)
pkg_check_modules(MD REQUIRED IMPORTED_TARGET libmd)
pkg_check_modules(MODULE_COMPRESSION REQUIRED IMPORTED_TARGET zlib liblzma
                  libzstd>=1.4.0)

# DynamoRIO needs an isolated configuration: its own defaults and generated
# export files must exist before the client is configured, not after a build.
set(DYNAMORIO_BUILD_DIR "${CMAKE_BINARY_DIR}/dynamorio")
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/dynamorio/CMakeLists.txt")
  message(
    FATAL_ERROR
      "Initialize DynamoRIO first: git submodule update --init --recursive")
endif()
set(DYNAMORIO_LINKER "${CMAKE_LINKER}")
get_filename_component(DYNAMORIO_LINKER_NAME "${DYNAMORIO_LINKER}" NAME)
if(DYNAMORIO_LINKER_NAME STREQUAL "lld")
  find_program(DYNAMORIO_ELF_LINKER NAMES ld.lld REQUIRED)
  set(DYNAMORIO_LINKER "${DYNAMORIO_ELF_LINKER}")
endif()
# DR implements its own libc; prevent Clang from rewriting those loops into
# calls back to the host libc. DR accepts these flags through its environment.
set(DYNAMORIO_BUILD_ENV "CFLAGS=$ENV{CFLAGS} -fno-builtin"
                        "CXXFLAGS=$ENV{CXXFLAGS} -fno-builtin")
get_filename_component(DYNAMORIO_LINKER_REAL "${DYNAMORIO_LINKER}" REALPATH)
get_filename_component(DYNAMORIO_LINKER_REAL "${DYNAMORIO_LINKER_REAL}" NAME)
if(DYNAMORIO_LINKER_REAL MATCHES "lld")
  set(DYNAMORIO_LINKER_KIND lld)
elseif(DYNAMORIO_LINKER_REAL MATCHES "gold")
  set(DYNAMORIO_LINKER_KIND gold)
elseif(DYNAMORIO_LINKER_REAL MATCHES "mold")
  set(DYNAMORIO_LINKER_KIND mold)
else()
  set(DYNAMORIO_LINKER_KIND bfd)
endif()
execute_process(
  COMMAND
    "${CMAKE_COMMAND}" -E env ${DYNAMORIO_BUILD_ENV} "${CMAKE_COMMAND}" -S
    "${CMAKE_SOURCE_DIR}/dynamorio" -B "${DYNAMORIO_BUILD_DIR}" -G
    "${CMAKE_GENERATOR}" -DCMAKE_BUILD_TYPE=RelWithDebInfo
    "-DCMAKE_C_COMPILER=${DYNAMORIO_C_COMPILER}"
    "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
    "-DCMAKE_LINKER=${DYNAMORIO_LINKER}"
    "-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=${DYNAMORIO_LINKER_KIND}"
    "-DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=${DYNAMORIO_LINKER_KIND}"
    "-DCMAKE_MODULE_LINKER_FLAGS=-fuse-ld=${DYNAMORIO_LINKER_KIND}"
    -DBUILD_TESTS=OFF -DBUILD_SAMPLES=OFF -DBUILD_CLIENTS=OFF -DBUILD_DOCS=OFF
    -DDISABLE_DRGUI=ON
  RESULT_VARIABLE DYNAMORIO_CONFIGURE_RESULT)
if(NOT DYNAMORIO_CONFIGURE_RESULT EQUAL 0)
  message(FATAL_ERROR "DynamoRIO configuration failed")
endif()
include(ExternalProject)
ExternalProject_Add(
  ctrace_dynamorio
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/dynamorio"
  BINARY_DIR "${DYNAMORIO_BUILD_DIR}"
  DOWNLOAD_COMMAND ""
  UPDATE_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND
    "${CMAKE_COMMAND}" -E env ${DYNAMORIO_BUILD_ENV} "${CMAKE_COMMAND}" --build
    <BINARY_DIR> --target drrun dynamorio drmgr drwrap drbbdup drreg
  BUILD_ALWAYS TRUE
  BUILD_BYPRODUCTS
    "${DYNAMORIO_BUILD_DIR}/bin64/drrun"
    "${DYNAMORIO_BUILD_DIR}/lib64/release/libdynamorio.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrmgr.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrwrap.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrbbdup.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrreg.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrcontainers.a"
  INSTALL_COMMAND "")
# Reconfigure the dependency before hashing its generated service contract.
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS
           "${CMAKE_SOURCE_DIR}/dynamorio/core/lib/dr_exec_resources.h"
           "${CMAKE_SOURCE_DIR}/dynamorio/core/lib/dr_thread_suspend.h"
           "${CMAKE_SOURCE_DIR}/dynamorio/core/unix/exec_resources.c"
           "${CMAKE_SOURCE_DIR}/dynamorio/core/unix/thread_suspend.c"
           "${CMAKE_SOURCE_DIR}/dynamorio/make/service_contract.cmake")
set(DynamoRIO_DIR "${DYNAMORIO_BUILD_DIR}/cmake")
set(DynamoRIO_INCLUDE_DIRS "${DYNAMORIO_BUILD_DIR}/include")

set(LAUNCHER_OUTPUT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ctrace")
execute_process(
  COMMAND
    "${CMAKE_COMMAND}" "-DSOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "-DLAUNCHER_OUTPUT=${LAUNCHER_OUTPUT}" -P
    "${CMAKE_SOURCE_DIR}/cmake/generate_version.cmake" COMMAND_ERROR_IS_FATAL
    ANY)
add_custom_target(
  version-${ROOT_PROJECT_NAME} ALL
  COMMAND
    "${CMAKE_COMMAND}" "-DSOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "-DLAUNCHER_OUTPUT=${LAUNCHER_OUTPUT}" -P
    "${CMAKE_SOURCE_DIR}/cmake/generate_version.cmake"
  BYPRODUCTS "${LAUNCHER_OUTPUT}"
  COMMENT "Generating ctrace version"
  VERBATIM)

include(cmake/generate_contract.cmake)
execute_process(
  COMMAND
    sh "${CMAKE_SOURCE_DIR}/module/generate-contract.sh"
    "${CMAKE_SOURCE_DIR}/module" "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_BINARY_DIR}/include/kctrace/contract.sha256"
    COMMAND_ERROR_IS_FATAL ANY)
file(READ "${CMAKE_BINARY_DIR}/include/kctrace/contract.sha256"
     KCTRACE_CONTRACT_HEX)
string(STRIP "${KCTRACE_CONTRACT_HEX}" KCTRACE_CONTRACT_HEX)
string(LENGTH "${KCTRACE_CONTRACT_HEX}" KCTRACE_CONTRACT_LENGTH)
if(NOT KCTRACE_CONTRACT_LENGTH EQUAL 64 OR NOT KCTRACE_CONTRACT_HEX MATCHES
                                           "^[0-9a-f]+$")
  message(FATAL_ERROR "Invalid generated kctrace contract digest")
endif()
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," KCTRACE_CONTRACT_BYTES
                     "${KCTRACE_CONTRACT_HEX}")
# Remove the old generated declaration, which would shadow the shared source.
file(REMOVE "${CMAKE_BINARY_DIR}/include/kctrace/contract.h")
file(
  GLOB
  KCTRACE_CONTRACT_INPUTS
  CONFIGURE_DEPENDS
  "${CMAKE_SOURCE_DIR}/module/*.c"
  "${CMAKE_SOURCE_DIR}/module/*.h"
  "${CMAKE_SOURCE_DIR}/module/*.S"
  "${CMAKE_SOURCE_DIR}/include/kctrace/*.h")
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS ${KCTRACE_CONTRACT_INPUTS}
           "${CMAKE_SOURCE_DIR}/module/include/uapi/linux/kctrace.h"
           "${CMAKE_SOURCE_DIR}/module/generate-contract.sh")
include_directories("${CMAKE_BINARY_DIR}/include")

# Add CMake source subdirectories.
add_subdirectory(src)

# Build-tree resources mirror the installed lib/ctrace layout. The scripts
# themselves are copied unchanged; only the launcher embeds the build version.
set(CTRACE_RESOURCE_DIR "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/ctrace")
configure_file(decompile/ctrace_decompile
               "${CTRACE_RESOURCE_DIR}/ctrace_decompile" COPYONLY)
configure_file(decompile/CtraceDecompileServer.java
               "${CTRACE_RESOURCE_DIR}/CtraceDecompileServer.java" COPYONLY)
foreach(source target.c target.h)
  configure_file("module/${source}" "${CTRACE_RESOURCE_DIR}/kernel/${source}"
                 COPYONLY)
endforeach()
configure_file(
  module/include/uapi/linux/kctrace.h
  "${CTRACE_RESOURCE_DIR}/kernel/include/uapi/linux/kctrace.h" COPYONLY)
configure_file(
  include/kctrace/runtime.h
  "${CTRACE_RESOURCE_DIR}/kernel/include/kctrace/runtime.h" COPYONLY)
configure_file(
  include/kctrace/contract.h
  "${CTRACE_RESOURCE_DIR}/kernel/include/kctrace/contract.h" COPYONLY)
configure_file(
  "${CMAKE_BINARY_DIR}/include/kctrace/contract.sha256"
  "${CTRACE_RESOURCE_DIR}/kernel/include/kctrace/contract.sha256" COPYONLY)
file(RELATIVE_PATH CTRACE_DECOMPILE_LINK "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
     "${CTRACE_RESOURCE_DIR}/ctrace_decompile")
file(CREATE_LINK "${CTRACE_DECOMPILE_LINK}"
     "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ctrace_decompile" SYMBOLIC)
file(RELATIVE_PATH CTRACE_KERNEL_LINK "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
     "${CTRACE_RESOURCE_DIR}/kernel")
file(CREATE_LINK "${CTRACE_KERNEL_LINK}"
     "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ctrace_kernel_data" SYMBOLIC)
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/install-bin")
file(RELATIVE_PATH CTRACE_DECOMPILE_LINK "${CMAKE_INSTALL_FULL_BINDIR}"
     "${CMAKE_INSTALL_FULL_LIBDIR}/ctrace/ctrace_decompile")
file(CREATE_LINK "${CTRACE_DECOMPILE_LINK}"
     "${CMAKE_BINARY_DIR}/install-bin/ctrace_decompile" SYMBOLIC)
file(RELATIVE_PATH CTRACE_KERNEL_LINK "${CMAKE_INSTALL_FULL_BINDIR}"
     "${CMAKE_INSTALL_FULL_LIBDIR}/ctrace/kernel")
file(CREATE_LINK "${CTRACE_KERNEL_LINK}"
     "${CMAKE_BINARY_DIR}/install-bin/ctrace_kernel_data" SYMBOLIC)
file(RELATIVE_PATH CTRACE_DRRUN_RELATIVE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
     "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/dynamorio/bin64/drrun")
configure_file(cmake/drrun.sh.in "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/drrun"
               @ONLY)
file(RELATIVE_PATH CTRACE_DRRUN_RELATIVE "${CMAKE_INSTALL_FULL_BINDIR}"
     "${CMAKE_INSTALL_FULL_LIBDIR}/dynamorio/bin64/drrun")
configure_file(cmake/drrun.sh.in "${CMAKE_BINARY_DIR}/install-bin/drrun" @ONLY)
file(
  CHMOD
  "${CTRACE_RESOURCE_DIR}/ctrace_decompile"
  "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/drrun"
  "${CMAKE_BINARY_DIR}/install-bin/drrun"
  PERMISSIONS
  OWNER_READ
  OWNER_WRITE
  OWNER_EXECUTE
  GROUP_READ
  GROUP_EXECUTE
  WORLD_READ
  WORLD_EXECUTE)
add_custom_target(
  ctrace_runtime ALL
  DEPENDS ctrace_dynamorio
  COMMAND
    "${CMAKE_COMMAND}" -E make_directory
    "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/dynamorio/bin64"
    "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/dynamorio/lib64/release"
  COMMAND
    "${CMAKE_COMMAND}" -E copy_if_different "${DYNAMORIO_BUILD_DIR}/bin64/drrun"
    "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/dynamorio/bin64/drrun"
  COMMAND
    "${CMAKE_COMMAND}" -E copy_if_different
    "${DYNAMORIO_BUILD_DIR}/lib64/release/libdynamorio.so"
    "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/dynamorio/lib64/release/libdynamorio.so"
  COMMAND
    "${CMAKE_COMMAND}" -E copy_if_different
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrmgr.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrwrap.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrbbdup.so"
    "${DYNAMORIO_BUILD_DIR}/ext/lib64/release/libdrreg.so"
    "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
  VERBATIM)

install(PROGRAMS "${LAUNCHER_OUTPUT}" "${CMAKE_BINARY_DIR}/install-bin/drrun"
                 "${CMAKE_BINARY_DIR}/install-bin/ctrace_decompile"
        DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${CMAKE_BINARY_DIR}/install-bin/ctrace_kernel_data"
        DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(
  DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/dynamorio"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  USE_SOURCE_PERMISSIONS)
install(
  FILES "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libdrmgr.so"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libdrwrap.so"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libdrbbdup.so"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libdrreg.so"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${CTRACE_RESOURCE_DIR}/CtraceDecompileServer.java"
              "${CTRACE_RESOURCE_DIR}/ctrace_contract.json"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/ctrace")
install(PROGRAMS "${CTRACE_RESOURCE_DIR}/ctrace_decompile"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/ctrace")
install(DIRECTORY "${CTRACE_RESOURCE_DIR}/kernel/"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/ctrace/kernel")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/ctrace")

# Manifest-based removal and host loader-cache refresh preserve DESTDIR.
configure_file(cmake/ldconfig.cmake.in ldconfig.cmake @ONLY)
configure_file(cmake/uninstall.cmake.in uninstall.cmake @ONLY)
add_custom_target(uninstall COMMAND "${CMAKE_COMMAND}" -P
                                    "${CMAKE_BINARY_DIR}/uninstall.cmake")
install(SCRIPT "${CMAKE_BINARY_DIR}/ldconfig.cmake")
