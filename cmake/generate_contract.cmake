# SPDX-License-Identifier: MIT

# Source identity guards private protocols; binary/dependency identities still
# guard executable artifacts and native-layout disk records independently.
file(
  GLOB_RECURSE
  CONTRACT_INPUTS
  CONFIGURE_DEPENDS
  "${CMAKE_SOURCE_DIR}/src/*.cc"
  "${CMAKE_SOURCE_DIR}/src/*.hh"
  "${CMAKE_SOURCE_DIR}/src/CMakeLists.txt"
  "${CMAKE_SOURCE_DIR}/src/*/CMakeLists.txt"
  "${CMAKE_SOURCE_DIR}/include/*.h"
  "${CMAKE_SOURCE_DIR}/decompile/*.java")
list(
  APPEND
  CONTRACT_INPUTS
  "${CMAKE_SOURCE_DIR}/CMakeLists.txt"
  "${CMAKE_SOURCE_DIR}/decompile/ctrace_decompile"
  "${CMAKE_SOURCE_DIR}/cmake/generate_contract.cmake"
  "${CMAKE_SOURCE_DIR}/module/include/uapi/linux/kctrace.h"
  "${DYNAMORIO_BUILD_DIR}/include/dr_service_contract.h")
list(REMOVE_DUPLICATES CONTRACT_INPUTS)
set(CONTRACT_CONTENT
    "${CMAKE_CXX_COMPILER_ID}:${CMAKE_CXX_COMPILER_VERSION}:${CMAKE_SYSTEM_PROCESSOR}:${CMAKE_SIZEOF_VOID_P}:${LLVM_PACKAGE_VERSION}\n"
)
foreach(
  SETTING
  CMAKE_SYSTEM_NAME
  CMAKE_CXX_BYTE_ORDER
  CMAKE_CXX_COMPILER_TARGET
  CMAKE_CXX_STANDARD
  CMAKE_CXX_EXTENSIONS
  CMAKE_BUILD_TYPE
  CMAKE_CXX_FLAGS
  CMAKE_CXX_FLAGS_DEBUG
  CMAKE_CXX_FLAGS_RELEASE
  CMAKE_CXX_FLAGS_RELWITHDEBINFO
  CMAKE_CXX_FLAGS_MINSIZEREL)
  string(APPEND CONTRACT_CONTENT "${SETTING}:${${SETTING}}\n")
endforeach()
foreach(INPUT IN LISTS CONTRACT_INPUTS)
  file(SHA256 "${INPUT}" DIGEST)
  # Generated dependency headers have a stable label across build directories.
  if(INPUT STREQUAL "${DYNAMORIO_BUILD_DIR}/include/dr_service_contract.h")
    set(LABEL "dynamorio/dr_service_contract.h")
  else()
    file(RELATIVE_PATH LABEL "${CMAKE_SOURCE_DIR}" "${INPUT}")
  endif()
  list(APPEND CONTRACT_RECORDS "${LABEL}:${DIGEST}")
endforeach()
set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS ${CONTRACT_INPUTS})
list(SORT CONTRACT_RECORDS)
string(JOIN "\n" CONTRACT_MANIFEST ${CONTRACT_RECORDS})
string(SHA256 CTRACE_CONTRACT_HASH "${CONTRACT_CONTENT}${CONTRACT_MANIFEST}")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1, " CTRACE_CONTRACT_BYTES
                     "${CTRACE_CONTRACT_HASH}")
set(CONTRACT_HEADER
    "#ifndef CTRACE_BUILD_CONTRACT_H\n#define CTRACE_BUILD_CONTRACT_H\n#define CTRACE_CONTRACT_HASH \"${CTRACE_CONTRACT_HASH}\"\n#define CTRACE_CONTRACT_BYTES { ${CTRACE_CONTRACT_BYTES} }\n#endif\n"
)
file(
  GENERATE
  OUTPUT "${CMAKE_BINARY_DIR}/include/ctrace_contract.h"
  CONTENT "${CONTRACT_HEADER}")
file(SHA256 "${CMAKE_SOURCE_DIR}/decompile/ctrace_decompile" PYTHON_HASH)
file(SHA256 "${CMAKE_SOURCE_DIR}/decompile/CtraceDecompileServer.java"
     JAVA_HASH)
file(
  GENERATE
  OUTPUT "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/ctrace/ctrace_contract.json"
  CONTENT
    "{\"contract_hash\":\"${CTRACE_CONTRACT_HASH}\",\"python_sha256\":\"${PYTHON_HASH}\",\"java_sha256\":\"${JAVA_HASH}\"}\n"
)
