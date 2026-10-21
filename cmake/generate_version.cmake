# SPDX-License-Identifier: MIT

if(NOT DEFINED SOURCE_DIR OR NOT DEFINED LAUNCHER_OUTPUT)
  message(FATAL_ERROR "missing ctrace version arguments")
endif()

execute_process(
  COMMAND sh "${SOURCE_DIR}/generate-version.sh"
  RESULT_VARIABLE VERSION_RES
  OUTPUT_VARIABLE VERSION
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT VERSION_RES STREQUAL "0" OR VERSION STREQUAL "")
  set(VERSION unknown)
endif()

# Hex preserves the script's bytes without treating them as Python source.
string(HEX "${VERSION}" VERSION_HEX)
file(READ "${SOURCE_DIR}/ctrace" LAUNCHER)
if(NOT LAUNCHER MATCHES "\nVERSION = None\n")
  message(FATAL_ERROR "ctrace launcher version marker is missing")
endif()
string(
  REPLACE "\nVERSION = None\n"
          "\nVERSION = bytes.fromhex(\"${VERSION_HEX}\").decode(\"utf-8\")\n"
          LAUNCHER "${LAUNCHER}")

get_filename_component(LAUNCHER_DIR "${LAUNCHER_OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${LAUNCHER_DIR}")
set(PREVIOUS_LAUNCHER "")
if(EXISTS "${LAUNCHER_OUTPUT}")
  file(READ "${LAUNCHER_OUTPUT}" PREVIOUS_LAUNCHER)
endif()
if(NOT LAUNCHER STREQUAL PREVIOUS_LAUNCHER)
  file(WRITE "${LAUNCHER_OUTPUT}" "${LAUNCHER}")
endif()
file(
  CHMOD
  "${LAUNCHER_OUTPUT}"
  PERMISSIONS
  OWNER_READ
  OWNER_WRITE
  OWNER_EXECUTE
  GROUP_READ
  GROUP_EXECUTE
  WORLD_READ
  WORLD_EXECUTE)
