#==============================================================================
# End-to-end differential tests.
#
# Each test compiles the workload clean and obfuscated (via the built plugin)
# and requires identical runtime output.  Requires a C compiler matching the
# plugin's LLVM (the build compiler) and, on Apple platforms, the macOS SDK.
#==============================================================================

if(NOT APPLE)
  message(STATUS "e2e differential tests currently target Apple toolchains; skipping.")
  return()
endif()

set(_workload "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/workload.c")
set(_driver "${CMAKE_CURRENT_SOURCE_DIR}/differential.sh")
set(_program_sweep "${CMAKE_CURRENT_SOURCE_DIR}/compile_programs.sh")
set(_max_config "${CMAKE_CURRENT_SOURCE_DIR}/max.toml")

foreach(preset low mid high)
  add_test(NAME "e2e/differential_${preset}"
    COMMAND bash "${_driver}"
            "${CMAKE_C_COMPILER}"
            "$<TARGET_FILE:morok_plugin>"
            "${CMAKE_OSX_SYSROOT}"
            "${_workload}"
            "${preset}"
            4242)
  set_tests_properties("e2e/differential_${preset}" PROPERTIES
    LABELS "e2e"
    # The plugin must exist before these run.
    REQUIRED_FILES "$<TARGET_FILE:morok_plugin>")
endforeach()

add_test(NAME "e2e/differential_max"
  COMMAND bash "${_driver}"
          "${CMAKE_C_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${CMAKE_OSX_SYSROOT}"
          "${_workload}"
          "${_max_config}"
          4242)
set_tests_properties("e2e/differential_max" PROPERTIES
  LABELS "e2e;max"
  REQUIRED_FILES "$<TARGET_FILE:morok_plugin>;${_max_config}")

add_test(NAME "e2e/programs_high_compile"
  COMMAND bash "${_program_sweep}"
          "${CMAKE_C_COMPILER}"
          "${CMAKE_CXX_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${CMAKE_OSX_SYSROOT}"
          "${PROJECT_SOURCE_DIR}/programs"
          "high"
          4242)
set_tests_properties("e2e/programs_high_compile" PROPERTIES
  LABELS "e2e;programs;max"
  REQUIRED_FILES "$<TARGET_FILE:morok_plugin>"
  TIMEOUT 600)

add_test(NAME "e2e/programs_max_compile"
  COMMAND bash "${_program_sweep}"
          "${CMAKE_C_COMPILER}"
          "${CMAKE_CXX_COMPILER}"
          "$<TARGET_FILE:morok_plugin>"
          "${CMAKE_OSX_SYSROOT}"
          "${PROJECT_SOURCE_DIR}/programs"
          "${_max_config}"
          4242)
set_tests_properties("e2e/programs_max_compile" PROPERTIES
  LABELS "e2e;programs;max"
  REQUIRED_FILES "$<TARGET_FILE:morok_plugin>;${_max_config}"
  TIMEOUT 900)
