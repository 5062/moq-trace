cmake_minimum_required(VERSION 3.20)
project(quic_trace VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
include(CMakePackageConfigHelpers)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LTTNG_UST REQUIRED IMPORTED_TARGET lttng-ust>=2.13)
find_program(LTTNG_GEN_TP lttng-gen-tp REQUIRED)

set(PROVIDER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/crates/quic-trace-lttng-sys/provider")
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}")

add_custom_command(
  OUTPUT "${GENERATED_DIR}/events.h"
  COMMAND "${LTTNG_GEN_TP}" "${PROVIDER_DIR}/events.tp" -o events.h
  WORKING_DIRECTORY "${GENERATED_DIR}"
  DEPENDS "${PROVIDER_DIR}/events.tp" "${PROVIDER_DIR}/interface.h"
  VERBATIM
)

add_library(quic_trace_provider STATIC
  "${PROVIDER_DIR}/interface.c"
  "${GENERATED_DIR}/events.h"
)
add_library(quic_trace::provider ALIAS quic_trace_provider)
set_target_properties(quic_trace_provider PROPERTIES EXPORT_NAME provider)
target_include_directories(quic_trace_provider PUBLIC
  "$<BUILD_INTERFACE:${PROVIDER_DIR}>"
  "$<INSTALL_INTERFACE:include/quic_trace>"
  PRIVATE "${GENERATED_DIR}"
)
target_link_libraries(quic_trace_provider PUBLIC PkgConfig::LTTNG_UST)
target_compile_features(quic_trace_provider PUBLIC c_std_11)

add_library(quic_trace_cpp INTERFACE)
add_library(quic_trace::cpp ALIAS quic_trace_cpp)
set_target_properties(quic_trace_cpp PROPERTIES EXPORT_NAME cpp)
target_link_libraries(quic_trace_cpp INTERFACE quic_trace_provider)
target_compile_features(quic_trace_cpp INTERFACE cxx_std_17)

if(BUILD_TESTING)
  add_executable(quic_trace_cpp_test cpp/tests/trace_test.cpp)
  target_link_libraries(quic_trace_cpp_test PRIVATE quic_trace_cpp)
  add_test(NAME quic_trace_cpp_test COMMAND quic_trace_cpp_test)
endif()

install(TARGETS quic_trace_provider quic_trace_cpp EXPORT quic_trace_targets)
install(FILES "${PROVIDER_DIR}/interface.h" "${PROVIDER_DIR}/trace.hpp"
  DESTINATION include/quic_trace)
install(EXPORT quic_trace_targets NAMESPACE quic_trace:: DESTINATION lib/cmake/quic_trace)
configure_package_config_file(
  cmake/quic_traceConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfig.cmake"
  INSTALL_DESTINATION lib/cmake/quic_trace
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfigVersion.cmake"
  DESTINATION lib/cmake/quic_trace
)
