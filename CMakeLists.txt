cmake_minimum_required(VERSION 3.20)
project(moq_trace VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
include(CMakePackageConfigHelpers)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LTTNG_UST REQUIRED IMPORTED_TARGET lttng-ust>=2.13)
find_program(LTTNG_GEN_TP lttng-gen-tp REQUIRED)

set(QUIC_PROVIDER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/crates/quic-trace-lttng-sys/provider")
set(MOQ_PROVIDER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/crates/moq-trace-lttng-sys/provider")
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}/quic" "${GENERATED_DIR}/moq")

add_custom_command(
  OUTPUT "${GENERATED_DIR}/quic/events.h"
  COMMAND "${LTTNG_GEN_TP}" "${QUIC_PROVIDER_DIR}/events.tp" -o events.h
  WORKING_DIRECTORY "${GENERATED_DIR}/quic"
  DEPENDS "${QUIC_PROVIDER_DIR}/events.tp" "${QUIC_PROVIDER_DIR}/interface.h"
  VERBATIM
)

add_library(quic_trace_provider STATIC
  "${QUIC_PROVIDER_DIR}/interface.c"
  "${GENERATED_DIR}/quic/events.h"
)
add_library(quic_trace::provider ALIAS quic_trace_provider)
set_target_properties(quic_trace_provider PROPERTIES EXPORT_NAME provider)
target_include_directories(quic_trace_provider PUBLIC
  "$<BUILD_INTERFACE:${QUIC_PROVIDER_DIR}>"
  "$<INSTALL_INTERFACE:include/quic_trace>"
  PRIVATE "${GENERATED_DIR}/quic"
)
target_link_libraries(quic_trace_provider PUBLIC PkgConfig::LTTNG_UST)
target_compile_features(quic_trace_provider PUBLIC c_std_11)

add_library(quic_trace_cpp INTERFACE)
add_library(quic_trace::cpp ALIAS quic_trace_cpp)
set_target_properties(quic_trace_cpp PROPERTIES EXPORT_NAME cpp)
target_link_libraries(quic_trace_cpp INTERFACE quic_trace_provider)
target_include_directories(quic_trace_cpp INTERFACE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<INSTALL_INTERFACE:include>"
)
target_compile_features(quic_trace_cpp INTERFACE cxx_std_17)

add_custom_command(
  OUTPUT "${GENERATED_DIR}/moq/events.h"
  COMMAND "${LTTNG_GEN_TP}" "${MOQ_PROVIDER_DIR}/events.tp" -o events.h
  WORKING_DIRECTORY "${GENERATED_DIR}/moq"
  DEPENDS "${MOQ_PROVIDER_DIR}/events.tp" "${MOQ_PROVIDER_DIR}/interface.h"
  VERBATIM
)

add_library(moq_trace_provider STATIC
  "${MOQ_PROVIDER_DIR}/interface.c"
  "${GENERATED_DIR}/moq/events.h"
)
add_library(moq_trace::provider ALIAS moq_trace_provider)
set_target_properties(moq_trace_provider PROPERTIES EXPORT_NAME provider)
target_include_directories(moq_trace_provider PUBLIC
  "$<BUILD_INTERFACE:${MOQ_PROVIDER_DIR}>"
  "$<INSTALL_INTERFACE:include/moq_trace>"
  PRIVATE "${GENERATED_DIR}/moq"
)
target_link_libraries(moq_trace_provider PUBLIC PkgConfig::LTTNG_UST)
target_compile_features(moq_trace_provider PUBLIC c_std_11)

add_library(moq_trace_cpp INTERFACE)
add_library(moq_trace::cpp ALIAS moq_trace_cpp)
set_target_properties(moq_trace_cpp PROPERTIES EXPORT_NAME cpp)
target_link_libraries(moq_trace_cpp INTERFACE moq_trace::provider quic_trace::cpp)
target_include_directories(moq_trace_cpp INTERFACE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<INSTALL_INTERFACE:include>"
)
target_compile_features(moq_trace_cpp INTERFACE cxx_std_17)

if(BUILD_TESTING)
  add_executable(quic_trace_cpp_test cpp/tests/trace_test.cpp)
  target_link_libraries(quic_trace_cpp_test PRIVATE quic_trace_cpp)
  add_test(NAME quic_trace_cpp_test COMMAND quic_trace_cpp_test)
  add_executable(moq_trace_cpp_test cpp/tests/object_trace_test.cpp)
  target_link_libraries(moq_trace_cpp_test PRIVATE moq_trace_cpp)
  add_test(NAME moq_trace_cpp_test COMMAND moq_trace_cpp_test)
endif()

install(TARGETS quic_trace_provider quic_trace_cpp EXPORT quic_trace_targets)
install(TARGETS moq_trace_provider moq_trace_cpp EXPORT moq_trace_targets)
install(FILES "${QUIC_PROVIDER_DIR}/interface.h" "${CMAKE_CURRENT_SOURCE_DIR}/include/quic_trace/trace.hpp"
  DESTINATION include/quic_trace)
install(FILES "${MOQ_PROVIDER_DIR}/interface.h" "${CMAKE_CURRENT_SOURCE_DIR}/include/moq_trace/trace.hpp"
  DESTINATION include/moq_trace)
install(EXPORT quic_trace_targets NAMESPACE quic_trace:: DESTINATION lib/cmake/quic_trace)
install(EXPORT moq_trace_targets NAMESPACE moq_trace:: DESTINATION lib/cmake/moq_trace)
configure_package_config_file(
  cmake/quic_traceConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfig.cmake"
  INSTALL_DESTINATION lib/cmake/quic_trace
)
configure_package_config_file(
  cmake/moq_traceConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/moq_traceConfig.cmake"
  INSTALL_DESTINATION lib/cmake/moq_trace
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/moq_traceConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfigVersion.cmake"
  DESTINATION lib/cmake/quic_trace
)
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/moq_traceConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/moq_traceConfigVersion.cmake"
  DESTINATION lib/cmake/moq_trace
)
