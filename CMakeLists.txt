cmake_minimum_required(VERSION 3.20)
project(moq_trace VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
include(CMakePackageConfigHelpers)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LTTNG_UST REQUIRED IMPORTED_TARGET lttng-ust>=2.13)
find_program(LTTNG_GEN_TP lttng-gen-tp REQUIRED)

set(QUIC_PROVIDER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/crates/quic-trace-lttng-sys/provider")
set(MOQ_PROVIDER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/crates/moq-trace-lttng-sys/provider")
set(PROVIDER_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/crates/trace-provider-build/provider.c.in")

# Build the static library `<provider>_provider` from the schema in `directory`.
#
# The C source comes from the template the Rust provider crates build through
# trace-provider-build, so Cargo and CMake compile the same provider.
function(add_trace_provider provider directory)
  set(generated "${CMAKE_CURRENT_BINARY_DIR}/generated/${provider}")
  file(MAKE_DIRECTORY "${generated}")
  set(PROVIDER "${provider}")
  configure_file("${PROVIDER_TEMPLATE}" "${generated}/provider.c" @ONLY)
  add_custom_command(
    OUTPUT "${generated}/events.h"
    COMMAND "${LTTNG_GEN_TP}" "${directory}/events.tp" -o events.h
    WORKING_DIRECTORY "${generated}"
    DEPENDS "${directory}/events.tp" "${directory}/interface.h"
    VERBATIM
  )
  add_library(${provider}_provider STATIC
    "${generated}/provider.c"
    "${directory}/identity.c"
    "${generated}/events.h"
  )
  add_library(${provider}::provider ALIAS ${provider}_provider)
  set_target_properties(${provider}_provider PROPERTIES
    EXPORT_NAME provider
    POSITION_INDEPENDENT_CODE ON
  )
  target_include_directories(${provider}_provider PUBLIC
    "$<BUILD_INTERFACE:${directory}>"
    "$<INSTALL_INTERFACE:include/${provider}>"
    PRIVATE "${generated}"
  )
  target_link_libraries(${provider}_provider PUBLIC PkgConfig::LTTNG_UST)
  target_compile_features(${provider}_provider PUBLIC c_std_11)
endfunction()

add_trace_provider(quic_trace "${QUIC_PROVIDER_DIR}")
add_trace_provider(moq_trace "${MOQ_PROVIDER_DIR}")

add_library(quic_trace_cpp INTERFACE)
add_library(quic_trace::cpp ALIAS quic_trace_cpp)
set_target_properties(quic_trace_cpp PROPERTIES EXPORT_NAME cpp)
target_link_libraries(quic_trace_cpp INTERFACE quic_trace_provider)
target_include_directories(quic_trace_cpp INTERFACE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<INSTALL_INTERFACE:include>"
)
target_compile_features(quic_trace_cpp INTERFACE cxx_std_17)

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
  add_executable(facade_contract cpp/tests/facade_contract.cpp)
  target_link_libraries(facade_contract PRIVATE moq_trace_cpp)
  add_executable(quic_trace_cpp_test cpp/tests/trace_test.cpp)
  target_link_libraries(quic_trace_cpp_test PRIVATE quic_trace_cpp)
  # The tests count clock reads at the shared C clock, which the facade calls.
  target_link_options(quic_trace_cpp_test PRIVATE "LINKER:--wrap=quic_trace_now_ns")
  add_test(NAME quic_trace_cpp_test COMMAND quic_trace_cpp_test)
  add_executable(moq_trace_cpp_test cpp/tests/object_trace_test.cpp)
  target_link_libraries(moq_trace_cpp_test PRIVATE moq_trace_cpp)
  target_link_options(moq_trace_cpp_test PRIVATE "LINKER:--wrap=quic_trace_now_ns")
  add_test(NAME moq_trace_cpp_test COMMAND moq_trace_cpp_test)
endif()

install(TARGETS quic_trace_provider quic_trace_cpp EXPORT quic_trace_targets COMPONENT quic_trace)
install(TARGETS moq_trace_provider moq_trace_cpp EXPORT moq_trace_targets COMPONENT moq_trace)
install(FILES "${QUIC_PROVIDER_DIR}/interface.h" "${CMAKE_CURRENT_SOURCE_DIR}/include/quic_trace/trace.hpp"
  DESTINATION include/quic_trace COMPONENT quic_trace)
install(FILES "${MOQ_PROVIDER_DIR}/interface.h" "${CMAKE_CURRENT_SOURCE_DIR}/include/moq_trace/trace.hpp"
  DESTINATION include/moq_trace COMPONENT moq_trace)
install(EXPORT quic_trace_targets NAMESPACE quic_trace:: DESTINATION lib/cmake/quic_trace COMPONENT quic_trace)
install(EXPORT moq_trace_targets NAMESPACE moq_trace:: DESTINATION lib/cmake/moq_trace COMPONENT moq_trace)
configure_package_config_file(
  cmake/quic_traceConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/quic_traceConfig.cmake"
  INSTALL_DESTINATION lib/cmake/quic_trace
)
configure_file(cmake/quic_trace.pc.in quic_trace.pc @ONLY)
configure_file(cmake/moq_trace.pc.in moq_trace.pc @ONLY)
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
  COMPONENT quic_trace
)
install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/quic_trace.pc"
  DESTINATION lib/pkgconfig
  COMPONENT quic_trace
)
install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/moq_trace.pc"
  DESTINATION lib/pkgconfig
  COMPONENT moq_trace
)
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/moq_traceConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/moq_traceConfigVersion.cmake"
  DESTINATION lib/cmake/moq_trace
  COMPONENT moq_trace
)
