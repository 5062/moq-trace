# Consumes the installed packages the way an out-of-tree relay does. The two
# packages are installed into separate prefixes by the `package` recipe, so this
# only configures when moq_trace resolves quic_trace through find_dependency.
cmake_minimum_required(VERSION 3.20)
project(moq_trace_consumer LANGUAGES CXX)

find_package(moq_trace CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE moq_trace::cpp)
