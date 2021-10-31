cmake_minimum_required(VERSION 3.20)
project(OpenProfinet)

set(CMAKE_CXX_STANDARD 20)

find_package(Threads REQUIRED)

include_directories(include)

add_executable(pntool main.cpp pcapInterface.c ProfinetTool.cpp)

target_link_libraries(pntool pcap Threads::Threads)

# set(CPACK_DEBIAN_PACKAGE_DEPENDS "")