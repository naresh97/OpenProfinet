cmake_minimum_required(VERSION 3.20)
project(OpenProfinet)

set(CMAKE_CXX_STANDARD 20)

find_package(Threads REQUIRED)

add_executable(OpenProfinet main.cpp pcapInterface.c ProfinetTool.cpp)

target_link_libraries(OpenProfinet pcap Threads::Threads)