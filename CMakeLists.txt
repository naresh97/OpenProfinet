cmake_minimum_required(VERSION 3.20)
project(OpenProfinet)
set(CMAKE_PROJECT_VERSION_MAJOR 0)
set(CMAKE_PROJECT_VERSION_MINOR 9)
set(CMAKE_PROJECT_VERSION_PATCH 2)

set(CMAKE_CXX_STANDARD 20)

find_package(Threads REQUIRED)

include_directories(include)

add_executable(pntool src/main.cpp src/pcapInterface.c src/ProfinetTool.cpp)

target_link_libraries(pntool pcap Threads::Threads)

install(TARGETS pntool DESTINATION bin)

set(CPACK_GENERATOR DEB)
set(CPACK_DEBIAN_PACKAGE_NAME OpenProfinet)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Nareshkumar Rao <contact@nareshkumarrao.com>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpcap0.8-dev")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "
OpenProfinet is a collection of tools for working with Profinet on Linux
https://github.com/naresh97/OpenProfinet
")
set(CPACK_DEBIAN_FILE_NAME OpenProfinet-${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH}.deb)
include(CPack)
