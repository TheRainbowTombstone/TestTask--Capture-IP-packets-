cmake_minimum_required(VERSION 3.10)

project(PcapProject)

set(CMAKE_CXX_STANDARD 11)

include_directories(external/libpcap-1.10.1)

set(SOURCES 
    src/main.cpp
    src/pcap_handler.cpp
    src/pcap_handler.h
)

add_executable(traffic_analyzer ${SOURCES})

find_library(PCAP_LIBRARY NAMES pcap PATHS ${CMAKE_SOURCE_DIR}/external/libpcap-1.10.1)
target_link_libraries(traffic_analyzer PRIVATE ${PCAP_LIBRARY})