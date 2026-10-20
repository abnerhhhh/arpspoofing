cmake_minimum_required(VERSION 3.20)

project(arpspoof LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "This project uses the Windows Npcap SDK and must be built with a Windows toolchain.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Select a 64-bit CLion toolchain; the bundled Npcap libraries are x64.")
endif()

add_executable(arpspoof src/main.cpp
        src/adapters.cpp
        src/adapters.h
        src/Packet.cpp
        src/Packet.h)
target_compile_features(arpspoof PRIVATE cxx_std_17)
target_include_directories(arpspoof PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/Include")

# Use full paths so CLion does not accidentally select the 32-bit Npcap SDK libs.
target_link_libraries(arpspoof PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/Lib/x64/wpcap.lib"
    "${CMAKE_CURRENT_SOURCE_DIR}/Lib/x64/Packet.lib"
    Iphlpapi
    Ws2_32
)

if(MSVC)
    target_compile_options(arpspoof PRIVATE /W4 /permissive-)
else()
    target_compile_options(arpspoof PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Keep the small adapter-enumeration sample available as a separate CLion target.
add_executable(adapter_info test.cpp
        src/adapters.cpp
        src/adapters.h
        src/Packet.cpp
        src/Packet.h)
target_compile_features(adapter_info PRIVATE cxx_std_17)
target_link_libraries(adapter_info PRIVATE Iphlpapi Ws2_32)

