cmake_minimum_required(VERSION 3.17)

# This firmware requires Pico W for WiFi support
if(NOT DEFINED PICO_BOARD OR PICO_BOARD STREQUAL "")
    set(PICO_BOARD pico_w CACHE STRING "Board type" FORCE)
    message(STATUS "Setting PICO_BOARD to pico_w (required for WiFi)")
elseif(NOT PICO_BOARD STREQUAL "pico_w")
    message(FATAL_ERROR "This firmware requires PICO_BOARD=pico_w (current: ${PICO_BOARD})")
endif()

# Initialize the Pico SDK
include(pico_sdk_import.cmake)

project(viking_bio_pwa C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# ============================================
# Build Version Information
# ============================================
execute_process(
    COMMAND git describe --tags --always --dirty
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

if(NOT GIT_VERSION)
    execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(GIT_COMMIT)
        set(GIT_VERSION "${GIT_COMMIT}")
    else()
        set(GIT_VERSION "unknown")
    endif()
endif()

string(TIMESTAMP BUILD_TIMESTAMP "%Y-%m-%d %H:%M:%S UTC" UTC)
set(FIRMWARE_VERSION "${GIT_VERSION}")

message(STATUS "Firmware Version: ${FIRMWARE_VERSION}")
message(STATUS "Build Timestamp: ${BUILD_TIMESTAMP}")

add_compile_definitions(
    FIRMWARE_VERSION="${FIRMWARE_VERSION}"
    BUILD_TIMESTAMP="${BUILD_TIMESTAMP}"
    GIT_COMMIT_HASH="${GIT_VERSION}"
)
# ============================================

# WiFi credentials - must be set at build time
# Set via: cmake -DWIFI_SSID="your_ssid" -DWIFI_PASSWORD="your_password" ..
# Or via environment variables WIFI_SSID and WIFI_PASSWORD
if(DEFINED ENV{WIFI_SSID} AND NOT DEFINED WIFI_SSID)
    set(WIFI_SSID "$ENV{WIFI_SSID}")
endif()
if(DEFINED ENV{WIFI_PASSWORD} AND NOT DEFINED WIFI_PASSWORD)
    set(WIFI_PASSWORD "$ENV{WIFI_PASSWORD}")
endif()

if(NOT DEFINED WIFI_SSID OR WIFI_SSID STREQUAL "")
    set(WIFI_SSID "viking_bio_network")
    message(WARNING "WIFI_SSID not set, using placeholder '${WIFI_SSID}'")
endif()
if(NOT DEFINED WIFI_PASSWORD OR WIFI_PASSWORD STREQUAL "")
    set(WIFI_PASSWORD "")
    message(WARNING "WIFI_PASSWORD not set, WiFi will be open")
endif()

add_compile_definitions(
    WIFI_SSID="${WIFI_SSID}"
    WIFI_PASSWORD="${WIFI_PASSWORD}"
)

message(STATUS "WiFi SSID: ${WIFI_SSID}")

# Initialize the Pico SDK
pico_sdk_init()

# Compiler optimizations
add_compile_options(
    -O2
)

# Define source files
set(SOURCES
    src/main.c
    src/version.c
    src/serial_handler.c
    src/viking_bio_protocol.c
    src/http_server.c
    src/push_manager.c
)

add_executable(viking_bio_pwa ${SOURCES})

target_include_directories(viking_bio_pwa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
)

# Pull in dependencies
target_link_libraries(viking_bio_pwa
    pico_stdlib
    hardware_uart
    hardware_gpio
    hardware_sync
    hardware_flash
    hardware_watchdog
    pico_unique_id
    pico_cyw43_arch_lwip_poll
    pico_mbedtls
)

# Enable USB output, disable UART output
pico_enable_stdio_usb(viking_bio_pwa 1)
pico_enable_stdio_uart(viking_bio_pwa 0)

# Create map/bin/hex/uf2 file etc.
pico_add_extra_outputs(viking_bio_pwa)

# Rename output files to include version
add_custom_command(TARGET viking_bio_pwa POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_pwa.uf2
        ${CMAKE_BINARY_DIR}/viking_bio_pwa-${FIRMWARE_VERSION}.uf2
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_pwa.elf
        ${CMAKE_BINARY_DIR}/viking_bio_pwa-${FIRMWARE_VERSION}.elf
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_pwa.bin
        ${CMAKE_BINARY_DIR}/viking_bio_pwa-${FIRMWARE_VERSION}.bin
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_pwa.hex
        ${CMAKE_BINARY_DIR}/viking_bio_pwa-${FIRMWARE_VERSION}.hex
    COMMENT "Renaming firmware files to include version: viking_bio_pwa-${FIRMWARE_VERSION}.*"
)
