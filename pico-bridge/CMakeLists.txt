cmake_minimum_required(VERSION 3.17)

include(FetchContent)

# This firmware requires Pico W for WiFi support
if(NOT DEFINED PICO_BOARD OR PICO_BOARD STREQUAL "")
    set(PICO_BOARD pico_w CACHE STRING "Board type" FORCE)
    message(STATUS "Setting PICO_BOARD to pico_w (required for WiFi)")
elseif(NOT PICO_BOARD STREQUAL "pico_w")
    message(FATAL_ERROR "This firmware requires PICO_BOARD=pico_w (current: ${PICO_BOARD})")
endif()

# Custom mbedTLS configuration (must be before pico_sdk_import.cmake)
add_compile_definitions(MBEDTLS_ALLOW_PRIVATE_ACCESS)
set(PICO_MBEDTLS_CONFIG_HEADER "${CMAKE_CURRENT_LIST_DIR}/platform/mbedtls_config.h"
    CACHE STRING "Custom mbedTLS config" FORCE)

# Initialize the Pico SDK
include(pico_sdk_import.cmake)

project(viking_bio_bridge C CXX ASM)

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

# WiFi credentials - optional at build time (primary configuration is via USB serial)
if(DEFINED ENV{WIFI_SSID} AND NOT DEFINED WIFI_SSID)
    set(WIFI_SSID "$ENV{WIFI_SSID}")
endif()
if(DEFINED ENV{WIFI_PASSWORD} AND NOT DEFINED WIFI_PASSWORD)
    set(WIFI_PASSWORD "$ENV{WIFI_PASSWORD}")
endif()

set(WIFI_COMPILE_CREDS_VALID 0)
if(DEFINED WIFI_SSID AND NOT WIFI_SSID STREQUAL "")
    set(WIFI_COMPILE_CREDS_VALID 1)
    message(STATUS "WiFi SSID: ${WIFI_SSID} (compile-time fallback enabled)")
else()
    set(WIFI_SSID "")
    set(WIFI_PASSWORD "")
    message(STATUS "WiFi SSID: not set (configure via USB serial at runtime)")
endif()

add_compile_definitions(
    WIFI_SSID="${WIFI_SSID}"
    WIFI_PASSWORD="${WIFI_PASSWORD}"
    WIFI_COMPILE_CREDS_VALID=${WIFI_COMPILE_CREDS_VALID}
)

# Initialize the Pico SDK
pico_sdk_init()

# Fetch LittleFS source for flash wear leveling
FetchContent_Declare(
    littlefs
    GIT_REPOSITORY https://github.com/littlefs-project/littlefs.git
    GIT_TAG        v2.11.2
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(littlefs)
if(NOT littlefs_POPULATED)
    FetchContent_Populate(littlefs)
endif()

# Compiler optimizations
add_compile_options(-O2)

# Define source files
set(SOURCES
    src/main.c
    src/version.c
    src/serial_handler.c
    src/viking_bio_protocol.c
    src/http_client.c
    src/push_manager.c
    src/wifi_config.c
    src/lfs_hal.c
    ${littlefs_SOURCE_DIR}/lfs.c
    ${littlefs_SOURCE_DIR}/lfs_util.c
    platform/mbedtls_time.c
)

add_executable(viking_bio_bridge ${SOURCES})

target_include_directories(viking_bio_bridge PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
    ${littlefs_SOURCE_DIR}
)

# Pull in dependencies
target_link_libraries(viking_bio_bridge
    pico_stdlib
    hardware_uart
    hardware_gpio
    hardware_sync
    hardware_flash
    hardware_watchdog
    pico_unique_id
    pico_cyw43_arch_lwip_poll
    pico_mbedtls
    pico_lwip_mdns
)

# Enable USB output, disable UART output
pico_enable_stdio_usb(viking_bio_bridge 1)
pico_enable_stdio_uart(viking_bio_bridge 0)

# Create map/bin/hex/uf2 file etc.
pico_add_extra_outputs(viking_bio_bridge)

# Rename output files to include version
add_custom_command(TARGET viking_bio_bridge POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_bridge.uf2
        ${CMAKE_BINARY_DIR}/viking_bio_bridge-${FIRMWARE_VERSION}.uf2
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_bridge.elf
        ${CMAKE_BINARY_DIR}/viking_bio_bridge-${FIRMWARE_VERSION}.elf
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_bridge.bin
        ${CMAKE_BINARY_DIR}/viking_bio_bridge-${FIRMWARE_VERSION}.bin
    COMMAND ${CMAKE_COMMAND} -E rename
        ${CMAKE_BINARY_DIR}/viking_bio_bridge.hex
        ${CMAKE_BINARY_DIR}/viking_bio_bridge-${FIRMWARE_VERSION}.hex
    COMMENT "Renaming firmware files: viking_bio_bridge-${FIRMWARE_VERSION}.*"
)
