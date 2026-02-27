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
# Enables ECP/P-256 for VAPID keys and HKDF for Web Push payload encryption
add_compile_definitions(MBEDTLS_ALLOW_PRIVATE_ACCESS)
set(PICO_MBEDTLS_CONFIG_HEADER "${CMAKE_CURRENT_LIST_DIR}/platform/mbedtls_config.h"
    CACHE STRING "Custom mbedTLS config" FORCE)

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

# Unix timestamp at build time – used by push_manager.c as the approximate
# base epoch for VAPID JWT expiry (no NTP on RP2040).
execute_process(
    COMMAND python3 -c "import time; print(int(time.time()))"
    OUTPUT_VARIABLE BUILD_UNIX_TIME
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT BUILD_UNIX_TIME OR BUILD_UNIX_TIME STREQUAL "")
    set(BUILD_UNIX_TIME 1740614400)  # 2026-02-27 fallback
endif()
add_compile_definitions(BUILD_UNIX_TIME=${BUILD_UNIX_TIME})
# ============================================

# WiFi credentials - optional at build time (primary configuration is via USB serial)
# Set via: cmake -DWIFI_SSID="your_ssid" -DWIFI_PASSWORD="your_password" ..
# Or via environment variables WIFI_SSID and WIFI_PASSWORD
if(DEFINED ENV{WIFI_SSID} AND NOT DEFINED WIFI_SSID)
    set(WIFI_SSID "$ENV{WIFI_SSID}")
endif()
if(DEFINED ENV{WIFI_PASSWORD} AND NOT DEFINED WIFI_PASSWORD)
    set(WIFI_PASSWORD "$ENV{WIFI_PASSWORD}")
endif()

# Determine whether real compile-time credentials were supplied
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

# Fetch LittleFS source for flash wear leveling (after project/pico_sdk_init)
FetchContent_Declare(
    littlefs
    GIT_REPOSITORY https://github.com/littlefs-project/littlefs.git
    GIT_TAG        v2.9.3
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(littlefs)
if(NOT littlefs_POPULATED)
    FetchContent_Populate(littlefs)
endif()

# Compiler optimizations
add_compile_options(
    -O2
)

# Generate web_content.h from web source files
find_program(PYTHON3_EXECUTABLE python3)
if(NOT PYTHON3_EXECUTABLE)
    find_program(PYTHON3_EXECUTABLE python)
endif()
if(NOT PYTHON3_EXECUTABLE)
    message(FATAL_ERROR "Python 3 is required to generate web_content.h")
endif()

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/web_content.h
    COMMAND ${PYTHON3_EXECUTABLE}
        ${CMAKE_SOURCE_DIR}/cmake/gen_web_content.py
        ${CMAKE_BINARY_DIR}/web_content.h
        ${CMAKE_SOURCE_DIR}/src/web/index.html INDEX_HTML
        ${CMAKE_SOURCE_DIR}/src/web/sw.js SW_JS
        ${CMAKE_SOURCE_DIR}/src/web/manifest.json MANIFEST_JSON
        ${CMAKE_SOURCE_DIR}/src/web/style.css STYLE_CSS
        ${CMAKE_SOURCE_DIR}/src/web/app.js APP_JS
    DEPENDS
        ${CMAKE_SOURCE_DIR}/src/web/index.html
        ${CMAKE_SOURCE_DIR}/src/web/sw.js
        ${CMAKE_SOURCE_DIR}/src/web/manifest.json
        ${CMAKE_SOURCE_DIR}/src/web/style.css
        ${CMAKE_SOURCE_DIR}/src/web/app.js
        ${CMAKE_SOURCE_DIR}/cmake/gen_web_content.py
    COMMENT "Generating web_content.h from web source files"
)
add_custom_target(web_content DEPENDS ${CMAKE_BINARY_DIR}/web_content.h)

# Define source files
set(SOURCES
    src/main.c
    src/version.c
    src/serial_handler.c
    src/viking_bio_protocol.c
    src/http_server.c
    src/push_manager.c
    src/wifi_config.c
    src/lfs_hal.c
    src/flame_counter.c
    ${littlefs_SOURCE_DIR}/lfs.c
    ${littlefs_SOURCE_DIR}/lfs_util.c
    platform/mbedtls_time.c
)

add_executable(viking_bio_pwa ${SOURCES})
add_dependencies(viking_bio_pwa web_content)

target_include_directories(viking_bio_pwa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
    ${CMAKE_BINARY_DIR}
    ${littlefs_SOURCE_DIR}
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
    pico_rand
    pico_runtime
    pico_cyw43_arch_lwip_poll
    pico_mbedtls
    pico_lwip_mbedtls
    pico_lwip_mdns
    pico_lwip_http
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
