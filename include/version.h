#ifndef VERSION_H
#define VERSION_H

// Firmware version strings (set at compile time from CMakeLists.txt)
#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "unknown"
#endif

#ifndef BUILD_TIMESTAMP
#define BUILD_TIMESTAMP "unknown"
#endif

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "unknown"
#endif

/**
 * Print firmware version information to stdout
 */
void version_print_info(void);

/**
 * Get firmware version string
 * @return Pointer to firmware version string
 */
const char *version_get_firmware(void);

/**
 * Get build timestamp string
 * @return Pointer to build timestamp string
 */
const char *version_get_timestamp(void);

#endif // VERSION_H
