#ifndef LFS_HAL_H
#define LFS_HAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lfs.h"

// LittleFS filesystem size: 64KB (16 × 4KB blocks) at end of flash
#define LFS_FLASH_SIZE    (64 * 1024)

/**
 * Initialize and mount the LittleFS filesystem.
 * On first boot (or corrupted filesystem), formats the flash area automatically.
 * Must be called before any other lfs_hal functions.
 * @return true on success, false on failure
 */
bool lfs_hal_init(void);

/**
 * Unmount the LittleFS filesystem.
 */
void lfs_hal_deinit(void);

/**
 * Read a file from the LittleFS filesystem.
 * @param path  File path (e.g. "/wifi.dat")
 * @param buf   Output buffer
 * @param size  Maximum bytes to read
 * @return Number of bytes read, or -1 on error
 */
int lfs_hal_read_file(const char *path, void *buf, size_t size);

/**
 * Write a file to the LittleFS filesystem (creates or overwrites).
 * @param path  File path (e.g. "/wifi.dat")
 * @param buf   Data to write
 * @param size  Number of bytes to write
 * @return true on success, false on failure
 */
bool lfs_hal_write_file(const char *path, const void *buf, size_t size);

/**
 * Delete a file from the LittleFS filesystem.
 * @param path  File path (e.g. "/wifi.dat")
 * @return true if deleted (or didn't exist), false on error
 */
bool lfs_hal_delete_file(const char *path);

#endif // LFS_HAL_H
