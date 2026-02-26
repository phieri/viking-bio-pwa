#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "lfs_hal.h"

// Flash layout: LittleFS occupies the last LFS_FLASH_SIZE bytes of flash
#define LFS_FLASH_OFFSET  (PICO_FLASH_SIZE_BYTES - LFS_FLASH_SIZE)
#define LFS_BLOCK_SIZE    FLASH_SECTOR_SIZE   // 4096
#define LFS_BLOCK_COUNT   (LFS_FLASH_SIZE / LFS_BLOCK_SIZE)  // 16

static lfs_t s_lfs;
static bool s_mounted = false;

// Read/prog buffers (must be at least cache_size bytes)
static uint8_t s_read_buf[FLASH_PAGE_SIZE];
static uint8_t s_prog_buf[FLASH_PAGE_SIZE];
static uint8_t s_lookahead_buf[16] __attribute__((aligned(4)));

// --- Block device callbacks ---

static int lfs_flash_read(const struct lfs_config *c, lfs_block_t block,
                           lfs_off_t off, void *buffer, lfs_size_t size) {
	(void)c;
	uint32_t addr = LFS_FLASH_OFFSET + block * LFS_BLOCK_SIZE + off;
	memcpy(buffer, (const void *)(XIP_BASE + addr), size);
	return LFS_ERR_OK;
}

static int lfs_flash_prog(const struct lfs_config *c, lfs_block_t block,
                           lfs_off_t off, const void *buffer, lfs_size_t size) {
	(void)c;
	uint32_t addr = LFS_FLASH_OFFSET + block * LFS_BLOCK_SIZE + off;
	uint32_t ints = save_and_disable_interrupts();
	flash_range_program(addr, (const uint8_t *)buffer, size);
	restore_interrupts(ints);
	return LFS_ERR_OK;
}

static int lfs_flash_erase(const struct lfs_config *c, lfs_block_t block) {
	(void)c;
	uint32_t addr = LFS_FLASH_OFFSET + block * LFS_BLOCK_SIZE;
	uint32_t ints = save_and_disable_interrupts();
	flash_range_erase(addr, LFS_BLOCK_SIZE);
	restore_interrupts(ints);
	return LFS_ERR_OK;
}

static int lfs_flash_sync(const struct lfs_config *c) {
	(void)c;
	return LFS_ERR_OK;
}

static const struct lfs_config s_lfs_cfg = {
	.read  = lfs_flash_read,
	.prog  = lfs_flash_prog,
	.erase = lfs_flash_erase,
	.sync  = lfs_flash_sync,

	.read_size      = 1,
	.prog_size      = FLASH_PAGE_SIZE,
	.block_size     = LFS_BLOCK_SIZE,
	.block_count    = LFS_BLOCK_COUNT,
	.cache_size     = FLASH_PAGE_SIZE,
	.lookahead_size = sizeof(s_lookahead_buf),
	.block_cycles   = 500,

	.read_buffer      = s_read_buf,
	.prog_buffer      = s_prog_buf,
	.lookahead_buffer = s_lookahead_buf,
};

bool lfs_hal_init(void) {
	if (s_mounted) return true;

	int err = lfs_mount(&s_lfs, &s_lfs_cfg);
	if (err != LFS_ERR_OK) {
		printf("lfs: mount failed (%d), formatting...\n", err);
		err = lfs_format(&s_lfs, &s_lfs_cfg);
		if (err != LFS_ERR_OK) {
			printf("lfs: format failed (%d)\n", err);
			return false;
		}
		err = lfs_mount(&s_lfs, &s_lfs_cfg);
		if (err != LFS_ERR_OK) {
			printf("lfs: mount after format failed (%d)\n", err);
			return false;
		}
	}

	s_mounted = true;
	printf("lfs: mounted (%d blocks of %d bytes)\n", LFS_BLOCK_COUNT, LFS_BLOCK_SIZE);
	return true;
}

void lfs_hal_deinit(void) {
	if (s_mounted) {
		lfs_unmount(&s_lfs);
		s_mounted = false;
	}
}

int lfs_hal_read_file(const char *path, void *buf, size_t size) {
	if (!s_mounted || !path || !buf) return -1;

	lfs_file_t file;
	if (lfs_file_open(&s_lfs, &file, path, LFS_O_RDONLY) < 0) {
		return -1;
	}

	lfs_ssize_t n = lfs_file_read(&s_lfs, &file, buf, size);
	lfs_file_close(&s_lfs, &file);
	return (n >= 0) ? (int)n : -1;
}

bool lfs_hal_write_file(const char *path, const void *buf, size_t size) {
	if (!s_mounted || !path || !buf) return false;

	lfs_file_t file;
	int flags = LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC;
	if (lfs_file_open(&s_lfs, &file, path, flags) < 0) {
		return false;
	}

	lfs_ssize_t n = lfs_file_write(&s_lfs, &file, buf, size);
	lfs_file_close(&s_lfs, &file);
	return (n == (lfs_ssize_t)size);
}

bool lfs_hal_delete_file(const char *path) {
	if (!s_mounted || !path) return false;

	int err = lfs_remove(&s_lfs, path);
	return (err == LFS_ERR_OK || err == LFS_ERR_NOENT);
}
