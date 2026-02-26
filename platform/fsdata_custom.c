/*
 * Empty compiled-in filesystem for lwIP httpd.
 * All content is served via fs_open_custom() in http_server.c.
 */
#include "lwip/apps/fs.h"

#define FS_ROOT  NULL
#define FS_NUMFILES 0

#if LWIP_HTTPD_FILE_STATE
void *fs_state_init(struct fs_file *file, const char *name) {
	(void)file; (void)name;
	return NULL;
}

void fs_state_free(struct fs_file *file, void *state) {
	(void)file; (void)state;
}
#endif /* LWIP_HTTPD_FILE_STATE */
