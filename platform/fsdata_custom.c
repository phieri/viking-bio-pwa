/*
 * Empty compiled-in filesystem for lwIP httpd.
 * All content is served via fs_open_custom() in http_server.c.
 */
#include "lwip/apps/fs.h"

#define FS_ROOT  NULL
#define FS_NUMFILES 0
