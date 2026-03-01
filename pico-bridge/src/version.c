#include <stdio.h>
#include "version.h"

void version_print_info(void) {
	printf("Viking Bio PWA Firmware\n");
	printf("Version:   %s\n", FIRMWARE_VERSION);
	printf("Built:     %s\n", BUILD_TIMESTAMP);
	printf("Commit:    %s\n", GIT_COMMIT_HASH);
	printf("\n");
}

const char *version_get_firmware(void) {
	return FIRMWARE_VERSION;
}

const char *version_get_timestamp(void) {
	return BUILD_TIMESTAMP;
}
