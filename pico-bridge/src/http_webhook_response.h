#ifndef HTTP_WEBHOOK_RESPONSE_H
#define HTTP_WEBHOOK_RESPONSE_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define WEBHOOK_RESPONSE_HEADERS_MAX 1024

typedef struct {
	char headers[WEBHOOK_RESPONSE_HEADERS_MAX];
	size_t len;
	int status;
} webhook_response_t;

static inline bool webhook_response_feed(webhook_response_t *response, char ch) {
	if ((unsigned char)ch < 32 && ch != '\r' && ch != '\n' && ch != '\t') return false;
	if ((unsigned char)ch == 127) return false;
	if (response->len >= sizeof(response->headers) - 1) return false;
	response->headers[response->len++] = ch;
	response->headers[response->len] = '\0';
	if (response->len < 4 ||
		memcmp(response->headers + response->len - 4, "\r\n\r\n", 4) != 0) return true;

	const char *line_end = strstr(response->headers, "\r\n");
	if (line_end == NULL || line_end - response->headers < 12 ||
		strncmp(response->headers, "HTTP/1.", 7) != 0 ||
		(response->headers[7] != '0' && response->headers[7] != '1') ||
		response->headers[8] != ' ' ||
		response->headers[9] < '1' || response->headers[9] > '5' ||
		response->headers[10] < '0' || response->headers[10] > '9' ||
		response->headers[11] < '0' || response->headers[11] > '9' ||
		(response->headers[12] != ' ' && response->headers[12] != '\r')) return false;

	int status = (response->headers[9] - '0') * 100 +
				 (response->headers[10] - '0') * 10 + (response->headers[11] - '0');
	response->len = 0;
	if (status >= 100 && status < 200) return true;
	response->status = status;
	return true;
}

#endif
