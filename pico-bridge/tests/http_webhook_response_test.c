#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/http_webhook_response.h"

static bool feed(webhook_response_t *response, const char *part) {
	for (; *part != '\0'; ++part) {
		if (!webhook_response_feed(response, *part)) return false;
		if (response->status != 0) return true;
	}
	return true;
}

int main(void) {
	webhook_response_t response = {0};
	assert(feed(&response, "HTTP/1.1 20"));
	assert(response.status == 0);
	assert(feed(&response, "4 No Content\r\nDate: now\r\n"));
	assert(response.status == 0);
	assert(feed(&response, "\r\n"));
	assert(response.status == 204);

	memset(&response, 0, sizeof(response));
	assert(feed(&response, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n"));
	assert(response.status == 0);
	assert(feed(&response, "\r\n"));
	assert(response.status == 201);

	memset(&response, 0, sizeof(response));
	assert(feed(&response, "HTTP/1.1 100 Continue\r\n\r\n"));
	assert(response.status == 0);
	assert(feed(&response, "HTTP/1.1 503 Unavailable\r\n\r\n"));
	assert(response.status == 503);

	memset(&response, 0, sizeof(response));
	assert(feed(&response, "HTTP/1.1 401 Unauthorized\r\n\r\n"));
	assert(response.status == 401);

	memset(&response, 0, sizeof(response));
	assert(!feed(&response, "garbage\r\n\r\n"));

	memset(&response, 0, sizeof(response));
	assert(!feed(&response, "HTTP/1.1 20\r\n\r\n"));
	memset(&response, 0, sizeof(response));
	assert(!feed(&response, "HTTP/1.1 200X\r\n\r\n"));
	memset(&response, 0, sizeof(response));
	assert(feed(&response, "HTTP/1.1 200 OK\r\n"));
	assert(!webhook_response_feed(&response, '\0'));

	memset(&response, 0, sizeof(response));
	assert(feed(&response, "HTTP/1.0 200 OK\r\nX-Long: "));
	for (size_t i = 0; i < WEBHOOK_RESPONSE_HEADERS_MAX; ++i) {
		if (!webhook_response_feed(&response, 'x')) {
			puts("webhook response tests passed");
			return 0;
		}
	}
	assert(false);
}
