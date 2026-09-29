#include <assert.h>
#include <stdio.h>

#include "../src/http_webhook_hostname.h"

int main(void) {
	assert(webhook_dns_hostname_valid("alerts.example.org"));
	assert(webhook_dns_hostname_valid("node-1.example.org"));
	assert(!webhook_dns_hostname_valid(""));
	assert(!webhook_dns_hostname_valid("192.0.2.1"));
	assert(!webhook_dns_hostname_valid("2001:db8::1"));
	assert(!webhook_dns_hostname_valid("a..example.org"));
	assert(!webhook_dns_hostname_valid("-a.example.org"));
	assert(!webhook_dns_hostname_valid("a-.example.org"));
	assert(!webhook_dns_hostname_valid("a.example.org."));
	assert(!webhook_dns_hostname_valid("a_example.org"));
	puts("webhook hostname tests passed");
	return 0;
}
