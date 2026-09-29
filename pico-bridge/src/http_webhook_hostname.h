#ifndef HTTP_WEBHOOK_HOSTNAME_H
#define HTTP_WEBHOOK_HOSTNAME_H

#include <stdbool.h>
#include <stddef.h>

static inline bool webhook_dns_hostname_valid(const char *host) {
	if (!host || !*host) return false;
	bool has_letter = false;
	size_t label_len = 0;
	char previous = '\0';
	for (const char *p = host; *p; ++p) {
		char c = *p;
		if (c == '.') {
			if (!label_len || previous == '-') return false;
			label_len = 0;
		} else {
			bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
			bool digit = c >= '0' && c <= '9';
			if ((!letter && !digit && c != '-') || (!label_len && c == '-') ||
				++label_len > 63) return false;
			has_letter |= letter;
		}
		previous = c;
	}
	return has_letter && label_len > 0 && previous != '-';
}

#endif
