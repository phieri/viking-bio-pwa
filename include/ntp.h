#ifndef NTP_H
#define NTP_H

#include <stdbool.h>

// Sync system time via NTP. Chooses server based on two-letter
// country code: if country == "SE" -> "ntp.se" else -> "pool.ntp.org".
// Returns true if time was set successfully.
bool ntp_sync_time_for_country(const char *country);

#endif // NTP_H
