#include "pico/stdlib.h"
#include "pico/time.h"
#include <stdint.h>

/*
 * Provide millisecond timing for mbedTLS when MBEDTLS_PLATFORM_MS_TIME_ALT
 * is defined in mbedtls_config.h.
 *
 * mbedtls_ms_time() should return a millisecond counter. We use the Pico SDK
 * helper to_ms_since_boot(get_absolute_time()) and cast to unsigned long.
 * It's OK if this wraps around (32-bit rollover) — mbedTLS handles that.
 */

unsigned long mbedtls_ms_time(void)
{
    return (unsigned long) to_ms_since_boot(get_absolute_time());
}
