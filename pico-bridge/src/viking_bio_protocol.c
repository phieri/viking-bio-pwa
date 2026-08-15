#include "pico/stdlib.h"
#include "viking_bio_protocol.h"

static uint32_t viking_bio_now_ms(void) {
    return to_ms_since_boot(get_absolute_time());
}

void viking_bio_init(void) {
    vikingbio_set_clock_provider(viking_bio_now_ms);
    vikingbio_init();
}

bool viking_bio_parse_data(const uint8_t *buffer, size_t length, viking_bio_data_t *data) {
    return vikingbio_parse_data(buffer, length, data);
}

void viking_bio_get_current_data(viking_bio_data_t *data) {
    vikingbio_get_current_data(data);
}

bool viking_bio_is_data_stale(uint32_t timeout_ms) {
    return vikingbio_is_data_stale(timeout_ms);
}
