#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "vikingbio.h"

static void test_binary_stream(void) {
    vikingbio_stream_t stream;
    vikingbio_data_t data;
    const uint8_t bytes[] = {
        0xAA, 0xAA, 0x01, 50, 0, 75, 0x55,
        0xAA, 0x00, 0, 0, 0, 0x55,
    };
    vikingbio_stream_init(&stream);
    int count = 0;
    for (size_t i = 0; i < sizeof(bytes); i++) {
        if (vikingbio_stream_push(&stream, bytes[i], &data)) {
            count++;
            if (count == 1) {
                assert(data.valid && data.flame_detected && data.fan_speed == 50 &&
                       data.temperature == 75);
            } else {
                assert(data.valid && !data.flame_detected && data.temperature == 0);
            }
        }
    }
    assert(count == 2);
}

static void test_text_stream(void) {
    vikingbio_stream_t stream;
    vikingbio_data_t data;
    const char *text = "F:1,S:42,T:73\r\n";
    vikingbio_stream_init(&stream);
    int count = 0;
    for (size_t i = 0; i < strlen(text); i++) {
        if (vikingbio_stream_push(&stream, (uint8_t)text[i], &data)) {
            count++;
            assert(data.valid && data.flame_detected && data.fan_speed == 42 &&
                   data.temperature == 73);
        }
    }
    assert(count == 1);
}

int main(void) {
    vikingbio_init();
    test_binary_stream();
    test_text_stream();
    return 0;
}
