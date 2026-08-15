#ifndef VIKINGBIO_H
#define VIKINGBIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VIKINGBIO_BINARY_START_BYTE 0xAA
#define VIKINGBIO_BINARY_END_BYTE 0x55
#define VIKINGBIO_MIN_BINARY_PACKET_SIZE 6
#define VIKINGBIO_MAX_TEMPERATURE_C 500
#define VIKINGBIO_MAX_TEXT_LENGTH 256
#define VIKING_BIO_TIMEOUT_MS 30000U

typedef enum {
    VIKINGBIO_MODEL_UNKNOWN = 0,
    VIKINGBIO_MODEL_VIKING_BIO_20 = 1,
} vikingbio_model_t;

typedef struct {
    bool flame_detected;
    uint8_t fan_speed;
    uint16_t temperature;
    uint8_t error_code;
    bool valid;
    vikingbio_model_t model;
} vikingbio_data_t;

typedef bool (*vikingbio_probe_fn)(const uint8_t *buffer, size_t length);
typedef bool (*vikingbio_parse_fn)(const uint8_t *buffer, size_t length, vikingbio_data_t *data);

typedef struct {
    const char *name;
    vikingbio_model_t model;
    vikingbio_probe_fn probe;
    vikingbio_parse_fn parse;
} vikingbio_parser_t;

typedef uint32_t (*vikingbio_clock_fn)(void);

typedef struct {
    vikingbio_data_t current;
    uint32_t last_success_ms;
    vikingbio_clock_fn now_ms;
} vikingbio_context_t;

void vikingbio_context_init(vikingbio_context_t *ctx);
void vikingbio_set_clock_provider(vikingbio_clock_fn clock);
void vikingbio_register_parser(const vikingbio_parser_t *parser);

void vikingbio_init(void);
bool vikingbio_detect_and_parse(vikingbio_context_t *ctx, const uint8_t *buffer,
                                size_t length, vikingbio_data_t *data);
bool vikingbio_parse_data(const uint8_t *buffer, size_t length, vikingbio_data_t *data);
void vikingbio_get_current_data(vikingbio_data_t *data);
bool vikingbio_is_data_stale(uint32_t timeout_ms);

/*
 * Adding a new model later:
 *   1. Add a new vikingbio_model_t value.
 *   2. Implement a probe/parse pair for the protocol variant.
 *   3. Register the parser with vikingbio_register_parser().
 *   4. Keep the parse step model-specific while returning a shared vikingbio_data_t.
 */

#endif
