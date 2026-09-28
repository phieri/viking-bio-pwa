/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

#include "vikingbio.h"

#include <stdio.h>
#include <string.h>

#define VIKINGBIO_MAX_PARSERS 8

static vikingbio_context_t g_default_context;
static vikingbio_clock_fn g_clock_provider = NULL;
static const vikingbio_parser_t *g_registered_parsers[VIKINGBIO_MAX_PARSERS];
static size_t g_registered_parser_count = 0;
static bool g_registry_initialized = false;

static uint32_t vikingbio_now_ms(void) {
    return g_clock_provider != NULL ? g_clock_provider() : 0U;
}

static void vikingbio_reset_parser_registry(void) {
    g_registered_parser_count = 0;
    memset(g_registered_parsers, 0, sizeof(g_registered_parsers));
}

static bool vikingbio_parse_binary_v20(const uint8_t *buffer, size_t length, vikingbio_data_t *data) {
    if (buffer == NULL || data == NULL || length < VIKINGBIO_MIN_BINARY_PACKET_SIZE) {
        return false;
    }

    memset(data, 0, sizeof(*data));
    data->valid = false;
    data->model = VIKINGBIO_MODEL_VIKING_BIO_20;

    for (size_t i = 0; i + VIKINGBIO_MIN_BINARY_PACKET_SIZE <= length; ++i) {
        if (buffer[i] != VIKINGBIO_BINARY_START_BYTE) {
            continue;
        }
        if (buffer[i + 5] != VIKINGBIO_BINARY_END_BYTE) {
            continue;
        }

        const uint8_t flags = buffer[i + 1];
        const uint8_t fan_speed = buffer[i + 2];
        const uint8_t temp_high = buffer[i + 3];
        const uint8_t temp_low = buffer[i + 4];
        const uint16_t temp = ((uint16_t)temp_high << 8) | temp_low;

        if (temp > VIKINGBIO_MAX_TEMPERATURE_C) {
            continue;
        }

        data->flame_detected = (flags & 0x01u) != 0u;
        data->fan_speed = fan_speed > 100u ? 100u : fan_speed;
        data->temperature = temp;
        data->error_code = (flags >> 1) & 0x7Fu;
        data->valid = true;
        return true;
    }

    return false;
}

static bool vikingbio_probe_binary_v20(const uint8_t *buffer, size_t length) {
    if (buffer == NULL || length < VIKINGBIO_MIN_BINARY_PACKET_SIZE) {
        return false;
    }

    for (size_t i = 0; i + VIKINGBIO_MIN_BINARY_PACKET_SIZE <= length; ++i) {
        if (buffer[i] == VIKINGBIO_BINARY_START_BYTE && buffer[i + 5] == VIKINGBIO_BINARY_END_BYTE) {
            return true;
        }
    }
    return false;
}

static bool vikingbio_parse_text_v20(const uint8_t *buffer, size_t length, vikingbio_data_t *data) {
    if (buffer == NULL || data == NULL || length == 0 || length >= VIKINGBIO_MAX_TEXT_LENGTH) {
        return false;
    }

    char text[VIKINGBIO_MAX_TEXT_LENGTH];
    size_t copy_len = length < (sizeof(text) - 1U) ? length : (sizeof(text) - 1U);
    memcpy(text, buffer, copy_len);
    text[copy_len] = '\0';

    int flame = 0;
    int speed = 0;
    int temp = 0;
    if (sscanf(text, "F:%d,S:%d,T:%d", &flame, &speed, &temp) != 3) {
        return false;
    }

    if (temp < 0 || temp > VIKINGBIO_MAX_TEMPERATURE_C) {
        return false;
    }

    memset(data, 0, sizeof(*data));
    data->flame_detected = flame != 0;
    data->fan_speed = (uint8_t)(speed < 0 ? 0 : (speed > 100 ? 100 : speed));
    data->temperature = (uint16_t)temp;
    data->error_code = 0u;
    data->valid = true;
    data->model = VIKINGBIO_MODEL_VIKING_BIO_20;
    return true;
}

static bool vikingbio_probe_text_v20(const uint8_t *buffer, size_t length) {
    if (buffer == NULL || length < 10U || length >= VIKINGBIO_MAX_TEXT_LENGTH) {
        return false;
    }

    const char *needle_f = memchr(buffer, 'F', length);
    const char *needle_s = memchr(buffer, 'S', length);
    const char *needle_t = memchr(buffer, 'T', length);
    return needle_f != NULL && needle_s != NULL && needle_t != NULL;
}

static void vikingbio_register_default_parsers(void) {
    static const vikingbio_parser_t default_parsers[] = {
        {"Viking Bio 20 binary", VIKINGBIO_MODEL_VIKING_BIO_20, vikingbio_probe_binary_v20,
         vikingbio_parse_binary_v20},
        {"Viking Bio 20 text", VIKINGBIO_MODEL_VIKING_BIO_20, vikingbio_probe_text_v20,
         vikingbio_parse_text_v20},
    };

    if (g_registry_initialized) {
        return;
    }

    for (size_t i = 0; i < (sizeof(default_parsers) / sizeof(default_parsers[0])); ++i) {
        vikingbio_register_parser(&default_parsers[i]);
    }
    g_registry_initialized = true;
}

void vikingbio_context_init(vikingbio_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->current.valid = false;
    ctx->current.model = VIKINGBIO_MODEL_UNKNOWN;
    ctx->last_success_ms = 0U;
    ctx->now_ms = g_clock_provider;
}

void vikingbio_set_clock_provider(vikingbio_clock_fn clock) {
    g_clock_provider = clock;
    g_default_context.now_ms = clock;
}

void vikingbio_register_parser(const vikingbio_parser_t *parser) {
    if (parser == NULL || g_registered_parser_count >= VIKINGBIO_MAX_PARSERS) {
        return;
    }
    if (parser->probe == NULL || parser->parse == NULL) {
        return;
    }
    g_registered_parsers[g_registered_parser_count++] = parser;
}

void vikingbio_init(void) {
    vikingbio_reset_parser_registry();
    g_registry_initialized = false;
    vikingbio_register_default_parsers();
    vikingbio_context_init(&g_default_context);
    g_default_context.now_ms = g_clock_provider;
}

bool vikingbio_detect_and_parse(vikingbio_context_t *ctx, const uint8_t *buffer, size_t length,
                                vikingbio_data_t *data) {
    if (data == NULL) {
        return false;
    }
    if (ctx == NULL) {
        ctx = &g_default_context;
    }

    vikingbio_register_default_parsers();

    memset(data, 0, sizeof(*data));
    data->valid = false;
    data->model = VIKINGBIO_MODEL_UNKNOWN;

    for (size_t i = 0; i < g_registered_parser_count; ++i) {
        const vikingbio_parser_t *parser = g_registered_parsers[i];
        if (parser == NULL || parser->probe == NULL || parser->parse == NULL) {
            continue;
        }
        if (!parser->probe(buffer, length)) {
            continue;
        }
        if (!parser->parse(buffer, length, data)) {
            continue;
        }

        memcpy(&ctx->current, data, sizeof(ctx->current));
        ctx->last_success_ms = vikingbio_now_ms();
        return true;
    }

    return false;
}

bool vikingbio_parse_data(const uint8_t *buffer, size_t length, vikingbio_data_t *data) {
    return vikingbio_detect_and_parse(&g_default_context, buffer, length, data);
}

void vikingbio_stream_init(vikingbio_stream_t *stream) {
    if (stream != NULL) {
        memset(stream, 0, sizeof(*stream));
    }
}

bool vikingbio_stream_push(vikingbio_stream_t *stream, uint8_t byte, vikingbio_data_t *data) {
    if (stream == NULL || data == NULL) {
        return false;
    }
    bool parsed = false;
    if (stream->binary_len == 0 && byte == VIKINGBIO_BINARY_START_BYTE) {
        stream->binary[stream->binary_len++] = byte;
    } else if (stream->binary_len > 0) {
        stream->binary[stream->binary_len++] = byte;
        if (stream->binary_len == sizeof(stream->binary)) {
            parsed = vikingbio_parse_data(stream->binary, stream->binary_len, data);
            stream->binary_len = 0;
            if (!parsed) {
                for (size_t j = 1; j < sizeof(stream->binary); j++) {
                    if (stream->binary[j] == VIKINGBIO_BINARY_START_BYTE) {
                        stream->binary_len = sizeof(stream->binary) - j;
                        memmove(stream->binary, stream->binary + j, stream->binary_len);
                        break;
                    }
                }
            }
        }
    }

    if (byte == '\n' || byte == '\r') {
        if (stream->text_len > 0 && !parsed) {
            parsed = vikingbio_parse_data(stream->text, stream->text_len, data);
        }
        stream->text_len = 0;
    } else if (byte >= 0x20 && byte <= 0x7e) {
        if (stream->text_len < sizeof(stream->text) - 1) {
            stream->text[stream->text_len++] = byte;
        } else {
            stream->text_len = 0;
        }
    } else {
        stream->text_len = 0;
    }
    return parsed;
}

void vikingbio_get_current_data(vikingbio_data_t *data) {
    if (data == NULL) {
        return;
    }
    memcpy(data, &g_default_context.current, sizeof(*data));
}

bool vikingbio_is_data_stale(uint32_t timeout_ms) {
    if (g_clock_provider == NULL) {
        return false;
    }
    const uint32_t now = vikingbio_now_ms();
    const uint32_t elapsed = now - g_default_context.last_success_ms;
    return elapsed >= timeout_ms;
}

