#ifndef VIKING_BIO_PROTOCOL_H
#define VIKING_BIO_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vikingbio.h"

#ifndef UART_PARITY_NONE
#define UART_PARITY_NONE 0
#endif

#define VIKING_BIO_BAUD_RATE 9600
#define VIKING_BIO_DATA_BITS 8
#define VIKING_BIO_STOP_BITS 1
#define VIKING_BIO_PARITY UART_PARITY_NONE
#define VIKING_BIO_MIN_PACKET_SIZE VIKINGBIO_MIN_BINARY_PACKET_SIZE

typedef vikingbio_data_t viking_bio_data_t;

void viking_bio_init(void);
bool viking_bio_parse_data(const uint8_t *buffer, size_t length, viking_bio_data_t *data)
    __attribute__((hot));
void viking_bio_get_current_data(viking_bio_data_t *data);
bool viking_bio_is_data_stale(uint32_t timeout_ms);

#endif
