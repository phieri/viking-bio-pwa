#ifndef VIKING_BIO_PROTOCOL_H
#define VIKING_BIO_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Viking Bio 20 serial protocol definitions
#define VIKING_BIO_BAUD_RATE 9600
#define VIKING_BIO_DATA_BITS 8
#define VIKING_BIO_STOP_BITS 1
#define VIKING_BIO_PARITY UART_PARITY_NONE
#define VIKING_BIO_TIMEOUT_MS 30000  // 30 second timeout for stale data detection

// Data packet structure representing Viking Bio 20 burner state
typedef struct {
	bool flame_detected;    // True if flame is detected
	uint8_t fan_speed;      // Fan speed percentage (0-100)
	uint16_t temperature;   // Temperature in Celsius (0-500 valid range)
	uint8_t error_code;     // Error code if any (from FLAGS byte bits 1-7)
	bool valid;             // Data validity flag
} viking_bio_data_t;

/**
 * Initialize the Viking Bio protocol parser
 * Resets internal state to safe defaults
 */
void viking_bio_init(void);

/**
 * Parse Viking Bio data from a buffer
 * Supports both binary protocol (0xAA...0x55) and text protocol (F:1,S:50,T:75)
 *
 * @param buffer Input buffer containing serial data (must not be NULL)
 * @param length Length of buffer in bytes (must be >= 6 for binary protocol)
 * @param data Output structure to receive parsed data (must not be NULL)
 * @return true if valid data was parsed, false otherwise
 */
bool viking_bio_parse_data(const uint8_t *buffer, size_t length, viking_bio_data_t *data) __attribute__((hot));

/**
 * Get the current cached Viking Bio data
 * Returns the last successfully parsed data
 *
 * @param data Output structure to receive cached data (must not be NULL)
 */
void viking_bio_get_current_data(viking_bio_data_t *data);

/**
 * Check if serial data is stale (no data received for timeout period)
 *
 * @param timeout_ms Timeout period in milliseconds
 * @return true if no data received for timeout_ms, false otherwise
 */
bool viking_bio_is_data_stale(uint32_t timeout_ms);

#endif // VIKING_BIO_PROTOCOL_H
