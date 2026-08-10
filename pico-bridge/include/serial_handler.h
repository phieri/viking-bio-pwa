#ifndef SERIAL_HANDLER_H
#define SERIAL_HANDLER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "hardware/sync.h"

// UART configuration for TTL serial input from Viking Bio 20
#define UART_ID uart0
#define UART_TX_PIN 0
#define UART_RX_PIN 1
#define SERIAL_BUFFER_SIZE 256

// External declarations for buffer state (defined in serial_handler.c)
extern volatile size_t buffer_count;

/**
 * Initialize the serial handler with interrupt-driven RX
 * Probes the Viking Bio serial link at 4800, 9600 and 19200 baud and keeps
 * the first rate that yields valid data.
 */
void serial_handler_init(void);

/**
 * Periodic task for serial handler processing
 * Currently unused as all processing is interrupt-driven
 */
void serial_handler_task(void);

/**
 * Check if data is available in the circular buffer
 * Thread-safe: disables interrupts during check
 * @return true if data is available, false otherwise
 */
static inline bool serial_handler_data_available(void) {
	uint32_t interrupts = save_and_disable_interrupts();
	bool has_data = buffer_count > 0;
	restore_interrupts(interrupts);
	return has_data;
}

/**
 * Read data from the circular buffer
 * Thread-safe: disables interrupts during read
 * @param buffer Output buffer for data (must not be NULL)
 * @param max_length Maximum number of bytes to read
 * @return Number of bytes actually read (0 if buffer is NULL or empty)
 */
size_t serial_handler_read(uint8_t *buffer, size_t max_length);

#endif // SERIAL_HANDLER_H
