#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/uart.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "serial_handler.h"
#include "vikingbio.h"

// Circular buffer for serial data
static uint8_t serial_buffer[SERIAL_BUFFER_SIZE];
static volatile size_t buffer_head = 0;
static volatile size_t buffer_tail = 0;
volatile size_t buffer_count = 0;  // Made non-static for inline function in header

// Event flags from main.c (for waking from sleep)
extern volatile uint32_t event_flags;
#define EVENT_SERIAL_DATA (1 << 0)
#define SERIAL_BAUD_PROBE_INTERVAL_MS 1000

static const uint32_t serial_baud_rates[] = {4800, VIKING_BIO_BAUD_RATE, 19200};
static size_t serial_baud_index = 0;
static bool serial_baud_probe_active = false;
static uint32_t serial_current_baud = 0;
static absolute_time_t serial_baud_deadline;

static void serial_handler_reset_rx_buffer(void) {
    uint32_t interrupts = save_and_disable_interrupts();
    buffer_head = 0;
    buffer_tail = 0;
    buffer_count = 0;
    restore_interrupts(interrupts);
}

static void serial_handler_configure_baud(uint32_t baud_rate) {
    int uart_irq = UART_ID == uart0 ? UART0_IRQ : UART1_IRQ;
    irq_set_enabled(uart_irq, false);

    uart_init(UART_ID, baud_rate);
    gpio_set_function(UART_TX_PIN, GPIO_FUNC_UART);
    gpio_set_function(UART_RX_PIN, GPIO_FUNC_UART);
    uart_set_format(UART_ID, VIKING_BIO_DATA_BITS, VIKING_BIO_STOP_BITS, VIKING_BIO_PARITY);
    uart_set_fifo_enabled(UART_ID, true);
    uart_set_irq_enables(UART_ID, true, false);

    irq_set_enabled(uart_irq, true);
    serial_current_baud = baud_rate;
    serial_baud_deadline = make_timeout_time_ms(SERIAL_BAUD_PROBE_INTERVAL_MS);
}

static size_t serial_handler_copy_buffer(uint8_t *buffer, size_t max_length, bool consume) {
    if (buffer == NULL || max_length == 0) {
        return 0;
    }

    uint32_t interrupts = save_and_disable_interrupts();
    size_t bytes_read = 0;
    size_t read_index = buffer_tail;
    size_t available = buffer_count;

    while (available > 0 && bytes_read < max_length) {
        buffer[bytes_read++] = serial_buffer[read_index];
        read_index = (read_index + 1) % SERIAL_BUFFER_SIZE;
        available--;
    }

    if (consume && bytes_read > 0) {
        buffer_tail = (buffer_tail + bytes_read) % SERIAL_BUFFER_SIZE;
        buffer_count -= bytes_read;
    }

    restore_interrupts(interrupts);
    return bytes_read;
}

// UART RX interrupt handler
static void on_uart_rx() {
    while (uart_is_readable(UART_ID)) {
        uint8_t ch = uart_getc(UART_ID);
        
        // Add to circular buffer if there's space
        if (buffer_count < SERIAL_BUFFER_SIZE) {
            serial_buffer[buffer_head] = ch;
            buffer_head = (buffer_head + 1) % SERIAL_BUFFER_SIZE;
            buffer_count++;
            
            // Set event flag to wake main loop
            event_flags |= EVENT_SERIAL_DATA;
            __sev();  // Wake CPU from WFE if sleeping
        }
    }
}

void serial_handler_init(void) {
    serial_handler_reset_rx_buffer();

    // Set up interrupt handler
    int UART_IRQ = UART_ID == uart0 ? UART0_IRQ : UART1_IRQ;
    irq_set_exclusive_handler(UART_IRQ, on_uart_rx);
    irq_set_enabled(UART_IRQ, true);

    serial_baud_index = 0;
    serial_baud_probe_active = true;
    serial_handler_configure_baud(serial_baud_rates[serial_baud_index]);
}

void serial_handler_task(void) {
    if (!serial_baud_probe_active) {
        return;
    }

    if (time_reached(serial_baud_deadline)) {
        uint8_t probe_buffer[SERIAL_BUFFER_SIZE];
        size_t bytes = serial_handler_copy_buffer(probe_buffer, sizeof(probe_buffer), false);

        vikingbio_data_t parsed_data;
        if (bytes >= VIKING_BIO_MIN_PACKET_SIZE &&
            vikingbio_detect_and_parse(NULL, probe_buffer, bytes, &parsed_data) && parsed_data.valid) {
            printf("serial: detected Viking Bio data at %lu baud\n",
                   (unsigned long)serial_current_baud);
            serial_baud_probe_active = false;
            return;
        }

        serial_baud_index++;
        if (serial_baud_index >= (sizeof(serial_baud_rates) / sizeof(serial_baud_rates[0]))) {
            printf("serial: no valid Viking Bio data at 4800/9600/19200 baud, keeping %lu baud\n",
                   (unsigned long)serial_current_baud);
            serial_baud_probe_active = false;
            return;
        }

        serial_handler_reset_rx_buffer();
        serial_handler_configure_baud(serial_baud_rates[serial_baud_index]);
    }
}

// serial_handler_data_available() is now inline in header file

size_t serial_handler_read(uint8_t *buffer, size_t max_length) {
    if (buffer == NULL || max_length == 0) {
        return 0;
    }
    
    size_t bytes_read = 0;
    
    // Disable interrupts while reading from buffer
    uint32_t interrupts = save_and_disable_interrupts();
    
    while (buffer_count > 0 && bytes_read < max_length) {
        buffer[bytes_read++] = serial_buffer[buffer_tail];
        buffer_tail = (buffer_tail + 1) % SERIAL_BUFFER_SIZE;
        buffer_count--;
    }
    
    restore_interrupts(interrupts);
    
    return bytes_read;
}
