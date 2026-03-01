#include <string.h>
#include "pico/stdlib.h"
#include "hardware/uart.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "serial_handler.h"
#include "viking_bio_protocol.h"

// Circular buffer for serial data
static uint8_t serial_buffer[SERIAL_BUFFER_SIZE];
static volatile size_t buffer_head = 0;
static volatile size_t buffer_tail = 0;
volatile size_t buffer_count = 0;  // Made non-static for inline function in header

// Event flags from main.c (for waking from sleep)
extern volatile uint32_t event_flags;
#define EVENT_SERIAL_DATA (1 << 0)

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
    // Initialize UART
    uart_init(UART_ID, VIKING_BIO_BAUD_RATE);
    
    // Set the GPIO pin functions for UART
    gpio_set_function(UART_TX_PIN, GPIO_FUNC_UART);
    gpio_set_function(UART_RX_PIN, GPIO_FUNC_UART);
    
    // Set data format
    uart_set_format(UART_ID, VIKING_BIO_DATA_BITS, VIKING_BIO_STOP_BITS, VIKING_BIO_PARITY);
    
    // Enable FIFO
    uart_set_fifo_enabled(UART_ID, true);
    
    // Set up interrupt handler
    int UART_IRQ = UART_ID == uart0 ? UART0_IRQ : UART1_IRQ;
    irq_set_exclusive_handler(UART_IRQ, on_uart_rx);
    irq_set_enabled(UART_IRQ, true);
    
    // Enable UART RX interrupt
    uart_set_irq_enables(UART_ID, true, false);
}

void serial_handler_task(void) {
    // This function can be used for periodic processing if needed
    // Currently, all RX handling is done in the interrupt handler
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
