#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "viking_bio_protocol.h"

// Branch prediction hints for better optimization
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// Current Viking Bio data state
static viking_bio_data_t current_data = {
    .flame_detected = false,
    .fan_speed = 0,
    .temperature = 0,
    .error_code = 0,
    .valid = false
};

// Timestamp of last successfully parsed data packet (milliseconds since boot)
static uint32_t last_data_timestamp = 0;

// Protocol constants for Viking Bio 20 burner
#define VIKING_BIO_START_BYTE 0xAA
#define VIKING_BIO_END_BYTE 0x55
#define VIKING_BIO_MIN_PACKET_SIZE 6  // START + FLAGS + SPEED + TEMP_H + TEMP_L + END
#define VIKING_BIO_MAX_TEMPERATURE 500  // Maximum valid temperature in Celsius (burner operational limit)
#define VIKING_BIO_MAX_TEXT_LENGTH 256   // Maximum text protocol message length

void viking_bio_init(void) {
    // Initialize data structure
    memset(&current_data, 0, sizeof(current_data));
    current_data.valid = false;
    
    // Initialize timestamp to current time to prevent false timeout on startup
    last_data_timestamp = to_ms_since_boot(get_absolute_time());
}

bool viking_bio_parse_data(const uint8_t *buffer, size_t length, viking_bio_data_t *data) {
    if (unlikely(buffer == NULL || data == NULL || length < VIKING_BIO_MIN_PACKET_SIZE)) {
        return false;
    }
    
    // Initialize output data to safe defaults
    memset(data, 0, sizeof(viking_bio_data_t));
    data->valid = false;
    
    // Simple protocol parser
    // Format: [START_BYTE] [FLAGS] [FAN_SPEED] [TEMP_HIGH] [TEMP_LOW] [END_BYTE]
    // FLAGS bit 0: flame detected
    // FLAGS bit 1-7: error codes
    
    for (size_t i = 0; i + VIKING_BIO_MIN_PACKET_SIZE <= length; i++) {
        if (buffer[i] == VIKING_BIO_START_BYTE) {
            // Check for valid end byte
            if (buffer[i + 5] == VIKING_BIO_END_BYTE) {
                uint8_t flags = buffer[i + 1];
                uint8_t fan_speed = buffer[i + 2];
                uint8_t temp_high = buffer[i + 3];
                uint8_t temp_low = buffer[i + 4];
                
                // Parse data
                data->flame_detected = (flags & 0x01) != 0;
                // Clamp fan speed to valid range 0-100
                data->fan_speed = (fan_speed > 100) ? 100 : fan_speed;
                
                // Parse temperature (16-bit value)
                uint16_t temp = ((uint16_t)temp_high << 8) | temp_low;
                // Validate temperature is within reasonable range (binary protocol uses unsigned, so min is 0)
                if (temp > VIKING_BIO_MAX_TEMPERATURE) {
                    // Invalid temperature, skip this packet
                    continue;
                }
                data->temperature = temp;
                data->error_code = (flags >> 1) & 0x7F;
                data->valid = true;
                
                // Update current state
                memcpy(&current_data, data, sizeof(viking_bio_data_t));
                
                // Update timestamp on successful parse
                last_data_timestamp = to_ms_since_boot(get_absolute_time());
                
                return true;
            }
        }
    }
    
    // If no valid packet found, try simple text protocol fallback
    // Format: "F:1,S:50,T:75\n" (Flame:bool, Speed:%, Temp:°C)
    if (length > 10 && length < VIKING_BIO_MAX_TEXT_LENGTH) {  // Sanity check on input length
        char str_buffer[VIKING_BIO_MAX_TEXT_LENGTH];
        size_t copy_len = length < sizeof(str_buffer) - 1 ? length : sizeof(str_buffer) - 1;
        memcpy(str_buffer, buffer, copy_len);
        str_buffer[copy_len] = '\0';
        
        int flame = 0, speed = 0, temp = 0;
        // Use explicit format with length limits to prevent overflow
        if (sscanf(str_buffer, "F:%d,S:%d,T:%d", &flame, &speed, &temp) == 3) {
            data->flame_detected = flame != 0;
            // Clamp fan speed to valid range 0-100
            if (speed < 0) {
                data->fan_speed = 0;
            } else if (speed > 100) {
                data->fan_speed = 100;
            } else {
                data->fan_speed = (uint8_t)speed;
            }
            // Validate temperature is within reasonable range (0-500°C for burner)
            if (temp < 0 || temp > VIKING_BIO_MAX_TEMPERATURE) {
                return false;
            }
            data->temperature = (uint16_t)temp;
            data->error_code = 0;
            data->valid = true;
            
            // Update current state
            memcpy(&current_data, data, sizeof(viking_bio_data_t));
            
            // Update timestamp on successful parse
            last_data_timestamp = to_ms_since_boot(get_absolute_time());
            
            return true;
        }
    }
    
    return false;
}

void viking_bio_get_current_data(viking_bio_data_t *data) {
    if (data != NULL) {
        memcpy(data, &current_data, sizeof(viking_bio_data_t));
    }
}

bool viking_bio_is_data_stale(uint32_t timeout_ms) {
    uint32_t current_time = to_ms_since_boot(get_absolute_time());
    // Calculate elapsed time using unsigned arithmetic
    // This correctly handles wrap-around: if current_time wraps to 5 and 
    // last_data_timestamp was 4294967290, elapsed = (2^32 - 4294967290) + 5 = 11
    // This works as long as the actual elapsed time is less than 2^31 ms (~24.8 days)
    uint32_t elapsed = current_time - last_data_timestamp;
    return elapsed >= timeout_ms;
}
