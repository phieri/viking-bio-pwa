#ifndef FLAME_COUNTER_H
#define FLAME_COUNTER_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Initialize the flame counter.
 * Loads the persisted value from flash (LittleFS). Must be called after
 * lfs_hal_init().
 */
void flame_counter_init(void);

/**
 * Update the flame counter with the current flame state.
 * Call periodically (every dt_ms milliseconds).
 * Accumulates time while flame_on is true and saves to flash on every
 * flame-off transition and every FLAME_COUNTER_SAVE_INTERVAL_MS.
 *
 * @param flame_on true if the flame is currently detected
 * @param dt_ms    elapsed time since the last call (milliseconds)
 */
void flame_counter_update(bool flame_on, uint32_t dt_ms);

/**
 * Get the total flame-on time in whole seconds (including any uncommitted
 * sub-second accumulation).
 *
 * @return Total seconds the flame has been on
 */
uint32_t flame_counter_get_seconds(void);

/**
 * Force an immediate save of the current counter value to flash.
 */
void flame_counter_save(void);

#endif // FLAME_COUNTER_H
