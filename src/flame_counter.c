#include <stdio.h>
#include "flame_counter.h"
#include "lfs_hal.h"

#define FLAME_COUNTER_FILE          "/flame_hours.dat"
// Save to flash at most once per minute while flame is on
#define FLAME_COUNTER_SAVE_INTERVAL_MS  (60u * 1000u)

// Total whole seconds the flame has been on (persisted)
static uint32_t s_flame_seconds = 0;

// Sub-second accumulation (ms); never reaches 1000
static uint32_t s_accumulated_ms = 0;

// Time since last flash save (ms)
static uint32_t s_save_timer_ms = 0;

// Previous flame state – used to detect transitions
static bool s_last_flame_on = false;

void flame_counter_init(void) {
	uint32_t saved = 0;
	int n = lfs_hal_read_file(FLAME_COUNTER_FILE, &saved, sizeof(saved));
	if (n == (int)sizeof(saved)) {
		s_flame_seconds = saved;
	}
	printf("flame counter: loaded %u seconds (%u hours)\n",
	       s_flame_seconds, s_flame_seconds / 3600u);
}

void flame_counter_update(bool flame_on, uint32_t dt_ms) {
	if (flame_on) {
		s_accumulated_ms += dt_ms;
		if (s_accumulated_ms >= 1000u) {
			s_flame_seconds  += s_accumulated_ms / 1000u;
			s_accumulated_ms  = s_accumulated_ms % 1000u;
		}
		s_save_timer_ms += dt_ms;
		if (s_save_timer_ms >= FLAME_COUNTER_SAVE_INTERVAL_MS) {
			s_save_timer_ms = 0;
			flame_counter_save();
		}
	}

	// Save on flame-off transition to minimise data loss on power cuts
	if (s_last_flame_on && !flame_on) {
		s_accumulated_ms = 0;
		s_save_timer_ms  = 0;
		flame_counter_save();
	}

	s_last_flame_on = flame_on;
}

uint32_t flame_counter_get_seconds(void) {
	return s_flame_seconds;
}

void flame_counter_save(void) {
	if (!lfs_hal_write_file(FLAME_COUNTER_FILE, &s_flame_seconds, sizeof(s_flame_seconds))) {
		printf("flame counter: save failed\n");
	}
}
