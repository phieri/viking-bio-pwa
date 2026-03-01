'use strict';

/**
 * Scheduler for periodic push notifications.
 *
 * Currently implements a cleaning reminder sent every Saturday at 07:00
 * during the heating season (November through March).
 *
 * @param {object} pushManager - Push manager instance
 * @returns {{ start: function, stop: function }}
 */
function createScheduler(pushManager) {
	let timer = null;

	/**
	 * Returns true if today is within the cleaning reminder window:
	 * Saturday 07:00 (±30 min) during November–March.
	 */
	function shouldSendCleaningReminder(now) {
		const month = now.getMonth(); // 0=Jan ... 10=Nov, 11=Dec
		const day   = now.getDay();   // 0=Sun, 6=Sat
		const hour  = now.getHours();
		const min   = now.getMinutes();

		// Heating season: November (10), December (11), January (0), February (1), March (2)
		const inSeason = [10, 11, 0, 1, 2].includes(month);
		// Saturday 07:00–07:30
		const isSatMorning = day === 6 && hour === 7 && min < 30;

		return inSeason && isSatMorning;
	}

	let reminderSentThisWeek = false;
	let lastCheckedWeek = -1;

	function tick() {
		const now = new Date();
		const week = getISOWeek(now);

		// Reset weekly flag at the start of a new week
		if (week !== lastCheckedWeek) {
			reminderSentThisWeek = false;
			lastCheckedWeek = week;
		}

		if (!reminderSentThisWeek && shouldSendCleaningReminder(now)) {
			reminderSentThisWeek = true;
			console.log('scheduler: sending cleaning reminder');
			pushManager.notifyByType(
				'clean',
				'Viking Bio: Cleaning Reminder',
				'Time to clean the burner. Regular cleaning keeps it running efficiently.'
			);
		}
	}

	function start() {
		// Check every 10 minutes
		timer = setInterval(tick, 10 * 60 * 1000);
		console.log('scheduler: cleaning reminder scheduler started');
	}

	function stop() {
		if (timer) {
			clearInterval(timer);
			timer = null;
		}
	}

	return { start, stop };
}

/** Compute ISO week number for a given Date. */
function getISOWeek(date) {
	const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
	d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
	const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
	return Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
}

module.exports = { createScheduler };
