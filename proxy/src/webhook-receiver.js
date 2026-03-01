'use strict';

const crypto = require('crypto');

/**
 * Creates a webhook receiver that validates auth tokens and processes
 * burner telemetry JSON posted to the /api/machine-data endpoint.
 *
 * @param {object} state - Shared burner state object (mutated in-place)
 * @param {object} pushManager - Push manager instance
 * @returns {{ middleware: function }}
 */
function createWebhookReceiver(state, pushManager) {
	// Flame-on time tracking
	let lastFlameUpdate = null;

	// Notification debounce flag
	let errorNotified = false;

	function handleMessage(msg) {
		const prevFlame = state.flame;
		const prevErr   = state.err;

		// Update shared state
		state.flame = !!msg.flame;
		state.fan   = typeof msg.fan  === 'number' ? msg.fan  : 0;
		state.temp  = typeof msg.temp === 'number' ? msg.temp : 0;
		state.err   = typeof msg.err  === 'number' ? msg.err  : 0;
		state.valid = !!msg.valid;
		state.updated_at = Date.now();

		// Accumulate flame-on seconds
		if (state.flame) {
			const now = Date.now();
			if (!lastFlameUpdate) lastFlameUpdate = now;
			state.flame_secs += Math.floor((now - lastFlameUpdate) / 1000);
			lastFlameUpdate = now;
		} else {
			lastFlameUpdate = null;
		}

		// Notify: flame on/off transitions
		if (state.flame !== prevFlame) {
			const title = state.flame ? 'Viking Bio: Flame ON' : 'Viking Bio: Flame OFF';
			const body  = state.flame
				? `Burner ignited – ${state.temp}°C`
				: 'Burner flame extinguished';
			pushManager.notifyByType('flame', title, body);
		}

		// Notify: new error
		if (state.err !== 0 && state.err !== prevErr && !errorNotified) {
			errorNotified = true;
			pushManager.notifyByType('error',
				'Viking Bio: Error',
				`Error code ${state.err} detected`);
		} else if (state.err === 0) {
			errorNotified = false;
		}
	}

	/**
	 * Express middleware for POST /api/machine-data.
	 * Validates X-Hook-Auth header if MACHINE_WEBHOOK_AUTH_TOKEN is set.
	 */
	function middleware(req, res) {
		const token = process.env.MACHINE_WEBHOOK_AUTH_TOKEN;
		if (token) {
			const provided   = req.headers['x-hook-auth'] || '';
			const tokenBuf   = Buffer.from(token);
			const providedBuf = Buffer.from(provided);
			// Constant-time comparison to prevent timing attacks
			if (providedBuf.length !== tokenBuf.length ||
			    !crypto.timingSafeEqual(providedBuf, tokenBuf)) {
				return res.status(401).json({ error: 'unauthorized' });
			}
		}

		const msg = req.body;
		if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
			return res.status(400).json({ error: 'bad request' });
		}

		handleMessage(msg);
		console.log(`webhook: data received (flame=${state.flame}, temp=${state.temp}°C, err=${state.err})`);
		res.json({ status: 'ok' });
	}

	return { middleware };
}

module.exports = { createWebhookReceiver };
