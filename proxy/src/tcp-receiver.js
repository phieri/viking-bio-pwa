'use strict';

const net = require('net');

/**
 * Creates a TCP server that receives newline-delimited JSON messages from the
 * Pico bridge. Each message updates shared `state` and triggers push
 * notifications via `pushManager`.
 *
 * Message format: {"flame":true,"fan":50,"temp":75,"err":0,"valid":true}
 *
 * @param {number} port - TCP port to listen on
 * @param {object} state - Shared burner state object (mutated in-place)
 * @param {object} pushManager - Push manager instance
 * @returns {net.Server}
 */
function createTcpReceiver(port, state, pushManager) {
	// Flame-on time tracking (tracks time of last update while flame is on)
	let lastFlameUpdate = null;

	// Notification debounce flags
	let errorNotified = false;

	function handleMessage(raw) {
		let msg;
		try {
			msg = JSON.parse(raw);
		} catch {
			console.warn('tcp-receiver: invalid JSON:', raw);
			return;
		}

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
			if (!lastFlameUpdate) lastFlameUpdate = Date.now();
			state.flame_secs += Math.floor((Date.now() - lastFlameUpdate) / 1000);
			lastFlameUpdate = Date.now();
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

	const server = net.createServer((socket) => {
		const remoteAddr = `${socket.remoteAddress}:${socket.remotePort}`;
		console.log(`tcp-receiver: Pico connected from ${remoteAddr}`);

		let buf = '';

		socket.setEncoding('utf8');

		socket.on('data', (chunk) => {
			buf += chunk;
			let nl;
			while ((nl = buf.indexOf('\n')) !== -1) {
				const line = buf.slice(0, nl).trim();
				buf = buf.slice(nl + 1);
				if (line) handleMessage(line);
			}
		});

		socket.on('end', () => {
			console.log(`tcp-receiver: Pico disconnected (${remoteAddr})`);
		});

		socket.on('error', (err) => {
			console.error(`tcp-receiver: socket error (${remoteAddr}):`, err.message);
		});
	});

	server.listen(port, () => {
		console.log(`tcp-receiver: listening on TCP port ${port}`);
	});

	server.on('error', (err) => {
		console.error('tcp-receiver: server error:', err.message);
	});

	return server;
}

module.exports = { createTcpReceiver };
