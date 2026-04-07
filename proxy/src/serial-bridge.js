'use strict';

/**
 * serial-bridge.js
 *
 * Communicates with the Pico W bridge over USB serial (CDC ACM, 115200 baud).
 * Sends configuration commands and collects multi-line responses.
 *
 * Supported Pico commands:
 *   SSID=<ssid>      – stage WiFi SSID
 *   PASS=<password>  – save staged SSID + password (device reboots)
 *   COUNTRY=<CC>     – set Wi-Fi country code (2 uppercase letters)
 *   SERVER=<ip>      – set proxy server IP/hostname
 *   PORT=<port>      – set proxy server port
 *   TOKEN=<token>    – set webhook X-Hook-Auth token
 *   STATUS           – show WiFi status, config, and VAPID public key
 *   CLEAR            – erase all credentials (device reboots)
 */

const { SerialPort } = require('serialport');

/** Default baud rate for Pico W USB CDC serial */
const DEFAULT_BAUD_RATE = 115200;

/**
 * Default silence timeout: how long (ms) after the last received line before
 * `sendCommand` considers the response complete.
 */
const DEFAULT_SILENCE_MS = 500;

/**
 * Maximum overall wait time (ms) for any command response.
 * Commands that trigger a reboot (PASS, CLEAR) may never reply – callers
 * should pass a shorter timeout so the script doesn't hang.
 */
const DEFAULT_RESPONSE_TIMEOUT_MS = 4000;

// ---------------------------------------------------------------------------
// Port listing
// ---------------------------------------------------------------------------

/**
 * List all available serial ports.
 *
 * @returns {Promise<import('@serialport/bindings-cpp').PortInfo[]>}
 */
async function listPorts() {
	return SerialPort.list();
}

// ---------------------------------------------------------------------------
// Serial bridge factory
// ---------------------------------------------------------------------------

/**
 * Creates a serial bridge to communicate with the Pico W.
 *
 * @param {string} portPath                   – serial port (e.g. /dev/ttyACM0, COM3)
 * @param {object} [options]
 * @param {number} [options.baudRate=115200]   – baud rate
 * @param {number} [options.silenceMs=500]     – ms of silence after last line → response done
 * @param {number} [options.responseTimeoutMs=4000] – max wait per command
 * @returns {{ connect, disconnect, sendCommand, getStatus, parseStatus }}
 */
function createSerialBridge(portPath, options = {}) {
	const baudRate          = options.baudRate          || DEFAULT_BAUD_RATE;
	const silenceMs         = options.silenceMs         || DEFAULT_SILENCE_MS;
	const responseTimeoutMs = options.responseTimeoutMs || DEFAULT_RESPONSE_TIMEOUT_MS;

	let port     = null;
	let rxBuffer = '';

	// Registered line listeners – each is a function(line: string)
	let lineListeners = [];

	function dispatchLine(line) {
		for (const fn of lineListeners) fn(line);
	}

	// ---------------------------------------------------------------------------
	// connect / disconnect
	// ---------------------------------------------------------------------------

	/**
	 * Open the serial port.
	 * @returns {Promise<void>}
	 */
	function connect() {
		return new Promise((resolve, reject) => {
			port = new SerialPort({ path: portPath, baudRate, autoOpen: false });

			port.on('data', (chunk) => {
				rxBuffer += chunk.toString('utf8');
				let nl;
				while ((nl = rxBuffer.indexOf('\n')) !== -1) {
					const raw  = rxBuffer.slice(0, nl);
					rxBuffer   = rxBuffer.slice(nl + 1);
					const line = raw.replace(/\r$/, '').trimEnd();
					if (line.length > 0) dispatchLine(line);
				}
			});

			port.open((err) => {
				if (err) reject(err);
				else     resolve();
			});
		});
	}

	/**
	 * Close the serial port.
	 * @returns {Promise<void>}
	 */
	function disconnect() {
		return new Promise((resolve) => {
			if (port && port.isOpen) {
				port.close(() => resolve());
			} else {
				resolve();
			}
		});
	}

	// ---------------------------------------------------------------------------
	// sendCommand
	// ---------------------------------------------------------------------------

	/**
	 * Send a command string (a `\n` is appended automatically) and collect all
	 * response lines.
	 *
	 * Response collection ends when either:
	 *   – `silenceMs` of silence follows the last received line, or
	 *   – `overrideTimeoutMs` (or `responseTimeoutMs`) elapses without any line.
	 *
	 * @param {string} cmd                           – command to send
	 * @param {number} [overrideTimeoutMs]           – optional per-call timeout override
	 * @returns {Promise<string[]>}                  – lines received (may be empty)
	 */
	function sendCommand(cmd, overrideTimeoutMs) {
		return new Promise((resolve, reject) => {
			if (!port || !port.isOpen) {
				return reject(new Error('serial port is not open'));
			}

			const timeout = overrideTimeoutMs != null ? overrideTimeoutMs : responseTimeoutMs;
			const lines   = [];

			let silenceTimer  = null;
			let overallTimer  = null;
			let settled       = false;

			const listener = (line) => {
				lines.push(line);
				resetSilenceTimer();
			};

			function finish() {
				if (settled) return;
				settled = true;
				clearTimeout(silenceTimer);
				clearTimeout(overallTimer);
				lineListeners = lineListeners.filter((fn) => fn !== listener);
				resolve(lines);
			}

			function resetSilenceTimer() {
				clearTimeout(silenceTimer);
				silenceTimer = setTimeout(finish, silenceMs);
			}

			lineListeners.push(listener);

			// Overall timeout: give up waiting after this many ms regardless
			overallTimer = setTimeout(finish, timeout);

			// Start silence timer immediately (handles commands with no response)
			resetSilenceTimer();

			port.write(cmd + '\n', (err) => {
				if (err) {
					clearTimeout(silenceTimer);
					clearTimeout(overallTimer);
					lineListeners = lineListeners.filter((fn) => fn !== listener);
					reject(err);
				}
			});
		});
	}

	// ---------------------------------------------------------------------------
	// STATUS parsing
	// ---------------------------------------------------------------------------

	/**
	 * Parse lines from the STATUS command into a structured object.
	 *
	 * Expected output format from the firmware:
	 *   wifi: connected
	 *     IPv6[0]: fe80::...
	 *     country: SE
	 *     server:  192.168.1.1:3000
	 *     webhook: active
	 *     push:    2 subscription(s)
	 *     token:   (set)
	 *     vapid_pub: <base64url>
	 *
	 * @param {string[]} lines
	 * @returns {{
	 *   connected:     boolean,
	 *   addresses:     string[],
	 *   country:       string|null,
	 *   server:        string|null,
	 *   port:          number|null,
	 *   webhook:       string|null,
	 *   subscriptions: number|null,
	 *   token:         string|null,
	 *   vapidPub:      string|null,
	 * }}
	 */
	function parseStatus(lines) {
		const result = {
			connected:     false,
			addresses:     [],
			country:       null,
			server:        null,
			port:          null,
			webhook:       null,
			subscriptions: null,
			token:         null,
			vapidPub:      null,
		};

		for (const line of lines) {
			if (/^wifi:\s/.test(line)) {
				result.connected = line.includes('connected') && !line.includes('disconnected');
			} else if (/^\s*IPv6\[\d+\]:\s/.test(line)) {
				result.addresses.push(line.replace(/^\s*IPv6\[\d+\]:\s+/, '').trim());
			} else if (/^\s*country:\s/.test(line)) {
				result.country = line.replace(/^\s*country:\s+/, '').trim();
			} else if (/^\s*server:\s/.test(line)) {
				const val = line.replace(/^\s*server:\s+/, '').trim();
				if (val !== 'not configured') {
					// "ip:port" – the port is after the last colon
					const lastColon = val.lastIndexOf(':');
					if (lastColon !== -1) {
						result.server = val.slice(0, lastColon).trim();
						result.port   = parseInt(val.slice(lastColon + 1), 10) || null;
					}
				}
			} else if (/^\s*webhook:\s/.test(line)) {
				result.webhook = line.replace(/^\s*webhook:\s+/, '').trim();
			} else if (/^\s*push:\s/.test(line)) {
				const m = line.match(/(\d+)\s+subscription/);
				if (m) result.subscriptions = parseInt(m[1], 10);
			} else if (/^\s*token:\s/.test(line)) {
				result.token = line.replace(/^\s*token:\s+/, '').trim();
			} else if (/^\s*vapid_pub:\s/.test(line)) {
				result.vapidPub = line.replace(/^\s*vapid_pub:\s+/, '').trim();
			}
		}

		return result;
	}

	/**
	 * Send STATUS command and return a parsed status object.
	 * @returns {Promise<ReturnType<parseStatus>>}
	 */
	async function getStatus() {
		const lines = await sendCommand('STATUS');
		return parseStatus(lines);
	}

	return { connect, disconnect, sendCommand, getStatus, parseStatus };
}

module.exports = { createSerialBridge, listPorts };
