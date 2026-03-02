'use strict';

/**
 * Zero-conf proxy registration announcer.
 *
 * Periodically multicasts a signed registration packet to the link-local
 * all-nodes IPv6 multicast group (ff02::1) on UDP port 41234 so that any
 * Viking Bio Pico W on the same network segment can automatically discover
 * the proxy address and save it without manual USB-serial configuration.
 *
 * Packet format (UTF-8, newline-terminated):
 *   "VIKINGBIO <token> <ipv6addr> <port>\n"
 *
 * The Pico validates <token> against its stored webhook auth token.  Only
 * devices that share the same token will accept the announcement.
 *
 * Environment variables consumed by this module:
 *   MACHINE_WEBHOOK_AUTH_TOKEN  – shared auth token (required; no-op if empty)
 *   HTTP_PORT                   – port to announce (default: 3000)
 *   ANNOUNCE_ADDR               – IPv6 address to announce (auto-detected if empty)
 *   ANNOUNCE_IFACE              – network interface for multicast (e.g. eth0)
 *   ANNOUNCE_INTERVAL_MS        – announcement interval in ms (default: 30000)
 */

const dgram = require('dgram');
const os    = require('os');

const REG_PORT       = 41234;
const MULTICAST_ADDR = 'ff02::1';

/**
 * Find the best IPv6 address to announce on the given interface.
 * Prefers non-link-local global addresses; falls back to link-local.
 *
 * @param {string} ifaceName  Optional interface name filter
 * @returns {string|null}  IPv6 address string (without scope ID), or null
 */
function findAnnounceAddr(ifaceName) {
	const ifaces = os.networkInterfaces();
	const candidates = [];

	for (const [name, addrs] of Object.entries(ifaces)) {
		if (ifaceName && name !== ifaceName) continue;
		if (!addrs) continue;
		for (const addr of addrs) {
			if (addr.family !== 'IPv6' || addr.internal) continue;
			// Strip scope ID (e.g. "fe80::1%eth0" → "fe80::1")
			const bare = addr.address.replace(/%.*$/, '');
			candidates.push({ name, bare, linkLocal: addr.address.startsWith('fe80') });
		}
	}

	// Prefer global (non-link-local) addresses
	const global = candidates.find(c => !c.linkLocal);
	if (global) return global.bare;
	// Fall back to link-local
	if (candidates.length > 0) return candidates[0].bare;
	return null;
}

/**
 * Create a registration announcer instance.
 *
 * @param {object} opts
 * @param {string} opts.token          – shared auth token
 * @param {number} opts.port           – HTTP port to advertise
 * @param {number} opts.intervalMs     – announcement interval in milliseconds
 * @param {string} opts.announceAddr   – explicit IPv6 address; auto-detected if ''
 * @param {string} opts.iface          – network interface for multicast
 * @returns {{ start: function, stop: function }}
 */
function createAnnouncer(opts = {}) {
	const {
		token        = '',
		port         = 3000,
		intervalMs   = 30000,
		announceAddr = '',
		iface        = '',
	} = opts;

	let timer = null;

	function announce() {
		if (!token) return;

		const addr = announceAddr || findAnnounceAddr(iface);
		if (!addr) {
			console.warn('announcer: no IPv6 address available – skipping');
			return;
		}

		const msg = Buffer.from(`VIKINGBIO ${token} ${addr} ${port}\n`, 'utf8');
		// Append interface name to multicast address when an interface is configured
		const dest = iface ? `${MULTICAST_ADDR}%${iface}` : MULTICAST_ADDR;

		const sock = dgram.createSocket({ type: 'udp6' });
		sock.on('error', (err) => {
			console.warn(`announcer: socket error: ${err.message}`);
			sock.close();
		});
		sock.send(msg, REG_PORT, dest, (err) => {
			if (err) {
				console.warn(`announcer: send failed: ${err.message}`);
			} else {
				console.log(`announcer: announced ${addr}:${port}`);
			}
			sock.close();
		});
	}

	return {
		start() {
			if (!token) {
				console.log('announcer: MACHINE_WEBHOOK_AUTH_TOKEN not set – announcer disabled');
				return;
			}
			announce();
			timer = setInterval(announce, intervalMs);
			console.log(`announcer: started (interval ${intervalMs}ms, dest ff02::1:${REG_PORT})`);
		},
		stop() {
			if (timer) {
				clearInterval(timer);
				timer = null;
			}
		},
	};
}

module.exports = { createAnnouncer };
