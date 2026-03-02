'use strict';

/**
 * mDNS / DNS-SD advertiser.
 *
 * Publishes the Viking Bio proxy as a DNS-SD service so it can be discovered
 * by standard mDNS clients (Bonjour on macOS, Avahi on Linux, Windows mDNS).
 *
 * Service type : _viking-bio._tcp
 * Instance name: configurable via MDNS_NAME (default "Viking Bio")
 * TXT records  : path=/api/data  (HTTP API entry-point for burner telemetry)
 *
 * Browser (PWA) limitation: web browsers cannot speak mDNS directly.  The
 * advertiser must run in a local Node.js process (this server).  The PWA
 * dashboard connects to the proxy over its regular HTTP/HTTPS URL.
 *
 * Environment variables:
 *   MDNS_NAME     – service instance name (default: "Viking Bio")
 *   MDNS_DISABLE  – set to "1" or "true" to suppress advertisement (useful
 *                   in Docker/CI environments without multicast)
 */

const bonjour = require('bonjour');

const SERVICE_TYPE = 'viking-bio';

/**
 * Create an mDNS/DNS-SD advertiser instance.
 *
 * @param {object} opts
 * @param {number} opts.port        – HTTP port to advertise
 * @param {string} opts.name        – DNS-SD instance name (human-readable)
 * @param {boolean} opts.disabled   – when true, advertiser is a no-op
 * @returns {{ start: function, stop: function }}
 */
function createMdnsAdvertiser(opts = {}) {
	const {
		port     = 3000,
		name     = 'Viking Bio',
		disabled = false,
	} = opts;

	let bonjourInstance = null;
	let service         = null;

	return {
		start() {
			if (disabled) {
				console.log('mdns-advertiser: disabled (MDNS_DISABLE is set)');
				return;
			}

			try {
				bonjourInstance = bonjour();
				service = bonjourInstance.publish({
					name,
					type:     SERVICE_TYPE,
					protocol: 'tcp',
					port,
					// TXT record: clients use "path" to locate the HTTP API entry-point
					// for querying burner telemetry (GET /api/data).
					txt: { path: '/api/data' },
				});
				service.on('up', () => {
					console.log(`mdns-advertiser: published _${SERVICE_TYPE}._tcp "${name}" on port ${port}`);
				});
				service.on('error', (err) => {
					console.warn(`mdns-advertiser: publish error: ${err.message}`);
				});
			} catch (err) {
				console.warn(`mdns-advertiser: failed to start: ${err.message}`);
			}
		},

		stop() {
			if (service) {
				service.stop();
				service = null;
			}
			if (bonjourInstance) {
				bonjourInstance.destroy();
				bonjourInstance = null;
			}
		},
	};
}

module.exports = { createMdnsAdvertiser };
