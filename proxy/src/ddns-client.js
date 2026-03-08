'use strict';

/**
 * DuckDNS DDNS client.
 *
 * Registers and keeps the server's current public IP address updated on
 * DuckDNS (https://www.duckdns.org/) so that a Let's Encrypt certificate
 * can be issued for the <subdomain>.duckdns.org hostname.
 *
 * DuckDNS is a free, open-source Dynamic DNS service.  When the token and
 * subdomain are configured the client performs an initial update on start(),
 * then repeats every UPDATE_INTERVAL_MS.  Passing empty ip/ipv6 parameters
 * lets the DuckDNS server detect the public address automatically.
 *
 * Environment variables:
 *   DDNS_SUBDOMAIN – DuckDNS subdomain (the part before ".duckdns.org")
 *   DDNS_TOKEN     – DuckDNS account token (from duckdns.org/install)
 */

const https = require('https');

const DUCKDNS_API       = 'https://www.duckdns.org/update';
const UPDATE_INTERVAL_MS = 5 * 60 * 1000; // update every 5 minutes

/**
 * Create a DuckDNS DDNS client.
 *
 * @param {object} [opts]
 * @param {string} [opts.subdomain]   – DuckDNS subdomain (overrides env)
 * @param {string} [opts.token]       – DuckDNS token (overrides env)
 * @param {number} [opts.intervalMs]  – update interval in ms (default 5 min)
 * @returns {{ domain: string, start: function, stop: function }}
 */
function createDdnsClient(opts = {}) {
	const subdomain  = opts.subdomain  || process.env.DDNS_SUBDOMAIN || '';
	const token      = opts.token      || process.env.DDNS_TOKEN     || '';
	const intervalMs = opts.intervalMs || UPDATE_INTERVAL_MS;

	if (!subdomain || !token) {
		return {
			/** Empty string signals that DDNS is not configured. */
			domain: '',
			start() {},
			stop()  {},
		};
	}

	const domain = `${subdomain}.duckdns.org`;
	let timer    = null;

	/**
	 * Send one DuckDNS update request.
	 * Passing empty ip= / ipv6= lets DuckDNS detect the public address.
	 *
	 * Note: the DuckDNS API requires the token as a URL query parameter
	 * (https://www.duckdns.org/spec.jsp).  This is inherent to the DuckDNS
	 * protocol; there is no header or body alternative.
	 *
	 * @returns {Promise<void>}
	 */
	function update() {
		const url = `${DUCKDNS_API}?domains=${encodeURIComponent(subdomain)}`
			+ `&token=${encodeURIComponent(token)}`
			+ '&ip=&ipv6=&verbose=true';

		return new Promise((resolve, reject) => {
			https.get(url, (res) => {
				let body = '';
				res.on('data', (chunk) => { body += chunk; });
				res.on('end',  () => {
					if (body.startsWith('OK')) {
						console.log(`ddns-client: updated ${domain}`);
						resolve();
					} else {
						const msg = `DuckDNS update failed: ${body.trim()}`;
						console.error(`ddns-client: ${msg}`);
						reject(new Error(msg));
					}
				});
			}).on('error', (err) => {
				console.error(`ddns-client: request error: ${err.message}`);
				reject(err);
			});
		});
	}

	return {
		/** Fully-qualified domain name managed by this client. */
		domain,

		/**
		 * Perform an immediate update and schedule periodic updates.
		 */
		start() {
			update().catch((err) => {
				console.error(`ddns-client: initial update failed: ${err.message}`);
			});
			timer = setInterval(() => {
				update().catch((err) => {
					console.error(`ddns-client: periodic update failed: ${err.message}`);
				});
			}, intervalMs);
		},

		/**
		 * Cancel the periodic update timer.
		 */
		stop() {
			if (timer !== null) {
				clearInterval(timer);
				timer = null;
			}
		},
	};
}

module.exports = { createDdnsClient };
