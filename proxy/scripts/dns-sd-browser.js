#!/usr/bin/env node
'use strict';

/**
 * DNS-SD browser / discovery diagnostic.
 *
 * Browses the local network for Viking Bio proxy instances advertised as
 * _viking-bio._tcp DNS-SD services and prints each discovered instance.
 *
 * Usage:
 *   node proxy/scripts/dns-sd-browser.js
 *
 * Requires the proxy to be running with mDNS advertisement enabled.
 *
 * Browser (PWA) limitation
 * ------------------------
 * Web browsers cannot open raw UDP sockets or speak mDNS.  This script must
 * be run from a local Node.js process or agent (not from the browser itself).
 * On macOS you can also use: dns-sd -B _viking-bio._tcp local
 * On Linux (Avahi):          avahi-browse _viking-bio._tcp --resolve
 * On Windows:                dns-sd -B _viking-bio._tcp local   (requires Bonjour SDK)
 *
 * Platform notes
 * --------------
 * macOS : works out of the box via the system Bonjour daemon (mDNSResponder).
 * Linux : requires Avahi daemon running (`systemctl start avahi-daemon`).
 * Windows: requires Apple Bonjour service or Windows mDNS.
 */

const bonjour = require('bonjour');

const SERVICE_TYPE = 'viking-bio';
const BROWSE_TIMEOUT_MS = parseInt(process.env.BROWSE_TIMEOUT_MS || '10000', 10);

const b = bonjour();

console.log(`Browsing for _${SERVICE_TYPE}._tcp services (${BROWSE_TIMEOUT_MS / 1000}s)...\n`);

const browser = b.find({ type: SERVICE_TYPE });

browser.on('up', (service) => {
	const addrs = (service.addresses || []).join(', ') || '(no addresses)';
	console.log(`Found: "${service.name}"`);
	console.log(`  Host:      ${service.host || '(unknown)'}`);
	console.log(`  Addresses: ${addrs}`);
	console.log(`  Port:      ${service.port}`);
	if (service.txt && Object.keys(service.txt).length > 0) {
		console.log(`  TXT:       ${JSON.stringify(service.txt)}`);
	}
	console.log();
});

browser.on('down', (service) => {
	console.log(`Lost:  "${service.name}"`);
});

setTimeout(() => {
	browser.stop();
	b.destroy();
	console.log('Browse complete.');
}, BROWSE_TIMEOUT_MS);
