#!/usr/bin/env node
'use strict';

const express = require('express');
const http    = require('http');
const https   = require('https');
const tls     = require('tls');
const fs      = require('fs');
const path    = require('path');
const { createWebhookReceiver } = require('./webhook-receiver');
const { createPushManager } = require('./push-manager');
const { createMdnsAdvertiser } = require('./mdns-advertiser');
const { createDdnsClient } = require('./ddns-client');
const { createCertManager } = require('./cert-manager');

function parsePort(value, fallback, envName) {
	const raw = String(value ?? fallback).trim();
	if (!/^\d+$/.test(raw)) {
		console.error(`${envName} must be an integer between 1 and 65535 (got: ${raw})`);
		process.exit(1);
	}
	const port = parseInt(raw, 10);
	if (port < 1 || port > 65535) {
		console.error(`${envName} must be an integer between 1 and 65535 (got: ${raw})`);
		process.exit(1);
	}
	return port;
}

function requireHttpUrl(value, envName) {
	if (!value) return '';
	const trimmedValue = value.trim();
	let parsed;
	try {
		parsed = new URL(trimmedValue);
	} catch (err) {
		console.error(`Invalid ${envName}: ${err.message}`);
		process.exit(1);
	}
	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
		console.error(`${envName} must use http:// or https:// (got: ${parsed.protocol})`);
		process.exit(1);
	}
	return trimmedValue;
}

function isPlainObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const HTTP_PORT = parsePort(process.env.HTTP_PORT, 3000, 'HTTP_PORT');

// Optional: base URL of the Pico W's webhook API (e.g. http://[fe80::1%25eth0]:8080).
// When set the proxy forwards push subscriptions to the Pico so it can send
// Web Push notifications directly.  Must use a bracketed IPv6 literal if the
// address is IPv6.
const PICO_BASE_URL = requireHttpUrl(process.env.PICO_BASE_URL || '', 'PICO_BASE_URL');
const PICO_FORWARD_TIMEOUT_MS = 5000;

// Optional: VAPID public key generated on the Pico W (output of 'STATUS' over
// USB serial after first boot).  When set this key is returned to browsers so
// their push subscriptions are tied to the Pico's private key.
const PICO_VAPID_PUBLIC_KEY = process.env.PICO_VAPID_PUBLIC_KEY || '';

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Shared burner state updated by webhook receiver
const state = {
	flame: false,
	fan: 0,
	temp: 0,
	err: 0,
	valid: false,
	flame_secs: 0,
	updated_at: 0,
};

// Push manager handles subscriptions and sending notifications (proxy side)
const pushManager = createPushManager();

// Webhook receiver processes authenticated POST requests from the Pico bridge
const webhookReceiver = createWebhookReceiver(state, pushManager);

// Advertise the proxy as a DNS-SD service (_viking-bio._tcp) so it can be
// discovered by standard mDNS clients (Bonjour, Avahi, Windows mDNS).
// Note: browsers/PWAs cannot speak mDNS directly; this runs server-side only.
const mdnsAdvertiser = createMdnsAdvertiser({
	port:     HTTP_PORT,
	name:     process.env.MDNS_NAME || 'Viking Bio',
	disabled: process.env.MDNS_DISABLE === '1' || process.env.MDNS_DISABLE === 'true',
});
mdnsAdvertiser.start();

let activeServer = null;
let activeDdnsClient = null;
let activeCertManager = null;
let shutdownPromise = null;

// ---------------------------------------------------------------------------
// Pico W forwarding helper
// ---------------------------------------------------------------------------

/**
 * Forward a JSON body to a Pico W webhook endpoint.
 * Adds X-Hook-Auth when MACHINE_WEBHOOK_AUTH_TOKEN is configured.
 * Returns true on success, false on any error (non-fatal – proxy continues).
 *
 * @param {string} urlPath  Path on the Pico W (e.g. '/api/subscribe')
 * @param {object} body     Object to serialise as JSON
 */
async function picoForward(urlPath, body) {
	if (!PICO_BASE_URL) return false;
	const fullUrl = PICO_BASE_URL + urlPath;
	let parsedUrl;
	try {
		parsedUrl = new URL(fullUrl);
	} catch {
		console.warn(`pico-forward: invalid PICO_BASE_URL: ${PICO_BASE_URL}`);
		return false;
	}

	const payload = JSON.stringify(body);
	const token   = process.env.MACHINE_WEBHOOK_AUTH_TOKEN || '';
	const headers = {
		'Content-Type':   'application/json',
		'Content-Length': Buffer.byteLength(payload),
	};
	if (token) headers['X-Hook-Auth'] = token;

	const transport = parsedUrl.protocol === 'https:' ? https : http;

	return new Promise((resolve) => {
		let settled = false;
		const finish = (ok) => {
			if (!settled) {
				settled = true;
				resolve(ok);
			}
		};
		const req = transport.request({
			hostname: parsedUrl.hostname,
			port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
			path:     parsedUrl.pathname,
			method:   'POST',
			headers,
			timeout:  PICO_FORWARD_TIMEOUT_MS,
		}, (res) => {
			res.resume(); // drain
			const ok = res.statusCode >= 200 && res.statusCode < 300;
			if (!ok) console.warn(`pico-forward: ${urlPath} → HTTP ${res.statusCode}`);
			finish(ok);
		});
		req.on('timeout', () => {
			console.warn(`pico-forward: ${urlPath} timed out after ${PICO_FORWARD_TIMEOUT_MS} ms`);
			req.destroy(new Error('request timeout'));
		});
		req.on('error', (err) => {
			console.warn(`pico-forward: ${urlPath} error: ${err.message}`);
			finish(false);
		});
		req.write(payload);
		req.end();
	});
}

// --- HTTP API ---

// GET /api/data - current burner state
app.get('/api/data', (req, res) => {
	res.json({
		flame:      state.flame,
		fan:        state.fan,
		temp:       state.temp,
		err:        state.err,
		valid:      state.valid,
		flame_secs: state.flame_secs,
	});
});

// GET /api/vapid-public-key - VAPID public key for push subscriptions.
// Returns the Pico W's key when PICO_VAPID_PUBLIC_KEY is configured so that
// browser subscriptions are tied to the Pico's on-device private key.
app.get('/api/vapid-public-key', (req, res) => {
	if (PICO_VAPID_PUBLIC_KEY) {
		res.json({ key: PICO_VAPID_PUBLIC_KEY, source: 'pico' });
	} else {
		res.json({ key: pushManager.getVapidPublicKey(), source: 'proxy' });
	}
});

// GET /api/subscribers - number of active subscriptions
app.get('/api/subscribers', (req, res) => {
	res.json({ count: pushManager.getSubscriptionCount() });
});

// POST /api/machine-data - receive authenticated telemetry from the Pico bridge
app.post('/api/machine-data', webhookReceiver.middleware);

// POST /api/subscribe - add or update a push subscription.
// Stores subscription locally and, when PICO_BASE_URL is set, forwards it to
// the Pico W so the device can send Web Push notifications directly.
app.post('/api/subscribe', (req, res) => {
	if (!isPlainObject(req.body)) {
		return res.status(400).json({ error: 'bad request' });
	}

	const endpoint = typeof req.body.endpoint === 'string' ? req.body.endpoint.trim() : '';
	const p256dh   = typeof req.body.p256dh === 'string' ? req.body.p256dh : '';
	const auth     = typeof req.body.auth === 'string' ? req.body.auth : '';
	const prefs    = isPlainObject(req.body.prefs) ? req.body.prefs : {};
	if (!endpoint) {
		return res.status(400).json({ error: 'bad request' });
	}
	const subscription = {
		endpoint,
		p256dh,
		auth,
		prefs: {
			flame: !!prefs.flame,
			error: !!prefs.error,
			clean: !!prefs.clean,
		},
	};
	const ok = pushManager.addSubscription(
		subscription.endpoint,
		subscription.p256dh,
		subscription.auth,
		subscription.prefs
	);
	// Best-effort forward to Pico W (errors are non-fatal; picoForward logs failures)
	void picoForward('/api/subscribe', subscription);
	res.json({ status: ok ? 'ok' : 'full' });
});

// POST /api/unsubscribe - remove a push subscription
app.post('/api/unsubscribe', (req, res) => {
	if (!isPlainObject(req.body)) {
		return res.status(400).json({ error: 'bad request' });
	}

	const endpoint = typeof req.body.endpoint === 'string' ? req.body.endpoint.trim() : '';
	if (!endpoint) {
		return res.status(400).json({ error: 'bad request' });
	}

	pushManager.removeSubscription(endpoint);
	// Best-effort forward to Pico W (errors are non-fatal; picoForward logs failures)
	void picoForward('/api/unsubscribe', { endpoint });
	res.json({ status: 'ok' });
});

app.use((err, req, res, next) => {
	if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
		return res.status(400).json({ error: 'bad request' });
	}
	return next(err);
});

function shutdown(signal) {
	if (!shutdownPromise) {
		console.log(`${signal} received, shutting down`);
		shutdownPromise = Promise.resolve()
			.then(() => mdnsAdvertiser.stop())
			.then(() => activeDdnsClient && activeDdnsClient.stop())
			.then(() => activeCertManager && activeCertManager.stop())
			.then(() => new Promise((resolve) => {
				if (!activeServer) {
					resolve();
					return;
				}
				activeServer.close(() => resolve());
			}))
			.catch((err) => {
				console.error(`Shutdown error: ${err.message}`);
			})
			.finally(() => {
				process.exit(0);
			});
	}
	return shutdownPromise;
}

process.once('SIGINT', () => {
	void shutdown('SIGINT');
});
process.once('SIGTERM', () => {
	void shutdown('SIGTERM');
});

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------
// Priority order:
//   1. DDNS_SUBDOMAIN + DDNS_TOKEN → automatic Let's Encrypt HTTPS
//   2. TLS_CERT_PATH  + TLS_KEY_PATH  → manual HTTPS with provided cert/key
//   3. fallback                       → plain HTTP (development only)
// ---------------------------------------------------------------------------

async function startServer() {
	const ddns    = createDdnsClient();
	activeDdnsClient = ddns;
	const certPath = process.env.TLS_CERT_PATH;
	const keyPath  = process.env.TLS_KEY_PATH;

	// ------------------------------------------------------------------
	// Option 1: automatic Let's Encrypt HTTPS via DuckDNS
	// ------------------------------------------------------------------
	if (ddns.domain) {
		ddns.start();

		const certMgr = createCertManager({ domain: ddns.domain });
		activeCertManager = certMgr;
		const ready   = await certMgr.initialize();

		if (ready) {
			// Load initial certificate into a TLS SecureContext.
			// SNICallback allows live reloading after renewal without restart.
			let secureContext;
			try {
				secureContext = tls.createSecureContext({
					cert: fs.readFileSync(certMgr.certPath),
					key:  fs.readFileSync(certMgr.keyPath),
				});
			} catch (err) {
				console.error(
					`cert-manager: failed to load certificate: ${err.message}`
					+ ` – check ACME_CERT_DIR and file permissions`
				);
			}

			if (secureContext) {
				// Reload the SecureContext whenever the certificate is renewed.
				certMgr.onRenew = () => {
					try {
						secureContext = tls.createSecureContext({
							cert: fs.readFileSync(certMgr.certPath),
							key:  fs.readFileSync(certMgr.keyPath),
						});
						console.log('HTTPS: TLS certificate reloaded after renewal');
					} catch (err) {
						console.error(`HTTPS: failed to reload certificate: ${err.message}`);
					}
				};

				const server = https.createServer(
					{ SNICallback: (_sni, cb) => cb(null, secureContext) },
					app
				);
				activeServer = server;
				server.listen(HTTP_PORT, '::', () => {
					console.log(
						`Viking Bio Proxy listening on https://${ddns.domain}:${HTTP_PORT}`
						+ ` (Let's Encrypt)`
					);
					if (PICO_BASE_URL)         console.log(`  Pico W base URL:        ${PICO_BASE_URL}`);
					if (PICO_VAPID_PUBLIC_KEY) console.log('  Using Pico W VAPID key');
				});
				return;
			}
		}

		// Certificate not available yet (e.g. DNS not propagated, port 80
		// unreachable); fall through to warn and start plain HTTP so the
		// dashboard is still reachable while the issue is resolved.
		console.warn('cert-manager: certificate not ready – starting HTTP instead.');
		console.warn(`  Ensure port 80 is reachable from the internet for ${ddns.domain}`);
	}

	// ------------------------------------------------------------------
	// Option 2: manual HTTPS with user-supplied cert/key
	// ------------------------------------------------------------------
	if (certPath && keyPath) {
		let cert, key;
		try {
			cert = fs.readFileSync(certPath);
			key  = fs.readFileSync(keyPath);
		} catch (err) {
			console.error(`Failed to read TLS cert/key: ${err.message}`);
			process.exit(1);
		}
		const server = https.createServer({ cert, key }, app);
		activeServer = server;
		server.listen(HTTP_PORT, '::', () => {
			console.log(`Viking Bio Proxy listening on https://[::]:${HTTP_PORT} (TLS)`);
			if (PICO_BASE_URL)         console.log(`  Pico W base URL:        ${PICO_BASE_URL}`);
			if (PICO_VAPID_PUBLIC_KEY) console.log('  Using Pico W VAPID key');
		});
		return;
	}

	// ------------------------------------------------------------------
	// Option 3: plain HTTP (development / fallback)
	// ------------------------------------------------------------------
	const server = http.createServer(app);
	activeServer = server;
	server.listen(HTTP_PORT, '::', () => {
		console.log(`Viking Bio Proxy listening on http://[::]:${HTTP_PORT}`);
		if (PICO_BASE_URL)         console.log(`  Pico W base URL:        ${PICO_BASE_URL}`);
		if (PICO_VAPID_PUBLIC_KEY) console.log('  Using Pico W VAPID key');
	});
}

startServer().catch((err) => {
	console.error(`Server startup failed: ${err.message}`);
	process.exit(1);
});
