#!/usr/bin/env node
'use strict';

const express = require('express');
const http    = require('http');
const https   = require('https');
const fs      = require('fs');
const path    = require('path');
const { createWebhookReceiver } = require('./webhook-receiver');
const { createPushManager } = require('./push-manager');
const { createScheduler } = require('./scheduler');

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '3000', 10);

// Optional: base URL of the Pico W's webhook API (e.g. http://[fe80::1%25eth0]:8080).
// When set the proxy forwards push subscriptions to the Pico so it can send
// Web Push notifications directly.  Must use a bracketed IPv6 literal if the
// address is IPv6.
const PICO_BASE_URL = process.env.PICO_BASE_URL || '';

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

// Scheduler handles the cleaning reminder
const scheduler = createScheduler(pushManager);

// Webhook receiver processes authenticated POST requests from the Pico bridge
const webhookReceiver = createWebhookReceiver(state, pushManager);

// Start cleaning reminder scheduler
scheduler.start();

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
		const req = transport.request({
			hostname: parsedUrl.hostname,
			port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
			path:     parsedUrl.pathname,
			method:   'POST',
			headers,
		}, (res) => {
			res.resume(); // drain
			const ok = res.statusCode >= 200 && res.statusCode < 300;
			if (!ok) console.warn(`pico-forward: ${urlPath} → HTTP ${res.statusCode}`);
			resolve(ok);
		});
		req.on('error', (err) => {
			console.warn(`pico-forward: ${urlPath} error: ${err.message}`);
			resolve(false);
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
		res.json({ key: PICO_VAPID_PUBLIC_KEY });
	} else {
		res.json({ key: pushManager.getVapidPublicKey() });
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
app.post('/api/subscribe', async (req, res) => {
	const { endpoint, p256dh, auth } = req.body;
	const prefs = req.body.prefs || {};
	if (!endpoint) {
		return res.status(400).json({ error: 'bad request' });
	}
	const ok = pushManager.addSubscription(endpoint, p256dh, auth, {
		flame: !!prefs.flame,
		error: !!prefs.error,
		clean: !!prefs.clean,
	});
	// Best-effort forward to Pico W (errors are non-fatal)
	picoForward('/api/subscribe', req.body);
	res.json({ status: ok ? 'ok' : 'full' });
});

// POST /api/unsubscribe - remove a push subscription
app.post('/api/unsubscribe', (req, res) => {
	const { endpoint } = req.body;
	if (endpoint) {
		pushManager.removeSubscription(endpoint);
		// Best-effort forward to Pico W
		picoForward('/api/unsubscribe', { endpoint });
	}
	res.json({ status: 'ok' });
});

// Start server: HTTPS if cert/key are configured, otherwise HTTP.
// Binds to '::' so the dashboard is reachable over both IPv6 and IPv4 (dual-stack).
const certPath = process.env.TLS_CERT_PATH;
const keyPath  = process.env.TLS_KEY_PATH;

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
	server.listen(HTTP_PORT, '::', () => {
		console.log(`Viking Bio Proxy listening on https://[::]:${HTTP_PORT} (TLS)`);
		if (PICO_BASE_URL)        console.log(`  Pico W base URL:        ${PICO_BASE_URL}`);
		if (PICO_VAPID_PUBLIC_KEY) console.log('  Using Pico W VAPID key');
	});
} else {
	const server = http.createServer(app);
	server.listen(HTTP_PORT, '::', () => {
		console.log(`Viking Bio Proxy listening on http://[::]:${HTTP_PORT}`);
		if (PICO_BASE_URL)        console.log(`  Pico W base URL:        ${PICO_BASE_URL}`);
		if (PICO_VAPID_PUBLIC_KEY) console.log('  Using Pico W VAPID key');
	});
}
