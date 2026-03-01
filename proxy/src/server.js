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

// Push manager handles subscriptions and sending notifications
const pushManager = createPushManager();

// Scheduler handles the cleaning reminder
const scheduler = createScheduler(pushManager);

// Webhook receiver processes authenticated POST requests from the Pico bridge
const webhookReceiver = createWebhookReceiver(state, pushManager);

// Start cleaning reminder scheduler
scheduler.start();

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

// GET /api/vapid-public-key - VAPID public key for push subscriptions
app.get('/api/vapid-public-key', (req, res) => {
	res.json({ key: pushManager.getVapidPublicKey() });
});

// GET /api/subscribers - number of active subscriptions
app.get('/api/subscribers', (req, res) => {
	res.json({ count: pushManager.getSubscriptionCount() });
});

// POST /api/machine-data - receive authenticated telemetry from the Pico bridge
app.post('/api/machine-data', webhookReceiver.middleware);

// POST /api/subscribe - add or update a push subscription
app.post('/api/subscribe', (req, res) => {
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
	res.json({ status: ok ? 'ok' : 'full' });
});

// POST /api/unsubscribe - remove a push subscription
app.post('/api/unsubscribe', (req, res) => {
	const { endpoint } = req.body;
	if (endpoint) pushManager.removeSubscription(endpoint);
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
	});
} else {
	const server = http.createServer(app);
	server.listen(HTTP_PORT, '::', () => {
		console.log(`Viking Bio Proxy listening on http://[::]:${HTTP_PORT}`);
	});
}
