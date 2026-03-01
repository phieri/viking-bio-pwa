#!/usr/bin/env node
'use strict';

const express = require('express');
const path = require('path');
const { createTcpReceiver } = require('./tcp-receiver');
const { createPushManager } = require('./push-manager');
const { createScheduler } = require('./scheduler');

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '3000', 10);
const TCP_PORT  = parseInt(process.env.TCP_PORT  || '9000', 10);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Shared burner state updated by TCP receiver
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

// TCP receiver gets data from the Pico bridge
createTcpReceiver(TCP_PORT, state, pushManager);

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

// Start HTTP server
app.listen(HTTP_PORT, () => {
	console.log(`Viking Bio Proxy listening on http://0.0.0.0:${HTTP_PORT}`);
	console.log(`TCP receiver listening on port ${TCP_PORT}`);
});
