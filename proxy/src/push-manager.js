'use strict';

const webpush = require('web-push');
const fs   = require('fs');
const path = require('path');

const DATA_DIR   = path.join(__dirname, '..', 'data');
const VAPID_FILE = path.join(DATA_DIR, 'vapid.json');
const SUBS_FILE  = path.join(DATA_DIR, 'subscriptions.json');

// Maximum stored subscriptions
const MAX_SUBSCRIPTIONS = 32;

/**
 * Creates a push manager that handles VAPID key generation/persistence,
 * subscription management, and sending Web Push notifications.
 *
 * Notification types:
 *   'flame' – flame on/off state change
 *   'error' – burner error code detected
 *   'clean' – periodic cleaning reminder
 *
 * @returns {object} Push manager API
 */
function createPushManager() {
	// Ensure data directory exists
	if (!fs.existsSync(DATA_DIR)) {
		fs.mkdirSync(DATA_DIR, { recursive: true });
	}

	// Load or generate VAPID keys
	let vapidKeys;
	if (fs.existsSync(VAPID_FILE)) {
		try {
			vapidKeys = JSON.parse(fs.readFileSync(VAPID_FILE, 'utf8'));
			console.log('push-manager: loaded VAPID keys from disk');
		} catch {
			vapidKeys = null;
		}
	}
	if (!vapidKeys || !vapidKeys.publicKey || !vapidKeys.privateKey) {
		vapidKeys = webpush.generateVAPIDKeys();
		fs.writeFileSync(VAPID_FILE, JSON.stringify(vapidKeys, null, 2));
		console.log('push-manager: generated new VAPID keys');
	}

	webpush.setVapidDetails(
		'mailto:admin@viking-bio.local',
		vapidKeys.publicKey,
		vapidKeys.privateKey
	);

	// Load stored subscriptions
	let subscriptions = [];
	if (fs.existsSync(SUBS_FILE)) {
		try {
			subscriptions = JSON.parse(fs.readFileSync(SUBS_FILE, 'utf8'));
			console.log(`push-manager: loaded ${subscriptions.length} subscription(s)`);
		} catch {
			subscriptions = [];
		}
	}

	function saveSubscriptions() {
		fs.writeFileSync(SUBS_FILE, JSON.stringify(subscriptions, null, 2));
	}

	/**
	 * Add or update a push subscription.
	 * @param {string} endpoint
	 * @param {string} p256dh
	 * @param {string} auth
	 * @param {{ flame: boolean, error: boolean, clean: boolean }} prefs
	 * @returns {boolean} true if added/updated, false if at capacity
	 */
	function addSubscription(endpoint, p256dh, auth, prefs) {
		const existing = subscriptions.findIndex(s => s.endpoint === endpoint);
		if (existing >= 0) {
			// Update existing subscription prefs
			subscriptions[existing] = { endpoint, p256dh, auth, prefs };
			saveSubscriptions();
			return true;
		}
		if (subscriptions.length >= MAX_SUBSCRIPTIONS) {
			console.warn('push-manager: subscription list full');
			return false;
		}
		subscriptions.push({ endpoint, p256dh, auth, prefs });
		saveSubscriptions();
		console.log(`push-manager: added subscription (total: ${subscriptions.length})`);
		return true;
	}

	/**
	 * Remove a push subscription by endpoint URL.
	 * @param {string} endpoint
	 */
	function removeSubscription(endpoint) {
		const before = subscriptions.length;
		subscriptions = subscriptions.filter(s => s.endpoint !== endpoint);
		if (subscriptions.length < before) {
			saveSubscriptions();
			console.log(`push-manager: removed subscription (total: ${subscriptions.length})`);
		}
	}

	/**
	 * Send a push notification to all subscribers that opted in to the given type.
	 *
	 * @param {'flame'|'error'|'clean'} type  Notification type
	 * @param {string} title  Notification title
	 * @param {string} body   Notification body
	 */
	async function notifyByType(type, title, body) {
		const payload = JSON.stringify({
			title,
			body,
			icon: '/icon.png',
			type,
			priority: type === 'error' ? 'high' : 'low',
		});

		const failed = [];

		await Promise.all(subscriptions.map(async (sub) => {
			// Check preference
			if (!sub.prefs || !sub.prefs[type]) return;

			const pushSub = {
				endpoint: sub.endpoint,
				keys: { p256dh: sub.p256dh, auth: sub.auth },
			};

			try {
				await webpush.sendNotification(pushSub, payload);
			} catch (err) {
				if (err.statusCode === 410 || err.statusCode === 404) {
					// Subscription expired – mark for removal
					failed.push(sub.endpoint);
				} else {
					console.error('push-manager: send error:', err.message);
				}
			}
		}));

		// Remove expired subscriptions
		if (failed.length > 0) {
			subscriptions = subscriptions.filter(s => !failed.includes(s.endpoint));
			saveSubscriptions();
			console.log(`push-manager: removed ${failed.length} expired subscription(s)`);
		}
	}

	return {
		getVapidPublicKey:    () => vapidKeys.publicKey,
		getSubscriptionCount: () => subscriptions.length,
		addSubscription,
		removeSubscription,
		notifyByType,
	};
}

module.exports = { createPushManager };
