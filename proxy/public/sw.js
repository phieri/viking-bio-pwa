const CACHE_NAME = 'viking-bio-v3';
const ASSETS = [
	'/',
	'/index.html',
	'/style.css',
	'/app.js',
	'/manifest.json',
	'/icon.svg',
	'/icon-192.png',
	'/icon-512.png',
	'/icon-maskable-192.png',
	'/icon-maskable-512.png',
	'/apple-touch-icon.png',
	'/favicon-32.png',
	'/favicon-16.png'
];

self.addEventListener('install', (e) => {
	e.waitUntil(
		caches.open(CACHE_NAME)
			.then((cache) => cache.addAll(ASSETS))
			.then(() => self.skipWaiting())
	);
});

self.addEventListener('activate', (e) => {
	e.waitUntil(
		caches.keys().then((names) => {
			return Promise.all(
				names.filter((n) => n !== CACHE_NAME)
					.map((n) => caches.delete(n))
			);
		}).then(() => clients.claim())
	);
});

self.addEventListener('fetch', (e) => {
	const url = new URL(e.request.url);

	// API requests: network-only (never cache dynamic data)
	if (url.pathname.startsWith('/api/')) {
		return;
	}

	// Static assets: cache-first, falling back to network
	e.respondWith(
		caches.match(e.request).then((cached) => {
			if (cached) {
				return cached;
			}
			return fetch(e.request).then((response) => {
				// Only cache successful same-origin responses
				if (response.ok && url.origin === self.location.origin) {
					const clone = response.clone();
					caches.open(CACHE_NAME).then((cache) => {
						cache.put(e.request, clone);
					});
				}
				return response;
			});
		})
	);
});

self.addEventListener('push', (e) => {
	let d = { title: 'Viking Bio-avisering', body: 'Avisering från pannan', icon: '/icon-192.png', priority: 'high', type: 'error', ts: Date.now() };
	try { d = e.data.json(); } catch (ex) {}

	// Use payload timestamp (ms since epoch) if present, otherwise fall back to now
	const ts = (typeof d.ts === 'number') ? d.ts : Date.now();
	const options = {
		body: d.body,
		icon: d.icon || '/icon-192.png',
		badge: '/icon-192.png',
		tag: 'viking-bio',
		// Pass timestamp to native notification UI (Chromium) and to data for all browsers
		timestamp: ts,
		data: Object.assign({}, d.data || {}, { ts }),
	};

	// Low-priority on/off/status messages: silent, non-intrusive
	if (d.priority === 'low' || d.type === 'status' || d.type === 'onoff') {
		options.silent = true;
		options.renotify = false;
		options.requireInteraction = false;
		options.tag = 'viking-bio-low';
	} else {
		// High-priority errors: require user interaction, vibrate, and renotify
		options.requireInteraction = true;
		options.renotify = true;
		options.vibrate = [200, 100, 200];
		options.tag = 'viking-bio-high';
	}

	e.waitUntil(self.registration.showNotification(d.title, options));
});

self.addEventListener('notificationclick', (e) => {
	e.notification.close();
	e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
		for (const c of clientList) {
			if (new URL(c.url).pathname === '/' && 'focus' in c) return c.focus();
		}
		if (clients.openWindow) return clients.openWindow('/');
	}));
});
