var CACHE_NAME = 'viking-bio-v1';
var ASSETS = [
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

self.addEventListener('install', function(e) {
	e.waitUntil(
		caches.open(CACHE_NAME).then(function(cache) {
			return cache.addAll(ASSETS);
		}).then(function() {
			return self.skipWaiting();
		})
	);
});

self.addEventListener('activate', function(e) {
	e.waitUntil(
		caches.keys().then(function(names) {
			return Promise.all(
				names.filter(function(n) { return n !== CACHE_NAME; })
					.map(function(n) { return caches.delete(n); })
			);
		}).then(function() {
			return clients.claim();
		})
	);
});

self.addEventListener('fetch', function(e) {
	var url = new URL(e.request.url);

	// API requests: network-only (never cache dynamic data)
	if (url.pathname.startsWith('/api/')) {
		return;
	}

	// Static assets: cache-first, falling back to network
	e.respondWith(
		caches.match(e.request).then(function(cached) {
			if (cached) {
				return cached;
			}
			return fetch(e.request).then(function(response) {
				// Only cache successful same-origin responses
				if (response.ok && url.origin === self.location.origin) {
					var clone = response.clone();
					caches.open(CACHE_NAME).then(function(cache) {
						cache.put(e.request, clone);
					});
				}
				return response;
			});
		})
	);
});

self.addEventListener('push', function(e) {
	var d = { title: 'Viking Bio Alert', body: 'Alert from burner', icon: '/icon-192.png', priority: 'high', type: 'error' };
	try { d = e.data.json(); } catch (ex) {}

	var options = {
		body: d.body,
		icon: d.icon || '/icon-192.png',
		badge: '/icon-192.png',
		tag: 'viking-bio'
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

self.addEventListener('notificationclick', function(e) {
	e.notification.close();
	e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
		for (var i = 0; i < clientList.length; i++) {
			var c = clientList[i];
			if (new URL(c.url).pathname === '/' && 'focus' in c) return c.focus();
		}
		if (clients.openWindow) return clients.openWindow('/');
	}));
});
