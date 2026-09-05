const CACHE_NAME = 'viking-bio-v11';
const ASSETS = [
	'/',
	'/index.html',
	'/docs.html',
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

