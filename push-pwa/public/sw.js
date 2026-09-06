self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  const payload = event.data && event.data.json ? event.data.json() : { title: 'Viking Bio', body: 'A new burner update is available.' };
  const rawTimestamp = payload.timestamp;
  const sentAt = rawTimestamp != null && Number.isFinite(Number(rawTimestamp)) ? Number(rawTimestamp) : Date.now();

  const options = {
    body: payload.body || 'New burner update',
    icon: payload.icon || '/icon.svg',
    badge: payload.icon || '/icon.svg',
    tag: payload.tag || 'viking-bio-alert',
    vibrate: [100, 50, 100],
    timestamp: sentAt,
    data: { url: payload.url || payload.uiUrl || '/', sentAt },
  };

  event.waitUntil(self.registration.showNotification(payload.title || 'Viking Bio', options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const payload = event.notification && event.notification.data ? event.notification.data : {};
  const targetUrl = payload.url || payload.uiUrl || '/';
  const openPage = () => self.clients.openWindow(targetUrl);
  event.waitUntil(openPage());
});
