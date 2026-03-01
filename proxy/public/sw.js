self.addEventListener('push', function(e) {
  var d = {title: 'Viking Bio Alert', body: 'Alert from burner', icon: '/icon.png', priority: 'high', type: 'error'};
  try { d = e.data.json(); } catch (ex) {}

  var options = {
    body: d.body,
    icon: d.icon || '/icon.png',
    badge: d.icon || '/icon.png',
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
  e.waitUntil(clients.matchAll({type: 'window', includeUncontrolled: true}).then(function(clientList) {
    for (var i = 0; i < clientList.length; i++) {
      var c = clientList[i];
      if (c.url === '/' && 'focus' in c) return c.focus();
    }
    if (clients.openWindow) return clients.openWindow('/');
  }));
});

self.addEventListener('install', function(e) { self.skipWaiting(); });
self.addEventListener('activate', function(e) { e.waitUntil(clients.claim()); });
