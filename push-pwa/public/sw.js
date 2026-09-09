/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const OFFLINE_HEARTBEATS_THRESHOLD = 3;
const DEVICE_OFFLINE_THRESHOLD_MS = HEARTBEAT_INTERVAL_MS * OFFLINE_HEARTBEATS_THRESHOLD;
const offlineNotifications = new Map();

async function checkOfflineDevices() {
  try {
    const response = await fetch('/status.php', { headers: { Accept: 'application/json' } });
    if (!response.ok) {
      return;
    }

    const data = await response.json();
    const devices = data && typeof data.devices === 'object' ? Object.values(data.devices) : [];
    const now = Date.now();

    for (const deviceEntry of devices) {
      const deviceId = String(deviceEntry.device || 'Bridge device').trim();
      const timestamp = Number(deviceEntry.timestamp);
      if (!Number.isFinite(timestamp) || timestamp <= 0) {
        continue;
      }

      if (now - timestamp > DEVICE_OFFLINE_THRESHOLD_MS) {
        const lastNotice = offlineNotifications.get(deviceId) || 0;
        if (now - lastNotice < 60 * 60 * 1000) {
          continue;
        }

        offlineNotifications.set(deviceId, now);
        await self.registration.showNotification('Viking Bio', {
          body: `${deviceId} appears to be offline.`,
          icon: '/icon.svg',
          badge: '/icon.svg',
          tag: `viking-bio-offline-${deviceId}`,
          data: { url: '/' },
        });
      } else {
        offlineNotifications.delete(deviceId);
      }
    }
  } catch (error) {
    // Ignore transient polling failures while the app is offline or the endpoint is unavailable.
  }
}

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
  self.setInterval(checkOfflineDevices, 60 * 1000);
});

function normaliseNotificationTarget(targetUrl) {
  const safeFallback = '/';
  if (typeof targetUrl !== 'string') {
    return safeFallback;
  }

  const trimmed = targetUrl.trim();
  if (trimmed === '' || trimmed === '#') {
    return safeFallback;
  }

  try {
    const url = new URL(trimmed, self.location.origin);
    if (url.origin !== self.location.origin) {
      return safeFallback;
    }
    return url.pathname + url.search + url.hash || safeFallback;
  } catch (error) {
    return safeFallback;
  }
}

self.addEventListener('push', (event) => {
  const payload = event.data && event.data.json ? event.data.json() : { title: 'Viking Bio', body: 'A new burner update is available.' };
  const rawTimestamp = payload.timestamp;
  const urgency = String(payload.urgency || 'normal').toLowerCase();
  const options = {
    body: payload.body || 'New burner update',
    icon: payload.icon || '/icon.svg',
    badge: payload.icon || '/icon.svg',
    tag: payload.tag || 'viking-bio-alert',
    data: { url: normaliseNotificationTarget(payload.url || payload.uiUrl || '/') },
  };

  if (urgency === 'high') {
    options.vibrate = [100, 50, 100];
  }

  if (rawTimestamp != null && Number.isFinite(Number(rawTimestamp))) {
    options.timestamp = Number(rawTimestamp);
  }

  event.waitUntil(self.registration.showNotification(payload.title || 'Viking Bio', options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const payload = event.notification && event.notification.data ? event.notification.data : {};
  const targetUrl = normaliseNotificationTarget(payload.url || payload.uiUrl || '/');
  const openPage = () => self.clients.openWindow(targetUrl);
  event.waitUntil(openPage());
});
