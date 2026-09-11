/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const OFFLINE_HEARTBEATS_THRESHOLD = 3;
const DEVICE_OFFLINE_THRESHOLD_MS = HEARTBEAT_INTERVAL_MS * OFFLINE_HEARTBEATS_THRESHOLD;
const offlineNotifications = new Map();
let preferredLanguage = 'en';

const messages = {
  en: { title: 'Viking Bio', offline: '{device} appears to be offline.', defaultBody: 'A new burner update is available.' },
  sv: { title: 'Viking Bio', offline: '{device} verkar vara offline.', defaultBody: 'En ny uppdatering från brännaren finns tillgänglig.' },
  no: { title: 'Viking Bio', offline: '{device} ser ut til å være frakoblet.', defaultBody: 'En ny oppdatering fra brenneren er tilgjengelig.' },
  fi: { title: 'Viking Bio', offline: '{device} näyttää olevan poissa verkosta.', defaultBody: 'Uusi päivitys polttimelta on saatavilla.' },
  da: { title: 'Viking Bio', offline: '{device} ser ud til at være offline.', defaultBody: 'En ny opdatering fra brænderen er tilgængelig.' },
  is: { title: 'Viking Bio', offline: '{device} virðist vera ótengt.', defaultBody: 'Ný uppfærsla frá brennara er tiltæk.' },
};

function normaliseLanguage(value) {
  const candidate = String(value || '').trim().toLowerCase().replace(/_/g, '-');
  if (!candidate) {
    return 'en';
  }
  if (candidate.startsWith('sv')) {
    return 'sv';
  }
  if (candidate.startsWith('no') || candidate.startsWith('nb') || candidate.startsWith('nn')) {
    return 'no';
  }
  if (candidate.startsWith('fi')) {
    return 'fi';
  }
  if (candidate.startsWith('da')) {
    return 'da';
  }
  if (candidate.startsWith('is')) {
    return 'is';
  }
  return 'en';
}

function t(key, replacements = {}) {
  const catalog = messages[preferredLanguage] || messages.en;
  const template = catalog[key] || messages.en[key] || '';
  return String(template).replace(/\{(\w+)\}/g, (_, name) => String(replacements[name] ?? ''));
}

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
        await self.registration.showNotification(t('title'), {
          body: t('offline', { device: deviceId }),
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

self.addEventListener('message', (event) => {
  const data = event.data && typeof event.data === 'object' ? event.data : null;
  if (data && data.type === 'set-language') {
    preferredLanguage = normaliseLanguage(data.language);
  }
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

async function forwardHeartbeatToClients(payload) {
  const clientsList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const client of clientsList) {
    client.postMessage({ type: 'heartbeat', payload });
  }
}

self.addEventListener('push', (event) => {
  const payload = event.data && event.data.json ? event.data.json() : { title: t('title'), body: t('defaultBody') };
  const rawTimestamp = payload.timestamp;
  const urgency = String(payload.urgency || 'normal').toLowerCase();

  if (payload && payload.type === 'heartbeat') {
    event.waitUntil(forwardHeartbeatToClients(payload));
    return;
  }

  const options = {
    body: payload.body || t('defaultBody'),
    icon: payload.icon || '/icon.svg',
    badge: payload.icon || '/icon.svg',
    tag: urgency === 'low' ? 'cleaningReminder' : (payload.tag || 'viking-bio-alert'),
    data: { url: normaliseNotificationTarget(payload.url || payload.uiUrl || '/') },
  };

  if (urgency === 'high') {
    options.vibrate = [100, 50, 100];
  }

  if (urgency === 'low') {
    options.silent = true;
  }

  if (rawTimestamp != null && Number.isFinite(Number(rawTimestamp))) {
    options.timestamp = Number(rawTimestamp);
  }

  event.waitUntil(self.registration.showNotification(payload.title || t('title'), options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const payload = event.notification && event.notification.data ? event.notification.data : {};
  const targetUrl = normaliseNotificationTarget(payload.url || payload.uiUrl || '/');
  const openPage = () => self.clients.openWindow(targetUrl);
  event.waitUntil(openPage());
});
