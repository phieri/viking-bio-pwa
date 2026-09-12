/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

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

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
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

function parsePushPayload(event) {
  if (!event.data) {
    return { title: t('title'), body: t('defaultBody') };
  }

  try {
    if (typeof event.data.json === 'function') {
      const payload = event.data.json();
      if (payload && typeof payload === 'object') {
        return payload;
      }
    }
  } catch (error) {
    console.warn('Ignoring malformed push payload JSON', error);
  }

  const text = typeof event.data.text === 'function' ? event.data.text() : '';
  if (typeof text === 'string' && text.trim() !== '') {
    return { title: t('title'), body: text.trim() };
  }

  return { title: t('title'), body: t('defaultBody') };
}

self.addEventListener('push', (event) => {
  const payload = parsePushPayload(event);
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
  event.waitUntil((async () => {
    const clientsList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of clientsList) {
      const clientUrl = normaliseNotificationTarget(client.url || '/');
      if (clientUrl === targetUrl) {
        if (typeof client.focus === 'function') {
          await client.focus();
        }
        return;
      }
    }

    await self.clients.openWindow(targetUrl);
  })());
});
