const STORAGE_KEY = 'viking-bio-locale';
const translations = {
  en: {
    title: 'Viking Bio Alerts',
    eyebrow: 'Viking Bio',
    heading: 'Burner alerts',
    lead: 'Generate a single YAML snippet for a client subscription and paste it into the subscription file manually.',
    installTitle: 'Install this app',
    installText: 'On iPhone or iPad, tap the Share button and choose “Add to Home Screen”.',
    installButton: 'Install app',
    languageLabel: 'Language',
    senderLabel: 'Sender ID',
    senderPlaceholder: 'viking-bio-01',
    notificationLevelsLabel: 'Notification levels',
    low: 'low',
    normal: 'normal',
    high: 'high',
    priorityLabel: 'Test alert priority',
    generateYaml: 'Generate client YAML',
    copyYaml: 'Copy YAML',
    sendTestAlert: 'Send test alert',
    yamlAria: 'Subscription YAML snippet',
    waitingHeartbeat: 'Waiting for device heartbeat.',
    waitingRssi: 'Waiting for RSSI data.',
    waitingLfs: 'Waiting for LittleFS health.',
    waitingStatus: 'Waiting for subscription data.',
    noHeartbeat: 'No device heartbeat received yet.',
    rssiUnavailable: 'RSSI: unavailable',
    lfsUnavailable: 'LittleFS: unavailable',
    deviceOfflineTitle: 'Viking Bio device offline',
    deviceOfflineBody: '{deviceLabel} appears to be offline.',
    offlineNotice: '{deviceLabel} appears to be offline.',
    unknownTime: 'Unknown time',
    lastContact: 'Last device contact: {label}',
    healthy: 'healthy',
    degraded: 'degraded',
    heartbeatStatusUnavailable: 'Heartbeat status unavailable.',
    loadingConfig: 'Loading app configuration...',
    registeringWorker: 'Registering service worker...',
    unsupportedPush: 'This browser does not support Web Push notifications.',
    requestingPermission: 'Requesting notification permission...',
    permissionNotGranted: 'Notification permission was not granted.',
    notificationsBlocked: 'Notifications are blocked.',
    missingPublicKey: 'The VAPID key is missing from the server response.',
    noInstallPrompt: 'The browser has not surfaced an install prompt yet.',
    shareButtonPrompt: 'Use the Share button in Safari, then choose “Add to Home Screen”.',
    noYamlBeforeCopy: 'Generate a client YAML snippet before copying it.',
    yamlCopied: 'Subscription YAML copied to clipboard.',
    generateBeforeCopyError: 'Generate a client YAML snippet before copying it.',
    statusLoadingConfig: 'Loading app configuration...',
    statusGenerating: 'Client subscription generated. Paste it into subscriptions.yaml.',
    statusTestSent: 'Sent {count} message(s).',
    testPermissionRequired: 'Grant notification permission before sending a test message.',
    testNotificationTitle: 'Test notification',
    testNotificationBody: 'This is a Viking Bio test alert from the push PWA.',
    testSendFailed: 'The test notification could not be sent.',
  },
  sv: {
    title: 'Viking Bio-varningar',
    eyebrow: 'Viking Bio',
    heading: 'Pannvarningar',
    lead: 'Skapa en enda YAML-snutt för en klientprenumeration och klistra in den i prenumerationsfilen manuellt.',
    installTitle: 'Installera appen',
    installText: 'På iPhone eller iPad trycker du på Delningsknappen och väljer “Lägg till på hemskärmen”.',
    installButton: 'Installera app',
    languageLabel: 'Språk',
    senderLabel: 'Avsändar-ID',
    senderPlaceholder: 'viking-bio-01',
    notificationLevelsLabel: 'Aviseringsnivåer',
    low: 'låg',
    normal: 'normal',
    high: 'hög',
    priorityLabel: 'Prioritet för testavisering',
    generateYaml: 'Skapa klient-YAML',
    copyYaml: 'Kopiera YAML',
    sendTestAlert: 'Skicka testavisering',
    yamlAria: 'YAML-snutt för prenumeration',
    waitingHeartbeat: 'Väntar på enhetssignal.',
    waitingRssi: 'Väntar på RSSI-data.',
    waitingLfs: 'Väntar på LittleFS-status.',
    waitingStatus: 'Väntar på prenumerationsdata.',
    noHeartbeat: 'Ingen enhetssignal har mottagits ännu.',
    rssiUnavailable: 'RSSI: ej tillgängligt',
    lfsUnavailable: 'LittleFS: ej tillgängligt',
    deviceOfflineTitle: 'Viking Bio-enheten är offline',
    deviceOfflineBody: '{deviceLabel} verkar vara offline.',
    offlineNotice: '{deviceLabel} verkar vara offline.',
    unknownTime: 'Okänd tid',
    lastContact: 'Senaste kontakt med enheten: {label}',
    healthy: 'frisk',
    degraded: 'nedsatt',
    heartbeatStatusUnavailable: 'Status för hjärtslag är inte tillgänglig.',
    loadingConfig: 'Laddar appkonfiguration...',
    registeringWorker: 'Registrerar tjänstearbetare...',
    unsupportedPush: 'Den här webbläsaren stöder inte Web Push-meddelanden.',
    requestingPermission: 'Begär tillåtelse för aviseringar...',
    permissionNotGranted: 'Tillåtelse för aviseringar gavs inte.',
    notificationsBlocked: 'Aviseringar är blockerade.',
    missingPublicKey: 'VAPID-nyckeln saknas i serverns svar.',
    noInstallPrompt: 'Webbläsaren har ännu inte visat någon installationsprompt.',
    shareButtonPrompt: 'Använd Delningsknappen i Safari och välj sedan “Lägg till på hemskärmen”.',
    noYamlBeforeCopy: 'Skapa en klient-YAML-snutt innan du kopierar den.',
    yamlCopied: 'Prenumerations-YAML kopierades till urklipp.',
    generateBeforeCopyError: 'Skapa en klient-YAML-snutt innan du kopierar den.',
    statusLoadingConfig: 'Laddar appkonfiguration...',
    statusGenerating: 'Kundprenumeration skapad. Klistra in den i subscriptions.yaml.',
    statusTestSent: 'Skickade {count} meddelande(n).',
    testPermissionRequired: 'Godkänn aviseringstillåtelse innan du skickar ett testmeddelande.',
    testNotificationTitle: 'Testavisering',
    testNotificationBody: 'Detta är ett Viking Bio-testmeddelande från push PWA.',
    testSendFailed: 'Testaviseringen kunde inte skickas.',
  },
};

let uiUrl = (window.location.origin && window.location.origin !== 'null') ? window.location.origin : (window.location.protocol + '//' + window.location.host);
let sendToken = '';
let locale = 'en';
const installBanner = document.getElementById('install-banner');
const installButton = document.getElementById('install-button');
const enablePushButton = document.getElementById('enable-push');
const sendTestButton = document.getElementById('send-test');
const copyButton = document.getElementById('copy-yaml');
const prioritySelect = document.getElementById('subscription-priority');
const senderInput = document.getElementById('subscription-sender');
const subscriptionYaml = document.getElementById('subscription-yaml');
const statusBox = document.getElementById('status');
const lastContactBox = document.getElementById('last-contact-status');
const rssiBox = document.getElementById('rssi-status');
const lfsBox = document.getElementById('lfs-status');
const languageSelect = document.getElementById('language-select');
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || ((window.navigator.userAgentData && window.navigator.userAgentData.platform === 'macOS') && navigator.maxTouchPoints > 1) || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const OFFLINE_HEARTBEATS_THRESHOLD = 3;
const DEVICE_OFFLINE_THRESHOLD_MS = HEARTBEAT_INTERVAL_MS * OFFLINE_HEARTBEATS_THRESHOLD;
let installPromptEvent = null;
let lastOfflineNotificationAt = 0;

function getPreferredLocale() {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored && Object.prototype.hasOwnProperty.call(translations, stored)) {
      return stored;
    }
  } catch (error) {
    // Ignore localStorage failures and fall back to browser language detection.
  }

  return navigator.language && navigator.language.toLowerCase().startsWith('sv') ? 'sv' : 'en';
}

function t(key, replacements = {}) {
  const strings = translations[locale] || translations.en;
  let value = strings[key] || translations.en[key] || key;

  Object.entries(replacements).forEach(([replacementKey, replacementValue]) => {
    value = value.replace(new RegExp(`\\{${replacementKey}\\}`, 'g'), String(replacementValue));
  });

  return value;
}

function applyTranslations() {
  document.documentElement.lang = locale;
  document.title = t('title');

  document.querySelectorAll('[data-i18n]').forEach((element) => {
    const key = element.dataset.i18n;
    if (key && translations[locale][key]) {
      element.textContent = t(key);
    }
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach((element) => {
    const key = element.dataset.i18nPlaceholder;
    if (key && translations[locale][key]) {
      element.placeholder = t(key);
    }
  });

  document.querySelectorAll('[data-i18n-aria]').forEach((element) => {
    const key = element.dataset.i18nAria;
    if (key && translations[locale][key]) {
      element.setAttribute('aria-label', t(key));
    }
  });

  if (languageSelect) {
    languageSelect.value = locale;
  }
}

function notifyOffline(deviceLabel) {
  if (!('Notification' in window) || Notification.permission !== 'granted') {
    return;
  }

  const now = Date.now();
  if (now - lastOfflineNotificationAt < 60 * 60 * 1000) {
    return;
  }

  lastOfflineNotificationAt = now;
  new Notification(t('deviceOfflineTitle'), {
    body: t('deviceOfflineBody', { deviceLabel }),
    tag: `viking-bio-offline-${deviceLabel}`,
    icon: '/icon.svg',
    badge: '/icon.svg',
  });
}

function setStatus(message, type = '') {
  statusBox.textContent = message;
  statusBox.className = `status ${type}`.trim();
}

async function loadLastContactStatus() {
  try {
    const response = await fetch('/status.php', { headers: { Accept: 'application/json' } });
    if (!response.ok) {
      throw new Error(t('heartbeatStatusUnavailable'));
    }

    const data = await response.json();
    const devices = data && typeof data.devices === 'object' ? Object.values(data.devices) : [];
    const selectedSender = (senderInput.value || '').trim();
    const selectedDevice = selectedSender
      ? devices.find((device) => String(device.device || '').toLowerCase() === selectedSender.toLowerCase())
      : null;
    const lastContact = selectedDevice ? selectedDevice.timestamp : data.lastContact;
    const rssiValue = selectedDevice && Number.isFinite(Number(selectedDevice.rssi))
      ? Number(selectedDevice.rssi)
      : (Number.isFinite(Number(data.lastRssi)) ? Number(data.lastRssi) : null);
    const lfsHealth = selectedDevice && Object.prototype.hasOwnProperty.call(selectedDevice, 'lfsHealth')
      ? selectedDevice.lfsHealth
      : data.lastLfsHealth;

    if (!lastContact || !Number.isFinite(Number(lastContact))) {
      lastContactBox.textContent = t('noHeartbeat');
      rssiBox.textContent = t('rssiUnavailable');
      lfsBox.textContent = t('lfsUnavailable');
      return;
    }

    const contactTimestamp = Number(lastContact);
    const isOffline = Date.now() - contactTimestamp > DEVICE_OFFLINE_THRESHOLD_MS;
    if (isOffline) {
      const deviceLabel = selectedDevice && selectedDevice.device ? selectedDevice.device : 'Bridge device';
      lastContactBox.textContent = t('offlineNotice', { deviceLabel });
      rssiBox.textContent = rssiValue === null ? t('rssiUnavailable') : `RSSI: ${rssiValue} dBm`;
      lfsBox.textContent = lfsHealth === null ? t('lfsUnavailable') : `LittleFS: ${lfsHealth ? t('healthy') : t('degraded')}`;
      notifyOffline(deviceLabel);
      return;
    }

    const stamp = new Date(contactTimestamp);
    const label = Number.isNaN(stamp.getTime()) ? t('unknownTime') : stamp.toLocaleString();
    lastContactBox.textContent = t('lastContact', { label });
    rssiBox.textContent = rssiValue === null ? t('rssiUnavailable') : `RSSI: ${rssiValue} dBm`;
    lfsBox.textContent = lfsHealth === null ? t('lfsUnavailable') : `LittleFS: ${lfsHealth ? t('healthy') : t('degraded')}`;
  } catch (error) {
    lastContactBox.textContent = t('heartbeatStatusUnavailable');
    rssiBox.textContent = t('rssiUnavailable');
    lfsBox.textContent = t('lfsUnavailable');
  }
}

async function loadConfig() {
  const response = await fetch('/config.php', { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error('Could not load the app configuration.');
  }

  const config = await response.json();
  uiUrl = config.uiUrl || uiUrl;
  sendToken = config.sendToken || sendToken;
  return config;
}

async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) {
    throw new Error(t('unsupportedPush'));
  }

  await navigator.serviceWorker.register('/sw.js', { scope: '/' });
}

async function fetchPublicKey() {
  const response = await fetch('/public-key.php', { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error('Could not fetch the VAPID public key.');
  }

  const data = await response.json();
  if (!data.publicKey) {
    throw new Error(t('missingPublicKey'));
  }

  return data.publicKey;
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const output = new Uint8Array(raw.length);

  for (let index = 0; index < raw.length; index += 1) {
    output[index] = raw.charCodeAt(index);
  }

  return output;
}

function getNotificationLevels() {
  return {
    low: document.getElementById('notification-level-low').checked,
    normal: document.getElementById('notification-level-normal').checked,
    high: document.getElementById('notification-level-high').checked,
  };
}

// This clipboard payload is intentionally wrapped under a `subscriptions` list so the
// generated YAML reads like a subscription collection, not a single user-facing priority.
function buildSubscriptionYaml(subscription) {
  const keys = subscription.toJSON ? subscription.toJSON().keys : subscription.keys || {};
  const sender = (senderInput.value || '').trim();
  return {
    subscriptions: [{
      endpoint: subscription.endpoint,
      keys: {
        p256dh: keys.p256dh || '',
        auth: keys.auth || '',
      },
      sender,
      notificationLevel: getNotificationLevels(),
      uiUrl,
    }],
  };
}

async function enableNotifications() {
  try {
    setStatus(t('loadingConfig'));
    await loadConfig();

    setStatus(t('registeringWorker'));
    await registerServiceWorker();

    if (!('PushManager' in window)) {
      throw new Error(t('unsupportedPush'));
    }

    let permission = Notification.permission;
    if (permission === 'default') {
      setStatus(t('requestingPermission'));
      permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        throw new Error(t('permissionNotGranted'));
      }
    }

    if (permission !== 'granted') {
      throw new Error(t('notificationsBlocked'));
    }

    const publicKey = await fetchPublicKey();
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    });

    const payload = buildSubscriptionYaml(subscription);
    subscriptionYaml.value = JSON.stringify(payload, null, 2);
    setStatus(t('statusGenerating'), 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

async function sendTestAlert() {
  try {
    if (!sendToken) {
      await loadConfig();
    }

    const permission = Notification.permission;
    if (permission !== 'granted') {
      throw new Error(t('testPermissionRequired'));
    }

    const sender = (senderInput.value || '').trim();
    const response = await fetch('/send.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + sendToken,
      },
      body: JSON.stringify({
        title: t('testNotificationTitle'),
        body: t('testNotificationBody'),
        sender,
        priority: prioritySelect.value,
        url: uiUrl,
      }),
    });

    if (!response.ok) {
      throw new Error(t('testSendFailed'));
    }

    const data = await response.json();
    setStatus(t('statusTestSent', { count: data.sent }), 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

copyButton.addEventListener('click', async () => {
  if (!subscriptionYaml.value.trim()) {
    setStatus(t('generateBeforeCopyError'), 'error');
    return;
  }

  await navigator.clipboard.writeText(subscriptionYaml.value);
  setStatus(t('yamlCopied'), 'success');
});

if (isIOS && !window.matchMedia('(display-mode: standalone)').matches) {
  installBanner.classList.remove('hidden');
}

languageSelect.addEventListener('change', (event) => {
  locale = event.target.value;
  try {
    window.localStorage.setItem(STORAGE_KEY, locale);
  } catch (error) {
    // Ignore storage errors and keep the selected locale in memory.
  }
  applyTranslations();
});

locale = getPreferredLocale();
applyTranslations();
loadLastContactStatus();
window.setInterval(loadLastContactStatus, 30000);

window.addEventListener('beforeinstallprompt', (event) => {
  event.preventDefault();
  installPromptEvent = event;
  if (!isIOS) {
    installBanner.classList.remove('hidden');
  }
});

installButton.addEventListener('click', async () => {
  if (isIOS) {
    setStatus(t('shareButtonPrompt'));
    return;
  }

  if (!installPromptEvent) {
    setStatus(t('noInstallPrompt'), 'error');
    return;
  }

  installPromptEvent.prompt();
  await installPromptEvent.userChoice;
  installBanner.classList.add('hidden');
});

enablePushButton.addEventListener('click', enableNotifications);
sendTestButton.addEventListener('click', sendTestAlert);
