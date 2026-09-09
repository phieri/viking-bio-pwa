let uiUrl = (window.location.origin && window.location.origin !== 'null') ? window.location.origin : (window.location.protocol + '//' + window.location.host);
let sendToken = '';
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || ((window.navigator.userAgentData && window.navigator.userAgentData.platform === 'macOS') && navigator.maxTouchPoints > 1) || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const OFFLINE_HEARTBEATS_THRESHOLD = 3;
const DEVICE_OFFLINE_THRESHOLD_MS = HEARTBEAT_INTERVAL_MS * OFFLINE_HEARTBEATS_THRESHOLD;
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
const cpuTempBox = document.getElementById('cpu-temp-status');
let installPromptEvent = null;
let lastOfflineNotificationAt = 0;

function notifyOffline(deviceLabel) {
  if (!('Notification' in window) || Notification.permission !== 'granted') {
    return;
  }

  const now = Date.now();
  if (now - lastOfflineNotificationAt < 60 * 60 * 1000) {
    return;
  }

  lastOfflineNotificationAt = now;
  new Notification('Viking Bio device offline', {
    body: `${deviceLabel} appears to be offline.`,
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
      throw new Error('Could not load device heartbeat status.');
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
    const cpuTempValue = selectedDevice && Number.isFinite(Number(selectedDevice.cpuTemp))
      ? Number(selectedDevice.cpuTemp)
      : (Number.isFinite(Number(data.lastCpuTemp)) ? Number(data.lastCpuTemp) : null);

    if (!lastContact || !Number.isFinite(Number(lastContact))) {
      lastContactBox.textContent = 'No device heartbeat received yet.';
      rssiBox.textContent = 'RSSI: unavailable';
      lfsBox.textContent = 'LittleFS: unavailable';
      cpuTempBox.textContent = 'CPU temp: unavailable';
      return;
    }

    const contactTimestamp = Number(lastContact);
    const isOffline = Date.now() - contactTimestamp > DEVICE_OFFLINE_THRESHOLD_MS;
    if (isOffline) {
      const deviceLabel = selectedDevice && selectedDevice.device ? selectedDevice.device : 'Bridge device';
      lastContactBox.textContent = `${deviceLabel} appears to be offline.`;
      rssiBox.textContent = rssiValue === null ? 'RSSI: unavailable' : `RSSI: ${rssiValue} dBm`;
      lfsBox.textContent = lfsHealth === null ? 'LittleFS: unavailable' : `LittleFS: ${lfsHealth ? 'healthy' : 'degraded'}`;
      cpuTempBox.textContent = cpuTempValue === null ? 'CPU temp: unavailable' : `CPU temp: ${cpuTempValue.toFixed(1)}°C`;
      notifyOffline(deviceLabel);
      return;
    }

    const stamp = new Date(contactTimestamp);
    const label = Number.isNaN(stamp.getTime()) ? 'Unknown time' : stamp.toLocaleString();
    lastContactBox.textContent = `Last device contact: ${label}`;
    rssiBox.textContent = rssiValue === null ? 'RSSI: unavailable' : `RSSI: ${rssiValue} dBm`;
    lfsBox.textContent = lfsHealth === null ? 'LittleFS: unavailable' : `LittleFS: ${lfsHealth ? 'healthy' : 'degraded'}`;
    cpuTempBox.textContent = cpuTempValue === null ? 'CPU temp: unavailable' : `CPU temp: ${cpuTempValue.toFixed(1)}°C`;
  } catch (error) {
    lastContactBox.textContent = 'Heartbeat status unavailable.';
    rssiBox.textContent = 'RSSI: unavailable';
    lfsBox.textContent = 'LittleFS: unavailable';
    cpuTempBox.textContent = 'CPU temp: unavailable';
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
    throw new Error('Service workers are not supported in this browser.');
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
    throw new Error('The VAPID key is missing from the server response.');
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
    setStatus('Loading app configuration...');
    await loadConfig();

    setStatus('Registering service worker...');
    await registerServiceWorker();

    if (!('PushManager' in window)) {
      throw new Error('This browser does not support Web Push notifications.');
    }

    let permission = Notification.permission;
    if (permission === 'default') {
      setStatus('Requesting notification permission...');
      permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        throw new Error('Notification permission was not granted.');
      }
    }

    if (permission !== 'granted') {
      throw new Error('Notifications are blocked.');
    }

    const publicKey = await fetchPublicKey();
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    });

    const payload = buildSubscriptionYaml(subscription);
    subscriptionYaml.value = JSON.stringify(payload, null, 2);
    setStatus('Client subscription generated. Paste it into subscriptions.yaml.', 'success');
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
      throw new Error('Grant notification permission before sending a test message.');
    }

    const sender = (senderInput.value || '').trim();
    const response = await fetch('/send.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + sendToken,
      },
      body: JSON.stringify({
        title: 'Test notification',
        body: 'This is a Viking Bio test alert from the push PWA.',
        sender,
        priority: prioritySelect.value,
        url: uiUrl,
      }),
    });

    if (!response.ok) {
      throw new Error('The test notification could not be sent.');
    }

    const data = await response.json();
    setStatus(`Sent ${data.sent} message(s).`, 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

copyButton.addEventListener('click', async () => {
  if (!subscriptionYaml.value.trim()) {
    setStatus('Generate a client YAML snippet before copying it.', 'error');
    return;
  }

  await navigator.clipboard.writeText(subscriptionYaml.value);
  setStatus('Subscription YAML copied to clipboard.', 'success');
});

if (isIOS && !window.matchMedia('(display-mode: standalone)').matches) {
  installBanner.classList.remove('hidden');
}

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
    setStatus('Use the Share button in Safari, then choose “Add to Home Screen”.');
    return;
  }

  if (!installPromptEvent) {
    setStatus('The browser has not surfaced an install prompt yet.', 'error');
    return;
  }

  installPromptEvent.prompt();
  await installPromptEvent.userChoice;
  installBanner.classList.add('hidden');
});

enablePushButton.addEventListener('click', enableNotifications);
sendTestButton.addEventListener('click', sendTestAlert);
