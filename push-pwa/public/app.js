let uiUrl = 'http://localhost:8000';
let sendToken = '';
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || ((window.navigator.userAgentData && window.navigator.userAgentData.platform === 'macOS') && navigator.maxTouchPoints > 1) || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
const installBanner = document.getElementById('install-banner');
const installButton = document.getElementById('install-button');
const enablePushButton = document.getElementById('enable-push');
const sendTestButton = document.getElementById('send-test');
const copyButton = document.getElementById('copy-yaml');
const prioritySelect = document.getElementById('subscription-priority');
const senderInput = document.getElementById('subscription-sender');
const subscriptionYaml = document.getElementById('subscription-yaml');
const statusBox = document.getElementById('status');
let installPromptEvent = null;

function setStatus(message, type = '') {
  statusBox.textContent = message;
  statusBox.className = `status ${type}`.trim();
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

function buildSubscriptionYaml(subscription) {
  const keys = subscription.toJSON ? subscription.toJSON().keys : subscription.keys || {};
  const sender = (senderInput.value || '').trim();
  return {
    endpoint: subscription.endpoint,
    keys: {
      p256dh: keys.p256dh || '',
      auth: keys.auth || '',
    },
    sender,
    priority: prioritySelect.value,
    uiUrl,
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
