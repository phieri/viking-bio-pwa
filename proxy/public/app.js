let pollTimer = null;
let seasonTimer = null;
let burnerPriceTimer = null;
let sw = null;
let sub = null;
const MS_PER_DAY = 86400000;
const POLL_INTERVAL_MS = 2000;
const SEASON_CHECK_INTERVAL_MS = 600000; // 10 minutes
const ENERGY_POLL_INTERVAL_MS = 300000;  // 5 minutes
const SEASON_START_MONTH = 10; // November (0-indexed)
const SEASON_END_MONTH = 3;   // April (0-indexed)
const MAX_SUBSCRIBER_LABEL_LENGTH = 48;
const ELLIPSIS_LENGTH = 3;
let wakeLockSentinel = null;

function getFullscreenElement() {
	return document.fullscreenElement ||
		document.webkitFullscreenElement ||
		document.mozFullScreenElement ||
		null;
}

function isFullscreenActive() {
	return !!getFullscreenElement();
}

async function requestFullscreen() {
	const el = document.documentElement;
	if (el.requestFullscreen) return el.requestFullscreen();
	if (el.webkitRequestFullscreen) return el.webkitRequestFullscreen();
	if (el.mozRequestFullScreen) return el.mozRequestFullScreen();
	throw new Error('Fullskärm stöds inte i den här webbläsaren.');
}

async function exitFullscreen() {
	if (document.exitFullscreen) return document.exitFullscreen();
	if (document.webkitExitFullscreen) return document.webkitExitFullscreen();
	if (document.mozCancelFullScreen) return document.mozCancelFullScreen();
	throw new Error('Det gick inte att lämna fullskärm.');
}

async function requestWakeLock() {
	if (!('wakeLock' in navigator) || wakeLockSentinel || !isFullscreenActive()) return;
	try {
		const wakeLock = await navigator.wakeLock.request('screen');
		wakeLockSentinel = wakeLock;
		wakeLock.addEventListener('release', () => {
			if (wakeLockSentinel === wakeLock) {
				wakeLockSentinel = null;
			}
		});
	} catch (error) {
		console.debug('Kunde inte aktivera wake lock', error);
	}
}

async function releaseWakeLock() {
	if (!wakeLockSentinel) return;
	const wakeLock = wakeLockSentinel;
	wakeLockSentinel = null;
	try {
		await wakeLock.release();
	} catch (error) {
		console.debug('Kunde inte släppa wake lock', error);
	}
}

function updateFullscreenButton() {
	const btn = document.getElementById('fullscreenBtn');
	if (!btn) return;
	const active = isFullscreenActive();
	btn.classList.toggle('is-fullscreen', active);
	btn.textContent = active ? 'Avsluta fullskärm' : 'Fullskärm';
	btn.setAttribute('aria-pressed', active ? 'true' : 'false');
	btn.setAttribute('aria-label', active ? 'Lämna fullskärm' : 'Gå till fullskärm');
}

async function handleFullscreenChange() {
	updateFullscreenButton();
	if (isFullscreenActive()) {
		await requestWakeLock();
	} else {
		await releaseWakeLock();
	}
}

async function toggleFullscreen() {
	try {
		if (isFullscreenActive()) {
			await exitFullscreen();
		} else {
			await requestFullscreen();
		}
	} catch (error) {
		console.error('Fullscreen toggle failed:', error);
		alert('Fullskärm stöds inte i den här webbläsaren.');
	}
}

function initFullscreenButton() {
	const btn = document.getElementById('fullscreenBtn');
	if (!btn) return;
	btn.addEventListener('click', (event) => {
		event.preventDefault();
		void toggleFullscreen();
	});
	updateFullscreenButton();
}

function updateSeasonCountdown(timestamp = Date.now()) {
	const today = new Date(timestamp);
	const todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());
	const countdownEl = document.getElementById('season-countdown');
	const targetEl = document.getElementById('season-target');
	let target;
	let label;
	let days;

	if (!countdownEl || !targetEl) return;

	if (todayStart < new Date(todayStart.getFullYear(), SEASON_END_MONTH, 1)) {
		target = new Date(todayStart.getFullYear(), SEASON_END_MONTH, 1);
		label = 'dagar till avstängning';
	} else if (todayStart < new Date(todayStart.getFullYear(), SEASON_START_MONTH, 1)) {
		target = new Date(todayStart.getFullYear(), SEASON_START_MONTH, 1);
		label = 'dagar till idrifttagning';
	} else {
		target = new Date(todayStart.getFullYear() + 1, SEASON_END_MONTH, 1);
		label = 'dagar till avstängning';
	}

	days = Math.floor((target - todayStart) / MS_PER_DAY);

	countdownEl.textContent = days;
	targetEl.textContent = label;
}

function formatSubscriberLabel(endpoint) {
	if (!endpoint) return 'Ingen aktiv prenumerant';
	try {
		const url = new URL(endpoint);
		const path = url.pathname === '/' ? '' : url.pathname;
		const label = `${url.hostname}${path}`;
		return label.length > MAX_SUBSCRIBER_LABEL_LENGTH ? `${label.slice(0, MAX_SUBSCRIBER_LABEL_LENGTH - ELLIPSIS_LENGTH)}…` : label;
	} catch {
		return endpoint.length > MAX_SUBSCRIBER_LABEL_LENGTH ? `${endpoint.slice(0, MAX_SUBSCRIBER_LABEL_LENGTH - ELLIPSIS_LENGTH)}…` : endpoint;
	}
}

function updateSubscriberSelect(data) {
	const select = document.getElementById('subscriberSelect');
	const btn = document.getElementById('testPushBtn');
	if (!select) return;

	const subscribers = Array.isArray(data?.subscribers) ? data.subscribers : [];
	const previousValue = select.value;
	select.innerHTML = '';
	if (!subscribers.length) {
		const opt = document.createElement('option');
		opt.value = '';
		opt.textContent = 'Ingen aktiv prenumerant';
		select.appendChild(opt);
		select.disabled = true;
		if (btn) btn.disabled = true;
		return;
	}

	select.disabled = false;
	const selected = subscribers.some((sub) => sub.endpoint === previousValue) ? previousValue : subscribers[0].endpoint;
	subscribers.forEach((sub) => {
		const opt = document.createElement('option');
		opt.value = sub.endpoint;
		opt.textContent = sub.label || formatSubscriberLabel(sub.endpoint);
		if (sub.endpoint === selected) {
			opt.selected = true;
		}
		select.appendChild(opt);
	});
	select.value = selected;
	if (btn) btn.disabled = false;
}

function pollSubscribers() {
	fetch('/api/subscribers')
		.then((r) => r.json())
		.then((s) => {
			if (typeof s.count !== 'undefined') {
				document.getElementById('subscribers').textContent = s.count;
			}
			updateSubscriberSelect(s);
		})
		.catch(() => {});
}

function fmtSEK(val) {
	return val.toLocaleString('sv-SE', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function updateBurnerPriceCard(data) {
	const card = document.getElementById('energy-price-card');
	if (!card) return;
	if (!data.enabled) {
		card.style.display = 'none';
		return;
	}

	card.style.display = '';
	document.getElementById('energy-price-value').textContent = fmtSEK(data.burner_sek_kwh);
	document.getElementById('energy-price-unit').textContent = 'kr/kWh';
	document.getElementById('energy-price-detail').textContent =
		`Pellets: ${fmtSEK(data.variable_sek_kwh)} | Fasta kostnader: ${fmtSEK(data.fixed_sek_kwh)} kr/kWh`;
}

function pollBurnerPrice() {
	fetch('/api/energy-price')
		.then((r) => r.json())
		.then(updateBurnerPriceCard)
		.catch(() => {});
}

function poll() {
	fetch('/api/data')
		.then((r) => r.json())
		.then((d) => {
			const flameEl = document.getElementById('flame');
			flameEl.textContent = d.flame ? '🔥' : 'AV';
			flameEl.setAttribute('aria-label', d.flame ? 'Låga på' : 'Låga av');
			document.getElementById('flame-card').className = `card ${d.flame ? 'flame-on' : 'flame-off'}`;
			document.getElementById('fan').textContent = d.fan;
			document.getElementById('temp').textContent = d.temp;
			document.getElementById('err').textContent = d.err;
			document.getElementById('flame-hours').textContent = (d.flame_secs / 3600).toLocaleString('sv-SE', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
			document.body.classList.toggle('error-active', d.err > 0);
			document.body.classList.toggle('blink-error', d.err > 0);

			pollSubscribers();

			if (d.err > 0) {
				setStatus(`Fel detekterat: kod ${d.err}`, 'error');
			} else if (!d.valid) {
				setStatus('Ingen data från pannan', 'stale');
			} else {
				setStatus('Live \u2014 senast uppdaterad: ' + new Date().toLocaleTimeString(), 'ok');
			}
		})
		.catch(() => {
			setStatus('Anslutning förlorad \u2014 försöker igen...', 'stale');
		});
}

function startPolling() {
	updateSeasonCountdown();
	poll();
	pollBurnerPrice();
	if (pollTimer) clearInterval(pollTimer);
	if (seasonTimer) clearInterval(seasonTimer);
	if (burnerPriceTimer) clearInterval(burnerPriceTimer);
	pollTimer = setInterval(poll, POLL_INTERVAL_MS);
	seasonTimer = setInterval(updateSeasonCountdown, SEASON_CHECK_INTERVAL_MS);
	burnerPriceTimer = setInterval(pollBurnerPrice, ENERGY_POLL_INTERVAL_MS);
}

function setStatus(msg, cls) {
	const el = document.getElementById('status');
	el.textContent = msg;
	el.className = `status ${cls}`;
}

function isAppleMobileDevice() {
	return /iPhone|iPad|iPod/.test(navigator.userAgent) ||
		(/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
}

function isStandalonePwa() {
	return window.matchMedia('(display-mode: standalone)').matches ||
		window.navigator.standalone === true;
}

function getPushAvailability() {
	if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
		return {
			canSubscribe: false,
			cls: 'unsupported',
			message: 'Push-aviseringar stöds inte i den här webbläsaren.'
		};
	}
	if (isAppleMobileDevice() && !isStandalonePwa()) {
		return {
			canSubscribe: false,
			cls: 'install',
			message: 'Push kan aktiveras först när sidan har installerats som app. På iPhone/iPad: öppna Dela och välj Lägg till på hemskärmen.'
		};
	}
	if (Notification.permission === 'denied') {
		return {
			canSubscribe: false,
			cls: 'blocked',
			message: 'Aviseringar är blockerade i webbläsaren. Tillåt aviseringar i inställningarna för att kunna prenumerera.'
		};
	}
	return {
		canSubscribe: true,
		cls: 'available',
		message: 'Push-prenumeration kan aktiveras på den här enheten.'
	};
}

function updatePushAvailability() {
	const el = document.getElementById('pushAvailability');
	const btn = document.getElementById('pushBtn');
	const { canSubscribe, cls, message } = getPushAvailability();
	if (el) {
		el.textContent = message;
		el.className = `push-availability ${cls}`;
	}
	if (btn) {
		btn.disabled = !canSubscribe;
		btn.title = btn.disabled ? message : '';
	}
}

async function subscribePush() {
	const availability = getPushAvailability();
	if (!availability.canSubscribe) {
		alert(availability.message);
		updatePushAvailability();
		return;
	}
	try {
		const r = await fetch('/api/vapid-public-key');
		const keyData = await r.json();
		sw = await navigator.serviceWorker.ready;
		const perm = await Notification.requestPermission();
		if (perm !== 'granted') {
			alert('Aviseringstillstånd nekades.');
			return;
		}
		sub = await sw.pushManager.subscribe({
			userVisibleOnly: true,
			applicationServerKey: urlBase64ToUint8Array(keyData.key)
		});
		await sendSubscription();
		updatePushUI(true);
		updatePushSource();
	} catch (e) {
		console.error('Push subscription failed:', e);
		alert('Push-prenumeration misslyckades: ' + e.message);
	}
}

async function unsubscribePush() {
	if (!sub) return;
	const ep = sub.endpoint;
	try {
		await sub.unsubscribe();
	} catch (e) {
		console.error('Unsubscribe failed:', e);
	}
	sub = null;
	await fetch('/api/unsubscribe', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ endpoint: ep })
	});
	updatePushUI(false);
	updatePushSource();
}

async function sendSubscription() {
	if (!sub) return;
	const subJson = sub.toJSON();
	const body = {
		endpoint: subJson.endpoint || '',
		p256dh: subJson.keys?.p256dh ?? '',
		auth: subJson.keys?.auth ?? '',
		prefs: {
			flame: !!document.getElementById('flameSub')?.checked,
			error: !!document.getElementById('errorSub')?.checked,
			clean: !!document.getElementById('cleanSub')?.checked
		}
	};
	await fetch('/api/subscribe', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
}

async function updateSubscription() {
	if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
		alert('Push-aviseringar stöds inte i den här webbläsaren.');
		return;
	}
	if (!sub) {
		await subscribePush();
		return;
	}
	try {
		await sendSubscription();
		document.getElementById('pushBtn').textContent = 'Inställningar uppdaterade';
		setTimeout(() => {
			document.getElementById('pushBtn').textContent = 'Uppdatera inställningar';
		}, 1500);
	} catch (e) {
		console.error('Updating subscription failed:', e);
		alert('Uppdatering av prenumeration misslyckades: ' + e.message);
	}
}

async function sendTestPush() {
	const select = document.getElementById('subscriberSelect');
	const priorityEl = document.getElementById('testPushPriority');
	const endpoint = select?.value;
	const priority = priorityEl?.value || 'normal';
	if (!endpoint) {
		setStatus('Inga aktiva prenumeranter att testa.', 'stale');
		return;
	}
	try {
		const resp = await fetch('/api/test-push', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ endpoint, priority })
		});
		const data = await resp.json().catch(() => ({}));
		if (!resp.ok) {
			throw new Error(data.error || 'Kunde inte skicka testaviseringen');
		}
		const label = select.selectedOptions[0]?.textContent || endpoint;
		setStatus(`Testavisering skickad till ${label} (${priority})`, 'ok');
	} catch (e) {
		console.error('Sending test push failed:', e);
		setStatus('Testavisering misslyckades: ' + e.message, 'error');
	}
}

function updatePushUI(subscribed) {
	const btn = document.getElementById('pushBtn');
	const unsub = document.getElementById('unsubBtn');
	if (subscribed) {
		btn.textContent = 'Uppdatera inställningar';
		btn.className = 'btn btn-push subscribed';
		unsub.style.display = 'inline-block';
	} else {
		btn.textContent = 'Aktivera aviseringar';
		btn.className = 'btn btn-push';
		unsub.style.display = 'none';
	}
	updatePushAvailability();
}

async function updatePushSource() {
	const el = document.getElementById('pushSource');
	if (!el) return;
	try {
		const r = await fetch('/api/vapid-public-key');
		const data = await r.json();
		let msg;
		if (data.source === 'pico') {
			msg = 'Push: hanteras av enhet (Pico)';
		} else if (data.source === 'proxy') {
			msg = 'Push: hanteras av denna proxy';
		} else if (data.source === 'demo') {
			msg = 'Push: demoläge \u2014 push kräver Pico';
		} else {
			msg = 'Push: okänd';
		}
		el.textContent = msg;
	} catch (e) {
		el.textContent = '';
	}
}

function urlBase64ToUint8Array(b64) {
	const p = b64.replace(/-/g, '+').replace(/_/g, '/');
	const paddingLength = (4 - (p.length % 4)) % 4;
	const padded = p.padEnd(p.length + paddingLength, '=');
	const r = atob(padded);
	return Uint8Array.from(r, (char) => char.charCodeAt(0));
}

if ('serviceWorker' in navigator) {
	navigator.serviceWorker.register('sw.js')
		.then((r) => r.pushManager.getSubscription())
		.then((s) => {
			if (s) {
				sub = s;
				updatePushUI(true);
			}
		});
}

initFullscreenButton();
document.addEventListener('fullscreenchange', () => {
	void handleFullscreenChange();
});
document.addEventListener('webkitfullscreenchange', () => {
	void handleFullscreenChange();
});
document.addEventListener('mozfullscreenchange', () => {
	void handleFullscreenChange();
});
document.addEventListener('visibilitychange', () => {
	if (document.visibilityState === 'visible' && isFullscreenActive()) {
		void requestWakeLock();
	}
});

updatePushAvailability();
startPolling();

window.addEventListener('load', () => {
	updatePushAvailability();
	updatePushSource();
});

window.addEventListener('focus', updatePushAvailability);
window.matchMedia('(display-mode: standalone)').addEventListener('change', updatePushAvailability);
