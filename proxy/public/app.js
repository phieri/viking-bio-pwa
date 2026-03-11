let pollTimer = null;
let seasonTimer = null;
let sw = null;
let sub = null;
const MS_PER_DAY = 86400000;

function updateSeasonCountdown(timestamp = Date.now()) {
	const today = new Date(timestamp);
	const todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());
	const countdownEl = document.getElementById('season-countdown');
	const targetEl = document.getElementById('season-target');
	let target;
	let label;
	let days;

	if (!countdownEl || !targetEl) return;

	if (todayStart < new Date(todayStart.getFullYear(), 3, 1)) {
		target = new Date(todayStart.getFullYear(), 3, 1);
		label = 'dagar till avstängning';
	} else if (todayStart < new Date(todayStart.getFullYear(), 10, 1)) {
		target = new Date(todayStart.getFullYear(), 10, 1);
		label = 'dagar till idrifttagning';
	} else {
		target = new Date(todayStart.getFullYear() + 1, 3, 1);
		label = 'dagar till avstängning';
	}

	days = Math.floor((target - todayStart) / MS_PER_DAY);

	countdownEl.textContent = days;
	targetEl.textContent = label;
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

			fetch('/api/subscribers')
				.then((r) => r.json())
				.then((s) => {
					if (typeof s.count !== 'undefined') {
						document.getElementById('subscribers').textContent = s.count;
					}
				})
				.catch(() => {});

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
	if (pollTimer) clearInterval(pollTimer);
	if (seasonTimer) clearInterval(seasonTimer);
	pollTimer = setInterval(poll, 2000);
	seasonTimer = setInterval(updateSeasonCountdown, 600000);
}

function setStatus(msg, cls) {
	const el = document.getElementById('status');
	el.textContent = msg;
	el.className = `status ${cls}`;
}

async function subscribePush() {
	if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
		alert('Push-aviseringar stöds inte i den här webbläsaren.');
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
	navigator.serviceWorker.register('/sw.js')
		.then((r) => r.pushManager.getSubscription())
		.then((s) => {
			if (s) {
				sub = s;
				updatePushUI(true);
			}
		});
}

startPolling();

window.addEventListener('load', () => {
	updatePushSource();
});
