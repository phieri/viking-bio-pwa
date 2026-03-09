var pollTimer = null;
var seasonTimer = null;
var sw = null;
var sub = null;
var MS_PER_DAY = 86400000;

function updateSeasonCountdown(timestamp) {
	var today = new Date(timestamp || Date.now());
	var todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());
	var countdownEl = document.getElementById('season-countdown');
	var targetEl = document.getElementById('season-target');
	var target;
	var label;
	var days;

	if (!countdownEl || !targetEl) return;

	if (todayStart < new Date(todayStart.getFullYear(), 3, 1)) {
		target = new Date(todayStart.getFullYear(), 3, 1);
		label = 'days until 1 Apr (turn off)';
	} else if (todayStart < new Date(todayStart.getFullYear(), 10, 1)) {
		target = new Date(todayStart.getFullYear(), 10, 1);
		label = 'days until 1 Nov (turn on)';
	} else {
		target = new Date(todayStart.getFullYear() + 1, 3, 1);
		label = 'days until 1 Apr (turn off)';
	}

	days = Math.floor((target - todayStart) / MS_PER_DAY);

	countdownEl.textContent = days;
	targetEl.textContent = label;
}

function poll() {
	fetch('/api/data')
		.then(function(r) { return r.json(); })
		.then(function(d) {
			document.getElementById('flame').textContent = d.flame ? 'ON' : 'OFF';
			document.getElementById('flame-card').className = 'card ' + (d.flame ? 'flame-on' : 'flame-off');
			document.getElementById('fan').textContent = d.fan;
			document.getElementById('temp').textContent = d.temp;
			document.getElementById('err').textContent = d.err;
			document.getElementById('flame-hours').textContent = (d.flame_secs / 3600).toFixed(1);

			fetch('/api/subscribers')
				.then(function(r) { return r.json(); })
				.then(function(s) {
					if (typeof s.count !== 'undefined') {
						document.getElementById('subscribers').textContent = s.count;
					}
				})
				.catch(function() {});

			if (d.err > 0) {
				setStatus('Error detected: code ' + d.err, 'error');
			} else if (!d.valid) {
				setStatus('No data from burner', 'stale');
			} else {
				setStatus('Live \u2014 last update: ' + new Date().toLocaleTimeString(), 'ok');
			}
		})
		.catch(function() {
			setStatus('Connection lost \u2014 retrying...', 'stale');
		});
}

function startPolling() {
	updateSeasonCountdown();
	poll();
	if (pollTimer) clearInterval(pollTimer);
	if (seasonTimer) clearInterval(seasonTimer);
	pollTimer = setInterval(poll, 2000);
	seasonTimer = setInterval(updateSeasonCountdown, 60000);
}

function setStatus(msg, cls) {
	var el = document.getElementById('status');
	el.textContent = msg;
	el.className = 'status ' + cls;
}

async function subscribePush() {
	if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
		alert('Push notifications not supported in this browser.');
		return;
	}
	try {
		var r = await fetch('/api/vapid-public-key');
		var keyData = await r.json();
		sw = await navigator.serviceWorker.ready;
		var perm = await Notification.requestPermission();
		if (perm !== 'granted') {
			alert('Notification permission denied.');
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
		alert('Push subscription failed: ' + e.message);
	}
}

async function unsubscribePush() {
	if (!sub) return;
	var ep = sub.endpoint;
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
	var subJson = sub.toJSON();
	var body = {
		endpoint: subJson.endpoint || '',
		p256dh: (subJson.keys && subJson.keys.p256dh) ? subJson.keys.p256dh : '',
		auth: (subJson.keys && subJson.keys.auth) ? subJson.keys.auth : '',
		prefs: {
			flame: !!document.getElementById('flameSub').checked,
			error: !!document.getElementById('errorSub').checked,
			clean: !!document.getElementById('cleanSub').checked
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
		alert('Push notifications not supported in this browser.');
		return;
	}
	if (!sub) {
		await subscribePush();
		return;
	}
	try {
		await sendSubscription();
		document.getElementById('pushBtn').textContent = 'Preferences Updated';
		setTimeout(function() {
			document.getElementById('pushBtn').textContent = 'Update Preferences';
		}, 1500);
	} catch (e) {
		console.error('Updating subscription failed:', e);
		alert('Updating subscription failed: ' + e.message);
	}
}

function updatePushUI(subscribed) {
	var btn = document.getElementById('pushBtn');
	var unsub = document.getElementById('unsubBtn');
	if (subscribed) {
		btn.textContent = 'Update Preferences';
		btn.className = 'btn btn-push subscribed';
		unsub.style.display = 'inline-block';
	} else {
		btn.textContent = 'Enable Notifications';
		btn.className = 'btn btn-push';
		unsub.style.display = 'none';
	}
}

async function updatePushSource() {
	var el = document.getElementById('pushSource');
	if (!el) return;
	try {
		var r = await fetch('/api/vapid-public-key');
		var data = await r.json();
		var msg;
		if (data.source === 'pico') {
			msg = 'Push: handled by device (Pico)';
		} else if (data.source === 'proxy') {
			msg = 'Push: handled by this proxy';
		} else if (data.source === 'demo') {
			msg = 'Push: demo mode \u2014 push requires Pico';
		} else {
			msg = 'Push: unknown';
		}
		el.textContent = msg;
	} catch (e) {
		el.textContent = '';
	}
}

function urlBase64ToUint8Array(b64) {
	var p = b64.replace(/-/g, '+').replace(/_/g, '/');
	while (p.length % 4) p += '=';
	var r = atob(p);
	var o = new Uint8Array(r.length);
	for (var i = 0; i < r.length; ++i) o[i] = r.charCodeAt(i);
	return o;
}

if ('serviceWorker' in navigator) {
	navigator.serviceWorker.register('/sw.js')
		.then(function(r) {
			return r.pushManager.getSubscription();
		})
		.then(function(s) {
			if (s) {
				sub = s;
				updatePushUI(true);
			}
		});
}

startPolling();

window.addEventListener('load', function () {
	updatePushSource();
});
