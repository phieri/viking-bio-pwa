/**
 * uptime-client.js
 *
 * Lightweight PWA module for collecting device uptime buckets and POSTing
 * them to the proxy with local buffering, retry, and exponential back-off.
 *
 * Data contract (proxy POST /api/v1/uptime/buckets):
 *
 *   Bucket batch:
 *   {
 *     device_id:   string,
 *     source:      "pwa",
 *     batch_id:    string  (UUID, for idempotency),
 *     buckets: [
 *       {
 *         bucket_id:        string  (UUID),
 *         start:            ISO8601,
 *         duration_seconds: number,
 *         seconds_on:       number
 *       }
 *     ]
 *   }
 *
 *   Daily summary:
 *   {
 *     device_id:    string,
 *     source:       "pwa",
 *     date:         "YYYY-MM-DD",
 *     seconds_on:   number,
 *     sample_count: number,
 *     summary_id:   string  (UUID, for idempotency)
 *   }
 *
 * Local storage layout (localStorage keys):
 *   uptime:<deviceId>:pending   – JSON array of unsent Bucket objects
 *   uptime:<deviceId>:sent      – JSON array of acknowledged batch_ids
 *
 * Usage:
 *   const client = new UptimeClient({
 *     deviceId: 'my-pwa-device',
 *     endpoint: '/api/v1/uptime/buckets',
 *     authToken: 'optional-bearer-token',
 *   });
 *
 *   // Record that the burner was on for 5 minutes within a 10-minute window
 *   client.addBucket({ durationSeconds: 600, secondsOn: 300 });
 *
 *   // Flush pending buckets to the server (call periodically or on visibility change)
 *   await client.flush();
 */

'use strict';

const STORAGE_PREFIX = 'uptime';
const MAX_BUCKETS_PER_BATCH = 50;
const MAX_RETRIES = 6;
const BASE_DELAY_MS = 1000;

/**
 * Generates a version-4 UUID using the Web Crypto API when available,
 * falling back to a Math.random-based implementation.
 * @returns {string}
 */
function uuid() {
	if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
		return crypto.randomUUID();
	}
	// Fallback for older environments
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
		const r = (Math.random() * 16) | 0;
		const v = c === 'x' ? r : (r & 0x3) | 0x8;
		return v.toString(16);
	});
}

/**
 * Returns the current UTC date as a "YYYY-MM-DD" string.
 * @returns {string}
 */
function todayUTC() {
	return new Date().toISOString().slice(0, 10);
}

/**
 * Sleeps for ms milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

class UptimeClient {
	/**
	 * @param {object} opts
	 * @param {string} opts.deviceId          Unique identifier for this device/browser.
	 * @param {string} [opts.endpoint]        POST endpoint (default: '/api/v1/uptime/buckets').
	 * @param {string} [opts.authToken]       Bearer token for Authorization header.
	 * @param {number} [opts.maxRetries]      Maximum retry attempts per flush (default: 6).
	 * @param {number} [opts.baseDelayMs]     Initial back-off delay in ms (default: 1000).
	 */
	constructor(opts = {}) {
		if (!opts.deviceId) {
			throw new Error('UptimeClient: deviceId is required');
		}
		this._deviceId = opts.deviceId;
		this._endpoint = opts.endpoint || '/api/v1/uptime/buckets';
		this._authToken = opts.authToken || '';
		this._maxRetries = typeof opts.maxRetries === 'number' ? opts.maxRetries : MAX_RETRIES;
		this._baseDelayMs = typeof opts.baseDelayMs === 'number' ? opts.baseDelayMs : BASE_DELAY_MS;
		this._pendingKey = `${STORAGE_PREFIX}:${this._deviceId}:pending`;
		// Promise chain used to serialise concurrent flush() calls.
		this._flushChain = Promise.resolve({ sent: 0, failed: 0 });
	}

	/**
	 * Returns the array of pending (unsent) buckets from localStorage.
	 * @returns {object[]}
	 */
	_loadPending() {
		try {
			return JSON.parse(localStorage.getItem(this._pendingKey) || '[]');
		} catch (_) {
			return [];
		}
	}

	/**
	 * Persists the pending bucket array to localStorage.
	 * @param {object[]} buckets
	 */
	_savePending(buckets) {
		localStorage.setItem(this._pendingKey, JSON.stringify(buckets));
	}

	/**
	 * Records a new uptime bucket in local storage.
	 *
	 * @param {object} opts
	 * @param {number}  opts.durationSeconds  Total window length in seconds.
	 * @param {number}  opts.secondsOn        Burner-on time within the window.
	 * @param {string}  [opts.start]          ISO8601 window start; defaults to now.
	 * @param {string}  [opts.bucketId]       Optional caller-supplied dedup ID; auto-generated if absent.
	 */
	addBucket({ durationSeconds, secondsOn, start, bucketId } = {}) {
		if (typeof durationSeconds !== 'number' || typeof secondsOn !== 'number') {
			throw new Error('UptimeClient.addBucket: durationSeconds and secondsOn are required numbers');
		}
		const bucket = {
			bucket_id:        bucketId || uuid(),
			start:            start || new Date().toISOString(),
			duration_seconds: durationSeconds,
			seconds_on:       secondsOn,
		};
		const pending = this._loadPending();
		pending.push(bucket);
		this._savePending(pending);
		return bucket;
	}

	/**
	 * Sends a single HTTP POST with retry + exponential back-off.
	 *
	 * @param {object} payload
	 * @returns {Promise<Response>}
	 */
	async _post(payload) {
		const headers = { 'Content-Type': 'application/json' };
		if (this._authToken) {
			headers['Authorization'] = `Bearer ${this._authToken}`;
		}
		let delay = this._baseDelayMs;
		let lastErr;
		for (let attempt = 0; attempt <= this._maxRetries; attempt++) {
			if (attempt > 0) {
				await sleep(delay);
				delay = Math.min(delay * 2, 60000); // cap at 60 s
			}
			try {
				const res = await fetch(this._endpoint, {
					method: 'POST',
					headers,
					body: JSON.stringify(payload),
				});
				if (res.ok) {
					return res;
				}
				// 4xx errors are not retried (client error, not transient)
				if (res.status >= 400 && res.status < 500) {
					throw new Error(`UptimeClient: server returned ${res.status} – not retrying`);
				}
				lastErr = new Error(`UptimeClient: server returned ${res.status}`);
			} catch (err) {
				lastErr = err;
				if (err.message && err.message.includes('not retrying')) {
					throw err;
				}
			}
		}
		throw lastErr || new Error('UptimeClient: flush failed after max retries');
	}

	/**
	 * Flushes all pending buckets to the server.
	 * Buckets are sent in batches of up to MAX_BUCKETS_PER_BATCH.
	 * On success, the buckets are removed from local storage.
	 * Concurrent flush() calls are queued and executed one after another,
	 * so every caller receives the correct result for its turn.
	 *
	 * @returns {Promise<{ sent: number, failed: number }>}
	 */
	flush() {
		// Chain onto the existing flush promise so concurrent calls are serialised.
		this._flushChain = this._flushChain.then(() => this._doFlush(), () => this._doFlush());
		return this._flushChain;
	}

	/** @private */
	async _doFlush() {
		let sent = 0;
		let failed = 0;
		const pending = this._loadPending();
		if (pending.length === 0) {
			return { sent: 0, failed: 0 };
		}

		// Process in batches
		for (let i = 0; i < pending.length; i += MAX_BUCKETS_PER_BATCH) {
			const slice = pending.slice(i, i + MAX_BUCKETS_PER_BATCH);
			const batchId = uuid();
			const payload = {
				device_id: this._deviceId,
				source:    'pwa',
				batch_id:  batchId,
				buckets:   slice,
			};
			try {
				const res = await this._post(payload);
				const json = await res.json().catch(() => ({}));
				const accepted = typeof json.accepted === 'number' ? json.accepted : slice.length;
				sent += accepted;
				// Remove successfully sent buckets from pending storage
				const remaining = this._loadPending().filter(
					(b) => !slice.some((s) => s.bucket_id === b.bucket_id)
				);
				this._savePending(remaining);
			} catch (err) {
				console.warn('UptimeClient: batch send failed:', err);
				failed += slice.length;
			}
		}
		return { sent, failed };
	}

	/**
	 * Submits a pre-aggregated daily summary directly (no local buffering).
	 *
	 * @param {object} opts
	 * @param {string}  [opts.date]           "YYYY-MM-DD" (defaults to today UTC).
	 * @param {number}  opts.secondsOn        Total burner-on seconds for the day.
	 * @param {number}  [opts.sampleCount]    Number of samples aggregated.
	 * @param {string}  [opts.summaryId]      Idempotency key; auto-generated if absent.
	 * @returns {Promise<Response>}
	 */
	async submitDailySummary({ date, secondsOn, sampleCount, summaryId } = {}) {
		if (typeof secondsOn !== 'number') {
			throw new Error('UptimeClient.submitDailySummary: secondsOn is required');
		}
		const payload = {
			device_id:    this._deviceId,
			source:       'pwa',
			date:         date || todayUTC(),
			seconds_on:   secondsOn,
			sample_count: sampleCount || 0,
			summary_id:   summaryId || uuid(),
		};
		return this._post(payload);
	}

	/**
	 * Returns the number of locally buffered (unsent) buckets.
	 * @returns {number}
	 */
	get pendingCount() {
		return this._loadPending().length;
	}

	/**
	 * Clears all locally buffered buckets without sending them.
	 */
	clearPending() {
		localStorage.removeItem(this._pendingKey);
	}
}

// Expose as ES module export when bundled, or as a global for plain <script> use.
if (typeof module !== 'undefined' && module.exports) {
	module.exports = { UptimeClient };
} else if (typeof window !== 'undefined') {
	window.UptimeClient = UptimeClient;
}
