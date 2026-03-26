'use strict';

/**
 * Let's Encrypt certificate manager.
 *
 * Obtains and auto-renews a TLS certificate for a given domain using the
 * ACME protocol (RFC 8555) with HTTP-01 challenge validation.  Certificates
 * are issued by Let's Encrypt (https://letsencrypt.org/) via the acme-client
 * npm package.
 *
 * Startup flow
 * ------------
 * 1. A minimal HTTP challenge server is started on ACME_HTTP_PORT (default 80).
 *    Let's Encrypt's validation agent must be able to reach this port from the
 *    internet; use iptables or authbind if the process does not run as root.
 * 2. The stored certificate (proxy/data/server.crt) is checked.  If it is
 *    absent or will expire within RENEW_BEFORE_DAYS days a new certificate is
 *    obtained (or renewed) automatically.
 * 3. A daily timer checks for upcoming expiry and renews proactively.
 * 4. An optional onRenew(certPath, keyPath) callback is invoked after every
 *    successful renewal so the HTTPS server can reload the certificate without
 *    restarting.
 *
 * Certificate storage
 * -------------------
 *   proxy/data/server.crt       – PEM certificate chain
 *   proxy/data/server.key       – PEM private key  (mode 0o600)
 *   proxy/data/acme-account.key – ACME account key (mode 0o600)
 *
 * Environment variables
 * ---------------------
 *   ACME_EMAIL      – contact e-mail for the Let's Encrypt account (recommended)
 *   ACME_STAGING    – set to "1" to use the staging environment (testing)
 *   ACME_CERT_DIR   – certificate storage directory (default: proxy/data)
 *   ACME_HTTP_PORT  – port for the HTTP-01 challenge server (default: 80)
 */

const acme   = require('acme-client');
const fs     = require('fs');
const http   = require('http');
const path   = require('path');
const crypto = require('crypto');

const DATA_DIR          = path.join(__dirname, '..', 'data');
const RENEW_BEFORE_DAYS = 30;
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

function parsePort(value, fallback, envName) {
	const raw = String(value ?? fallback).trim();
	if (!/^\d+$/.test(raw)) {
		throw new Error(`${envName} must be an integer between 1 and 65535 (got: ${raw})`);
	}
	const port = parseInt(raw, 10);
	if (port < 1 || port > 65535) {
		throw new Error(`${envName} must be an integer between 1 and 65535 (got: ${raw})`);
	}
	return port;
}

/**
 * Create a Let's Encrypt certificate manager.
 *
 * @param {object} [opts]
 * @param {string}   [opts.domain]         – FQDN to obtain a certificate for
 * @param {string}   [opts.email]          – contact e-mail (overrides env)
 * @param {boolean}  [opts.staging]        – use LE staging (overrides env)
 * @param {string}   [opts.certDir]        – certificate storage dir (overrides env)
 * @param {number}   [opts.challengePort]  – HTTP-01 challenge port (overrides env)
 * @returns {{ certPath, keyPath, onRenew, initialize, stop }}
 */
function createCertManager(opts = {}) {
	const domain        = opts.domain || '';
	const email         = opts.email         || process.env.ACME_EMAIL    || '';
	const staging       = opts.staging       !== undefined
		? !!opts.staging
		: (process.env.ACME_STAGING === '1' || process.env.ACME_STAGING === 'true');
	const certDir       = opts.certDir       || process.env.ACME_CERT_DIR || DATA_DIR;
	const challengePort = parsePort(opts.challengePort ?? process.env.ACME_HTTP_PORT, 80,
		'ACME_HTTP_PORT');

	const certPath       = path.join(certDir, 'server.crt');
	const keyPath        = path.join(certDir, 'server.key');
	const accountKeyPath = path.join(certDir, 'acme-account.key');

	// Active HTTP-01 challenge tokens: token → key-authorisation string
	const challenges     = new Map();
	let   challengeServer = null;
	let   renewTimer      = null;

	/** Callback invoked after every successful renewal. */
	let onRenew = null;

	// -----------------------------------------------------------------------
	// No-op manager when no domain is configured
	// -----------------------------------------------------------------------
	if (!domain) {
		return {
			certPath:  null,
			keyPath:   null,
			set onRenew(_fn) {},
			async initialize() { return false; },
			stop() {},
		};
	}

	// -----------------------------------------------------------------------
	// Internal helpers
	// -----------------------------------------------------------------------

	/** Load the persisted ACME account private key, or generate a new one. */
	async function loadOrCreateAccountKey() {
		try {
			return fs.readFileSync(accountKeyPath);
		} catch {
			const key = await acme.crypto.createPrivateKey();
			fs.mkdirSync(certDir, { recursive: true, mode: 0o700 });
			fs.writeFileSync(accountKeyPath, key, { mode: 0o600 });
			return key;
		}
	}

	/**
	 * Return true when the stored certificate is absent or expires within
	 * RENEW_BEFORE_DAYS days.
	 */
	function needsRenewal() {
		try {
			const pem   = fs.readFileSync(certPath, 'utf8');
			const x509  = new crypto.X509Certificate(pem);
			const expiry = new Date(x509.validTo);
			const nowMs  = Date.now();
			const remaining = expiry.getTime() - nowMs;
			return remaining < RENEW_BEFORE_DAYS * 24 * 60 * 60 * 1000;
		} catch {
			return true; // missing or unreadable → must obtain
		}
	}

	/**
	 * Start a minimal HTTP server that serves ACME HTTP-01 challenge responses
	 * at GET /.well-known/acme-challenge/<token>.
	 */
	function startChallengeServer() {
		return new Promise((resolve, reject) => {
			challengeServer = http.createServer((req, res) => {
				const prefix = '/.well-known/acme-challenge/';
				if (req.method === 'GET' && req.url && req.url.startsWith(prefix)) {
					const token   = req.url.slice(prefix.length).split('?')[0];
					const keyAuth = challenges.get(token);
					if (keyAuth) {
						res.writeHead(200, { 'Content-Type': 'text/plain' });
						res.end(keyAuth);
						return;
					}
				}
				res.writeHead(404, { 'Content-Type': 'text/plain' });
				res.end('not found');
			});

			challengeServer.once('error', reject);
			challengeServer.listen(challengePort, '::', () => {
				console.log(`cert-manager: HTTP-01 challenge server listening on port ${challengePort}`);
				resolve();
			});
		});
	}

	/** Obtain (or renew) the certificate using Let's Encrypt. */
	async function obtainCertificate() {
		console.log(
			`cert-manager: obtaining certificate for ${domain}`
			+ ` (staging=${staging}, email=${email || 'none'})`
		);

		const accountKey    = await loadOrCreateAccountKey();
		const directoryUrl  = staging
			? acme.directory.letsencrypt.staging
			: acme.directory.letsencrypt.production;

		const client = new acme.Client({ directoryUrl, accountKey });

		await client.createAccount({
			termsOfServiceAgreed: true,
			contact: email ? [`mailto:${email}`] : [],
		});

		const [domainKey, csr] = await acme.crypto.createCsr({ commonName: domain });

		const cert = await client.auto({
			csr,
			email:                email || undefined,
			termsOfServiceAgreed: true,
			challengePriority:    ['http-01'],
			challengeCreateFn: async (_authz, challenge, keyAuthorization) => {
				challenges.set(challenge.token, keyAuthorization);
			},
			challengeRemoveFn: async (_authz, challenge) => {
				challenges.delete(challenge.token);
			},
		});

		fs.mkdirSync(certDir, { recursive: true, mode: 0o700 });
		fs.writeFileSync(keyPath,  domainKey, { mode: 0o600 });
		fs.writeFileSync(certPath, cert);
		console.log(`cert-manager: certificate saved to ${certDir}`);
	}

	/** Check expiry and renew if needed; fire onRenew callback on success. */
	async function checkAndRenew() {
		if (!needsRenewal()) return;
		try {
			await obtainCertificate();
			if (typeof onRenew === 'function') {
				onRenew(certPath, keyPath);
			}
		} catch (err) {
			console.error(`cert-manager: renewal failed: ${err.message}`);
		}
	}

	// -----------------------------------------------------------------------
	// Public API
	// -----------------------------------------------------------------------
	return {
		/** Path to the PEM certificate file. */
		certPath,

		/** Path to the PEM private key file. */
		keyPath,

		/**
		 * Optional callback invoked after every successful certificate renewal.
		 * Signature: (certPath: string, keyPath: string) => void
		 */
		set onRenew(fn) { onRenew = fn; },

		/**
		 * Start the HTTP-01 challenge server, obtain a certificate if needed,
		 * and schedule daily renewal checks.
		 *
		 * @returns {Promise<boolean>} true when a valid certificate is ready
		 */
		async initialize() {
			try {
				await startChallengeServer();
			} catch (err) {
				console.error(
					`cert-manager: cannot start challenge server on port ${challengePort}: ${err.message}`
				);
				console.error(
					'cert-manager: ensure the process can bind that port, '
					+ 'or set ACME_HTTP_PORT to an unprivileged port and forward '
					+ 'port 80 with iptables/authbind'
				);
				return false;
			}

			await checkAndRenew();

			if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
				console.error('cert-manager: certificate not available after initialization');
				return false;
			}

			// Schedule daily renewal checks
			renewTimer = setInterval(checkAndRenew, CHECK_INTERVAL_MS);
			return true;
		},

		/**
		 * Stop the challenge server and cancel the renewal timer.
		 */
		stop() {
			if (renewTimer !== null) {
				clearInterval(renewTimer);
				renewTimer = null;
			}
			if (challengeServer !== null) {
				challengeServer.close();
				challengeServer = null;
			}
		},
	};
}

module.exports = { createCertManager };
