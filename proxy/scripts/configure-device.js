#!/usr/bin/env node
'use strict';

/**
 * configure-device.js
 *
 * Interactive TUI for configuring the Viking Bio Pico W bridge over USB serial.
 *
 * Usage:
 *   node proxy/scripts/configure-device.js [port]
 *   npm run configure  (from the proxy/ directory)
 *
 * Examples:
 *   node proxy/scripts/configure-device.js            # auto-detect port
 *   node proxy/scripts/configure-device.js /dev/ttyACM0
 *   node proxy/scripts/configure-device.js COM3       # Windows
 *
 * The Pico W must be connected via USB and running the viking_bio_bridge
 * firmware. The USB serial port appears as:
 *   Linux:   /dev/ttyACM0  (or ttyACM1, ttyACM2, ...)
 *   macOS:   /dev/cu.usbmodem<id>
 *   Windows: COM3 (or COM4, ...)
 */

const readline = require('readline');

// ---------------------------------------------------------------------------
// Graceful require of serialport (optional dependency)
// ---------------------------------------------------------------------------
let createSerialBridge, listPorts;
try {
	({ createSerialBridge, listPorts } = require('../src/serial-bridge'));
} catch (err) {
	console.error(
		'\nError: the serialport package is not available.\n' +
		'Install it by running:\n\n  npm install\n\n' +
		`(original error: ${err.message})\n`
	);
	process.exit(1);
}

// ---------------------------------------------------------------------------
// ANSI helpers
// ---------------------------------------------------------------------------
const isTTY = process.stdout.isTTY;

const A = {
	reset:  isTTY ? '\x1b[0m'  : '',
	bold:   isTTY ? '\x1b[1m'  : '',
	dim:    isTTY ? '\x1b[2m'  : '',
	red:    isTTY ? '\x1b[31m' : '',
	green:  isTTY ? '\x1b[32m' : '',
	yellow: isTTY ? '\x1b[33m' : '',
	cyan:   isTTY ? '\x1b[36m' : '',
};

function styled(color, text) { return `${A[color]}${text}${A.reset}`; }
function bold(text)   { return `${A.bold}${text}${A.reset}`; }
function dim(text)    { return `${A.dim}${text}${A.reset}`; }
function red(text)    { return styled('red', text); }
function green(text)  { return styled('green', text); }
function yellow(text) { return styled('yellow', text); }
function cyan(text)   { return styled('cyan', text); }

// ---------------------------------------------------------------------------
// readline helpers
// ---------------------------------------------------------------------------
let rl = null;

function createRl() {
	if (rl) rl.close();
	rl = readline.createInterface({ input: process.stdin, output: process.stdout });
}

/** Prompt the user and return the trimmed answer. */
function ask(question) {
	return new Promise((resolve) => {
		if (!rl) createRl();
		rl.question(question, (answer) => resolve(answer.trim()));
	});
}

/** Prompt with an optional default value shown in brackets. */
async function askWithDefault(question, defaultVal) {
	const hint   = defaultVal ? ` ${dim(`[${defaultVal}]`)}` : '';
	const answer = await ask(`${question}${hint}: `);
	return answer || defaultVal || '';
}

/**
 * Prompt for a password.
 * If stdin is a TTY, characters are echoed as '*'; otherwise the input is
 * read normally (piped input, e.g. automated testing).
 */
function askPassword(question) {
	return new Promise((resolve) => {
		if (!process.stdin.isTTY) {
			// Non-interactive (piped): read normally
			return ask(question + ': ').then(resolve);
		}

		// Close the existing readline so raw mode can take over stdin
		if (rl) {
			rl.close();
			rl = null;
		}

		process.stdout.write(question + ': ');
		process.stdin.setRawMode(true);
		process.stdin.resume();
		process.stdin.setEncoding('utf8');

		let password = '';

		function onData(ch) {
			switch (ch) {
				case '\n':
				case '\r':
					process.stdin.setRawMode(false);
					process.stdin.pause();
					process.stdin.removeListener('data', onData);
					process.stdout.write('\n');
					createRl(); // restore readline
					resolve(password);
					break;
				case '\x03': // Ctrl-C
					process.stdout.write('\n');
					process.exit(0);
					break;
				case '\x7f': // Backspace
				case '\b':
					if (password.length > 0) {
						password = password.slice(0, -1);
						process.stdout.write('\b \b');
					}
					break;
				default:
					if (ch >= ' ') {
						password += ch;
						process.stdout.write('*');
					}
					break;
			}
		}

		process.stdin.on('data', onData);
	});
}

// ---------------------------------------------------------------------------
// Port selection
// ---------------------------------------------------------------------------

/**
 * Identify ports that are likely Raspberry Pi Pico W devices.
 * Pico W USB VID: 0x2E8A (Raspberry Pi)
 */
function isPicoPort(portInfo) {
	if (!portInfo) return false;
	const vid = (portInfo.vendorId || '').toLowerCase();
	const path = portInfo.path || '';
	return vid === '2e8a' ||
	       /ttyACM/i.test(path) ||
	       /usbmodem/i.test(path);
}

async function selectPort(portArg) {
	if (portArg) {
		console.log(`Using port: ${cyan(portArg)}`);
		return portArg;
	}

	process.stdout.write('Scanning for serial ports...');
	let ports;
	try {
		ports = await listPorts();
	} catch (err) {
		console.error(red(`\nFailed to list ports: ${err.message}`));
		process.exit(1);
	}
	console.log(' done.\n');

	if (ports.length === 0) {
		console.error(red('No serial ports found. Is the Pico W connected via USB?'));
		process.exit(1);
	}

	// Try to narrow down to Pico-like ports
	const picoLike = ports.filter(isPicoPort);
	const display  = picoLike.length > 0 ? picoLike : ports;

	if (display.length === 1 && picoLike.length > 0) {
		const p = display[0];
		const mfg = p.manufacturer ? ` ${dim('(' + p.manufacturer + ')')}` : '';
		console.log(`Found Pico W port: ${cyan(p.path)}${mfg}`);
		const ans = await ask('Use this port? [Y/n]: ');
		if (ans.toLowerCase() === 'n') {
			console.log('Aborted.');
			process.exit(0);
		}
		return p.path;
	}

	console.log('Available serial ports:');
	display.forEach((p, i) => {
		const mfg  = p.manufacturer ? ` ${dim('– ' + p.manufacturer)}` : '';
		const mark = isPicoPort(p) ? ` ${green('← likely Pico W')}` : '';
		console.log(`  ${bold(String(i + 1))}) ${cyan(p.path)}${mfg}${mark}`);
	});
	if (picoLike.length > 0 && ports.length > display.length) {
		console.log(`  ${bold(String(display.length + 1))}) Show all ${ports.length} ports`);
	}
	console.log(`  ${bold('0')}) Exit`);

	const ans = await ask('\nSelect port number: ');
	const n   = parseInt(ans, 10);

	if (isNaN(n) || n === 0) {
		console.log('Aborted.');
		process.exit(0);
	}

	// "Show all" option
	if (picoLike.length > 0 && ports.length > display.length && n === display.length + 1) {
		// Show all ports – reformat with full list
		console.log('\nAll serial ports:');
		ports.forEach((p, i) => {
			const mfg  = p.manufacturer ? ` ${dim('– ' + p.manufacturer)}` : '';
			const mark = isPicoPort(p) ? ` ${green('← likely Pico W')}` : '';
			console.log(`  ${bold(String(i + 1))}) ${cyan(p.path)}${mfg}${mark}`);
		});
		const ans2 = await ask('\nSelect port number (0 to exit): ');
		const n2   = parseInt(ans2, 10);
		if (isNaN(n2) || n2 === 0 || n2 > ports.length) {
			console.log('Aborted.');
			process.exit(0);
		}
		return ports[n2 - 1].path;
	}

	if (n < 1 || n > display.length) {
		console.error(red('Invalid selection.'));
		process.exit(1);
	}

	return display[n - 1].path;
}

// ---------------------------------------------------------------------------
// Status display
// ---------------------------------------------------------------------------

function printStatus(status) {
	console.log('\n' + bold('Device Status'));
	console.log('─'.repeat(40));

	const wifiLabel = status.connected
		? green('connected')
		: yellow('disconnected');
	console.log(`  WiFi:          ${wifiLabel}`);

	if (status.addresses.length > 0) {
		status.addresses.forEach((addr, i) => {
			console.log(`  IPv6[${i}]:       ${addr}`);
		});
	}

	console.log(`  Country:       ${status.country  || dim('(not set)')}`);

	if (status.server) {
		console.log(`  Server:        ${status.server}:${status.port}`);
	} else {
		console.log(`  Server:        ${dim('not configured')}`);
	}

	console.log(`  Webhook:       ${status.webhook       || dim('(unknown)')}`);
	console.log(`  Token:         ${status.token         || dim('not set')}`);

	const subs = status.subscriptions !== null
		? String(status.subscriptions)
		: dim('(unknown)');
	console.log(`  Push subs:     ${subs}`);

	if (status.vapidPub) {
		const preview = status.vapidPub.length > 24
			? status.vapidPub.slice(0, 24) + '…'
			: status.vapidPub;
		console.log(`  VAPID pub key: ${dim(preview)}`);
		console.log(`                 ${dim('(full key – copy for PICO_VAPID_PUBLIC_KEY):')}`)
		console.log(`  ${status.vapidPub}`);
	}

	console.log('');
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

function printMenu() {
	console.log(bold('Configuration Menu'));
	console.log('─'.repeat(40));
	console.log(`  ${bold('1')}  Show status`);
	console.log(`  ${bold('2')}  Configure WiFi (SSID + password)`);
	console.log(`  ${bold('3')}  Set Wi-Fi country code`);
	console.log(`  ${bold('4')}  Set proxy server address & port`);
	console.log(`  ${bold('5')}  Set webhook auth token`);
	console.log(`  ${bold('6')}  Clear all credentials ${red('(reboots device)')}`);
	console.log(`  ${bold('0')}  Exit`);
	console.log('');
}

// ---------------------------------------------------------------------------
// Menu action handlers
// ---------------------------------------------------------------------------

async function doStatus(bridge) {
	process.stdout.write('Reading status...');
	const status = await bridge.getStatus();
	console.log('');
	printStatus(status);
	return false; // don't exit loop
}

async function doConfigureWifi(bridge) {
	console.log('\n' + bold('Configure WiFi'));
	console.log(dim('The device will reboot after saving credentials.\n'));

	const ssid = await askWithDefault('SSID');
	if (!ssid) {
		console.log(yellow('Cancelled – no SSID entered.\n'));
		return false;
	}

	const pass = await askPassword('Password');
	if (!pass) {
		console.log(yellow('\nCancelled – no password entered.\n'));
		return false;
	}

	process.stdout.write('\nSending SSID...');
	const ssidLines = await bridge.sendCommand(`SSID=${ssid}`);
	console.log('');
	ssidLines.forEach((l) => console.log(`  ${l}`));

	process.stdout.write('Sending password (device will reboot)...');
	// Give a longer window since the device may start rebooting before replying
	const passLines = await bridge.sendCommand(`PASS=${pass}`, 3000);
	console.log('');
	passLines.forEach((l) => console.log(`  ${l}`));

	console.log(yellow('\nThe device is rebooting. Please wait a few seconds, then reconnect.\n'));
	return true; // exit main loop (port will close on reboot)
}

async function doSetCountry(bridge) {
	console.log('\n' + bold('Set Wi-Fi Country Code'));
	console.log(dim('2-letter ISO 3166-1 alpha-2 code (e.g. SE, US, GB, DE, FI).\n'));

	const cc = await askWithDefault('Country code');
	if (!cc) {
		console.log(yellow('Cancelled.\n'));
		return false;
	}
	if (cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) {
		console.log(red('Country code must be exactly 2 letters (e.g. SE).\n'));
		return false;
	}

	const lines = await bridge.sendCommand(`COUNTRY=${cc.toUpperCase()}`);
	lines.forEach((l) => console.log(`  ${l}`));
	console.log(dim('Reboot the device to apply.\n'));
	return false;
}

async function doSetServer(bridge) {
	console.log('\n' + bold('Set Proxy Server Address & Port'));
	console.log(dim(
		'Enter the IP address (or hostname) of the proxy computer.\n' +
		'For IPv6, enter the bare address without brackets (e.g. fe80::1%eth0).\n'
	));

	const ip = await askWithDefault('Server IP / hostname');
	if (!ip) {
		console.log(yellow('Cancelled.\n'));
		return false;
	}

	const portStr = await askWithDefault('Server port', '3000');
	const portNum = parseInt(portStr, 10);
	if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
		console.log(red('Invalid port number (must be 1–65535).\n'));
		return false;
	}

	process.stdout.write('Setting server address...');
	const serverLines = await bridge.sendCommand(`SERVER=${ip}`);
	console.log('');
	serverLines.forEach((l) => console.log(`  ${l}`));

	process.stdout.write('Setting port...');
	const portLines = await bridge.sendCommand(`PORT=${portNum}`);
	console.log('');
	portLines.forEach((l) => console.log(`  ${l}`));

	console.log(dim('Reboot the device to apply.\n'));
	return false;
}

async function doSetToken(bridge) {
	console.log('\n' + bold('Set Webhook Auth Token'));
	console.log(dim(
		'This token must match MACHINE_WEBHOOK_AUTH_TOKEN in the proxy .env file.\n' +
		'Leave empty to clear the token (disables authentication – dev only).\n'
	));

	const token = await askWithDefault('Auth token (max 64 chars)');
	if (token.length > 64) {
		console.log(red('Token too long (max 64 characters).\n'));
		return false;
	}

	const lines = await bridge.sendCommand(`TOKEN=${token}`);
	lines.forEach((l) => console.log(`  ${l}`));
	console.log(dim('Reboot the device to apply.\n'));
	return false;
}

async function doClearCredentials(bridge) {
	console.log('\n' + red(bold('Clear All Stored Credentials')));
	console.log(dim('This erases WiFi credentials, server config, and token from flash.\n'));

	const confirm = await ask('Type ' + bold('YES') + ' to confirm: ');
	if (confirm !== 'YES') {
		console.log(yellow('Cancelled.\n'));
		return false;
	}

	process.stdout.write('Clearing credentials (device will reboot)...');
	const lines = await bridge.sendCommand('CLEAR', 3000);
	console.log('');
	lines.forEach((l) => console.log(`  ${l}`));

	console.log(yellow('\nThe device is rebooting with cleared credentials.\n'));
	return true; // exit main loop
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
	const portArg = process.argv[2];

	// Banner
	console.log('\n' + cyan(bold('  Viking Bio Device Configurator')));
	console.log(dim('  Configure the Pico W bridge over USB serial\n'));

	// Port selection
	const portPath = await selectPort(portArg);

	// Connect
	console.log(`\nConnecting to ${cyan(portPath)}...`);
	const bridge = createSerialBridge(portPath);
	try {
		await bridge.connect();
		console.log(green('Connected.\n'));
	} catch (err) {
		console.error(red(`Connection failed: ${err.message}`));
		if (rl) rl.close();
		process.exit(1);
	}

	// Graceful shutdown on Ctrl-C
	process.once('SIGINT', async () => {
		console.log('\n\nInterrupted – disconnecting...');
		await bridge.disconnect();
		if (rl) rl.close();
		process.exit(0);
	});

	// Show initial status
	console.log('Reading device status...');
	try {
		const status = await bridge.getStatus();
		printStatus(status);
	} catch (err) {
		console.warn(yellow(`Could not read status: ${err.message}\n`));
	}

	// Main menu loop
	let running = true;
	while (running) {
		printMenu();
		const choice = await ask('Enter choice: ');

		switch (choice) {
			case '1':
				running = !(await doStatus(bridge));
				break;
			case '2':
				running = !(await doConfigureWifi(bridge));
				break;
			case '3':
				running = !(await doSetCountry(bridge));
				break;
			case '4':
				running = !(await doSetServer(bridge));
				break;
			case '5':
				running = !(await doSetToken(bridge));
				break;
			case '6':
				running = !(await doClearCredentials(bridge));
				break;
			case '0':
			case 'q':
			case 'quit':
			case 'exit':
				running = false;
				break;
			default:
				console.log(yellow('Invalid choice – enter 0–6.\n'));
				break;
		}
	}

	await bridge.disconnect();
	if (rl) rl.close();
	console.log('\nDisconnected. Goodbye!\n');
}

main().catch((err) => {
	console.error(red(`\nFatal error: ${err.message}`));
	if (rl) rl.close();
	process.exit(1);
});
