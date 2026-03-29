'use strict';

/**
 * Validate and parse a numeric port value.
 *
 * @param {*}      value     – raw value (string, number, or undefined)
 * @param {number} fallback  – default when value is nullish
 * @param {string} envName   – environment variable name (for error messages)
 * @returns {number} parsed port in the range 1–65535
 * @throws {Error} when the value is not a valid port number
 */
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
 * Return true when value is a non-null, non-array plain object.
 *
 * @param {*} value
 * @returns {boolean}
 */
function isPlainObject(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

module.exports = { parsePort, isPlainObject };
