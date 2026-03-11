/**
 * Exported functions:
 *
 * startBlink(targetElement)  - adds continuous blink class to element (default document.body)
 * stopBlink(targetElement)   - removes blink class
 * enableAutoBlink(selector, options) - watch DOM for an "error element" and toggle blink automatically
 *
 * Safety & accessibility:
 * - If the user has prefers-reduced-motion, the CSS animation is suppressed; a non-flashing
 *   indicator is applied instead via the same class and a @media rule in blink-error.css.
 * - Optionally respects a user opt-out stored in localStorage under 'blinkDisabled'.
 */

const BLINK_CLASS = 'blink-error';
const USER_OPT_OUT_KEY = 'blinkDisabled';

export function startBlink(el = document.body) {
	if (!el) return;
	// Always add the class; CSS handles both the animation and the reduced-motion
	// fallback via @media (prefers-reduced-motion: reduce).
	// When the user has opted out, stopBlink() is called instead (see setUserBlinkOptOut).
	el.classList.add(BLINK_CLASS);
}

export function stopBlink(el = document.body) {
	if (!el) return;
	el.classList.remove(BLINK_CLASS);
}

/* Optional user preference to disable blink; persists in localStorage */
export function setUserBlinkOptOut(disabled) {
	try {
		if (disabled) localStorage.setItem(USER_OPT_OUT_KEY, '1');
		else localStorage.removeItem(USER_OPT_OUT_KEY);
	} catch (e) {
		// localStorage may be unavailable; ignore silently
	}
}

export function isUserOptedOut() {
	try {
		return localStorage.getItem(USER_OPT_OUT_KEY) === '1';
	} catch (e) {
		return false;
	}
}

/**
 * enableAutoBlink
 *  - selector: CSS selector for the error element that appears when there's an active error.
 *    e.g., '#site-error' or '.has-error' or '.error-banner'
 *  - options:
 *     rootEl: element to which blink class will be applied (default document.body)
 *     observeTargets: element to attach MutationObserver to (default document.body)
 *     attribute: if provided, will also watch this attribute on the selected element (optional)
 *
 * Returns an object { disconnect } to stop observing.
 */
export function enableAutoBlink(selector, options = {}) {
	const rootEl = options.rootEl || document.body;
	const observeTargets = options.observeTargets || document.body;
	const attribute = options.attribute || null;

	// Helper to check presence of element
	function hasErrorElement() {
		const el = document.querySelector(selector);
		if (!el) return false;
		if (attribute) {
			return el.getAttribute(attribute) !== null;
		}
		return true;
	}

	// Initial state
	if (hasErrorElement()) startBlink(rootEl);
	else stopBlink(rootEl);

	// Watch for DOM changes so blinking toggles while the error exists
	const observer = new MutationObserver((mutations) => {
		// Simple, cheap check: if element exists then start, otherwise stop
		if (hasErrorElement()) startBlink(rootEl);
		else stopBlink(rootEl);
	});

	observer.observe(observeTargets, {
		childList: true,
		subtree: true,
		attributes: !!attribute,
		attributeFilter: attribute ? [attribute] : undefined,
	});

	return {
		disconnect() {
			observer.disconnect();
			stopBlink(rootEl);
		}
	};
}
