/**
 * Names shared by the server and the browser.
 *
 * Kept in their own module so client code can import the names without pulling
 * in `node:crypto`, which `csrf.ts` needs and the browser cannot bundle.
 */

/** Holds the double-submit CSRF token. Readable by same-origin JavaScript. */
export const CSRF_COOKIE_NAME = "cloudpatrol.csrf";

/** Carries the CSRF token back on unsafe requests. */
export const CSRF_HEADER_NAME = "x-csrf-token";

/** Carries the per-request CSP nonce from the proxy to the renderer. */
export const NONCE_HEADER = "x-nonce";

/**
 * Comma-separated extra origins allowed to make unsafe requests, for example
 * `https://app.cloudpatrol.dev,https://staging.cloudpatrol.dev`. The app's own
 * origin is always trusted in addition to this list.
 */
export const TRUSTED_ORIGINS_ENV = "APP_ORIGINS";
