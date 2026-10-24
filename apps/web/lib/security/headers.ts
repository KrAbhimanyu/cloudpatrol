/**
 * Security response headers.
 *
 * Two groups, applied in two places, because they have different lifetimes:
 *
 * - **Per-request** (`contentSecurityPolicy`): the CSP carries a nonce that
 *   changes on every response, so it is built in `proxy.ts`.
 * - **Static** (`staticSecurityHeaders`): everything else, applied from
 *   `next.config.ts` so the headers also cover the BFF route and any other
 *   response the proxy's matcher deliberately skips.
 *
 * ## The CSP
 *
 * Scripts are nonce-based rather than `'unsafe-inline'`. This app renders every
 * page dynamically (all routes report as dynamic in the production build), and
 * dynamic rendering is what makes a nonce possible: Next.js reads the nonce out
 * of the `Content-Security-Policy` header on the *request*, then stamps it onto
 * the framework scripts, the page bundles, and the inline scripts it emits.
 * A statically prerendered page is built once, with no request in hand, so a
 * nonce could never reach it — which is why this policy depends on the app
 * staying fully dynamic.
 *
 * `'strict-dynamic'` lets those nonce'd scripts load the rest of the bundle
 * without every chunk having to be listed. `'unsafe-eval'` is added in
 * development only, where React uses `eval` to rebuild server-side error
 * stacks; production does not need it and does not get it.
 *
 * ## Deliberate exceptions
 *
 * - `style-src-attr 'unsafe-inline'`: React renders the `style` prop to an
 *   inline `style` attribute, and a CSP nonce does not authorise style
 *   attributes — only `<style>` elements. The dashboard's savings bar sets its
 *   width that way. Scoped to `style-src-attr` alone, this does not permit
 *   `<style>` blocks (which still need the nonce), does not permit inline event
 *   handlers, and does not touch `script-src` at all. An inline style attribute
 *   cannot execute script, so the exposure is style injection, not code
 *   execution. Recorded here rather than silently widened into `style-src`.
 * - `img-src` allows `blob:` and `data:`, which Next.js uses for optimised and
 *   inlined images.
 *
 * ## HSTS
 *
 * Only sent in production. `Strict-Transport-Security` on a plain-HTTP
 * development origin would pin a browser to a scheme that origin cannot serve,
 * and the header is ignored on `localhost` anyway. `preload` is deliberately
 * omitted: it is a near-permanent commitment that should be a deliberate
 * operational decision, not a side effect of deploying.
 */

import { NONCE_HEADER } from "./constants";
import { CSP_REPORT_ENDPOINT_NAME, CSP_REPORT_PATH } from "./reporting";

export { NONCE_HEADER };

export interface SecurityHeader {
  key: string;
  value: string;
}

/** A fresh, URL-safe nonce for one response. 128 bits. */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64");
}

function isDevelopment(): boolean {
  return process.env.NODE_ENV === "development";
}

/**
 * Declares the endpoint that `report-to` refers to by name.
 *
 * `report-to` takes an endpoint *name*, which the browser resolves through this
 * header; `report-uri` takes the URL directly. The name has to be declared here
 * or the `report-to` directive has nothing to resolve and is ignored.
 *
 * The browser ignores an endpoint whose origin is not "potentially
 * trustworthy", which for practical purposes means HTTPS or `localhost`. A
 * development server reached by bare IP over plain HTTP will therefore not
 * deliver reports; that is the browser's rule, not something this app can
 * override, and it is noted in `docs/SECURITY.md`.
 */
export function reportingEndpointsHeader(origin: string): SecurityHeader {
  return {
    key: "Reporting-Endpoints",
    value: `${CSP_REPORT_ENDPOINT_NAME}="${origin}${CSP_REPORT_PATH}"`,
  };
}

/**
 * The Content-Security-Policy for a single response.
 *
 * Kept as an array of directives joined with "; " so a test can assert on one
 * directive without matching the whole string.
 *
 * `origin` adds the two reporting directives, which tell the browser *where to
 * send a violation notice*. Reporting is purely additive: neither directive
 * grants permission to load anything, so adding them cannot make the policy
 * more permissive. Enforcement is unchanged — the header is still
 * `Content-Security-Policy`, never the report-only variant.
 *
 * Both directives are sent on purpose. `report-to` is the current mechanism and
 * `report-uri` is deprecated, but the specification says `report-uri` "only
 * takes effect if `report-to` is not present" — so a modern browser uses
 * `report-to` and one that predates it falls back to `report-uri`. Sending both
 * is the documented way to cover both.
 */
export function contentSecurityPolicy(nonce: string, origin?: string): string {
  const directives: string[] = [
    "default-src 'self'",
    // Nonce + strict-dynamic, per the Next.js CSP guidance. Development adds
    // 'unsafe-eval' for React's debugging path; production does not.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDevelopment() ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    // React's `style` prop becomes an attribute, which a nonce cannot cover.
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "font-src 'self'",
    // The browser talks only to this origin: every API call goes through the
    // BFF route, and Supabase is reached from the server, never the client.
    // The reporting endpoint is same-origin, so it needs no entry here.
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    // Server actions and the sign-in form both post to this origin.
    "form-action 'self'",
    // Clickjacking. Duplicated by X-Frame-Options for older browsers.
    "frame-ancestors 'none'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "upgrade-insecure-requests",
  ];

  if (origin) {
    directives.push(`report-uri ${origin}${CSP_REPORT_PATH}`);
    directives.push(`report-to ${CSP_REPORT_ENDPOINT_NAME}`);
  }

  return directives.join("; ");
}

/**
 * Headers that do not vary per request.
 *
 * Returned from a function rather than a constant so the production-only HSTS
 * decision is made when the server starts, not when the module is first
 * imported during a build.
 */
export function staticSecurityHeaders(): SecurityHeader[] {
  const headers: SecurityHeader[] = [
    // Stop the browser from re-interpreting a response as a different type.
    { key: "X-Content-Type-Options", value: "nosniff" },
    // Send the origin (not the path) on cross-origin requests, and nothing on
    // a downgrade. Keeps resource IDs out of other sites' logs.
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    {
      key: "Permissions-Policy",
      value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), midi=()",
    },
    // Belt and braces with frame-ancestors, for browsers that predate CSP2.
    { key: "X-Frame-Options", value: "DENY" },
    // No popups are used, so nothing needs a cross-origin opener reference.
    { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  ];

  if (process.env.NODE_ENV === "production") {
    headers.push({
      key: "Strict-Transport-Security",
      value: "max-age=63072000; includeSubDomains",
    });
  }

  return headers;
}

/** True when the response must not be stored, which is true for all auth paths. */
export function isSensitivePath(pathname: string): boolean {
  return pathname.startsWith("/sign-in") || pathname.startsWith("/api/");
}
