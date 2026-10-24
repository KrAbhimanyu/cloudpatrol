/**
 * Origin validation for state-changing requests.
 *
 * A browser will happily attach this app's session cookie to a request that
 * another site caused it to send. `SameSite=Lax` already stops the cookie from
 * riding along on a cross-site POST, but that attribute is a single line of
 * defence and is not honoured identically everywhere, so the origin is checked
 * as well.
 *
 * ## Policy
 *
 * Safe methods (`GET`, `HEAD`, `OPTIONS`) are not checked: they must not change
 * state, and a same-origin `GET` is how the app reads its data.
 *
 * For unsafe methods (`POST`, `PUT`, `PATCH`, `DELETE`) the `Origin` header
 * must be present and must name a trusted origin. Trusted means the app's own
 * origin for this request, plus anything listed in `APP_ORIGINS`.
 *
 * When `Origin` is absent the decision falls back to `Sec-Fetch-Site`, which
 * every current browser sends and which a page cannot forge:
 *
 * - `same-origin` — accepted. Some clients omit `Origin` on same-origin
 *   requests, and `Sec-Fetch-Site` is positive evidence the request came from
 *   this origin.
 * - anything else, or absent — rejected. A request with neither header carries
 *   no evidence of where it came from, and treating "no evidence" as "same
 *   origin" is exactly the assumption that makes an origin check decorative.
 *
 * A malformed `Origin`, or the literal `null` that a sandboxed iframe or a
 * `file://` page sends, is rejected.
 *
 * This check is one of two on an unsafe request. The CSRF token in `csrf.ts`
 * is the other, and it is what stops a cross-site request even if an origin
 * somehow looks acceptable. Neither is treated as sufficient alone.
 */

import type { NextRequest } from "next/server";

import { TRUSTED_ORIGINS_ENV } from "./constants";

/** Methods that must not change state, and so need no origin check. */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export type OriginReason =
  | "safe-method"
  | "same-origin"
  | "allow-listed"
  | "missing-origin-same-site"
  | "missing-origin"
  | "untrusted-origin"
  | "malformed-origin";

export interface OriginDecision {
  allowed: boolean;
  reason: OriginReason;
}

export function isUnsafeMethod(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

/**
 * Origins that may send an unsafe request to this app.
 *
 * The request's own origin comes first, so local development and any
 * deployment work without extra configuration. `APP_ORIGINS` adds explicit
 * entries for deployments reached by more than one hostname.
 */
export function trustedOriginsFor(request: NextRequest): Set<string> {
  const origins = new Set<string>();

  // Derived from the Host the browser actually used, so this matches the
  // origin a legitimate same-origin request reports. A cross-site request
  // carries the attacker's origin here while Host stays ours, which is what
  // makes the comparison meaningful.
  origins.add(request.nextUrl.origin);

  for (const entry of (process.env[TRUSTED_ORIGINS_ENV] ?? "").split(",")) {
    const trimmed = entry.trim().replace(/\/$/, "");
    if (trimmed) origins.add(trimmed);
  }

  return origins;
}

/** Normalises an origin for comparison, or returns null when unusable. */
function normalise(origin: string): string | null {
  if (!origin || origin === "null") return null;
  try {
    const url = new URL(origin);
    // An origin has no path, query or credentials; anything else is a malformed
    // value rather than an origin.
    if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * Decide whether a request may proceed.
 *
 * Returns a reason as well as a verdict so the rejection can be logged and
 * tested without the caller having to re-derive why.
 */
export function evaluateOrigin(request: NextRequest): OriginDecision {
  if (!isUnsafeMethod(request.method)) {
    return { allowed: true, reason: "safe-method" };
  }

  const trusted = trustedOriginsFor(request);
  const raw = request.headers.get("origin");

  if (raw === null) {
    // No Origin at all. Fall back to Sec-Fetch-Site, which cannot be set by
    // page script and so is trustworthy evidence of the request's origin.
    const fetchSite = request.headers.get("sec-fetch-site");
    if (fetchSite === "same-origin") {
      return { allowed: true, reason: "missing-origin-same-site" };
    }
    return { allowed: false, reason: "missing-origin" };
  }

  const origin = normalise(raw);
  if (origin === null) {
    return { allowed: false, reason: "malformed-origin" };
  }

  if (origin === request.nextUrl.origin) {
    return { allowed: true, reason: "same-origin" };
  }
  if (trusted.has(origin)) {
    return { allowed: true, reason: "allow-listed" };
  }
  return { allowed: false, reason: "untrusted-origin" };
}
