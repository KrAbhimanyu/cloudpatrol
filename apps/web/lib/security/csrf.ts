/**
 * CSRF tokens for the BFF.
 *
 * ## Why a token at all
 *
 * The session cookie is `SameSite=Lax`, which already blocks the cookie from
 * riding along on a cross-site `POST`. That is a real defence but a narrow one:
 * it is a single attribute, it is applied by the browser, and it is exactly the
 * control an origin check is also trying to provide. A token adds a second,
 * independent one that does not depend on the browser honouring `SameSite` at
 * all — if an attacker can make the browser send the cookie, they still cannot
 * guess the token.
 *
 * ## The scheme
 *
 * This is the double-submit pattern, which is the one that fits a
 * server-rendered app with an HttpOnly session cookie:
 *
 * 1. The proxy mints a random token and sets it in a cookie that is
 *    deliberately **not** HttpOnly, so this app's own JavaScript can read it.
 * 2. The client echoes that value in the `X-CSRF-Token` header on unsafe
 *    requests (`lib/api.ts` does this automatically).
 * 3. The proxy compares the header to the cookie in constant time and rejects
 *    a mismatch.
 *
 * Why double-submit rather than a token stored in the session: the session
 * lives in an HttpOnly cookie this app cannot read, and the token must be
 * readable by the app's own script to be echoed back. Double-submit gets that
 * without putting anything secret in a readable place — the token is only
 * meaningful when paired with the session cookie, and a cross-site attacker can
 * read neither the cookie (SameSite) nor the header value (it cannot read
 * this origin's cookies or storage).
 *
 * ## Why this is safe despite the cookie being readable
 *
 * A cookie that script can read is, on its own, no defence: any XSS can read
 * it. But XSS is not the threat a CSRF token addresses — a request forged from
 * another origin is. Against that, the attacker cannot read the cookie to copy
 * it into a header. The token is a CSRF control, and it is documented as such
 * rather than as an XSS control.
 *
 * ## Scope
 *
 * The cookie is scoped to `/` and `SameSite=Strict`. `Strict` is correct here
 * (unlike the session cookie, which must survive a magic-link redirect) because
 * the token is only ever read and sent by same-origin script, never needed on
 * a cross-site navigation.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";

import type { NextRequest } from "next/server";

import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "./constants";

export { CSRF_COOKIE_NAME, CSRF_HEADER_NAME };

/** 256 bits, base64url-encoded. Unguessable and URL-safe. */
export function generateCsrfToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Cookie attributes for the CSRF token.
 *
 * Not HttpOnly, by necessity: the client has to read it to echo it. See the
 * module comment for why that is acceptable for a CSRF token specifically.
 */
export function csrfCookieOptions(): {
  httpOnly: false;
  secure: boolean;
  sameSite: "strict";
  path: string;
} {
  return {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  };
}

export type CsrfReason =
  | "safe-method"
  | "valid"
  | "missing-cookie"
  | "missing-header"
  | "mismatch";

export interface CsrfDecision {
  allowed: boolean;
  reason: CsrfReason;
}

/** Constant-time string comparison that does not leak length. */
function equal(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  // timingSafeEqual throws on a length mismatch, so the lengths are compared
  // first. Length is not secret — it is fixed at 43 characters for every token
  // this app mints — so this early return leaks nothing.
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Verify the double-submit token on an unsafe request.
 *
 * Both halves must be present and equal. A request with the cookie but no
 * header (a plain cross-site form post, which cannot set a custom header) is
 * rejected, and so is a header with no cookie.
 */
export function evaluateCsrf(request: NextRequest): CsrfDecision {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return { allowed: true, reason: "safe-method" };
  }

  const cookie = request.cookies.get(CSRF_COOKIE_NAME)?.value;
  if (!cookie) {
    return { allowed: false, reason: "missing-cookie" };
  }

  const header = request.headers.get(CSRF_HEADER_NAME);
  if (!header) {
    return { allowed: false, reason: "missing-header" };
  }

  if (!equal(cookie, header)) {
    return { allowed: false, reason: "mismatch" };
  }

  return { allowed: true, reason: "valid" };
}
