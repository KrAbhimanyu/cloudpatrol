/**
 * Session refresh and route protection.
 *
 * Next.js 16 renamed the `middleware.ts` convention to `proxy.ts`, and the
 * exported function from `middleware` to `proxy`. The older names are
 * deprecated in this version, so the new ones are used here.
 *
 * Two jobs, in this order:
 *
 * 1. Refresh the Supabase session. Server Components cannot write cookies, so
 *    without this an expired access token is never replaced and the user is
 *    silently signed out. `getClaims()` is what triggers the refresh and
 *    writes the rotated cookies onto the response.
 * 2. Redirect an unauthenticated visitor away from a protected page before it
 *    renders. This is a convenience, not the security boundary: the FastAPI
 *    service verifies the token itself on every call, and a page that
 *    rendered without a session would still show no data.
 *
 * The response returned by `setAll` is the one that carries the refreshed
 * cookies, so it must be the response that is ultimately returned. An earlier
 * response object would drop them.
 *
 * It also does three security jobs:
 *
 * 3. Generates a per-request CSP nonce and sets the Content-Security-Policy on
 *    both the request (which is how Next.js learns the nonce to stamp onto its
 *    inline scripts) and the response (which is what the browser enforces).
 * 4. Mints the double-submit CSRF cookie when it is absent.
 * 5. Applies the static security headers, so a redirect carries them too.
 *
 * Ordering matters: the CSP must be on the request headers *before* the page
 * renders, because Next.js reads it during rendering. The nonce is therefore
 * generated at the top and threaded into every response this function returns.
 */

import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

import { CSRF_COOKIE_NAME, NONCE_HEADER } from "@/lib/security/constants";
import { csrfCookieOptions, generateCsrfToken } from "@/lib/security/csrf";
import {
  contentSecurityPolicy,
  generateNonce,
  reportingEndpointsHeader,
  staticSecurityHeaders,
} from "@/lib/security/headers";
import { isSupabaseConfigured, supabasePublicConfig } from "@/lib/supabase/env";

/** Pages that require a session. Everything else is public. */
const PROTECTED_PREFIXES = ["/dashboard", "/accounts", "/scans", "/findings", "/savings", "/settings"];

const SIGN_IN_PATH = "/sign-in";

function isProtected(pathname: string): boolean {
  return PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // A fresh nonce per request. Reusing one would let an injected script that
  // learned it keep working.
  const nonce = generateNonce();
  // Reporting is added to the enforced policy, not instead of it. The header is
  // still `Content-Security-Policy`: a violation is still blocked, and is now
  // also reported. Nothing here relaxes a directive.
  const csp = contentSecurityPolicy(nonce, request.nextUrl.origin);

  // The CSRF token is minted once per request and reused if the browser already
  // has one. Rotating it on every response would invalidate a token that a
  // concurrent request is already carrying, which shows up as a spurious 403.
  const csrfToken = request.cookies.get(CSRF_COOKIE_NAME)?.value || generateCsrfToken();

  /**
   * Finish a response: security headers, the CSRF cookie when the browser did
   * not already have one, and no-store. Every return below goes through here,
   * so no branch can accidentally omit a header.
   */
  const finish = (response: NextResponse): NextResponse => {
    response.headers.set("Content-Security-Policy", csp);
    // Declares the endpoint that the CSP's `report-to` directive names. Without
    // it the directive has no name to resolve and is ignored, so the CSP and
    // this header must always be set together.
    const endpoints = reportingEndpointsHeader(request.nextUrl.origin);
    response.headers.set(endpoints.key, endpoints.value);
    for (const { key, value } of staticSecurityHeaders()) {
      response.headers.set(key, value);
    }
    response.headers.set("Cache-Control", "private, no-store");
    if (!request.cookies.get(CSRF_COOKIE_NAME)) {
      response.cookies.set(CSRF_COOKIE_NAME, csrfToken, csrfCookieOptions());
    }
    return response;
  };

  // Without configuration the app cannot establish a session at all. Let the
  // request through so the page can explain what is missing rather than
  // redirect-looping to a sign-in page that cannot work. The nonce still has
  // to be forwarded, or the page's own scripts would be blocked by the CSP.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set(NONCE_HEADER, nonce);
  // Next.js parses the nonce out of this header during rendering.
  requestHeaders.set("Content-Security-Policy", csp);

  if (!isSupabaseConfigured()) {
    return finish(NextResponse.next({ request: { headers: requestHeaders } }));
  }

  let response = NextResponse.next({ request: { headers: requestHeaders } });
  const { url, anonKey } = supabasePublicConfig();

  const supabase = createServerClient(url, anonKey, {
    cookieOptions: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    },
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) {
          request.cookies.set(name, value);
        }
        response = NextResponse.next({ request: { headers: requestHeaders } });
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
      },
    },
  });

  // Validates the JWT signature and refreshes it when close to expiry.
  const { data } = await supabase.auth.getClaims();
  const signedIn = Boolean(data?.claims?.sub);

  if (!signedIn && isProtected(pathname)) {
    const redirect = request.nextUrl.clone();
    redirect.pathname = SIGN_IN_PATH;
    // Preserve where the user was going so sign-in can return them there.
    // Only the path is carried, never the query string, so nothing sensitive
    // is copied into a URL that might be logged.
    redirect.search = `?next=${encodeURIComponent(pathname)}`;
    return finish(NextResponse.redirect(redirect));
  }

  if (signedIn && pathname === SIGN_IN_PATH) {
    const redirect = request.nextUrl.clone();
    redirect.pathname = "/dashboard";
    redirect.search = "";
    return finish(NextResponse.redirect(redirect));
  }

  return finish(response);
}

export const config = {
  /**
   * Run on page routes only. Excluding `api` keeps the BFF proxy route free of
   * a second session read, and excluding static assets avoids a Supabase call
   * on every image request.
   */
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)"],
};
