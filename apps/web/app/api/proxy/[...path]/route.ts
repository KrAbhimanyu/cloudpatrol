/**
 * Backend-for-frontend proxy to the CloudPatrol API.
 *
 * The browser calls `/api/proxy/<path>` on its own origin. This route reads
 * the HttpOnly session cookie, attaches the bearer token, and forwards the
 * request to FastAPI. The token is never returned to the client and never
 * appears in the browser at all.
 *
 * Why a proxy rather than calling FastAPI from the browser: the API is a
 * different origin, so it cannot read this app's cookie. The alternative —
 * handing the token to client JavaScript so it can set an `Authorization`
 * header — would put the token back where `localStorage` had it, readable by
 * any injected script, and would undo the point of this phase.
 *
 * This route performs no authorization of its own. It proves only that a
 * session exists. FastAPI verifies the token's signature and claims and
 * enforces organization membership; a client that calls this route with a
 * forged or stale session gets the same rejection it would get directly.
 *
 * It does, however, enforce two CSRF controls before forwarding anything. An
 * unsafe request (POST/PUT/PATCH/DELETE) must come from a trusted origin and
 * must carry a CSRF token matching its cookie. Both are checked here rather
 * than in FastAPI because this is the browser-facing hop: FastAPI is reached
 * server-to-server with a bearer token and has no cookies to inspect. See
 * `lib/security/origin.ts` and `lib/security/csrf.ts` for the policies.
 */

import { NextResponse, type NextRequest } from "next/server";

import { CSRF_HEADER_NAME } from "@/lib/security/constants";
import { evaluateCsrf } from "@/lib/security/csrf";
import { evaluateOrigin } from "@/lib/security/origin";
import { getAccessToken } from "@/lib/supabase/server";

/**
 * Read per request rather than at module load, so the value can be changed
 * without a rebuild and so a test can point the proxy at a stub host.
 */
function apiBaseUrl(): string {
  return process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
}

/** Headers that describe this hop and must not be forwarded verbatim. */
const STRIPPED_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "cookie",
  "authorization",
  "x-organization-id",
  // The client's own origin is not the API's origin; forwarding it would
  // misrepresent the caller and can trip origin checks.
  "origin",
  "referer",
  "accept-encoding",
  // This app's CSRF token is meaningless to FastAPI, which authenticates the
  // server-to-server call by bearer token and never sees a cookie. Forwarding
  // it would leak a value that should stay on this hop.
  CSRF_HEADER_NAME,
  // The proxy sets the nonce; a client-supplied one must not be relayed.
  "x-nonce",
  // Client-controlled hints about the transport. Only a trusted reverse proxy
  // may set these, and this hop is not one.
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
]);

/** Hop-by-hop response headers that must not be relayed to the browser. */
const STRIPPED_RESPONSE_HEADERS = new Set([
  "connection",
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "set-cookie",
]);

export const dynamic = "force-dynamic";

function rejected(code: string, message: string, status: number): NextResponse {
  // `private, no-store` on a rejection too: it carries no data but must not be
  // cached and replayed as if it were a success.
  return NextResponse.json(
    { error: { code, message, details: {} } },
    { status, headers: { "Cache-Control": "private, no-store" } },
  );
}

async function forward(request: NextRequest, path: string[]): Promise<Response> {
  // Origin first: it is the cheapest check and rejects a cross-site request
  // before any token work or upstream call happens.
  const origin = evaluateOrigin(request);
  if (!origin.allowed) {
    return rejected(
      "forbidden_origin",
      "This request did not come from a trusted origin.",
      403,
    );
  }

  // Then the double-submit token. Both checks are required on an unsafe
  // request; neither is treated as sufficient on its own.
  const csrf = evaluateCsrf(request);
  if (!csrf.allowed) {
    return rejected(
      "csrf_failed",
      "The request could not be verified as coming from this application. Reload the page and try again.",
      403,
    );
  }

  const token = await getAccessToken();
  if (!token) {
    return rejected(
      "unauthenticated",
      "Your session has ended. Sign in again to continue.",
      401,
    );
  }

  const target = new URL(`${apiBaseUrl()}/api/v1/${path.map(encodeURIComponent).join("/")}`);
  // Preserve filters such as ?state=estimated exactly as given.
  request.nextUrl.searchParams.forEach((value, key) => target.searchParams.append(key, value));

  const headers = new Headers();
  for (const [key, value] of request.headers) {
    if (!STRIPPED_REQUEST_HEADERS.has(key.toLowerCase())) headers.set(key, value);
  }
  headers.set("Authorization", `Bearer ${token}`);

  // The active workspace is chosen by the client and is not a secret. FastAPI
  // still verifies membership, so a tampered value yields 403, not data.
  const organizationId = request.headers.get("x-organization-id");
  if (organizationId) headers.set("X-Organization-Id", organizationId);

  const hasBody = !["GET", "HEAD"].includes(request.method);
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: request.method,
      headers,
      body: hasBody ? await request.arrayBuffer() : undefined,
      // Never follow a redirect from the API: a 3xx here would silently turn
      // into a GET against another path and drop the authorization intent.
      redirect: "manual",
      cache: "no-store",
    });
  } catch {
    return rejected(
      "network_error",
      "Could not reach the CloudPatrol API. Check that the service is running.",
      502,
    );
  }

  const responseHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    if (!STRIPPED_RESPONSE_HEADERS.has(key.toLowerCase())) responseHeaders.set(key, value);
  });
  // API responses are per-user and must not be cached by a shared proxy.
  responseHeaders.set("Cache-Control", "private, no-store");

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
}

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

export async function GET(request: NextRequest, context: RouteContext): Promise<Response> {
  return forward(request, (await context.params).path);
}

export async function POST(request: NextRequest, context: RouteContext): Promise<Response> {
  return forward(request, (await context.params).path);
}

export async function PATCH(request: NextRequest, context: RouteContext): Promise<Response> {
  return forward(request, (await context.params).path);
}

export async function PUT(request: NextRequest, context: RouteContext): Promise<Response> {
  return forward(request, (await context.params).path);
}

export async function DELETE(request: NextRequest, context: RouteContext): Promise<Response> {
  return forward(request, (await context.params).path);
}
