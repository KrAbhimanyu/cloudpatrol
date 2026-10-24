/**
 * CSP violation reporting endpoint.
 *
 * Browsers POST here when the Content-Security-Policy blocks something. Two
 * mechanisms deliver reports, and both are accepted:
 *
 * - **`report-to`** (CSP3, the current mechanism) resolves an endpoint name
 *   declared in the `Reporting-Endpoints` response header. Reports arrive as an
 *   **array** of entries with `Content-Type: application/reports+json`, and a
 *   browser may batch several into one request.
 * - **`report-uri`** (deprecated, kept for browsers that predate `report-to`)
 *   takes a URL directly. A report arrives as a **single** object with
 *   `Content-Type: application/csp-report`, one request per violation.
 *
 * The two are complementary, not alternatives: the specification states that
 * `report-uri` "only takes effect if `report-to` is not present", so a browser
 * that understands `report-to` uses it and one that does not falls back. Sending
 * both is how the older browsers are covered.
 *
 * ## This endpoint is public
 *
 * A violation can occur on a page before sign-in — that is often exactly when a
 * policy breaks — so the endpoint is unauthenticated. It is therefore reachable
 * by anyone, and everything it receives is treated as hostile:
 *
 * - The body is size-limited while it is still being read, so an oversized
 *   request is refused without being buffered in full.
 * - The declared `Content-Length` is checked first as a fast path, but is never
 *   trusted on its own; the streaming check is authoritative.
 * - Only two content types are accepted, and anything else is refused before
 *   the body is read.
 * - The parsed shape is validated field by field, and only known fields are
 *   kept. Unknown fields are dropped rather than logged.
 * - URLs are reduced to scheme, host and path, so a query string is never
 *   written down (see `redactUrl`).
 * - Text fields are truncated and stripped of control characters, so a crafted
 *   `sample` cannot forge a log line.
 * - A token bucket bounds the request rate.
 *
 * ## What this endpoint cannot do
 *
 * Reports are logged and that is all. They are not persisted, not queued, and
 * never fed back into the policy: nothing here can add a source to a directive
 * or relax one. A forged report is therefore noise in a log, not a way to
 * change what the browser enforces.
 *
 * ## What is deliberately not enforced
 *
 * The CSRF and origin checks that guard the BFF are not applied here, and that
 * is a decision rather than an oversight. Those controls protect requests that
 * change state on behalf of an authenticated user; this endpoint has no
 * authenticated action, no session to ride, and no state to change. It writes a
 * log line and nothing else, so there is no cross-site request to forge.
 * Applying an origin check would instead risk discarding real reports: the
 * legacy `report-uri` mechanism sends with `mode: "no-cors"`, and a browser is
 * free to omit `Origin` in ways this app cannot control. The consequence of
 * accepting a cross-origin report is log noise, which the rate limit and the
 * fact that reports are never rendered both bound. Recorded here because an
 * unauthenticated POST with no origin check looks like a mistake otherwise.
 */

import { NextResponse, type NextRequest } from "next/server";

import { hashKey, reportRateLimiter } from "@/lib/security/rate-limit";
import {
  isSupportedContentType,
  MAX_REPORT_BYTES,
  parseReportBody,
  REPORT_BUCKET_COOKIE,
  type NormalisedViolation,
} from "@/lib/security/reporting";

/** Node crypto is used for the bucket hash and the cookie value. */
export const runtime = "nodejs";

/** Reports are per-request and must never be cached or replayed. */
const NO_STORE = "private, no-store";

/**
 * Responses carry no body at all, deliberately.
 *
 * A report is not a query, so there is nothing useful to return, and a response
 * that explained *why* a body was rejected would tell a prober how to shape an
 * accepted one. A bare status is all a browser needs: it treats any success as
 * delivered, and a browser never sends a report it expects a body from.
 */
function status(code: number, headers: Record<string, string> = {}): NextResponse {
  return new NextResponse(null, {
    status: code,
    headers: { "Cache-Control": NO_STORE, ...headers },
  });
}

/** Extra response headers: a bucket cookie only when the browser has none. */
function bucketHeaders(bucketCookie: string | undefined): Record<string, string> {
  if (bucketCookie) return {};
  return { "Set-Cookie": buildBucketCookie() };
}

/**
 * The bucket cookie.
 *
 * `HttpOnly` because nothing in the browser needs to read it — it exists only
 * so the server can tell one reporter from another, and it carries no authority.
 * `SameSite=Lax` is enough: the cookie is only ever set and read on this origin.
 */
function buildBucketCookie(): string {
  const value = crypto.randomUUID();
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `${REPORT_BUCKET_COOKIE}=${value}; Path=/api/csp-report; HttpOnly; SameSite=Lax${secure}`;
}

/**
 * Read the body, refusing anything over `limit` bytes.
 *
 * The limit is enforced while reading rather than after, so a 100 MB body is
 * abandoned at 16 KiB instead of being buffered first and measured later.
 * `Content-Length` is checked before reading as a fast path — it lets an
 * obviously oversized request be refused without touching the stream — but a
 * request that lies about its length is still caught by the running total,
 * because the header is attacker-controlled.
 */
async function readBodyWithLimit(
  request: NextRequest,
  limit: number,
): Promise<{ ok: true; text: string } | { ok: false }> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const bytes = Number(declared);
    // A non-numeric or negative Content-Length is malformed; fall through to the
    // streaming check rather than trusting it either way.
    if (Number.isFinite(bytes) && bytes > limit) return { ok: false };
  }

  const body = request.body;
  if (body === null) return { ok: true, text: "" };

  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let text = "";
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        return { ok: false };
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch {
    // A stream that fails mid-read is not a report we can act on.
    return { ok: false };
  }

  return { ok: true, text };
}

/**
 * Write one violation to the log.
 *
 * A single line per violation, prefixed so it can be filtered out of ordinary
 * output. Only fields that were validated and normalised are included: no
 * cookies, no headers, no raw body. `redactUrl` has already removed any query
 * string before a URL reaches this point.
 */
function logViolation(violation: NormalisedViolation, source: "report-to" | "report-uri"): void {
  console.warn(
    "[csp-violation]",
    JSON.stringify({
      source,
      kind: violation.kind,
      directive: violation.effectiveDirective,
      violated: violation.violatedDirective,
      disposition: violation.disposition,
      document: violation.documentUrl,
      blocked: violation.blockedUrl,
      sourceFile: violation.sourceFile,
      line: violation.lineNumber,
      sample: violation.sample,
      status: violation.statusCode,
      // The policy text is truncated by the normaliser. It is included because
      // the most common false alarm is a stale policy still cached in a
      // browser, and the policy text is how that is recognised.
      policy: violation.originalPolicy,
    }),
  );
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  // Rate limit first: it is the cheapest check and it bounds everything that
  // follows, including the cost of reading a body.
  //
  // The key is a cookie this app mints rather than the client IP. An IP would
  // have to be read from a forwarding header, which any client can set unless a
  // trusted reverse proxy overwrites it; trusting it here would let an attacker
  // rotate the header and bypass the limit entirely. A client that refuses the
  // cookie falls into the shared anonymous bucket, which is bounded as well.
  const bucketCookie = request.cookies.get(REPORT_BUCKET_COOKIE)?.value;
  const bucketKey = hashKey(bucketCookie ?? "anonymous");
  const decision = reportRateLimiter.check("csp-report", bucketKey);

  const setBucketCookie = bucketHeaders(bucketCookie);

  if (!decision.allowed) {
    return status(429, {
      "Retry-After": String(decision.retryAfterSeconds),
      ...setBucketCookie,
    });
  }

  // Then the content type, before the body is touched.
  const contentType = request.headers.get("content-type");
  if (!isSupportedContentType(contentType)) {
    return status(415, setBucketCookie);
  }

  const body = await readBodyWithLimit(request, MAX_REPORT_BYTES);
  if (!body.ok) {
    return status(413, setBucketCookie);
  }

  const violations = parseReportBody(body.text);
  if (violations === null) {
    // Not JSON. A browser only ever sends JSON here, so this is either a
    // misconfigured client or a probe. Worth a distinct status so a genuine
    // misconfiguration is visible, and it reveals nothing about the shape of an
    // accepted report.
    return status(400, setBucketCookie);
  }

  // The format is recorded rather than re-derived, so a reader can tell which
  // mechanism is actually in use in the field. A `report-to` request batches,
  // so it can carry more than one violation.
  const source = violations[0]?.kind === "csp-violation" ? "report-to" : "report-uri";
  for (const violation of violations) {
    logViolation(violation, source);
  }

  // A body that parsed but held nothing recognisable is answered the same way as
  // a valid report. A browser should not retry, and an attacker probing for a
  // difference between "accepted" and "understood" learns nothing.
  return status(204, setBucketCookie);
}

/** Reports arrive by POST only. Anything else is refused without reading a body. */
export async function GET(): Promise<NextResponse> {
  return status(405, { Allow: "POST" });
}
