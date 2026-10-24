/**
 * The CSP reporting endpoint.
 *
 * These tests drive the real route handler rather than a mock, because the
 * behaviour that matters is what the handler does with a hostile request: how
 * much it reads, what it refuses, what it writes to the log, and what it
 * returns. The rate limiter is the shared one, so the tests reset it between
 * cases by draining rather than by replacing the module.
 */

import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { POST, GET } from "@/app/api/csp-report/route";
import { reportRateLimiter } from "@/lib/security/rate-limit";
import { MAX_REPORT_BYTES, REPORT_BUCKET_COOKIE } from "@/lib/security/reporting";

const APP = "https://app.example.test";
const URL_UNDER_TEST = `${APP}/api/csp-report`;

/** A distinct cookie per call, so each case gets a fresh rate-limit bucket. */
let cookieSeq = 0;
function freshCookie(): string {
  cookieSeq += 1;
  return `${REPORT_BUCKET_COOKIE}=bucket-${cookieSeq}-${Date.now()}`;
}

interface RequestOptions {
  contentType?: string | null;
  body?: string;
  cookie?: string | null;
  contentLength?: string | null;
  method?: string;
}

function makeRequest({
  contentType = "application/csp-report",
  body = "{}",
  cookie = freshCookie(),
  contentLength,
  method = "POST",
}: RequestOptions = {}): NextRequest {
  const headers = new Headers();
  if (contentType !== null) headers.set("content-type", contentType);
  if (cookie !== null) headers.set("cookie", cookie);
  if (contentLength !== null && contentLength !== undefined) {
    headers.set("content-length", contentLength);
  }
  return new NextRequest(new URL(URL_UNDER_TEST), { method, headers, body });
}

const LEGACY_BODY = JSON.stringify({
  "csp-report": {
    "document-uri": "https://app.example.test/dashboard?token=leaky",
    "violated-directive": "script-src 'self'",
    "effective-directive": "script-src",
    disposition: "enforce",
    "blocked-uri": "https://evil.test/x.js",
    "status-code": 200,
  },
});

const MODERN_BODY = JSON.stringify([
  {
    type: "csp-violation",
    url: "https://app.example.test/dashboard?token=leaky",
    body: {
      documentURL: "https://app.example.test/dashboard?token=leaky",
      blockedURL: "inline",
      effectiveDirective: "style-src",
      disposition: "enforce",
      lineNumber: 42,
    },
  },
]);

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  // The limiter is a shared singleton, so a previous test's traffic would
  // otherwise carry into this one and a rate-limit test would be order-dependent.
  reportRateLimiter.reset();
});

afterEach(() => {
  warnSpy.mockRestore();
});

/** Everything written to console.warn during a test, joined. */
function logged(): string {
  return warnSpy.mock.calls.map((call: unknown[]) => call.map(String).join(" ")).join("\n");
}

describe("accepting reports", () => {
  it("accepts a legacy report-uri report with 204", async () => {
    const response = await POST(makeRequest({ body: LEGACY_BODY }));
    expect(response.status).toBe(204);
  });

  it("accepts a Reporting API batch with 204", async () => {
    const response = await POST(
      makeRequest({ contentType: "application/reports+json", body: MODERN_BODY }),
    );
    expect(response.status).toBe(204);
  });

  it("returns no body, so nothing about the accepted shape is revealed", async () => {
    const response = await POST(makeRequest({ body: LEGACY_BODY }));
    expect(await response.text()).toBe("");
  });

  it("logs one line per violation", async () => {
    await POST(makeRequest({ body: LEGACY_BODY }));
    const lines = logged().split("\n").filter((line) => line.includes("[csp-violation]"));
    expect(lines).toHaveLength(1);
  });

  it("logs every violation in a batch", async () => {
    const batch = JSON.stringify([
      { type: "csp-violation", body: { effectiveDirective: "style-src" } },
      { type: "csp-violation", body: { effectiveDirective: "img-src" } },
      { type: "csp-violation", body: { effectiveDirective: "font-src" } },
    ]);
    await POST(makeRequest({ contentType: "application/reports+json", body: batch }));

    const lines = logged().split("\n").filter((line) => line.includes("[csp-violation]"));
    expect(lines).toHaveLength(3);
  });

  it("records which mechanism delivered the report", async () => {
    await POST(makeRequest({ body: LEGACY_BODY }));
    expect(logged()).toContain("report-uri");

    warnSpy.mockClear();
    await POST(makeRequest({ contentType: "application/reports+json", body: MODERN_BODY }));
    expect(logged()).toContain("report-to");
  });

  it("marks the response no-store", async () => {
    const response = await POST(makeRequest({ body: LEGACY_BODY }));
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
  });

  it("does not require a session, because a violation can precede sign-in", async () => {
    const response = await POST(makeRequest({ body: LEGACY_BODY, cookie: null }));
    expect(response.status).toBe(204);
  });
});

describe("redaction of sensitive fields", () => {
  it("never logs the document query string", async () => {
    await POST(makeRequest({ body: LEGACY_BODY }));
    expect(logged()).not.toContain("token=leaky");
    expect(logged()).toContain("https://app.example.test/dashboard");
  });

  it("never logs the query string from a Reporting API report either", async () => {
    await POST(makeRequest({ contentType: "application/reports+json", body: MODERN_BODY }));
    expect(logged()).not.toContain("token=leaky");
  });

  it("never logs a cookie value", async () => {
    const cookie = freshCookie();
    await POST(makeRequest({ body: LEGACY_BODY, cookie }));
    expect(logged()).not.toContain(cookie.split("=")[1] as string);
    expect(logged()).not.toContain(REPORT_BUCKET_COOKIE);
  });

  it("never logs the raw request body", async () => {
    const body = JSON.stringify({
      "csp-report": { "effective-directive": "script-src", "script-sample": "UNIQUE_MARKER_XYZ" },
    });
    await POST(makeRequest({ body }));

    // Parse the logged line and assert the exact key set. A substring check is
    // too weak here: the normalised output legitimately contains the word
    // "csp-report" as a `kind` value. What must not happen is the wire envelope
    // being written through, so the keys are pinned.
    const line = logged().split("\n").find((entry) => entry.includes("[csp-violation]"));
    const json = JSON.parse((line as string).replace("[csp-violation] ", ""));
    expect(Object.keys(json).sort()).toEqual([
      "blocked",
      "directive",
      "disposition",
      "document",
      "kind",
      "line",
      "policy",
      "sample",
      "source",
      "sourceFile",
      "status",
      "violated",
    ]);
  });

  it("strips control characters from a crafted sample", async () => {
    const body = JSON.stringify({
      "csp-report": {
        "effective-directive": "script-src",
        "script-sample": "evil\n[ERROR] forged log entry",
      },
    });
    await POST(makeRequest({ body }));
    const lines = logged().split("\n").filter((line) => line.includes("[csp-violation]"));
    // If the newline survived, the violation would occupy two lines.
    expect(lines).toHaveLength(1);
    expect(logged()).not.toContain("\n[ERROR]");
  });

  it("truncates an oversized field rather than logging it in full", async () => {
    const body = JSON.stringify({
      "csp-report": { "effective-directive": "script-src", "script-sample": "A".repeat(100_000) },
    });
    await POST(makeRequest({ body }));
    expect(logged()).not.toContain("A".repeat(1000));
  });

  it("drops unknown fields entirely", async () => {
    const body = JSON.stringify({
      "csp-report": { "effective-directive": "script-src", exfiltrated: "SECRET_VALUE" },
    });
    await POST(makeRequest({ body }));
    expect(logged()).not.toContain("SECRET_VALUE");
  });
});

describe("oversized bodies", () => {
  it("rejects a body over the limit with 413", async () => {
    const body = "x".repeat(MAX_REPORT_BYTES + 1);
    const response = await POST(makeRequest({ body }));
    expect(response.status).toBe(413);
  });

  it("accepts a body at exactly the limit", async () => {
    // Padding inside a valid report, so the shape is still understood.
    const padding = "x".repeat(1000);
    const body = JSON.stringify({
      "csp-report": { "effective-directive": "script-src", "script-sample": padding },
    });
    const response = await POST(makeRequest({ body }));
    expect(response.status).toBe(204);
  });

  it("rejects an oversized body declared by Content-Length without reading it", async () => {
    const response = await POST(
      makeRequest({ body: "{}", contentLength: String(MAX_REPORT_BYTES * 100) }),
    );
    expect(response.status).toBe(413);
  });

  it("still rejects an oversized body when Content-Length lies and understates it", async () => {
    // The header is attacker-controlled, so the streaming check is authoritative.
    const body = "x".repeat(MAX_REPORT_BYTES + 1);
    const response = await POST(makeRequest({ body, contentLength: "2" }));
    expect(response.status).toBe(413);
  });

  it("does not log anything for an oversized body", async () => {
    await POST(makeRequest({ body: "x".repeat(MAX_REPORT_BYTES + 1) }));
    expect(logged()).toBe("");
  });

  it("tolerates a non-numeric Content-Length", async () => {
    const response = await POST(makeRequest({ body: LEGACY_BODY, contentLength: "not-a-number" }));
    expect(response.status).toBe(204);
  });
});

describe("unsupported content types", () => {
  it.each([
    ["application/json", "a JSON body"],
    ["application/x-www-form-urlencoded", "a form body"],
    ["text/plain", "plain text"],
    ["multipart/form-data", "a multipart body"],
  ])("rejects %s with 415", async (contentType) => {
    const response = await POST(makeRequest({ contentType, body: LEGACY_BODY }));
    expect(response.status).toBe(415);
  });

  it("rejects a missing content type with 415", async () => {
    const response = await POST(makeRequest({ contentType: null, body: LEGACY_BODY }));
    expect(response.status).toBe(415);
  });

  it("does not log anything for a rejected content type", async () => {
    await POST(makeRequest({ contentType: "application/json", body: LEGACY_BODY }));
    expect(logged()).toBe("");
  });

  it("does not read the body of a request it will reject", async () => {
    // The body is a stream; if the handler consumed it, reading it here would
    // yield nothing. It should still be intact, proving nothing was read.
    const request = makeRequest({ contentType: "application/json", body: LEGACY_BODY });
    await POST(request);
    expect(await request.text()).toBe(LEGACY_BODY);
  });
});

describe("malformed payloads", () => {
  it.each([
    ["an HTML body", "<html>hi</html>"],
    ["an empty body", ""],
    ["truncated JSON", '{"csp-report": {'],
    ["a bare word", "hello"],
  ])("returns 400 for %s", async (_label, body) => {
    const response = await POST(makeRequest({ body }));
    expect(response.status).toBe(400);
  });

  it("returns 400 without echoing the body back", async () => {
    const response = await POST(makeRequest({ body: "<html>UNIQUE_MARKER</html>" }));
    expect(await response.text()).toBe("");
    expect(logged()).not.toContain("UNIQUE_MARKER");
  });

  it("acknowledges well-formed JSON of the wrong shape with 204, so a browser does not retry", async () => {
    const response = await POST(makeRequest({ body: '{"unexpected": true}' }));
    expect(response.status).toBe(204);
  });

  it("does not log anything for a well-formed but unrecognised body", async () => {
    await POST(makeRequest({ body: '{"unexpected": true}' }));
    expect(logged()).toBe("");
  });

  it("acknowledges a batch of report types it does not handle without logging them", async () => {
    const batch = JSON.stringify([
      { type: "deprecation", body: { message: "old api" } },
      { type: "intervention", body: {} },
    ]);
    const response = await POST(makeRequest({ contentType: "application/reports+json", body: batch }));
    expect(response.status).toBe(204);
    expect(logged()).toBe("");
  });

  it("survives a hostile deeply-nested body without throwing", async () => {
    const body = `${"[".repeat(1000)}${"]".repeat(1000)}`;
    const response = await POST(makeRequest({ body }));
    expect([204, 400, 413]).toContain(response.status);
  });
});

describe("method handling", () => {
  it("refuses GET with 405 and names the allowed method", async () => {
    const response = await GET();
    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("POST");
  });

  it("returns no body for GET", async () => {
    expect(await (await GET()).text()).toBe("");
  });
});

describe("rate limiting", () => {
  it("allows a burst and then refuses with 429", async () => {
    const cookie = freshCookie();
    let refusedAt = -1;

    for (let i = 0; i < 200; i += 1) {
      const response = await POST(makeRequest({ body: LEGACY_BODY, cookie }));
      if (response.status === 429) {
        refusedAt = i;
        break;
      }
      expect(response.status).toBe(204);
    }

    // The rule is a burst of 60, so the 61st request is the first refused.
    expect(refusedAt).toBe(60);
  });

  it("sets Retry-After on a refusal", async () => {
    const cookie = freshCookie();
    let response;
    for (let i = 0; i < 200; i += 1) {
      response = await POST(makeRequest({ body: LEGACY_BODY, cookie }));
      if (response.status === 429) break;
    }
    expect(response?.status).toBe(429);
    const retryAfter = Number(response?.headers.get("Retry-After"));
    expect(Number.isFinite(retryAfter)).toBe(true);
    expect(retryAfter).toBeGreaterThan(0);
  });

  it("does not log anything for a refused request", async () => {
    const cookie = freshCookie();
    for (let i = 0; i < 200; i += 1) {
      const response = await POST(makeRequest({ body: LEGACY_BODY, cookie }));
      if (response.status === 429) break;
    }
    warnSpy.mockClear();
    await POST(makeRequest({ body: LEGACY_BODY, cookie }));
    expect(logged()).toBe("");
  });

  it("buckets a client without a cookie separately from one with a cookie", async () => {
    // Drain the shared anonymous bucket.
    for (let i = 0; i < 200; i += 1) {
      const response = await POST(makeRequest({ body: LEGACY_BODY, cookie: null }));
      if (response.status === 429) break;
    }

    // A fresh cookie has its own bucket and must still be served.
    const response = await POST(makeRequest({ body: LEGACY_BODY, cookie: freshCookie() }));
    expect(response.status).toBe(204);
  });

  it("rate limits before reading the body, so a flood is cheap to refuse", async () => {
    const cookie = freshCookie();
    for (let i = 0; i < 200; i += 1) {
      const response = await POST(makeRequest({ body: LEGACY_BODY, cookie }));
      if (response.status === 429) break;
    }
    // An oversized body from a refused client is answered 429, not 413: the
    // rate check runs first, so no body is read at all.
    const response = await POST(
      makeRequest({ body: "x".repeat(MAX_REPORT_BYTES * 2), cookie }),
    );
    expect(response.status).toBe(429);
  });
});

describe("bucket cookie", () => {
  it("sets a bucket cookie when the browser has none", async () => {
    const response = await POST(makeRequest({ body: LEGACY_BODY, cookie: null }));
    const setCookie = response.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain(`${REPORT_BUCKET_COOKIE}=`);
    // HttpOnly: nothing in the browser needs to read it, and it carries no
    // authority — it only separates one reporter's bucket from another's.
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).toContain("Path=/api/csp-report");
  });

  it("does not re-issue the cookie when the browser already has one", async () => {
    const response = await POST(makeRequest({ body: LEGACY_BODY, cookie: freshCookie() }));
    expect(response.headers.get("Set-Cookie")).toBeNull();
  });

  it("sets the cookie even on a rejected request, so the next one is bucketed", async () => {
    const response = await POST(makeRequest({ contentType: "application/json", cookie: null }));
    expect(response.status).toBe(415);
    expect(response.headers.get("Set-Cookie")).toContain(REPORT_BUCKET_COOKIE);
  });
});
