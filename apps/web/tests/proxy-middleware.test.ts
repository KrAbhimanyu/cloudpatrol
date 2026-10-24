/**
 * Tests for the session-refresh proxy (Next.js 16's `proxy.ts`, formerly
 * `middleware.ts`).
 *
 * Two claims are checked here: an unauthenticated visitor is kept off a
 * protected page, and a request is never left without the cookie refresh that
 * keeps a session alive.
 *
 * `@supabase/ssr` is mocked at the boundary. These tests are about the routing
 * decision, not about Supabase's own token handling.
 */

import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getClaims = vi.fn();

vi.mock("@supabase/ssr", () => ({
  createServerClient: () => ({ auth: { getClaims } }),
}));

vi.mock("@/lib/supabase/env", () => ({
  isSupabaseConfigured: () => true,
  supabasePublicConfig: () => ({ url: "https://proj.supabase.co", anonKey: "anon" }),
}));

const { proxy, config } = await import("@/proxy");

beforeEach(() => {
  getClaims.mockReset();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

function request(path: string): NextRequest {
  return new NextRequest(new URL(path, "https://app.example.test"));
}

function signedIn(sub = "user-1") {
  getClaims.mockResolvedValue({ data: { claims: { sub } } });
}

function signedOut() {
  getClaims.mockResolvedValue({ data: { claims: null } });
}

describe("route protection", () => {
  it("redirects a signed-out visitor from a protected page to sign-in", async () => {
    signedOut();
    const response = await proxy(request("/dashboard"));

    expect(response.status).toBe(307);
    const location = new URL(response.headers.get("location") as string);
    expect(location.pathname).toBe("/sign-in");
    expect(location.searchParams.get("next")).toBe("/dashboard");
  });

  it("protects every data page", async () => {
    signedOut();
    for (const path of ["/accounts", "/scans", "/findings", "/savings", "/settings"]) {
      const response = await proxy(request(path));
      expect(response.status, `expected ${path} to be protected`).toBe(307);
    }
  });

  it("protects a nested path under a protected prefix", async () => {
    signedOut();
    const response = await proxy(request("/findings/abc123"));
    expect(response.status).toBe(307);
  });

  it("does not redirect from a public page", async () => {
    signedOut();
    const response = await proxy(request("/"));
    expect(response.status).toBe(200);
  });

  it("lets a signed-in visitor reach a protected page", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    expect(response.status).toBe(200);
  });

  it("sends a signed-in visitor away from the sign-in page", async () => {
    signedIn();
    const response = await proxy(request("/sign-in"));

    expect(response.status).toBe(307);
    expect(new URL(response.headers.get("location") as string).pathname).toBe("/dashboard");
  });

  it("treats a claim without a subject as signed out", async () => {
    getClaims.mockResolvedValue({ data: { claims: { sub: null } } });
    const response = await proxy(request("/dashboard"));
    // A token that verifies but identifies nobody must not open a data page.
    expect(response.status).toBe(307);
  });

  it("carries only the path, never the query string, into the redirect", async () => {
    signedOut();
    const response = await proxy(request("/findings?token=leaky"));
    const location = new URL(response.headers.get("location") as string);
    expect(location.searchParams.get("next")).toBe("/findings");
    expect(location.searchParams.get("token")).toBeNull();
  });
});

describe("caching", () => {
  it("marks the response private so a shared cache cannot store a session", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
  });
});

describe("matcher", () => {
  it("excludes the API and static assets", () => {
    const matcher = config.matcher.join("");
    // The proxy must not run on the BFF route or on asset requests.
    expect(matcher).toContain("api");
    expect(matcher).toContain("_next/static");
  });
});

describe("security headers", () => {
  it("sets a CSP on a normal page response", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    expect(response.headers.get("Content-Security-Policy")).toBeTruthy();
  });

  it("sets a CSP on the redirect a signed-out visitor receives", async () => {
    signedOut();
    const response = await proxy(request("/dashboard"));
    // A redirect is still a response the browser renders headers from.
    expect(response.status).toBe(307);
    expect(response.headers.get("Content-Security-Policy")).toBeTruthy();
  });

  it("sets nosniff and a referrer policy", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
  });

  it("denies framing", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
  });

  it("uses a fresh nonce on each response", async () => {
    signedIn();
    const first = await proxy(request("/dashboard"));
    const second = await proxy(request("/dashboard"));

    const nonceOf = (r: Response) =>
      (r.headers.get("Content-Security-Policy") ?? "").match(/'nonce-([^']+)'/)?.[1];

    const a = nonceOf(first);
    const b = nonceOf(second);
    expect(a).toBeTruthy();
    expect(a).not.toBe(b);
  });

  it("passes the nonce to the renderer on the request headers", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));

    // Next.js reads the nonce from the CSP header on the *request* during
    // rendering. Middleware cannot mutate the incoming request directly, so it
    // emits override headers that Next.js applies before rendering. Asserting
    // on these is what actually proves the nonce reaches the renderer — the
    // response CSP alone would still be set even if rendering never saw it.
    const csp = response.headers.get("Content-Security-Policy") ?? "";
    const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
    expect(nonce).toBeTruthy();

    expect(response.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
    expect(response.headers.get("x-middleware-request-content-security-policy")).toBe(csp);
    expect(response.headers.get("x-middleware-override-headers")).toContain("x-nonce");
  });

  it("sets the CSRF cookie when the browser has none", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));

    const cookie = response.cookies.get("cloudpatrol.csrf");
    expect(cookie?.value).toBeTruthy();
    // Readable by the client, which has to echo it, and SameSite=Strict.
    expect(cookie?.httpOnly).toBe(false);
    expect(cookie?.sameSite).toBe("strict");
  });

  it("keeps an existing CSRF token rather than rotating it on every response", async () => {
    signedIn();
    const existing = "existing-token-value";
    const withCookie = new NextRequest(new URL("/dashboard", "https://app.example.test"), {
      headers: { cookie: `cloudpatrol.csrf=${existing}` },
    });

    const response = await proxy(withCookie);

    // Rotating on every response would invalidate a token a concurrent request
    // is already carrying, producing spurious 403s.
    expect(response.cookies.get("cloudpatrol.csrf")).toBeUndefined();
  });

  it("sets the CSRF cookie on the sign-out redirect too", async () => {
    signedOut();
    const response = await proxy(request("/dashboard"));
    expect(response.cookies.get("cloudpatrol.csrf")?.value).toBeTruthy();
  });

  it("declares a reporting endpoint on the response", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    expect(response.headers.get("Reporting-Endpoints")).toBe(
      'csp="https://app.example.test/api/csp-report"',
    );
  });

  it("points report-uri at the same endpoint the Reporting-Endpoints header declares", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));

    const declared = response.headers.get("Reporting-Endpoints") ?? "";
    const declaredUrl = declared.match(/="([^"]+)"/)?.[1];
    const csp = response.headers.get("Content-Security-Policy") ?? "";
    const reportUri = csp.match(/report-uri ([^;]+)/)?.[1]?.trim();

    // The two must agree, or `report-uri` would post to an undeclared URL.
    expect(reportUri).toBe(declaredUrl);
  });

  it("keeps the policy enforced, not report-only", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    // Reporting is additive: the blocking header must still be present. A
    // regression to Report-Only would disable enforcement entirely.
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(response.headers.get("Content-Security-Policy-Report-Only")).toBeNull();
  });

  it("carries the reporting directives on a redirect, so a violation on the way is not lost", async () => {
    signedOut();
    const response = await proxy(request("/dashboard"));
    const csp = response.headers.get("Content-Security-Policy") ?? "";
    expect(csp).toContain("report-uri ");
    expect(csp).toContain("report-to ");
    expect(response.headers.get("Reporting-Endpoints")).toContain("/api/csp-report");
  });

  it("still sends the CSP when reporting is configured", async () => {
    signedIn();
    const response = await proxy(request("/dashboard"));
    const csp = response.headers.get("Content-Security-Policy") ?? "";
    // The blocking directives are unchanged; only reporting was added.
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
  });
});

