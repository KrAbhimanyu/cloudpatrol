/**
 * Double-submit CSRF token.
 *
 * The property that matters is that a request is rejected unless the cookie and
 * the header are both present and equal. Each of those three conditions is
 * tested independently, plus the token's randomness.
 */

import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  csrfCookieOptions,
  evaluateCsrf,
  generateCsrfToken,
} from "@/lib/security/csrf";

const APP = "https://app.example.test";

function request(
  method: string,
  headers: Record<string, string> = {},
  cookies: Record<string, string> = {},
): NextRequest {
  const cookieHeader = Object.entries(cookies)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
  return new NextRequest(new URL("/api/proxy/scans", APP), {
    method,
    headers: { ...(cookieHeader ? { cookie: cookieHeader } : {}), ...headers },
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("generateCsrfToken", () => {
  it("produces a URL-safe token with 256 bits of entropy", () => {
    const token = generateCsrfToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    // 32 random bytes in base64url is 43 characters, no padding.
    expect(token).toHaveLength(43);
  });

  it("does not repeat", () => {
    const tokens = new Set(Array.from({ length: 200 }, () => generateCsrfToken()));
    expect(tokens.size).toBe(200);
  });
});

describe("csrfCookieOptions", () => {
  it("is readable by script, since the client must echo it", () => {
    // httpOnly would make the token unreadable by the very code that has to
    // send it back. This is the one cookie that is deliberately not HttpOnly.
    expect(csrfCookieOptions().httpOnly).toBe(false);
  });

  it("is SameSite=Strict, unlike the session cookie", () => {
    expect(csrfCookieOptions().sameSite).toBe("strict");
  });

  it("is Secure in production only", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(csrfCookieOptions().secure).toBe(true);
  });

  it("is not Secure outside production", () => {
    vi.stubEnv("NODE_ENV", "development");
    expect(csrfCookieOptions().secure).toBe(false);
  });
});

describe("safe methods", () => {
  it.each(["GET", "HEAD", "OPTIONS"])("does not require a token on %s", (method) => {
    expect(evaluateCsrf(request(method))).toEqual({ allowed: true, reason: "safe-method" });
  });
});

describe("acceptance", () => {
  it("accepts a request whose cookie and header match", () => {
    const token = generateCsrfToken();
    const decision = evaluateCsrf(
      request("POST", { [CSRF_HEADER_NAME]: token }, { [CSRF_COOKIE_NAME]: token }),
    );
    expect(decision).toEqual({ allowed: true, reason: "valid" });
  });

  it.each(["POST", "PUT", "PATCH", "DELETE"])("requires the token on %s", (method) => {
    const token = generateCsrfToken();
    const decision = evaluateCsrf(
      request(method, { [CSRF_HEADER_NAME]: token }, { [CSRF_COOKIE_NAME]: token }),
    );
    expect(decision.allowed).toBe(true);
  });
});

describe("rejections", () => {
  it("rejects a request with no cookie", () => {
    const token = generateCsrfToken();
    expect(evaluateCsrf(request("POST", { [CSRF_HEADER_NAME]: token }))).toEqual({
      allowed: false,
      reason: "missing-cookie",
    });
  });

  it("rejects a request with no header, which is what a cross-site form post looks like", () => {
    const token = generateCsrfToken();
    expect(evaluateCsrf(request("POST", {}, { [CSRF_COOKIE_NAME]: token }))).toEqual({
      allowed: false,
      reason: "missing-header",
    });
  });

  it("rejects a mismatched pair", () => {
    const decision = evaluateCsrf(
      request(
        "POST",
        { [CSRF_HEADER_NAME]: generateCsrfToken() },
        { [CSRF_COOKIE_NAME]: generateCsrfToken() },
      ),
    );
    expect(decision).toEqual({ allowed: false, reason: "mismatch" });
  });

  it("rejects a token that is a prefix of the real one", () => {
    const token = generateCsrfToken();
    const decision = evaluateCsrf(
      request("POST", { [CSRF_HEADER_NAME]: token.slice(0, -1) }, { [CSRF_COOKIE_NAME]: token }),
    );
    expect(decision.allowed).toBe(false);
  });

  it("rejects an empty header value", () => {
    const token = generateCsrfToken();
    expect(
      evaluateCsrf(request("POST", { [CSRF_HEADER_NAME]: "" }, { [CSRF_COOKIE_NAME]: token }))
        .allowed,
    ).toBe(false);
  });

  it("rejects an empty cookie value", () => {
    const token = generateCsrfToken();
    expect(
      evaluateCsrf(request("POST", { [CSRF_HEADER_NAME]: token }, { [CSRF_COOKIE_NAME]: "" }))
        .allowed,
    ).toBe(false);
  });
});
