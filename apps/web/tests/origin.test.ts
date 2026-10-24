/**
 * Origin-validation policy.
 *
 * The policy has to be exact, because the failure mode of a sloppy origin
 * check is not "it breaks" but "it silently accepts". These tests pin every
 * branch of `evaluateOrigin`, including the ones that reject.
 */

import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { evaluateOrigin, isUnsafeMethod, trustedOriginsFor } from "@/lib/security/origin";

const APP = "https://app.example.test";

function request(
  method: string,
  headers: Record<string, string> = {},
  url = "/api/proxy/organizations",
): NextRequest {
  return new NextRequest(new URL(url, APP), { method, headers });
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("isUnsafeMethod", () => {
  it.each(["POST", "PUT", "PATCH", "DELETE"])("treats %s as unsafe", (method) => {
    expect(isUnsafeMethod(method)).toBe(true);
  });

  it.each(["GET", "HEAD", "OPTIONS"])("treats %s as safe", (method) => {
    expect(isUnsafeMethod(method)).toBe(false);
  });

  it("is case-insensitive", () => {
    expect(isUnsafeMethod("post")).toBe(true);
  });
});

describe("safe methods", () => {
  it("allows a GET from another origin, because it cannot change state", () => {
    const decision = evaluateOrigin(request("GET", { origin: "https://evil.test" }));
    expect(decision).toEqual({ allowed: true, reason: "safe-method" });
  });
});

describe("trusted origins", () => {
  it("trusts the app's own origin", () => {
    expect(evaluateOrigin(request("POST", { origin: APP }))).toEqual({
      allowed: true,
      reason: "same-origin",
    });
  });

  it("trusts an origin listed in APP_ORIGINS", () => {
    vi.stubEnv("APP_ORIGINS", "https://staging.example.test");
    expect(evaluateOrigin(request("POST", { origin: "https://staging.example.test" }))).toEqual({
      allowed: true,
      reason: "allow-listed",
    });
  });

  it("accepts a comma-separated APP_ORIGINS list with surrounding whitespace", () => {
    vi.stubEnv("APP_ORIGINS", " https://a.test , https://b.test ");
    const trusted = trustedOriginsFor(request("POST"));
    expect(trusted.has("https://a.test")).toBe(true);
    expect(trusted.has("https://b.test")).toBe(true);
  });

  it("tolerates a trailing slash in APP_ORIGINS", () => {
    vi.stubEnv("APP_ORIGINS", "https://a.test/");
    expect(evaluateOrigin(request("POST", { origin: "https://a.test" })).allowed).toBe(true);
  });

  it("ignores empty entries in APP_ORIGINS", () => {
    vi.stubEnv("APP_ORIGINS", ",,,");
    const trusted = trustedOriginsFor(request("POST"));
    expect(trusted.size).toBe(1);
  });
});

describe("rejections", () => {
  it("rejects a POST from an untrusted origin", () => {
    const decision = evaluateOrigin(request("POST", { origin: "https://evil.test" }));
    expect(decision).toEqual({ allowed: false, reason: "untrusted-origin" });
  });

  it("rejects the literal 'null' origin a sandboxed frame sends", () => {
    const decision = evaluateOrigin(request("POST", { origin: "null" }));
    expect(decision).toEqual({ allowed: false, reason: "malformed-origin" });
  });

  it("rejects a malformed Origin", () => {
    expect(evaluateOrigin(request("POST", { origin: "not a url" })).reason).toBe("malformed-origin");
  });

  it("rejects an Origin that smuggles a path", () => {
    expect(evaluateOrigin(request("POST", { origin: `${APP}/evil` })).reason).toBe(
      "malformed-origin",
    );
  });

  it("rejects an Origin carrying credentials", () => {
    expect(
      evaluateOrigin(request("POST", { origin: "https://user:pass@app.example.test" })).reason,
    ).toBe("malformed-origin");
  });

  it("rejects a cross-origin request that omits Origin entirely", () => {
    // No Origin and no Sec-Fetch-Site: no evidence of provenance at all.
    expect(evaluateOrigin(request("POST"))).toEqual({ allowed: false, reason: "missing-origin" });
  });

  it("rejects when Sec-Fetch-Site says the request is cross-site", () => {
    expect(evaluateOrigin(request("POST", { "sec-fetch-site": "cross-site" })).reason).toBe(
      "missing-origin",
    );
  });

  it("rejects when Sec-Fetch-Site is same-site but not same-origin", () => {
    // A sibling subdomain is a different origin and must not be trusted.
    expect(evaluateOrigin(request("POST", { "sec-fetch-site": "same-site" })).reason).toBe(
      "missing-origin",
    );
  });
});

describe("missing Origin with browser evidence", () => {
  it("allows a same-origin request that omitted Origin but set Sec-Fetch-Site", () => {
    expect(evaluateOrigin(request("POST", { "sec-fetch-site": "same-origin" }))).toEqual({
      allowed: true,
      reason: "missing-origin-same-site",
    });
  });

  it("still rejects a cross-site request that supplies a spoofed Origin", () => {
    // Sec-Fetch-Site cannot be set by page script, and it says cross-site, but
    // the check here is on Origin, which is the attacker's. Rejected because it
    // is not trusted, which is the correct outcome either way.
    const decision = evaluateOrigin(
      request("POST", { origin: "https://evil.test", "sec-fetch-site": "cross-site" }),
    );
    expect(decision.allowed).toBe(false);
  });

  it("does not let a same-origin Sec-Fetch-Site override an untrusted Origin", () => {
    // If Origin is present it is authoritative: the header was actually sent,
    // so a lie in Sec-Fetch-Site must not rescue it.
    const decision = evaluateOrigin(
      request("POST", { origin: "https://evil.test", "sec-fetch-site": "same-origin" }),
    );
    expect(decision).toEqual({ allowed: false, reason: "untrusted-origin" });
  });
});

describe("port handling", () => {
  it("treats a different port as a different origin", () => {
    expect(evaluateOrigin(request("POST", { origin: "https://app.example.test:8443" })).allowed).toBe(
      false,
    );
  });

  it("matches the origin including the port when one is used", () => {
    const withPort = new NextRequest(new URL("/api/proxy/organizations", "http://localhost:3000"), {
      method: "POST",
      headers: { origin: "http://localhost:3000" },
    });
    expect(evaluateOrigin(withPort).allowed).toBe(true);
  });
});
