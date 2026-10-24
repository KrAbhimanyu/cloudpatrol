/**
 * Security header and CSP construction.
 *
 * The CSP is asserted directive by directive rather than as one long string,
 * so a change to an unrelated directive does not silently pass and a change to
 * a load-bearing one cannot hide.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  contentSecurityPolicy,
  generateNonce,
  isSensitivePath,
  reportingEndpointsHeader,
  staticSecurityHeaders,
} from "@/lib/security/headers";
import { CSP_REPORT_ENDPOINT_NAME } from "@/lib/security/reporting";

afterEach(() => {
  vi.unstubAllEnvs();
});

/** Split a policy into `directive -> value` for precise assertions. */
function directives(policy: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of policy.split(";")) {
    const [name, ...rest] = part.trim().split(/\s+/);
    if (name) map.set(name, rest.join(" "));
  }
  return map;
}

describe("generateNonce", () => {
  it("is 128 bits of base64", () => {
    // 16 bytes -> 24 base64 characters with padding.
    expect(generateNonce()).toHaveLength(24);
  });

  it("does not repeat", () => {
    const nonces = new Set(Array.from({ length: 500 }, () => generateNonce()));
    expect(nonces.size).toBe(500);
  });

  it("contains no characters that would break out of a header", () => {
    for (let i = 0; i < 100; i += 1) {
      expect(generateNonce()).toMatch(/^[A-Za-z0-9+/=]+$/);
    }
  });
});

describe("contentSecurityPolicy", () => {
  it("uses the nonce for scripts", () => {
    const nonce = generateNonce();
    expect(directives(contentSecurityPolicy(nonce)).get("script-src")).toContain(`'nonce-${nonce}'`);
  });

  it("does not allow unsafe-inline for scripts", () => {
    // unsafe-inline would defeat the point of the nonce: an injected inline
    // script would be authorised alongside the framework's own.
    expect(contentSecurityPolicy(generateNonce())).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(directives(contentSecurityPolicy(generateNonce())).get("script-src")).not.toContain(
      "'unsafe-inline'",
    );
  });

  it("does not allow unsafe-eval in production", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(directives(contentSecurityPolicy(generateNonce())).get("script-src")).not.toContain(
      "'unsafe-eval'",
    );
  });

  it("allows unsafe-eval only in development, where React needs it", () => {
    vi.stubEnv("NODE_ENV", "development");
    expect(directives(contentSecurityPolicy(generateNonce())).get("script-src")).toContain(
      "'unsafe-eval'",
    );
  });

  it("uses strict-dynamic so nonce'd scripts can load the bundle", () => {
    expect(directives(contentSecurityPolicy(generateNonce())).get("script-src")).toContain(
      "'strict-dynamic'",
    );
  });

  it("uses the nonce for style elements", () => {
    const nonce = generateNonce();
    expect(directives(contentSecurityPolicy(nonce)).get("style-src")).toBe(`'self' 'nonce-${nonce}'`);
  });

  it("permits inline style attributes, which a nonce cannot cover", () => {
    // Documented exception: React's `style` prop renders an attribute, not a
    // <style> element, so it is governed by style-src-attr. Scoped there so
    // style-src itself stays nonce-only.
    const map = directives(contentSecurityPolicy(generateNonce()));
    expect(map.get("style-src-attr")).toBe("'unsafe-inline'");
    expect(map.get("style-src")).not.toContain("'unsafe-inline'");
  });

  it("restricts default-src to self", () => {
    expect(directives(contentSecurityPolicy(generateNonce())).get("default-src")).toBe("'self'");
  });

  it("blocks framing", () => {
    expect(directives(contentSecurityPolicy(generateNonce())).get("frame-ancestors")).toBe("'none'");
  });

  it("blocks plugins", () => {
    expect(directives(contentSecurityPolicy(generateNonce())).get("object-src")).toBe("'none'");
  });

  it("restricts form submissions to this origin", () => {
    expect(directives(contentSecurityPolicy(generateNonce())).get("form-action")).toBe("'self'");
  });

  it("restricts base-uri, which would otherwise allow a tag-injection hijack", () => {
    expect(directives(contentSecurityPolicy(generateNonce())).get("base-uri")).toBe("'self'");
  });

  it("keeps connect-src to self, because every call goes through the BFF", () => {
    expect(directives(contentSecurityPolicy(generateNonce())).get("connect-src")).toBe("'self'");
  });

  it("upgrades insecure requests", () => {
    expect(contentSecurityPolicy(generateNonce())).toContain("upgrade-insecure-requests");
  });

  it("embeds no literal newline, which would truncate the header", () => {
    expect(contentSecurityPolicy(generateNonce())).not.toContain("\n");
  });

  it("produces a different policy for a different nonce", () => {
    expect(contentSecurityPolicy(generateNonce())).not.toBe(contentSecurityPolicy(generateNonce()));
  });
});

describe("reporting directives", () => {
  const ORIGIN = "https://app.example.test";

  it("omits reporting directives when no origin is given", () => {
    // Keeps the function usable without an origin, so a caller cannot
    // accidentally emit a report-uri pointing at the literal string "undefined".
    const policy = contentSecurityPolicy(generateNonce());
    expect(policy).not.toContain("report-uri");
    expect(policy).not.toContain("report-to");
  });

  it("adds report-uri pointing at this origin's endpoint", () => {
    const map = directives(contentSecurityPolicy(generateNonce(), ORIGIN));
    expect(map.get("report-uri")).toBe(`${ORIGIN}/api/csp-report`);
  });

  it("adds report-to naming the declared endpoint", () => {
    const map = directives(contentSecurityPolicy(generateNonce(), ORIGIN));
    expect(map.get("report-to")).toBe(CSP_REPORT_ENDPOINT_NAME);
  });

  it("sends both, because report-uri only applies when report-to is absent", () => {
    const map = directives(contentSecurityPolicy(generateNonce(), ORIGIN));
    expect(map.has("report-uri")).toBe(true);
    expect(map.has("report-to")).toBe(true);
  });

  it("never points the report endpoint at another origin", () => {
    const map = directives(contentSecurityPolicy(generateNonce(), ORIGIN));
    expect(map.get("report-uri")).toContain(ORIGIN);
  });

  it("keeps the endpoint same-origin, so connect-src needs no change", () => {
    const map = directives(contentSecurityPolicy(generateNonce(), ORIGIN));
    expect(map.get("connect-src")).toBe("'self'");
  });

  it("declares the endpoint that report-to names", () => {
    const header = reportingEndpointsHeader(ORIGIN);
    expect(header.key).toBe("Reporting-Endpoints");
    expect(header.value).toBe(`${CSP_REPORT_ENDPOINT_NAME}="${ORIGIN}/api/csp-report"`);
  });

  it("quotes the endpoint URL, as the header grammar requires", () => {
    expect(reportingEndpointsHeader(ORIGIN).value).toMatch(/="[^"]+"$/);
  });

  it("does not weaken enforcement by switching to report-only", () => {
    // Reporting is additive. If this ever becomes Report-Only, every other test
    // in this file would still pass while the policy stopped blocking anything.
    expect(contentSecurityPolicy(generateNonce(), ORIGIN)).not.toContain("Report-Only");
  });

  it("leaves every blocking directive intact when reporting is enabled", () => {
    const withReporting = directives(contentSecurityPolicy(generateNonce(), ORIGIN));
    const without = directives(contentSecurityPolicy(generateNonce()));

    // Every directive present without reporting must be byte-identical with it,
    // apart from the nonce, which differs per call.
    const nonceOf = (map: Map<string, string>) => map.get("script-src")?.match(/'nonce-[^']+'/)?.[0];
    expect(nonceOf(withReporting)).toBeTruthy();

    for (const [name, value] of without) {
      if (name === "script-src" || name === "style-src") continue;
      expect(withReporting.get(name), `directive ${name} changed`).toBe(value);
    }
    // The two nonce-bearing directives differ only in the nonce value itself.
    expect(withReporting.get("script-src")?.replace(/'nonce-[^']+'/, "")).toBe(
      without.get("script-src")?.replace(/'nonce-[^']+'/, ""),
    );
    expect(withReporting.get("style-src")?.replace(/'nonce-[^']+'/, "")).toBe(
      without.get("style-src")?.replace(/'nonce-[^']+'/, ""),
    );
  });
});

describe("staticSecurityHeaders", () => {
  function headerMap(): Map<string, string> {
    return new Map(staticSecurityHeaders().map(({ key, value }) => [key, value]));
  }

  it("sets nosniff", () => {
    expect(headerMap().get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("sets a referrer policy that does not leak paths", () => {
    expect(headerMap().get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
  });

  it("denies framing for browsers that predate frame-ancestors", () => {
    expect(headerMap().get("X-Frame-Options")).toBe("DENY");
  });

  it("disables unused browser features", () => {
    const policy = headerMap().get("Permissions-Policy") ?? "";
    expect(policy).toContain("camera=()");
    expect(policy).toContain("microphone=()");
    expect(policy).toContain("geolocation=()");
  });

  it("isolates the browsing context", () => {
    expect(headerMap().get("Cross-Origin-Opener-Policy")).toBe("same-origin");
  });

  it("omits HSTS outside production", () => {
    vi.stubEnv("NODE_ENV", "development");
    expect(headerMap().has("Strict-Transport-Security")).toBe(false);
  });

  it("sets HSTS in production, without preload", () => {
    vi.stubEnv("NODE_ENV", "production");
    const hsts = headerMap().get("Strict-Transport-Security") ?? "";
    expect(hsts).toContain("max-age=");
    expect(hsts).toContain("includeSubDomains");
    // preload is a near-permanent commitment and is deliberately not sent.
    expect(hsts).not.toContain("preload");
  });
});

describe("isSensitivePath", () => {
  it.each(["/sign-in", "/sign-in/reset", "/api/proxy/organizations"])(
    "treats %s as sensitive",
    (path) => {
      expect(isSensitivePath(path)).toBe(true);
    },
  );

  it.each(["/dashboard", "/", "/findings"])("treats %s as not sensitive", (path) => {
    expect(isSensitivePath(path)).toBe(false);
  });
});
