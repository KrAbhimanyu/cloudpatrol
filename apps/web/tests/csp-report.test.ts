/**
 * CSP report parsing and redaction.
 *
 * A report is attacker-controlled input, so the properties that matter are the
 * negative ones: a query string never survives, a control character never
 * reaches a log line, an unbounded field is truncated, and an unknown shape is
 * dropped rather than passed through.
 */

import { describe, expect, it } from "vitest";

import {
  ACCEPTED_REPORT_TYPES,
  isSupportedContentType,
  MAX_REPORTS_PER_REQUEST,
  parseReportBody,
  redactUrl,
  sanitiseText,
} from "@/lib/security/reporting";

describe("redactUrl", () => {
  it("keeps scheme, host and path", () => {
    expect(redactUrl("https://app.example.test/dashboard")).toBe(
      "https://app.example.test/dashboard",
    );
  });

  it("drops the query string", () => {
    // The reason this function exists: a query string is the part of a URL most
    // likely to acquire a token later, and a report is a log line.
    expect(redactUrl("https://app.example.test/callback?token=secret&code=abc")).toBe(
      "https://app.example.test/callback",
    );
  });

  it("drops the fragment", () => {
    expect(redactUrl("https://app.example.test/page#section")).toBe(
      "https://app.example.test/page",
    );
  });

  it("drops credentials embedded in the URL", () => {
    expect(redactUrl("https://user:pass@app.example.test/x")).toBe("https://app.example.test/x");
  });

  it("keeps the port", () => {
    expect(redactUrl("http://localhost:3000/dashboard")).toBe("http://localhost:3000/dashboard");
  });

  it("reduces a schemeless-scheme URL such as data: to its scheme", () => {
    expect(redactUrl("data:text/html;base64,PHNjcmlwdD4=")).toBe("data:");
  });

  it("returns the scheme for about:blank", () => {
    expect(redactUrl("about:blank")).toBe("about:");
  });

  it.each([
    ["a relative path", "/dashboard"],
    ["an empty string", ""],
    ["a bare word", "not-a-url"],
    ["a number", 42],
    ["null", null],
    ["an object", { href: "https://x.test" }],
  ])("returns null for %s", (_label, value) => {
    expect(redactUrl(value)).toBeNull();
  });

  it("returns null for an over-long URL rather than truncating it into a different URL", () => {
    expect(redactUrl(`https://app.example.test/${"a".repeat(4000)}`)).toBeNull();
  });
});

describe("sanitiseText", () => {
  it("keeps ordinary text", () => {
    expect(sanitiseText("script-src 'self'")).toBe("script-src 'self'");
  });

  it("strips control characters that could forge a log line", () => {
    // A newline in a logged field is how one log entry becomes two.
    expect(sanitiseText("evil\n[error] forged entry")).toBe("evil[error] forged entry");
  });

  it("strips NUL and escape characters", () => {
    expect(sanitiseText("a\u0000b\u001bc")).toBe("abc");
  });

  it("returns null when only control characters remain", () => {
    expect(sanitiseText("\u0000\n\r")).toBeNull();
  });

  it("truncates an over-long value rather than dropping the report", () => {
    const result = sanitiseText("x".repeat(5000));
    expect(result).toHaveLength(512);
  });

  it.each([
    ["an empty string", ""],
    ["a number", 7],
    ["null", null],
    ["an array", ["a"]],
  ])("returns null for %s", (_label, value) => {
    expect(sanitiseText(value)).toBeNull();
  });
});

describe("isSupportedContentType", () => {
  it("accepts the legacy CSP content type", () => {
    expect(isSupportedContentType("application/csp-report")).toBe(true);
  });

  it("accepts the Reporting API content type", () => {
    expect(isSupportedContentType("application/reports+json")).toBe(true);
  });

  it("accepts a charset parameter", () => {
    expect(isSupportedContentType("application/csp-report; charset=UTF-8")).toBe(true);
  });

  it("ignores case and surrounding whitespace", () => {
    expect(isSupportedContentType("  Application/CSP-Report  ")).toBe(true);
  });

  it.each([
    ["JSON", "application/json"],
    ["form encoding", "application/x-www-form-urlencoded"],
    ["plain text", "text/plain"],
    ["a missing header", null],
    ["an empty string", ""],
  ])("rejects %s", (_label, value) => {
    expect(isSupportedContentType(value)).toBe(false);
  });
});

describe("parseReportBody: legacy report-uri format", () => {
  const legacy = {
    "csp-report": {
      "document-uri": "https://app.example.test/dashboard?token=leaky",
      referrer: "https://app.example.test/",
      "violated-directive": "script-src 'self'",
      "effective-directive": "script-src",
      "original-policy": "default-src 'self'; script-src 'self' 'nonce-abc'",
      disposition: "enforce",
      "blocked-uri": "https://evil.test/x.js",
      "status-code": 200,
      "script-sample": "",
    },
  };

  it("normalises the hyphenated field names", () => {
    const [violation] = parseReportBody(JSON.stringify(legacy)) ?? [];
    expect(violation).toMatchObject({
      kind: "csp-report",
      effectiveDirective: "script-src",
      violatedDirective: "script-src 'self'",
      disposition: "enforce",
      blockedUrl: "https://evil.test/x.js",
      statusCode: 200,
    });
  });

  it("redacts the document URL", () => {
    const [violation] = parseReportBody(JSON.stringify(legacy)) ?? [];
    expect(violation?.documentUrl).toBe("https://app.example.test/dashboard");
  });

  it("keeps 'inline' as the blocked value rather than trying to parse it as a URL", () => {
    const body = { "csp-report": { "effective-directive": "script-src", "blocked-uri": "inline" } };
    const [violation] = parseReportBody(JSON.stringify(body)) ?? [];
    expect(violation?.blockedUrl).toBe("inline");
  });

  it("keeps 'eval' as the blocked value", () => {
    const body = { "csp-report": { "blocked-uri": "eval" } };
    const [violation] = parseReportBody(JSON.stringify(body)) ?? [];
    expect(violation?.blockedUrl).toBe("eval");
  });

  it("drops an unknown field rather than logging it", () => {
    const body = { "csp-report": { "effective-directive": "script-src", exfiltrate: "secret" } };
    const [violation] = parseReportBody(JSON.stringify(body)) ?? [];
    expect(JSON.stringify(violation)).not.toContain("exfiltrate");
    expect(JSON.stringify(violation)).not.toContain("secret");
  });
});

describe("parseReportBody: Reporting API format", () => {
  const modern = [
    {
      type: "csp-violation",
      age: 10,
      url: "https://app.example.test/dashboard?token=leaky",
      user_agent: "Mozilla/5.0",
      body: {
        documentURL: "https://app.example.test/dashboard?token=leaky",
        referrer: "https://app.example.test/",
        blockedURL: "inline",
        effectiveDirective: "style-src",
        originalPolicy: "default-src 'self'",
        sample: "color: red",
        disposition: "enforce",
        statusCode: 200,
        lineNumber: 42,
        columnNumber: 7,
      },
    },
  ];

  it("normalises a batched array", () => {
    const violations = parseReportBody(JSON.stringify(modern)) ?? [];
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      kind: "csp-violation",
      effectiveDirective: "style-src",
      blockedUrl: "inline",
      lineNumber: 42,
      statusCode: 200,
      sample: "color: red",
    });
  });

  it("redacts the document URL", () => {
    const [violation] = parseReportBody(JSON.stringify(modern)) ?? [];
    expect(violation?.documentUrl).toBe("https://app.example.test/dashboard");
  });

  it("accepts a single unbatched entry", () => {
    const violations = parseReportBody(JSON.stringify(modern[0])) ?? [];
    expect(violations).toHaveLength(1);
  });

  it("keeps only the reports it understands from a mixed batch", () => {
    const mixed = [
      { type: "deprecation", body: { message: "old api" } },
      ...modern,
      { type: "intervention", body: {} },
    ];
    const violations = parseReportBody(JSON.stringify(mixed)) ?? [];
    expect(violations).toHaveLength(1);
    expect(violations[0]?.effectiveDirective).toBe("style-src");
  });

  it("only accepts csp-violation as a report type", () => {
    expect([...ACCEPTED_REPORT_TYPES]).toEqual(["csp-violation"]);
  });

  it("caps the number of reports examined in one request", () => {
    // A body under the size limit could still hold thousands of tiny objects.
    const flood = Array.from({ length: 500 }, () => modern[0]);
    const violations = parseReportBody(JSON.stringify(flood)) ?? [];
    expect(violations).toHaveLength(MAX_REPORTS_PER_REQUEST);
  });
});

describe("parseReportBody: hostile and malformed input", () => {
  it("returns null for a body that is not JSON", () => {
    expect(parseReportBody("<html>not json</html>")).toBeNull();
  });

  it("returns null for an empty body", () => {
    expect(parseReportBody("")).toBeNull();
  });

  it("returns null for a truncated JSON body", () => {
    expect(parseReportBody('{"csp-report": {')).toBeNull();
  });

  it("returns an empty list for JSON of the wrong shape", () => {
    expect(parseReportBody('"just a string"')).toEqual([]);
    expect(parseReportBody("42")).toEqual([]);
    expect(parseReportBody("null")).toEqual([]);
    expect(parseReportBody("{}")).toEqual([]);
  });

  it("returns an empty list for a legacy wrapper with no report inside", () => {
    expect(parseReportBody('{"csp-report": "not an object"}')).toEqual([]);
    expect(parseReportBody('{"csp-report": null}')).toEqual([]);
  });

  it("survives deeply nested input without recursing", () => {
    const nested = `${"[".repeat(50)}${"]".repeat(50)}`;
    expect(() => parseReportBody(nested)).not.toThrow();
  });

  it("tolerates wrong types on every field", () => {
    const body = {
      "csp-report": {
        "document-uri": 12345,
        "effective-directive": ["script-src"],
        "line-number": "not a number",
        "status-code": {},
        "script-sample": null,
        "original-policy": false,
      },
    };
    const [violation] = parseReportBody(JSON.stringify(body)) ?? [];
    expect(violation).toMatchObject({
      documentUrl: null,
      effectiveDirective: null,
      lineNumber: null,
      statusCode: null,
      sample: null,
      originalPolicy: null,
    });
  });

  it("does not treat a prototype-polluted key as a known field", () => {
    const body = { "csp-report": { "effective-directive": "script-src" }, __proto__: { evil: 1 } };
    const [violation] = parseReportBody(JSON.stringify(body)) ?? [];
    expect(violation?.effectiveDirective).toBe("script-src");
    expect(Object.prototype).not.toHaveProperty("evil");
  });

  it("rejects a NaN or Infinity line number", () => {
    const body = { "csp-report": { "line-number": Number.NaN } };
    // JSON.stringify turns NaN into null, so this arrives as null.
    const [violation] = parseReportBody(JSON.stringify(body)) ?? [];
    expect(violation?.lineNumber).toBeNull();
  });

  it("does not let an injected object reach the normalised output", () => {
    const body = {
      "csp-report": {
        "effective-directive": "script-src",
        "script-sample": { toString: "evil" },
      },
    };
    const [violation] = parseReportBody(JSON.stringify(body)) ?? [];
    // A non-string is discarded outright, so nothing object-shaped can be
    // carried into a log line or into a consumer that might call a method on it.
    expect(violation?.sample).toBeNull();
  });
});
