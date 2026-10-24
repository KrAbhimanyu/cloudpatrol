/**
 * Tests for the BFF proxy route.
 *
 * The route is the security-critical seam of this phase: it is where the
 * HttpOnly session becomes an `Authorization` header that the browser never
 * sees. These tests exercise the real handler, mocking only the session lookup
 * (which needs a live Supabase project).
 */

import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getAccessToken = vi.fn();

vi.mock("@/lib/supabase/server", () => ({
  getAccessToken: () => getAccessToken(),
}));

const { GET, POST, DELETE } = await import("@/app/api/proxy/[...path]/route");

const fetchMock = vi.fn();

beforeEach(() => {
  getAccessToken.mockReset();
  // A session by default; tests that need the unauthenticated path override it.
  getAccessToken.mockResolvedValue("session-token");
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "https://api.example.test");
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

function makeRequest(
  url: string,
  { method = "GET", headers = {} as Record<string, string> } = {},
): NextRequest {
  return new NextRequest(new URL(url, "https://app.example.test"), { method, headers });
}

/**
 * A request as the browser would actually send it: same-origin, and carrying
 * the CSRF cookie/header pair on an unsafe method. Without these the proxy
 * rejects the request before it reaches the forwarding logic under test.
 */
const CSRF = "test-csrf-token";

const APP = "https://app.example.test";

function browserRequest(
  url: string,
  {
    method = "GET",
    headers = {} as Record<string, string>,
    body,
  }: { method?: string; headers?: Record<string, string>; body?: string } = {},
): NextRequest {
  const merged: Record<string, string> = { origin: "https://app.example.test", ...headers };
  if (method !== "GET" && method !== "HEAD") {
    merged["x-csrf-token"] = CSRF;
    merged.cookie = `cloudpatrol.csrf=${CSRF}`;
  }
  return new NextRequest(new URL(url, "https://app.example.test"), {
    method,
    headers: merged,
    body,
  });
}

function context(path: string[]) {
  return { params: Promise.resolve({ path }) };
}

describe("authentication", () => {
  it("returns 401 without calling the API when there is no session", async () => {
    getAccessToken.mockResolvedValue(null);

    const response = await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));

    expect(response.status).toBe(401);
    // No upstream call at all: an unauthenticated request must not reach the API.
    expect(fetchMock).not.toHaveBeenCalled();
    const body = await response.json();
    expect(body.error.code).toBe("unauthenticated");
  });
});

describe("forwarding", () => {
  beforeEach(() => {
    getAccessToken.mockResolvedValue("session-token");
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
  });

  it("attaches the bearer token server-side", async () => {
    await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));

    const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect(url.toString()).toBe("https://api.example.test/api/v1/organizations");
    expect((init.headers as Headers).get("Authorization")).toBe("Bearer session-token");
  });

  it("never trusts a client-supplied Authorization header", async () => {
    await GET(
      makeRequest("/api/proxy/organizations", {
        headers: { authorization: "Bearer attacker-token" },
      }),
      context(["organizations"]),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    // The session wins; a client header must not be able to override it.
    expect((init.headers as Headers).get("Authorization")).toBe("Bearer session-token");
  });

  it("forwards the organization header", async () => {
    await GET(
      makeRequest("/api/proxy/organizations", { headers: { "x-organization-id": "org-9" } }),
      context(["organizations"]),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Headers).get("X-Organization-Id")).toBe("org-9");
  });

  it("does not forward the session cookie upstream", async () => {
    await GET(
      makeRequest("/api/proxy/organizations", { headers: { cookie: "sb-token=secret" } }),
      context(["organizations"]),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    // The cookie is this app's session; the API authenticates by bearer token.
    expect((init.headers as Headers).get("cookie")).toBeNull();
  });

  it("preserves query parameters", async () => {
    await GET(makeRequest("/api/proxy/findings?state=estimated"), context(["findings"]));

    const [url] = fetchMock.mock.calls[0] as [URL];
    expect(url.toString()).toBe("https://api.example.test/api/v1/findings?state=estimated");
  });

  it("encodes path segments", async () => {
    await GET(makeRequest("/api/proxy/findings/a b"), context(["findings", "a b"]));

    const [url] = fetchMock.mock.calls[0] as [URL];
    expect(url.toString()).toBe("https://api.example.test/api/v1/findings/a%20b");
  });

  it("forwards a request body on POST", async () => {
    await POST(
      browserRequest("/api/proxy/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ aws_account_id: "a1" }),
      }),
      context(["scans"]),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("POST");
    expect(new TextDecoder().decode(init.body as ArrayBuffer)).toBe(
      JSON.stringify({ aws_account_id: "a1" }),
    );
  });

  it("marks the response private so a shared cache cannot store it", async () => {
    const response = await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
  });

  it("strips hop-by-hop headers from the upstream response", async () => {
    fetchMock.mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json", "Set-Cookie": "leak=1" },
      }),
    );

    const response = await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  it("passes through the upstream status and body", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: { code: "forbidden" } }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const response = await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: { code: "forbidden" } });
  });

  it("reports an unreachable API as 502 rather than as success", async () => {
    fetchMock.mockRejectedValue(new TypeError("connect ECONNREFUSED"));

    const response = await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));
    expect(response.status).toBe(502);
    expect((await response.json()).error.code).toBe("network_error");
  });

  it("does not follow an upstream redirect", async () => {
    await DELETE(
      browserRequest("/api/proxy/scans/s1", { method: "DELETE" }),
      context(["scans", "s1"]),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    // Following a redirect would silently convert the call into a GET against
    // another path, losing the intent of the original method.
    expect(init.redirect).toBe("manual");
  });
});

describe("CSRF and origin enforcement", () => {
  it("rejects a cross-site POST before reaching the API", async () => {
    const response = await POST(
      new NextRequest(new URL("/api/proxy/scans", APP), {
        method: "POST",
        headers: { origin: "https://evil.test", "content-type": "application/json" },
        body: "{}",
      }),
      context(["scans"]),
    );

    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("forbidden_origin");
    // The point of rejecting early: no upstream call, no token use.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an unsafe request with no Origin and no browser evidence", async () => {
    const response = await POST(
      new NextRequest(new URL("/api/proxy/scans", APP), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
      context(["scans"]),
    );

    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("forbidden_origin");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("accepts a same-origin POST that omitted Origin but set Sec-Fetch-Site", async () => {
    fetchMock.mockResolvedValue(new Response("{}", { status: 200 }));

    const response = await POST(
      new NextRequest(new URL("/api/proxy/scans", APP), {
        method: "POST",
        headers: {
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
          "x-csrf-token": CSRF,
          cookie: `cloudpatrol.csrf=${CSRF}`,
        },
        body: "{}",
      }),
      context(["scans"]),
    );

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalled();
  });

  it("rejects a same-origin POST with no CSRF header", async () => {
    const response = await POST(
      new NextRequest(new URL("/api/proxy/scans", APP), {
        method: "POST",
        headers: { origin: APP, "content-type": "application/json" },
        body: "{}",
      }),
      context(["scans"]),
    );

    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("csrf_failed");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a same-origin POST whose CSRF header does not match the cookie", async () => {
    const response = await POST(
      new NextRequest(new URL("/api/proxy/scans", APP), {
        method: "POST",
        headers: {
          origin: APP,
          "content-type": "application/json",
          "x-csrf-token": "attacker-guess",
          cookie: `cloudpatrol.csrf=${CSRF}`,
        },
        body: "{}",
      }),
      context(["scans"]),
    );

    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("csrf_failed");
  });

  it("checks origin before CSRF, so a cross-site request is refused on origin alone", async () => {
    const response = await POST(
      new NextRequest(new URL("/api/proxy/scans", APP), {
        method: "POST",
        headers: { origin: "https://evil.test", "content-type": "application/json" },
        body: "{}",
      }),
      context(["scans"]),
    );

    // Even though no CSRF token was supplied either, the reported reason is
    // the origin: the cheaper check runs first.
    expect((await response.json()).error.code).toBe("forbidden_origin");
  });

  it("allows a GET without a CSRF token, because it cannot change state", async () => {
    fetchMock.mockResolvedValue(new Response("{}", { status: 200 }));

    const response = await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));

    expect(response.status).toBe(200);
  });

  it("does not forward the CSRF header to the API", async () => {
    fetchMock.mockResolvedValue(new Response("{}", { status: 200 }));

    await POST(browserRequest("/api/proxy/scans", { method: "POST", body: "{}" }), context(["scans"]));

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = new Headers(init.headers as HeadersInit);
    expect(sent.get("x-csrf-token")).toBeNull();
  });

  it("does not forward the session cookie to the API", async () => {
    fetchMock.mockResolvedValue(new Response("{}", { status: 200 }));

    await GET(makeRequest("/api/proxy/organizations"), context(["organizations"]));

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = new Headers(init.headers as HeadersInit);
    expect(sent.get("cookie")).toBeNull();
  });

  it("replaces a client-supplied Authorization header with the session token", async () => {
    getAccessToken.mockResolvedValue("real-session-token");
    fetchMock.mockResolvedValue(new Response("{}", { status: 200 }));

    await GET(
      makeRequest("/api/proxy/organizations", {
        headers: { authorization: "Bearer attacker-supplied" },
      }),
      context(["organizations"]),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = new Headers(init.headers as HeadersInit);
    expect(sent.get("authorization")).toBe("Bearer real-session-token");
  });

  it("does not forward client-supplied forwarding headers", async () => {
    fetchMock.mockResolvedValue(new Response("{}", { status: 200 }));

    await GET(
      makeRequest("/api/proxy/organizations", {
        headers: { "x-forwarded-for": "10.0.0.1", "x-forwarded-host": "spoofed.test" },
      }),
      context(["organizations"]),
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const sent = new Headers(init.headers as HeadersInit);
    expect(sent.get("x-forwarded-for")).toBeNull();
    expect(sent.get("x-forwarded-host")).toBeNull();
  });

  it("marks a rejection private so it cannot be cached as a success", async () => {
    const response = await POST(
      new NextRequest(new URL("/api/proxy/scans", APP), {
        method: "POST",
        headers: { origin: "https://evil.test", "content-type": "application/json" },
        body: "{}",
      }),
      context(["scans"]),
    );

    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
  });
});

describe("authentication ordering", () => {
  it("rejects an unauthenticated same-origin POST with 401, after the CSRF check passes", async () => {
    getAccessToken.mockResolvedValue(null);

    const response = await POST(
      browserRequest("/api/proxy/scans", { method: "POST", body: "{}" }),
      context(["scans"]),
    );

    expect(response.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
