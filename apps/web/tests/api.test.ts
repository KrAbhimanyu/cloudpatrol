/**
 * Tests for the API client.
 *
 * The behaviours that matter: calls go to the same-origin proxy rather than to
 * the API host, the client never attaches a credential, server error messages
 * reach the caller intact, and a transport failure is distinguishable from an
 * empty result.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api } from "@/lib/api";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function lastCall(): { url: string; init: RequestInit } {
  const [url, init] = fetchMock.mock.calls.at(-1) as [string, RequestInit];
  return { url, init };
}

describe("proxy routing", () => {
  it("calls the same-origin proxy, not the API host", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({});

    // The browser must never talk to the API directly: that is what allows the
    // token to stay in an HttpOnly cookie.
    expect(lastCall().url).toBe("/api/proxy/organizations");
  });

  it("never sends an Authorization header from the client", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({ organizationId: "org-9" });

    const headers = lastCall().init.headers as Record<string, string>;
    // If this ever appears, the token has leaked back into client JavaScript.
    expect(headers.Authorization).toBeUndefined();
    for (const key of Object.keys(headers)) {
      expect(key.toLowerCase()).not.toBe("authorization");
    }
  });

  it("sends the organization header when supplied", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({ organizationId: "org-9" });
    expect((lastCall().init.headers as Record<string, string>)["X-Organization-Id"]).toBe("org-9");
  });

  it("does not send an organization header when none is supplied", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({});
    expect((lastCall().init.headers as Record<string, string>)["X-Organization-Id"]).toBeUndefined();
  });

  it("sends same-origin credentials so the session cookie travels", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({});
    expect(lastCall().init.credentials).toBe("same-origin");
  });

  it("never caches a per-user response", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({});
    expect(lastCall().init.cache).toBe("no-store");
  });
});

describe("api.listOrganizations", () => {
  it("returns the parsed body", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ items: [{ id: "o1", name: "Acme", slug: "acme", role: "owner" }], total: 1 }),
    );
    const result = await api.listOrganizations({});
    expect(result.total).toBe(1);
    expect(result.items[0]?.name).toBe("Acme");
  });
});

describe("error handling", () => {
  it("surfaces the server error message and code", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "forbidden",
            message: "You are not a member of that organization.",
            details: {},
            request_id: "req-1",
          },
        },
        403,
      ),
    );

    await expect(api.listOrganizations({ organizationId: "org-9" })).rejects.toMatchObject({
      status: 403,
      code: "forbidden",
      message: "You are not a member of that organization.",
    });
  });

  it("marks a 401 as an authentication failure", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        { error: { code: "unauthenticated", message: "Session ended.", details: {} } },
        401,
      ),
    );

    const failure = await api.listOrganizations({}).catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).isUnauthenticated).toBe(true);
  });

  it("reports a transport failure as a network error, not as empty data", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    const failure = await api.listOrganizations({}).catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe("network_error");
    // Status 0 marks "never reached the server", which is distinct from 4xx/5xx.
    expect((failure as ApiError).status).toBe(0);
  });

  it("does not crash on a non-JSON error body", async () => {
    fetchMock.mockResolvedValue(
      new Response("<html>Bad gateway</html>", {
        status: 502,
        headers: { "Content-Type": "text/html" },
      }),
    );

    const failure = await api.listOrganizations({}).catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).code).toBe("invalid_response");
  });

  it("keeps the underlying cause for debugging", async () => {
    const cause = new TypeError("Failed to fetch");
    fetchMock.mockRejectedValue(cause);

    const failure = (await api.listOrganizations({}).catch((e: unknown) => e)) as ApiError;
    expect((failure as Error & { cause?: unknown }).cause).toBe(cause);
  });
});

describe("mutations", () => {
  it("sends a POST body to the proxied path", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ id: "s1" }));
    await api.startScan({ organizationId: "org-1" }, { aws_account_id: "a1" });

    const { url, init } = lastCall();
    expect(url).toBe("/api/proxy/scans");
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ aws_account_id: "a1" }));
  });

  it("encodes identifiers placed in the path", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ id: "s1" }));
    await api.getFinding({ organizationId: "org-1" }, "id/with/slash");

    expect(lastCall().url).toBe("/api/proxy/findings/id%2Fwith%2Fslash");
  });

  it("builds a query string for filters", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listFindings({ organizationId: "org-1" }, { state: "estimated" });

    expect(lastCall().url).toBe("/api/proxy/findings?state=estimated");
  });

  it("returns undefined for a 204 response", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(api.listOrganizations({})).resolves.toBeUndefined();
  });
});

describe("CSRF token", () => {
  const TOKEN = "csrf-token-value";

  function withCsrfCookie(value = TOKEN) {
    vi.stubGlobal("document", { cookie: `other=1; cloudpatrol.csrf=${value}; another=2` });
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends the token from the cookie on a POST", async () => {
    withCsrfCookie();
    fetchMock.mockResolvedValue(jsonResponse({ id: "s1" }));

    await api.startScan({ organizationId: "org-1" }, { aws_account_id: "a1" });

    const headers = lastCall().init.headers as Record<string, string>;
    expect(headers["x-csrf-token"]).toBe(TOKEN);
  });

  it("sends the token on PATCH and DELETE", async () => {
    withCsrfCookie();
    fetchMock.mockResolvedValue(jsonResponse({ id: "f1" }));
    await api.reviewFinding({}, "f1", { state: "dismissed" });
    expect((lastCall().init.headers as Record<string, string>)["x-csrf-token"]).toBe(TOKEN);
  });

  it("does not send the token on a GET, which needs none", async () => {
    withCsrfCookie();
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));

    await api.listOrganizations({});

    const headers = lastCall().init.headers as Record<string, string>;
    expect(headers["x-csrf-token"]).toBeUndefined();
  });

  it("omits the header when the cookie is absent, rather than sending an empty value", async () => {
    vi.stubGlobal("document", { cookie: "other=1" });
    fetchMock.mockResolvedValue(jsonResponse({ id: "s1" }));

    await api.startScan({}, { aws_account_id: "a1" });

    const headers = lastCall().init.headers as Record<string, string>;
    // The server reports a missing header distinctly from a mismatch; an empty
    // string would blur the two.
    expect(headers["x-csrf-token"]).toBeUndefined();
  });

  it("url-decodes the cookie value", async () => {
    withCsrfCookie("a%2Bb");
    fetchMock.mockResolvedValue(jsonResponse({ id: "s1" }));

    await api.startScan({}, { aws_account_id: "a1" });

    expect((lastCall().init.headers as Record<string, string>)["x-csrf-token"]).toBe("a+b");
  });
});

