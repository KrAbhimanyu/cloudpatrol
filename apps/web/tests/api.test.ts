/**
 * Tests for the API client.
 *
 * The behaviours that matter: server error messages reach the caller intact,
 * a transport failure is distinguishable from an empty result, the
 * organization header is only sent when known, and no token is cached.
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

describe("api.listOrganizations", () => {
  it("sends the bearer token", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({ token: "tok-123" });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer tok-123");
  });

  it("does not send an organization header when none is supplied", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({ token: "tok-123" });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["X-Organization-Id"]).toBeUndefined();
  });

  it("sends the organization header when supplied", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listOrganizations({ token: "tok-123", organizationId: "org-9" });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["X-Organization-Id"]).toBe("org-9");
  });

  it("returns the parsed body", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ items: [{ id: "o1", name: "Acme", slug: "acme", role: "owner" }], total: 1 }),
    );
    const result = await api.listOrganizations({ token: "t" });
    expect(result.total).toBe(1);
    expect(result.items[0]?.name).toBe("Acme");
  });
});

describe("error handling", () => {
  it("surfaces the server error message and code", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        { error: { code: "forbidden", message: "You are not a member of this workspace." } },
        403,
      ),
    );

    await expect(api.listOrganizations({ token: "t" })).rejects.toThrow(
      "You are not a member of this workspace.",
    );
  });

  it("exposes the status and code on the error", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ error: { code: "forbidden", message: "nope" } }, 403),
    );

    try {
      await api.listOrganizations({ token: "t" });
      throw new Error("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      const apiError = error as ApiError;
      expect(apiError.status).toBe(403);
      expect(apiError.code).toBe("forbidden");
    }
  });

  it("reports a transport failure distinctly from an empty result", async () => {
    // This distinction matters: an unreachable API must not render as
    // "no findings".
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    await expect(api.listOrganizations({ token: "t" })).rejects.toThrow(/Could not reach/);
    try {
      await api.listOrganizations({ token: "t" });
    } catch (error) {
      expect((error as ApiError).code).toBe("network_error");
      expect((error as ApiError).status).toBe(0);
    }
  });

  it("includes the request id from the error body", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        { error: { code: "internal_error", message: "boom", request_id: "req-42" } },
        500,
      ),
    );

    try {
      await api.listOrganizations({ token: "t" });
    } catch (error) {
      expect((error as ApiError).requestId).toBe("req-42");
    }
  });
});

describe("api.startScan", () => {
  it("posts the account id and accepts a queued scan", async () => {
    // The API accepts the job with 202 and returns it queued; the client polls
    // getScan for the outcome.
    fetchMock.mockResolvedValue(jsonResponse({ id: "s1", status: "queued" }, 202));
    await api.startScan({ token: "t", organizationId: "o1" }, { aws_account_id: "acct-1" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/scans");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ aws_account_id: "acct-1" });
  });

  it("surfaces a conflict when a scan is already running", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "conflict",
            message: "A scan for this account is already in progress.",
            details: { scan_id: "s-existing" },
          },
        },
        409,
      ),
    );

    try {
      await api.startScan({ token: "t" }, { aws_account_id: "acct-1" });
      throw new Error("should have thrown");
    } catch (error) {
      const apiError = error as ApiError;
      expect(apiError.status).toBe(409);
      expect(apiError.details.scan_id).toBe("s-existing");
    }
  });
});

describe("api.reviewFinding", () => {
  it("patches the finding state", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ id: "f1", state: "acknowledged" }));
    await api.reviewFinding({ token: "t" }, "f1", { state: "acknowledged", note: "ok" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/findings/f1");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({ state: "acknowledged", note: "ok" });
  });

  it("encodes identifiers placed in the path", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ id: "x" }));
    await api.getFinding({ token: "t" }, "id/with/slash");

    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain("id%2Fwith%2Fslash");
  });
});

describe("api.listFindings", () => {
  it("builds a query string from filters", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listFindings({ token: "t" }, { state: "estimated", aws_account_id: "a1" });

    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain("state=estimated");
    expect(url).toContain("aws_account_id=a1");
  });

  it("sends no query string when there are no filters", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await api.listFindings({ token: "t" });

    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url.endsWith("/api/v1/findings")).toBe(true);
  });
});
