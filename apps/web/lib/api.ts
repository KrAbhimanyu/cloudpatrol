/**
 * API client for the CloudPatrol backend.
 *
 * Every call goes to this app's own `/api/proxy` route, not to the API host
 * directly. The browser therefore never holds or sends a bearer token: the
 * proxy route reads the HttpOnly session cookie and attaches the credential
 * server-side. No token is stored in module scope or in `localStorage`.
 *
 * Errors are never swallowed. A failed request surfaces as an `ApiError`
 * carrying the server's code and message, so the UI can show why something
 * failed instead of an empty table that looks like "no findings". A 401 is
 * reported distinctly, because "your session ended" and "you have no data"
 * must not look the same.
 */

import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "./security/constants";

import type {
  ApiErrorBody,
  AwsAccount,
  CostSummary,
  Finding,
  Organization,
  Paginated,
  SavingsBasis,
  SavingsEntry,
  SavingsLedger,
  Scan,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: Record<string, unknown>;
  readonly requestId: string | undefined;

  constructor(
    message: string,
    status: number,
    code: string,
    details: Record<string, unknown> = {},
    requestId?: string,
    cause?: unknown,
  ) {
    // The underlying failure is retained as `cause` so it can be inspected in
    // a debugger or log without leaking into the user-facing message.
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
  }

  /** True when the server rejected the session, not the request. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }
}

export interface RequestOptions {
  organizationId?: string;
  signal?: AbortSignal;
}

const PROXY_BASE = "/api/proxy";

/** Methods that need the CSRF token. Mirrors the server-side check. */
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Read the CSRF token the proxy placed in a non-HttpOnly cookie.
 *
 * Read on each call rather than cached: the token is rotated by the proxy, and
 * a cached value would go stale and start failing the check. A missing cookie
 * yields an empty string, and the request is still sent so the server can
 * return its own 403 rather than the client inventing a failure.
 */
function csrfToken(): string {
  if (typeof document === "undefined") return "";
  const prefix = `${CSRF_COOKIE_NAME}=`;
  for (const part of document.cookie.split("; ")) {
    if (part.startsWith(prefix)) {
      return decodeURIComponent(part.slice(prefix.length));
    }
  }
  return "";
}

async function request<T>(
  path: string,
  options: RequestOptions = {},
  init: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init.headers as Record<string, string>) ?? {}),
  };
  // The active workspace. Not a secret: FastAPI verifies membership, so a
  // tampered value yields 403 rather than another tenant's data.
  if (options.organizationId) {
    headers["X-Organization-Id"] = options.organizationId;
  }
  // Double-submit CSRF token. A cross-site request cannot set this header, so
  // its absence or mismatch is what the server rejects. An empty value is
  // omitted rather than sent, so the server sees a missing header and says so.
  const method = (init.method ?? "GET").toUpperCase();
  if (UNSAFE_METHODS.has(method)) {
    const token = csrfToken();
    if (token) headers[CSRF_HEADER_NAME] = token;
  }

  let response: Response;
  try {
    response = await fetch(`${PROXY_BASE}${path}`, {
      ...init,
      headers,
      signal: options.signal,
      // The session is per-user; a cached response must never be reused.
      cache: "no-store",
      credentials: "same-origin",
    });
  } catch (cause) {
    // A transport failure is reported as such; it must not be mistaken for an
    // empty result set.
    throw new ApiError(
      "Could not reach the CloudPatrol API. Check that the service is running.",
      0,
      "network_error",
      {},
      undefined,
      cause,
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      // A non-JSON body (an HTML error page from a proxy, say) must not crash
      // the client with a parse error.
      throw new ApiError(
        `The API returned an unreadable response (status ${response.status}).`,
        response.status,
        "invalid_response",
      );
    }
  }

  if (!response.ok) {
    const body = payload as ApiErrorBody | null;
    throw new ApiError(
      body?.error?.message ?? `Request failed with status ${response.status}.`,
      response.status,
      body?.error?.code ?? "unknown_error",
      body?.error?.details ?? {},
      body?.error?.request_id,
    );
  }

  return payload as T;
}

export const api = {
  listOrganizations: (options: RequestOptions = {}): Promise<Paginated<Organization>> =>
    request("/organizations", options),

  createOrganization: (
    options: RequestOptions,
    body: { name: string; slug: string },
  ): Promise<Organization> =>
    request("/organizations", options, { method: "POST", body: JSON.stringify(body) }),

  listAccounts: (options: RequestOptions = {}): Promise<Paginated<AwsAccount>> =>
    request("/aws/accounts", options),

  connectAccount: (
    options: RequestOptions,
    body: {
      label: string;
      account_id: string;
      role_arn: string;
      external_id: string;
      regions: string[];
    },
  ): Promise<AwsAccount> =>
    request("/aws/accounts", options, { method: "POST", body: JSON.stringify(body) }),

  listScans: (options: RequestOptions = {}): Promise<Paginated<Scan>> =>
    request("/scans", options),

  startScan: (options: RequestOptions, body: { aws_account_id: string }): Promise<Scan> =>
    request("/scans", options, { method: "POST", body: JSON.stringify(body) }),

  getScan: (options: RequestOptions, scanId: string): Promise<Scan> =>
    request(`/scans/${encodeURIComponent(scanId)}`, options),

  listFindings: (
    options: RequestOptions,
    filters: { state?: string; aws_account_id?: string } = {},
  ): Promise<Paginated<Finding>> => {
    const params = new URLSearchParams();
    if (filters.state) params.set("state", filters.state);
    if (filters.aws_account_id) params.set("aws_account_id", filters.aws_account_id);
    const query = params.toString();
    return request(`/findings${query ? `?${query}` : ""}`, options);
  },

  getFinding: (options: RequestOptions, findingId: string): Promise<Finding> =>
    request(`/findings/${encodeURIComponent(findingId)}`, options),

  reviewFinding: (
    options: RequestOptions,
    findingId: string,
    body: { state: "acknowledged" | "dismissed"; note?: string },
  ): Promise<Finding> =>
    request(`/findings/${encodeURIComponent(findingId)}`, options, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),

  savingsLedger: (options: RequestOptions = {}): Promise<SavingsLedger> =>
    request("/savings/ledger", options),

  advanceSavings: (
    options: RequestOptions,
    findingId: string,
    body: {
      target_basis: SavingsBasis;
      monthly_amount?: string;
      evidence?: Record<string, unknown>;
      measured_from?: string;
      measured_to?: string;
      note?: string;
    },
  ): Promise<SavingsEntry> =>
    request(`/savings/findings/${encodeURIComponent(findingId)}/advance`, options, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  costSummary: (
    options: RequestOptions,
    filters: { aws_account_id?: string } = {},
  ): Promise<CostSummary> => {
    const params = new URLSearchParams();
    if (filters.aws_account_id) params.set("aws_account_id", filters.aws_account_id);
    const query = params.toString();
    return request(`/costs/summary${query ? `?${query}` : ""}`, options);
  },
};
