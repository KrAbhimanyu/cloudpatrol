/**
 * API client for the CloudPatrol backend.
 *
 * Two behaviours are deliberate:
 *
 * 1. Errors are never swallowed. A failed request surfaces as an ApiError
 *    carrying the server's code and message, so the UI can show why something
 *    failed instead of an empty table that looks like "no findings".
 * 2. The bearer token and organization ID are supplied per call by the
 *    caller. Nothing is cached in module scope, so one user's token can never
 *    be reused for another's request.
 */

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
}

export interface RequestOptions {
  token: string;
  organizationId?: string;
  signal?: AbortSignal;
}

const BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

async function request<T>(
  path: string,
  options: RequestOptions,
  init: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${options.token}`,
    "Content-Type": "application/json",
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (options.organizationId) {
    headers["X-Organization-Id"] = options.organizationId;
  }

  let response: Response;
  try {
    response = await fetch(`${BASE_URL}${path}`, { ...init, headers, signal: options.signal });
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
  const payload: unknown = text ? JSON.parse(text) : null;

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
  listOrganizations: (options: RequestOptions): Promise<Paginated<Organization>> =>
    request("/api/v1/organizations", options),

  createOrganization: (
    options: RequestOptions,
    body: { name: string; slug: string },
  ): Promise<Organization> =>
    request("/api/v1/organizations", options, { method: "POST", body: JSON.stringify(body) }),

  listAccounts: (options: RequestOptions): Promise<Paginated<AwsAccount>> =>
    request("/api/v1/aws/accounts", options),

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
    request("/api/v1/aws/accounts", options, { method: "POST", body: JSON.stringify(body) }),

  listScans: (options: RequestOptions): Promise<Paginated<Scan>> =>
    request("/api/v1/scans", options),

  startScan: (options: RequestOptions, body: { aws_account_id: string }): Promise<Scan> =>
    request("/api/v1/scans", options, { method: "POST", body: JSON.stringify(body) }),

  getScan: (options: RequestOptions, scanId: string): Promise<Scan> =>
    request(`/api/v1/scans/${encodeURIComponent(scanId)}`, options),

  listFindings: (
    options: RequestOptions,
    filters: { state?: string; aws_account_id?: string } = {},
  ): Promise<Paginated<Finding>> => {
    const params = new URLSearchParams();
    if (filters.state) params.set("state", filters.state);
    if (filters.aws_account_id) params.set("aws_account_id", filters.aws_account_id);
    const query = params.toString();
    return request(`/api/v1/findings${query ? `?${query}` : ""}`, options);
  },

  getFinding: (options: RequestOptions, findingId: string): Promise<Finding> =>
    request(`/api/v1/findings/${encodeURIComponent(findingId)}`, options),

  reviewFinding: (
    options: RequestOptions,
    findingId: string,
    body: { state: "acknowledged" | "dismissed"; note?: string },
  ): Promise<Finding> =>
    request(`/api/v1/findings/${encodeURIComponent(findingId)}`, options, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),

  savingsLedger: (options: RequestOptions): Promise<SavingsLedger> =>
    request("/api/v1/savings/ledger", options),

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
    request(`/api/v1/savings/findings/${encodeURIComponent(findingId)}/advance`, options, {
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
    return request(`/api/v1/costs/summary${query ? `?${query}` : ""}`, options);
  },
};
