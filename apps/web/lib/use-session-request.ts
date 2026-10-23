"use client";

/**
 * Session-bound data access.
 *
 * Pages should not each rebuild `{ token, organizationId }` and remember to
 * guard against a missing session. This hook centralises that: it returns the
 * request options plus a `ready` flag, so a page can render a loading state
 * instead of firing a request with an empty token.
 */

import { useMemo } from "react";

import type { RequestOptions } from "@/lib/api";
import { useSession } from "@/lib/session-context";

export interface SessionRequest {
  options: RequestOptions | null;
  /** True when both a token and an organization are available. */
  ready: boolean;
  organizationId: string | null;
  token: string | null;
}

export function useSessionRequest(): SessionRequest {
  const { token, organizationId } = useSession();

  const options = useMemo<RequestOptions | null>(() => {
    if (!token || !organizationId) return null;
    return { token, organizationId };
  }, [token, organizationId]);

  return {
    options,
    ready: options !== null,
    organizationId,
    token,
  };
}
