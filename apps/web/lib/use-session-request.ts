"use client";

/**
 * Session-bound data access.
 *
 * Pages should not each rebuild `{ organizationId }` and remember to guard
 * against a missing session. This hook centralises that: it returns the
 * request options plus a `ready` flag, so a page renders a loading state
 * instead of firing a request with no workspace selected.
 *
 * There is no token to thread through: the credential is attached by the
 * `/api/proxy` route from the HttpOnly session cookie.
 */

import { useMemo } from "react";

import type { RequestOptions } from "@/lib/api";
import { useSession } from "@/lib/session-context";

export interface SessionRequest {
  options: RequestOptions | null;
  /** True when a workspace is selected and a session exists. */
  ready: boolean;
  organizationId: string | null;
}

export function useSessionRequest(): SessionRequest {
  const { signedIn, organizationId } = useSession();

  const options = useMemo<RequestOptions | null>(() => {
    if (!signedIn || !organizationId) return null;
    return { organizationId };
  }, [signedIn, organizationId]);

  return {
    options,
    ready: options !== null,
    organizationId,
  };
}
