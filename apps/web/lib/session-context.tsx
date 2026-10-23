"use client";

/**
 * Session context: who is signed in, and which organization is active.
 *
 * The stored session is read through `useSyncExternalStore`, so hydration is
 * correct and there is no setState-on-mount cascade.
 *
 * The organization list is fetched, and every state update happens inside the
 * request's own callbacks rather than synchronously in the effect body — the
 * React compiler flags a synchronous setState in an effect because it cascades
 * an extra render. State that can be derived (an empty list when signed out) is
 * derived rather than stored.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
} from "react";

import { api } from "@/lib/api";
import {
  clearSession,
  getServerSnapshot,
  getSnapshot,
  setOrganizationId,
  setSession,
  subscribe,
} from "@/lib/session";
import type { Organization } from "@/lib/types";

interface SessionContextValue {
  ready: boolean;
  token: string | null;
  organizationId: string | null;
  organizations: Organization[];
  loadingOrganizations: boolean;
  error: string | null;
  signIn: (token: string) => void;
  signOut: () => void;
  selectOrganization: (organizationId: string) => void;
  reloadOrganizations: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

interface OrgState {
  forToken: string | null;
  items: Organization[];
  loading: boolean;
  error: string | null;
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const session = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const token = session?.token ?? null;
  const organizationId = session?.organizationId ?? null;

  const [orgState, setOrgState] = useState<OrgState>({
    forToken: null,
    items: [],
    loading: false,
    error: null,
  });
  const [reloadToken, setReloadToken] = useState(0);

  // `ready` is true once hydration has happened, which is exactly when the
  // session store starts returning a value. Deriving it avoids a setState.
  const ready = useSyncExternalStore(subscribe, () => true, () => false);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    api
      .listOrganizations({ token })
      .then((page) => {
        if (cancelled) return;
        setOrgState({ forToken: token, items: page.items, loading: false, error: null });
        // Reconcile the stored selection against what the user can read.
        const current = getSnapshot()?.organizationId ?? null;
        const stillValid = current !== null && page.items.some((org) => org.id === current);
        if (!stillValid) setOrganizationId(page.items[0]?.id ?? null);
      })
      .catch((cause: unknown) => {
        if (cancelled) return;
        setOrgState({
          forToken: token,
          items: [],
          loading: false,
          error: cause instanceof Error ? cause.message : "Could not load organizations.",
        });
      });

    return () => {
      cancelled = true;
    };
  }, [token, reloadToken]);

  // Show the previous token's data as "loading" rather than stale data from
  // another session: `forToken` is what makes that distinction possible.
  const organizations = useMemo(
    () => (orgState.forToken === token ? orgState.items : []),
    [orgState, token],
  );
  const loadingOrganizations = token !== null && orgState.forToken !== token;
  const error = orgState.forToken === token ? orgState.error : null;

  const signIn = useCallback((nextToken: string) => {
    setSession({ token: nextToken, organizationId: null });
  }, []);

  const signOut = useCallback(() => {
    clearSession();
    setOrgState({ forToken: null, items: [], loading: false, error: null });
  }, []);

  const selectOrganization = useCallback((next: string) => {
    setOrganizationId(next);
  }, []);

  const reloadOrganizations = useCallback(() => setReloadToken((n) => n + 1), []);

  const value = useMemo<SessionContextValue>(
    () => ({
      ready,
      token,
      organizationId,
      organizations,
      loadingOrganizations,
      error,
      signIn,
      signOut,
      selectOrganization,
      reloadOrganizations,
    }),
    [
      ready,
      token,
      organizationId,
      organizations,
      loadingOrganizations,
      error,
      signIn,
      signOut,
      selectOrganization,
      reloadOrganizations,
    ],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (value === null) {
    throw new Error("useSession must be used inside a SessionProvider.");
  }
  return value;
}
