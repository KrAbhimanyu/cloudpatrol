"use client";

/**
 * Session context: who is signed in, and which organization is active.
 *
 * The credential is not here. The browser cannot read the session at all: it
 * is an HttpOnly cookie, and every API call goes through the `/api/proxy`
 * route, which attaches the token server-side. What this context exposes is
 * the identity (supplied by the server layout) and the selected workspace.
 *
 * `signedIn` starts from the server-rendered identity, so the first paint does
 * not flash a sign-in form at a user who is in fact signed in. A later 401
 * from the API flips it back, so an expired session surfaces as "signed out"
 * rather than as a page of empty tables.
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

import { ApiError, api } from "@/lib/api";
import { signOutAction } from "@/lib/auth/actions";
import {
  clearOrganizationId,
  getServerSnapshot,
  getSnapshot,
  setOrganizationId,
  subscribe,
} from "@/lib/session";
import type { Organization } from "@/lib/types";

export interface Identity {
  userId: string;
  email: string | null;
}

interface SessionContextValue {
  ready: boolean;
  signedIn: boolean;
  identity: Identity | null;
  organizationId: string | null;
  organizations: Organization[];
  loadingOrganizations: boolean;
  error: string | null;
  /** True when the session ended mid-use, so the UI can say so plainly. */
  sessionExpired: boolean;
  signOut: () => void;
  selectOrganization: (organizationId: string) => void;
  reloadOrganizations: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

interface OrgState {
  loaded: boolean;
  items: Organization[];
  error: string | null;
}

export function SessionProvider({
  children,
  initialIdentity,
}: {
  children: React.ReactNode;
  initialIdentity: Identity | null;
}) {
  const organizationId = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const [identity, setIdentity] = useState<Identity | null>(initialIdentity);
  const [signedIn, setSignedIn] = useState(initialIdentity !== null);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [orgState, setOrgState] = useState<OrgState>({
    loaded: false,
    items: [],
    error: null,
  });
  const [reloadToken, setReloadToken] = useState(0);

  // `ready` is true once hydration has happened. Deriving it avoids a setState
  // in an effect that would cascade an extra render.
  const ready = useSyncExternalStore(subscribe, () => true, () => false);

  useEffect(() => {
    if (!signedIn) return;
    let cancelled = false;

    api
      .listOrganizations()
      .then((page) => {
        if (cancelled) return;
        setOrgState({ loaded: true, items: page.items, error: null });
        // Reconcile the stored selection against what the user can actually
        // read, so a stale workspace ID cannot leave the app pointed at an
        // organization the user has been removed from.
        const current = getSnapshot();
        const stillValid = current !== null && page.items.some((org) => org.id === current);
        if (!stillValid) setOrganizationId(page.items[0]?.id ?? null);
      })
      .catch((cause: unknown) => {
        if (cancelled) return;
        // A 401 means the cookie expired between render and request. Report
        // that as an ended session, not as a failed workspace load.
        if (cause instanceof ApiError && cause.isUnauthenticated) {
          setSignedIn(false);
          setSessionExpired(true);
          setOrgState({ loaded: true, items: [], error: null });
          return;
        }
        setOrgState({
          loaded: true,
          items: [],
          error: cause instanceof Error ? cause.message : "Could not load workspaces.",
        });
      });

    return () => {
      cancelled = true;
    };
  }, [signedIn, reloadToken]);

  const signOut = useCallback(() => {
    // Drop the workspace preference first, so the UI stops showing the
    // previous tenant's workspace even if the redirect is interrupted.
    clearOrganizationId();
    setOrgState({ loaded: false, items: [], error: null });
    setIdentity(null);
    setSignedIn(false);
    // A server action, because only the server can clear an HttpOnly cookie.
    void signOutAction();
  }, []);

  const selectOrganization = useCallback((next: string) => {
    setOrganizationId(next);
  }, []);

  const reloadOrganizations = useCallback(() => setReloadToken((n) => n + 1), []);

  const value = useMemo<SessionContextValue>(
    () => ({
      ready,
      signedIn,
      identity,
      organizationId,
      organizations: orgState.items,
      loadingOrganizations: signedIn && !orgState.loaded,
      error: orgState.error,
      sessionExpired,
      signOut,
      selectOrganization,
      reloadOrganizations,
    }),
    [
      ready,
      signedIn,
      identity,
      organizationId,
      orgState,
      sessionExpired,
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
