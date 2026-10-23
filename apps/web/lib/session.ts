/**
 * Session storage for the bearer token and the active organization.
 *
 * Exposed as an external store so React can read it with
 * `useSyncExternalStore`. That avoids two problems an effect-and-setState
 * approach has: a server/client hydration mismatch, and a setState during the
 * first effect that cascades an extra render.
 *
 * Deliberately explicit about its limits:
 *
 * * The token is kept in `localStorage`, which is readable by any script on the
 *   origin. That is acceptable only because this is a development-stage app
 *   with no third-party scripts. Before production the token should move to an
 *   HttpOnly cookie set by a same-origin auth route, which is the only way to
 *   make it unreadable to injected script. This is recorded here so the choice
 *   is a known trade-off rather than an oversight.
 * * The server snapshot is always empty, so the first client render matches the
 *   server and the real session appears on the client after hydration.
 */

const TOKEN_KEY = "cloudpatrol.token";
const ORG_KEY = "cloudpatrol.organizationId";

export interface Session {
  token: string;
  organizationId: string | null;
}

const listeners = new Set<() => void>();
// Cached so `getSnapshot` returns a stable reference between changes, which
// `useSyncExternalStore` requires to avoid an infinite re-render loop.
let cached: Session | null = null;
let cachedRaw = "\u0000";

function storage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    // Storage can throw when disabled by policy. The app then behaves as if
    // signed out, which is the safe direction.
    return null;
  }
}

function read(): Session | null {
  const store = storage();
  if (!store) return null;
  const token = store.getItem(TOKEN_KEY);
  if (!token) return null;
  return { token, organizationId: store.getItem(ORG_KEY) };
}

function emit(): void {
  for (const listener of listeners) listener();
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // Another tab changing the session should be reflected here too.
  const onStorage = (event: StorageEvent) => {
    if (event.key === TOKEN_KEY || event.key === ORG_KEY) listener();
  };
  if (typeof window !== "undefined") {
    window.addEventListener("storage", onStorage);
  }
  return () => {
    listeners.delete(listener);
    if (typeof window !== "undefined") {
      window.removeEventListener("storage", onStorage);
    }
  };
}

export function getSnapshot(): Session | null {
  const next = read();
  const raw = next ? `${next.token}\u0000${next.organizationId ?? ""}` : "";
  if (raw !== cachedRaw) {
    cachedRaw = raw;
    cached = next;
  }
  return cached;
}

export function getServerSnapshot(): Session | null {
  return null;
}

export function setSession(session: Session): void {
  const store = storage();
  if (!store) return;
  store.setItem(TOKEN_KEY, session.token);
  if (session.organizationId) {
    store.setItem(ORG_KEY, session.organizationId);
  } else {
    store.removeItem(ORG_KEY);
  }
  emit();
}

export function setOrganizationId(organizationId: string | null): void {
  const store = storage();
  if (!store) return;
  if (organizationId) {
    store.setItem(ORG_KEY, organizationId);
  } else {
    store.removeItem(ORG_KEY);
  }
  emit();
}

export function clearSession(): void {
  const store = storage();
  if (!store) return;
  store.removeItem(TOKEN_KEY);
  store.removeItem(ORG_KEY);
  emit();
}
