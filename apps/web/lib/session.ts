/**
 * The active workspace preference.
 *
 * This module used to hold the bearer token in `localStorage`. It no longer
 * holds any credential: the session is a server-side HttpOnly cookie that
 * JavaScript cannot read. What remains is the selected organization ID, which
 * is a UI preference, not a secret — FastAPI re-checks membership on every
 * request, so tampering with it yields a 403 rather than another tenant's data.
 *
 * Exposed as an external store so React can read it with
 * `useSyncExternalStore`. That avoids two problems an effect-and-setState
 * approach has: a server/client hydration mismatch, and a setState during the
 * first effect that cascades an extra render.
 */

const ORG_KEY = "cloudpatrol.organizationId";

const listeners = new Set<() => void>();
// Cached so `getSnapshot` returns a stable reference between changes, which
// `useSyncExternalStore` requires to avoid an infinite re-render loop.
let cached: string | null = null;
let cachedRaw = "\u0000";

function storage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    // Storage can throw when disabled by policy. The app then falls back to
    // the first workspace the user can read, which is a safe direction.
    return null;
  }
}

function read(): string | null {
  const store = storage();
  if (!store) return null;
  return store.getItem(ORG_KEY);
}

function emit(): void {
  for (const listener of listeners) listener();
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // Another tab changing the workspace should be reflected here too.
  const onStorage = (event: StorageEvent) => {
    if (event.key === ORG_KEY) listener();
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

export function getSnapshot(): string | null {
  const next = read();
  const raw = next ?? "";
  if (raw !== cachedRaw) {
    cachedRaw = raw;
    cached = next;
  }
  return cached;
}

export function getServerSnapshot(): string | null {
  return null;
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

export function clearOrganizationId(): void {
  setOrganizationId(null);
}
