"use client";

/**
 * Workspace switcher and sign-out.
 *
 * Shown only when a session exists, so the sign-in screen is not cluttered with
 * controls that cannot act yet. With one workspace the select is rendered
 * disabled rather than hidden, so the user can see which workspace the figures
 * on screen belong to — that context matters more than saving a row.
 */

import { useSession } from "@/lib/session-context";

export function WorkspaceSwitcher() {
  const { ready, signedIn, organizations, organizationId, selectOrganization, signOut } =
    useSession();

  if (!ready || !signedIn || organizations.length === 0) return null;

  return (
    <div className="space-y-2" data-testid="workspace-switcher">
      <label
        htmlFor="workspace"
        className="block text-xs font-medium uppercase tracking-wide text-slate-500"
      >
        Workspace
      </label>
      <select
        id="workspace"
        value={organizationId ?? ""}
        disabled={organizations.length === 1}
        onChange={(event) => selectOrganization(event.target.value)}
        className="w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-800 shadow-sm disabled:bg-slate-50 disabled:text-slate-600"
      >
        {organizations.map((org) => (
          <option key={org.id} value={org.id}>
            {org.name}
          </option>
        ))}
      </select>
      <button
        type="button"
        onClick={signOut}
        className="text-xs font-semibold text-slate-500 hover:text-slate-800 hover:underline"
      >
        Sign out
      </button>
    </div>
  );
}
