"use client";

/**
 * Session gate and workspace guard.
 *
 * There is no token-entry form here any more. Sign-in happens on its own page
 * against Supabase Auth; this component only decides what to render given the
 * session the server already established.
 *
 * It still refuses to render a data page it cannot back with a workspace,
 * because an empty dashboard is indistinguishable from "no findings" and that
 * would be a lie about the customer's account.
 */

import Link from "next/link";

import { useSession } from "@/lib/session-context";

export function RequireSession({ children }: { children: React.ReactNode }) {
  const {
    ready,
    signedIn,
    sessionExpired,
    organizationId,
    organizations,
    loadingOrganizations,
    error,
    signOut,
  } = useSession();

  if (!ready) {
    return <CenteredMessage>Loading…</CenteredMessage>;
  }

  if (!signedIn) {
    return (
      <CenteredMessage tone={sessionExpired ? "error" : "neutral"}>
        {sessionExpired
          ? "Your session has ended. Sign in again to continue."
          : "You are not signed in."}
        <div className="mt-4">
          <Link
            href="/sign-in"
            className="text-xs font-semibold text-brand-700 hover:underline"
          >
            Go to sign in
          </Link>
        </div>
      </CenteredMessage>
    );
  }

  if (loadingOrganizations && organizations.length === 0) {
    return <CenteredMessage>Loading workspaces…</CenteredMessage>;
  }

  if (error) {
    return (
      <CenteredMessage tone="error">
        {error}
        <SignOutButton onClick={signOut} />
      </CenteredMessage>
    );
  }

  if (organizations.length === 0) {
    return (
      <CenteredMessage>
        This account does not belong to any workspace yet.
        <SignOutButton onClick={signOut} />
      </CenteredMessage>
    );
  }

  if (!organizationId) {
    return <CenteredMessage>Select a workspace to continue.</CenteredMessage>;
  }

  return <>{children}</>;
}

function CenteredMessage({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "neutral" | "error";
}) {
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={`mx-auto mt-16 max-w-md rounded-xl border px-6 py-8 text-center text-sm ${
        tone === "error"
          ? "border-red-200 bg-red-50 text-red-900"
          : "border-slate-200 bg-white text-slate-600"
      }`}
    >
      {children}
    </div>
  );
}

function SignOutButton({ onClick }: { onClick: () => void }) {
  return (
    <div className="mt-4">
      <button
        type="button"
        onClick={onClick}
        className="text-xs font-semibold text-brand-700 hover:underline"
      >
        Sign out
      </button>
    </div>
  );
}
