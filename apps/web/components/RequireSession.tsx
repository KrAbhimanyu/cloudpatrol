"use client";

/**
 * Sign-in gate and session status.
 *
 * Two responsibilities, both about honesty:
 *
 * 1. If there is no session, show a form that takes a token rather than
 *    rendering an empty page that would read as "no findings".
 * 2. If there is a session but no organization yet, say so, because every data
 *    page needs one and an empty dashboard would otherwise look like "no
 *    findings" rather than "no workspace selected".
 */

import { useState } from "react";

import { useSession } from "@/lib/session-context";

export function RequireSession({ children }: { children: React.ReactNode }) {
  const { ready, token, organizationId, organizations, loadingOrganizations, error } =
    useSession();

  if (!ready) {
    return <CenteredMessage>Loading…</CenteredMessage>;
  }

  if (!token) {
    return <SignInForm />;
  }

  if (loadingOrganizations && organizations.length === 0) {
    return <CenteredMessage>Loading workspaces…</CenteredMessage>;
  }

  if (error) {
    return (
      <CenteredMessage tone="error">
        {error}
        <SignOutLink />
      </CenteredMessage>
    );
  }

  if (organizations.length === 0) {
    return (
      <CenteredMessage>
        This account does not belong to any workspace yet.
        <SignOutLink />
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

function SignOutLink() {
  const { signOut } = useSession();
  return (
    <div className="mt-4">
      <button
        type="button"
        onClick={signOut}
        className="text-xs font-semibold text-brand-700 hover:underline"
      >
        Use a different token
      </button>
    </div>
  );
}

function SignInForm() {
  const { signIn } = useSession();
  const [value, setValue] = useState("");

  return (
    <div className="mx-auto mt-16 max-w-md rounded-xl border border-slate-200 bg-white px-6 py-8 shadow-sm">
      <h1 className="text-lg font-semibold tracking-tight text-slate-900">
        Connect to CloudPatrol
      </h1>
      <p className="mt-1.5 text-sm text-slate-600">
        Paste an API token to load your workspaces. The token is sent as a bearer
        credential and is stored only in this browser.
      </p>
      <form
        className="mt-5"
        onSubmit={(event) => {
          event.preventDefault();
          const trimmed = value.trim();
          if (trimmed) signIn(trimmed);
        }}
      >
        <label htmlFor="token" className="block text-xs font-medium text-slate-700">
          API token
        </label>
        <input
          id="token"
          name="token"
          type="password"
          autoComplete="off"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
        />
        <button
          type="submit"
          disabled={value.trim().length === 0}
          className="mt-4 w-full rounded-md bg-brand-600 px-3 py-2 text-sm font-semibold text-white hover:bg-brand-700 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Continue
        </button>
      </form>
    </div>
  );
}
