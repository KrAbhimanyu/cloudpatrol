"use client";

/**
 * Email and password sign-in.
 *
 * Uses `useActionState` so the pending state and the error come from the
 * server action itself rather than being guessed locally. The password field
 * is never logged, never placed in a URL, and is cleared from component state
 * only by unmounting after a successful redirect.
 */

import { useActionState } from "react";

import { signInAction } from "@/lib/auth/actions";
import { EMPTY_AUTH_STATE } from "@/lib/auth/state";

export function SignInForm({ next }: { next: string }) {
  const [state, formAction, pending] = useActionState(signInAction, EMPTY_AUTH_STATE);

  return (
    <form
      action={formAction}
      className="rounded-xl border border-slate-200 bg-white px-6 py-7 shadow-sm"
      data-testid="sign-in-form"
    >
      <input type="hidden" name="next" value={next} />

      <div className="space-y-4">
        <div>
          <label htmlFor="email" className="block text-xs font-medium text-slate-700">
            Email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            required
            autoComplete="email"
            autoFocus
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
          />
        </div>

        <div>
          <label htmlFor="password" className="block text-xs font-medium text-slate-700">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            required
            autoComplete="current-password"
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
          />
        </div>
      </div>

      {state.error && (
        <p
          role="alert"
          className="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-900"
        >
          {state.error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="mt-5 w-full rounded-md bg-brand-600 px-3 py-2 text-sm font-semibold text-white hover:bg-brand-700 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>

      <p className="mt-4 text-center text-xs text-slate-500">
        Sessions are held in a secure cookie on the server. CloudPatrol never stores an AWS
        credential and never writes to your AWS account.
      </p>
    </form>
  );
}
