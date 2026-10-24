"use server";

/**
 * Authentication actions.
 *
 * Sign-in and sign-out run on the server so the session cookie is written
 * HttpOnly and never touches JavaScript. `@supabase/ssr` handles the token
 * exchange, rotation and expiry; nothing here parses or stores a token itself.
 *
 * Error messages are mapped to a small fixed set rather than forwarding the
 * provider's text. Supabase distinguishes "invalid credentials" from "email
 * not confirmed", which is useful to a real user, so those two are kept; the
 * rest collapse to one message so a failure cannot be used to enumerate
 * which addresses have accounts.
 */

import { redirect } from "next/navigation";

import type { AuthActionState } from "@/lib/auth/state";
import { createSupabaseServerClient } from "@/lib/supabase/server";

/** Only allow same-origin relative paths, so `next` cannot redirect off-site. */
function safeRedirectTarget(value: FormDataEntryValue | null): string {
  const raw = typeof value === "string" ? value : "";
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return "/dashboard";
  return raw;
}

function messageFor(error: { code?: string; message: string }): string {
  switch (error.code) {
    case "invalid_credentials":
      return "That email and password combination is not correct.";
    case "email_not_confirmed":
      return "Confirm your email address before signing in. Check your inbox for the link.";
    case "over_request_rate_limit":
    case "over_email_send_rate_limit":
      return "Too many attempts. Wait a moment and try again.";
    case "user_already_exists":
      return "An account with that email already exists. Sign in instead.";
    case "weak_password":
      return "Choose a longer password. Supabase requires at least 6 characters.";
    case "signup_disabled":
      return "Sign-up is disabled for this project. Ask an administrator for access.";
    default:
      // Deliberately not the raw message: it can echo the submitted address.
      return "Sign-in could not be completed. Try again.";
  }
}

export async function signInAction(
  _previous: AuthActionState,
  formData: FormData,
): Promise<AuthActionState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");

  if (!email || !password) {
    return { error: "Enter your email and password.", notice: null };
  }

  const supabase = await createSupabaseServerClient();
  const { error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    return { error: messageFor(error), notice: null };
  }

  // `redirect` throws, so it must be outside any try/catch that would swallow
  // it. The target is validated above.
  redirect(safeRedirectTarget(formData.get("next")));
}

export async function signOutAction(): Promise<void> {
  const supabase = await createSupabaseServerClient();
  await supabase.auth.signOut();
  redirect("/sign-in");
}
