/**
 * Server-side Supabase client.
 *
 * Sessions live in cookies that Supabase writes and this app never parses.
 * `@supabase/ssr` owns the cookie format, the refresh-token rotation and the
 * expiry logic; this file only wires it to Next.js's cookie store. There is no
 * hand-rolled session or token handling anywhere in the app.
 *
 * `getAll`/`setAll` are the supported interface. `setAll` throws when called
 * from a Server Component, because only a Route Handler, Server Action or the
 * proxy can set a cookie. That is expected and safe to ignore as long as the
 * proxy refreshes sessions on every request; the comment in the catch says so.
 */

import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

import { supabasePublicConfig } from "./env";

/**
 * Cookie attributes for the session.
 *
 * `httpOnly` is the point of this phase: the session cookie is unreadable by
 * JavaScript, so injected script cannot exfiltrate it. `@supabase/ssr`
 * defaults to `httpOnly: false`, which is what makes its browser client able
 * to read the session; this app does not use that client, so the stricter
 * value is safe here.
 *
 * `secure` is on in production only. A production build served over plain
 * HTTP would then fail to receive the cookie, which is correct: an
 * unencrypted transport must not carry a session.
 */
function cookieOptions(): { httpOnly: boolean; secure: boolean; sameSite: "lax" } {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  };
}

export async function createSupabaseServerClient() {
  const cookieStore = await cookies();
  const { url, anonKey } = supabasePublicConfig();

  return createServerClient(url, anonKey, {
    cookieOptions: cookieOptions(),
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Called from a Server Component, where cookies are read-only.
          // The proxy refreshes the session instead, so nothing is lost.
        }
      },
    },
  });
}

/**
 * The current access token, or null when there is no valid session.
 *
 * `getSession()` is used only to read the token for the server-to-server call
 * to the FastAPI service. It is never trusted for authorization on its own:
 * FastAPI verifies the signature and claims itself. `getUser()` is the
 * authoritative check and is used wherever a decision depends on identity.
 */
export async function getAccessToken(): Promise<string | null> {
  const supabase = await createSupabaseServerClient();
  const { data, error } = await supabase.auth.getSession();
  if (error || !data.session) return null;
  return data.session.access_token;
}

export interface AuthenticatedUser {
  id: string;
  email: string | null;
}

/** The verified signed-in user, or null. */
export async function getAuthenticatedUser(): Promise<AuthenticatedUser | null> {
  const supabase = await createSupabaseServerClient();
  const { data, error } = await supabase.auth.getUser();
  if (error || !data.user) return null;
  return { id: data.user.id, email: data.user.email ?? null };
}
