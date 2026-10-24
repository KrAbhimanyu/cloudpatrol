import type { Metadata } from "next";

import { SignInForm } from "@/components/SignInForm";
import { isSupabaseConfigured } from "@/lib/supabase/env";

export const metadata: Metadata = {
  title: "Sign in",
};

/**
 * The sign-in page.
 *
 * Rendered on the server so it can report missing configuration before the
 * user types anything, and so a signed-in visitor is redirected by the proxy
 * rather than seeing a form they do not need.
 */
export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const { next } = await searchParams;

  return (
    <div className="mx-auto mt-12 w-full max-w-md sm:mt-20">
      <div className="mb-6 text-center">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Sign in to CloudPatrol
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Read-only AWS cost intelligence for your workspaces.
        </p>
      </div>

      {isSupabaseConfigured() ? (
        <SignInForm next={next ?? "/dashboard"} />
      ) : (
        <NotConfigured />
      )}
    </div>
  );
}

function NotConfigured() {
  return (
    <div
      role="alert"
      className="rounded-xl border border-amber-200 bg-amber-50 px-6 py-5 text-sm text-amber-900"
    >
      <p className="font-semibold">Supabase is not configured</p>
      <p className="mt-2 leading-relaxed">
        Set <code className="font-mono text-xs">NEXT_PUBLIC_SUPABASE_URL</code> and{" "}
        <code className="font-mono text-xs">NEXT_PUBLIC_SUPABASE_ANON_KEY</code> in the web app&rsquo;s
        environment, then restart the dev server. See{" "}
        <code className="font-mono text-xs">.env.example</code>.
      </p>
    </div>
  );
}
