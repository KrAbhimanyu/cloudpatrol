import type { Metadata } from "next";

import { AppShell } from "@/components/AppShell";
import { SessionProvider } from "@/lib/session-context";
import { getAuthenticatedUser } from "@/lib/supabase/server";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "CloudPatrol — AWS cost intelligence",
    template: "%s · CloudPatrol",
  },
  description:
    "Read-only AWS cost intelligence. Find idle resources, understand the reasoning, and see which savings are real.",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Resolved on the server so the first paint already knows whether a session
  // exists. Without this a signed-in user would briefly see the sign-in form.
  // A failure here (Supabase unreachable or unconfigured) degrades to "signed
  // out" rather than crashing every page.
  let identity: { userId: string; email: string | null } | null = null;
  try {
    const user = await getAuthenticatedUser();
    identity = user ? { userId: user.id, email: user.email } : null;
  } catch {
    identity = null;
  }

  return (
    <html lang="en">
      <body>
        <SessionProvider initialIdentity={identity}>
          <AppShell>{children}</AppShell>
        </SessionProvider>
      </body>
    </html>
  );
}
