import type { Metadata } from "next";

import { AppShell } from "@/components/AppShell";
import { SessionProvider } from "@/lib/session-context";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "CloudPatrol — AWS cost intelligence",
    template: "%s · CloudPatrol",
  },
  description:
    "Read-only AWS cost intelligence. Find idle resources, understand the reasoning, and see which savings are real.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <SessionProvider>
          <AppShell>{children}</AppShell>
        </SessionProvider>
      </body>
    </html>
  );
}
