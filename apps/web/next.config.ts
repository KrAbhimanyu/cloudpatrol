import type { NextConfig } from "next";

import { staticSecurityHeaders } from "./lib/security/headers";

/**
 * Origins allowed to invoke a Server Action, beyond this app's own host.
 *
 * Next.js compares the `Origin` of a Server Action request against `Host` and
 * rejects a mismatch, which is a CSRF check. Behind a reverse proxy that
 * forwards its own host rather than the public one, that comparison fails for
 * legitimate requests, and this list is how the public host is declared.
 * Comma-separated, for example `https://app.cloudpatrol.dev`.
 */
const allowedActionOrigins = (process.env.APP_ORIGINS ?? "")
  .split(",")
  .map((entry) => entry.trim().replace(/^https?:\/\//, "").replace(/\/$/, ""))
  .filter(Boolean);

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // The service-role key and other server-only secrets must never be bundled
  // into client code. Only variables prefixed NEXT_PUBLIC_ are exposed by
  // Next.js, and this list is kept deliberately short.
  env: {
    NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
  },
  // Do not advertise the framework and version on every response.
  poweredByHeader: false,
  experimental: {
    serverActions: {
      // An empty list keeps the default behaviour: only the same origin may
      // invoke an action. The value is a host, not a URL.
      allowedOrigins: allowedActionOrigins,
    },
  },
  /**
   * Security headers that do not vary per request.
   *
   * The CSP is deliberately absent: it carries a per-request nonce and is set
   * in `proxy.ts`, which runs on page routes. This list covers everything the
   * proxy's matcher skips, including the BFF route under `/api`.
   */
  async headers() {
    const headers = staticSecurityHeaders().map(({ key, value }) => ({ key, value }));
    return [
      {
        // Static assets are immutable and can be cached; the security headers
        // are still worth setting on them.
        source: "/:path*",
        headers,
      },
    ];
  },
};

export default nextConfig;
