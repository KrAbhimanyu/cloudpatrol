import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // The service-role key and other server-only secrets must never be bundled
  // into client code. Only variables prefixed NEXT_PUBLIC_ are exposed by
  // Next.js, and this list is kept deliberately short.
  env: {
    NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
  },
};

export default nextConfig;
