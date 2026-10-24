/**
 * Supabase configuration for the web app.
 *
 * Only the public URL and the publishable (anon) key are read here. Both are
 * designed to reach the browser. The service-role key is deliberately absent:
 * it bypasses Row Level Security, so it must never be importable from a file
 * the bundler can reach.
 *
 * Configuration is read lazily and throws a named error rather than letting
 * `undefined` reach `createClient`, because a missing key otherwise surfaces
 * as an opaque fetch failure at sign-in time.
 */

export interface SupabasePublicConfig {
  url: string;
  anonKey: string;
}

let cached: SupabasePublicConfig | null = null;

export function supabasePublicConfig(): SupabasePublicConfig {
  if (cached) return cached;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  const missing = [
    ["NEXT_PUBLIC_SUPABASE_URL", url],
    ["NEXT_PUBLIC_SUPABASE_ANON_KEY", anonKey],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name as string);

  if (missing.length > 0) {
    throw new Error(
      `Supabase is not configured. Set ${missing.join(" and ")}. ` +
        "See .env.example for the full list.",
    );
  }

  cached = { url: url as string, anonKey: anonKey as string };
  return cached;
}

/** True when both public Supabase variables are present. */
export function isSupabaseConfigured(): boolean {
  return Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  );
}
