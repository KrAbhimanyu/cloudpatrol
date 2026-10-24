/**
 * A bounded, in-process token bucket.
 *
 * The API service has its own limiter (`services/api/app/core/rate_limit.py`);
 * this is the web app's equivalent, kept deliberately to the same shape —
 * token bucket, bounded key count, injectable clock — so the two behave the
 * same way and a reader does not have to learn two designs.
 *
 * ## Why a token bucket
 *
 * A burst is allowed up to the bucket size, while the sustained rate is held to
 * the refill rate. A fixed window would let a caller spend a full quota at the
 * end of one window and again at the start of the next, which is exactly the
 * burst pattern a flood uses.
 *
 * ## Limits of this implementation
 *
 * - **In-process.** With N replicas the effective limit is N times the
 *   configured rate, and a restart clears the buckets. A shared store is the
 *   upgrade path and is not needed for a single process.
 * - **Bounded.** One bucket per distinct key is an unbounded map that an
 *   attacker can grow, so the count is capped and the least-recently-used
 *   buckets are evicted. Eviction grants a fresh bucket, which is why the cap is
 *   set well above the number of legitimate callers.
 */

import { createHash } from "node:crypto";

export interface RateLimitRule {
  /** Maximum burst, in tokens. */
  capacity: number;
  /** Tokens added per second. */
  refillPerSecond: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  /** Seconds to wait before retrying. Zero when allowed. */
  retryAfterSeconds: number;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

export class TokenBucketRateLimiter {
  private readonly rules: Map<string, RateLimitRule>;
  private readonly maxKeys: number;
  private readonly now: () => number;
  /**
   * Insertion order is the LRU order: `Map` preserves it, and both reads and
   * writes re-insert the key. JavaScript is single-threaded per request
   * handler, so no lock is needed here — unlike the Python implementation,
   * which runs behind a thread pool.
   */
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    rules: Record<string, RateLimitRule>,
    options: { maxKeys?: number; now?: () => number } = {},
  ) {
    this.rules = new Map(Object.entries(rules));
    this.maxKeys = options.maxKeys ?? 10_000;
    this.now = options.now ?? (() => Date.now() / 1000);
  }

  /**
   * Consume `cost` tokens, or report that the limit was exceeded.
   *
   * An unknown class is not limited. A missing rule is a configuration gap, and
   * failing open keeps a misconfiguration from taking the endpoint down; the
   * caller logs the gap rather than it passing silently.
   */
  check(limitClass: string, key: string, cost = 1): RateLimitDecision {
    const rule = this.rules.get(limitClass);
    if (!rule) return { allowed: true, retryAfterSeconds: 0 };

    const now = this.now();
    const bucketKey = `${limitClass}\u0000${key}`;

    let bucket = this.buckets.get(bucketKey);
    if (bucket === undefined) {
      bucket = { tokens: rule.capacity, updatedAt: now };
    } else {
      const elapsed = Math.max(0, now - bucket.updatedAt);
      bucket.tokens = Math.min(rule.capacity, bucket.tokens + elapsed * rule.refillPerSecond);
      bucket.updatedAt = now;
      // Re-insert so this key is the most recently used.
      this.buckets.delete(bucketKey);
    }
    this.buckets.set(bucketKey, bucket);

    if (bucket.tokens < cost) {
      const deficit = cost - bucket.tokens;
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil(deficit / rule.refillPerSecond)),
      };
    }

    bucket.tokens -= cost;
    this.evictIfNeeded();
    return { allowed: true, retryAfterSeconds: 0 };
  }

  /** Drop the oldest idle buckets once the cap is exceeded. */
  private evictIfNeeded(): void {
    while (this.buckets.size > this.maxKeys) {
      const oldest = this.buckets.keys().next();
      if (oldest.done) return;
      this.buckets.delete(oldest.value);
    }
  }

  /**
   * Clear every bucket.
   *
   * The limiter is a module-level singleton so its buckets survive between
   * requests, which is the point of it. That also means state leaks between
   * tests that share the module, so this exists for tests to start from a known
   * state. It is not called by application code: resetting the counters in
   * production would hand an attacker a fresh burst.
   */
  reset(): void {
    this.buckets.clear();
  }
}

/**
 * Derive a bucket key without storing the raw input.
 *
 * The map key is a hash so a cookie value never sits in memory as a map key
 * where a heap dump or a stray log line could expose it.
 */
export function hashKey(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 32);
}

/**
 * The limits the web app runs with.
 *
 * `csp-report` is generous in rate but bounded overall: a page with a genuine
 * policy problem can emit several violations as it loads, and throttling those
 * would hide the very problem the endpoint exists to reveal. The limit is set
 * high enough that ordinary traffic never reaches it and low enough that a
 * flood is capped.
 */
export function buildDefaultRules(): Record<string, RateLimitRule> {
  return {
    // A burst of 60, sustained 1 per second.
    "csp-report": { capacity: 60, refillPerSecond: 1 },
  };
}

/**
 * The shared limiter for the reporting endpoint.
 *
 * A module-level instance, so the buckets survive between requests in the same
 * process. Tests construct their own limiter rather than reaching for this one.
 */
export const reportRateLimiter = new TokenBucketRateLimiter(buildDefaultRules());
