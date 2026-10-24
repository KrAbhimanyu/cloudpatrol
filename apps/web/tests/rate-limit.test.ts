/**
 * The token bucket.
 *
 * The clock is injected, so these tests advance time instead of sleeping, and
 * they assert on the refill behaviour rather than only on the first refusal —
 * a limiter that never refills would pass a naive test and lock out every user.
 */

import { describe, expect, it } from "vitest";

import { buildDefaultRules, hashKey, TokenBucketRateLimiter } from "@/lib/security/rate-limit";

/** A limiter with a controllable clock. */
function limiter(
  rules: Record<string, { capacity: number; refillPerSecond: number }> = {
    test: { capacity: 3, refillPerSecond: 1 },
  },
  options: { maxKeys?: number } = {},
) {
  let now = 0;
  const instance = new TokenBucketRateLimiter(rules, {
    ...options,
    now: () => now,
  });
  return {
    instance,
    advance: (seconds: number) => {
      now += seconds;
    },
  };
}

describe("TokenBucketRateLimiter", () => {
  it("allows a burst up to the capacity", () => {
    const { instance } = limiter();
    expect(instance.check("test", "k").allowed).toBe(true);
    expect(instance.check("test", "k").allowed).toBe(true);
    expect(instance.check("test", "k").allowed).toBe(true);
  });

  it("refuses the request past the capacity", () => {
    const { instance } = limiter();
    for (let i = 0; i < 3; i += 1) instance.check("test", "k");
    expect(instance.check("test", "k").allowed).toBe(false);
  });

  it("reports a retry delay when it refuses", () => {
    const { instance } = limiter();
    for (let i = 0; i < 3; i += 1) instance.check("test", "k");
    const decision = instance.check("test", "k");
    // One token, refilling at one per second.
    expect(decision.retryAfterSeconds).toBe(1);
  });

  it("refills over time", () => {
    const { instance, advance } = limiter();
    for (let i = 0; i < 3; i += 1) instance.check("test", "k");
    expect(instance.check("test", "k").allowed).toBe(false);

    advance(1);
    expect(instance.check("test", "k").allowed).toBe(true);
  });

  it("does not refill past the capacity", () => {
    const { instance, advance } = limiter();
    advance(1000);
    expect(instance.check("test", "k").allowed).toBe(true);
    expect(instance.check("test", "k").allowed).toBe(true);
    expect(instance.check("test", "k").allowed).toBe(true);
    expect(instance.check("test", "k").allowed).toBe(false);
  });

  it("tracks each key separately", () => {
    const { instance } = limiter();
    for (let i = 0; i < 3; i += 1) instance.check("test", "a");
    expect(instance.check("test", "a").allowed).toBe(false);
    expect(instance.check("test", "b").allowed).toBe(true);
  });

  it("tracks each class separately", () => {
    const { instance } = limiter({
      one: { capacity: 1, refillPerSecond: 1 },
      two: { capacity: 1, refillPerSecond: 1 },
    });
    expect(instance.check("one", "k").allowed).toBe(true);
    expect(instance.check("one", "k").allowed).toBe(false);
    expect(instance.check("two", "k").allowed).toBe(true);
  });

  it("fails open for an unknown class, so a config gap does not take the route down", () => {
    const { instance } = limiter();
    for (let i = 0; i < 100; i += 1) {
      expect(instance.check("not-configured", "k").allowed).toBe(true);
    }
  });

  it("bounds the number of keys, so a key-cycling attacker cannot grow the map", () => {
    const { instance } = limiter({ test: { capacity: 1, refillPerSecond: 1 } }, { maxKeys: 10 });
    for (let i = 0; i < 1000; i += 1) {
      instance.check("test", `key-${i}`);
    }
    // Not directly observable, so it is inferred: the most recent key is still
    // tracked (its bucket is spent) while an old one has been evicted and got a
    // fresh bucket. That is the documented trade-off of a bounded map.
    expect(instance.check("test", "key-999").allowed).toBe(false);
    expect(instance.check("test", "key-0").allowed).toBe(true);
  });

  it("supports a cost above one", () => {
    const { instance } = limiter({ test: { capacity: 10, refillPerSecond: 1 } });
    expect(instance.check("test", "k", 10).allowed).toBe(true);
    expect(instance.check("test", "k", 1).allowed).toBe(false);
  });
});

describe("hashKey", () => {
  it("is deterministic", () => {
    expect(hashKey("value")).toBe(hashKey("value"));
  });

  it("does not contain the input", () => {
    const secret = "super-secret-cookie-value";
    expect(hashKey(secret)).not.toContain(secret);
  });

  it("is a fixed-length hex string", () => {
    expect(hashKey("a")).toMatch(/^[0-9a-f]{32}$/);
    expect(hashKey("a".repeat(10_000))).toMatch(/^[0-9a-f]{32}$/);
  });

  it("separates distinct inputs", () => {
    expect(hashKey("a")).not.toBe(hashKey("b"));
  });
});

describe("buildDefaultRules", () => {
  it("configures the csp-report class", () => {
    expect(buildDefaultRules()["csp-report"]).toBeDefined();
  });

  it("allows a burst large enough for a page emitting several violations", () => {
    // A page with a real policy problem can emit a handful of violations as it
    // loads; throttling those would hide the problem the endpoint exists to show.
    expect(buildDefaultRules()["csp-report"]?.capacity).toBeGreaterThanOrEqual(10);
  });

  it("still bounds the sustained rate", () => {
    expect(buildDefaultRules()["csp-report"]?.refillPerSecond).toBeLessThanOrEqual(5);
  });
});
