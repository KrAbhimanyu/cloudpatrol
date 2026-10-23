/**
 * Tests for the session store and the async data hook.
 *
 * The properties that matter for a cost tool: a request is never fired without
 * a token, a failed load is never indistinguishable from an empty one, and a
 * change of workspace drops the previous workspace's figures rather than
 * showing them under the new heading.
 */

import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearSession,
  getSnapshot,
  setOrganizationId,
  setSession,
  subscribe,
} from "@/lib/session";
import { useAsync } from "@/lib/use-async";

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("session store", () => {
  it("is empty before anything is stored", () => {
    expect(getSnapshot()).toBeNull();
  });

  it("returns the stored token and organization", () => {
    setSession({ token: "tok-1", organizationId: "org-1" });
    expect(getSnapshot()).toEqual({ token: "tok-1", organizationId: "org-1" });
  });

  it("clears both values on sign out", () => {
    setSession({ token: "tok-1", organizationId: "org-1" });
    clearSession();
    expect(getSnapshot()).toBeNull();
    expect(window.localStorage.getItem("cloudpatrol.token")).toBeNull();
  });

  it("changes the organization without touching the token", () => {
    setSession({ token: "tok-1", organizationId: "org-1" });
    setOrganizationId("org-2");
    expect(getSnapshot()).toEqual({ token: "tok-1", organizationId: "org-2" });
  });

  it("notifies subscribers when the session changes", () => {
    const listener = vi.fn();
    const unsubscribe = subscribe(listener);
    setSession({ token: "tok-1", organizationId: null });
    expect(listener).toHaveBeenCalledTimes(1);
    unsubscribe();
    setOrganizationId("org-9");
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("returns a stable reference between reads when nothing changed", () => {
    setSession({ token: "tok-1", organizationId: "org-1" });
    // An unstable reference here would loop `useSyncExternalStore` forever.
    expect(getSnapshot()).toBe(getSnapshot());
  });
});

describe("useAsync", () => {
  it("does not fetch while disabled", async () => {
    const fetcher = vi.fn().mockResolvedValue("data");
    const { result } = renderHook(() => useAsync(fetcher, ["a"], { enabled: false }));

    expect(fetcher).not.toHaveBeenCalled();
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBeNull();
  });

  it("exposes the resolved value and stops loading", async () => {
    const fetcher = vi.fn().mockResolvedValue({ value: 42 });
    const { result } = renderHook(() => useAsync(fetcher, ["a"]));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ value: 42 });
    expect(result.current.error).toBeNull();
  });

  it("surfaces a failure as an error, not as empty data", async () => {
    const fetcher = vi.fn().mockRejectedValue(new Error("AssumeRole denied."));
    const { result } = renderHook(() => useAsync(fetcher, ["a"]));

    await waitFor(() => expect(result.current.error).toBe("AssumeRole denied."));
    expect(result.current.data).toBeNull();
    expect(result.current.loading).toBe(false);
  });

  it("refetches when the dependency changes", async () => {
    const fetcher = vi.fn().mockResolvedValue("first");
    const { result, rerender } = renderHook(
      ({ key }: { key: string }) => useAsync(fetcher, [key]),
      { initialProps: { key: "a" } },
    );
    await waitFor(() => expect(result.current.data).toBe("first"));

    fetcher.mockResolvedValue("second");
    rerender({ key: "b" });

    await waitFor(() => expect(result.current.data).toBe("second"));
  });

  it("polls while shouldPoll is true and stops when it is false", async () => {
    vi.useFakeTimers();
    try {
      let active = true;
      const fetcher = vi.fn().mockResolvedValue("data");
      renderHook(() =>
        useAsync(fetcher, ["a"], {
          refetchIntervalMs: 1000,
          shouldPoll: () => active,
        }),
      );

      await vi.advanceTimersByTimeAsync(1000);
      expect(fetcher.mock.calls.length).toBeGreaterThan(1);

      const callsWhileActive = fetcher.mock.calls.length;
      active = false;
      await vi.advanceTimersByTimeAsync(3000);
      // Once the queue has drained the timer stops calling the API.
      expect(fetcher.mock.calls.length).toBe(callsWhileActive);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not poll when no interval is given", async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi.fn().mockResolvedValue("data");
      renderHook(() => useAsync(fetcher, ["a"]));
      await vi.advanceTimersByTimeAsync(5000);
      expect(fetcher).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("reload triggers a fresh fetch", async () => {
    const fetcher = vi.fn().mockResolvedValue("v1");
    const { result } = renderHook(() => useAsync(fetcher, ["a"]));
    await waitFor(() => expect(result.current.data).toBe("v1"));

    fetcher.mockResolvedValue("v2");
    result.current.reload();

    await waitFor(() => expect(result.current.data).toBe("v2"));
  });
});
