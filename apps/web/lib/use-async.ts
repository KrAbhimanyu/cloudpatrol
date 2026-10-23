"use client";

/**
 * A small data-fetching hook for the dashboard pages.
 *
 * It exists so every page handles the same four states the same way: loading,
 * error, empty and loaded. The alternative — each page calling `fetch` in an
 * effect with its own ad-hoc state — is how an error ends up rendering as an
 * empty list, which for a cost tool reads as "you have no waste" when the
 * truth is "the request failed".
 *
 * Two design notes, both driven by the React compiler rules this codebase
 * follows:
 *
 * * `loading` is *derived* from whether the stored result belongs to the
 *   current key, rather than set synchronously at the top of the effect. That
 *   avoids the cascading-render warning, and means a background refresh does
 *   not flash a spinner over data that is already on screen.
 * * The fetcher is held in a ref that is updated inside its own effect. Effects
 *   run in declaration order, so the ref is current before the fetch effect
 *   below it runs.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

interface Result<T> {
  key: string;
  data: T | null;
  error: string | null;
}

export function useAsync<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
  options: {
    /**
     * Poll every `refetchIntervalMs` while `shouldPoll` returns true for the
     * data most recently loaded. Deciding from the data lets a page poll a
     * queue that is draining and stop once it is empty, without the page
     * having to hold a second copy of that state.
     */
    refetchIntervalMs?: number;
    shouldPoll?: (data: T | null) => boolean;
    enabled?: boolean;
  } = {},
): AsyncState<T> {
  const { refetchIntervalMs, shouldPoll, enabled = true } = options;
  const [nonce, setNonce] = useState(0);
  const [result, setResult] = useState<Result<T>>({ key: "\u0000", data: null, error: null });
  // Mirrors `result` for the poll timer, which runs outside React's render.
  const resultRef = useRef(result);

  // The key encodes everything that should trigger a fresh load. Comparing the
  // stored key against the current one is what lets `loading` be derived.
  const key = JSON.stringify([deps, nonce, enabled]);

  const fetcherRef = useRef(fetcher);
  const shouldPollRef = useRef(shouldPoll);
  useEffect(() => {
    fetcherRef.current = fetcher;
    shouldPollRef.current = shouldPoll;
    resultRef.current = result;
  });

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    let cancelled = false;

    const run = () => {
      fetcherRef
        .current(controller.signal)
        .then((data) => {
          if (!cancelled) setResult({ key, data, error: null });
        })
        .catch((cause: unknown) => {
          if (cancelled || controller.signal.aborted) return;
          setResult({
            key,
            data: null,
            error: cause instanceof Error ? cause.message : "Something went wrong.",
          });
        });
    };

    run();

    let timer: ReturnType<typeof setInterval> | undefined;
    if (refetchIntervalMs && refetchIntervalMs > 0) {
      timer = setInterval(() => {
        // Read through the ref so the poll sees the latest loaded data rather
        // than the value captured when the effect started.
        if (shouldPollRef.current && !shouldPollRef.current(resultRef.current.data)) return;
        run();
      }, refetchIntervalMs);
    }

    return () => {
      cancelled = true;
      controller.abort();
      if (timer) clearInterval(timer);
    };
  }, [key, enabled, refetchIntervalMs]);


  const reload = useCallback(() => setNonce((n) => n + 1), []);

  // `settled` is false only while the very first load for this key is in
  // flight. A poll reuses the same key, so its result replaces the stored one
  // without a loading flash; a changed key (a different workspace, or a manual
  // reload) drops the previous data rather than showing it under the new
  // heading.
  const settled = result.key === key;
  return {
    data: settled ? result.data : null,
    loading: enabled && !settled,
    error: settled ? result.error : null,
    reload,
  };
}
