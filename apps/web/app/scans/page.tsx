"use client";

/**
 * Scan history and scan creation.
 *
 * Scanning is asynchronous, so the list polls while any scan is queued or
 * running and stops when none are. That keeps a running scan's progress visible
 * without a permanent timer that keeps fetching once everything has settled.
 *
 * "Run a scan" is disabled until an account is chosen, and while a scan for
 * that account is already in flight — the API enforces the same rule, but
 * showing it here avoids a pointless round trip.
 */

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import { RequireSession } from "@/components/RequireSession";
import { ScanRow } from "@/components/ScanRow";
import { Card, EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { useSessionRequest } from "@/lib/use-session-request";
import type { AwsAccount, Paginated, Scan } from "@/lib/types";

const ACTIVE_STATUSES = new Set(["queued", "running"]);
const POLL_INTERVAL_MS = 3000;

export default function ScansPage() {
  return (
    <RequireSession>
      <ScansContent />
    </RequireSession>
  );
}

function ScansContent() {
  const { options, ready } = useSessionRequest();
  const [selectedAccount, setSelectedAccount] = useState<string>("");
  const [starting, setStarting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchAccounts = useCallback(
    (signal: AbortSignal) => {
      if (!options) return Promise.reject(new Error("No workspace selected."));
      return api.listAccounts({ ...options, signal });
    },
    [options],
  );
  const accounts = useAsync<Paginated<AwsAccount>>(fetchAccounts, [options], { enabled: ready });

  const fetchScans = useCallback(
    (signal: AbortSignal) => {
      if (!options) return Promise.reject(new Error("No workspace selected."));
      return api.listScans({ ...options, signal });
    },
    [options],
  );
  const scans = useAsync<Paginated<Scan>>(fetchScans, [options], {
    enabled: ready,
    // Poll only while a scan is in flight. A permanent timer would keep hitting
    // the API on an idle workspace for no reason.
    refetchIntervalMs: POLL_INTERVAL_MS,
    shouldPoll: (page) =>
      (page?.items ?? []).some((scan) => ACTIVE_STATUSES.has(scan.status)),
  });

  const accountList = useMemo(() => accounts.data?.items ?? [], [accounts.data]);
  const scanList = useMemo(() => scans.data?.items ?? [], [scans.data]);

  const hasActiveScan = scanList.some((scan) => ACTIVE_STATUSES.has(scan.status));

  const activeForSelected = useMemo(
    () =>
      selectedAccount !== "" &&
      scanList.some(
        (scan) => scan.aws_account_id === selectedAccount && ACTIVE_STATUSES.has(scan.status),
      ),
    [scanList, selectedAccount],
  );

  const canStart =
    ready && selectedAccount !== "" && !starting && !hasActiveScan && accountList.length > 0;

  async function startScan() {
    if (!options || !canStart) return;
    setStarting(true);
    setActionError(null);
    try {
      await api.startScan(options, { aws_account_id: selectedAccount });
      // The refetch brings the queued scan into the list, which switches
      // polling on for as long as it runs.
      scans.reload();
    } catch (cause) {
      setActionError(
        cause instanceof ApiError
          ? cause.message
          : cause instanceof Error
            ? cause.message
            : "Could not start the scan.",
      );
    } finally {
      setStarting(false);
    }
  }

  const sorted = [...scanList].sort((a, b) => b.created_at.localeCompare(a.created_at));

  return (
    <>
      <PageHeader
        title="Scans"
        description="Each scan reads your account through the read-only role and records what it found. Nothing is changed."
      />

      <Card className="mb-6" title="Run a scan" description="Choose the account to inspect.">
        {!ready ? (
          <LoadingState label="Loading workspace…" />
        ) : accounts.loading ? (
          <LoadingState />
        ) : accounts.error ? (
          <ErrorState message={accounts.error} onRetry={accounts.reload} />
        ) : accountList.length === 0 ? (
          <EmptyState
            title="No accounts connected"
            description="Connect an AWS account before running a scan."
            action={
              <Link
                href="/accounts"
                className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
              >
                Connect an account
              </Link>
            }
          />
        ) : (
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-56">
              <label htmlFor="scan-account" className="block text-xs font-medium text-slate-700">
                Account
              </label>
              <select
                id="scan-account"
                value={selectedAccount}
                onChange={(event) => setSelectedAccount(event.target.value)}
                className="mt-1 w-full rounded-md border border-slate-300 bg-white px-2.5 py-2 text-sm shadow-sm"
              >
                <option value="">Select an account…</option>
                {accountList.map((account) => (
                  <option key={account.id} value={account.id}>
                    {account.label} ({account.account_id})
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              onClick={() => void startScan()}
              disabled={!canStart}
              className="rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {starting ? "Starting…" : "Run a scan"}
            </button>
          </div>
        )}

        {hasActiveScan && (
          <p role="status" className="mt-3 text-xs text-sky-800">
            A scan is in progress. Scans run one at a time per workspace, so a second cannot
            start until it finishes.
          </p>
        )}
        {activeForSelected && !hasActiveScan && (
          <p role="status" className="mt-3 text-xs text-sky-800">
            This account already has a scan in progress.
          </p>
        )}
        {actionError && (
          <p role="alert" className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-900">
            {actionError}
          </p>
        )}
      </Card>

      {!ready ? (
        <LoadingState label="Loading workspace…" />
      ) : scans.loading ? (
        <LoadingState />
      ) : scans.error ? (
        <ErrorState message={scans.error} onRetry={scans.reload} />
      ) : sorted.length === 0 ? (
        <EmptyState
          title="No scans yet"
          description="Connect an AWS account, then run your first scan to look for idle resources."
        />
      ) : (
        <div className="space-y-4">
          {sorted.map((scan) => (
            <ScanRow key={scan.id} scan={scan} />
          ))}
        </div>
      )}

      <Card
        title="How a scan works"
        description="What happens between pressing the button and seeing findings."
        className="mt-6"
      >
        <ol className="space-y-3 text-sm text-slate-600">
          <li className="flex gap-3">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700">
              1
            </span>
            <span>
              CloudPatrol assumes the read-only role and confirms the returned account identity
              matches the one you registered.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700">
              2
            </span>
            <span>
              It lists resources in each selected region, following pagination to the end so a
              large account is not silently truncated.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700">
              3
            </span>
            <span>
              It reads CloudWatch metrics for running instances and billing data from Cost
              Explorer, then runs each detector over the collected snapshot.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700">
              4
            </span>
            <span>
              If any region or service could not be read, the scan is marked partial and the
              reason is recorded, so you always know how complete the result is.
            </span>
          </li>
        </ol>
      </Card>
    </>
  );
}
