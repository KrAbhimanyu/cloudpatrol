"use client";

/**
 * Dashboard: the summary across connected accounts.
 *
 * Every figure here is fetched, and each of the four sources (accounts,
 * findings, savings ledger, cost summary) reports its own failure. A tile whose
 * data could not be loaded shows "—" and an explanation rather than a zero,
 * because a zero on a cost dashboard reads as a fact.
 */

import Link from "next/link";
import { useCallback } from "react";

import { RequireSession } from "@/components/RequireSession";
import { Card, EmptyState, ErrorState, LoadingState, PageHeader, Stat } from "@/components/ui";
import { api } from "@/lib/api";
import { detectorLabel } from "@/lib/detectors";
import { formatMoney, formatNumber } from "@/lib/format";
import { useAsync } from "@/lib/use-async";
import { useSessionRequest } from "@/lib/use-session-request";
import type {
  AwsAccount,
  CostSummary,
  Finding,
  Paginated,
  SavingsEntry,
  SavingsLedger,
} from "@/lib/types";

export default function DashboardPage() {
  return (
    <RequireSession>
      <DashboardContent />
    </RequireSession>
  );
}

function DashboardContent() {
  const { options, ready } = useSessionRequest();

  const accounts = useAsync<Paginated<AwsAccount>>(
    useCallback(
      (signal: AbortSignal) => {
        if (!options) return Promise.reject(new Error("No workspace selected."));
        return api.listAccounts({ ...options, signal });
      },
      [options],
    ),
    [options],
    { enabled: ready },
  );

  const findings = useAsync<Paginated<Finding>>(
    useCallback(
      (signal: AbortSignal) => {
        if (!options) return Promise.reject(new Error("No workspace selected."));
        return api.listFindings({ ...options, signal });
      },
      [options],
    ),
    [options],
    { enabled: ready },
  );

  const ledger = useAsync<SavingsLedger>(
    useCallback(
      (signal: AbortSignal) => {
        if (!options) return Promise.reject(new Error("No workspace selected."));
        return api.savingsLedger({ ...options, signal });
      },
      [options],
    ),
    [options],
    { enabled: ready },
  );

  const costs = useAsync<CostSummary>(
    useCallback(
      (signal: AbortSignal) => {
        if (!options) return Promise.reject(new Error("No workspace selected."));
        return api.costSummary({ ...options, signal });
      },
      [options],
    ),
    [options],
    { enabled: ready },
  );

  if (!ready) return <LoadingState label="Loading workspace…" />;

  const openFindings = (findings.data?.items ?? []).filter(
    (finding) => finding.state !== "dismissed",
  );
  const byDetector = summariseByDetector(ledger.data?.entries ?? []);

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="A summary of what CloudPatrol has found across your connected accounts."
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Potential monthly"
          value={
            ledger.data ? formatMoney(ledger.data.potential_monthly_savings, ledger.data.currency) : "—"
          }
          hint={ledger.error ? "Ledger could not be loaded" : "Estimated, not yet achieved"}
          emphasis
        />
        <Stat
          label="Verified monthly"
          value={
            ledger.data ? formatMoney(ledger.data.verified_monthly_savings, ledger.data.currency) : "—"
          }
          hint={ledger.error ? "Ledger could not be loaded" : "Confirmed by post-change evidence"}
        />
        <Stat
          label="Open findings"
          value={findings.data ? formatNumber(openFindings.length) : "—"}
          hint={
            findings.error
              ? "Findings could not be loaded"
              : `${openFindings.filter((f) => f.estimated_monthly_savings === null).length} without a price`
          }
        />
        <Stat
          label="Accounts connected"
          value={accounts.data ? formatNumber(accounts.data.items.length) : "—"}
          hint={accounts.error ? "Accounts could not be loaded" : "Read-only role"}
        />
      </div>

      {costs.data && !costs.data.available && (
        <p
          role="status"
          className="mt-4 rounded-lg border border-amber-300 bg-amber-50 px-4 py-2.5 text-xs text-amber-900"
        >
          Billing data is not available for this account. The read-only role may not include
          <span className="font-mono"> ce:GetCostAndUsage</span>, or no scan has read the bill
          yet. This is not the same as a zero bill.
        </p>
      )}

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card
          title="Potential savings by detector"
          description="Which checks are finding the most opportunity."
        >
          {ledger.loading ? (
            <LoadingState />
          ) : ledger.error ? (
            <ErrorState message={ledger.error} onRetry={ledger.reload} />
          ) : byDetector.length === 0 ? (
            <p className="text-sm text-slate-500">No priced findings yet.</p>
          ) : (
            <ul className="space-y-3">
              {byDetector.map(([detector, amount]) => {
                const total = Number(ledger.data?.potential_monthly_savings) || 1;
                const share = Math.max(0, Math.min(100, (Number(amount) / total) * 100));
                return (
                  <li key={detector}>
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="text-sm text-slate-700">{detectorLabel(detector)}</span>
                      <span className="text-sm font-semibold tabular-nums text-slate-900">
                        {formatMoney(amount, ledger.data?.currency ?? "USD")}
                      </span>
                    </div>
                    <div
                      className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-slate-100"
                      role="presentation"
                    >
                      <div
                        className="h-full rounded-full bg-brand-500"
                        style={{ width: `${share}%` }}
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card
          title="Highest-priority findings"
          description="Ordered by severity, then by estimated value."
          action={
            <Link
              href="/findings"
              className="text-xs font-semibold text-brand-700 hover:underline"
            >
              View all
            </Link>
          }
        >
          {findings.loading ? (
            <LoadingState />
          ) : findings.error ? (
            <ErrorState message={findings.error} onRetry={findings.reload} />
          ) : openFindings.length === 0 ? (
            <EmptyState
              title="Nothing to review"
              description="Run a scan to look for idle resources in your account."
            />
          ) : (
            <ul className="divide-y divide-slate-100">
              {openFindings.slice(0, 4).map((finding) => (
                <li key={finding.id} className="flex items-start justify-between gap-4 py-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-900">{finding.title}</p>
                    <p className="mt-0.5 font-mono text-xs text-slate-500">
                      {finding.resource_id} · {finding.region}
                    </p>
                  </div>
                  <span className="shrink-0 text-sm font-semibold tabular-nums text-slate-900">
                    {formatMoney(finding.estimated_monthly_savings, finding.currency)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {costs.data && costs.data.available && (
        <Card
          title="Reported spend"
          description="Read from Cost Explorer, separate from the savings ledger."
          className="mt-6"
        >
          {costs.data.by_service.length === 0 ? (
            <p className="text-sm text-slate-500">No cost observations recorded yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Reported spend by service</caption>
                <thead>
                  <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Service
                    </th>
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Amount
                    </th>
                    <th scope="col" className="py-2 font-medium">
                      Period
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {costs.data.by_service.map((row) => (
                    <tr key={row.id}>
                      <td className="py-2 pr-4 text-slate-800">{row.service}</td>
                      <td className="py-2 pr-4 tabular-nums text-slate-900">
                        {formatMoney(row.amount, row.currency)}
                      </td>
                      <td className="py-2 text-xs text-slate-600">
                        {row.period_start} → {row.period_end}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </>
  );
}

/**
 * Potential savings grouped by detector.
 *
 * Only potential entries are counted. Grouping a verified figure here would put
 * a realised saving in the same bar chart as an estimate, which is the exact
 * confusion the ledger's separate bases exist to prevent.
 */
function summariseByDetector(entries: SavingsEntry[]): [string, string][] {
  const totals = new Map<string, number>();
  for (const entry of entries) {
    if (entry.basis !== "potential" || !entry.detector) continue;
    totals.set(entry.detector, (totals.get(entry.detector) ?? 0) + Number(entry.monthly_amount));
  }
  return [...totals.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([detector, amount]) => [detector, amount.toFixed(2)]);
}
