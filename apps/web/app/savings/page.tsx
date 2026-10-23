"use client";

/**
 * The savings ledger.
 *
 * The page is organised around one rule: a figure is shown next to the basis it
 * actually has. Potential, approved, implemented, verified and inconclusive are
 * five separate cards, never summed. A single "total savings" tile would be the
 * most misleading thing this page could show, so it does not exist.
 *
 * Only `verified` is money that has stopped being spent, and it is the only
 * card given the emphasis treatment.
 */

import { useCallback } from "react";

import { Card, ErrorState, LoadingState, PageHeader, Stat } from "@/components/ui";
import { api } from "@/lib/api";
import { detectorLabel } from "@/lib/detectors";
import { formatDateTime, formatMoney } from "@/lib/format";
import { useAsync } from "@/lib/use-async";
import { useSessionRequest } from "@/lib/use-session-request";
import type { SavingsEntry, SavingsLedger } from "@/lib/types";

const BASIS_LABELS: Record<string, string> = {
  potential: "Potential",
  approved: "Approved",
  implemented: "Implemented",
  verified: "Verified",
  inconclusive: "Inconclusive",
};

const BASIS_HELP: Record<string, string> = {
  potential: "Estimated from findings. Not money saved.",
  approved: "A decision to act. Still not money saved.",
  implemented: "The change was made. Not yet proven.",
  verified: "Measured after the change. This is real money.",
  inconclusive: "Measured, but the result proved nothing.",
};

export default function SavingsPage() {
  const { options, ready } = useSessionRequest();

  const fetchLedger = useCallback(
    (signal: AbortSignal) => {
      if (!options) return Promise.reject(new Error("No workspace selected."));
      return api.savingsLedger({ ...options, signal });
    },
    [options],
  );

  const { data, loading, error, reload } = useAsync<SavingsLedger>(fetchLedger, [options], {
    enabled: ready,
  });

  if (!ready) return <LoadingState label="Loading workspace…" />;
  if (loading && !data) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={reload} />;
  if (!data) return <ErrorState message="No ledger data was returned." onRetry={reload} />;

  const ledger = data;
  const byDetector = summariseByDetector(ledger.entries);

  return (
    <>
      <PageHeader
        title="Savings"
        description="Five ledgers, kept deliberately separate. Only verified savings are money that has actually stopped being spent."
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Stat
          label="Potential monthly"
          value={formatMoney(ledger.potential_monthly_savings, ledger.currency)}
          hint={BASIS_HELP.potential}
        />
        <Stat
          label="Approved monthly"
          value={formatMoney(ledger.approved_monthly_savings, ledger.currency)}
          hint={BASIS_HELP.approved}
        />
        <Stat
          label="Implemented monthly"
          value={formatMoney(ledger.implemented_monthly_savings, ledger.currency)}
          hint={BASIS_HELP.implemented}
        />
        <Stat
          label="Verified monthly"
          value={formatMoney(ledger.verified_monthly_savings, ledger.currency)}
          hint={BASIS_HELP.verified}
          emphasis
        />
        <Stat
          label="Inconclusive"
          value={formatMoney(ledger.inconclusive_monthly_savings, ledger.currency)}
          hint={BASIS_HELP.inconclusive}
        />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card title="Potential savings by detector">
          {byDetector.length === 0 ? (
            <p className="text-sm text-slate-500">No priced findings yet.</p>
          ) : (
            <ul className="space-y-3">
              {byDetector.map(([detector, amount]) => (
                <li key={detector} className="flex items-baseline justify-between gap-3">
                  <span className="text-sm text-slate-700">{detectorLabel(detector)}</span>
                  <span className="text-sm font-semibold tabular-nums text-slate-900">
                    {formatMoney(amount, ledger.currency)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Why verified is separate">
          <p className="text-sm leading-relaxed text-slate-600">
            A potential saving is an estimate derived from a finding. A verified saving is a
            measured reduction, recorded with the evidence and the window it was measured over.
          </p>
          <p className="mt-3 text-sm leading-relaxed text-slate-600">
            The two are never added together. A tool that reported its own estimates back to you
            as achieved savings would be misleading, so the figures are shown side by side and
            the verified one is the only one marked as real.
          </p>
          {ledger.verified_count > 0 && (
            <p className="mt-3 text-sm leading-relaxed text-slate-600">
              Annualised, the verified figure is{" "}
              <span className="font-semibold text-slate-900">
                {formatMoney(ledger.annualised_verified_savings, ledger.currency)}
              </span>
              .
            </p>
          )}
        </Card>
      </div>

      <Card
        title="Ledger entries"
        description="Every recorded figure, with the basis it holds."
        className="mt-6"
      >
        {ledger.entries.length === 0 ? (
          <p className="text-sm text-slate-500">
            Nothing in the ledger yet. Run a scan to record potential savings from findings.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Savings ledger entries</caption>
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Basis
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Detector
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Monthly
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Measured window
                  </th>
                  <th scope="col" className="py-2 font-medium">
                    Recorded
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {ledger.entries.map((entry) => (
                  <tr key={entry.id}>
                    <td className="py-2 pr-4">
                      <span className={basisBadge(entry.basis)}>
                        {BASIS_LABELS[entry.basis] ?? entry.basis}
                      </span>
                    </td>
                    <td className="py-2 pr-4 text-slate-700">
                      {entry.detector ? detectorLabel(entry.detector) : "—"}
                    </td>
                    <td className="py-2 pr-4 tabular-nums text-slate-900">
                      {formatMoney(entry.monthly_amount, entry.currency)}
                    </td>
                    <td className="py-2 pr-4 text-xs text-slate-600">
                      {entry.measured_from && entry.measured_to
                        ? `${formatDateTime(entry.measured_from)} → ${formatDateTime(entry.measured_to)}`
                        : "—"}
                    </td>
                    <td className="py-2 text-xs text-slate-600">
                      {formatDateTime(entry.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="How estimates are produced"
        description="The assumptions behind every potential figure on this page."
        className="mt-6"
      >
        <dl className="space-y-3 text-sm">
          <div>
            <dt className="font-medium text-slate-800">Pricing source</dt>
            <dd className="mt-0.5 text-slate-600">
              A built-in reference price book, with the capture date recorded on each finding. It
              is not a live pricing feed, so treat figures as close approximations rather than
              quotes.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-slate-800">Monthly basis</dt>
            <dd className="mt-0.5 text-slate-600">
              Storage and address charges are converted to a monthly figure using a 730-hour
              month. Rounding is applied once, at the end, to avoid compounding.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-slate-800">Discounts</dt>
            <dd className="mt-0.5 text-slate-600">
              Reserved Instance and Savings Plan discounts are not applied, so estimates are
              usually higher than the reduction you would see on your bill.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-slate-800">Currency</dt>
            <dd className="mt-0.5 text-slate-600">
              Figures are shown in the currency the ledger recorded. No conversion is performed.
            </dd>
          </div>
        </dl>
      </Card>
    </>
  );
}

function basisBadge(basis: string): string {
  const base = "inline-flex rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ";
  switch (basis) {
    case "verified":
      return base + "bg-emerald-50 text-emerald-800 ring-emerald-200";
    case "implemented":
      return base + "bg-blue-50 text-blue-800 ring-blue-200";
    case "approved":
      return base + "bg-amber-50 text-amber-800 ring-amber-200";
    case "inconclusive":
      return base + "bg-slate-100 text-slate-700 ring-slate-200";
    default:
      return base + "bg-slate-50 text-slate-700 ring-slate-200";
  }
}

function summariseByDetector(entries: SavingsEntry[]): [string, string][] {
  // Only potential entries are grouped here: the detector a saving came from is
  // meaningful for an estimate derived from a finding, and grouping a verified
  // figure by detector would mix the two ledgers on screen.
  const totals = new Map<string, number>();
  for (const entry of entries) {
    if (entry.basis !== "potential" || !entry.detector) continue;
    totals.set(entry.detector, (totals.get(entry.detector) ?? 0) + Number(entry.monthly_amount));
  }
  return [...totals.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([detector, amount]) => [detector, amount.toFixed(2)]);
}
