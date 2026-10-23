"use client";

/**
 * Findings list.
 *
 * The savings figures shown here come from the ledger, not from summing the
 * findings client-side, so the number on this page and the number on the
 * savings page are the same number computed the same way.
 */

import { useCallback } from "react";

import { FindingCard } from "@/components/FindingCard";
import { RequireSession } from "@/components/RequireSession";
import { EmptyState, ErrorState, LoadingState, PageHeader, Stat } from "@/components/ui";
import { api } from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/detectors";
import { formatMoney, formatNumber } from "@/lib/format";
import { useAsync } from "@/lib/use-async";
import { useSessionRequest } from "@/lib/use-session-request";
import type { Finding, Paginated, SavingsLedger } from "@/lib/types";

export default function FindingsPage() {
  return (
    <RequireSession>
      <FindingsContent />
    </RequireSession>
  );
}

function FindingsContent() {
  const { options, ready } = useSessionRequest();

  const fetchFindings = useCallback(
    (signal: AbortSignal) => {
      if (!options) return Promise.reject(new Error("No workspace selected."));
      return api.listFindings({ ...options, signal });
    },
    [options],
  );
  const findings = useAsync<Paginated<Finding>>(fetchFindings, [options], { enabled: ready });

  const fetchLedger = useCallback(
    (signal: AbortSignal) => {
      if (!options) return Promise.reject(new Error("No workspace selected."));
      return api.savingsLedger({ ...options, signal });
    },
    [options],
  );
  const ledger = useAsync<SavingsLedger>(fetchLedger, [options], { enabled: ready });

  const all = findings.data?.items ?? [];
  const open = all
    .filter((finding) => finding.state !== "dismissed")
    .sort((a, b) => {
      const severity = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
      if (severity !== 0) return severity;
      // Within a severity band, the larger estimated value first. Findings with
      // no estimate sort last, since they carry no comparable number.
      return Number(b.estimated_monthly_savings ?? -1) - Number(a.estimated_monthly_savings ?? -1);
    });

  const potential = ledger.data?.potential_monthly_savings ?? null;
  const currency = ledger.data?.currency ?? "USD";
  const withoutEstimate = all.filter(
    (finding) => finding.estimated_monthly_savings === null && finding.state !== "dismissed",
  ).length;

  return (
    <>
      <PageHeader
        title="Findings"
        description="Every finding shows the resource, the measurement behind it, and what to check before acting."
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <Stat
          label="Open findings"
          value={formatNumber(open.length)}
          hint="Not yet dismissed"
        />
        <Stat
          label="Potential monthly"
          value={potential === null ? "—" : formatMoney(potential, currency)}
          hint="From the savings ledger"
          emphasis
        />
        <Stat
          label="Without a price"
          value={formatNumber(withoutEstimate)}
          hint="Flagged, but not costed"
        />
      </div>

      {!ready ? (
        <LoadingState label="Loading workspace…" />
      ) : findings.loading ? (
        <LoadingState />
      ) : findings.error ? (
        <ErrorState message={findings.error} onRetry={findings.reload} />
      ) : open.length === 0 ? (
        <EmptyState
          title="No open findings"
          description="Either your account has no idle resources, or no scan has run yet."
        />
      ) : (
        <div className="space-y-4">
          {open.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              onReviewed={() => {
                findings.reload();
                ledger.reload();
              }}
            />
          ))}
        </div>
      )}

      <p className="mt-6 text-xs leading-relaxed text-slate-500">
        Estimates assume on-demand pricing for the region shown and do not account for Savings
        Plans, Reserved Instances or enterprise discounts. Treat them as an upper bound for
        prioritisation, not a forecast.
      </p>
    </>
  );
}
