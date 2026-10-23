"use client";

import { useState } from "react";

import {
  CONFIDENCE_STYLES,
  DETECTOR_META,
  SEVERITY_STYLES,
  STATE_LABELS,
  STATE_STYLES,
  detectorLabel,
} from "@/lib/detectors";
import { NOT_PRICED_LABEL, formatMoney } from "@/lib/format";
import type { Finding } from "@/lib/types";

import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session-context";
import { Badge } from "./ui";

/**
 * A single finding, rendered with its reasoning visible.
 *
 * The evidence block is not hidden behind a disclosure by default: a savings
 * claim a user cannot audit is a claim they cannot safely act on. The price
 * source and the assumption are shown alongside the number.
 *
 * The review actions (acknowledge, dismiss) call the API and are disabled while
 * a request is in flight, so a double click cannot send two conflicting state
 * changes. Dismissing is destructive to the ledger — it withdraws the potential
 * saving — so it is labelled to say so rather than reading as a neutral toggle.
 */
export function FindingCard({
  finding,
  onReviewed,
}: {
  finding: Finding;
  onReviewed?: () => void;
}) {
  const { token, organizationId } = useSession();
  const [pending, setPending] = useState<"acknowledged" | "dismissed" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const meta = DETECTOR_META[finding.detector];
  const priced = finding.estimated_monthly_savings !== null;
  const reviewable = finding.state === "estimated" || finding.state === "acknowledged";
  const canAct = reviewable && token !== null && organizationId !== null && pending === null;

  async function review(state: "acknowledged" | "dismissed") {
    if (!token || !organizationId || !canAct) return;
    setPending(state);
    setError(null);
    try {
      await api.reviewFinding({ token, organizationId }, finding.id, { state });
      onReviewed?.();
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause.message
          : cause instanceof Error
            ? cause.message
            : "Could not update the finding.",
      );
    } finally {
      setPending(null);
    }
  }

  return (
    <article
      className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
      data-testid="finding-card"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.low}>
              {finding.severity} severity
            </Badge>
            <Badge className={STATE_STYLES[finding.state] ?? STATE_STYLES.estimated}>
              {STATE_LABELS[finding.state] ?? finding.state}
            </Badge>
            <Badge className={CONFIDENCE_STYLES[finding.confidence] ?? CONFIDENCE_STYLES.low}>
              {finding.confidence} confidence
            </Badge>
          </div>
          <h3 className="mt-2.5 text-base font-semibold text-slate-900">{finding.title}</h3>
          <p className="mt-1 text-sm text-slate-600">{finding.summary}</p>
        </div>

        <div className="shrink-0 text-right">
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Potential monthly
          </p>
          <p
            className={`mt-1 text-xl font-semibold tabular-nums ${
              priced ? "text-slate-900" : "text-slate-400"
            }`}
          >
            {formatMoney(finding.estimated_monthly_savings, finding.currency)}
          </p>
          {!priced && (
            <p className="mt-0.5 max-w-[12rem] text-xs text-slate-500">
              {NOT_PRICED_LABEL}: no defensible figure without a chosen target.
            </p>
          )}
        </div>
      </div>

      <dl className="mt-4 grid gap-x-6 gap-y-2 border-t border-slate-100 pt-4 text-xs sm:grid-cols-2">
        <div className="flex gap-2">
          <dt className="w-24 shrink-0 font-medium text-slate-500">Resource</dt>
          <dd className="min-w-0 break-all font-mono text-slate-800">{finding.resource_id}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-24 shrink-0 font-medium text-slate-500">Region</dt>
          <dd className="font-mono text-slate-800">{finding.region}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-24 shrink-0 font-medium text-slate-500">Detector</dt>
          <dd className="text-slate-800">{detectorLabel(finding.detector)}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-24 shrink-0 font-medium text-slate-500">Detected</dt>
          <dd className="text-slate-800">{finding.created_at.slice(0, 10)}</dd>
        </div>
      </dl>

      <div className="mt-4 rounded-lg bg-slate-50 p-4">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Why this was flagged
        </h4>
        {meta && <p className="mt-1.5 text-sm text-slate-700">{meta.method}</p>}
        <EvidenceList evidence={finding.evidence} />
        {meta && (
          <p className="mt-3 border-t border-slate-200 pt-3 text-xs leading-relaxed text-slate-600">
            <span className="font-semibold">Before you act:</span> {meta.caveat}
          </p>
        )}
      </div>

      <div className="mt-4">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Recommended action
        </h4>
        <p className="mt-1.5 text-sm text-slate-700">{finding.recommended_action}</p>
      </div>

      {reviewable && (
        <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-4">
          <button
            type="button"
            onClick={() => void review("acknowledged")}
            disabled={!canAct}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {pending === "acknowledged" ? "Saving…" : "Acknowledge"}
          </button>
          <button
            type="button"
            onClick={() => void review("dismissed")}
            disabled={!canAct}
            className="rounded-lg border border-red-300 px-3 py-1.5 text-xs font-semibold text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {pending === "dismissed" ? "Saving…" : "Dismiss and withdraw estimate"}
          </button>
          <span className="text-xs text-slate-500">
            Dismissing removes this finding&apos;s potential saving from the ledger.
          </span>
        </div>
      )}

      {error && (
        <p role="alert" className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-xs text-red-900">
          {error}
        </p>
      )}
    </article>
  );
}

const EVIDENCE_LABELS: Record<string, string> = {
  size_gb: "Volume size (GiB)",
  volume_type: "Volume type",
  age_days: "Age (days)",
  retention_tag_present: "Retention tag present",
  instance_type: "Instance type",
  average_cpu_percent: "Average CPU (%)",
  datapoint_count: "Datapoints observed",
  window_days: "Observation window (days)",
  price_source: "Price source",
  price_captured_on: "Price captured on",
  assumption: "Assumption",
  hours_per_month: "Hours per month",
  public_ip: "Public IP",
};

function EvidenceList({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence);
  if (entries.length === 0) return null;

  return (
    <dl className="mt-3 grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
      {entries.map(([key, value]) => (
        <div key={key} className="flex gap-2 text-xs">
          <dt className="w-36 shrink-0 text-slate-500">{EVIDENCE_LABELS[key] ?? key}</dt>
          <dd className="min-w-0 break-words text-slate-800">{formatEvidence(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function formatEvidence(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
