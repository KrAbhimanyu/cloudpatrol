import { SCAN_STATUS_LABELS, SCAN_STATUS_STYLES } from "@/lib/detectors";
import { formatDateTime, formatNumber } from "@/lib/format";
import type { Scan } from "@/lib/types";

import { Badge } from "./ui";

/**
 * A scan's outcome.
 *
 * The `partial` case is given a full explanation block rather than a badge
 * alone. A partial scan means the numbers below it are incomplete, and a user
 * who misses that could conclude an account is clean when it is only partly
 * visible.
 */
export function ScanRow({ scan }: { scan: Scan }) {
  const hasGaps = scan.partial_failures.length > 0;

  return (
    <article
      className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"
      data-testid="scan-row"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={SCAN_STATUS_STYLES[scan.status] ?? SCAN_STATUS_STYLES.queued}>
              {SCAN_STATUS_LABELS[scan.status] ?? scan.status}
            </Badge>
            <span className="font-mono text-xs text-slate-500">{scan.id.slice(0, 12)}</span>
          </div>
          <p className="mt-2 text-sm text-slate-700">
            Started {formatDateTime(scan.started_at)} · Finished {formatDateTime(scan.finished_at)}
          </p>
        </div>
        <dl className="flex gap-6 text-right">
          <div>
            <dt className="text-xs text-slate-500">Resources</dt>
            <dd className="text-lg font-semibold tabular-nums text-slate-900">
              {formatNumber(scan.resource_count)}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Findings</dt>
            <dd className="text-lg font-semibold tabular-nums text-slate-900">
              {formatNumber(scan.finding_count)}
            </dd>
          </div>
        </dl>
      </div>

      {scan.error_message && (
        <p className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {scan.error_message}
        </p>
      )}

      {hasGaps && (
        <div className="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-amber-900">
            This scan has gaps
          </h3>
          <p className="mt-1 text-sm text-amber-900">
            Some data could not be read. Findings below reflect only what was visible, so an
            absence of findings is not proof of an absence of waste.
          </p>
          <ul className="mt-2.5 space-y-1.5">
            {scan.partial_failures.map((failure, index) => (
              <li key={`${failure.service}-${failure.region}-${index}`} className="text-xs">
                <span className="font-mono font-medium text-amber-900">{failure.service}</span>
                {failure.region && <span className="text-amber-800"> in {failure.region}</span>}
                <span className="text-amber-800"> — {failure.message}</span>
                <span className="ml-1 font-mono text-amber-700">({failure.code})</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}
