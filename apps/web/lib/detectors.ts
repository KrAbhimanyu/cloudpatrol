/**
 * Presentation metadata for detectors, severities, confidence and states.
 *
 * Centralised so a label is defined once. Each detector's `method` string is
 * shown in the UI, because a recommendation is only actionable if the user can
 * see how it was reached.
 */

export interface DetectorMeta {
  label: string;
  /** What the detector looks for, in plain language. */
  method: string;
  /** The limitation a reader must understand before acting. */
  caveat: string;
}

export const DETECTOR_META: Record<string, DetectorMeta> = {
  unattached_ebs_volume: {
    label: "Unattached EBS volume",
    method: "A volume whose state is 'available', meaning it is not attached to any instance.",
    caveat:
      "A detached volume may be a deliberate snapshot source or a backup awaiting restore. Confirm it is not needed before deleting.",
  },
  unassociated_elastic_ip: {
    label: "Unassociated Elastic IP",
    method:
      "An Elastic IP with no association to an instance or network interface while the account holds it.",
    caveat:
      "AWS charges for idle Elastic IPs on current account types. An address reserved for failover may be intentionally idle.",
  },
  low_utilisation_ec2: {
    label: "Low-utilisation EC2 instance",
    method:
      "A running instance whose average CPU utilisation over the observation window sits below the configured threshold.",
    caveat:
      "CPU alone does not describe memory, disk or network pressure. This flags a candidate for review, not a proven oversized instance.",
  },
};

export function detectorLabel(detector: string): string {
  return DETECTOR_META[detector]?.label ?? detector.replace(/_/g, " ");
}

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-100 text-red-800 ring-red-600/20",
  high: "bg-orange-100 text-orange-800 ring-orange-600/20",
  medium: "bg-amber-100 text-amber-800 ring-amber-600/20",
  low: "bg-slate-100 text-slate-700 ring-slate-600/20",
};

export const CONFIDENCE_STYLES: Record<string, string> = {
  high: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
  medium: "bg-sky-100 text-sky-800 ring-sky-600/20",
  low: "bg-slate-100 text-slate-600 ring-slate-500/20",
};

export const STATE_LABELS: Record<string, string> = {
  estimated: "Estimated",
  acknowledged: "Acknowledged",
  dismissed: "Dismissed",
  verified: "Verified",
};

export const STATE_STYLES: Record<string, string> = {
  estimated: "bg-blue-100 text-blue-800 ring-blue-600/20",
  acknowledged: "bg-violet-100 text-violet-800 ring-violet-600/20",
  dismissed: "bg-slate-100 text-slate-600 ring-slate-500/20",
  verified: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
};

export const SCAN_STATUS_LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  partial: "Completed with gaps",
  failed: "Failed",
};

export const SCAN_STATUS_STYLES: Record<string, string> = {
  queued: "bg-slate-100 text-slate-700 ring-slate-600/20",
  running: "bg-sky-100 text-sky-800 ring-sky-600/20",
  completed: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
  partial: "bg-amber-100 text-amber-900 ring-amber-600/20",
  failed: "bg-red-100 text-red-800 ring-red-600/20",
};
