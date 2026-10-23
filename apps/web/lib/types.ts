/**
 * Types mirroring the CloudPatrol API contract.
 *
 * These are written by hand rather than generated, because the shapes carry
 * meaning that generation would flatten — for example that
 * `estimated_monthly_savings` is a decimal *string*, not a number. Money is
 * carried as a string end to end so no float rounding is introduced in the
 * browser.
 */

export type Severity = "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingState = "estimated" | "acknowledged" | "dismissed" | "verified";
export type ScanStatus = "queued" | "running" | "completed" | "partial" | "failed";
export type AccountStatus = "pending" | "validated" | "invalid";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  role: string;
}

export interface AwsAccount {
  id: string;
  organization_id: string;
  label: string;
  account_id: string;
  role_arn: string;
  regions: string[];
  status: AccountStatus;
  status_message: string | null;
  last_validated_at: string | null;
  created_at: string;
}

export interface PartialFailure {
  service: string;
  region: string | null;
  code: string;
  message: string;
}

export interface Scan {
  id: string;
  organization_id: string;
  aws_account_id: string;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  resource_count: number;
  finding_count: number;
  partial_failures: PartialFailure[];
  error_message: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  organization_id: string;
  scan_id: string;
  aws_account_id: string;
  detector: string;
  resource_type: string;
  resource_id: string;
  region: string;
  severity: Severity;
  confidence: Confidence;
  state: FindingState;
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  recommended_action: string;
  /**
   * Decimal string, or null when no defensible figure could be produced.
   * Null is meaningful: it means "we could not price this", not "zero".
   */
  estimated_monthly_savings: string | null;
  currency: string;
  created_at: string;
}

export interface SavingsSummary {
  potential_monthly_savings: string;
  annualised_potential_savings: string;
  verified_monthly_savings: string;
  open_finding_count: number;
  verified_finding_count: number;
  dismissed_finding_count: number;
  findings_without_estimate: number;
  monthly_savings_by_detector: Record<string, string>;
  currency: string;
}

/** The savings ledger buckets. Only `verified` is money actually saved. */
export type SavingsBasis =
  | "potential"
  | "approved"
  | "implemented"
  | "verified"
  | "inconclusive";

export interface SavingsEntry {
  id: string;
  organization_id: string;
  aws_account_id: string;
  finding_id: string | null;
  basis: SavingsBasis;
  monthly_amount: string;
  currency: string;
  evidence: Record<string, unknown> | null;
  measured_from: string | null;
  measured_to: string | null;
  created_by: string | null;
  created_at: string;
  /** The detector behind the originating finding, resolved by the API. */
  detector: string | null;
}

/**
 * Ledger totals. Each basis is its own field and there is deliberately no
 * combined total: adding `potential` to `verified` would state that an
 * opportunity is as good as money saved.
 */
export interface SavingsLedger {
  currency: string;
  potential_monthly_savings: string;
  approved_monthly_savings: string;
  implemented_monthly_savings: string;
  verified_monthly_savings: string;
  inconclusive_monthly_savings: string;
  potential_count: number;
  approved_count: number;
  implemented_count: number;
  verified_count: number;
  inconclusive_count: number;
  annualised_verified_savings: string;
  entries: SavingsEntry[];
}

export interface CostObservation {
  id: string;
  organization_id: string;
  aws_account_id: string;
  scan_id: string | null;
  service: string;
  amount: string;
  currency: string;
  period_start: string;
  period_end: string;
  created_at: string;
}

/**
 * Reported spend. `available` is false when Cost Explorer could not be read;
 * the totals are then null rather than "0", so "we could not read the bill" is
 * never rendered as "the bill is $0".
 */
export interface CostSummary {
  available: boolean;
  currency: string;
  period_start: string | null;
  period_end: string | null;
  total_amount: string | null;
  by_service: CostObservation[];
}

export interface Paginated<T> {
  items: T[];
  total: number;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    request_id?: string;
  };
}
