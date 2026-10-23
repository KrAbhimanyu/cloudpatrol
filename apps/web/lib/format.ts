/**
 * Display formatting helpers.
 *
 * Money arrives from the API as a decimal string. These helpers parse only to
 * format, and fall back to an explicit "not priced" label rather than
 * rendering a missing estimate as "$0.00" — those two states mean different
 * things to someone deciding what to do.
 */

export const NOT_PRICED_LABEL = "Not priced";

export function formatMoney(
  value: string | null | undefined,
  currency = "USD",
): string {
  if (value === null || value === undefined || value === "") {
    return NOT_PRICED_LABEL;
  }
  const amount = Number(value);
  if (!Number.isFinite(amount)) {
    return NOT_PRICED_LABEL;
  }
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount);
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return "—";
  }
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const diffMs = Date.now() - date.getTime();
  const minutes = Math.round(diffMs / 60000);
  if (Math.abs(minutes) < 1) return "just now";
  if (Math.abs(minutes) < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}
