/**
 * CSP violation reporting: configuration and untrusted-input handling.
 *
 * ## Why reports are worth collecting
 *
 * An enforced CSP has one failure mode that is invisible from the server: a
 * blocked resource. The browser refuses the load, the page renders without it,
 * and nothing reaches any log. A reporting endpoint is the only way to learn
 * that the policy is breaking something real rather than seeing it as a user
 * complaint about a missing style.
 *
 * ## Why this does not weaken the policy
 *
 * Adding reporting to CSP is purely additive. `report-to` and `report-uri`
 * direct where a *violation* notice is sent; neither grants permission to load
 * anything, and neither changes what the browser blocks. The app stays in
 * enforce mode — `Content-Security-Policy` is sent, not
 * `Content-Security-Policy-Report-Only` — so a violation is still prevented and
 * merely also reported. Nothing in this module can alter a directive.
 *
 * ## Treating reports as hostile
 *
 * Everything here assumes a report is attacker-controlled:
 *
 * - The endpoint is same-origin and unauthenticated, because a violation can
 *   happen on a page before sign-in. It is therefore reachable by anyone.
 * - `blockedURL`, `documentURL`, `sourceFile` and `sample` are all
 *   attacker-influenced strings. The CSP specification says so outright, of the
 *   `sample` field: "which are both completely attacker-controlled strings".
 *   A report is never rendered, never evaluated, and never used to make a
 *   security decision.
 * - Reports are not persisted. There is no queue, no table and no external
 *   collector, so a flood cannot grow storage.
 *
 * ## Privacy: what is deliberately dropped
 *
 * Both report formats carry a full document URL, which can include a query
 * string. This app puts nothing sensitive in a query string, but the report is
 * written by the browser from whatever URL was loaded, and a URL is exactly the
 * kind of value that later acquires a token in it. Rather than depend on that
 * staying true, the URL is reduced to scheme, host and path — the query string
 * and fragment are discarded before anything is logged. See `redactUrl`.
 */

/**
 * Cookie used to bucket the report rate limit.
 *
 * Reports are unauthenticated, so the endpoint has no principal to key on. A
 * cookie is used in preference to the client IP because the IP would have to
 * come from a forwarding header, which is client-controlled unless a trusted
 * reverse proxy overwrites it — and trusting it here would let an attacker
 * rotate the header to bypass the limit entirely. The cookie is a random value
 * this app mints; a client that discards it simply falls into the shared
 * anonymous bucket, which is bounded too.
 */
export const REPORT_BUCKET_COOKIE = "cloudpatrol.report";

/** The endpoint name referenced by the CSP `report-to` directive. */
export const CSP_REPORT_ENDPOINT_NAME = "csp";

/**
 * Path of the reporting endpoint.
 *
 * Deliberately not under `/api/proxy`: that route forwards to FastAPI with a
 * bearer token, and reports are neither authenticated nor meant for the API.
 */
export const CSP_REPORT_PATH = "/api/csp-report";

/**
 * Largest report body accepted, in bytes.
 *
 * The Reporting API batches multiple reports into one request, so this has to
 * be comfortably larger than a single report. A typical `application/reports+json`
 * body for one violation is around 500-800 bytes; this allows a batch of
 * roughly twenty with room to spare. A `report-uri` request carries exactly one
 * report, so 16 KiB is far above anything a browser sends legitimately and low
 * enough that a flood is cheap to reject.
 */
export const MAX_REPORT_BYTES = 16 * 1024;

/**
 * Maximum number of reports honoured in one batched request.
 *
 * A body under the size limit could still hold thousands of tiny objects. Only
 * the first `MAX_REPORTS_PER_REQUEST` are examined; the rest are dropped rather
 * than parsed, which bounds the work a single request can cause.
 */
export const MAX_REPORTS_PER_REQUEST = 20;

/** Longest value kept for any single free-text field. */
const MAX_FIELD_LENGTH = 512;

/** Longest value kept for a URL field, which is legitimately longer. */
const MAX_URL_LENGTH = 2048;

/** The two content types a browser uses to deliver reports. */
export const CSP_REPORT_CONTENT_TYPE = "application/csp-report";
export const REPORTING_API_CONTENT_TYPE = "application/reports+json";

/**
 * Report types that this endpoint accepts from the Reporting API format.
 *
 * A Reporting API endpoint is generic: once declared, a browser may deliver any
 * report type to it. Only CSP violations are meaningful here, so anything else
 * is acknowledged and discarded rather than logged as a security signal.
 */
export const ACCEPTED_REPORT_TYPES = new Set(["csp-violation"]);

/**
 * Reduce a URL to scheme, host and path.
 *
 * Query string and fragment are removed. The CSP and Reporting specifications
 * both define a "strip URL for use in reports" algorithm that keeps the query
 * string; this app discards it as well, because a report is a log line and a
 * query string is the part of a URL most likely to carry something that should
 * not be written down. The path is kept because without it a violation cannot
 * be located.
 *
 * A value that is not an absolute URL is not a URL we can safely normalise, so
 * it is dropped rather than logged verbatim.
 */
export function redactUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  if (value.length > MAX_URL_LENGTH) return null;
  try {
    const url = new URL(value);
    // A bare scheme such as "about" or "data" has no meaningful path here.
    if (!url.host) return `${url.protocol}`;
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return null;
  }
}

/**
 * Normalise a free-text field.
 *
 * Truncated rather than rejected: a long `sample` should not cause the whole
 * report to be discarded, but it also must not be logged at unbounded length.
 * Control characters are stripped so a crafted value cannot inject line breaks
 * or escape sequences into a log line and forge entries.
 */
export function sanitiseText(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, "");
  if (cleaned.length === 0) return null;
  return cleaned.slice(0, MAX_FIELD_LENGTH);
}

/** A numeric field, if the value is a usable number. */
function numberOrNull(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  return null;
}

/** A short string field, e.g. a directive name. */
function shortText(value: unknown): string | null {
  return sanitiseText(value);
}

/**
 * A violation, after normalisation.
 *
 * Field names are the app's own, not the wire format's, so the two wire formats
 * collapse into one shape and a consumer does not have to know which one a
 * given report arrived in.
 */
export interface NormalisedViolation {
  /** `csp-violation` for the Reporting API format, `csp-report` for the legacy one. */
  kind: "csp-violation" | "csp-report";
  /** The directive that was actually enforced. */
  effectiveDirective: string | null;
  /** The directive as written in the policy. */
  violatedDirective: string | null;
  /** `enforce` or `report`. */
  disposition: string | null;
  /** Where the document was, minus query and fragment. */
  documentUrl: string | null;
  /** What was blocked. `inline` or `eval` for those cases. */
  blockedUrl: string | null;
  /** The file the violation occurred in, minus query and fragment. */
  sourceFile: string | null;
  /** 1-based line number, when the browser supplied one. */
  lineNumber: number | null;
  /** The offending fragment, truncated and stripped of control characters. */
  sample: string | null;
  /** The full policy text, truncated. Useful to spot a stale cached policy. */
  originalPolicy: string | null;
  /** HTTP status of the blocked response, when there was one. */
  statusCode: number | null;
}

/** Read one field from an object, tolerating both wire spellings. */
function pick(source: Record<string, unknown>, ...keys: string[]): unknown {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(source, key)) return source[key];
  }
  return undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Normalise one legacy (`report-uri`) report body.
 *
 * The legacy format wraps the violation in a `csp-report` key and uses
 * hyphenated field names. Field names come from CSP3 §5.3.
 */
function normaliseLegacy(body: unknown): NormalisedViolation | null {
  if (!isPlainObject(body)) return null;
  const report = pick(body, "csp-report");
  if (!isPlainObject(report)) return null;

  return {
    kind: "csp-report",
    effectiveDirective: shortText(pick(report, "effective-directive")),
    violatedDirective: shortText(pick(report, "violated-directive")),
    disposition: shortText(pick(report, "disposition")),
    documentUrl: redactUrl(pick(report, "document-uri")),
    blockedUrl: shortText(pick(report, "blocked-uri")) ?? redactUrl(pick(report, "blocked-uri")),
    sourceFile: redactUrl(pick(report, "source-file")),
    lineNumber: numberOrNull(pick(report, "line-number")),
    sample: sanitiseText(pick(report, "script-sample", "sample")),
    originalPolicy: sanitiseText(pick(report, "original-policy")),
    statusCode: numberOrNull(pick(report, "status-code")),
  };
}

/**
 * Normalise one Reporting API (`report-to`) entry.
 *
 * The modern format uses camelCase field names inside a `body` key, alongside
 * envelope fields (`type`, `url`, `age`). Field names come from the CSP3
 * `CSPViolationReportBody` dictionary.
 */
function normaliseModern(entry: unknown): NormalisedViolation | null {
  if (!isPlainObject(entry)) return null;

  // Only CSP violations are a security signal here. A different type is
  // acknowledged by the caller and dropped.
  const type = pick(entry, "type");
  if (typeof type !== "string" || !ACCEPTED_REPORT_TYPES.has(type)) return null;

  const body = pick(entry, "body");
  if (!isPlainObject(body)) return null;

  return {
    kind: "csp-violation",
    effectiveDirective: shortText(pick(body, "effectiveDirective")),
    violatedDirective: shortText(pick(body, "violatedDirective")),
    disposition: shortText(pick(body, "disposition")),
    documentUrl: redactUrl(pick(body, "documentURL")),
    blockedUrl: shortText(pick(body, "blockedURL")) ?? redactUrl(pick(body, "blockedURL")),
    sourceFile: redactUrl(pick(body, "sourceFile")),
    lineNumber: numberOrNull(pick(body, "lineNumber")),
    sample: sanitiseText(pick(body, "sample")),
    originalPolicy: sanitiseText(pick(body, "originalPolicy")),
    statusCode: numberOrNull(pick(body, "statusCode")),
  };
}

/**
 * Parse and normalise a report body.
 *
 * Returns the violations that could be understood. An empty array means the
 * body parsed as JSON but held nothing recognisable, which the caller answers
 * with the same success response as a valid report: a browser should not retry,
 * and an attacker probing the endpoint learns nothing from a difference.
 *
 * `null` means the body was not JSON at all, which is the one case worth a
 * distinct answer, because a browser only ever sends JSON here and a
 * non-JSON body is therefore not a browser.
 *
 * Both wire formats are accepted regardless of the declared content type,
 * because the two formats are trivially distinguishable by shape and a browser
 * that sends the wrong header should not lose its report over it.
 */
export function parseReportBody(raw: string): NormalisedViolation[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  // Legacy: a single object with a `csp-report` key.
  if (isPlainObject(parsed) && "csp-report" in parsed) {
    const violation = normaliseLegacy(parsed);
    return violation ? [violation] : [];
  }

  // Reporting API: an array of entries, each with `type` and `body`.
  if (Array.isArray(parsed)) {
    const violations: NormalisedViolation[] = [];
    for (const entry of parsed.slice(0, MAX_REPORTS_PER_REQUEST)) {
      const violation = normaliseModern(entry);
      if (violation) violations.push(violation);
    }
    return violations;
  }

  // A single modern entry is not what the specification sends, but it costs
  // nothing to accept and avoids discarding a report over an envelope detail.
  if (isPlainObject(parsed)) {
    const violation = normaliseModern(parsed);
    return violation ? [violation] : [];
  }

  return [];
}

/**
 * Whether a request body should be read at all, given its declared type.
 *
 * Returns `false` for anything a browser would not send, so an unsupported type
 * is refused before the body is consumed.
 */
export function isSupportedContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  // The type may carry a charset parameter, e.g. `application/csp-report; charset=UTF-8`.
  const essence = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
  return essence === CSP_REPORT_CONTENT_TYPE || essence === REPORTING_API_CONTENT_TYPE;
}
