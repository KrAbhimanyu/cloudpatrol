"use client";

/**
 * The connect-account form.
 *
 * Client-side validation mirrors the API's rules so obvious mistakes are
 * caught before a network round trip. The server re-validates everything;
 * this is convenience, not a security control.
 *
 * The external ID field is generated in the browser and is never pre-filled
 * from a server value, because the API never returns one.
 */

import { useState } from "react";

import { Card } from "./ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/session-context";
import type { AwsAccount } from "@/lib/types";

const ACCOUNT_ID_PATTERN = /^\d{12}$/;
const ROLE_ARN_PATTERN = /^arn:aws:iam::(\d{12}):role\/[\w+=,.@/-]{1,64}$/;
const EXTERNAL_ID_PATTERN = /^[\w+=,.@:/-]{2,1224}$/;

const COMMON_REGIONS = [
  "us-east-1",
  "us-west-2",
  "eu-west-1",
  "ap-south-1",
  "ap-southeast-1",
] as const;

function generateExternalId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `cloudpatrol-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export function ConnectAccountForm({
  onConnected,
}: {
  onConnected?: (account: AwsAccount) => void;
}) {
  const { signedIn, organizationId } = useSession();
  const [label, setLabel] = useState("");
  const [accountId, setAccountId] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState(generateExternalId);
  const [regions, setRegions] = useState<string[]>(["us-east-1"]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  function toggleRegion(region: string) {
    setRegions((current) =>
      current.includes(region) ? current.filter((r) => r !== region) : [...current, region],
    );
  }

  function validate(): Record<string, string> {
    const found: Record<string, string> = {};
    if (!label.trim()) found.label = "Give the account a name you will recognise.";
    if (!ACCOUNT_ID_PATTERN.test(accountId)) {
      found.account_id = "An AWS account ID is exactly 12 digits.";
    }
    const match = ROLE_ARN_PATTERN.exec(roleArn);
    if (!match) {
      found.role_arn =
        "Enter a role ARN such as arn:aws:iam::123456789012:role/CloudPatrolReadOnly.";
    } else if (match[1] !== accountId) {
      // Catching this here saves a confusing failure from AWS later.
      found.role_arn = "The account ID in the role ARN does not match the account ID above.";
    }
    if (!EXTERNAL_ID_PATTERN.test(externalId)) {
      found.external_id = "The external ID must be 2-1224 characters and contain no spaces.";
    }
    if (regions.length === 0) found.regions = "Select at least one region to scan.";
    return found;
  }

  async function submit() {
    const found = validate();
    setErrors(found);
    setResult(null);
    if (Object.keys(found).length > 0) return;
    if (!signedIn || !organizationId) {
      setResult({ ok: false, message: "Select a workspace before connecting an account." });
      return;
    }

    setSubmitting(true);
    try {
      const account = await api.connectAccount(
        { organizationId },
        {
          label: label.trim(),
          account_id: accountId,
          role_arn: roleArn,
          external_id: externalId,
          regions,
        },
      );
      setResult({ ok: true, message: `Connected ${account.label} (${account.account_id}).` });
      setLabel("");
      setAccountId("");
      setRoleArn("");
      setExternalId(generateExternalId());
      onConnected?.(account);
    } catch (cause) {
      // The server's message is shown as-is: it explains why the role could not
      // be assumed, which is the whole point of validation.
      const message =
        cause instanceof ApiError
          ? cause.message
          : cause instanceof Error
            ? cause.message
            : "Could not connect the account.";
      setResult({ ok: false, message });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card
      title="Connect an account"
      description="You create the role in your own AWS account, then tell CloudPatrol its ARN."
    >
      <form
        className="space-y-4"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Field label="Display name" error={errors.label} htmlFor="label">
          <input
            id="label"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            placeholder="Production"
            className={inputClass(errors.label)}
          />
        </Field>

        <Field
          label="AWS account ID"
          error={errors.account_id}
          htmlFor="account_id"
          hint="12 digits, for example 123456789012."
        >
          <input
            id="account_id"
            inputMode="numeric"
            value={accountId}
            onChange={(event) => setAccountId(event.target.value.replace(/\D/g, "").slice(0, 12))}
            placeholder="123456789012"
            className={inputClass(errors.account_id)}
          />
        </Field>

        <Field label="Read-only role ARN" error={errors.role_arn} htmlFor="role_arn">
          <input
            id="role_arn"
            value={roleArn}
            onChange={(event) => setRoleArn(event.target.value.trim())}
            placeholder="arn:aws:iam::123456789012:role/CloudPatrolReadOnly"
            className={inputClass(errors.role_arn)}
          />
        </Field>

        <Field
          label="External ID"
          error={errors.external_id}
          htmlFor="external_id"
          hint="Put this same value in the role's trust policy. It stops anyone who learns your role ARN from assuming it."
        >
          <div className="flex gap-2">
            <input
              id="external_id"
              value={externalId}
              onChange={(event) => setExternalId(event.target.value)}
              className={`${inputClass(errors.external_id)} font-mono text-xs`}
            />
            <button
              type="button"
              onClick={() => setExternalId(generateExternalId())}
              className="shrink-0 rounded-lg border border-slate-300 px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
            >
              Regenerate
            </button>
          </div>
        </Field>

        <fieldset>
          <legend className="text-sm font-medium text-slate-700">Regions to scan</legend>
          <div className="mt-2 flex flex-wrap gap-2">
            {COMMON_REGIONS.map((region) => {
              const checked = regions.includes(region);
              return (
                <label
                  key={region}
                  className={`cursor-pointer rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors ${
                    checked
                      ? "border-brand-500 bg-brand-50 text-brand-700"
                      : "border-slate-300 text-slate-600 hover:bg-slate-50"
                  }`}
                >
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={checked}
                    onChange={() => toggleRegion(region)}
                  />
                  {region}
                </label>
              );
            })}
          </div>
          {errors.regions && <p className="mt-1.5 text-xs text-red-600">{errors.regions}</p>}
        </fieldset>

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitting ? "Validating…" : "Validate and connect"}
        </button>

        {result && (
          <p
            role={result.ok ? "status" : "alert"}
            className={`rounded-lg px-3 py-2 text-xs ${
              result.ok ? "bg-emerald-50 text-emerald-900" : "bg-red-50 text-red-900"
            }`}
          >
            {result.message}
          </p>
        )}

        <p className="text-xs leading-relaxed text-slate-500">
          Validation assumes the role and confirms the returned identity matches the account ID
          you entered. CloudPatrol discards the temporary credentials once validation finishes.
        </p>
      </form>
    </Card>
  );
}

function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label htmlFor={htmlFor} className="block text-sm font-medium text-slate-700">
        {label}
      </label>
      {hint && <p className="mt-0.5 text-xs text-slate-500">{hint}</p>}
      <div className="mt-1.5">{children}</div>
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-red-600">
          {error}
        </p>
      )}
    </div>
  );
}

function inputClass(error?: string): string {
  return `w-full rounded-lg border px-3 py-2 text-sm shadow-sm transition-colors ${
    error ? "border-red-400 focus:border-red-500" : "border-slate-300 focus:border-brand-500"
  }`;
}
