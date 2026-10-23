"use client";

/**
 * Connected AWS accounts.
 *
 * The list is loaded from the API for the active workspace. A failure is shown
 * as a failure rather than as "no accounts connected", because those two states
 * lead to very different actions: one is a retry, the other is "connect an
 * account".
 */

import Link from "next/link";
import { useCallback, useState } from "react";

import { ConnectAccountForm } from "@/components/ConnectAccountForm";
import { RequireSession } from "@/components/RequireSession";
import { Badge, Card, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { api } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useAsync } from "@/lib/use-async";
import { useSessionRequest } from "@/lib/use-session-request";
import type { AwsAccount, Paginated } from "@/lib/types";

const STATUS_STYLES: Record<string, string> = {
  validated: "bg-emerald-100 text-emerald-800 ring-emerald-600/20",
  pending: "bg-amber-100 text-amber-800 ring-amber-600/20",
  invalid: "bg-red-100 text-red-800 ring-red-600/20",
};

export default function AccountsPage() {
  return (
    <RequireSession>
      <AccountsContent />
    </RequireSession>
  );
}

function AccountsContent() {
  const { options, ready } = useSessionRequest();
  const [extra, setExtra] = useState<AwsAccount[]>([]);

  const fetchAccounts = useCallback(
    (signal: AbortSignal) => {
      if (!options) return Promise.reject(new Error("No workspace selected."));
      return api.listAccounts({ ...options, signal });
    },
    [options],
  );

  const { data, loading, error, reload } = useAsync<Paginated<AwsAccount>>(fetchAccounts, [options], {
    enabled: ready,
  });

  const accounts = mergeAccounts(data?.items ?? [], extra);

  return (
    <>
      <PageHeader
        title="AWS accounts"
        description="CloudPatrol reaches your account by assuming a read-only role that you create and control. It never stores access keys."
      />

      <div className="grid gap-6 lg:grid-cols-[1fr_1.1fr]">
        <Card
          title="Connected accounts"
          description="Each account is validated by assuming its role and confirming the identity."
        >
          {!ready ? (
            <LoadingState label="Loading workspace…" />
          ) : loading ? (
            <LoadingState />
          ) : error ? (
            <ErrorState message={error} onRetry={reload} />
          ) : accounts.length === 0 ? (
            <p className="text-sm text-slate-500">No accounts connected yet.</p>
          ) : (
            <ul className="space-y-4">
              {accounts.map((account) => (
                <li
                  key={account.id}
                  className="rounded-lg border border-slate-200 p-4"
                  data-testid="account-item"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-semibold text-slate-900">{account.label}</h3>
                    <Badge className={STATUS_STYLES[account.status] ?? STATUS_STYLES.pending}>
                      {account.status}
                    </Badge>
                  </div>
                  <dl className="mt-2.5 space-y-1 text-xs">
                    <div className="flex gap-2">
                      <dt className="w-20 shrink-0 text-slate-500">Account</dt>
                      <dd className="font-mono text-slate-800">{account.account_id}</dd>
                    </div>
                    <div className="flex gap-2">
                      <dt className="w-20 shrink-0 text-slate-500">Role</dt>
                      <dd className="min-w-0 break-all font-mono text-slate-800">
                        {account.role_arn}
                      </dd>
                    </div>
                    <div className="flex gap-2">
                      <dt className="w-20 shrink-0 text-slate-500">Regions</dt>
                      <dd className="font-mono text-slate-800">{account.regions.join(", ")}</dd>
                    </div>
                    <div className="flex gap-2">
                      <dt className="w-20 shrink-0 text-slate-500">Validated</dt>
                      <dd className="text-slate-800">{formatDateTime(account.last_validated_at)}</dd>
                    </div>
                    {account.status_message && (
                      <div className="flex gap-2">
                        <dt className="w-20 shrink-0 text-slate-500">Note</dt>
                        <dd className="text-slate-800">{account.status_message}</dd>
                      </div>
                    )}
                  </dl>
                  <Link
                    href="/scans"
                    className="mt-3 inline-block text-xs font-semibold text-brand-700 hover:underline"
                  >
                    Run a scan for this account →
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <div className="space-y-6">
          <ConnectAccountForm
            onConnected={(account) => {
              setExtra((current) => mergeAccounts(current, [account]));
              reload();
            }}
          />
          <Card title="What the role grants">
            <p className="text-sm leading-relaxed text-slate-600">
              The trust policy requires an external ID, which stops another party who learns your
              role ARN from assuming it. The permission policy allows only describe, metric-read
              and cost-read operations. There is no write, delete or create permission in the
              template, and CloudPatrol has no code that would use one.
            </p>
            <ul className="mt-3 space-y-1.5 font-mono text-xs text-slate-700">
              <li>sts:AssumeRole (trust policy only)</li>
              <li>ec2:DescribeVolumes, DescribeAddresses, DescribeInstances</li>
              <li>cloudwatch:GetMetricStatistics</li>
              <li>ce:GetCostAndUsage</li>
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}

function mergeAccounts(base: AwsAccount[], extra: AwsAccount[]): AwsAccount[] {
  // A newly connected account is shown immediately, then reconciled when the
  // refetch lands. Keyed by id so the same account is never listed twice.
  const byId = new Map<string, AwsAccount>();
  for (const account of [...base, ...extra]) byId.set(account.id, account);
  return [...byId.values()];
}
