"use client";

/**
 * Settings: the workspace identity and the limits CloudPatrol operates within.
 *
 * The workspace name, role and id are read from the active session rather than
 * hard-coded, so the page cannot claim a workspace the user is not actually in.
 */

import { RequireSession } from "@/components/RequireSession";
import { Card, LoadingState, PageHeader } from "@/components/ui";
import { useSession } from "@/lib/session-context";

export default function SettingsPage() {
  return (
    <RequireSession>
      <SettingsContent />
    </RequireSession>
  );
}

function SettingsContent() {
  const { organizations, organizationId, signedIn } = useSession();
  const current = organizations.find((org) => org.id === organizationId) ?? null;

  if (!signedIn) return <LoadingState label="Loading session…" />;
  if (!current) return <LoadingState label="Loading workspace…" />;

  return (
    <>
      <PageHeader
        title="Settings"
        description="Workspace configuration and the limits CloudPatrol operates within."
      />

      <div className="space-y-6">
        <Card title="Workspace">
          <dl className="space-y-3 text-sm">
            <div className="flex flex-wrap gap-2">
              <dt className="w-40 shrink-0 font-medium text-slate-500">Workspace</dt>
              <dd className="text-slate-800">{current.name}</dd>
            </div>
            <div className="flex flex-wrap gap-2">
              <dt className="w-40 shrink-0 font-medium text-slate-500">Your role</dt>
              <dd className="capitalize text-slate-800">{current.role}</dd>
            </div>
            <div className="flex flex-wrap gap-2">
              <dt className="w-40 shrink-0 font-medium text-slate-500">Workspace ID</dt>
              <dd className="font-mono text-xs text-slate-800">{current.id}</dd>
            </div>
          </dl>
        </Card>

        <Card title="Permissions" description="What members of a workspace are allowed to do.">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">
                Workspace roles and the actions each may perform
              </caption>
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Action
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Owner
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Admin
                  </th>
                  <th scope="col" className="py-2 font-medium">
                    Member
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                <PermissionRow action="View findings and savings" owner admin member />
                <PermissionRow action="Run a scan" owner admin member />
                <PermissionRow action="Connect an AWS account" owner admin />
                <PermissionRow action="Change the savings ledger" owner admin />
                <PermissionRow action="Manage workspace members" owner admin />
                <PermissionRow action="Delete the workspace" owner />
              </tbody>
            </table>
          </div>
        </Card>

        <Card title="Read-only guarantee">
          <p className="text-sm leading-relaxed text-slate-600">
            CloudPatrol reaches AWS only through a role you create in your own account. The
            permission policy attached to that role grants describe, metric-read and cost-read
            operations. There is no write, delete or create permission in the template, and no
            code path in the application that would use one.
          </p>
          <p className="mt-3 text-sm leading-relaxed text-slate-600">
            No AWS access keys are stored. Access is obtained by assuming the role, and the
            temporary credentials are discarded when the operation finishes.
          </p>
        </Card>
      </div>
    </>
  );
}

function PermissionRow({
  action,
  owner = false,
  admin = false,
  member = false,
}: {
  action: string;
  owner?: boolean;
  admin?: boolean;
  member?: boolean;
}) {
  return (
    <tr>
      <td className="py-2 pr-4 text-slate-700">{action}</td>
      <Mark allowed={owner} />
      <Mark allowed={admin} />
      <Mark allowed={member} />
    </tr>
  );
}

function Mark({ allowed }: { allowed: boolean }) {
  return (
    <td className="py-2 pr-4 text-slate-700">
      <span aria-hidden="true">{allowed ? "Yes" : "—"}</span>
      <span className="sr-only">{allowed ? "Allowed" : "Not allowed"}</span>
    </td>
  );
}
