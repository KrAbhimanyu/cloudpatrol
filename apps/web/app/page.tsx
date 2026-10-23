import Link from "next/link";

import { Card } from "@/components/ui";

export default function HomePage() {
  return (
    <div className="space-y-10">
      <section className="max-w-3xl">
        <p className="text-xs font-semibold uppercase tracking-wider text-brand-600">
          Read-only AWS cost intelligence
        </p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">
          Find the cloud spend you can actually justify removing.
        </h1>
        <p className="mt-4 text-base leading-relaxed text-slate-600">
          CloudPatrol inspects your AWS account through a read-only role, shows you why each
          opportunity was flagged, and separates money you <em>might</em> save from money you
          have <em>verified</em> you saved. It never changes your infrastructure.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          <Link
            href="/accounts"
            className="rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-700"
          >
            Connect an AWS account
          </Link>
          <Link
            href="/dashboard"
            className="rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50"
          >
            View the dashboard
          </Link>
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-3">
        <Card title="Read-only, verifiably">
          <p className="text-sm leading-relaxed text-slate-600">
            The role you create grants describe and metric-read permissions only. CloudPatrol has
            no code path that creates, modifies or deletes an AWS resource.
          </p>
        </Card>
        <Card title="Evidence, not assertions">
          <p className="text-sm leading-relaxed text-slate-600">
            Every finding shows the resource, the metric window, the price source and the
            assumption behind its estimate, so you can check the reasoning yourself.
          </p>
        </Card>
        <Card title="Honest about gaps">
          <p className="text-sm leading-relaxed text-slate-600">
            If part of a scan fails, the result is marked partial. An incomplete scan is never
            presented as a clean bill of health.
          </p>
        </Card>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <Card title="Potential is not the same as achieved">
          <p className="text-sm leading-relaxed text-slate-600">
            Most tools quote a single savings number. CloudPatrol keeps two ledgers. Potential
            savings are estimates of what a change might yield. Verified savings are recorded
            only after a change is made and the result is measured against it.
          </p>
        </Card>
        <Card title="Where to start">
          <ol className="list-decimal space-y-1.5 pl-5 text-sm text-slate-600">
            <li>
              <Link href="/accounts" className="font-medium text-brand-700 hover:underline">
                Connect an AWS account
              </Link>{" "}
              using the provided read-only role template.
            </li>
            <li>
              <Link href="/scans" className="font-medium text-brand-700 hover:underline">
                Run a scan
              </Link>{" "}
              and watch it complete.
            </li>
            <li>
              <Link href="/findings" className="font-medium text-brand-700 hover:underline">
                Review findings
              </Link>{" "}
              and acknowledge or dismiss them.
            </li>
          </ol>
        </Card>
      </section>
    </div>
  );
}
