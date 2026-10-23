import Link from "next/link";

import { NavLinks } from "./NavLinks";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";

/**
 * The application frame: a persistent sidebar, the workspace switcher, and the
 * page body.
 *
 * The shell states the read-only guarantee in the sidebar rather than burying
 * it in documentation, because it is the single most important thing a new
 * user needs to know about what this tool does to their account.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[16rem_1fr]">
      <aside className="border-b border-slate-200 bg-white lg:sticky lg:top-0 lg:h-screen lg:border-b-0 lg:border-r">
        <div className="flex h-full flex-col gap-6 p-5">
          <Link href="/" className="flex items-center gap-2.5">
            <CloudPatrolMark />
            <span className="text-lg font-semibold tracking-tight">CloudPatrol</span>
          </Link>

          <NavLinks />

          <div className="mt-auto space-y-4">
            <WorkspaceSwitcher />
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3">
              <p className="text-xs font-semibold text-emerald-900">Read-only by design</p>
              <p className="mt-1 text-xs leading-relaxed text-emerald-800">
                CloudPatrol inspects your account and never changes, deletes or creates AWS
                resources.
              </p>
            </div>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-col">
        <main className="min-w-0 flex-1 px-5 py-6 sm:px-8 sm:py-8">
          <div className="mx-auto max-w-6xl">{children}</div>
        </main>
        <footer className="border-t border-slate-200 px-5 py-4 sm:px-8">
          <p className="text-xs text-slate-500">
            Savings shown as &ldquo;potential&rdquo; are estimates. Only savings recorded as
            verified have been confirmed by post-change evidence.
          </p>
        </footer>
      </div>
    </div>
  );
}

function CloudPatrolMark() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      className="h-7 w-7 shrink-0 text-brand-600"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M17.5 18H7a4 4 0 0 1-.6-7.95A5.5 5.5 0 0 1 17 9.5a4.25 4.25 0 0 1 .5 8.5Z" />
      <path d="m9.5 14.5 2 2 3.5-3.5" />
    </svg>
  );
}
