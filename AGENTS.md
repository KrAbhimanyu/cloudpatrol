# AGENTS.md

Repository-specific knowledge for CloudPatrol. Read this before making changes.

## What this project is

AWS cloud cost intelligence SaaS. It reads a customer's AWS account through a
customer-created read-only role and reports idle or under-used resources.

**The read-only constraint is the product's core promise.** Do not add code that
creates, modifies or deletes an AWS resource. Do not add IAM actions beyond
those in `docs/aws/read-only-policy.json`. If a task appears to require a write
to AWS, stop and ask.

## Layout

```
services/api/          FastAPI service (Python 3.13)
apps/web/              Next.js dashboard (App Router)
supabase/migrations/   PostgreSQL schema + RLS
supabase/seed.sql      Development seed data
docs/                  ARCHITECTURE.md, SECURITY.md, DEVELOPMENT.md
```

## Commands

Use the Makefile. It is the single source of truth for how things are run.

```bash
make test          # both suites
make lint          # ruff + eslint
make typecheck     # mypy + tsc
make check         # everything CI runs (lint, typecheck, test, build)
make db-up db-apply db-seed   # local PostgreSQL
```

## Invariants that must not be broken

1. **Read-only against AWS.** No mutating AWS calls. Ever.
2. **No AWS credentials are stored.** `aws_accounts` holds a role ARN and an
   opaque vault reference. There is no column for an access key, and there must
   never be one.
3. **NULL savings is not zero.** `estimated_monthly_savings` is nullable and
   means "not defensibly priceable". It renders as "Not priced", never `$0.00`.
   Any new detector that cannot price its finding must return `None`.
4. **Estimated is never presented as verified.** Only the `verified` savings
   basis counts as achieved. The database rejects a `verified` row without
   evidence and a measurement window.
5. **Tenant isolation lives in two places.** Repository queries filter by
   `organization_id`, *and* every tenant table has RLS. Adding a tenant table
   means adding RLS policies for it in the same migration.
6. **Money is `numeric(14,2)`, never a float.** Floats cannot represent `0.10`.
7. **Partial scans must stay visible.** A scan with non-empty
   `partial_failures` is reported as "Completed with gaps". Never let an
   incomplete scan render as a clean result.
8. **Only `NEXT_PUBLIC_*` reaches the browser.** The Supabase service-role key
   bypasses RLS and must never appear in client code or a client response.

## Dependency constraints

Both of these cost real time to rediscover:

- **TypeScript must stay 5.x.** `typescript-eslint` (via `eslint-config-next`)
  declares `typescript: ">=4.8.4 <6.1.0"`. TS 6/7 break it.
- **ESLint must stay 9.x.** `eslint-plugin-react` and `eslint-plugin-import`
  support up to ESLint 9. Under ESLint 10, npm nests them inside
  `eslint-config-next` where ESLint cannot resolve them.
- `eslint-config-next` 16 exports **native flat config arrays**. Spread them
  directly in `eslint.config.mjs`. Do not use `FlatCompat` — it targets the old
  eslintrc format and throws a circular-structure error on these objects.
- Tailwind 4 uses `@tailwindcss/postcss`. `autoprefixer` is not needed.

## Testing notes

- **API tests never touch the network.** `tests/fake_aws.py` implements the
  `AwsAdapter` protocol. Verified by running the suite with outbound sockets
  blocked; keep it that way, and do not add a test that needs real AWS.
- **A scan is asynchronous.** `POST /api/v1/scans` returns `202` with a
  `queued` scan; the row reaches a terminal state on a background worker. API
  tests must poll via the `_run_scan` helper in `tests/test_api_integration.py`
  rather than reading the POST response, which reflects acceptance only.
- The scan worker pool runs real threads in tests. The stale-scan reaper is
  disabled there because its interval would slow the suite; it is exercised
  directly through `reap_once()` in `tests/test_scan_runner.py`.
- The migration depends on Supabase's `auth.users` and `auth.uid()`. Against
  plain PostgreSQL these must be stubbed before applying it, or the
  `memberships` foreign key fails. That is expected, not a defect.
- The migration and seed are both idempotent and were validated against
  PostgreSQL 16. Re-verify after schema changes.
- In the seed, PL/pgSQL variable names must be prefixed (`v_scan`, not
  `scan_id`). An unprefixed name shadows the column in `ON CONFLICT` target
  lists, which Postgres rejects as ambiguous.

## Documentation

When behaviour changes, update the doc that claims it:

- `docs/ARCHITECTURE.md` — layers, request flow, data model
- `docs/SECURITY.md` — verified properties, test results, known gaps
- `docs/DEVELOPMENT.md` — setup, dependency constraints

Known gaps are listed in `docs/SECURITY.md`. Do not quietly remove one from
that list; fix it, or say plainly that it still stands.
