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
9. **The access token stays server-side.** The session is an HttpOnly cookie and
   is turned into an `Authorization` header only by
   `app/api/proxy/[...path]/route.ts`. Nothing under `lib/` or `components/` may
   hold a token, and no client code may send an `Authorization` header. Only the
   organization ID is persisted in the browser, and it is a preference, not a
   credential.
10. **Unsafe requests need both an origin check and a CSRF token.** The BFF
    rejects `POST`/`PUT`/`PATCH`/`DELETE` unless the origin is trusted *and* the
    `X-CSRF-Token` header matches the `cloudpatrol.csrf` cookie. Neither is
    sufficient alone. A new mutating route must go through `/api/proxy` (which
    enforces this) rather than calling FastAPI directly. See
    `lib/security/origin.ts` and `lib/security/csrf.ts`.
11. **The CSP is nonce-based, so the app must stay dynamically rendered.** Every
    route reports `ƒ` (dynamic) in the build. A statically prerendered page is
    built once with no request in hand, so the nonce never reaches its inline
    scripts and the policy blocks them. If a route is ever made static, its CSP
    has to be reconsidered.
12. **CSP reporting is additive; enforcement is never traded for visibility.**
    The header stays `Content-Security-Policy`, never
    `Content-Security-Policy-Report-Only`. `report-uri`/`report-to` only say
    where a violation notice goes — they grant no permission — so adding them
    cannot relax the policy. A test asserts the header is not report-only.
    `report-to` names an endpoint declared by the `Reporting-Endpoints` header;
    the two are set together in `proxy.ts` and their URLs must agree.
13. **The CSP report endpoint treats its input as hostile.** `POST
    /api/csp-report` is unauthenticated by design (a violation can precede
    sign-in), so the body is size-capped while streaming, the content type is
    checked before the body is read, only known fields survive, URLs are
    stripped of their query string and fragment, and text fields are truncated
    and de-quoted of control characters. Reports are logged, never persisted and
    never rendered. Do not add authentication, persistence or an origin check
    without revisiting the reasoning in the route's module comment.

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

## Gotchas found the hard way

- **`next build` writes `apps/web/AGENTS.md`.** It is generated by Next.js
  (`generate-agent-files.js`), not by a human, and it reappears on every build.
  It shows up as an untracked file; that is expected.
- **Cost Explorer needs `GroupBy`.** Without
  `GroupBy: [{Type: DIMENSION, Key: SERVICE}]` the response contains a single
  `Total` and no `Groups`, so per-service spend silently never populates. The
  call is also paginated via `NextPageToken`; read every page or the bill is
  understated.
- **`AccessDenied` from `sts:AssumeRole` is ambiguous.** AWS uses it for a wrong
  external ID, a missing trust relationship, and other cases. Classify it in
  `translate_assume_role_error`, which has the AWS message available, and never
  forward that message: it echoes the role ARN and the external ID.
- **A cost total is per-currency and per-period.** Summing observations across
  months, or across currencies, produces a number matching no invoice.
  `GET /costs/summary` totals the latest period only and withholds the total if
  one period holds multiple currencies.
- **`aws_allowed_regions` is enforced at account connection.** Do not document
  it as a constraint without a check; that is how it was previously wrong.
- **Next.js 16 renamed `middleware.ts` to `proxy.ts`.** The exported function is
  `proxy`, not `middleware`. Under the old name it is never called, so sessions
  silently stop refreshing and users are signed out at token expiry with no
  error. The file lives at `apps/web/proxy.ts`.
- **`@supabase/ssr` defaults `httpOnly` to `false`.** That default exists so its
  browser client can read the session. This app does not use that client, so
  `cookieOptions` sets `httpOnly: true` explicitly in `lib/supabase/server.ts`
  and `proxy.ts`. Leaving it at the default would silently undo the point of the
  cookie. The two must agree or a refresh writes a cookie the other cannot read.
- **`setAll` receives a second `headers` argument.** It carries the
  `Cache-Control: private, no-store` that must accompany auth cookies. Dropping
  it lets a CDN serve one user's session to another. The proxy sets the header
  on the response itself, which covers the same ground.
- **`NEXT_PUBLIC_API_BASE_URL` is read per request in the proxy route.** Reading
  it at module load bakes the value in at build time and makes it untestable.
- **`serverActions` lives under `experimental` in Next 16.** `next.config.ts`
  has it at `experimental.serverActions.allowedOrigins`. At the top level,
  `tsc` rejects it as an unknown property on `NextConfig`. The value is a
  **host**, not a URL: `next.config.ts` strips the scheme, because Next.js
  matches only the host of the request `Origin`.
- **The CSRF cookie is deliberately not HttpOnly, and is `SameSite=Strict`.**
  The client has to read it to echo it in a header, so `httpOnly: true` would
  break every mutation. It is separate from the session cookie, which stays
  HttpOnly with `SameSite=Lax`. Do not "fix" either to match the other.
- **The proxy forwards the nonce by overriding request headers.** Next.js reads
  the CSP nonce from the *request* headers during rendering. Middleware cannot
  mutate the request directly, so `proxy.ts` passes
  `NextResponse.next({ request: { headers } })` and Next.js emits
  `x-middleware-request-*` override headers. Setting the CSP on the response
  alone leaves the nonce out of the HTML and the policy blocks every inline
  script. Verified against a real production build.
- **The CSP reporting endpoint must be reachable without the proxy's matcher.**
  `proxy.ts` excludes `/api` from its matcher, so `app/api/csp-report/route.ts`
  gets no per-request CSP from the proxy. That is fine — the route returns a
  bodiless status and no HTML — but it is why the endpoint lives under `/api`
  and not on a page path.
- **Browsers only deliver reports to a "potentially trustworthy" origin.** HTTPS
  or `localhost`, in practice. A dev server reached by bare IP over plain HTTP
  silently delivers nothing, which looks identical to "no violations". Check the
  URL scheme before concluding the policy is clean.
- **psycopg's `sql.Composable` is not accepted by `Cursor.execute`'s stubs.**
  `execute` is typed for `str | bytes | SQL | Composed | Template`, and
  `sql.Composable` — the base class of `SQL`, `Composed` and `Placeholder` — is
  none of those. A helper annotated `-> sql.Composable` therefore makes every
  call site a mypy `call-overload` error. Annotate builders as
  `sql.SQL | sql.Composed`. Related: `sql.Placeholder()` is a `Composable`, not
  an `SQL`, so a placeholder map typed `dict[str, sql.Composable]` has the same
  problem — type it `dict[str, sql.SQL]` and use `sql.SQL("%s")` for the plain
  case. Identifiers still need `sql.Identifier`; the composed statement is what
  makes a value a bound parameter and a name a quoted identifier.
- **psycopg's `Diagnostic.constraint_name` has no setter.** It is populated by
  libpq, so a test cannot build a `UniqueViolation` and attach a constraint name
  to it. Inject it through a subclass that shadows `diag`; the instance still
  passes `isinstance(exc, UniqueViolation)`, which is what the repository checks.
- **`Database.connection()` commits and closes; `_BoundConnection` does
  neither.** `build_postgres_container(database, connection=conn)` binds
  repositories to a caller-owned connection so a multi-step workflow shares one
  transaction — the connection context manager is the only thing that commits.
  A repository bound that way must not commit on its own, or the unit of work
  loses its atomicity. Test harnesses must mirror whichever lifecycle they mean:
  a source that wraps `with conn:` commits, a bare passthrough does not.

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

### Real-PostgreSQL integration tests

`tests/integration/` runs the repository layer against a live PostgreSQL server
and the real migrations. It is opt-in: set `TEST_DATABASE_URL` to a throwaway
server, and the suite creates a `cloudpatrol_it_<random>` database, applies
migrations `0001`–`0004` to it, runs the tests, and drops that database.

```sh
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres \
  pytest tests/integration
```

- Unset, the whole suite skips, so `pytest` alone stays offline and fast.
  Deselect explicitly with `-m "not integration"` when you want it gone from the
  summary rather than reported as skipped.
- `_harness.py` refuses a Supabase host outright and refuses a non-loopback host
  unless `CLOUDPATROL_ALLOW_NONLOCAL_TEST_DB=1` is set. That is what makes it
  safe to point at a server: it can only ever drop a database whose name it
  generated itself.
- The tests share one session database, so fixtures must generate unique values
  (see `org_factory`). A hardcoded slug or account id collides across tests.
- `tests/test_integration_harness.py` tests the guard itself and runs with no
  database at all. Keep it that way: the guard is what decides whether it is safe
  to create and drop databases, so it must be checked even where the suite skips.
- What these tests are for: a fake cursor returns whatever the test told it to,
  so it cannot catch a wrong column name, a bad type cast, an array mapped to a
  string, a `date` mapped to the wrong type, a missing constraint, or two real
  connections racing to claim one scan. Those are exactly the failures that reach
  production, and the unit tests in `tests/test_postgres_repositories.py` pin only
  the SQL *shape*. Add a case here when the behaviour depends on the server.
- The suite was checked by mutation: reverting the finding-upsert `state`
  preservation, dropping the `organization_id` predicate from a `list_for_org`,
  and removing the `where not exists` scan guard each made the relevant tests
  fail. A new test that cannot fail this way is probably not testing the server.

## Documentation

When behaviour changes, update the doc that claims it:

- `docs/ARCHITECTURE.md` — layers, request flow, data model
- `docs/SECURITY.md` — verified properties, test results, known gaps
- `docs/DEVELOPMENT.md` — setup, dependency constraints

Known gaps are listed in `docs/SECURITY.md`. Do not quietly remove one from
that list; fix it, or say plainly that it still stands.
