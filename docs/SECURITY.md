# Security

This document records the security properties of CloudPatrol and how they were
verified. Claims here are backed by tests or by an executed check; where a
property could not be verified in this environment, that is stated plainly.

## The read-only guarantee

**Claim.** CloudPatrol cannot change anything in a customer's AWS account.

**Evidence.** A search of the API source for mutating AWS operations — create,
delete, terminate, modify, attach, detach, release, allocate, put, start, stop,
reboot, and their resource-specific forms — returns nothing. The only boto3
clients constructed are `sts`, `ec2`, `cloudwatch` and `ce`
(`app/aws/boto3_adapter.py`), and the operations called on them are
`AssumeRole`, `GetCallerIdentity`, `DescribeVolumes`, `DescribeAddresses`,
`DescribeInstances`, `GetMetricStatistics` and `GetCostAndUsage`.

**Evidence.** `docs/aws/read-only-policy.json` grants exactly those actions and
no others. The policy was checked against the operations in the code rather
than written from memory; an initial draft omitted `sts:GetCallerIdentity`,
which the code does call.

**Caveat.** Source review proves what the code *intends* to call. It cannot
prove the effective permissions of a role deployed in a live account. Only an
IAM policy simulation or CloudTrail review can do that, and neither was run.

## Credential handling

CloudPatrol never stores an AWS access key, secret key or session token.

- `AwsAccountRecord` (`app/repositories/models.py`) has no credential field.
  It stores the role ARN and `external_id_ref`, an opaque key into a secret
  vault.
- The database schema has no credential column and no column for the external
  ID itself (`supabase/migrations/0001_init.sql`).
- Credentials from `AssumeRole` are used for the duration of a scan and are
  not persisted.
- `.env.example` contains variable names and non-functional placeholders only,
  and there is deliberately no `AWS_ACCESS_KEY_ID` in it: a static platform key
  would be a larger risk than the temporary, scoped credentials AssumeRole
  produces. A test (`services/api/tests/test_env_example_safety.py`) fails the
  build if a real-looking credential is ever added to the file.

The external ID is what prevents the "confused deputy" problem — a party who
learns the role ARN still cannot assume it without the external ID. It is
generated in the browser with `crypto.getRandomValues`
(`components/ConnectAccountForm.tsx`) and is never returned by the API.

## Authentication

Supabase issues the access token; the API verifies it
(`app/core/security.py`).

- The accepted algorithms are an allow-list read from configuration
  (`SUPABASE_JWT_ALGORITHMS`), never from the token's own `alg` header. The
  header is attacker-controlled, so letting it choose the verification method
  is what enables an algorithm-confusion attack.
- Symmetric (`HS*`) and asymmetric (`RS*`/`ES*`) algorithms cannot be enabled
  together. The combination is refused at startup, because it would allow an
  attacker to present an HS256 token whose HMAC secret is the project's
  *public* key.
- A configured `SUPABASE_JWT_SECRET` is rejected at startup unless it is a
  high-entropy value of at least 32 characters. A URL, a public key or a JWKS
  endpoint is refused outright: such a value is public, so using it as an HMAC
  secret would let anyone forge a token.
- Any algorithm outside the allow-list, including `none`, is refused outright.
  This is the check that prevents a forged-token bypass.
- `exp`, `sub`, `aud` and `iss` are all required. An expired token is rejected.
- The audience is pinned to `authenticated`, so a token minted for another
  purpose is not accepted.
- When `SUPABASE_URL` is set, the issuer is pinned to `<url>/auth/v1`, so a
  token from a different project is refused even if it verifies cryptographically.

Asymmetric verification (the default) needs `SUPABASE_URL` to resolve the
project's JWKS, and needs no shared secret at all. Symmetric verification needs
`SUPABASE_JWT_ALGORITHMS=HS256` and a strong `SUPABASE_JWT_SECRET`. A
configuration that is missing either is refused at startup in production.

The caller identity is derived from the verified token. The API never accepts a
user or organization identifier from the request body as proof of identity.

### How the browser session is held

The access token never reaches browser JavaScript. The flow is:

1. The user signs in at `/sign-in`. A server action calls
   `supabase.auth.signInWithPassword` (`lib/auth/actions.ts`) and `@supabase/ssr`
   writes the session as an **HttpOnly** cookie (`lib/supabase/server.ts`).
   `httpOnly` is set explicitly, because the library defaults to `false`.
2. `proxy.ts` (Next.js 16's rename of `middleware.ts`) refreshes the session on
   every page request and redirects an unauthenticated visitor off a protected
   page.
3. The browser calls same-origin `/api/proxy/*`. That route
   (`app/api/proxy/[...path]/route.ts`) reads the cookie, attaches the
   `Authorization` header server-side, and forwards to FastAPI. The token is
   never in a client-readable location.

The alternative — handing the token to client JavaScript so it could set the
header — would leave it exactly as exposed as `localStorage` was, so the proxy
is what makes the HttpOnly cookie meaningful rather than decorative.

Only the selected organization ID is kept in `localStorage`
(`lib/session.ts`). It is a UI preference, not a credential: the API re-checks
membership on every request, so a tampered value yields `403`, not another
tenant's data.

## CSRF protection

Two independent controls guard every state-changing request to the BFF. Both
are enforced in `app/api/proxy/[...path]/route.ts` before anything is
forwarded, and either one failing yields `403` with no upstream call.

**1. Origin validation** (`lib/security/origin.ts`). Safe methods (`GET`,
`HEAD`, `OPTIONS`) are not checked — they must not change state. For
`POST`/`PUT`/`PATCH`/`DELETE` the `Origin` header must name a trusted origin:
this app's own origin, or an entry in `APP_ORIGINS`.

When `Origin` is absent, the decision falls back to `Sec-Fetch-Site`, which
page script cannot set:

| `Origin` | `Sec-Fetch-Site` | Result |
| --- | --- | --- |
| trusted | any | allowed |
| untrusted | any | rejected (`untrusted-origin`) |
| `null` or malformed | any | rejected (`malformed-origin`) |
| absent | `same-origin` | allowed (`missing-origin-same-site`) |
| absent | anything else or absent | rejected (`missing-origin`) |

A present `Origin` is always authoritative: a `Sec-Fetch-Site: same-origin`
value cannot rescue an untrusted `Origin`. Treating a missing header as "same
origin" would make the check decorative, so it is treated as no evidence.

**2. Double-submit CSRF token** (`lib/security/csrf.ts`). `proxy.ts` mints a
256-bit token into a cookie (`cloudpatrol.csrf`) that is deliberately **not**
HttpOnly, because the client must read it to echo it back. `lib/api.ts` reads
that cookie and sends it in `X-CSRF-Token` on unsafe methods only. The proxy
compares header to cookie with a constant-time comparison and rejects a
mismatch, a missing cookie, or a missing header.

The cookie is `SameSite=Strict` (unlike the session cookie, which must survive
a magic-link redirect) and `Secure` in production. The token is rotated only
when absent: rotating on every response would invalidate a token a concurrent
request is already carrying, producing spurious `403`s.

Why both, rather than `SameSite` alone: `SameSite=Lax` is a single browser
attribute, and the threat it addresses overlaps with the origin check. The
token does not depend on the browser honouring `SameSite` at all. This is
documented as a **CSRF** control, not an XSS control — a readable cookie offers
no protection against script injection, which is what CSP is for.

Server Actions carry their own framework-level check: Next.js compares the
request `Origin` against `Host` and rejects a mismatch. `APP_ORIGINS` is passed
to `experimental.serverActions.allowedOrigins` in `next.config.ts` so this does
not break behind a reverse proxy.

## Security headers and CSP

Set in two places, because they have different lifetimes:

- **Per-request** (`lib/security/headers.ts`, applied in `proxy.ts`): the CSP,
  which carries a nonce that changes on every response.
- **Static** (`next.config.ts`): `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`,
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`, and HSTS
  in production only. These also cover the BFF route, which the proxy's matcher
  skips.

Scripts are nonce-based, not `unsafe-inline`:

```
default-src 'self';
script-src 'self' 'nonce-<per-request>' 'strict-dynamic'
style-src 'self' 'nonce-<per-request>'
style-src-attr 'unsafe-inline'
object-src 'none'; base-uri 'self'; form-action 'self';
frame-ancestors 'none'; connect-src 'self';
report-uri <origin>/api/csp-report; report-to csp
```

`connect-src 'self'` is sufficient because every API call goes through the BFF;
the browser never contacts FastAPI or Supabase directly.

This depends on the app staying **fully dynamic**. Every route reports as
dynamic in the production build, which is what lets the nonce reach the HTML:
Next.js reads the nonce from the CSP header on the *request* and stamps it onto
its inline scripts during rendering. A statically prerendered page is built
once, with no request in hand, so a nonce could never reach it. Verified
against a real production build — the nonce appears on all 3 inline and 9
external script tags, and differs between requests.

### Violation reporting

The policy is enforced and violations are reported. Reporting is **additive**:
`report-uri` and `report-to` say where to send a violation notice, they do not
grant permission to load anything, and the header is still
`Content-Security-Policy` rather than `Content-Security-Policy-Report-Only`. A
blocked resource is still blocked; it is also now recorded. A test asserts the
policy is not report-only, because every other header test would pass if
enforcement were silently dropped.

Both directives are sent deliberately. `report-to` is the current mechanism and
resolves an endpoint *name* through the `Reporting-Endpoints` response header,
which `proxy.ts` sets alongside the CSP; `report-uri` is deprecated but the CSP
specification says it "only takes effect if `report-to` is not present", so a
browser that understands `report-to` uses it and an older one falls back. The
two URLs are asserted to match, so `report-uri` can never point somewhere the
endpoint header does not declare.

`POST /api/csp-report` (`app/api/csp-report/route.ts`) accepts both wire
formats — `application/csp-report` (one report per request, legacy) and
`application/reports+json` (an array, possibly batched) — normalises them to one
shape (`lib/security/reporting.ts`), and writes one `[csp-violation]` line per
violation to the server log. It is the only thing it does: reports are not
persisted, not queued, and never fed back into the policy.

The endpoint is public, because a violation can happen on a page before
sign-in. Everything it receives is treated as hostile:

- The body is capped at 16 KiB **while being read**, so an oversized request is
  abandoned rather than buffered. `Content-Length` is checked first as a fast
  path but is never trusted: a request that understates its length is still
  caught by the running total.
- Only the two report content types are accepted; anything else is refused with
  `415` before the body is read.
- Only known fields are kept. A field of the wrong type is dropped, and a
  non-JSON body is refused with `400`.
- URLs are reduced to **scheme, host and path**. The query string and fragment
  are discarded before anything is logged, so a URL that later acquires a token
  cannot leak one into the log. The specification's own "strip URL for use in
  reports" keeps the query string; this app drops it as well, deliberately.
- Text fields are truncated to 512 characters and stripped of control
  characters, so a crafted `sample` cannot inject a newline and forge a log
  entry. The CSP specification notes these fields are "completely
  attacker-controlled strings"; they are logged, never rendered or evaluated.
- A token bucket (`lib/security/rate-limit.ts`, a burst of 60, sustained one
  per second) bounds the request rate, keyed on a random cookie this app mints.
  An IP key would require a forwarding header, which a client controls unless a
  trusted proxy overwrites it, so trusting it would let an attacker rotate the
  header and bypass the limit. A client that drops the cookie shares a bounded
  anonymous bucket.

Responses carry no body: a bare `204` on acceptance, `400` for a non-JSON body,
`413` for an oversized one, `415` for a wrong content type, `429` when rate
limited, `405` for anything but `POST`. A rejection never explains what shape
would have been accepted.

Two deliberate omissions, stated so they are not read as oversights:

- **No CSRF or origin check.** Those controls protect requests that change state
  for an authenticated user. This endpoint has no session, no authenticated
  action and no state, so there is nothing to forge; the only outcome of a
  cross-site report is a log line. Adding an origin check would instead risk
  discarding real reports, because the legacy `report-uri` mechanism sends with
  `mode: "no-cors"` and a browser may omit `Origin`.
- **No persistence.** Nothing is written to the database. Reports go to the
  process log, which is where an operator looks for them. A durable collector is
  a later phase and would need its own retention and access decisions.

To read reports locally, run the app and filter the server output:

```
npm run dev 2>&1 | grep '\[csp-violation\]'
```

Browsers only deliver to an endpoint whose origin is "potentially trustworthy",
which in practice means HTTPS or `localhost`. A development server reached by
bare IP over plain HTTP will not deliver reports; that is the browser's rule,
not a setting this app can change.

The endpoint URL in both the CSP and the `Reporting-Endpoints` header is built
from the origin the browser used (`request.nextUrl.origin`), so it matches what
the browser will POST back to. A reverse proxy that rewrites `Host` to an
internal name must forward the public host, exactly as the CSRF origin check
already requires (`lib/security/origin.ts`). If it does not, the report URL
points at the internal host and browsers will refuse to deliver.

### Deliberate exceptions

- **`style-src-attr 'unsafe-inline'`.** React renders the `style` prop as an
  inline `style` attribute, which a CSP nonce does not authorise — nonces cover
  `<style>` elements, not attributes. The dashboard's savings bar sets its
  width this way. Scoped to `style-src-attr` alone, so `style-src` stays
  nonce-only, inline event handlers remain blocked, and `script-src` is
  untouched. An inline style attribute cannot execute script; the exposure is
  style injection, not code execution.
- **`'unsafe-eval'` in development only.** React uses `eval` to rebuild
  server-side error stacks in the browser. Production does not receive it, and
  a test asserts that.
- **HSTS without `preload`.** `preload` is a near-permanent commitment and is
  left as an explicit operational decision rather than a side effect of
  deploying. HSTS is sent only in production, where it is meaningful.

## Multi-tenant isolation

Two independent layers:

1. **Application.** Every repository read takes an `organization_id` and
   filters by it (`app/repositories/protocols.py`). Membership is resolved
   server-side (`app/core/dependencies.py`).
2. **Database.** Every tenant-owned table has RLS enabled with policies keyed
   on membership.

The membership helper functions are `SECURITY DEFINER` with `search_path`
pinned to `public, pg_temp`. Without `SECURITY DEFINER`, a policy on
`memberships` that queries `memberships` would recurse; without the pinned
`search_path`, a caller could shadow the objects the function resolves.

### RLS test results

The migration was applied to a PostgreSQL 16 instance and the policies were
exercised by switching to the `authenticated` role with a JWT subject set, once
per tenant. Results:

| Check | Result |
| --- | --- |
| Member of tenant A sees only A's organizations | 1 row, "Tenant A" |
| Member of tenant A sees only A's accounts | 1 row, "A prod" |
| Member of tenant A sees only A's findings | 2 rows, B's excluded |
| Member of A cannot insert an AWS account (needs admin) | rejected |
| Member of A cannot write into tenant B | rejected |
| Member cannot fabricate a savings record | rejected |
| Member cannot forge an audit event | rejected |
| Member cannot rename an organization | 0 rows affected |
| Owner of B sees only B's organizations and accounts | B only |
| Owner of B cannot see A's findings | 0 rows |
| Owner may insert into their own tenant | allowed |

Note that a rejected insert raises `insufficient_privilege`: the table-level
grant exists, and the RLS policy is what refuses the row. That is the intended
mechanism.

**Caveat.** These tests ran against plain PostgreSQL 16 with minimal stand-ins
for `auth.users` and `auth.uid()`. They validate the policy logic, not a live
Supabase deployment. Effective behaviour in a real project should be
re-confirmed there.

The member-isolation, non-member-denial and admin-only-account-insert checks
above are now automated: `tests/integration/test_repositories_postgres.py`
asserts them on every run of the opt-in suite, so they cannot silently regress.
The rest of the table remains a one-off manual result.

## Database integrity constraints

Verified by execution against PostgreSQL 16:

| Constraint | Result |
| --- | --- |
| Role ARN's account must equal `account_id` | rejected when mismatched |
| `account_id` must be 12 digits | rejected when short |
| One connection per AWS account per tenant | duplicate rejected |
| `verified` savings requires evidence and a window | rejected without them |
| `estimated` savings may omit evidence | accepted |
| Null savings distinct from zero | both coexist |
| Duplicate finding via `dedupe_key` | rejected |
| At most one active scan per account | second rejected |
| `finished_at` cannot precede `started_at` | rejected |

The last-but-one of these is a partial unique index, which is what makes the
"one scan at a time" rule hold under concurrent requests; an application-level
check alone would be racy.

## Credential handling on re-validation

- Re-validation performs a real `sts:AssumeRole` with the external ID read from
  the vault. The external ID is never returned in a response, written to an
  account row, or included in an error.
- An `AssumeRole` failure is classified before it reaches the client
  (`translate_assume_role_error`). AWS returns `AccessDenied` for both a wrong
  external ID and a missing trust relationship, and echoes the role ARN and the
  external ID in its message. The message is used only to choose an error code
  and is discarded; only the code and a fixed sentence are returned.
- A failed re-validation marks the stored connection `failed`. A connection
  that no longer works must not continue to advertise itself as `validated`.
- Temporary credentials are used immediately and never stored. The session
  expiry is returned so the caller can see the session was short-lived.

## Region constraint

`aws_allowed_regions` is enforced when an account is connected: a region
outside the list is rejected before any AWS call is made. Without this a
connected account could widen a scan to every AWS region, which is a cost and
an operational risk.

## Queue observability

`GET /health/ready` reports scan-queue depth, capacity, and a `saturated` flag.
A full queue refuses new scans, so saturation is reported as `degraded` rather
than hidden in logs.

## Secret handling

- The Supabase service-role key is server-only. It bypasses RLS, so it must
  never reach a browser bundle or a client-visible response. Only the anon key
  is exposed, and only through `NEXT_PUBLIC_*` variables.
- `validate_startup` (`app/core/config.py`) refuses to start in production if
  any Supabase setting is missing, and refuses a `*` CORS origin. A
  misconfigured deployment fails loudly instead of running insecurely.
- `.gitignore` excludes `.env` and `.env.*` while keeping `.env.example`.
- `TEST_DATABASE_URL` is read only by the integration suite, never by the API.
  The suite refuses a Supabase host outright and refuses a non-loopback host
  unless `CLOUDPATROL_ALLOW_NONLOCAL_TEST_DB=1` is set deliberately, then creates
  its own `cloudpatrol_it_<random>` database and drops only that name at the end.
  The only destructive statement it can issue is a `DROP DATABASE` for a name it
  generated in this process.

## Known gaps

Stated so they are not mistaken for solved problems:

- **Rate limiting is in-process only.** `RateLimitMiddleware` applies a token
  bucket per authenticated principal (falling back to IP when the token cannot
  be verified), with the tightest budget on scan creation because it is the
  only class that spends money. The buckets live in the API process, so a
  multi-replica deployment enforces the limit per replica rather than globally,
  and a restart resets the counters. A shared store is a later phase.
- **The scan queue is in-process and not durable.** Scans run on a bounded
  worker pool inside the API process, so a hard crash loses queued work. The
  stale-scan reaper fails abandoned scans so the account is released, but it
  does not resume them. A durable queue (a job table or an external broker) is
  a later phase.
- **Scan queue depth is bounded but not per-tenant.** A single organization
  issuing many scans can fill the shared queue and cause another tenant's
  submission to be refused with 409. Fairness between tenants is not
  implemented.
- **No live AWS validation.** No role has been assumed against a real account,
  so effective IAM permissions and real API behaviour are unverified.
- **Deployed RLS behaviour is unverified.** The policies are now exercised by
  the automated integration suite (`tests/integration/`), which asserts that a
  member sees only their own organization, that a non-member sees nothing, and
  that a plain member cannot insert an AWS account. That runs against plain
  PostgreSQL with stand-ins for `auth.users` and `auth.uid()`, not a live
  Supabase project, so the policy *logic* is tested and the deployed
  configuration is not. Re-confirm against a real project before relying on it.
- **Audit writes come from the service role.** The API bypasses RLS to write
  audit events, so a bug in the API could write a misleading audit entry. The
  alternative — giving the browser a write policy — would be worse, but the
  risk is real.
- **The session cookie is `SameSite=Lax`, not `Strict`.** `Lax` is required for
  the OAuth/magic-link redirect to carry the session back to the app. It does
  mean a top-level GET navigation from another site sends the cookie; the app
  does not perform state changes on GET, and unsafe methods now also require a
  trusted origin and a CSRF token, so the exposure is limited to a cross-site
  page load, not a cross-site write.
- **The CSRF token cookie is readable by script, by necessity.** The client must
  read it to echo it in `X-CSRF-Token`, so it cannot be HttpOnly. This is
  acceptable for a CSRF token and is not an XSS control: an attacker who can run
  script in this origin can read the token, but such an attacker no longer needs
  CSRF. Stated explicitly so the readable cookie is not mistaken for an
  oversight.
- **No CSRF token on Server Actions.** Sign-in and sign-out rely on the
  framework's own `Origin`-versus-`Host` check, not on this app's
  double-submit token. The framework check runs in production as well as in
  development, but it is a different mechanism and is not covered by this
  app's tests beyond the redirect and error-handling assertions.
- **`style-src-attr 'unsafe-inline'` is required** while any component uses
  React's `style` prop. Removing it means replacing those with CSS classes.
- **Violation reports go to the log, not to a store.** The endpoint exists and
  the enforced policy reports to it, but nothing is persisted: reports are
  written as `[csp-violation]` lines and are only as durable as the process log.
  There is no retention policy, no aggregation, and no dashboard. A report is
  also best-effort by specification — a browser may drop it, batch it, or delay
  it — so the absence of a report does not prove the absence of a violation.
- **No report-only rollout was performed.** The policy is enforced directly.
  Reporting now exists, so a future policy change can be validated against the
  collected reports before release, but the current policy was not first run in
  report-only mode.
- **Password reset, email confirmation and sign-up are not wired up.** Only
  sign-in and sign-out exist (`lib/auth/actions.ts`). A user must be created in
  the Supabase dashboard. `messageFor` already maps the confirmation and
  sign-up-disabled errors, so the UI will explain those cases if they occur.
- **No MFA.** Supabase supports it; the app does not enable or enforce it.
- **The proxy does not re-validate authorization.** It proves a session exists
  and attaches the token; every authorization decision is made by FastAPI. A
  request that reaches the API with a valid session but no membership still
  gets `403`.
- **The PostgreSQL repositories are written but not running.** `app/repositories/postgres.py`
  implements every repository protocol, but no runtime path selects it:
  `build_container()` returns the in-memory store in every environment, and
  `build_container_for_settings()` warns rather than switching when
  `DATABASE_URL` is set. Its behaviour is now validated against a real
  PostgreSQL 17 server by `tests/integration/` (see the note on RLS below), but
  it still carries no traffic.
- **Scan completion is not atomic under PostgreSQL.** The scan service writes
  resources, findings, savings, costs, status and audit through separate
  repository handles, so those are separate transactions. A crash between them
  can leave a scan with partial results and a non-terminal status; the stale-scan
  reaper releases the account, but the partial rows remain. `Database.transaction()`
  is the unit-of-work primitive the fix will use; the service has not been
  refactored to it.
- **Tenant isolation now has a second implementation to keep correct.** The
  in-memory store enforced `organization_id` in Python; the PostgreSQL
  repositories enforce it in each statement's `WHERE` clause. Both are exercised
  by tests, including against a live server, but they remain two independent
  implementations of the same rule.
- **`psycopg_pool` is not installed.** Every PostgreSQL operation opens and
  closes a connection rather than borrowing one from a pool. Correct, but not
  what a loaded deployment wants.
