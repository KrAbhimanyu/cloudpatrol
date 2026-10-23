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
- `.env.example` contains variable names only, with no values, and there is
  deliberately no `AWS_ACCESS_KEY_ID` in it: a static platform key would be a
  larger risk than the temporary, scoped credentials AssumeRole produces.

The external ID is what prevents the "confused deputy" problem — a party who
learns the role ARN still cannot assume it without the external ID. It is
generated in the browser with `crypto.getRandomValues`
(`components/ConnectAccountForm.tsx`) and is never returned by the API.

## Authentication

Supabase issues the access token; the API verifies it
(`app/core/security.py`).

- HS256 tokens are verified against the project secret.
- RS256/ES256 tokens are verified against the project's JWKS endpoint.
- Any other algorithm, including `none`, is refused outright. This is the check
  that prevents a forged-token bypass.
- `exp` and `sub` are required; an expired token is rejected.
- The audience is pinned to `authenticated`, so a token minted for another
  purpose is not accepted.

The caller identity is derived from the verified token. The API never accepts a
user or organization identifier from the request body as proof of identity.

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

## Secret handling

- The Supabase service-role key is server-only. It bypasses RLS, so it must
  never reach a browser bundle or a client-visible response. Only the anon key
  is exposed, and only through `NEXT_PUBLIC_*` variables.
- `validate_startup` (`app/core/config.py`) refuses to start in production if
  any Supabase setting is missing, and refuses a `*` CORS origin. A
  misconfigured deployment fails loudly instead of running insecurely.
- `.gitignore` excludes `.env` and `.env.*` while keeping `.env.example`.

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
- **Deployed RLS behaviour is unverified.** The policies were tested against
  plain PostgreSQL, not a live Supabase project.
- **Audit writes come from the service role.** The API bypasses RLS to write
  audit events, so a bug in the API could write a misleading audit entry. The
  alternative — giving the browser a write policy — would be worse, but the
  risk is real.
- **No CSP or security headers** are configured on the Next.js app yet.
- **The browser holds the access token in `localStorage`.** `lib/session.ts`
  keeps the bearer token in `localStorage`, which any script running on the
  origin can read. This is a development-stage trade-off, recorded here rather
  than left implicit. Before production the token should move to an HttpOnly
  cookie issued by a same-origin auth route, which is the only way to make it
  unreadable to injected script. There is no sign-in UI yet either: the session
  gate (`components/RequireSession.tsx`) accepts a token pasted by the user.
