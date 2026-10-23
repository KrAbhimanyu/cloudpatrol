# CloudPatrol

AWS cloud cost intelligence. CloudPatrol reads your AWS account through a
read-only role, shows you which resources look idle or under-used, explains the
evidence behind each finding, and keeps estimated savings separate from savings
you have actually verified.

It never changes anything in your account. That is a structural property, not a
setting: the application contains no code that creates, modifies or deletes an
AWS resource, and the IAM policy it asks you to attach grants no permission to
do so.

## What it does today

Three detectors, each with the reasoning shown alongside the result:

| Detector | What it looks for | Savings estimate |
| --- | --- | --- |
| Unattached EBS volume | A volume in `available` state, attached to nothing | size x per-GiB-month |
| Unassociated Elastic IP | An allocated address with no association | hourly rate x 730 |
| Low-utilisation EC2 | Average CPU below a threshold over an observation window | none — see below |

The EC2 detector deliberately reports **no** savings figure. Downsizing to an
unknown target cannot be priced, and a made-up number would be worse than no
number. Where CloudPatrol cannot defend a figure, it says so instead of showing
`$0.00` — those two states mean different things.

## Two savings ledgers

Most tools quote one savings number. CloudPatrol keeps two:

- **Potential** — what a change might save, estimated from current findings.
- **Verified** — what a change has been shown to save, confirmed by measuring
  the account after the change.

Only the verified ledger is described as money actually saved. Nothing in the
current phase writes to it, because verification needs post-change evidence
that only a later, separately controlled remediation phase could supply. The
database enforces the distinction: a `verified` savings row is rejected unless
it carries evidence and a measurement window.

## Honest about gaps

If part of a scan fails — a permission gap in one region, a throttled API — the
scan is marked **partial**, and the UI states plainly that findings reflect only
what was visible, so an absence of findings is not proof of an absence of waste.
An incomplete scan is never presented as a clean bill of health.

## Layout

```
services/api/          FastAPI service (Python 3.13)
apps/web/              Next.js dashboard (App Router, React, TypeScript)
supabase/migrations/   PostgreSQL schema with Row Level Security
docs/                  Architecture, security, development notes
```

## Quick start

```bash
# API
cd services/api
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/uvicorn app.main:app --reload --port 8000

# Web
cd apps/web
npm ci
npm test
npm run dev     # http://localhost:3000
```

Copy `.env.example` to `.env` first. It documents variable names only.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness |
| `GET` | `/health/ready` | Readiness |
| `GET` | `/api/v1/organizations` | List the caller's workspaces |
| `POST` | `/api/v1/organizations` | Create a workspace |
| `GET` | `/api/v1/aws/accounts` | List connected AWS accounts |
| `POST` | `/api/v1/aws/accounts` | Connect an account |
| `POST` | `/api/v1/aws/accounts/{id}/validate` | Validate the role can be assumed |
| `GET` | `/api/v1/scans` | Scan history |
| `POST` | `/api/v1/scans` | Start a scan |
| `GET` | `/api/v1/scans/{id}` | Scan status |
| `GET` | `/api/v1/findings` | List findings, filterable |
| `GET` | `/api/v1/findings/{id}` | One finding |
| `PATCH` | `/api/v1/findings/{id}` | Acknowledge or dismiss |
| `GET` | `/api/v1/findings/summary/savings` | Potential and verified totals |

All `/api/v1` routes require a Supabase-issued bearer token. The caller's
organization is resolved server-side from membership; it is never taken from
the request body.

## Connecting an AWS account

1. In your AWS account, create an IAM role whose trust policy names the
   CloudPatrol account and requires an external ID
   (`docs/aws/trust-policy.json`).
2. Attach the read-only policy (`docs/aws/read-only-policy.json`). It grants
   describe and metric-read permissions only.
3. Register the role ARN in CloudPatrol, along with the external ID shown in
   the connect form.

CloudPatrol stores the role ARN and a vault reference — never an access key.

## Security posture

- Read-only by construction, verified by searching the source for mutating AWS
  operations (none exist) and by checking the IAM policy against the operations
  actually called.
- Tenant isolation in two layers: repository queries filter by organization,
  and every tenant table has RLS enabled.
- RLS policies exercised against PostgreSQL 16 with per-tenant JWT subjects.
  Results are recorded in `docs/SECURITY.md`.
- The Supabase service-role key is server-only; only the anon key reaches the
  browser.
- Money is stored as `numeric(14,2)`, never a float.

Scans run on a bounded background worker pool: `POST /api/v1/scans` returns
`202 Accepted` with the queued scan, and the client polls `GET /api/v1/scans/{id}`.
A stale-scan reaper fails scans abandoned by a dead worker, so a crashed scan
cannot lock an account out of future scans.

Known gaps — no rate limiting, a non-durable in-process scan queue, and no live
AWS validation — are listed in `docs/SECURITY.md` rather than left implicit.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layers, request flow, data model
- [`docs/SECURITY.md`](docs/SECURITY.md) — verified properties, test results, known gaps
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — local setup and dependency constraints

## Status

The API and web applications are implemented and tested. The database migration
is written and was validated against PostgreSQL 16, including its RLS policies
and integrity constraints.

Not yet done: wiring a live Supabase project, deploying either service, and
validating against a real AWS account. Until a real role is assumed, effective
IAM permissions and real API behaviour remain unverified.
