# Development

## Requirements

- Python 3.13 (3.11+ is declared; 3.13 is what the suite is verified against)
- Node.js 24
- Docker, only if you want to run the database migration locally

## API

```bash
cd services/api
python -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/pytest -q              # tests
.venv/bin/mypy app               # types
.venv/bin/ruff check .           # lint
.venv/bin/ruff format --check .  # format
```

Run it:

```bash
cp ../../.env.example .env
# The application is built by a factory, so uvicorn needs --factory.
.venv/bin/uvicorn --factory app.main:create_app --reload --port 8000
```

`GET /health` returns service status. Interactive docs are at `/docs`.

### Tests do not touch AWS

`tests/fake_aws.py` implements the `AwsAdapter` protocol, so the suite runs the
whole application without network access. This was verified by running the
suite with outbound sockets blocked: all tests still pass. That is what makes
the claim "no test reaches live AWS" a measurement rather than a hope.

## Web

```bash
cd apps/web
npm ci

npm run lint       # ESLint
npm run typecheck  # tsc --noEmit
npm test           # Vitest
npm run build      # production build
npm run dev        # http://localhost:3000
```

### Dependency notes

Two constraints are worth knowing, because both cost time to discover:

- **TypeScript is pinned to 5.x.** `typescript-eslint`, which
  `eslint-config-next` depends on, declares `typescript: ">=4.8.4 <6.1.0"`.
  TypeScript 6 and 7 are outside that range.
- **ESLint is pinned to 9.x.** `eslint-plugin-react` and `eslint-plugin-import`
  declare support up to ESLint 9. Under ESLint 10 npm nests them inside
  `eslint-config-next`, where ESLint cannot resolve them.

`eslint-config-next` 16 exports native flat config arrays, so they are spread
in directly in `eslint.config.mjs`. `FlatCompat` is not used: it targets the
old eslintrc format and throws a circular-structure error on these already-flat
objects.

## Database

Apply the migration on Supabase through the SQL editor, or with
`supabase db push`.

To check it against plain PostgreSQL, note that the migration depends on
`auth.users` and `auth.uid()`, which Supabase provides. Against a bare
PostgreSQL instance those must be stubbed first, or the migration will fail on
the `memberships` foreign key. That is expected, not a defect in the migration.

The migration is idempotent: every object is created `IF NOT EXISTS`, so
re-applying it is safe and does not error.

## Environment

Copy `.env.example` to `.env`. It documents variable names only and contains no
values. Two things about it are deliberate:

- There is no `AWS_ACCESS_KEY_ID`. CloudPatrol uses cross-account roles with
  temporary credentials, so there is nowhere for a static key to go.
- The service-role key is marked server-only. It bypasses RLS and must never
  reach a browser bundle.

Outside `local` and `test`, the API refuses to start if any Supabase setting is
missing, and refuses a `*` CORS origin.

## Continuous integration

`.github/workflows/ci.yml` runs the API job (ruff, mypy, pytest) and the web job
(eslint, tsc, vitest, build) on every push and pull request to `main`.

The web job type-checks, lints, tests and builds the dashboard. The pages fetch
their data from the API at runtime, so the build does not depend on any
sample data being present.
