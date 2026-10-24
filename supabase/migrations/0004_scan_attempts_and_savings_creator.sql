-- Additive columns required by the persistence layer.
--
-- The API still runs on the in-memory store, but the repository models already
-- carry two fields the schema cannot represent. Without them a PostgreSQL
-- repository could not be written without either losing data or dropping a
-- column, so they are added now, on their own, before any repository exists.
--
-- Additive only: two `add column if not exists` statements. No existing column
-- is renamed, retyped or dropped, no enum type is altered, and no RLS policy,
-- grant or role is touched. Both statements are safe on a database that already
-- contains rows:
--
--   * `attempts` is added with a constant default, which PostgreSQL 11+ applies
--     as a metadata-only change (no table rewrite). Existing scans read 0, and
--     that is accurate: no scan recorded before this column existed has been
--     retried by the worker that counts attempts.
--   * `created_by` is nullable, so no existing row needs a value invented for
--     it. Ledger entries written before this migration simply have no recorded
--     author, which is the honest representation.

-- ---------------------------------------------------------------------------
-- scans.attempts
--
-- How many times a worker has picked this scan up. It is what lets the stale
-- scan reaper tell "queued and never started" from "started, then the worker
-- died" without guessing from timestamps, and it is recorded in the
-- `scan.reaped` audit event. `ScanRecord.attempts`
-- (app/repositories/models.py) carries the same value.
--
-- `NOT NULL DEFAULT 0` with a constant default is a metadata-only change on
-- PostgreSQL 11+: no table rewrite and no row scan, so this is safe and quick
-- on a table that already holds scan history. No CHECK constraint is added
-- inline for the same reason — an inline check can trigger a validation pass —
-- so the column is exactly the definition the persistence layer requires.
-- ---------------------------------------------------------------------------
alter table public.scans
  add column if not exists attempts integer not null default 0;

-- ---------------------------------------------------------------------------
-- savings_records.created_by
--
-- The authenticated user who created a ledger entry, taken from the verified
-- token subject (principal.user_id) and never from a request body. Nullable
-- because a row may predate this column, and because the value is genuinely
-- unknown for rows written before it existed.
--
-- The foreign key and ON DELETE SET NULL match every other actor column in this
-- schema (`aws_accounts.created_by`, `scans.created_by`,
-- `finding_reviews.actor_user_id`, `audit_events.actor_user_id`): deleting an
-- auth user must not delete the financial history that user created.
-- ---------------------------------------------------------------------------
alter table public.savings_records
  add column if not exists created_by uuid references auth.users (id) on delete set null;

-- ---------------------------------------------------------------------------
-- Known inconsistency, deliberately not changed here
--
-- `cost_observations.currency` is `text`, while `savings_records.currency` is
-- `char(3)`. Both hold ISO-4217 codes and both are read into a Python `str`
-- (app/services/billing.py, app/services/savings_ledger.py). No query joins or
-- compares the two columns, so the difference is not a compatibility failure.
-- Narrowing `text` to `char(3)` would be a destructive type change on a table
-- that may already hold rows, so it is deferred until a concrete defect
-- justifies it.
-- ---------------------------------------------------------------------------
