-- Widen the savings_records.basis domain.
--
-- 0001 restricted basis to ('estimated', 'verified'). That is enough to stop an
-- estimate being summed with a measured figure, but it cannot express the
-- intermediate states a real workflow passes through: a human approving a
-- change, the change being implemented, and a measurement that fails to prove
-- anything. Without those, an approved-but-unmeasured item has nowhere to live
-- except back in the estimate bucket, which is exactly the conflation the
-- ledger exists to prevent.
--
-- Additive and data-preserving: the old constraint is dropped and a wider one
-- added in the same transaction. Existing rows ('estimated' and 'verified')
-- already satisfy the wider domain, so no row is rewritten or rejected.
--
-- Note the mapping: 'estimated' remains valid and means the same thing as the
-- API's 'potential' bucket. It is kept rather than renamed so this migration
-- does not have to rewrite existing rows.

alter table public.savings_records
  drop constraint if exists savings_records_basis_check;

alter table public.savings_records
  add constraint savings_records_basis_check
  check (basis in ('estimated', 'potential', 'approved', 'implemented', 'verified', 'inconclusive'));

-- A finding may contribute at most one live ledger entry per basis. This is the
-- database-level guarantee against double attribution: re-running a scan, or
-- re-approving an already-approved finding, cannot create a second row that
-- would be summed into the same total.
create unique index if not exists savings_records_finding_basis_idx
  on public.savings_records (organization_id, finding_id, basis)
  where finding_id is not null;

-- Only a verified row represents realised money, so only a verified row needs
-- evidence and a window. The constraint from 0001 already enforces that; this
-- index supports the summary query that separates the two ledgers.
create index if not exists savings_records_org_basis_created_idx
  on public.savings_records (organization_id, basis, created_at desc);
