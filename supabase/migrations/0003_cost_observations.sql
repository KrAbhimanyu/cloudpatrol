-- Billing observations from Cost Explorer.
--
-- Kept in its own table rather than folded into resource_snapshots, because it
-- is a different kind of fact:
--
--   * It is *reported spend*, not an inventory item and not a saving.
--   * It arrives under a separate permission (ce:GetCostAndUsage), so an
--     account may have inventory rows and no cost rows. That asymmetry has to
--     be representable without implying the bill was zero.
--   * Its natural key is (account, service, billing period), not a resource id.
--
-- Additive only: a new table. Nothing existing is altered or dropped.

create table if not exists public.cost_observations (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations (id) on delete cascade,
    aws_account_id uuid not null references public.aws_accounts (id) on delete cascade,
    -- Nullable: a cost row can be imported outside a scan. ``on delete set
    -- null`` keeps the cost history if a scan row is ever pruned.
    scan_id uuid references public.scans (id) on delete set null,
    service text not null,
    amount numeric(14, 4) not null,
    currency text not null default 'USD',
    period_start date not null,
    period_end date not null,
    created_at timestamptz not null default now(),
    constraint cost_observations_period_order check (period_end >= period_start)
);

-- The natural key. A re-scan of the same account must not duplicate a reported
-- cost, or the apparent bill would double.
create unique index if not exists cost_observations_unique_idx
    on public.cost_observations (aws_account_id, scan_id, service, period_start);

-- Supports the per-organization, per-account summary read.
create index if not exists cost_observations_org_created_idx
    on public.cost_observations (organization_id, period_start desc);

alter table public.cost_observations enable row level security;

-- Tenant isolation, following the same shape as resource_snapshots: members of
-- the organization may read, and only an owner/admin may write.
drop policy if exists cost_observations_select_member on public.cost_observations;
create policy cost_observations_select_member on public.cost_observations
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists cost_observations_insert_admin on public.cost_observations;
create policy cost_observations_insert_admin on public.cost_observations
  for insert to authenticated
  with check (
    public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[])
  );

drop policy if exists cost_observations_delete_admin on public.cost_observations;
create policy cost_observations_delete_admin on public.cost_observations
  for delete to authenticated
  using (
    public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[])
  );
