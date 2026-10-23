-- CloudPatrol initial schema.
--
-- Design notes:
--
-- 1. Additive only. Every object is created with IF NOT EXISTS and no existing
--    object is dropped or altered destructively, so this migration is safe to
--    apply to a database that already has data.
--
-- 2. Tenant isolation is enforced in the database, not only in application
--    code. Every tenant-owned table has Row Level Security enabled and a
--    policy keyed on membership. Application-level filtering is a second line
--    of defence, never the only one.
--
-- 3. No credential is stored. aws_accounts holds the role ARN and an opaque
--    reference into a secret vault. There is deliberately no column for an
--    access key, secret key or session token, and no column for the external
--    ID itself.
--
-- 4. Money is stored as numeric(14,2), never as a float. Binary floating point
--    cannot represent 0.10 exactly, and these values are summed and shown to
--    users as currency.

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------------------
-- Enums
--
-- Values mirror the Python Literal types in app/schemas so the database and
-- the API cannot drift apart silently.
-- ---------------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_type where typname = 'member_role') then
    create type public.member_role as enum ('owner', 'admin', 'member');
  end if;

  if not exists (select 1 from pg_type where typname = 'aws_account_status') then
    create type public.aws_account_status as enum ('pending', 'validated', 'failed', 'disabled');
  end if;

  if not exists (select 1 from pg_type where typname = 'scan_status') then
    create type public.scan_status as enum ('queued', 'running', 'completed', 'partial', 'failed');
  end if;

  if not exists (select 1 from pg_type where typname = 'finding_severity') then
    create type public.finding_severity as enum ('low', 'medium', 'high');
  end if;

  if not exists (select 1 from pg_type where typname = 'finding_confidence') then
    create type public.finding_confidence as enum ('low', 'medium', 'high');
  end if;

  if not exists (select 1 from pg_type where typname = 'finding_state') then
    create type public.finding_state as enum (
      'estimated', 'acknowledged', 'implemented', 'verified', 'dismissed'
    );
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- organizations
-- ---------------------------------------------------------------------------
create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(btrim(name)) between 1 and 100),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.organizations is
  'A tenant. Every other tenant-owned row carries organization_id referencing this table.';

-- ---------------------------------------------------------------------------
-- memberships
--
-- user_id references auth.users, so deleting a Supabase auth user removes
-- their access. ON DELETE CASCADE is intentional: an orphaned membership
-- would be an authorisation row with no identity behind it.
-- ---------------------------------------------------------------------------
create table if not exists public.memberships (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role public.member_role not null default 'member',
  created_at timestamptz not null default now(),
  unique (organization_id, user_id)
);

create index if not exists memberships_user_id_idx on public.memberships (user_id);
create index if not exists memberships_org_id_idx on public.memberships (organization_id);

-- ---------------------------------------------------------------------------
-- Membership helpers
--
-- These are SECURITY DEFINER so a policy on `memberships` can call them
-- without re-entering its own policy, which would recurse. `search_path` is
-- pinned to defeat search-path hijacking of the functions they call.
-- ---------------------------------------------------------------------------
create or replace function public.is_org_member(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.memberships m
    where m.organization_id = target_org
      and m.user_id = auth.uid()
  );
$$;

create or replace function public.has_org_role(target_org uuid, allowed public.member_role[])
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.memberships m
    where m.organization_id = target_org
      and m.user_id = auth.uid()
      and m.role = any (allowed)
  );
$$;

revoke all on function public.is_org_member(uuid) from public;
revoke all on function public.has_org_role(uuid, public.member_role[]) from public;
grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.has_org_role(uuid, public.member_role[]) to authenticated;

-- ---------------------------------------------------------------------------
-- aws_accounts
--
-- Note the absence of any credential column, and of the external ID itself.
-- `external_id_ref` is an opaque key into a secret vault; the value lives
-- outside the database.
-- ---------------------------------------------------------------------------
create table if not exists public.aws_accounts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  label text not null check (length(btrim(label)) between 1 and 100),
  account_id text not null check (account_id ~ '^[0-9]{12}$'),
  role_arn text not null check (role_arn ~ '^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/.+$'),
  regions text[] not null check (array_length(regions, 1) between 1 and 20),
  status public.aws_account_status not null default 'pending',
  status_message text,
  external_id_ref text,
  last_validated_at timestamptz,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- One connection per AWS account per tenant: registering the same account
  -- twice would double every finding from it.
  unique (organization_id, account_id)
);

create index if not exists aws_accounts_org_idx on public.aws_accounts (organization_id);

-- The role ARN must name the same account as the account_id column. Without
-- this, a row could claim one account and point at another's role.
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'aws_accounts_role_arn_matches_account'
  ) then
    alter table public.aws_accounts
      add constraint aws_accounts_role_arn_matches_account
      check (split_part(role_arn, ':', 5) = account_id);
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- scans
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  aws_account_id uuid not null references public.aws_accounts (id) on delete cascade,
  status public.scan_status not null default 'queued',
  started_at timestamptz,
  finished_at timestamptz,
  resource_count integer not null default 0 check (resource_count >= 0),
  finding_count integer not null default 0 check (finding_count >= 0),
  -- Per-service failures. A non-empty array is what makes a scan `partial`,
  -- and it is surfaced in the UI so an incomplete scan is never read as a
  -- clean result.
  partial_failures jsonb not null default '[]'::jsonb check (jsonb_typeof(partial_failures) = 'array'),
  error_message text,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- A scan cannot finish before it started.
  constraint scans_time_order check (finished_at is null or started_at is null or finished_at >= started_at)
);

create index if not exists scans_org_created_idx on public.scans (organization_id, created_at desc);
create index if not exists scans_account_idx on public.scans (aws_account_id);

-- At most one active scan per account. This is the database-level guarantee
-- behind the "a second scan cannot start while one is running" rule; the API
-- check alone would be racy under concurrent requests.
create unique index if not exists scans_one_active_per_account_idx
  on public.scans (aws_account_id)
  where status in ('queued', 'running');

-- ---------------------------------------------------------------------------
-- resource_snapshots
-- ---------------------------------------------------------------------------
create table if not exists public.resource_snapshots (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  scan_id uuid not null references public.scans (id) on delete cascade,
  aws_account_id uuid not null references public.aws_accounts (id) on delete cascade,
  resource_type text not null,
  resource_id text not null,
  region text not null,
  name text,
  state text,
  attributes jsonb not null default '{}'::jsonb check (jsonb_typeof(attributes) = 'object'),
  created_at timestamptz not null default now(),
  -- Within one scan a resource appears once. Re-running the same scan cannot
  -- duplicate inventory rows.
  unique (scan_id, resource_type, resource_id, region)
);

create index if not exists resource_snapshots_scan_idx on public.resource_snapshots (scan_id);
create index if not exists resource_snapshots_org_idx on public.resource_snapshots (organization_id);

-- ---------------------------------------------------------------------------
-- findings
--
-- dedupe_key is what stops the same problem being reported twice across scans.
-- The unique index is scoped per account, not per scan, so re-scanning does
-- not multiply findings.
-- ---------------------------------------------------------------------------
create table if not exists public.findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  scan_id uuid not null references public.scans (id) on delete cascade,
  aws_account_id uuid not null references public.aws_accounts (id) on delete cascade,
  detector text not null,
  resource_type text not null,
  resource_id text not null,
  region text not null,
  severity public.finding_severity not null,
  confidence public.finding_confidence not null,
  state public.finding_state not null default 'estimated',
  title text not null,
  summary text not null,
  evidence jsonb not null default '{}'::jsonb check (jsonb_typeof(evidence) = 'object'),
  recommended_action text not null,
  -- Nullable on purpose. NULL means "we could not defensibly price this",
  -- which is a different statement from 0.00 ("this saves nothing").
  estimated_monthly_savings numeric(14, 2) check (estimated_monthly_savings >= 0),
  currency char(3) not null default 'USD',
  dedupe_key text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (aws_account_id, dedupe_key)
);

create index if not exists findings_org_state_idx on public.findings (organization_id, state);
create index if not exists findings_account_idx on public.findings (aws_account_id);
create index if not exists findings_severity_idx on public.findings (organization_id, severity);

-- ---------------------------------------------------------------------------
-- finding_reviews
--
-- An append-only record of review decisions. The current state lives on
-- findings.state; this table is why the state changed and who changed it.
-- ---------------------------------------------------------------------------
create table if not exists public.finding_reviews (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  actor_user_id uuid references auth.users (id) on delete set null,
  previous_state public.finding_state not null,
  new_state public.finding_state not null,
  note text check (note is null or length(note) <= 2000),
  created_at timestamptz not null default now()
);

create index if not exists finding_reviews_finding_idx on public.finding_reviews (finding_id);

-- ---------------------------------------------------------------------------
-- savings_records
--
-- The savings ledger. `basis` is the crucial column: it records whether a
-- figure is an estimate or something measured after a change. Estimated and
-- verified amounts are therefore never summed together by accident.
-- ---------------------------------------------------------------------------
create table if not exists public.savings_records (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  finding_id uuid references public.findings (id) on delete set null,
  aws_account_id uuid not null references public.aws_accounts (id) on delete cascade,
  basis text not null check (basis in ('estimated', 'verified')),
  monthly_amount numeric(14, 2) not null check (monthly_amount >= 0),
  currency char(3) not null default 'USD',
  -- Evidence supporting a verified figure. Required when basis = 'verified',
  -- so a "verified" row cannot exist without something backing it.
  evidence jsonb check (evidence is null or jsonb_typeof(evidence) = 'object'),
  measured_from timestamptz,
  measured_to timestamptz,
  created_at timestamptz not null default now(),
  constraint savings_verified_needs_evidence
    check (basis <> 'verified' or evidence is not null),
  constraint savings_verified_needs_window
    check (basis <> 'verified' or (measured_from is not null and measured_to is not null)),
  constraint savings_window_order
    check (measured_from is null or measured_to is null or measured_to >= measured_from)
);

create index if not exists savings_records_org_basis_idx on public.savings_records (organization_id, basis);

-- ---------------------------------------------------------------------------
-- audit_events
-- ---------------------------------------------------------------------------
create table if not exists public.audit_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  actor_user_id uuid references auth.users (id) on delete set null,
  action text not null,
  target_type text not null,
  target_id text,
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  created_at timestamptz not null default now()
);

create index if not exists audit_events_org_created_idx on public.audit_events (organization_id, created_at desc);

-- ---------------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------------
create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

do $$
declare
  t text;
begin
  foreach t in array array['organizations', 'aws_accounts', 'scans', 'findings']
  loop
    -- tgname is only unique per table, so the lookup must be scoped by
    -- relation as well; otherwise a same-named trigger on another table would
    -- make this skip creating the one we need.
    if not exists (
      select 1
      from pg_trigger
      where tgname = format('%s_touch_updated_at', t)
        and tgrelid = format('public.%I', t)::regclass
    ) then
      execute format(
        'create trigger %I before update on public.%I
           for each row execute function public.touch_updated_at()',
        format('%s_touch_updated_at', t), t
      );
    end if;
  end loop;
end
$$;

-- ---------------------------------------------------------------------------
-- Row Level Security
--
-- Every tenant table is locked down. A member of an organization can read its
-- rows; only owners and admins may write connection and scan data.
-- ---------------------------------------------------------------------------
alter table public.organizations enable row level security;
alter table public.memberships enable row level security;
alter table public.aws_accounts enable row level security;
alter table public.scans enable row level security;
alter table public.resource_snapshots enable row level security;
alter table public.findings enable row level security;
alter table public.finding_reviews enable row level security;
alter table public.savings_records enable row level security;
alter table public.audit_events enable row level security;

-- organizations: visible to members; only owners may rename or delete.
drop policy if exists organizations_select_member on public.organizations;
create policy organizations_select_member on public.organizations
  for select to authenticated
  using (public.is_org_member(id));

drop policy if exists organizations_update_owner on public.organizations;
create policy organizations_update_owner on public.organizations
  for update to authenticated
  using (public.has_org_role(id, array['owner']::public.member_role[]))
  with check (public.has_org_role(id, array['owner']::public.member_role[]));

drop policy if exists organizations_delete_owner on public.organizations;
create policy organizations_delete_owner on public.organizations
  for delete to authenticated
  using (public.has_org_role(id, array['owner']::public.member_role[]));

-- memberships: a user sees their own organizations' memberships. Only owners
-- and admins may add or change them.
drop policy if exists memberships_select_member on public.memberships;
create policy memberships_select_member on public.memberships
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists memberships_insert_admin on public.memberships;
create policy memberships_insert_admin on public.memberships
  for insert to authenticated
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

drop policy if exists memberships_update_admin on public.memberships;
create policy memberships_update_admin on public.memberships
  for update to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]))
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

drop policy if exists memberships_delete_admin on public.memberships;
create policy memberships_delete_admin on public.memberships
  for delete to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

-- aws_accounts: any member may view connections; only owners and admins may
-- add, change or remove them.
drop policy if exists aws_accounts_select_member on public.aws_accounts;
create policy aws_accounts_select_member on public.aws_accounts
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists aws_accounts_insert_admin on public.aws_accounts;
create policy aws_accounts_insert_admin on public.aws_accounts
  for insert to authenticated
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

drop policy if exists aws_accounts_update_admin on public.aws_accounts;
create policy aws_accounts_update_admin on public.aws_accounts
  for update to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]))
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

drop policy if exists aws_accounts_delete_admin on public.aws_accounts;
create policy aws_accounts_delete_admin on public.aws_accounts
  for delete to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

-- scans and resource snapshots: members read; owners and admins start scans.
drop policy if exists scans_select_member on public.scans;
create policy scans_select_member on public.scans
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists scans_insert_admin on public.scans;
create policy scans_insert_admin on public.scans
  for insert to authenticated
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

drop policy if exists scans_update_admin on public.scans;
create policy scans_update_admin on public.scans
  for update to authenticated
  using (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]))
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

drop policy if exists resource_snapshots_select_member on public.resource_snapshots;
create policy resource_snapshots_select_member on public.resource_snapshots
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists resource_snapshots_insert_admin on public.resource_snapshots;
create policy resource_snapshots_insert_admin on public.resource_snapshots
  for insert to authenticated
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

-- findings: every member may read and review. Reviewing is not an
-- infrastructure change, so members are allowed to triage.
drop policy if exists findings_select_member on public.findings;
create policy findings_select_member on public.findings
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists findings_insert_admin on public.findings;
create policy findings_insert_admin on public.findings
  for insert to authenticated
  with check (public.has_org_role(organization_id, array['owner', 'admin']::public.member_role[]));

drop policy if exists findings_update_member on public.findings;
create policy findings_update_member on public.findings
  for update to authenticated
  using (public.is_org_member(organization_id))
  with check (public.is_org_member(organization_id));

drop policy if exists finding_reviews_select_member on public.finding_reviews;
create policy finding_reviews_select_member on public.finding_reviews
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists finding_reviews_insert_member on public.finding_reviews;
create policy finding_reviews_insert_member on public.finding_reviews
  for insert to authenticated
  with check (public.is_org_member(organization_id));

-- savings and audit history: readable by members. Writes come from the service
-- role (the API), which bypasses RLS by design; no client-side write policy is
-- provided for either, so a browser session cannot fabricate a savings record
-- or an audit entry.
drop policy if exists savings_records_select_member on public.savings_records;
create policy savings_records_select_member on public.savings_records
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists audit_events_select_member on public.audit_events;
create policy audit_events_select_member on public.audit_events
  for select to authenticated
  using (public.is_org_member(organization_id));
