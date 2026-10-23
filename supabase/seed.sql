-- Development seed data. NOT for production.
--
-- This inserts one demo workspace with a connected account, a scan, three
-- findings and matching savings records, so the dashboard has something to
-- render before any real AWS account is connected.
--
-- It needs an existing auth user, because memberships.user_id references
-- auth.users. Sign a user up first; the seed attaches the demo workspace to the
-- earliest-created user. If no user exists it raises rather than failing on a
-- foreign key with a confusing message.
--
-- It is idempotent: fixed UUIDs throughout, so re-running creates nothing and
-- duplicates nothing.

do $$
declare
  -- Prefixed to avoid colliding with column names. A variable named `scan_id`
  -- would shadow the column inside ON CONFLICT target lists, which PL/pgSQL
  -- rejects as ambiguous.
  v_demo_user uuid;
  v_org uuid := 'd0000000-0000-4000-8000-000000000001';
  v_account uuid := 'd0000000-0000-4000-8000-000000000002';
  v_scan uuid := 'd0000000-0000-4000-8000-000000000003';
begin
  select u.id into v_demo_user from auth.users u order by u.created_at, u.id limit 1;

  if v_demo_user is null then
    raise exception 'No auth user found. Sign a user up before seeding.';
  end if;

  insert into public.organizations (id, name, slug)
  values (v_org, 'Demo Workspace', 'demo-workspace')
  on conflict (id) do nothing;

  insert into public.memberships (organization_id, user_id, role)
  values (v_org, v_demo_user, 'owner')
  on conflict (organization_id, user_id) do nothing;

  insert into public.aws_accounts
    (id, organization_id, label, account_id, role_arn, regions, status,
     status_message, last_validated_at, created_by)
  values
    (v_account, v_org, 'Demo production', '111122223333',
     'arn:aws:iam::111122223333:role/CloudPatrolReadOnly',
     array['us-east-1'], 'validated', 'Role assumed successfully.', now(), v_demo_user)
  on conflict (id) do nothing;

  insert into public.scans
    (id, organization_id, aws_account_id, status, started_at, finished_at,
     resource_count, finding_count, partial_failures, created_by)
  values
    (v_scan, v_org, v_account, 'partial', now() - interval '4 minutes',
     now() - interval '3 minutes', 14, 3,
     -- One region failed, so this scan is partial rather than clean. The demo
     -- data exercises that path deliberately.
     '[{"service": "cloudwatch", "region": "us-west-2", "reason": "AccessDenied"}]'::jsonb,
     v_demo_user)
  on conflict (id) do nothing;

  insert into public.resource_snapshots
    (organization_id, scan_id, aws_account_id, resource_type, resource_id, region, name, state, attributes)
  values
    (v_org, v_scan, v_account, 'ebs_volume', 'vol-0demo0000000001', 'us-east-1',
     'orphaned-data', 'available', '{"size_gb": 500, "volume_type": "gp3"}'::jsonb),
    (v_org, v_scan, v_account, 'elastic_ip', 'eipalloc-0demo0000001', 'us-east-1',
     null, 'allocated', '{"association_id": null}'::jsonb),
    (v_org, v_scan, v_account, 'ec2_instance', 'i-0demo00000000001', 'us-east-1',
     'batch-worker', 'running', '{"instance_type": "m5.2xlarge"}'::jsonb)
  on conflict (scan_id, resource_type, resource_id, region) do nothing;

  insert into public.findings
    (organization_id, scan_id, aws_account_id, detector, resource_type, resource_id, region,
     severity, confidence, state, title, summary, evidence, recommended_action,
     estimated_monthly_savings, dedupe_key)
  values
    (v_org, v_scan, v_account, 'unattached_ebs_volume', 'ebs_volume',
     'vol-0demo0000000001', 'us-east-1', 'high', 'high', 'estimated',
     'Unattached EBS volume: 500 GB gp3',
     'The volume has been in the available state for 62 days. It is attached to no instance.',
     '{"size_gb": 500, "volume_type": "gp3", "state": "available", "days_unattached": 62,
       "price_source": "placeholder-us-east-1-on-demand (not a live AWS price feed)",
       "price_captured_on": "2026-01-01", "unit_price_per_gb_month": "0.08"}'::jsonb,
     'Take a snapshot for retention, then delete the volume.',
     40.00, 'ebs_volume:us-east-1:vol-0demo0000000001'),

    (v_org, v_scan, v_account, 'unassociated_elastic_ip', 'elastic_ip',
     'eipalloc-0demo0000001', 'us-east-1', 'medium', 'high', 'estimated',
     'Unassociated Elastic IP',
     'The address is allocated but associated with nothing, and is billed hourly while idle.',
     '{"association_id": null, "days_unassociated": 21,
       "price_source": "placeholder-us-east-1-on-demand (not a live AWS price feed)",
       "price_captured_on": "2026-01-01", "hourly_price": "0.005", "hours_per_month": 730}'::jsonb,
     'Release the address if it is no longer needed.',
     3.65, 'elastic_ip:us-east-1:eipalloc-0demo0000001'),

    -- Deliberately unpriced. The EC2 detector cannot know the right target
    -- size, so it reports no figure. NULL here is a different statement from
    -- 0.00, and the UI renders it as "Not priced".
    (v_org, v_scan, v_account, 'low_utilisation_ec2', 'ec2_instance',
     'i-0demo00000000001', 'us-east-1', 'medium', 'medium', 'estimated',
     'Low-utilisation EC2 instance: batch-worker',
     'Average CPU utilisation was 1.8% over the last 14 days, well below the 5% threshold.',
     '{"instance_type": "m5.2xlarge", "cpu_average_percent": 1.8, "threshold_percent": 5.0,
       "observation_days": 14, "datapoints": 336}'::jsonb,
     'Confirm the workload is still needed, then resize or stop the instance.',
     null, 'ec2_instance:us-east-1:i-0demo00000000001')
  on conflict (aws_account_id, dedupe_key) do nothing;

  insert into public.savings_records
    (organization_id, finding_id, aws_account_id, basis, monthly_amount)
  select v_org, f.id, v_account, 'estimated', f.estimated_monthly_savings
  from public.findings f
  where f.aws_account_id = v_account
    and f.estimated_monthly_savings is not null
    and not exists (
      select 1 from public.savings_records s
      where s.finding_id = f.id and s.basis = 'estimated'
    );

  insert into public.audit_events (organization_id, actor_user_id, action, target_type, target_id, metadata)
  select v_org, v_demo_user, 'aws_account.connected', 'aws_account', v_account::text,
         '{"label": "Demo production"}'::jsonb
  where not exists (
    select 1 from public.audit_events
    where organization_id = v_org and action = 'aws_account.connected'
  );

  raise notice 'Seeded demo workspace % for user %.', v_org, v_demo_user;
end
$$;
