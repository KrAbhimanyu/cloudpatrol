"""Integration tests for the AWS account, scan and finding endpoints.

The AWS adapter is replaced with the in-memory fake via the app's state, so
the full HTTP path — routing, validation, authorization, service, repository —
runs for real. No network call is made and no credential is required.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from app.services.billing import BillingService
from app.services.scan_runner import ScanJob, ScanWorkerPool
from tests.fake_aws import FakeAwsAdapter, FakeAwsError

ROLE_ARN = "arn:aws:iam::123456789012:role/CloudPatrolReadOnly"
ACCOUNT_ID = "123456789012"


def make_account_payload(**overrides) -> dict:  # type: ignore[no-untyped-def]
    payload = {
        "label": "Production",
        "account_id": ACCOUNT_ID,
        "role_arn": ROLE_ARN,
        "external_id": "cloudpatrol-ext-1234",
        "regions": ["us-east-1"],
    }
    payload.update(overrides)
    return payload


def unattached_volume(volume_id: str = "vol-1") -> dict:
    return {
        "VolumeId": volume_id,
        "State": "available",
        "Size": 100,
        "VolumeType": "gp3",
        "AvailabilityZone": "us-east-1a",
        "CreateTime": datetime.now(UTC),
        "Tags": [],
    }


@pytest.fixture
def org(client, alice_headers) -> str:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/organizations",
        headers=alice_headers,
        json={"name": "Acme", "slug": "acme"},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


@pytest.fixture
def org_headers(alice_headers, org):  # type: ignore[no-untyped-def]
    return {**alice_headers, "X-Organization-Id": org}


@pytest.fixture
def fake_adapter(app) -> FakeAwsAdapter:  # type: ignore[no-untyped-def]
    """Install a fake AWS adapter on the running app.

    Both the request path (account validation) and the worker path (scan
    execution) resolve AWS through the connection service and the scan service,
    so swapping those two covers the whole pipeline. The billing service is a
    third holder of the adapter and is swapped too, or a scan would reach the
    real Cost Explorer client.
    """
    adapter = FakeAwsAdapter()
    app.state.aws_adapter = adapter
    app.state.aws_connection_service._adapter = adapter  # noqa: SLF001
    app.state.scan_service._adapter = adapter  # noqa: SLF001
    # Rebuild the billing service around the fake, rather than mutating its
    # internals, so a scan cannot reach the real Cost Explorer client.
    if app.state.scan_service._billing is not None:  # noqa: SLF001
        app.state.scan_service._billing = BillingService(adapter)
    return adapter


# --- account registration -----------------------------------------------


def test_connect_account_succeeds(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    response = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["account_id"] == ACCOUNT_ID
    assert body["status"] == "validated"


def test_account_response_never_includes_external_id(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    response = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    assert "external_id" not in response.text
    assert "cloudpatrol-ext-1234" not in response.text


def test_account_response_never_includes_credentials(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    response = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    text = response.text.lower()
    for forbidden in ("secret", "session_token", "access_key", "password"):
        assert forbidden not in text


@pytest.mark.parametrize(
    "overrides",
    [
        {"account_id": "123"},
        {"account_id": "abcdefghijkl"},
        {"role_arn": "not-an-arn"},
        {"role_arn": "arn:aws:iam::999999999999:role/Other"},
        {"external_id": "x"},
        {"external_id": "bad id with spaces"},
        {"regions": []},
        {"regions": ["not-a-region"]},
        {"label": ""},
    ],
)
def test_invalid_account_payloads_are_rejected(
    client, org_headers, fake_adapter, overrides
) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/aws/accounts", headers=org_headers, json=make_account_payload(**overrides)
    )
    assert response.status_code in {400, 403, 422}, response.text


def test_role_arn_account_mismatch_is_rejected_before_aws_call(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/aws/accounts",
        headers=org_headers,
        json=make_account_payload(role_arn="arn:aws:iam::555555555555:role/CloudPatrolReadOnly"),
    )
    assert response.status_code == 403
    # No AWS call should have been attempted for a locally detectable error.
    assert fake_adapter.calls == []


def test_duplicate_account_conflicts(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    first = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    assert first.status_code == 201
    second = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    assert second.status_code == 409


def test_assume_role_denied_surfaces_as_403(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    fake_adapter.fail_on["sts"] = FakeAwsError(
        "denied", code="aws_permission_denied", status_code=403
    )
    response = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    assert response.status_code == 403


def test_account_mismatch_between_role_and_identity_is_caught(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    """The role resolves to a different account than the user claimed."""
    fake_adapter.account_id = "999999999999"
    response = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "aws_account_mismatch"


def test_list_accounts_is_org_scoped(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    response = client.get("/api/v1/aws/accounts", headers=org_headers)
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_non_member_cannot_list_accounts(
    client, org_headers, bob_headers, org, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/api/v1/aws/accounts", headers={**bob_headers, "X-Organization-Id": org})
    assert response.status_code == 403


# --- scanning -----------------------------------------------------------


def _connect(client, org_headers, fake_adapter) -> str:  # type: ignore[no-untyped-def]
    response = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_account_payload())
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _await_scan(client, org_headers, scan_id, timeout=5.0):  # type: ignore[no-untyped-def]
    """Poll a queued scan until the background worker reaches a terminal state.

    Scanning is asynchronous, so the POST only accepts the job. Polling is what
    the frontend does, so exercising it here covers the real contract.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/v1/scans/{scan_id}", headers=org_headers).json()
        if body["status"] not in {"queued", "running"}:
            return body
        time.sleep(0.01)
    raise AssertionError(f"scan {scan_id} did not finish within {timeout}s")


def _run_scan(client, org_headers, account_pk):  # type: ignore[no-untyped-def]
    """Queue a scan and wait for its outcome."""
    response = client.post(
        "/api/v1/scans", headers=org_headers, json={"aws_account_id": account_pk}
    )
    assert response.status_code == 202, response.text
    return _await_scan(client, org_headers, response.json()["id"])


def test_scan_creates_findings(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001

    body = _run_scan(client, org_headers, account_pk)
    assert body["status"] == "completed"
    assert body["finding_count"] == 1

    findings = client.get("/api/v1/findings", headers=org_headers).json()
    assert findings["total"] == 1
    assert findings["items"][0]["state"] == "estimated"


def test_scan_for_unknown_account_404s(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/scans",
        headers=org_headers,
        json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert response.status_code == 404


def test_scan_cannot_target_another_orgs_account(
    client, org_headers, bob_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    # Bob is not a member of Alice's org, so he cannot even reach the route.
    response = client.post(
        "/api/v1/scans",
        headers={**bob_headers, "X-Organization-Id": org_headers["X-Organization-Id"]},
        json={"aws_account_id": account_pk},
    )
    assert response.status_code == 403


def test_partial_scan_is_reported_as_partial(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    fake_adapter._instances = [  # noqa: SLF001
        {"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "m5.large"}
    ]
    fake_adapter.fail_on["cloudwatch"] = FakeAwsError(
        "denied", code="aws_permission_denied", status_code=403
    )

    body = _run_scan(client, org_headers, account_pk)
    assert body["status"] == "partial"
    assert body["partial_failures"]


def test_ec2_denied_marks_scan_partial_but_keeps_volume_findings(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    """A denial on one service must not discard what another service returned."""
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    fake_adapter.fail_on["ec2"] = FakeAwsError(
        "denied", code="aws_permission_denied", status_code=403
    )

    body = _run_scan(client, org_headers, account_pk)
    # All EC2 calls fail and nothing else is collected, so this is a total
    # failure rather than a partial one.
    assert body["status"] == "failed"


def test_scan_history_is_listed(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    _run_scan(client, org_headers, account_pk)
    history = client.get("/api/v1/scans", headers=org_headers).json()
    assert history["total"] == 1


def test_scan_status_can_be_fetched(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    created = client.post(
        "/api/v1/scans", headers=org_headers, json={"aws_account_id": account_pk}
    ).json()
    fetched = client.get(f"/api/v1/scans/{created['id']}", headers=org_headers)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == created["id"]


def test_scan_status_of_another_org_404s(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    scan = _run_scan(client, org_headers, account_pk)

    # A second user who creates their own org must not read that scan.
    other = client.post(
        "/api/v1/organizations",
        headers={"Authorization": "Bearer test-token-bob"},
        json={"name": "Bob Co", "slug": "bob-co"},
    ).json()
    response = client.get(
        f"/api/v1/scans/{scan['id']}",
        headers={"Authorization": "Bearer test-token-bob", "X-Organization-Id": other["id"]},
    )
    assert response.status_code == 404


# --- findings and savings ----------------------------------------------


def test_finding_review_transition_is_audited(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)
    finding = client.get("/api/v1/findings", headers=org_headers).json()["items"][0]

    response = client.patch(
        f"/api/v1/findings/{finding['id']}",
        headers=org_headers,
        json={"state": "acknowledged", "note": "reviewing"},
    )
    assert response.status_code == 200
    assert response.json()["state"] == "acknowledged"

    events = client.app.state.container.audit.list_for_org(org_headers["X-Organization-Id"])
    assert any(e.action == "finding.acknowledged" for e in events)


def test_finding_cannot_be_marked_verified(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    """Verification needs post-change evidence; it cannot be set by hand."""
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)
    finding = client.get("/api/v1/findings", headers=org_headers).json()["items"][0]

    response = client.patch(
        f"/api/v1/findings/{finding['id']}",
        headers=org_headers,
        json={"state": "verified"},
    )
    assert response.status_code == 422


def test_dismissed_finding_cannot_be_reviewed_again(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)
    finding = client.get("/api/v1/findings", headers=org_headers).json()["items"][0]

    client.patch(
        f"/api/v1/findings/{finding['id']}", headers=org_headers, json={"state": "dismissed"}
    )
    second = client.patch(
        f"/api/v1/findings/{finding['id']}", headers=org_headers, json={"state": "acknowledged"}
    )
    assert second.status_code == 409


def test_savings_summary_separates_potential_from_verified(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)

    summary = client.get("/api/v1/findings/summary/savings", headers=org_headers).json()
    assert summary["potential_monthly_savings"] == "8.00"
    # Nothing has been remediated, so verified must be zero.
    assert summary["verified_monthly_savings"] == "0.00"


def test_duplicate_scan_is_rejected(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    """An in-flight scan for the same account must not be started twice."""
    account_pk = _connect(client, org_headers, fake_adapter)

    # Simulate a scan already in progress.
    client.app.state.container.scans.create(
        organization_id=org_headers["X-Organization-Id"],
        aws_account_id=account_pk,
        status="running",
        started_at=datetime.now(UTC),
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-alice",
    )

    response = client.post(
        "/api/v1/scans", headers=org_headers, json={"aws_account_id": account_pk}
    )
    assert response.status_code == 409


def test_failed_role_assumption_does_not_block_later_scans(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    """A failed AssumeRole must not leave a scan row that locks the account.

    Regression test: the scan row used to be created before the role was
    assumed. When AssumeRole failed, the row stayed ``queued``, and because
    ``queued`` counts as active, every later scan of that account returned 409
    forever.
    """
    account_pk = _connect(client, org_headers, fake_adapter)

    fake_adapter.fail_on["sts"] = FakeAwsError(
        "denied", code="aws_permission_denied", status_code=403
    )
    first = client.post("/api/v1/scans", headers=org_headers, json={"aws_account_id": account_pk})
    assert first.status_code == 403

    # No scan row should have been left behind by the failed attempt.
    scans = client.get("/api/v1/scans", headers=org_headers).json()
    assert scans["total"] == 0

    # With the role healthy again, scanning must work.
    fake_adapter.fail_on.clear()
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    body = _run_scan(client, org_headers, account_pk)
    assert body["status"] == "completed"


def test_a_full_scan_queue_does_not_strand_the_account(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    """A refused job must fail its scan row, not leave it queued.

    A stranded `queued` row counts as active, so it would block every later
    scan of that account. A fresh pool with no workers started keeps accepting
    submissions while nothing drains the queue, which is how the refusal path
    is reached deterministically.
    """
    account_pk = _connect(client, org_headers, fake_adapter)

    real_pool = client.app.state.scan_pool
    stalled = ScanWorkerPool(
        executor=real_pool._executor,  # noqa: SLF001
        worker_count=1,
        max_queue_size=1,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=1.0,
    )
    # Not started: submissions are accepted, but nothing consumes them.
    client.app.state.scan_pool = stalled
    stalled.submit(
        ScanJob(
            scan_id="filler",
            organization_id=org_headers["X-Organization-Id"],
            aws_account_id=account_pk,
            created_by="user-alice",
        )
    )

    response = client.post(
        "/api/v1/scans", headers=org_headers, json={"aws_account_id": account_pk}
    )
    assert response.status_code == 409, response.text
    assert "full" in response.json()["error"]["message"].lower()

    # The refused scan row was failed rather than left queued, so it does not
    # count as active and the account is free for a later attempt.
    scans = client.get("/api/v1/scans", headers=org_headers).json()
    assert scans["total"] == 1
    assert scans["items"][0]["status"] == "failed"
    assert (
        client.app.state.container.scans.find_active_for_account(
            org_headers["X-Organization-Id"], account_pk
        )
        is None
    )


def test_openapi_schema_is_available(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "/api/v1/aws/accounts" in response.json()["paths"]


# --- savings ledger (HTTP) ----------------------------------------------


def test_a_scan_populates_the_potential_ledger(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)

    ledger = client.get("/api/v1/savings/ledger", headers=org_headers).json()
    # An unattached gp3 volume is priced, so it lands in the potential bucket.
    assert float(ledger["potential_monthly_savings"]) > 0
    # And critically, nothing landed in the verified bucket.
    assert ledger["verified_monthly_savings"] == "0.00"
    assert ledger["verified_count"] == 0
    assert len(ledger["entries"]) == 1
    assert ledger["entries"][0]["basis"] == "potential"


def test_rescanning_does_not_double_the_potential_total(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    """The end-to-end version of the double-attribution guarantee."""
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001

    _run_scan(client, org_headers, account_pk)
    first = client.get("/api/v1/savings/ledger", headers=org_headers).json()
    _run_scan(client, org_headers, account_pk)
    second = client.get("/api/v1/savings/ledger", headers=org_headers).json()

    assert first["potential_monthly_savings"] == second["potential_monthly_savings"]
    assert first["potential_count"] == second["potential_count"] == 1


def test_verified_advance_requires_evidence_over_http(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)

    finding_id = client.get("/api/v1/findings", headers=org_headers).json()["items"][0]["id"]

    # Walking the workflow in order, but the final step omits evidence.
    for basis in ("approved", "implemented"):
        response = client.post(
            f"/api/v1/savings/findings/{finding_id}/advance",
            headers=org_headers,
            json={"target_basis": basis},
        )
        assert response.status_code == 200, response.text

    response = client.post(
        f"/api/v1/savings/findings/{finding_id}/advance",
        headers=org_headers,
        json={"target_basis": "verified", "monthly_amount": "12.00"},
    )
    assert response.status_code == 422, response.text
    assert "evidence" in response.json()["error"]["details"]["missing"]


def test_skipping_the_workflow_is_rejected_over_http(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)

    finding_id = client.get("/api/v1/findings", headers=org_headers).json()["items"][0]["id"]
    response = client.post(
        f"/api/v1/savings/findings/{finding_id}/advance",
        headers=org_headers,
        json={
            "target_basis": "verified",
            "monthly_amount": "12.00",
            "evidence": {"method": "x"},
            "measured_from": "2026-01-01T00:00:00Z",
            "measured_to": "2026-02-01T00:00:00Z",
        },
    )
    assert response.status_code == 409, response.text


def test_dismissing_a_finding_withdraws_its_potential(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)

    finding_id = client.get("/api/v1/findings", headers=org_headers).json()["items"][0]["id"]
    client.patch(f"/api/v1/findings/{finding_id}", headers=org_headers, json={"state": "dismissed"})

    ledger = client.get("/api/v1/savings/ledger", headers=org_headers).json()
    assert ledger["potential_monthly_savings"] == "0.00"
    assert ledger["potential_count"] == 0


def test_a_member_cannot_advance_the_ledger(
    client, bob_headers, alice_headers, org, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    """Ledger writes are an owner/admin decision, not a member one."""
    alice_org = {**alice_headers, "X-Organization-Id": org}
    account_pk = _connect(client, alice_org, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, alice_org, account_pk)
    finding_id = client.get("/api/v1/findings", headers=alice_org).json()["items"][0]["id"]

    # Bob is not a member of Alice's organization at all.
    bob_org = {**bob_headers, "X-Organization-Id": org}
    response = client.post(
        f"/api/v1/savings/findings/{finding_id}/advance",
        headers=bob_org,
        json={"target_basis": "approved"},
    )
    assert response.status_code == 403


# --- reported spend (HTTP) -----------------------------------------------


def cost_group(service: str, amount: str) -> dict:  # type: ignore[no-untyped-def]
    return {
        "Keys": [service],
        "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}},
    }


def test_a_scan_records_reported_spend_separately_from_savings(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    """Billing lands in its own endpoint, never in the savings ledger."""
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._cost_groups = [cost_group("Amazon Elastic Compute Cloud - Compute", "250.00")]

    _run_scan(client, org_headers, account_pk)

    summary = client.get("/api/v1/costs/summary", headers=org_headers).json()
    assert summary["available"] is True
    assert summary["total_amount"] == "250.00"
    assert len(summary["by_service"]) == 1

    # The savings ledger must be untouched by billing data.
    ledger = client.get("/api/v1/savings/ledger", headers=org_headers).json()
    assert ledger["verified_monthly_savings"] == "0.00"


def test_cost_summary_is_unavailable_not_zero_when_nothing_was_read(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    """No observations must not be rendered as a zero bill."""
    _connect(client, org_headers, fake_adapter)
    summary = client.get("/api/v1/costs/summary", headers=org_headers).json()
    assert summary["available"] is False
    assert summary["total_amount"] is None


def test_a_billing_permission_denial_keeps_the_scan_from_reporting_a_bill(
    client, org_headers, fake_adapter
) -> None:  # type: ignore[no-untyped-def]
    """A denied ce:GetCostAndUsage is recorded as a gap, not as $0 spent."""
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    fake_adapter.fail_on["ce"] = FakeAwsError(
        "denied", code="aws_permission_denied", status_code=403
    )

    body = _run_scan(client, org_headers, account_pk)
    # Inventory still succeeded, so the scan is partial rather than failed.
    assert body["status"] == "partial"
    assert any(failure["service"] == "ce" for failure in body["partial_failures"])

    summary = client.get("/api/v1/costs/summary", headers=org_headers).json()
    assert summary["available"] is False
    assert summary["total_amount"] is None


def test_cost_summary_can_be_filtered_by_account(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._cost_groups = [cost_group("Amazon Simple Storage Service", "9.00")]
    _run_scan(client, org_headers, account_pk)

    matching = client.get(
        f"/api/v1/costs/summary?aws_account_id={account_pk}", headers=org_headers
    ).json()
    assert matching["available"] is True

    other = client.get(
        "/api/v1/costs/summary?aws_account_id=00000000-0000-0000-0000-000000000000",
        headers=org_headers,
    ).json()
    assert other["available"] is False


def test_a_ledger_entry_carries_its_detector(client, org_headers, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    """The client groups potential savings by detector, so the API resolves it."""
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._volumes = [unattached_volume()]  # noqa: SLF001
    _run_scan(client, org_headers, account_pk)

    ledger = client.get("/api/v1/savings/ledger", headers=org_headers).json()
    assert ledger["entries"][0]["detector"] == "unattached_ebs_volume"


def test_costs_are_org_scoped(client, org_headers, bob_headers, org, fake_adapter) -> None:  # type: ignore[no-untyped-def]
    """Bob cannot read Alice's spend even with her organization header."""
    account_pk = _connect(client, org_headers, fake_adapter)
    fake_adapter._cost_groups = [cost_group("Amazon EC2", "100.00")]
    _run_scan(client, org_headers, account_pk)

    response = client.get(
        "/api/v1/costs/summary",
        headers={**bob_headers, "X-Organization-Id": org},
    )
    assert response.status_code == 403
