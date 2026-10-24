"""Tests for cross-account role validation, AssumeRole error classification
and credential-expiry handling.

Everything here runs against the in-memory fake adapter. No AWS call is made
and no real credential is used; the failures are injected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from app.aws.adapter import translate_assume_role_error
from app.core.errors import ErrorCode
from tests.fake_aws import FakeAwsAdapter, FakeAwsError

ROLE_ARN = "arn:aws:iam::123456789012:role/CloudPatrolReadOnly"
ACCOUNT_ID = "123456789012"
EXTERNAL_ID = "cloudpatrol-ext-1234"


def make_payload(**overrides) -> dict:  # type: ignore[no-untyped-def]
    payload = {
        "label": "Production",
        "account_id": ACCOUNT_ID,
        "role_arn": ROLE_ARN,
        "external_id": EXTERNAL_ID,
        "regions": ["us-east-1"],
    }
    payload.update(overrides)
    return payload


def _client_error(code: str, message: str, status: int = 403) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "AssumeRole",
    )


# --- AssumeRole error classification ------------------------------------


def test_missing_role_maps_to_a_distinct_code() -> None:
    """A deleted or mistyped role is not a permissions problem."""
    error = translate_assume_role_error(_client_error("NoSuchEntity", "Role not found", 404))
    assert error.code == ErrorCode.AWS_ROLE_NOT_FOUND
    assert error.status_code == 400


def test_rejected_external_id_is_distinguishable_from_a_trust_problem() -> None:
    """The two AccessDenied variants need different fixes, so they differ."""
    external = translate_assume_role_error(
        _client_error("AccessDenied", "The external ID is not valid for this role")
    )
    trust = translate_assume_role_error(
        _client_error("AccessDenied", "User is not authorized to perform sts:AssumeRole")
    )
    assert external.code == ErrorCode.AWS_EXTERNAL_ID_INVALID
    assert trust.code == ErrorCode.AWS_PERMISSION_DENIED
    assert external.code != trust.code


def test_assume_role_error_does_not_leak_the_aws_message() -> None:
    """AWS echoes the role ARN and external ID in its error text."""
    secret_external_id = "super-secret-external-id-value"
    error = translate_assume_role_error(
        _client_error(
            "AccessDenied",
            f"Not authorized to assume role with external id {secret_external_id}",
        )
    )
    assert secret_external_id not in error.message
    assert "arn:aws:iam" not in error.message
    assert "external" not in error.details


# --- credential expiry --------------------------------------------------


def test_expired_credentials_are_detected() -> None:
    from app.aws.adapter import AwsCredentials

    expired = AwsCredentials(
        access_key_id="ASIAX",
        secret_access_key="s",
        session_token="t",
        expiration=datetime.now(UTC) - timedelta(minutes=1),
    )
    assert expired.is_expired(now=datetime.now(UTC)) is True


def test_credentials_without_an_expiry_are_not_reported_expired() -> None:
    from app.aws.adapter import AwsCredentials

    credentials = AwsCredentials(access_key_id="ASIAX", secret_access_key="s", session_token="t")
    assert credentials.is_expired(now=datetime.now(UTC)) is False


def test_a_scan_stops_early_when_credentials_expire() -> None:
    """Expiry must be recorded once, not as one error per remaining region."""
    from app.aws.adapter import AwsCredentials
    from app.repositories.memory import build_container
    from app.services.scan_service import ScanService

    container = build_container()
    adapter = FakeAwsAdapter()
    service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=[],
    )
    scan = container.scans.create(
        organization_id="org-1",
        aws_account_id="acct-1",
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-1",
    )
    expired = AwsCredentials(
        access_key_id="ASIAX",
        secret_access_key="s",
        session_token="t",
        expiration=datetime.now(UTC) - timedelta(minutes=5),
    )

    record = service.run_scan(
        organization_id="org-1",
        aws_account_id="acct-1",
        account_id=ACCOUNT_ID,
        regions=["us-east-1", "us-west-2", "eu-west-1"],
        credentials=expired,
        created_by="user-1",
        scan_id=scan.id,
    )

    # Not a clean result, and no AWS call was attempted with dead credentials.
    assert record.status == "failed"
    assert adapter.calls == []
    assert len(record.partial_failures) == 1
    assert record.partial_failures[0]["code"] == str(ErrorCode.AWS_ASSUME_ROLE_FAILED)


# --- the validate endpoint ---------------------------------------------


@pytest.fixture
def connected_account(client, org_headers, fake_adapter):  # type: ignore[no-untyped-def]
    response = client.post("/api/v1/aws/accounts", headers=org_headers, json=make_payload())
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_validate_reassumes_the_role_and_reports_the_caller(
    client, org_headers, fake_adapter, connected_account
) -> None:
    response = client.post(
        f"/api/v1/aws/accounts/{connected_account}/validate", headers=org_headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "validated"
    assert body["caller_identity_arn"] is not None
    assert ACCOUNT_ID in body["caller_identity_arn"]
    assert body["credentials_expire_at"] is not None
    # A real assumption happened, not a metadata echo.
    assert ("sts", "AssumeRole") in fake_adapter.calls
    assert ("sts", "GetCallerIdentity") in fake_adapter.calls


def test_validate_never_returns_the_external_id(
    client, org_headers, fake_adapter, connected_account
) -> None:
    response = client.post(
        f"/api/v1/aws/accounts/{connected_account}/validate", headers=org_headers
    )
    assert EXTERNAL_ID not in response.text
    for forbidden in ("secret", "session_token", "access_key"):
        assert forbidden not in response.text.lower()


def test_validate_marks_the_connection_failed_when_the_role_is_gone(
    client, org_headers, fake_adapter, connected_account
) -> None:
    """A connection that stopped working must stop claiming to be validated."""
    fake_adapter.fail_on["sts"] = FakeAwsError(
        "The role could not be assumed.",
        code=ErrorCode.AWS_ROLE_NOT_FOUND,
        status_code=400,
    )
    response = client.post(
        f"/api/v1/aws/accounts/{connected_account}/validate", headers=org_headers
    )
    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == str(ErrorCode.AWS_ROLE_NOT_FOUND)

    listing = client.get("/api/v1/aws/accounts", headers=org_headers).json()
    assert listing["items"][0]["status"] == "failed"


def test_validate_requires_owner_or_admin(
    client, app, org_headers, fake_adapter, connected_account
):  # type: ignore[no-untyped-def]
    """A non-managing member cannot force a role assumption."""
    from app.repositories.models import MembershipRecord, new_id, utc_now

    store = app.state.container.store
    org_id = org_headers["X-Organization-Id"]
    membership = MembershipRecord(
        id=new_id(),
        organization_id=org_id,
        user_id="user-bob",
        role="viewer",
        created_at=utc_now(),
    )
    with store.lock:
        store.memberships[membership.id] = membership

    headers = {"Authorization": "Bearer test-token-bob", "X-Organization-Id": org_id}
    response = client.post(f"/api/v1/aws/accounts/{connected_account}/validate", headers=headers)
    assert response.status_code == 403, response.text


def test_validate_is_tenant_scoped(client, org_headers, fake_adapter, connected_account) -> None:
    """Another organization cannot validate an account it does not own."""
    other = client.post(
        "/api/v1/organizations",
        headers={"Authorization": "Bearer test-token-bob"},
        json={"name": "Globex", "slug": "globex"},
    )
    assert other.status_code == 201, other.text
    other_headers = {
        "Authorization": "Bearer test-token-bob",
        "X-Organization-Id": other.json()["id"],
    }
    response = client.post(
        f"/api/v1/aws/accounts/{connected_account}/validate", headers=other_headers
    )
    # 404, not 403: the existence of another tenant's account is not disclosed.
    assert response.status_code == 404, response.text


# --- region allowlist ---------------------------------------------------


def test_a_region_outside_the_allowlist_is_rejected(client, org_headers, fake_adapter) -> None:
    """The configured allowlist is enforced, not merely documented."""
    response = client.post(
        "/api/v1/aws/accounts",
        headers=org_headers,
        json=make_payload(regions=["us-east-1", "af-south-1"]),
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["details"]["unsupported_regions"] == ["af-south-1"]


def test_allowlisted_regions_are_accepted(client, org_headers, fake_adapter) -> None:
    response = client.post(
        "/api/v1/aws/accounts",
        headers=org_headers,
        json=make_payload(regions=["us-east-1", "eu-west-1"]),
    )
    assert response.status_code == 201, response.text
    assert response.json()["regions"] == ["us-east-1", "eu-west-1"]
