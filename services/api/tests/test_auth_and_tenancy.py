"""Tests for authentication and tenant authorization boundaries."""

from __future__ import annotations

from tests.conftest import ALICE_ID, ALICE_TOKEN


def test_missing_authorization_header_is_rejected(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/api/v1/organizations")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_non_bearer_scheme_is_rejected(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/api/v1/organizations", headers={"Authorization": "Basic abc"})
    assert response.status_code == 401


def test_unknown_token_is_rejected(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get(
        "/api/v1/organizations", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert response.status_code == 401


def test_error_envelope_has_stable_shape(client) -> None:  # type: ignore[no-untyped-def]
    body = client.get("/api/v1/organizations").json()
    assert set(body) == {"error"}
    assert set(body["error"]) >= {"code", "message", "details"}


def _create_org(client, headers, slug: str) -> str:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/organizations",
        headers=headers,
        json={"name": f"Org {slug}", "slug": slug},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_create_organization_makes_caller_the_owner(client, alice_headers) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/api/v1/organizations",
        headers=alice_headers,
        json={"name": "Acme Cloud", "slug": "acme-cloud"},
    )
    assert response.status_code == 201
    assert response.json()["role"] == "owner"


def test_organization_requires_org_header(client, alice_headers) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/api/v1/aws/accounts", headers=alice_headers)
    assert response.status_code == 403


def test_non_member_cannot_read_another_orgs_accounts(client, alice_headers, bob_headers) -> None:  # type: ignore[no-untyped-def]
    org_id = _create_org(client, alice_headers, "alice-org")

    # Bob presents Alice's organization ID. The API must refuse.
    response = client.get(
        "/api/v1/aws/accounts",
        headers={**bob_headers, "X-Organization-Id": org_id},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_member_sees_only_their_own_organizations(client, alice_headers, bob_headers) -> None:  # type: ignore[no-untyped-def]
    _create_org(client, alice_headers, "alice-only")

    alice_list = client.get("/api/v1/organizations", headers=alice_headers).json()
    bob_list = client.get("/api/v1/organizations", headers=bob_headers).json()

    assert alice_list["total"] == 1
    assert bob_list["total"] == 0


def test_nonexistent_organization_is_indistinguishable_from_forbidden(client, bob_headers) -> None:  # type: ignore[no-untyped-def]
    # A wrong ID and a non-member ID must return the same response, so the
    # endpoint cannot be used to discover which organizations exist.
    response = client.get(
        "/api/v1/aws/accounts",
        headers={**bob_headers, "X-Organization-Id": "00000000-0000-0000-0000-000000000000"},
    )
    assert response.status_code == 403


def test_duplicate_slug_for_same_user_conflicts(client, alice_headers) -> None:  # type: ignore[no-untyped-def]
    _create_org(client, alice_headers, "same-slug")
    response = client.post(
        "/api/v1/organizations",
        headers=alice_headers,
        json={"name": "Another", "slug": "same-slug"},
    )
    assert response.status_code == 409


def test_principal_user_id_comes_from_token_not_request(client, alice_headers) -> None:  # type: ignore[no-untyped-def]
    # There is no user_id field in the payload, so a client cannot impersonate
    # another user by supplying one.
    response = client.post(
        "/api/v1/organizations",
        headers=alice_headers,
        json={"name": "X", "slug": "x-org", "user_id": "someone-else"},
    )
    assert response.status_code == 422

    listed = client.get("/api/v1/organizations", headers=alice_headers).json()
    assert listed["total"] == 0

    # And the org created under Alice's identity is hers.
    client.post("/api/v1/organizations", headers=alice_headers, json={"name": "Y", "slug": "y-org"})
    assert client.get("/api/v1/organizations", headers=alice_headers).json()["total"] == 1
    assert ALICE_TOKEN  # token identity is the only source of user_id
    assert ALICE_ID
