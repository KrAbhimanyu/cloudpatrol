"""Tests for health endpoints and configuration validation."""

from __future__ import annotations

import pytest

from app.core.config import Settings


def test_health_returns_ok(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["environment"] == "test"


def test_health_does_not_require_authentication(client) -> None:  # type: ignore[no-untyped-def]
    # A liveness probe that needs a token cannot be used by an orchestrator.
    assert client.get("/health").status_code == 200


def test_health_returns_request_id_header(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/health")
    assert response.headers.get("X-Request-Id")


def test_health_echoes_supplied_request_id(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/health", headers={"X-Request-Id": "trace-me-123"})
    assert response.headers["X-Request-Id"] == "trace-me-123"


def test_readiness_reports_configuration_presence(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["database_configured"] is True
    assert body["missing_configuration"] == []


def test_readiness_never_leaks_secret_values(client) -> None:  # type: ignore[no-untyped-def]
    body = client.get("/health/ready").text
    # The configured values must not appear anywhere in the response.
    assert "test-service-role-key" not in body
    assert "test-jwt-secret" not in body
    assert "test-anon-key" not in body


def test_production_startup_rejects_missing_configuration() -> None:
    settings = Settings(
        app_env="production",
        supabase_url=None,
        supabase_anon_key=None,
        supabase_service_role_key=None,
        supabase_jwt_secret=None,
    )
    with pytest.raises(RuntimeError) as excinfo:
        settings.validate_startup()
    message = str(excinfo.value)
    assert "SUPABASE_URL" in message
    assert "SUPABASE_SERVICE_ROLE_KEY" in message


def test_production_startup_rejects_wildcard_cors() -> None:
    settings = Settings(
        app_env="production",
        supabase_url="https://example.supabase.co",
        supabase_anon_key="a",
        supabase_service_role_key="b",
        supabase_jwt_secret="c",
        cors_allowed_origins=["*"],
    )
    with pytest.raises(RuntimeError, match="CORS_ALLOWED_ORIGINS"):
        settings.validate_startup()


def test_local_startup_tolerates_missing_configuration() -> None:
    # Local development must not require a Supabase project to boot.
    Settings(app_env="local").validate_startup()


def test_cors_origins_parse_from_csv() -> None:
    settings = Settings(cors_allowed_origins="http://a.test,http://b.test")
    assert settings.cors_allowed_origins == ["http://a.test", "http://b.test"]


def test_supabase_url_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="absolute"):
        Settings(supabase_url="not-a-url")
