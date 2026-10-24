"""Tests for health endpoints and configuration validation."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


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


def test_list_settings_accept_csv_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented CSV form must work as an env var, not just a kwarg.

    pydantic-settings JSON-decodes list fields before validators run, so
    without ``NoDecode`` a plain ``a,b`` value is a hard parse error.
    """
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://a.test,http://b.test")
    monkeypatch.setenv("AWS_ALLOWED_REGIONS", "us-east-1,eu-west-1")
    monkeypatch.setenv("SUPABASE_JWT_ALGORITHMS", "RS256,ES256")

    settings = Settings(app_env="test")
    assert settings.cors_allowed_origins == ["http://a.test", "http://b.test"]
    assert settings.aws_allowed_regions == ["us-east-1", "eu-west-1"]
    assert settings.supabase_jwt_algorithms == ["RS256", "ES256"]


def test_list_settings_accept_a_json_array_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A JSON array must keep working, so existing deployments do not break."""
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", '["http://a.test"]')
    monkeypatch.setenv("SUPABASE_JWT_ALGORITHMS", '["hs256"]')
    monkeypatch.setenv("SUPABASE_JWT_SECRET", "s" * 40)

    settings = Settings(app_env="test")
    assert settings.cors_allowed_origins == ["http://a.test"]
    # Names are normalised, so a lower-case JSON value still validates.
    assert settings.supabase_jwt_algorithms == ["HS256"]
    settings.validate_jwt_configuration()


def test_algorithm_names_are_normalised_to_upper_case() -> None:
    settings = Settings(app_env="test", supabase_jwt_algorithms="rs256, es256")
    assert settings.supabase_jwt_algorithms == ["RS256", "ES256"]


# --- DATABASE_URL (Phase A: optional, unused at runtime) ---------------------


def test_database_url_defaults_to_none() -> None:
    """Absent configuration must be valid, not an error."""
    assert Settings(app_env="test").database_url is None


def test_database_url_is_not_required_in_production() -> None:
    """A deployment not yet migrated to PostgreSQL must still start.

    The setting is deliberately excluded from the required-configuration check
    so that adding it cannot break an existing deployment.
    """
    settings = Settings(
        app_env="production",
        supabase_url="https://your-project-ref.supabase.co",
        supabase_anon_key="anon-key",
        supabase_service_role_key="service-role-key",
        supabase_jwt_algorithms=["RS256", "ES256"],
    )
    assert settings.database_url is None
    assert "DATABASE_URL" not in settings.missing_required_for_runtime()
    settings.validate_startup()


def test_database_url_accepts_a_placeholder_connection_string() -> None:
    """A supplied value parses, without being validated or connected to."""
    settings = Settings(
        app_env="test",
        database_url="postgresql://user:placeholder@localhost:5432/cloudpatrol",
    )
    assert settings.database_url is not None
    assert (
        settings.database_url.get_secret_value()
        == "postgresql://user:placeholder@localhost:5432/cloudpatrol"
    )


def test_database_url_is_a_secret_and_never_rendered() -> None:
    """The DSN embeds a password, so it must not appear in a repr or a str."""
    settings = Settings(
        app_env="test",
        database_url="postgresql://user:placeholder@localhost:5432/cloudpatrol",
    )
    assert "placeholder" not in repr(settings)
    assert "placeholder" not in str(settings)
    assert "placeholder" not in repr(settings.database_url)


def test_blank_database_url_is_treated_as_unset() -> None:
    """``.env.example`` ships ``DATABASE_URL=``; that must equal "unset"."""
    assert Settings(app_env="test", database_url="").database_url is None
    assert Settings(app_env="test", database_url="   ").database_url is None


def test_database_url_is_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:placeholder@localhost:5432/cloudpatrol")
    settings = Settings(app_env="test")
    assert settings.database_url is not None
    assert (
        settings.database_url.get_secret_value()
        == "postgresql://user:placeholder@localhost:5432/cloudpatrol"
    )


def test_readiness_endpoint_does_not_expose_a_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configured connection string is a credential and must not be echoed."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:placeholder@localhost:5432/cloudpatrol")
    settings = Settings(app_env="test")
    assert settings.database_url is not None

    application = create_app(settings)
    with TestClient(application) as test_client:
        body = test_client.get("/health/ready").text

    assert "postgresql://" not in body
    assert "placeholder" not in body
