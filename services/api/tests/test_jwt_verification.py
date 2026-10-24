"""Tests for real JWT verification.

These exercise `SupabaseTokenVerifier` against tokens signed with locally
generated RSA and EC key pairs. No network is used and no real credential
exists: the public key is injected through the JWKS client, so the signature
path is the real one.

The properties under test are the ones a forged token would attack:

* The signature must be checked, and the accepted algorithm must come from
  configuration rather than from the token's own header.
* An HS256 token signed with a *public* JWKS URL must be rejected. This is the
  algorithm-confusion attack: the URL is public, so accepting it as an HMAC
  secret would let anyone mint a token for any user.
* `exp`, `aud`, `iss` and `sub` must all be enforced.
* A missing or self-contradictory signing configuration must fail closed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.errors import UnauthenticatedError
from app.core.security import SupabaseTokenVerifier
from app.main import create_app

SUPABASE_URL = "https://project.supabase.co"
ISSUER = f"{SUPABASE_URL}/auth/v1"
AUDIENCE = "authenticated"
# The public JWKS endpoint. It ships to the browser, so an attacker knows it.
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"

# A strong, high-entropy secret. Used only by the symmetric-mode tests.
STRONG_SECRET = "correct-horse-battery-staple-" + "0" * 20

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_EC_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())


class _StaticJWKSClient:
    """Returns a fixed public key, standing in for the project's JWKS."""

    def __init__(self, key: object) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> object:  # noqa: ARG002
        return type("SigningKey", (), {"key": self._key})()


def _asymmetric_settings() -> Settings:
    """The documented configuration: asymmetric Supabase signing keys."""
    return Settings(
        app_env="test",
        supabase_url=SUPABASE_URL,
        supabase_jwt_algorithms=["RS256", "ES256"],
    )


def _symmetric_settings(*, secret: str | None = STRONG_SECRET) -> Settings:
    """The legacy configuration: a single shared secret."""
    return Settings(
        app_env="test",
        supabase_url=None,
        supabase_jwt_secret=secret,
        supabase_jwt_algorithms=["HS256"],
    )


def build_verifier(settings: Settings | None = None) -> SupabaseTokenVerifier:
    """A verifier whose JWKS lookup returns the local test key."""
    verifier = SupabaseTokenVerifier(settings or _asymmetric_settings())
    verifier._jwks_client = _StaticJWKSClient(_PRIVATE_KEY.public_key())  # type: ignore[assignment]
    return verifier


def sign(**overrides: object) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "sub": "11111111-1111-1111-1111-111111111111",
        "email": "alice@example.com",
        "aud": AUDIENCE,
        "iss": ISSUER,
        "iat": now,
        "exp": now + timedelta(hours=1),
    }
    claims.update(overrides)
    # A claim explicitly set to None is removed, so a test can omit it.
    payload = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256")


def test_valid_token_yields_the_principal() -> None:
    principal = build_verifier().verify(sign())
    assert principal.user_id == "11111111-1111-1111-1111-111111111111"
    assert principal.email == "alice@example.com"


def test_valid_es256_token_verifies_when_configured() -> None:
    verifier = build_verifier()
    verifier._jwks_client = _StaticJWKSClient(_EC_PRIVATE_KEY.public_key())  # type: ignore[assignment]
    now = datetime.now(UTC)
    token = jwt.encode(
        {"sub": "user-es256", "aud": AUDIENCE, "iss": ISSUER, "exp": now + timedelta(hours=1)},
        _EC_PRIVATE_KEY,
        algorithm="ES256",
    )
    assert verifier.verify(token).user_id == "user-es256"


def test_valid_hs256_token_verifies_when_symmetric_is_configured() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {"sub": "user-hs", "aud": AUDIENCE, "iss": ISSUER, "exp": now + timedelta(hours=1)},
        STRONG_SECRET,
        algorithm="HS256",
    )
    assert build_verifier(_symmetric_settings()).verify(token).user_id == "user-hs"


# --- Algorithm confusion: the core regression ------------------------------


def test_hs256_signed_with_public_jwks_url_is_rejected() -> None:
    """The exact attack: HMAC signed with a value the server treats as public.

    The JWKS URL ships to the browser, so an attacker knows it. It must never
    be usable as an HMAC secret.
    """
    now = datetime.now(UTC)
    forged = jwt.encode(
        {
            "sub": "attacker-chosen-user",
            "aud": AUDIENCE,
            "iss": ISSUER,
            "exp": now + timedelta(hours=24),
        },
        JWKS_URL,
        algorithm="HS256",
    )
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(forged)


def test_pyjwt_refuses_asymmetric_key_material_as_an_hmac_secret() -> None:
    """Defence in depth beneath this service's own allow-list.

    PyJWT refuses to treat a PEM/DER/SSH public key as an HMAC secret, so that
    particular variant of the confusion attack cannot even be constructed. The
    JWKS-URL variant above is the one that PyJWT does *not* catch, which is why
    the configuration-level checks are the load-bearing defence.
    """
    public_pem = _PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = datetime.now(UTC)
    with pytest.raises(jwt.InvalidKeyError):
        jwt.encode(
            {"sub": "attacker", "aud": AUDIENCE, "iss": ISSUER, "exp": now + timedelta(hours=1)},
            public_pem,
            algorithm="HS256",
        )


def test_hs256_token_is_rejected_when_only_asymmetric_algorithms_are_configured() -> None:
    # Even a correctly signed HS256 token is refused: HS256 is not accepted in
    # this configuration.
    now = datetime.now(UTC)
    token = jwt.encode(
        {"sub": "user", "aud": AUDIENCE, "iss": ISSUER, "exp": now + timedelta(hours=1)},
        STRONG_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(token)


def test_asymmetric_token_is_rejected_when_only_symmetric_is_configured() -> None:
    # The reverse confusion: an RS256 token must not be accepted when the
    # server is configured for HMAC only.
    with pytest.raises(UnauthenticatedError):
        build_verifier(_symmetric_settings()).verify(sign())


def test_expired_token_is_rejected() -> None:
    token = sign(exp=datetime.now(UTC) - timedelta(minutes=1))
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(token)


def test_token_from_another_project_is_rejected() -> None:
    token = sign(iss="https://someone-else.supabase.co/auth/v1")
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(token)


def test_token_for_another_audience_is_rejected() -> None:
    token = sign(aud="service_role")
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(token)


def test_token_without_subject_is_rejected() -> None:
    token = sign(sub=None)
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(token)


def test_token_without_expiry_is_rejected() -> None:
    token = sign(exp=None)
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(token)


def test_token_signed_by_another_key_is_rejected() -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {
            "sub": "attacker",
            "aud": AUDIENCE,
            "iss": ISSUER,
            "exp": datetime.now(UTC) + timedelta(hours=1),
        },
        other,
        algorithm="RS256",
    )
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(forged)


def test_unsigned_token_is_rejected() -> None:
    # "alg: none" is the classic bypass; the header check must refuse it before
    # any signature logic runs.
    forged = jwt.encode(
        {"sub": "attacker", "aud": AUDIENCE, "iss": ISSUER},
        key="",
        algorithm="none",
    )
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(forged)


def test_hs256_without_a_configured_secret_is_rejected() -> None:
    # Without a secret configured, an HS256 token must not be trusted, or an
    # attacker could sign one with the public key as the HMAC secret.
    forged = jwt.encode(
        {"sub": "attacker", "aud": AUDIENCE, "iss": ISSUER, "exp": 9999999999},
        key="a" * 48,
        algorithm="HS256",
    )
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(forged)


def test_token_without_issuer_is_rejected() -> None:
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify(sign(iss=None))


def test_empty_token_is_rejected() -> None:
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify("")


def test_garbage_token_is_rejected() -> None:
    with pytest.raises(UnauthenticatedError):
        build_verifier().verify("not.a.jwt")


def test_issuer_is_not_enforced_when_no_url_is_configured() -> None:
    # A deployment using only a shared secret has no project URL to compare
    # against; it must still verify rather than reject everything.
    settings = _symmetric_settings()
    verifier = SupabaseTokenVerifier(settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "user-1",
            "aud": AUDIENCE,
            "iss": ISSUER,
            "exp": now + timedelta(hours=1),
        },
        STRONG_SECRET,
        algorithm="HS256",
    )
    assert verifier.verify(token).user_id == "user-1"


# --- Configuration fails closed --------------------------------------------


def test_url_as_symmetric_secret_is_rejected() -> None:
    """A URL must never be accepted as an HMAC secret.

    This is the misconfiguration that created the bypass: the value is public,
    so anyone could sign a token with it.
    """
    with pytest.raises(RuntimeError, match="high-entropy"):
        SupabaseTokenVerifier(_symmetric_settings(secret=JWKS_URL))


def test_short_symmetric_secret_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="high-entropy"):
        SupabaseTokenVerifier(_symmetric_settings(secret="too-short"))


def test_mixing_symmetric_and_asymmetric_algorithms_is_rejected() -> None:
    settings = Settings(
        app_env="test",
        supabase_url=SUPABASE_URL,
        supabase_jwt_secret=STRONG_SECRET,
        supabase_jwt_algorithms=["HS256", "RS256"],
    )
    with pytest.raises(RuntimeError, match="mix"):
        SupabaseTokenVerifier(settings)


def test_none_algorithm_cannot_be_configured() -> None:
    settings = Settings(app_env="test", supabase_jwt_algorithms=["none"])
    with pytest.raises(RuntimeError, match="none"):
        SupabaseTokenVerifier(settings)


def test_unknown_algorithm_is_rejected() -> None:
    settings = Settings(app_env="test", supabase_jwt_algorithms=["HS999"])
    with pytest.raises(RuntimeError, match="unsupported"):
        SupabaseTokenVerifier(settings)


def test_empty_algorithm_list_is_rejected() -> None:
    settings = Settings(app_env="test", supabase_jwt_algorithms=[])
    with pytest.raises(RuntimeError, match="at least one"):
        SupabaseTokenVerifier(settings)


def test_asymmetric_without_a_project_url_fails_closed_in_production() -> None:
    settings = Settings(
        app_env="production",
        supabase_url=None,
        supabase_anon_key="a",
        supabase_service_role_key="b",
        supabase_jwt_algorithms=["RS256"],
    )
    with pytest.raises(RuntimeError, match="SUPABASE_URL"):
        settings.validate_jwt_configuration()


def test_symmetric_without_a_secret_fails_closed_in_production() -> None:
    settings = Settings(
        app_env="production",
        supabase_url=SUPABASE_URL,
        supabase_anon_key="a",
        supabase_service_role_key="b",
        supabase_jwt_secret=None,
        supabase_jwt_algorithms=["HS256"],
    )
    with pytest.raises(RuntimeError, match="SUPABASE_JWT_SECRET"):
        settings.validate_jwt_configuration()


def test_algorithms_parse_from_a_comma_separated_string() -> None:
    settings = Settings(app_env="test", supabase_jwt_algorithms="rs256, es256")
    assert settings.supabase_jwt_algorithms == ["RS256", "ES256"]


# --- End to end: a forged token is refused by a protected endpoint ----------


def _app_with_real_verifier() -> FastAPI:
    """A real app whose auth uses the real verifier, not the test stub."""
    settings = Settings(
        app_env="test",
        log_level="WARNING",
        supabase_url=SUPABASE_URL,
        supabase_anon_key="test-anon-key",
        supabase_service_role_key="test-service-role-key",
        cors_allowed_origins=["http://localhost:3000"],
        scan_worker_count=1,
        scan_queue_max_size=2,
        scan_worker_poll_timeout_seconds=0.01,
        scan_reaper_enabled=False,
    )
    application = create_app(settings)
    verifier = build_verifier(settings)

    import app.core.dependencies as deps

    application.dependency_overrides[deps.get_token_verifier] = lambda: verifier
    application.state.token_verifier = verifier
    return application


def test_protected_endpoint_returns_401_for_a_forged_hs256_token() -> None:
    """The end-to-end regression for the reported vulnerability.

    Before the fix this returned 200 and listed the impersonated user's
    organizations.
    """
    now = datetime.now(UTC)
    forged = jwt.encode(
        {
            "sub": "attacker-chosen-user",
            "aud": AUDIENCE,
            "iss": ISSUER,
            "exp": now + timedelta(hours=24),
        },
        JWKS_URL,
        algorithm="HS256",
    )
    with TestClient(_app_with_real_verifier()) as client:
        response = client.get(
            "/api/v1/organizations",
            headers={"Authorization": f"Bearer {forged}"},
        )
    assert response.status_code == 401


def test_protected_endpoint_accepts_a_valid_token() -> None:
    """The same endpoint must still work for a legitimately signed token."""
    with TestClient(_app_with_real_verifier()) as client:
        response = client.get(
            "/api/v1/organizations",
            headers={"Authorization": f"Bearer {sign()}"},
        )
    # Authenticated successfully: the caller simply has no organizations yet.
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}
