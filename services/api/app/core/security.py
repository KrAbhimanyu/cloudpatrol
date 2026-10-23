"""Authentication: verification of Supabase-issued access tokens.

The API is a resource server. It verifies a bearer JWT and derives the caller
identity from it; it never trusts a user or organization identifier supplied
by the client. Authorization decisions are then made server-side against the
derived identity.

Verification is pluggable so tests can inject a stub verifier without
weakening any production check.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient

from app.core.config import Settings, get_settings
from app.core.errors import UnauthenticatedError

# Supabase access tokens are signed with the project's JWT secret (HS256) or,
# for newer projects, asymmetric keys published at the JWKS endpoint.
_ASYMMETRIC_ALGORITHMS = frozenset({"RS256", "ES256"})


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    user_id: str
    email: str | None
    claims: dict[str, Any]

    @property
    def app_metadata(self) -> dict[str, Any]:
        value = self.claims.get("app_metadata")
        return value if isinstance(value, dict) else {}


class TokenVerifier(Protocol):
    """Verifies a bearer token and returns the caller identity."""

    def verify(self, token: str) -> Principal: ...


class SupabaseTokenVerifier:
    """Verifies Supabase JWTs using either the shared secret or JWKS."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jwks_client: PyJWKClient | None = None

    def _audience(self) -> str | None:
        # Supabase issues "authenticated" for signed-in users. Enforcing the
        # audience prevents accepting a token minted for another purpose.
        return "authenticated"

    def verify(self, token: str) -> Principal:
        if not token:
            raise UnauthenticatedError("No bearer token supplied.")

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise UnauthenticatedError("Malformed bearer token.") from exc

        algorithm = header.get("alg", "")
        key: Any
        algorithms: list[str]

        if algorithm in _ASYMMETRIC_ALGORITHMS:
            key = self._jwks_signing_key(token)
            algorithms = [algorithm]
        elif algorithm == "HS256":
            secret = self._settings.supabase_jwt_secret
            if not secret:
                raise UnauthenticatedError("Token verification is not configured.")
            key = secret
            algorithms = ["HS256"]
        else:
            # Refusing "none" and any unexpected algorithm is what prevents a
            # forged-token bypass.
            raise UnauthenticatedError("Unsupported token signing algorithm.")

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=algorithms,
                audience=self._audience(),
                options={"require": ["exp", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise UnauthenticatedError("The session has expired.") from exc
        except jwt.PyJWTError as exc:
            raise UnauthenticatedError("The bearer token is not valid.") from exc

        subject = claims.get("sub")
        if not subject:
            raise UnauthenticatedError("The bearer token has no subject.")

        email = claims.get("email")
        return Principal(
            user_id=str(subject),
            email=str(email) if email else None,
            claims=claims,
        )

    def _jwks_signing_key(self, token: str) -> Any:
        url = self._settings.supabase_url
        if not url:
            raise UnauthenticatedError("Token verification is not configured.")
        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(f"{url.rstrip('/')}/auth/v1/.well-known/jwks.json")
        try:
            return self._jwks_client.get_signing_key_from_jwt(token).key
        except jwt.PyJWTError as exc:
            raise UnauthenticatedError("Unable to resolve the token signing key.") from exc


class StubTokenVerifier:
    """Test-only verifier that accepts a fixed set of tokens.

    Deliberately explicit: tests must declare the token they use, so no test
    can accidentally pass by relying on a real credential.
    """

    def __init__(self, tokens: dict[str, Principal]) -> None:
        self._tokens = tokens

    def verify(self, token: str) -> Principal:
        try:
            return self._tokens[token]
        except KeyError as exc:
            raise UnauthenticatedError("Unknown test token.") from exc


@lru_cache
def get_token_verifier() -> SupabaseTokenVerifier:
    return SupabaseTokenVerifier(get_settings())
