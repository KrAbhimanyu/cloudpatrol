"""Authentication: verification of Supabase-issued access tokens.

The API is a resource server. It verifies a bearer JWT and derives the caller
identity from it; it never trusts a user or organization identifier supplied
by the client. Authorization decisions are then made server-side against the
derived identity.

## Which algorithms are accepted

The set of accepted algorithms comes from trusted server configuration
(``SUPABASE_JWT_ALGORITHMS``), never from the token's own header. The ``alg``
header is attacker-controlled, so using it to choose a key type is what makes
an algorithm-confusion attack possible: an attacker signs with HMAC using a
value the server would otherwise treat as a public key.

Two rules follow from that and are enforced here:

* The algorithm the token claims must be one of the configured algorithms.
  A token claiming anything else is rejected before a key is even selected.
* Symmetric and asymmetric algorithms are never enabled together, and a
  symmetric secret is never a URL or a public key. The configuration layer
  refuses both, so a forged HMAC token cannot be verified against public key
  material.

Verification is pluggable so tests can inject a stub verifier without
weakening any production check.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient

from app.core.config import Settings, get_settings, is_strong_symmetric_secret
from app.core.errors import UnauthenticatedError

# Asymmetric algorithms are verified against the project's published keys;
# symmetric ones against the shared secret. The split is by configuration, not
# by the token header.
_SYMMETRIC_PREFIX = "HS"


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
    """Verifies Supabase JWTs using the algorithms the server is configured for.

    Every decision is derived from ``Settings``. Nothing in this class consults
    the token's ``alg`` header to decide *what* is acceptable; the header is
    only checked for membership in the configured allow-list.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jwks_client: PyJWKClient | None = None
        # Validate at construction so a bad configuration fails here rather
        # than on the first token, and so no request can reach an unverifiable
        # state. Fail closed: an unusable configuration raises rather than
        # falling back to something weaker.
        settings.validate_jwt_configuration()
        self._algorithms: tuple[str, ...] = tuple(settings.supabase_jwt_algorithms)

    def _audience(self) -> str | None:
        # Supabase issues "authenticated" for signed-in users. Enforcing the
        # audience prevents accepting a token minted for another purpose.
        return "authenticated"

    def _issuer(self) -> str | None:
        # A Supabase project issues tokens with `iss` set to "<url>/auth/v1".
        # Checking it means a token from a different project — even one signed
        # with the same key material — is refused. Only enforced when the URL
        # is configured, so a project that relies solely on a shared secret
        # still verifies.
        url = self._settings.supabase_url
        if not url:
            return None
        return f"{url.rstrip('/')}/auth/v1"

    def _resolve_key(self, token: str, algorithm: str) -> Any:
        """Select the verification key for a configured algorithm.

        The branch is on the *configured* algorithm, which is trusted, rather
        than on the token's header. A symmetric algorithm uses the shared
        secret; anything else resolves the project's public signing key.
        """
        if algorithm.startswith(_SYMMETRIC_PREFIX):
            secret = self._settings.supabase_jwt_secret
            if not secret or not is_strong_symmetric_secret(secret):
                # Configuration validation should have caught this; refuse
                # rather than verify against a weak or public value.
                raise UnauthenticatedError("Token verification is not configured.")
            return secret
        return self._jwks_signing_key(token)

    def verify(self, token: str) -> Principal:
        if not token:
            raise UnauthenticatedError("No bearer token supplied.")

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise UnauthenticatedError("Malformed bearer token.") from exc

        # The header is read only to *reject* a token that claims an algorithm
        # this server does not accept. It never widens what is accepted, and it
        # never selects a key type.
        claimed = header.get("alg")
        if not isinstance(claimed, str) or claimed not in self._algorithms:
            # Covers "none" and any algorithm outside the allow-list.
            raise UnauthenticatedError("Unsupported token signing algorithm.")

        # The key is chosen from the configured algorithm, and the same
        # algorithm is what the signature is checked against, so the two cannot
        # disagree.
        key = self._resolve_key(token, claimed)

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[claimed],
                audience=self._audience(),
                issuer=self._issuer(),
                options={"require": ["exp", "sub", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise UnauthenticatedError("The session has expired.") from exc
        except jwt.InvalidIssuerError as exc:
            raise UnauthenticatedError("The bearer token was issued by another project.") from exc
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
