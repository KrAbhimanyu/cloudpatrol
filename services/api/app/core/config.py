"""Application configuration and startup validation.

All configuration is read from the environment. There are deliberately no
hard-coded secrets or credential defaults. When ``APP_ENV`` is not
``local``/``test`` the application refuses to start if required values are
missing, so a misconfigured deployment fails loudly instead of silently
running with insecure defaults.

The signing configuration is validated in every environment rather than only
in production: which JWT algorithms are accepted is a security decision, and a
mistake there must not be able to reach a running service.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

Environment = Literal["local", "test", "staging", "production"]

# Environments where placeholder secrets are tolerated.
_NON_PRODUCTION: frozenset[str] = frozenset({"local", "test"})

# Signing algorithms this service knows how to verify. "none" is deliberately
# absent: it is never a valid signature.
_SUPPORTED_JWT_ALGORITHMS: frozenset[str] = frozenset(
    {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)

# Minimum length for a symmetric (HMAC) secret. Below this a secret is
# brute-forceable offline, and short values are typically placeholders or
# configuration mistakes rather than real keys.
_MIN_SYMMETRIC_SECRET_LENGTH = 32


def is_strong_symmetric_secret(value: str) -> bool:
    """Whether a value is usable as an HMAC key.

    A URL or JWKS endpoint is rejected outright: it is public, so using it as a
    shared secret would let anyone forge a token. This is the specific mistake
    that turns a symmetric branch into an authentication bypass.
    """
    candidate = value.strip()
    if len(candidate) < _MIN_SYMMETRIC_SECRET_LENGTH:
        return False
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return False
    if "jwks" in lowered or "well-known" in lowered:
        return False
    return True


def _split_list_value(value: object) -> object:
    """Parse a list setting from either a CSV string or a JSON array.

    ``pydantic-settings`` JSON-decodes list-typed fields before validators run,
    which makes a plain ``a,b`` value in the environment or a ``.env`` file a
    hard error. Fields below opt out with ``NoDecode`` and are parsed here so
    that both the documented CSV form and a JSON array are accepted.
    """
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            # Fall through to CSV parsing so the error names the field rather
            # than surfacing as a raw JSON traceback.
            decoded = None
        if isinstance(decoded, list):
            return decoded
    return [item.strip() for item in text.split(",") if item.strip()]


class Settings(BaseSettings):
    """Runtime settings for the CloudPatrol API."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Runtime ---------------------------------------------------------
    app_env: Environment = "local"
    app_name: str = "CloudPatrol API"
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"

    # --- Supabase --------------------------------------------------------
    # The service-role key is server-only. It must never be exposed to the
    # browser; the frontend receives only the anon key.
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    supabase_service_role_key: str | None = None

    # Shared secret for HS256 verification. This is a *symmetric* key: it must
    # be a high-entropy secret, never a URL and never a public key. Supabase
    # projects using asymmetric signing keys do not have one, and the value is
    # then absent. Whether a value is required is decided by
    # ``supabase_jwt_algorithms`` rather than assumed.
    supabase_jwt_secret: str | None = None

    # The signing algorithms this deployment accepts, from trusted
    # configuration. This is an allow-list, never derived from a token header:
    # the token's ``alg`` is attacker-controlled, so it must not be able to
    # select the key type used to verify it. A symmetric HMAC algorithm
    # (``HS256``) and an asymmetric one (``RS256``/``ES256``) cannot be enabled
    # together, because accepting both is what enables an algorithm-confusion
    # attack: an attacker signs with HMAC using a value the server treats as a
    # public key.
    #
    # The default matches the documented configuration (asymmetric Supabase
    # signing keys verified against JWKS). A project on the legacy shared
    # secret sets ``SUPABASE_JWT_ALGORITHMS=HS256`` and supplies
    # ``SUPABASE_JWT_SECRET``.
    supabase_jwt_algorithms: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["RS256", "ES256"]
    )

    # Optional PostgreSQL connection string. The application still runs on the
    # in-memory store by default; PostgreSQL is an explicit opt-in (see
    # ``build_postgres_container``) and nothing here selects it. It defaults to
    # None so an absent value is valid in every environment, including
    # production, and cannot make startup fail.
    #
    # It is deliberately *not* part of ``missing_required_for_runtime``: a
    # deployment that has not been migrated to PostgreSQL must keep booting.
    #
    # Held as ``SecretStr`` because a DSN embeds a password. A plain ``str``
    # would appear in full in a traceback, a log line or an accidental
    # ``repr(settings)``; ``SecretStr`` renders as ``**********`` in all of them
    # and requires an explicit ``.get_secret_value()`` to read.
    database_url: SecretStr | None = None

    # --- AWS -------------------------------------------------------------
    # CloudPatrol never stores customer access keys. It assumes a
    # customer-side role with an external ID and uses temporary credentials.
    aws_default_region: str = "us-east-1"
    aws_allowed_regions: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "us-east-1",
            "us-west-2",
            "eu-west-1",
            "ap-south-1",
            "ap-southeast-1",
        ]
    )
    aws_connect_timeout_seconds: float = 5.0
    aws_read_timeout_seconds: float = 30.0
    aws_max_retry_attempts: int = 4
    # Billing (Cost Explorer) is a separate permission from inventory. When
    # false the scan skips cost collection entirely; when true a denial is
    # recorded as a partial failure and no cost figure is fabricated.
    aws_billing_enabled: bool = True
    # Days of billing history to request.
    aws_billing_lookback_days: int = Field(default=30, ge=1, le=365)

    # --- CORS ------------------------------------------------------------
    # Explicit origins only. A wildcard is rejected in production.
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000"]
    )

    # --- Scan workers ----------------------------------------------------
    # A scan takes far longer than a request should be held open, so it runs on
    # a background worker and the request returns as soon as the job is
    # accepted. The queue is bounded: unbounded work would let a burst of
    # requests consume all memory, so a full queue is refused with 503.
    scan_worker_count: int = Field(default=2, ge=1, le=32)
    scan_queue_max_size: int = Field(default=100, ge=1)
    # How long a worker waits for a job before checking whether it should stop.
    scan_worker_poll_timeout_seconds: float = 1.0
    # Grace period on shutdown for in-flight scans to finish.
    scan_shutdown_grace_seconds: float = 10.0

    # --- Stale scan reaping ----------------------------------------------
    # A worker that dies mid-scan would otherwise leave a `running` row that
    # blocks the account from ever being scanned again. The reaper fails such
    # scans so the account is released. It must comfortably exceed the longest
    # legitimate scan, or it will fail work that is still progressing.
    scan_stale_after_seconds: int = Field(default=1800, ge=60)
    scan_reaper_interval_seconds: float = Field(default=60.0, gt=0)
    scan_reaper_enabled: bool = True

    # --- Rate limiting ---------------------------------------------------
    # In-process token buckets. Bounds a caller who would otherwise issue
    # unlimited scan requests, each of which spends money on AWS API calls.
    # Not distributed: with N replicas the effective limit is N x the rate.
    rate_limit_enabled: bool = True
    rate_limit_max_keys: int = Field(default=10_000, ge=100)

    # --- Demo mode -------------------------------------------------------
    # When enabled the UI may show clearly labelled sample data. The API
    # never fabricates cost or savings figures.
    demo_mode_enabled: bool = True

    @field_validator("cors_allowed_origins", "aws_allowed_regions", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Allow comma-separated strings so env vars stay readable."""
        return _split_list_value(value)

    @field_validator("supabase_jwt_algorithms", mode="before")
    @classmethod
    def _normalise_algorithms(cls, value: object) -> object:
        """Accept a comma-separated string or a list, and upper-case the names."""
        value = _split_list_value(value)
        if isinstance(value, (list, tuple)):
            return [str(item).strip().upper() for item in value if str(item).strip()]
        return value

    @field_validator("database_url", mode="before")
    @classmethod
    def _blank_database_url_is_unset(cls, value: object) -> object:
        """Treat an empty value as absent.

        ``.env.example`` ships ``DATABASE_URL=`` so the variable is documented
        without a value. A blank string and an unset variable must mean the same
        thing, or "not configured" would depend on which form the operator used.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("supabase_url")
    @classmethod
    def _validate_supabase_url(cls, value: str | None) -> str | None:
        if value and not value.startswith(("http://", "https://")):
            raise ValueError("SUPABASE_URL must be an absolute http(s) URL")
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def uses_symmetric_jwt(self) -> bool:
        """Whether a symmetric (HMAC) algorithm is among those accepted."""
        return any(name.startswith("HS") for name in self.supabase_jwt_algorithms)

    def missing_required_for_runtime(self) -> list[str]:
        """Return names of settings required outside local/test.

        Used by startup validation to produce an actionable error message
        rather than a stack trace deep inside a request handler.
        """
        required = {
            "SUPABASE_URL": self.supabase_url,
            "SUPABASE_ANON_KEY": self.supabase_anon_key,
            "SUPABASE_SERVICE_ROLE_KEY": self.supabase_service_role_key,
        }
        # The shared secret is only required when a symmetric algorithm is
        # actually accepted. An asymmetric deployment has no shared secret, so
        # demanding one would force an operator to invent a value — and a
        # value invented to satisfy a check is exactly how a public string
        # ends up used as an HMAC key.
        if self.uses_symmetric_jwt:
            required["SUPABASE_JWT_SECRET"] = self.supabase_jwt_secret
        return [name for name, value in required.items() if not value]

    def validate_startup(self) -> None:
        """Fail fast on unsafe production configuration."""
        if not self.is_production:
            return

        missing = self.missing_required_for_runtime()
        if missing:
            raise RuntimeError(
                "Refusing to start in production with missing configuration: "
                + ", ".join(sorted(missing))
            )
        if "*" in self.cors_allowed_origins:
            raise RuntimeError("CORS_ALLOWED_ORIGINS must not contain '*' in production")

        self.validate_jwt_configuration()

    def validate_jwt_configuration(self) -> None:
        """Reject a signing configuration that would be unsafe to verify with.

        Two tiers:

        * **Consistency** is checked in every environment. An allow-list that
          is empty, names an unknown algorithm, includes ``none``, or mixes
          symmetric and asymmetric algorithms is a security defect wherever it
          appears, and must never reach a running service.
        * **Presence** of the key material is required only in production. In
          local/test a developer may run without a Supabase project; the
          verifier then fails closed per request rather than the process
          refusing to boot.
        """
        algorithms = list(self.supabase_jwt_algorithms)

        if not algorithms:
            raise RuntimeError("SUPABASE_JWT_ALGORITHMS must name at least one signing algorithm.")

        unknown = sorted(set(algorithms) - _SUPPORTED_JWT_ALGORITHMS)
        if any(name.lower() == "none" for name in algorithms):
            # Checked before the unknown-algorithm branch so the message names
            # the specific problem rather than reporting 'NONE' as unsupported.
            raise RuntimeError("SUPABASE_JWT_ALGORITHMS must not include 'none'.")

        if unknown:
            raise RuntimeError(
                "SUPABASE_JWT_ALGORITHMS contains unsupported algorithms: " + ", ".join(unknown)
            )

        symmetric = [name for name in algorithms if name.startswith("HS")]
        asymmetric = [name for name in algorithms if not name.startswith("HS")]
        if symmetric and asymmetric:
            # This is the algorithm-confusion precondition: a token could
            # present an HMAC algorithm and have the asymmetric public key
            # treated as the HMAC secret. Refuse the combination outright.
            raise RuntimeError(
                "SUPABASE_JWT_ALGORITHMS must not mix symmetric and asymmetric "
                "algorithms; that combination enables algorithm confusion."
            )

        if symmetric:
            # In symmetric mode the secret *is* the trust anchor, so it is
            # checked in every environment: a URL or a public key here is the
            # exact value that turns this branch into an authentication bypass.
            if self.supabase_jwt_secret:
                if not is_strong_symmetric_secret(self.supabase_jwt_secret):
                    raise RuntimeError(
                        "SUPABASE_JWT_SECRET must be a high-entropy secret of at least 32 "
                        "characters. It must not be a URL, a public key, or a JWKS endpoint."
                    )
            elif self.is_production:
                raise RuntimeError(
                    "SUPABASE_JWT_SECRET is required in production when a symmetric "
                    "algorithm is enabled."
                )
        elif self.is_production and not self.supabase_url:
            # Asymmetric verification needs the project URL to resolve JWKS.
            raise RuntimeError(
                "SUPABASE_URL is required in production to verify asymmetric tokens "
                "against the project's JWKS."
            )


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor."""
    return Settings()
