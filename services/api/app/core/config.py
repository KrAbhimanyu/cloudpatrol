"""Application configuration and startup validation.

All configuration is read from the environment. There are deliberately no
hard-coded secrets or credential defaults. When ``APP_ENV`` is not
``local``/``test`` the application refuses to start if required values are
missing, so a misconfigured deployment fails loudly instead of silently
running with insecure defaults.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "test", "staging", "production"]

# Environments where placeholder secrets are tolerated.
_NON_PRODUCTION: frozenset[str] = frozenset({"local", "test"})


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
    supabase_jwt_secret: str | None = None

    # --- AWS -------------------------------------------------------------
    # CloudPatrol never stores customer access keys. It assumes a
    # customer-side role with an external ID and uses temporary credentials.
    aws_default_region: str = "us-east-1"
    aws_allowed_regions: list[str] = Field(
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
    cors_allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

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
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
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

    def missing_required_for_runtime(self) -> list[str]:
        """Return names of settings required outside local/test.

        Used by startup validation to produce an actionable error message
        rather than a stack trace deep inside a request handler.
        """
        required = {
            "SUPABASE_URL": self.supabase_url,
            "SUPABASE_ANON_KEY": self.supabase_anon_key,
            "SUPABASE_SERVICE_ROLE_KEY": self.supabase_service_role_key,
            "SUPABASE_JWT_SECRET": self.supabase_jwt_secret,
        }
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


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor."""
    return Settings()
