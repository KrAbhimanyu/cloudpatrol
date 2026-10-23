"""Application factory and middleware wiring.

Middleware order matters and is deliberate:

1. Request context — assigns the request ID first, so every later log line and
   error response can carry it.
2. Error handling — converts typed application errors and unexpected
   exceptions into the standard envelope, and never leaks internals.
3. CORS — restricted to explicitly configured origins.

CORS is not configured with a wildcard. Combined with bearer tokens that would
allow any origin to drive the API on a signed-in user's behalf.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.health import router as health_router
from app.api.v1.aws_accounts import router as aws_accounts_router
from app.api.v1.costs import router as costs_router
from app.api.v1.findings import router as findings_router
from app.api.v1.organizations import router as organizations_router
from app.api.v1.savings import router as savings_router
from app.api.v1.scans import router as scans_router
from app.aws.boto3_adapter import build_adapter
from app.core.config import Settings, get_settings
from app.core.errors import AppError, ErrorCode
from app.core.logging import configure_logging, get_request_id, new_request_id, set_request_id
from app.core.rate_limit import TokenBucketRateLimiter, build_default_rules
from app.core.rate_limit_middleware import RateLimitMiddleware
from app.repositories.memory import build_container
from app.services.aws_connection import AwsConnectionService
from app.services.billing import BillingService
from app.services.detectors import build_detectors
from app.services.savings_ledger import SavingsLedgerService
from app.services.scan_runner import ScanExecutor, ScanWorkerPool, StaleScanReaper
from app.services.scan_service import ScanService
from app.services.secrets import InMemorySecretVault

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application."""
    resolved = settings or get_settings()
    configure_logging(resolved.log_level)

    # Fail fast on unsafe production configuration.
    resolved.validate_startup()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = build_container()
        adapter = build_adapter(resolved)
        # Settings are attached to the app so handlers use the configuration
        # the app was built with, rather than re-reading the environment.
        app.state.settings = resolved
        app.state.container = container
        app.state.aws_adapter = adapter
        connection_service = AwsConnectionService(adapter)
        app.state.aws_connection_service = connection_service
        app.state.secret_vault = InMemorySecretVault()
        savings_ledger_service = SavingsLedgerService(
            savings=container.savings,
            findings=container.findings,
            audit=container.audit,
        )
        app.state.savings_ledger_service = savings_ledger_service
        scan_service = ScanService(
            adapter=adapter,
            scans=container.scans,
            resources=container.resources,
            findings=container.findings,
            audit=container.audit,
            detectors=build_detectors(),
            savings_ledger=savings_ledger_service,
            costs=container.costs,
            billing=(BillingService(adapter) if resolved.aws_billing_enabled else None),
        )
        app.state.scan_service = scan_service

        executor = ScanExecutor(
            connection=connection_service,
            vault=app.state.secret_vault,
            accounts=container.aws_accounts,
            scans=container.scans,
            scan_service=scan_service,
        )
        pool = ScanWorkerPool(
            executor=executor,
            worker_count=resolved.scan_worker_count,
            max_queue_size=resolved.scan_queue_max_size,
            poll_timeout_seconds=resolved.scan_worker_poll_timeout_seconds,
            shutdown_grace_seconds=resolved.scan_shutdown_grace_seconds,
        )
        app.state.scan_pool = pool
        pool.start()

        reaper = StaleScanReaper(
            scans=container.scans,
            executor=executor,
            stale_after_seconds=resolved.scan_stale_after_seconds,
            interval_seconds=resolved.scan_reaper_interval_seconds,
        )
        app.state.scan_reaper = reaper
        if resolved.scan_reaper_enabled:
            reaper.start()

        logger.info("CloudPatrol API started", extra={"environment": resolved.app_env})
        try:
            yield
        finally:
            # Stop accepting new work, then let in-flight scans finish writing
            # their outcome. Order matters: the reaper is stopped first so it
            # cannot fail a scan that is still running.
            if resolved.scan_reaper_enabled:
                reaper.stop()
            pool.stop()
            logger.info("CloudPatrol API stopped")

    app = FastAPI(
        title=resolved.app_name,
        version="0.1.0",
        description=(
            "CloudPatrol API — read-only AWS cloud cost intelligence. "
            "This phase performs read-only discovery and produces estimated, "
            "evidence-backed opportunities. It never modifies AWS resources."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-Id") or new_request_id()
        set_request_id(request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    # The path only — never the query string, which could carry
                    # sensitive values.
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                },
            )
        response.headers["X-Request-Id"] = request_id
        return response

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_payload(get_request_id()),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Field locations are useful to the client; submitted values are not
        # echoed back, because they may contain a role ARN or an external ID.
        fields = [
            {"loc": [str(part) for part in err.get("loc", [])], "msg": err.get("msg", "")}
            for err in exc.errors()
        ]
        payload = AppError(
            "The request payload is invalid.",
            details={"fields": fields},
        )
        payload.code = ErrorCode.VALIDATION_ERROR
        payload.status_code = 422
        return JSONResponse(status_code=422, content=payload.to_payload(get_request_id()))

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # The exception is logged with its traceback; the client receives only
        # a correlation ID, so no internal detail escapes.
        logger.exception("Unhandled exception")
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": str(ErrorCode.INTERNAL_ERROR),
                    "message": "An unexpected error occurred.",
                    "details": {},
                    "request_id": get_request_id(),
                }
            },
        )

    # Rate limiting is added before CORS so the limit applies even to a
    # preflight-adjacent burst. Starlette runs the last-added middleware
    # outermost, so CORS ends up outside the limiter; the limiter still sees
    # every real request.
    if resolved.rate_limit_enabled:
        app.add_middleware(
            RateLimitMiddleware,
            limiter=TokenBucketRateLimiter(
                build_default_rules(), max_keys=resolved.rate_limit_max_keys
            ),
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Organization-Id", "X-Request-Id"],
        expose_headers=["X-Request-Id"],
    )

    app.include_router(health_router)
    app.include_router(organizations_router, prefix=resolved.api_v1_prefix)
    app.include_router(aws_accounts_router, prefix=resolved.api_v1_prefix)
    app.include_router(scans_router, prefix=resolved.api_v1_prefix)
    app.include_router(findings_router, prefix=resolved.api_v1_prefix)
    app.include_router(savings_router, prefix=resolved.api_v1_prefix)
    app.include_router(costs_router, prefix=resolved.api_v1_prefix)

    return app
