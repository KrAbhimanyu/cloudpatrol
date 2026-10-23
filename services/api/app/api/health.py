"""Health and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness probe")
async def health(request: Request) -> dict[str, str]:
    """Report that the process is running.

    Deliberately does not touch the database or AWS: a liveness probe that
    depends on a downstream service will restart a healthy process whenever
    that service hiccups.
    """
    settings = request.app.state.settings
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.app_env,
    }


@router.get("/health/ready", summary="Readiness probe")
async def readiness(request: Request) -> dict[str, object]:
    """Report which dependencies are configured.

    Returns configuration *presence* only. No secret value, account ID or
    connection string is ever included.
    """
    settings = request.app.state.settings
    missing = settings.missing_required_for_runtime()
    return {
        "status": "ready" if not missing else "degraded",
        "checks": {
            "database_configured": bool(settings.supabase_url),
            "auth_configured": bool(settings.supabase_jwt_secret or settings.supabase_url),
            "aws_adapter": "boto3",
        },
        "missing_configuration": missing,
    }
