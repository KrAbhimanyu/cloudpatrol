"""Rate limiting middleware.

The limit class is derived from the request, then the bucket is keyed on the
authenticated principal when one can be resolved. Resolving the principal here
means verifying the bearer token a second time, which is cheap (a local HMAC or
a cached JWKS lookup) and is the only way to key the *authenticated* identity
rather than the IP.

If the token cannot be verified the request is keyed on IP. It is not rejected
here: authentication is the route dependency's job, and rejecting in the
middleware would turn every 401 into a rate-limit response and make the auth
failure impossible to debug. The bucket still bounds the flood.
"""

from __future__ import annotations

import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from app.core.rate_limit import TokenBucketRateLimiter, rate_limit_key
from app.core.security import get_token_verifier

logger = logging.getLogger(__name__)

# Paths that must never be rate limited: a probe or an auth check that gets
# throttled turns a healthy service into a failing one.
_EXEMPT_PATHS = frozenset({"/health", "/healthz", "/api/health"})


def classify_request(method: str, path: str) -> str:
    """Assign a request to a rate-limit class.

    Scan creation is separated from other writes because it is the only route
    that causes outbound AWS spend.
    """
    if method.upper() == "GET":
        return "read"
    if path.rstrip("/").endswith("/scans") and method.upper() == "POST":
        return "scan"
    return "write"


def _client_ip(request: Request) -> str | None:
    """Best-effort client IP.

    ``X-Forwarded-For`` is honoured only for its first entry and only as a
    hint; behind a proxy that does not strip the header a client could spoof it,
    so the limiter treats it as one signal rather than a trusted identity.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Applies the configured limiter to every non-exempt request."""

    def __init__(self, app, limiter: TokenBucketRateLimiter) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._limiter = limiter

    def _resolve_principal_id(self, request: Request, token: str) -> str | None:
        """Resolve the caller id, preferring a verifier on ``app.state``.

        Tests install a stub verifier on the app; production uses the real one.
        Reading it from app state is what lets the limiter key on the
        authenticated identity in both cases without importing a test double.
        """
        verifier = getattr(request.app.state, "token_verifier", None) or get_token_verifier()
        try:
            return verifier.verify(token).user_id
        except Exception:  # noqa: BLE001 - unverifiable token is keyed by IP
            return None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if path in _EXEMPT_PATHS:
            return await call_next(request)

        principal_id: str | None = None
        authorization = request.headers.get("Authorization")
        if authorization:
            _, _, token = authorization.partition(" ")
            if token.strip():
                principal_id = self._resolve_principal_id(request, token.strip())

        key = rate_limit_key(principal_id=principal_id, client_ip=_client_ip(request))
        limit_class = classify_request(request.method, path)

        try:
            self._limiter.check(limit_class=limit_class, key=key)
        except Exception as exc:  # noqa: BLE001 - translated to the error envelope below
            from app.core.errors import AppError

            if isinstance(exc, AppError):
                headers: dict[str, str] = {}
                retry_after = exc.details.get("retry_after_seconds")
                if isinstance(retry_after, int):
                    headers["Retry-After"] = str(retry_after)
                return JSONResponse(
                    status_code=exc.status_code,
                    content=exc.to_payload(request.headers.get("X-Request-Id")),
                    headers=headers,
                )
            raise

        return await call_next(request)
