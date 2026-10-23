"""Request IDs and structured JSON logging.

Logs are emitted as single-line JSON so they can be shipped to any collector
without a parser. A small redaction pass removes anything that looks like a
credential before a record is written — defence in depth, because the primary
rule is that secrets are never passed to the logger in the first place.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)

# Keys whose values must never be written to logs.
_REDACT_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "secretaccesskey",
        "secret_access_key",
        "sessiontoken",
        "session_token",
        "accesskeyid",
        "access_key_id",
        "service_role_key",
        "service_role",
        "anon_key",
        "jwt",
        "jwt_secret",
        "password",
        "token",
        "external_id",
        "api_key",
        "apikey",
    }
)

_REDACTED = "[REDACTED]"

# Catch bare bearer tokens and AWS-style key IDs inside free text.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
)


def new_request_id() -> str:
    """Generate a request identifier."""
    return uuid.uuid4().hex


def set_request_id(value: str | None) -> None:
    _request_id.set(value)


def get_request_id() -> str | None:
    return _request_id.get()


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        for pattern in _PATTERNS:
            value = pattern.sub(_REDACTED, value)
        return value
    if isinstance(value, dict):
        return {
            k: (_REDACTED if str(k).lower() in _REDACT_KEYS else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    """Render log records as compact JSON with redaction applied."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_value(record.getMessage()),
        }

        request_id = get_request_id()
        if request_id:
            payload["request_id"] = request_id

        for key in ("method", "path", "status_code", "duration_ms", "org_id", "user_id"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Install the JSON formatter on the root logger."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # uvicorn's access log duplicates our middleware log line.
    logging.getLogger("uvicorn.access").disabled = True
