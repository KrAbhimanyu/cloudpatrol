"""Guard: the tracked ``.env.example`` must contain no real credentials.

``.env.example`` is committed, so anything in it is public. It is easy for a
developer to paste a working project URL and key into it while debugging and
forget to take them out, so this is checked mechanically rather than by review.

The check is deliberately narrow: it looks for *secret-shaped* values, not for
"any non-empty value". A placeholder such as ``replace-me-with-your-key`` is
safe and must not fail the suite, or the guard would be turned off the first
time it got in the way.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# tests/ -> services/api/ -> services/ -> repository root
ENV_EXAMPLE = Path(__file__).resolve().parents[3] / ".env.example"

# Values that are intentionally present in the template. Everything here is a
# placeholder, a documentation example, or a non-secret default.
_ALLOWED_PLACEHOLDERS = frozenset(
    {
        "",
        # Documented example refs and this project's placeholder.
        "https://your-project-ref.supabase.co",
        "https://abcdefgh.supabase.co",
        # Explicit placeholders.
        "replace-me-with-your-publishable-key",
        "replace-me-with-your-service-role-key",
        # Local development defaults (not secrets).
        "http://localhost:8000",
        "http://localhost:3000",
    }
)

# Shapes that indicate a real credential rather than a placeholder.
_SECRET_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Supabase's current API key formats.
    ("supabase secret key", re.compile(r"^sb_secret_")),
    ("supabase publishable key", re.compile(r"^sb_publishable_")),
    # A JWT, as issued for a signed-in session or a service role.
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_\-]{10,}")),
    # A live Supabase project URL. Project refs are 20 lowercase letters; the
    # documented examples are explicitly allowed above.
    ("supabase project url", re.compile(r"^https://[a-z0-9]{20}\.supabase\.co")),
    # AWS access key IDs.
    ("aws access key id", re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$")),
    # A private key block.
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def _parse_env(text: str) -> dict[str, str]:
    """Return key -> value for every ``KEY=value`` line, ignoring comments."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def test_env_example_exists_and_is_tracked() -> None:
    # A missing template would silently disable every check below.
    assert ENV_EXAMPLE.is_file(), f"Expected {ENV_EXAMPLE} to exist"


def test_env_example_contains_no_secret_shaped_values() -> None:
    values = _parse_env(ENV_EXAMPLE.read_text(encoding="utf-8"))
    offenders: list[str] = []

    for key, value in values.items():
        if value in _ALLOWED_PLACEHOLDERS:
            continue
        for label, pattern in _SECRET_SHAPES:
            if pattern.search(value):
                # The key is named; the value is not, so a failure report in CI
                # does not echo whatever was found.
                offenders.append(f"{key} looks like a real {label}")

    assert not offenders, ".env.example must contain placeholders only, but: " + "; ".join(
        offenders
    )


def test_env_example_documents_the_signing_configuration() -> None:
    """The JWT settings the verifier reads must be discoverable in the template."""
    values = _parse_env(ENV_EXAMPLE.read_text(encoding="utf-8"))
    assert "SUPABASE_JWT_ALGORITHMS" in values
    assert "SUPABASE_JWT_SECRET" in values


def test_guard_rejects_a_planted_secret() -> None:
    """The guard itself must fail on a real-looking value.

    Without this, a broken regex would make the whole file pass silently.
    """
    planted = "SUPABASE_SERVICE_ROLE_KEY=sb_secret_abcdefghijklmnopqrstuvwxyz012345\n"
    values = _parse_env(planted)
    value = values["SUPABASE_SERVICE_ROLE_KEY"]
    assert any(pattern.search(value) for _, pattern in _SECRET_SHAPES)


def test_guard_accepts_the_documented_placeholders() -> None:
    """And it must not fire on the safe placeholders actually in use."""
    for placeholder in _ALLOWED_PLACEHOLDERS:
        if not placeholder:
            continue
        assert not any(pattern.search(placeholder) for _, pattern in _SECRET_SHAPES), (
            f"placeholder {placeholder!r} must not be treated as a secret"
        )


def test_parse_env_ignores_comments_and_blank_lines() -> None:
    parsed = _parse_env("# a comment\n\nKEY=value\n  OTHER = spaced  \n")
    assert parsed == {"KEY": "value", "OTHER": "spaced"}


if __name__ == "__main__":  # pragma: no cover - manual invocation convenience
    pytest.main([__file__, "-q"])
