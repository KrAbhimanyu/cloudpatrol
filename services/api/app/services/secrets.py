"""Secret storage for AWS external IDs.

An external ID is a shared secret: it is what stops anyone who guesses a role
ARN from assuming it. It therefore does not belong in a plaintext database
column alongside non-secret connection metadata.

This module defines a narrow vault interface. The in-memory implementation
below is for local development and tests only; it stores values in process
memory and never touches disk. A production deployment must supply an
implementation backed by a managed secret store (AWS Secrets Manager, or
KMS-encrypted at rest), and the account row keeps only an opaque reference.
"""

from __future__ import annotations

import threading
from typing import Protocol


class SecretVault(Protocol):
    """Stores and retrieves secrets by opaque reference."""

    def put(self, reference: str, value: str) -> None: ...
    def get(self, reference: str) -> str | None: ...
    def delete(self, reference: str) -> None: ...


class InMemorySecretVault:
    """Process-local vault for local development and tests.

    Explicitly not suitable for production: values are lost on restart and are
    held unencrypted in memory. It exists so the code path is identical to the
    managed-vault path, which means the wiring is exercised by tests.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._values: dict[str, str] = {}

    def put(self, reference: str, value: str) -> None:
        with self._lock:
            self._values[reference] = value

    def get(self, reference: str) -> str | None:
        with self._lock:
            return self._values.get(reference)

    def delete(self, reference: str) -> None:
        with self._lock:
            self._values.pop(reference, None)
