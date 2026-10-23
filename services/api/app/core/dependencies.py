"""FastAPI dependencies: authentication and tenant authorization.

Every tenant-scoped route depends on :func:`require_organization`, which
proves membership before the handler runs. This is the server-side
authorization boundary; the client cannot influence which organization it is
allowed to act on.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, Request

from app.core.errors import ForbiddenError, UnauthenticatedError
from app.core.security import Principal, TokenVerifier, get_token_verifier
from app.repositories.models import MembershipRecord
from app.repositories.protocols import OrganizationRepository


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise UnauthenticatedError("The Authorization header is missing.")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise UnauthenticatedError("The Authorization header must use the Bearer scheme.")
    return token.strip()


async def get_current_principal(
    authorization: Annotated[str | None, Header()] = None,
    verifier: Annotated[TokenVerifier, Depends(get_token_verifier)] = None,  # type: ignore[assignment]
) -> Principal:
    """Resolve the authenticated caller, or raise 401."""
    token = _extract_bearer_token(authorization)
    return verifier.verify(token)


async def require_organization(
    request: Request,
    principal: Annotated[Principal, Depends(get_current_principal)],
    organization_id: Annotated[str | None, Header(alias="X-Organization-Id")] = None,
) -> tuple[Principal, MembershipRecord]:
    """Authorize the caller against the organization named in the header.

    Returns the principal and the membership record so handlers can scope
    their data access without re-deriving tenancy.
    """
    if not organization_id:
        raise ForbiddenError("The X-Organization-Id header is required.")

    repository: OrganizationRepository = request.app.state.container.organizations
    membership = repository.get_membership(principal.user_id, organization_id)
    if membership is None:
        # A non-member is told the same thing as a wrong ID, so the endpoint
        # cannot be used to probe which organizations exist.
        raise ForbiddenError("You are not a member of this organization.")

    return principal, membership


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
OrganizationContext = Annotated[tuple[Principal, MembershipRecord], Depends(require_organization)]
