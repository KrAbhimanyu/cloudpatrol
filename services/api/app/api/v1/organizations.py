"""Organization routes: create a workspace, list the caller's workspaces.

These are the only routes that do not require an ``X-Organization-Id`` header,
because they are how a caller discovers which organizations they belong to.
"""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.dependencies import CurrentPrincipal
from app.core.errors import ConflictError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", tags=["organizations"])

_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$")


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    slug: str = Field(min_length=3, max_length=40)

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, value: str) -> str:
        value = value.strip().lower()
        if not _SLUG_RE.match(value):
            raise ValueError(
                "slug must be 3-40 characters of lowercase letters, digits or hyphens, "
                "and must start and end with a letter or digit"
            )
        return value


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    role: str


class OrganizationList(BaseModel):
    items: list[OrganizationRead]
    total: int


@router.get("", response_model=OrganizationList, summary="List the caller's workspaces")
async def list_organizations(principal: CurrentPrincipal, request: Request) -> OrganizationList:
    repository = request.app.state.container.organizations
    items: list[OrganizationRead] = []
    for membership in repository.list_memberships(principal.user_id):
        organization = repository.get_organization(membership.organization_id)
        if organization is None:
            continue
        items.append(
            OrganizationRead(
                id=organization.id,
                name=organization.name,
                slug=organization.slug,
                role=membership.role,
            )
        )
    return OrganizationList(items=items, total=len(items))


@router.post(
    "",
    response_model=OrganizationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a workspace",
)
async def create_organization(
    payload: OrganizationCreate,
    principal: CurrentPrincipal,
    request: Request,
) -> OrganizationRead:
    repository = request.app.state.container.organizations

    for membership in repository.list_memberships(principal.user_id):
        existing = repository.get_organization(membership.organization_id)
        if existing is not None and existing.slug == payload.slug:
            raise ConflictError("You already have a workspace with this slug.")

    organization = repository.create_organization(
        name=payload.name,
        slug=payload.slug,
        owner_user_id=principal.user_id,
    )
    return OrganizationRead(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        role="owner",
    )
