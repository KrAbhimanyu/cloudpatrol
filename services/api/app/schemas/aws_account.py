"""Pydantic schemas for AWS account connection and validation."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# 12-digit AWS account ID.
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
# arn:aws:iam::<account>:role/<name>
_ROLE_ARN_RE = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)$")
# AWS region names are lowercase letters, digits and hyphens.
_REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
# External IDs must match the pattern AWS accepts for AssumeRole.
_EXTERNAL_ID_RE = re.compile(r"^[\w+=,.@:\/-]{2,1224}$")

ConnectionStatus = Literal["pending", "validated", "failed", "disabled"]


class AwsAccountCreate(BaseModel):
    """Request body for registering an AWS account."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=100)
    account_id: str = Field(description="12-digit AWS account ID")
    role_arn: str = Field(description="ARN of the read-only role to assume")
    external_id: str = Field(description="External ID configured in the trust policy")
    regions: list[str] = Field(min_length=1, max_length=20)

    @field_validator("account_id")
    @classmethod
    def _check_account_id(cls, value: str) -> str:
        value = value.strip()
        if not _ACCOUNT_ID_RE.match(value):
            raise ValueError("account_id must be exactly 12 digits")
        return value

    @field_validator("role_arn")
    @classmethod
    def _check_role_arn(cls, value: str) -> str:
        value = value.strip()
        match = _ROLE_ARN_RE.match(value)
        if not match:
            raise ValueError("role_arn must look like arn:aws:iam::<12-digit-account>:role/<name>")
        return value

    @field_validator("external_id")
    @classmethod
    def _check_external_id(cls, value: str) -> str:
        value = value.strip()
        if not _EXTERNAL_ID_RE.match(value):
            raise ValueError(
                "external_id must be 2-1224 characters of letters, digits, or +=,.@:/-_"
            )
        return value

    @field_validator("regions")
    @classmethod
    def _check_regions(cls, value: list[str]) -> list[str]:
        seen: list[str] = []
        for region in value:
            region = region.strip()
            if not _REGION_RE.match(region):
                raise ValueError(f"'{region}' is not a valid AWS region name")
            if region not in seen:
                seen.append(region)
        if not seen:
            raise ValueError("at least one region is required")
        return seen

    @field_validator("label")
    @classmethod
    def _check_label(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("label must not be blank")
        return value

    def role_arn_account_id(self) -> str:
        """The account ID embedded in the role ARN, for cross-checking."""
        match = _ROLE_ARN_RE.match(self.role_arn)
        assert match is not None  # guaranteed by the validator
        return match.group(2)


class AwsAccountRead(BaseModel):
    """AWS account connection metadata returned to the client.

    Note the absence of any credential field. Only non-secret connection
    metadata is ever returned.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    label: str
    account_id: str
    role_arn: str
    regions: list[str]
    status: ConnectionStatus
    status_message: str | None = None
    last_validated_at: datetime | None = None
    created_at: datetime


class AwsConnectionValidation(BaseModel):
    """Result of validating an AWS connection."""

    model_config = ConfigDict(from_attributes=True)

    account_id: str
    status: ConnectionStatus
    message: str
    caller_identity_arn: str | None = None
    assumed_role_arn: str | None = None
    credentials_expire_at: datetime | None = None


class AwsAccountList(BaseModel):
    items: list[AwsAccountRead]
    total: int
