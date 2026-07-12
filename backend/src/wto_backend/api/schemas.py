from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - protocol token type, not a credential
    expires_in: int
    must_change_password: bool


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    email: str | None = Field(default=None, max_length=254)
    password: str = Field(min_length=12, max_length=1024)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()


class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_active: bool


class UserView(BaseModel):
    id: UUID
    username: str
    email: str | None
    is_active: bool
    must_change_password: bool
    auth_version: int
    roles: list[str]
    created_at: datetime
    updated_at: datetime


class UserList(BaseModel):
    items: list[UserView]


class PermissionView(BaseModel):
    id: UUID
    key: str
    description: str


class RoleView(BaseModel):
    id: UUID
    key: str
    display_name: str
    description: str
    permissions: list[str]


class AuditView(BaseModel):
    id: UUID
    actor_type: str
    actor_id: UUID | None
    actor_agent_id: UUID | None
    action: str
    resource_type: str
    resource_id: UUID | None
    outcome: str
    occurred_at: datetime
    correlation_id: str
    metadata: dict[str, object]


class AuditPage(BaseModel):
    items: list[AuditView]
    next_cursor: UUID | None
