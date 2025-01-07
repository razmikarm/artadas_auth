from uuid import UUID
from typing import TYPE_CHECKING
from datetime import datetime, UTC
from sqlmodel import SQLModel, Field, func, Relationship


# Import only for type checking
# Avoids forward references
if TYPE_CHECKING:
    from models.users import User


class Login(SQLModel):
    username: str
    password: str


class TokenBase(SQLModel):
    user_id: str
    token: str
    expires_at: datetime


class TokenResponse(SQLModel):
    access_token: str
    refresh_token: str


class RefreshToken(SQLModel, table=True):
    user_id: UUID = Field(foreign_key="user.id")
    token_hash: str = Field(nullable=False, primary_key=True, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        nullable=False,
        sa_column_kwargs={"server_default": func.current_timestamp()},
    )
    expires_at: datetime = Field(nullable=False)
    is_revoked: bool = Field(default=False, nullable=False)

    user: "User" = Relationship(back_populates="refresh_tokens")


class TokenRequest(SQLModel):
    token: str
