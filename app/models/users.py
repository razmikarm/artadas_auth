from typing import TYPE_CHECKING

from uuid import UUID, uuid4
from pydantic import EmailStr
from datetime import datetime, UTC
from sqlmodel import SQLModel, Field, Relationship, func


# Import only for type checking
# Avoids forward references
if TYPE_CHECKING:
    from models.auth import RefreshToken


class UserBase(SQLModel):
    username: str = Field(index=True, nullable=False, unique=True)
    email: str = Field(index=True, nullable=False, unique=True)
    full_name: str | None = None


class User(UserBase, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True, index=True, nullable=False)
    hashed_password: str = Field(nullable=False)
    is_active: bool = Field(default=False)
    is_admin: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        nullable=False,
        sa_column_kwargs={"server_default": func.current_timestamp()},
    )
    last_updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC).replace(tzinfo=None),
        nullable=False,
        sa_column_kwargs={"server_default": func.current_timestamp()},
    )

    refresh_tokens: list["RefreshToken"] = Relationship(
        back_populates="user", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class UserCreate(SQLModel):
    username: str
    email: EmailStr
    password: str
    full_name: str | None = None


class UserRead(SQLModel):
    id: UUID
    username: str
    email: EmailStr
    full_name: str | None


class UserUpdate(SQLModel):
    full_name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
