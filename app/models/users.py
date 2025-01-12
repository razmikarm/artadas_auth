import re
from typing import TYPE_CHECKING

from uuid import UUID, uuid4
from pydantic import EmailStr, field_validator
from datetime import datetime, UTC
from sqlmodel import SQLModel, Field, Relationship, func
from fastapi import HTTPException, status

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
    updated_at: datetime = Field(
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

    @field_validator("username")
    def validate_username(cls, username: str) -> str:
        if not username.isalnum():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username must be alphanumeric")
        if not username[0].isalpha():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username must start with a letter")
        return username

    @field_validator("password")
    def validate_password(cls, passwd: str) -> str:
        if len(passwd) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters long"
            )
        if not re.search(r"[a-z]", passwd):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one lowercase letter"
            )
        if not re.search(r"[A-Z]", passwd):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one uppercase letter"
            )
        if not re.search(r"\d", passwd):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one number"
            )
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>~]", passwd):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one special character"
            )
        return passwd


class UserRead(SQLModel):
    id: UUID
    username: str
    email: EmailStr
    full_name: str | None


class UserUpdate(SQLModel):
    full_name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
