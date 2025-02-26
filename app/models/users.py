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
    email: str | None = Field(index=True, nullable=True, unique=True, default=None)
    full_name: str | None = None
    tg_id: int | None = Field(index=True, nullable=True, unique=True, default=None)


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
    tg_id: int | None = None

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
    email: EmailStr | None
    full_name: str | None
    tg_id: int | None = None

    class Config:
        json_encoders = {UUID: lambda v: str(v)}


class UserUpdate(SQLModel):
    full_name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    tg_id: int | None = None


class TelegramUser(SQLModel):
    """
    This object represents a Telegram user or bot.

    Source: https://core.telegram.org/bots/api#user
    """

    id: int
    """Unique identifier for this user or bot. This number may have more than 32 significant bits and some programming languages may have difficulty/silent defects in interpreting it. But it has at most 52 significant bits, so a 64-bit integer or double-precision float type are safe for storing this identifier."""
    is_bot: bool
    """:code:`True`, if this user is a bot"""
    first_name: str
    """User's or bot's first name"""
    last_name: str | None = None
    """*Optional*. User's or bot's last name"""
    username: str | None = None
    """*Optional*. User's or bot's username"""
    language_code: str | None = None
    """*Optional*. `IETF language tag <https://en.wikipedia.org/wiki/IETF_language_tag>`_ of the user's language"""
    is_premium: bool | None = None
    """*Optional*. :code:`True`, if this user is a Telegram Premium user"""
    added_to_attachment_menu: bool | None = None
    """*Optional*. :code:`True`, if this user added the bot to the attachment menu"""
    can_join_groups: bool | None = None
    """*Optional*. :code:`True`, if the bot can be invited to groups. Returned only in :class:`aiogram.methods.get_me.GetMe`."""
    can_read_all_group_messages: bool | None = None
    """*Optional*. :code:`True`, if `privacy mode <https://core.telegram.org/bots/features#privacy-mode>`_ is disabled for the bot. Returned only in :class:`aiogram.methods.get_me.GetMe`."""
    supports_inline_queries: bool | None = None
    """*Optional*. :code:`True`, if the bot supports inline queries. Returned only in :class:`aiogram.methods.get_me.GetMe`."""
    can_connect_to_business: bool | None = None
    """*Optional*. :code:`True`, if the bot can be connected to a Telegram Business account to receive its messages. Returned only in :class:`aiogram.methods.get_me.GetMe`."""
    has_main_web_app: bool | None = None
    """*Optional*. :code:`True`, if the bot has a main Web App. Returned only in :class:`aiogram.methods.get_me.GetMe`."""
