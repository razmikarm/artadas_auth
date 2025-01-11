import bcrypt
import hashlib
from uuid import UUID
from jose import jwt, JWTError, ExpiredSignatureError
from typing import Literal, Annotated
from sqlmodel import Session, select
from datetime import datetime, timedelta, UTC
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings
from app.models.users import User
from app.db.database import DBSession
from app.models.auth import RefreshToken, TokenResponse, TokenBase

SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_TIMEOUT = settings.access_token_timeout
REFRESH_TOKEN_TIMEOUT = settings.refresh_token_timeout
REFRESH_TOKEN_SECRET = settings.refresh_token_secret

oauth2_scheme = Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="auth/login"))]


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# Hash a password using bcrypt
def hash_password(password: str) -> str:
    pwd_bytes = password.encode()
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    return hashed_password.decode()


# Check if the provided password matches the stored password (hashed)
def verify_password(plain_password: str, hashed_password: str) -> str:
    password_byte_enc = plain_password.encode()
    hashed_password_enc = hashed_password.encode()
    return bcrypt.checkpw(password_byte_enc, hashed_password_enc)


def authenticate_user(session: Session, username: str, password: str) -> User | None:
    user = session.exec(select(User).where(User.username == username)).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return user


def create_token(data: dict, token_type: Literal["access", "refresh"]) -> TokenBase:
    timeout, secret = {
        "access": (ACCESS_TOKEN_TIMEOUT, SECRET_KEY),
        "refresh": (REFRESH_TOKEN_TIMEOUT, REFRESH_TOKEN_SECRET),
    }[token_type]
    to_encode = data.copy()
    expire = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=timeout)
    to_encode.update({"exp": expire})
    token = TokenBase(user_id=data["uid"], token=jwt.encode(to_encode, secret, algorithm=ALGORITHM), expires_at=expire)
    return token


def generate_tokens(user: User, session: Session) -> TokenResponse:
    token_data = {"uname": user.username, "uid": str(user.id)}
    refresh_token = create_token(token_data, token_type="refresh")
    db_refresh_token = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token.token),
        expires_at=refresh_token.expires_at,
        is_revoked=False,
    )
    session.add(db_refresh_token)
    session.commit()
    session.refresh(db_refresh_token)
    token_data.update({"special_id": str(db_refresh_token.id)})
    access_token = create_token(token_data, token_type="access")
    response = TokenResponse(
        access_token=access_token.token,
        refresh_token=refresh_token.token,
    )
    return response


def verify_token(token: oauth2_scheme, token_type: Literal["access", "refresh"] = "access") -> str:
    _, secret = {
        "access": (ACCESS_TOKEN_TIMEOUT, SECRET_KEY),
        "refresh": (REFRESH_TOKEN_TIMEOUT, REFRESH_TOKEN_SECRET),
    }[token_type]
    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        uid = payload.get("uid")
        refresh_id = payload.get("special_id")
        if uid is None or (token_type == "access" and refresh_id is None):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return uid, refresh_id

    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is expired")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def get_current_user(
    token: oauth2_scheme, session: DBSession, token_type: Literal["access", "refresh"] = "access"
) -> User:
    try:
        user_id, refresh_id = verify_token(token, token_type)
        if token_type == "access":
            _ = get_db_refresh_token_by_id(refresh_id, session)
        user = session.exec(select(User).where(User.id == user_id)).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication")


def get_db_refresh_token_by_id(token_id: UUID, session: Session) -> RefreshToken:
    db_refresh_token = session.exec(select(RefreshToken).where(RefreshToken.id == token_id)).one_or_none()
    if db_refresh_token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    if db_refresh_token.expires_at < datetime.now(UTC).replace(tzinfo=None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token is expired")
    if db_refresh_token.is_revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token is revoked")
    return db_refresh_token


def get_db_refresh_token(token: str, session: Session) -> RefreshToken:
    hashed_token = hash_refresh_token(token)
    db_refresh_token = session.exec(select(RefreshToken).where(RefreshToken.token_hash == hashed_token)).one_or_none()
    if db_refresh_token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    if db_refresh_token.expires_at < datetime.now(UTC).replace(tzinfo=None):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token is expired")
    if db_refresh_token.is_revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token is revoked")
    return db_refresh_token


def get_header_auth_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scheme")
    return authorization.split(" ", 1)[1]


HeaderAuthToken = Annotated[str, Depends(get_header_auth_token)]
CurrentUser = Annotated[User, Depends(get_current_user)]
