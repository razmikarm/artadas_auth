from fastapi import APIRouter, status

from app.db.database import DBSession
from app.models.users import UserRead, TelegramUser
from app.models.auth import TokenResponse, TokenRequest, Login
from app.utils.users import get_or_create_tg_user
from app.utils.auth import authenticate_user, get_current_user, generate_tokens, get_db_refresh_token, HeaderAuthToken


router = APIRouter(prefix="/auth")


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def login(login_data: Login, session: DBSession) -> TokenResponse:
    user = authenticate_user(session, login_data.username, login_data.password)
    token_response = generate_tokens(user, session)
    return token_response


@router.post("/bot_login", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def bot_login(tg_user: TelegramUser, session: DBSession) -> TokenResponse:
    user = get_or_create_tg_user(tg_user, session)
    token_response = generate_tokens(user, session)
    return token_response


@router.post("/verify", response_model=UserRead, status_code=status.HTTP_200_OK)
def verify(access_token: TokenRequest, session: DBSession) -> UserRead:
    user = get_current_user(access_token.token, session, "access")
    return user


@router.post("/logout", response_model=dict, status_code=status.HTTP_201_CREATED)
def logout(refresh_token: HeaderAuthToken, session: DBSession) -> dict:
    db_refresh_token = get_db_refresh_token(refresh_token, session)
    db_refresh_token.is_revoked = True
    session.add(db_refresh_token)
    session.commit()
    return {"message": "Successfully logged out."}


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def refresh_token(refresh_token: HeaderAuthToken, session: DBSession) -> TokenResponse:
    user = get_current_user(refresh_token, session, "refresh")
    db_refresh_token = get_db_refresh_token(refresh_token, session)
    db_refresh_token.is_revoked = True
    session.add(db_refresh_token)
    session.commit()
    token_response = generate_tokens(user, session)
    return token_response
