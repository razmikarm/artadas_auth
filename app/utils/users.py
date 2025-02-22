from sqlmodel import Session, select
from app.models.users import User, TelegramUser


def get_or_create_tg_user(tg_user: TelegramUser, session: Session) -> User:
    user = session.exec(select(User).where(User.tg_id == tg_user.id)).first()
    if user:
        return user
    # Need to create a user
    new_user = User(
        username=tg_user.username,
        hashed_password="",
        full_name=tg_user.first_name,
        tg_id=tg_user.id,
        is_active=True,
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user
