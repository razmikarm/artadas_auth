from uuid import UUID
from sqlmodel import select
from fastapi import APIRouter, HTTPException, status

from app.db.database import DBSession
from app.utils.auth import hash_password, CurrentUser
from app.models.users import User, UserCreate, UserRead
from app.models.courses import CourseReadList
from app.models.topics import TopicReadList

router = APIRouter(prefix="/users")


@router.get("/", response_model=list[UserRead])
def read_users(session: DBSession) -> list[UserRead]:
    statement = select(User)
    users = session.exec(statement).all()
    return users


@router.get("/me", response_model=UserRead)
def read_current_user(user: CurrentUser, session: DBSession) -> UserRead:
    return user


@router.post("/", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, session: DBSession) -> UserRead:
    hashed_pwd = hash_password(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pwd,
        full_name=user.full_name,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@router.get("/{user_id}", response_model=UserRead)
def read_user(user_id: UUID, session: DBSession):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/{user_id}/courses", response_model=list[CourseReadList])
def read_user_courses(user_id: UUID, session: DBSession):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user.courses


@router.get("/{user_id}/topics", response_model=list[TopicReadList])
def read_user_topics(user_id: UUID, session: DBSession):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user.topics
