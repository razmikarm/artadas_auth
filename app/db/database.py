from fastapi import Depends
from typing import Annotated

from sqlmodel import Session, create_engine

from app.core.config import settings


# Create database engine
engine = create_engine(settings.database_url)


# Dependency to get a database session
def get_session():
    with Session(engine) as session:
        yield session


DBSession = Annotated[Session, Depends(get_session)]
