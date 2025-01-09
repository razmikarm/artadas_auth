from sqlmodel import select, SQLModel
from fastapi import HTTPException, status

from app.db.database import Session


def check_unique_fields(db_model: SQLModel, values: dict, session: Session) -> None:
    for field, value in values.items():
        stmt = select(db_model).where(getattr(db_model, field) == value)
        result = session.exec(stmt)
        if result.one_or_none():
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE, detail=f"{field.capitalize()} '{value}' is already in use."
            )
