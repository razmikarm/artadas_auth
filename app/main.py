from fastapi import FastAPI
from contextlib import asynccontextmanager
from app.utils.migrations import apply_migrations
from app.routers import auth, users
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Perform any startup logic here
    apply_migrations()  # Apply migrations when the app starts
    yield  # Control returns to the application during runtime
    # Perform any shutdown logic here if needed


app = FastAPI(lifespan=lifespan, debug=settings.debug)

app.include_router(auth.router, tags=["Auth"])
app.include_router(users.router, tags=["Users"])
