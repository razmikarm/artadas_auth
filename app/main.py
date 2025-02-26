import logging
import multiprocessing
from fastapi import FastAPI, WebSocket
from contextlib import asynccontextmanager

from app.core.config import settings
from app.db.database import DBSession
from app.routers import auth, users, websockets
from app.utils.migrations import apply_migrations
# from app.utils.middleware import LoggingMiddleware


log = logging.getLogger("uvicorn")
log.setLevel(logging.DEBUG if settings.debug else logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Perform any startup logic here
    log.info("Starting up...")
    log.info("Run alembic upgrade head...")
    process = multiprocessing.Process(target=apply_migrations)
    process.start()
    process.join()  # Wait for the process to finish
    log.info("Finished alembic upgrade.")
    yield  # Control returns to the application during runtime
    log.info("Shutting down...")
    # Perform any shutdown logic here if needed


app = FastAPI(lifespan=lifespan, debug=settings.debug, docs_url=None, redoc_url=None)

app.include_router(auth.router, prefix="/api", tags=["Auth"])
app.include_router(users.router, prefix="/api", tags=["Users"])

# app.add_middleware(LoggingMiddleware, debug=settings.debug)


@app.websocket("/ws")
async def auth_websocket(websocket: WebSocket, session: DBSession):
    await websockets.websocket_handler(websocket, session)
