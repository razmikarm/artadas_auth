import json
import logging
from redis.asyncio import Redis
from fastapi import WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.db.database import DBSession
from app.models.auth import TokenRequest
from app.utils.auth import get_current_user
from app.utils.users import get_or_create_tg_user
from app.models.users import TelegramUser, UserRead


log = logging.getLogger("uvicorn")
log.setLevel(logging.DEBUG if settings.debug else logging.INFO)

expire_time = settings.access_token_timeout * 60
redis_client = Redis.from_url(settings.REDIS_URL)


# WebSocket connection handlers
async def websocket_handler(websocket: WebSocket, session: DBSession):
    await websocket.accept()
    internal_key = websocket.headers.get("X-Internal-Key")
    if internal_key != settings.INTERNAL_API_KEY:
        await websocket.close(code=1008)  # Policy Violation
        return

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")
            content = data.get("content")
            if not action or not content:
                await websocket.send_json({"status": "error", "message": "Invalid data"})
                continue
            if action == "auth_bot":
                tg_user = TelegramUser(**content)
                user = get_or_create_tg_user(tg_user, session)
                redis_key = f"tg_token:{user.id}"
            elif action == "validate":
                access_token = TokenRequest(**content)
                user = get_current_user(access_token.token, session, "access")
                redis_key = f"access_token:{access_token}"
            else:
                await websocket.send_json({"status": "error", "message": f"Action '{action}' not found"})
                continue
            resp_user = UserRead(**user.model_dump())
            await redis_client.set(redis_key, json.dumps(resp_user), ex=expire_time)
            await websocket.send_json({"status": "ok", "message": redis_key})
    except WebSocketDisconnect:
        log.info("Auth WebSocket disconnected")
