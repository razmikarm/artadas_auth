import logging
from redis.asyncio import Redis
from fastapi import WebSocket, WebSocketDisconnect, HTTPException

from app.core.config import settings
from app.db.database import Session
from app.models.auth import TokenRequest
from app.utils.auth import get_current_user
from app.utils.users import get_or_create_tg_user
from app.models.users import TelegramUser, UserRead


log = logging.getLogger("uvicorn")
log.setLevel(logging.DEBUG if settings.debug else logging.INFO)

expire_time = settings.access_token_timeout * 60
redis_client = Redis.from_url(settings.REDIS_URL)


# WebSocket connection handlers
async def websocket_handler(websocket: WebSocket, session: Session):
    await websocket.accept()
    internal_key = websocket.headers.get("X-Internal-Key")
    if internal_key != settings.INTERNAL_API_KEY:
        await websocket.close(code=1008)  # Policy Violation
        return
    log.debug("Got new websocket connection.")

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
                try:
                    user = get_current_user(access_token.token, session, "access")
                except HTTPException as e:
                    await websocket.send_json({"status": "error", "message": str(e)})
                    continue
                redis_key = f"access_token:{access_token.token}"
            else:
                await websocket.send_json({"status": "error", "message": f"Action '{action}' not found"})
                continue
            user_data = UserRead(**user.model_dump()).model_dump_json()
            await redis_client.set(redis_key, user_data, ex=expire_time)
            await websocket.send_json({"status": "ok", "message": redis_key})
    except WebSocketDisconnect:
        log.info("Auth WebSocket disconnected")
