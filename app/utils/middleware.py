import json
import logging

from fastapi import Request
from app.core.config import settings
from starlette.middleware.base import BaseHTTPMiddleware

# Configure logging
logger = logging.getLogger("uvicorn")
logger.setLevel(logging.DEBUG if settings.debug else logging.INFO)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Log request details
        logger.debug(f"--> Request URL: {request.url}")
        logger.debug(f"--> Request method: {request.method}")
        logger.debug(f"--> Request headers: \n{json.dumps(dict(request.headers), indent=4)}")

        # Read and log request body
        try:
            data = await request.json()
            if data:
                logger.debug(f"--> Request body: \n{json.dumps(data, indent=4)}")
        except Exception as e:
            logger.debug("--> Request body: Empty or invalid")
            logger.warning(f"Failed to read request body: {e}")

        # Call the next middleware or actual endpoint
        response = await call_next(request)

        # Log response details
        logger.debug(f"Response status code: {response.status_code}")
        return response
