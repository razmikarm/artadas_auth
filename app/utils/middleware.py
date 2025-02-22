import json
import logging

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


class LoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, debug: bool):
        super().__init__(app)
        self.debug = debug
        self.logger = logging.getLogger("uvicorn")
        self.logger.setLevel(logging.DEBUG if self.debug else logging.INFO)

    async def dispatch(self, request: Request, call_next):
        # Log request details
        self.logger.debug(f"--> Request URL: {request.url}")
        self.logger.debug(f"--> Request method: {request.method}")
        self.logger.debug(f"--> Request headers: \n{json.dumps(dict(request.headers), indent=4)}")

        # Read and log request body
        try:
            data = await request.json()
            if data:
                self.logger.debug(f"--> Request body: \n{json.dumps(data, indent=4)}")
        except Exception as e:
            self.logger.debug("--> Request body: Empty or invalid")
            self.logger.warning(f"Failed to read request body: {e}")

        response = await call_next(request)

        # Log response details
        self.logger.debug(f"Response status code: {response.status_code}")
        return response


class InternalRequestValidatorMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, internal_ips: set[str], internal_api_key: str):
        super().__init__(app)
        self.internal_ips = internal_ips
        self.internal_api_key = internal_api_key

    async def dispatch(self, request: Request, call_next):
        # Check if trying login for bot
        endpoint = request.url.path
        if endpoint != "/bot_login":
            return await call_next(request)

        # Check API Key
        internal_api_key = request.headers.get("X-Internal-API-Key")
        if not internal_api_key:
            raise HTTPException(status_code=400, detail="Internal API Key is missing")
        if internal_api_key != self.internal_api_key:
            raise HTTPException(status_code=403, detail="Invalid Internal API key")

        # Check IP
        # client_host = request.client.host
        # if client_host not in self.internal_ips:
        #         raise HTTPException(status_code=403, detail="Access denied")

        return await call_next(request)
