"""HTTP Basic Auth gate for synthetic-only Render staging."""
from __future__ import annotations

import base64
import hmac
import json


class StagingAccessGate:
    def __init__(self, app, username: str, password: str):
        if not username or len(password) < 24:
            raise RuntimeError("Staging Basic Auth credentials are missing or too short.")
        self.app = app
        self.username = username.encode("utf-8")
        self.password = password.encode("utf-8")

    def _authorized(self, scope) -> bool:
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        authorization = headers.get(b"authorization", b"")
        if len(authorization) > 2048 or not authorization.startswith(b"Basic "):
            return False
        try:
            decoded = base64.b64decode(authorization[6:], validate=True)
            username, separator, password = decoded.partition(b":")
            return bool(separator) and hmac.compare_digest(username, self.username) \
                and hmac.compare_digest(password, self.password)
        except (ValueError, TypeError):
            return False

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            if not self._authorized(scope):
                await send({"type": "websocket.close", "code": 1008})
                return
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path == "/healthz" and scope.get("method") == "GET":
            body = json.dumps({"status": "ok", "mode": "synthetic-staging"}).encode()
            await send({"type": "http.response.start", "status": 200, "headers": [
                (b"content-type", b"application/json"), (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode()), (b"x-content-type-options", b"nosniff") ]})
            await send({"type": "http.response.body", "body": body})
            return
        if not self._authorized(scope):
            body = b"Staging access required."
            await send({"type": "http.response.start", "status": 401, "headers": [
                (b"www-authenticate", b'Basic realm="MARINA AI synthetic staging", charset="UTF-8"'),
                (b"cache-control", b"no-store"), (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()), (b"x-content-type-options", b"nosniff") ]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)
