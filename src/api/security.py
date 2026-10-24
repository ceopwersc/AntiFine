"""Loopback HTTP authentication, origin checks and last-mile JSON redaction."""
import hmac
import json
import os
import secrets
import asyncio
import ipaddress
from urllib.parse import urlsplit

from starlette.responses import JSONResponse
from src.services.secret_boundary import sanitize_text

ORIGINS = frozenset({"http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000"})
CAPABILITY = os.getenv("ANTIFINE_API_TOKEN") or secrets.token_urlsafe(48)


def safe_json(value):
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [safe_json(x) for x in value]
    if isinstance(value, dict):
        return {sanitize_text(k): safe_json(v) for k, v in value.items()}
    return value


class LocalSecurityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        host = urlsplit("http://" + headers.get("host", "")).hostname
        allowed = {"localhost", "127.0.0.1", "::1"}
        if os.getenv("ANTIFINE_TESTING") == "1":
            allowed.add("testserver")
        async def reject(status, message):
            await JSONResponse({"detail": message}, status_code=status)(scope, receive, send)
        peer = (scope.get("client") or ("", 0))[0]
        try:
            address = ipaddress.ip_address(peer)
            local_peer = (address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address).is_loopback
        except ValueError:
            local_peer = os.getenv("ANTIFINE_TESTING") == "1" and peer == "testclient"
        if not local_peer:
            return await reject(403, "AntiFine accepts loopback clients only")
        if host not in allowed:
            return await reject(400, "Untrusted Host")
        origin = headers.get("origin")
        if origin is not None and origin not in ORIGINS:
            return await reject(403, "Untrusted Origin")
        path, method = scope["path"], scope["method"]
        if method == "OPTIONS":
            return await self.app(scope, receive, send)
        if path == "/api/session" and method == "POST":
            if origin not in ORIGINS or headers.get("x-antifine-request") != "1":
                return await reject(403, "Local session requires an authorized frontend Origin")
            response = JSONResponse({"status": "ready"})
            response.set_cookie("antifine_session", CAPABILITY, httponly=True, samesite="strict", path="/api")
            response.headers["Cache-Control"] = "no-store"
            return await response(scope, receive, send)
        if path not in {"/api/health"}:
            from http.cookies import SimpleCookie
            cookies = SimpleCookie()
            try:
                cookies.load(headers.get("cookie", ""))
            except Exception:
                pass
            cookie = cookies.get("antifine_session")
            supplied = headers.get("x-antifine-token", "") or (cookie.value if cookie else "")
            if not hmac.compare_digest(supplied, CAPABILITY):
                return await reject(401, "Local session required")
        # Cap the received body, including chunked multipart overhead, before parsing.
        size = 0
        limit = 17 * 1024 * 1024 if path == "/api/scan/upload" else 256 * 1024
        try:
            announced_size = int(headers.get("content-length", "0") or "0")
        except ValueError:
            return await reject(400, "Invalid content length")
        if announced_size < 0:
            return await reject(400, "Invalid content length")
        if announced_size > limit:
            return await reject(413, "Request quota exceeded")
        messages = []
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=10)
            except TimeoutError:
                return await reject(408, "Request body deadline exceeded")
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > limit:
                return await reject(413, "Request quota exceeded")
            messages.append(message)
            if not message.get("more_body", False):
                break
        async def replay():
            return messages.pop(0) if messages else await receive()
        response_start = None
        chunks = []
        async def capture(message):
            nonlocal response_start
            if message["type"] == "http.response.start":
                response_start = message
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))
        await self.app(scope, replay, capture)
        if response_start is None:
            return
        body = b"".join(chunks)
        content_type = dict(response_start["headers"]).get(b"content-type", b"")
        if b"application/json" in content_type:
            body = json.dumps(safe_json(json.loads(body)), ensure_ascii=True).encode()
        response_start["headers"] = [(k,v) for k,v in response_start["headers"] if k not in {b"content-length", b"cache-control"}]
        response_start["headers"] += [(b"content-length", str(len(body)).encode()), (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]
        await send(response_start)
        await send({"type": "http.response.body", "body": body})
        import logging
        route = getattr(scope.get("route"), "path", "unmatched")
        logging.getLogger("antifine.http").info("%s %s %s", method, route, response_start["status"])
