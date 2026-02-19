"""Sample secure MCP server exposed via Streamable HTTP."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("sample-mcp-server")

HOST = os.getenv("MCP_HOST", "0.0.0.0")
PORT = int(os.getenv("MCP_PORT", "8000"))
MCP_PATH = os.getenv("MCP_PATH", "/mcp")

ALLOWED_KEYS = {
    item.strip() for item in os.getenv("MCP_API_KEYS", "").split(",") if item.strip()
}
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

RATE_STATE: dict[str, Deque[float]] = defaultdict(deque)

mcp = FastMCP("secure-sample-mcp")


def _extract_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip() or None


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(token: str, ip: str) -> None:
    now = time.time()
    key = f"{token}:{ip}"
    timestamps = RATE_STATE[key]

    while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW_SECONDS:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    timestamps.append(now)


@mcp.tool()
def echo(text: str) -> dict:
    return {"echo": text, "length": len(text)}


@mcp.tool()
def current_time() -> dict:
    return {"utc": datetime.now(timezone.utc).isoformat()}


@mcp.tool()
def add_numbers(a: float, b: float) -> dict:
    return {"a": a, "b": b, "sum": a + b}


@mcp.tool()
def random_quote() -> dict:
    quotes = [
        "Simplicity is the soul of efficiency.",
        "Make it work, make it right, make it fast.",
        "Security is a process, not a product.",
    ]
    idx = int(time.time()) % len(quotes)
    return {"quote": quotes[idx], "index": idx}


@mcp.tool()
def secure_hash(value: str, salt: str = "") -> dict:
    digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256)
    return {"algorithm": "hmac-sha256", "digest": digest.hexdigest()}


app = FastAPI(title="Secure Sample MCP Server")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.url.path.startswith(MCP_PATH):
        token = _extract_bearer_token(request)
        if not token:
            return JSONResponse(status_code=401, content={"detail": "Missing bearer token"})

        if ALLOWED_KEYS and token not in ALLOWED_KEYS:
            return JSONResponse(status_code=403, content={"detail": "Invalid API key"})

        ip = _client_ip(request)
        try:
            _enforce_rate_limit(token=token, ip=ip)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    start = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 2)
    logger.info("%s %s -> %s (%sms)", request.method, request.url.path, response.status_code, duration_ms)
    return response


app.mount(MCP_PATH, mcp.streamable_http_app())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT)
