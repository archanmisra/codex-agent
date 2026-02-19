#!/usr/bin/env bash
set -euo pipefail

if [[ ! -d .git ]]; then
  echo "Error: run from the root of your git repo (codex-agent)." >&2
  exit 1
fi

mkdir -p tests

cat > .env.example <<'EOT'
MCP_HOST=0.0.0.0
MCP_PORT=8000
MCP_PATH=/mcp
MCP_API_KEYS=dev-token-1,dev-token-2
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW_SECONDS=60
EOT

cat > requirements.txt <<'EOT'
mcp>=1.2.0
python-dotenv>=1.0.1
uvicorn>=0.30.0
fastapi>=0.115.0

pytest>=8.0.0
EOT

cat > server.py <<'EOT'
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
EOT

cat > tests/test_server.py <<'EOT'
import hashlib
import hmac
import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _install_stubs() -> None:
    dotenv_module = types.ModuleType("dotenv")
    dotenv_module.load_dotenv = lambda: None
    sys.modules["dotenv"] = dotenv_module

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class JSONResponse:
        def __init__(self, status_code: int, content: dict):
            self.status_code = status_code
            self.content = content

    class FastAPI:
        def __init__(self, title: str):
            self.title = title

        def middleware(self, _kind: str):
            def decorator(func):
                return func

            return decorator

        def mount(self, _path: str, _app):
            return None

    fastapi_module = types.ModuleType("fastapi")
    fastapi_module.FastAPI = FastAPI
    fastapi_module.HTTPException = HTTPException
    fastapi_module.Request = object
    sys.modules["fastapi"] = fastapi_module

    fastapi_responses = types.ModuleType("fastapi.responses")
    fastapi_responses.JSONResponse = JSONResponse
    sys.modules["fastapi.responses"] = fastapi_responses

    class FastMCP:
        def __init__(self, _name: str):
            pass

        def tool(self):
            def decorator(func):
                return func

            return decorator

        def streamable_http_app(self):
            return object()

    mcp_pkg = types.ModuleType("mcp")
    mcp_server_pkg = types.ModuleType("mcp.server")
    mcp_fastmcp_module = types.ModuleType("mcp.server.fastmcp")
    mcp_fastmcp_module.FastMCP = FastMCP
    sys.modules["mcp"] = mcp_pkg
    sys.modules["mcp.server"] = mcp_server_pkg
    sys.modules["mcp.server.fastmcp"] = mcp_fastmcp_module


_install_stubs()
server = importlib.import_module("server")


class DummyRequest:
    def __init__(self, path: str, authorization: str | None = None, ip: str = "127.0.0.1"):
        self.url = SimpleNamespace(path=path)
        self.headers = {}
        if authorization:
            self.headers["authorization"] = authorization
        self.client = SimpleNamespace(host=ip)
        self.method = "GET"


async def _call_next(_request):
    return SimpleNamespace(status_code=200)


def setup_function() -> None:
    server.RATE_STATE.clear()
    server.ALLOWED_KEYS = {"test-token"}
    server.RATE_LIMIT_REQUESTS = 3
    server.RATE_LIMIT_WINDOW_SECONDS = 60


def test_missing_bearer_token_is_rejected():
    import asyncio

    response = asyncio.run(server.security_middleware(DummyRequest("/mcp"), _call_next))
    assert response.status_code == 401


def test_invalid_bearer_token_is_rejected():
    import asyncio

    req = DummyRequest("/mcp", authorization="Bearer bad-token")
    response = asyncio.run(server.security_middleware(req, _call_next))
    assert response.status_code == 403


def test_rate_limit_enforced():
    import asyncio

    req = DummyRequest("/mcp", authorization="Bearer test-token")
    for _ in range(server.RATE_LIMIT_REQUESTS):
        response = asyncio.run(server.security_middleware(req, _call_next))
        assert response.status_code == 200

    blocked = asyncio.run(server.security_middleware(req, _call_next))
    assert blocked.status_code == 429


def test_add_numbers_tool():
    assert server.add_numbers(2, 3.5) == {"a": 2, "b": 3.5, "sum": 5.5}


def test_secure_hash_tool():
    expected = hmac.new(b"pepper", b"hello", hashlib.sha256).hexdigest()
    assert server.secure_hash("hello", "pepper") == {
        "algorithm": "hmac-sha256",
        "digest": expected,
    }
EOT

cat > README.md <<'EOT'
# Sample Secure MCP Server (Python)

This repository contains a starter MCP server implemented in Python, exposed over **Streamable HTTP** for agent integration.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python server.py
```

## Running tests

```bash
pytest -q
```

## Bootstrap on Mac

If your GitHub clone is empty, run this from repo root:

```bash
bash scripts/bootstrap_mac.sh
```

Then push:

```bash
git add .
git commit -m "Bootstrap secure sample MCP server"
git push -u origin main
```
EOT

echo "Bootstrap complete. Next steps:"
echo "  git add ."
echo "  git commit -m 'Bootstrap secure sample MCP server'"
echo "  git push -u origin main"
