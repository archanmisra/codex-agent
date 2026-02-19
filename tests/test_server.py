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
