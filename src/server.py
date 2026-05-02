from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from src.modules.phishing.mcp.tools import register_phishing_tools, PHISHING_TOOL_NAMES

mcp = FastMCP(
    name="phishing-detector",
    instructions=(
        "MCP server for phishing and financial fraud detection in emails. "
        "Tools analyze suspicious emails using WHOIS, CMF Chile registry, and Claude AI."
    ),
    stateless_http=True,
)

register_phishing_tools(mcp)


async def health(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "name": "phishing-detector MCP server",
        "version": "1.0.0",
        "tools": PHISHING_TOOL_NAMES,
        "mcp_endpoint": "/mcp",
        "transport": "StreamableHTTP",
        "runtime": "Python/FastMCP",
    })


def create_app() -> Starlette:
    mcp_asgi = mcp.streamable_http_app()
    return Starlette(
        routes=[
            Route("/", health),
            Mount("/mcp", app=mcp_asgi),
        ]
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "3000"))
    app = create_app()

    print(f"[server] phishing-detector MCP server (Python/FastMCP) on port {port}")
    print(f"[server] Health:  http://localhost:{port}/")
    print(f"[server] MCP:     http://localhost:{port}/mcp")

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
