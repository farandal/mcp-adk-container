from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from src.modules.phishing.mcp.tools import register_phishing_tools, PHISHING_TOOL_NAMES
from src.modules.image_fraud.mcp.tools import register_image_fraud_tools, IMAGE_FRAUD_TOOL_NAMES

mcp = FastMCP(
    name="phishing-detector",
    instructions=(
        "MCP server for phishing and financial fraud detection in emails and images. "
        "Tools analyze suspicious emails using WHOIS, CMF Chile registry, and Claude AI, "
        "and detect fraud in images using CLIP semantic similarity against the CSIRT Chile dataset."
    ),
    stateless_http=True,
    # Quick tunnels use rotating hostnames, so strict host allowlists would
    # reject valid requests from Claude Desktop via trycloudflare.com.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

register_phishing_tools(mcp)
register_image_fraud_tools(mcp)


async def health(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "name": "phishing-detector MCP server",
        "version": "1.0.0",
        "tools": PHISHING_TOOL_NAMES + IMAGE_FRAUD_TOOL_NAMES,
        "mcp_endpoint": "/mcp",
        "transport": "StreamableHTTP",
        "runtime": "Python/FastMCP",
    })


def create_app() -> Starlette:
    mcp_asgi = mcp.streamable_http_app()
    # Ensure MCP handshake requests are not redirected between /mcp and /mcp/
    mcp_asgi.router.redirect_slashes = False
    app = Starlette(
        lifespan=mcp_asgi.router.lifespan_context,
        routes=[
            Route("/", health),
            Mount("/", app=mcp_asgi),
        ],
    )
    # MCP clients may not follow POST redirects during handshake.
    # Disable slash normalization redirects so /mcp is served directly.
    app.router.redirect_slashes = False
    return app


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "3000"))
    app = create_app()

    print(f"[server] phishing-detector MCP server (Python/FastMCP) on port {port}")
    print(f"[server] Health:  http://localhost:{port}/")
    print(f"[server] MCP:     http://localhost:{port}/mcp")

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
