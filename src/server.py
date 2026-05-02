from __future__ import annotations

import json
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .tools.analyze_email import analyze_email
from .tools.check_email_patterns import check_email_patterns
from .tools.cmf_verify import verify_cmf_entity
from .tools.whois_lookup import lookup_domain_whois

TOOL_NAMES = ["analyze_email", "lookup_domain_whois", "verify_cmf_entity", "check_email_patterns"]

mcp = FastMCP(
    name="phishing-detector",
    instructions=(
        "MCP server for phishing and financial fraud detection in emails. "
        "Tools analyze suspicious emails using WHOIS, CMF Chile registry, and Claude AI."
    ),
    stateless_http=True,
)


@mcp.tool()
async def analyze_email_tool(
    email_content: str,
    sender_email: str = "",
    subject: str = "",
) -> str:
    """Analiza un correo electrónico sospechoso para detectar phishing o fraude financiero.
    Combina análisis de patrones, verificación WHOIS del dominio, consulta a CMF Chile
    y análisis con IA (Claude). Retorna un informe estructurado con score de riesgo,
    indicadores y recomendaciones en español."""
    result = await analyze_email(
        email_content,
        sender_email or None,
        subject or None,
    )
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
async def lookup_domain_whois_tool(domain: str) -> str:
    """Consulta información WHOIS de un dominio usando RDAP.
    Retorna registrador, fecha de creación, país y estado del dominio.
    No requiere API key — usa rdap.org (gratuito)."""
    result = await lookup_domain_whois(domain)
    return result.model_dump_json(indent=2)


@mcp.tool()
async def verify_cmf_entity_tool(institution_name: str) -> str:
    """Verifica si una institución financiera está registrada en la CMF (Comisión para el
    Mercado Financiero de Chile). Útil para detectar suplantación de bancos u otras
    entidades reguladas. Requiere CMF_API_KEY configurada en el entorno."""
    result = await verify_cmf_entity(institution_name)
    return result.model_dump_json(indent=2)


@mcp.tool()
def check_email_patterns_tool(
    email_content: str,
    sender_email: str = "",
    subject: str = "",
) -> str:
    """Análisis estático de patrones de phishing en un correo: urgencia, TLDs sospechosos,
    suplantación de instituciones chilenas, solicitud de credenciales, enlaces sospechosos.
    No requiere llamadas externas ni API keys."""
    result = check_email_patterns(
        email_content,
        sender_email or None,
        subject or None,
    )
    return result.model_dump_json(indent=2)


async def health(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "name": "phishing-detector MCP server",
        "version": "1.0.0",
        "tools": TOOL_NAMES,
        "mcp_endpoint": "/mcp",
        "transport": "StreamableHTTP",
        "runtime": "Python/FastMCP",
    })


def create_app() -> Starlette:
    """Build the top-level Starlette app: health at / and MCP at /mcp."""
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
