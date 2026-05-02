from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from src.modules.phishing.domain.analyzer import analyze_email
from src.modules.phishing.domain.cmf import verify_cmf_entity
from src.modules.phishing.domain.patterns import check_email_patterns
from src.modules.phishing.domain.whois import lookup_domain_whois

PHISHING_TOOL_NAMES = [
    "analyze_email",
    "lookup_domain_whois",
    "verify_cmf_entity",
    "check_email_patterns",
]


def register_phishing_tools(mcp: FastMCP) -> None:
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
