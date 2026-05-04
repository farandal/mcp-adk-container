from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import FastMCP

from src.modules.phishing.domain.analyzer import analyze_email
from src.modules.phishing.domain.cmf import verify_cmf_entity
from src.modules.phishing.domain.patterns import check_email_patterns
from src.modules.phishing.domain.whois import lookup_domain_whois

logger = logging.getLogger(__name__)

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
        logger.info(
            "analyze_email invocation sender_present=%s subject_len=%s content_len=%s",
            bool(sender_email),
            len(subject or ""),
            len(email_content or ""),
        )
        try:
            result = await analyze_email(
                email_content,
                sender_email or None,
                subject or None,
            )
        except Exception:
            logger.exception("analyze_email failed")
            raise

        logger.info(
            "analyze_email result riskScore=%s riskLevel=%s indicators=%s cmfRegistered=%s",
            result.get("riskScore"),
            result.get("riskLevel"),
            len(result.get("indicators") or []),
            result.get("cmfRegistered"),
        )
        return json.dumps(result, ensure_ascii=False, indent=2)

    @mcp.tool()
    async def lookup_domain_whois_tool(domain: str) -> str:
        """Consulta información WHOIS de un dominio usando RDAP.
        Retorna registrador, fecha de creación, país y estado del dominio.
        No requiere API key — usa rdap.org (gratuito)."""
        logger.info("lookup_domain_whois invocation domain=%s", domain)
        try:
            result = await lookup_domain_whois(domain)
        except Exception:
            logger.exception("lookup_domain_whois failed domain=%s", domain)
            raise

        logger.info(
            "lookup_domain_whois result domain=%s has_created=%s country=%s",
            result.domain,
            bool(result.created),
            result.country,
        )
        return result.model_dump_json(indent=2)

    @mcp.tool()
    async def verify_cmf_entity_tool(institution_name: str) -> str:
        """Verifica si una institución financiera está registrada en la CMF (Comisión para el
        Mercado Financiero de Chile). Útil para detectar suplantación de bancos u otras
        entidades reguladas. Requiere CMF_API_KEY configurada en el entorno."""
        logger.info("verify_cmf_entity invocation institution=%s", institution_name)
        try:
            result = await verify_cmf_entity(institution_name)
        except Exception:
            logger.exception("verify_cmf_entity failed institution=%s", institution_name)
            raise

        logger.info(
            "verify_cmf_entity result found=%s entity=%s type=%s score=%s",
            result.found,
            result.entityName,
            result.entityType,
            result.matchScore,
        )
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
        logger.info(
            "check_email_patterns invocation sender_present=%s subject_len=%s content_len=%s",
            bool(sender_email),
            len(subject or ""),
            len(email_content or ""),
        )
        try:
            result = check_email_patterns(
                email_content,
                sender_email or None,
                subject or None,
            )
        except Exception:
            logger.exception("check_email_patterns failed")
            raise

        logger.info(
            "check_email_patterns result suspiciousCount=%s patterns=%s",
            result.suspiciousCount,
            ",".join(result.patterns) if result.patterns else "none",
        )
        return result.model_dump_json(indent=2)
