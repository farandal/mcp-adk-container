from __future__ import annotations

import asyncio
import base64
import json
import os
import re
from typing import Optional

import anthropic

from ..types import FraudReport
from .check_email_patterns import check_email_patterns
from .cmf_verify import verify_cmf_entity
from .whois_lookup import lookup_domain_whois

SYSTEM_PROMPT = """Eres un experto en ciberseguridad financiera chilena. Tu tarea es analizar correos electrónicos potencialmente fraudulentos y generar informes de riesgo detallados, comprensibles para ciudadanos no técnicos.

Contexto regulatorio chileno:
- CMF (Comisión para el Mercado Financiero): regula bancos, seguros, valores
- SII (Servicio de Impuestos Internos): impuestos, RUT, facturas electrónicas
- SERNAC: protección al consumidor
- BancoEstado, Banco de Chile, Santander, BCI, Scotiabank, Itaú son los principales bancos
- Transbank maneja pagos con tarjeta
- Las instituciones oficiales NUNCA solicitan contraseñas, datos de tarjeta ni claves por correo

Tu respuesta debe ser ÚNICAMENTE un objeto JSON válido con esta estructura exacta:
{
  "riskScore": <número 0-100>,
  "riskLevel": <"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">,
  "indicators": [<lista de indicadores técnicos en español>],
  "explanation": "<explicación clara en español para una persona sin conocimientos técnicos, máximo 3 párrafos>",
  "recommendations": [<lista de recomendaciones concretas en español>]
}

Escala de riesgo:
- 0-25: LOW — correo probablemente legítimo
- 26-50: MEDIUM — señales de alerta, proceder con cautela
- 51-75: HIGH — probable phishing o fraude
- 76-100: CRITICAL — phishing confirmado o estafa evidente"""

_EMAIL_DOMAIN_RE = re.compile(r"@([^>@\s]+)")
_INSTITUTION_PATTERNS = [
    "banco de chile", "bancochile", "bancoestado", "banco estado",
    "santander", "bci", "scotiabank", "itaú", "itau",
    "transbank", "sii", "cmf", "sernac", "falabella", "ripley",
    "previred", "afp", "isapre",
]
_JSON_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```|(\{[\s\S]+\})")


def _extract_domain(email: str) -> Optional[str]:
    m = _EMAIL_DOMAIN_RE.search(email)
    return m.group(1).lower() if m else None


def _mentioned_institutions(content: str) -> list[str]:
    lower = content.lower()
    return [p for p in _INSTITUTION_PATTERNS if p in lower]


def _try_decode_base64(text: str) -> str:
    stripped = text.strip()
    if len(stripped) > 100 and re.match(r"^[A-Za-z0-9+/=\n]+$", stripped):
        try:
            return base64.b64decode(stripped).decode("utf-8")
        except Exception:
            pass
    return text


async def analyze_email(
    email_content: str,
    sender_email: Optional[str] = None,
    subject: Optional[str] = None,
) -> dict:
    content = _try_decode_base64(email_content)

    pattern_result = check_email_patterns(content, sender_email, subject)

    sender_domain = _extract_domain(sender_email) if sender_email else None
    institutions = _mentioned_institutions(content)

    whois_task = (
        lookup_domain_whois(sender_domain) if sender_domain else asyncio.sleep(0)
    )
    cmf_task = (
        verify_cmf_entity(institutions[0]) if institutions else asyncio.sleep(0)
    )
    whois_data, cmf_result = await asyncio.gather(whois_task, cmf_task)

    # Build context summaries
    if sender_domain and hasattr(whois_data, "domain"):
        whois_summary = (
            f"dominio={whois_data.domain}, "
            f"registrador={whois_data.registrar or 'desconocido'}, "
            f"creado={whois_data.created or 'desconocido'}, "
            f"país={whois_data.country or 'desconocido'}, "
            f"estado={whois_data.status or 'desconocido'}"
        )
    else:
        whois_summary = "No se pudo obtener información WHOIS del dominio"

    if cmf_result and hasattr(cmf_result, "found"):
        if cmf_result.found:
            cmf_summary = (
                f'La institución "{cmf_result.entityName}" SÍ está registrada en CMF '
                f"(tipo: {cmf_result.entityType})"
            )
        else:
            cmf_summary = "La institución mencionada NO está registrada en CMF Chile"
    else:
        cmf_summary = "No se verificó ninguna institución chilena en este correo"

    if pattern_result.suspiciousCount > 0:
        pattern_summary = (
            f"{pattern_result.suspiciousCount} patrones sospechosos: "
            + "; ".join(pattern_result.details)
        )
    else:
        pattern_summary = "No se detectaron patrones sospechosos automáticamente"

    preview = content[:3000] + "\n[... contenido truncado ...]" if len(content) > 3000 else content
    user_prompt = (
        f"Analiza este correo potencialmente fraudulento:\n\n"
        f"REMITENTE: {sender_email or '(no especificado)'}\n"
        f"ASUNTO: {subject or '(no especificado)'}\n\n"
        f"CONTENIDO DEL CORREO:\n{preview}\n\n"
        f"DATOS EXTERNOS RECOPILADOS:\n"
        f"- WHOIS del dominio remitente: {whois_summary}\n"
        f"- Verificación CMF: {cmf_summary}\n"
        f"- Patrones sospechosos detectados: {pattern_summary}\n\n"
        f"Genera el informe JSON de riesgo."
    )

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1500,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw_text = "".join(b.text for b in response.content if b.type == "text")
    m = _JSON_RE.search(raw_text)

    fallback: dict = {
        "riskScore": 50,
        "riskLevel": "MEDIUM",
        "indicators": pattern_result.patterns,
        "domainAge": whois_data.created if hasattr(whois_data, "created") else None,
        "domainCountry": whois_data.country if hasattr(whois_data, "country") else None,
        "cmfRegistered": cmf_result.found if hasattr(cmf_result, "found") else None,
        "explanation": raw_text[:500] if not m else "Análisis no disponible",
        "recommendations": ["Verificar manualmente con la institución usando canales oficiales"],
    }

    if not m:
        return fallback

    try:
        parsed: dict = json.loads(m.group(1) or m.group(2))
        return {
            "riskScore": int(parsed.get("riskScore", 50)),
            "riskLevel": parsed.get("riskLevel", "MEDIUM"),
            "indicators": parsed.get("indicators", pattern_result.patterns),
            "domainAge": whois_data.created if hasattr(whois_data, "created") else None,
            "domainCountry": whois_data.country if hasattr(whois_data, "country") else None,
            "cmfRegistered": cmf_result.found if hasattr(cmf_result, "found") else None,
            "explanation": parsed.get("explanation", "Análisis no disponible"),
            "recommendations": parsed.get("recommendations", []),
        }
    except (json.JSONDecodeError, KeyError):
        return fallback
