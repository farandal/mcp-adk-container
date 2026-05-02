from __future__ import annotations

import re
from typing import Optional

from ..types import PatternCheckResult

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".click", ".link",
                  ".site", ".online", ".tech", ".info"}

URGENCY_KEYWORDS = [
    "urgente", "urgente!", "inmediato", "expira hoy", "vence hoy",
    "última oportunidad", "cuenta suspendida", "cuenta bloqueada",
    "verificar ahora", "actuar ahora", "su cuenta será cerrada",
    "acceso denegado", "alerta de seguridad",
    "urgent", "immediate action", "account suspended", "verify now", "act now",
]

CHILEAN_INSTITUTIONS = [
    (re.compile(r"sii\.cl", re.I), "SII (Servicio de Impuestos Internos)"),
    (re.compile(r"cmfchile\.cl", re.I), "CMF (Comisión para el Mercado Financiero)"),
    (re.compile(r"sernac\.cl", re.I), "SERNAC"),
    (re.compile(r"bancochile|banco\s+de\s+chile", re.I), "Banco de Chile"),
    (re.compile(r"santander", re.I), "Santander Chile"),
    (re.compile(r"bci\.cl", re.I), "BCI"),
    (re.compile(r"scotiabank", re.I), "Scotiabank Chile"),
    (re.compile(r"itau", re.I), "Itaú Chile"),
    (re.compile(r"banco.?estado", re.I), "BancoEstado"),
    (re.compile(r"falabella", re.I), "Falabella"),
    (re.compile(r"ripley", re.I), "Ripley"),
    (re.compile(r"transbank", re.I), "Transbank"),
    (re.compile(r"previred", re.I), "PreviRed"),
    (re.compile(r"\bafp\b", re.I), "AFP"),
    (re.compile(r"isapre", re.I), "Isapre"),
]

SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl", re.I),
    re.compile(r"[a-z0-9\-]{30,}\.(com|net|org|cl)", re.I),
]

CREDENTIAL_KEYWORDS = ["contraseña", "password", "clave", "rut",
                        "número de tarjeta", "cvv", "pin"]

_URL_RE = re.compile(r"https?://[^\s<>\"]+", re.I)
_EMAIL_DOMAIN_RE = re.compile(r"@([^>@\s]+)")
_DISPLAY_NAME_RE = re.compile(r"^([^<]+)<")
_NON_ASCII_RE = re.compile(r"[^\x00-\x7F\xC0-\xFF]")


def _domain(email: str) -> Optional[str]:
    m = _EMAIL_DOMAIN_RE.search(email)
    return m.group(1).lower() if m else None


def _display_name(email: str) -> Optional[str]:
    m = _DISPLAY_NAME_RE.match(email)
    return m.group(1).strip().lower() if m else None


def check_email_patterns(
    email_content: str,
    sender_email: Optional[str] = None,
    subject: Optional[str] = None,
) -> PatternCheckResult:
    patterns: list[str] = []
    details: list[str] = []

    full_text = " ".join(filter(None, [email_content, subject, sender_email])).lower()
    links = _URL_RE.findall(email_content)

    # Urgency language
    for kw in URGENCY_KEYWORDS:
        if kw.lower() in full_text:
            patterns.append("urgency_language")
            details.append(f'Lenguaje de urgencia detectado: "{kw}"')
            break

    if sender_email:
        domain = _domain(sender_email)
        if domain:
            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    patterns.append("suspicious_tld")
                    details.append(f"Dominio remitente usa TLD sospechoso: {tld}")
                    break

            # Sender spoofing: display name mentions institution but domain doesn't
            display = _display_name(sender_email)
            if display:
                for pattern, institution in CHILEAN_INSTITUTIONS:
                    if pattern.search(display) and not pattern.search(domain):
                        patterns.append("sender_spoofing")
                        details.append(
                            f'Nombre muestra "{institution}" pero dominio real es "{domain}" — posible suplantación'
                        )

            # Institution mentioned in body but sender domain doesn't match
            for pattern, institution in CHILEAN_INSTITUTIONS:
                if pattern.search(full_text) and not pattern.search(domain):
                    if "institution_mismatch" not in patterns:
                        patterns.append("institution_mismatch")
                        details.append(
                            f'Se menciona "{institution}" pero el remitente no usa el dominio oficial'
                        )

    # Suspicious links
    for link in links:
        for url_pattern in SUSPICIOUS_URL_PATTERNS:
            if url_pattern.search(link):
                if "suspicious_links" not in patterns:
                    patterns.append("suspicious_links")
                    details.append(f"Enlace sospechoso: {link[:80]}...")
                break

    if len(links) > 5:
        patterns.append("excessive_links")
        details.append(f"Cantidad inusual de enlaces: {len(links)}")

    # Unicode lookalikes in subject/sender
    for field, label in [(subject or "", "asunto"), (sender_email or "", "remitente")]:
        if _NON_ASCII_RE.search(field):
            patterns.append("unicode_lookalike")
            details.append(f"Caracteres Unicode inusuales en {label} — posible homografía")
            break

    # Credential requests
    for kw in CREDENTIAL_KEYWORDS:
        if kw in full_text:
            if "credential_request" not in patterns:
                patterns.append("credential_request")
                details.append(f'Solicita información sensible: "{kw}"')

    # Malformed sender
    if sender_email and "@" not in sender_email:
        patterns.append("malformed_sender")
        details.append("Dirección de remitente malformada (sin dominio)")

    return PatternCheckResult(
        patterns=patterns,
        suspiciousCount=len(patterns),
        details=details,
    )
