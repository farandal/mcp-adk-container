from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

import httpx

from ..types import WhoisData

_DOMAIN_CLEAN_RE = re.compile(r"^https?://|/.*$")


def _clean_domain(domain: str) -> str:
    return _DOMAIN_CLEAN_RE.sub("", domain).lower()


def _parse_date(date_str: str) -> Optional[str]:
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except (ValueError, AttributeError):
        return None


def _extract_registrar(entities: list[dict[str, Any]]) -> Optional[str]:
    for entity in entities:
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for entry in vcard[1]:
                    if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
                        return str(entry[3])
    return None


def _extract_country(entities: list[dict[str, Any]]) -> Optional[str]:
    for entity in entities:
        vcard = entity.get("vcardArray", [])
        if len(vcard) > 1 and isinstance(vcard[1], list):
            for entry in vcard[1]:
                if isinstance(entry, list) and entry[0] == "adr" and isinstance(entry[3], list):
                    parts: list[str] = entry[3]
                    if len(parts) >= 7 and parts[6]:
                        return parts[6]
    return None


async def lookup_domain_whois(domain: str) -> WhoisData:
    clean = _clean_domain(domain)
    url = f"https://rdap.org/domain/{clean}"

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})

        if not resp.is_success:
            return WhoisData(domain=clean)

        data: dict[str, Any] = resp.json()
        entities: list[dict[str, Any]] = data.get("entities", [])
        events: list[dict[str, Any]] = data.get("events", [])

        created = next(
            (_parse_date(e["eventDate"]) for e in events if e.get("eventAction") == "registration"),
            None,
        )
        expires = next(
            (_parse_date(e["eventDate"]) for e in events if e.get("eventAction") == "expiration"),
            None,
        )
        nameservers = [ns["ldhName"] for ns in data.get("nameservers", []) if "ldhName" in ns]

        return WhoisData(
            domain=clean,
            registrar=_extract_registrar(entities),
            created=created,
            expires=expires,
            country=_extract_country(entities),
            status=", ".join(data.get("status", [])) or None,
            nameservers=nameservers or None,
        )
    except Exception as exc:
        return WhoisData(domain=clean)
