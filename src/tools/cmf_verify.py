from __future__ import annotations

import os
import unicodedata
from typing import Any

import httpx

from ..types import CmfEntityResult


def _normalize(text: str) -> str:
    nfd = unicodedata.normalize("NFD", text.lower())
    stripped = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    return " ".join(stripped.split())


def _match_score(query: str, candidate: str) -> float:
    nq, nc = _normalize(query), _normalize(candidate)
    if nc == nq:
        return 1.0
    if nq in nc:
        return 0.9
    if nc in nq:
        return 0.8
    query_words = [w for w in nq.split() if len(w) > 2]
    candidate_words = set(nc.split())
    if not query_words:
        return 0.0
    matched = sum(1 for w in query_words if w in candidate_words)
    return matched / len(query_words)


async def verify_cmf_entity(institution_name: str) -> CmfEntityResult:
    api_key = os.getenv("CMF_API_KEY")
    if not api_key:
        return CmfEntityResult(found=False)

    url = (
        "https://api.cmfchile.cl/api-sbifv3/recursos_api/instituciones"
        f"?apikey={api_key}&formato=json"
    )

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url)

        if not resp.is_success:
            return CmfEntityResult(found=False)

        data: dict[str, Any] = resp.json()
        raw_list = data.get("Instituciones", {}).get("Institucion", None)
        if not raw_list:
            return CmfEntityResult(found=False)

        institutions: list[dict[str, Any]] = (
            raw_list if isinstance(raw_list, list) else [raw_list]
        )

        best = CmfEntityResult(found=False, matchScore=0.0)
        for inst in institutions:
            name: str = inst.get("Nombre", "")
            score = _match_score(institution_name, name)
            if score >= 0.5 and score > (best.matchScore or 0.0):
                best = CmfEntityResult(
                    found=True,
                    entityName=name,
                    entityType=inst.get("Tipo", "Institución Financiera"),
                    matchScore=score,
                )
        return best

    except Exception:
        return CmfEntityResult(found=False)
