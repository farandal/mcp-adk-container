from __future__ import annotations

import json
import logging

from mcp.server.fastmcp import FastMCP

from src.modules.image_fraud.domain.detector import score_image_b64

logger = logging.getLogger(__name__)

IMAGE_FRAUD_TOOL_NAMES = [
    "analyze_fraud_image",
]


def register_image_fraud_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def analyze_fraud_image_tool(
        image_b64: str,
        top_k: int = 5,
    ) -> str:
        """Analiza una imagen para detectar fraude visual mediante similitud semántica.

        Compara la imagen recibida contra 3.764 imágenes de fraude confirmadas del
        CSIRT del Gobierno de Chile (boletines 2019–2024) usando CLIP ViT-B/32 + FAISS.

        Parámetros
        ----------
        image_b64 : str
            Imagen codificada en base64 (JPEG, PNG u otro formato compatible con PIL).
            Se acepta con o sin prefijo data-URI (p.ej. "data:image/jpeg;base64,…").
        top_k : int
            Cantidad de incidentes de referencia más similares a retornar (1–20).
            Por defecto 5.

        Retorna
        -------
        JSON con:
          • fraud_score  — similitud coseno promedio con los top-k vecinos (0.0–1.0).
          • risk_level   — MINIMAL / LOW / MEDIUM / HIGH / CRITICAL.
          • top_matches  — lista de incidentes CSIRT más similares, cada uno con:
              rank, similarity, alert_code, clase_de_alerta, tipo_de_incidente,
              nivel_de_riesgo, fecha_lanzamiento, indicadores (IoC: URLs, IPs, SHA-256).

        Escala de riesgo
        ----------------
          CRITICAL  ≥ 0.80  Imagen casi idéntica a un fraude conocido.
          HIGH      ≥ 0.65  Fuerte similitud con una campaña de fraude.
          MEDIUM    ≥ 0.50  Parecido notable con patrones de fraude.
          LOW       ≥ 0.35  Leve parecido; requiere revisión manual.
          MINIMAL   < 0.35  Sin similitud significativa con fraudes conocidos.
        """
        image_len = len(image_b64) if image_b64 else 0
        logger.info(
            "ML fraud-image invocation received top_k=%s image_b64_len=%s",
            top_k,
            image_len,
        )

        try:
            result = score_image_b64(image_b64, top_k=top_k)
        except BaseException as exc:
            logger.exception("ML fraud-image invocation failed")
            message = str(exc)
            if "tracing-appender" in message or "hf_xet" in message:
                raise RuntimeError(
                    "Image model initialization failed in container runtime (hf_xet thread spawn). "
                    "Set HF_HUB_DISABLE_XET=1 and redeploy mcp-server."
                ) from exc
            raise RuntimeError(f"analyze_fraud_image failed: {message}") from exc

        top_matches = result.get("top_matches") or []
        top_alert_codes = [
            match.get("alert_code")
            for match in top_matches[:3]
            if isinstance(match, dict) and match.get("alert_code")
        ]
        logger.info(
            "ML fraud-image result fraud_score=%s risk_level=%s matches=%s top_alert_codes=%s",
            result.get("fraud_score"),
            result.get("risk_level"),
            len(top_matches),
            ",".join(top_alert_codes) if top_alert_codes else "none",
        )

        return json.dumps(result, ensure_ascii=False, indent=2)
