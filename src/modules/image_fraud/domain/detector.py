"""Thin wrapper around the csirt-img-ml-model FraudDetector.

Exposes a single async-compatible function ``score_image_b64`` that accepts a
base64-encoded image, runs it through the CLIP+FAISS fraud detector, and
returns the result as a plain dict ready for JSON serialisation.

Environment variables
---------------------
FRAUD_MODEL_BASE        If set, this directory is prepended to sys.path so
                        that ``import fraud_model`` can locate the package when
                        running outside the Docker container (local dev).
                        Example: /Users/shadow/ANALYSISARMY/csirt-img-ml-model

FRAUD_MODEL_ARTIFACTS   Optional override for the path to the FAISS index and
                        metadata JSON.  Defaults to ``fraud_model/artifacts``
                        relative to the working directory (correct inside the
                        container once the package is COPYed there).
"""

from __future__ import annotations

import base64
import io
import os
import sys

# ── Optional sys.path injection for local development ───────────────────────
_fraud_model_base = os.environ.get("FRAUD_MODEL_BASE")
if _fraud_model_base and _fraud_model_base not in sys.path:
    sys.path.insert(0, _fraud_model_base)

from fraud_model import FraudDetector, FraudResult  # noqa: E402

# ── Lazy singleton (mirrors claude.py pattern) ───────────────────────────────
_detector: FraudDetector | None = None


def get_detector() -> FraudDetector:
    global _detector
    if _detector is None:
        artifacts_dir = os.environ.get("FRAUD_MODEL_ARTIFACTS", "fraud_model/artifacts")
        _detector = FraudDetector(artifacts_dir=artifacts_dir)
    return _detector


def score_image_b64(image_b64: str, top_k: int = 5) -> dict:
    """Decode a base64 image and score it against the fraud index.

    Parameters
    ----------
    image_b64 : str
        Base64-encoded image bytes (JPEG, PNG, or any PIL-supported format).
        The data-URI prefix (``data:image/…;base64,``) is stripped automatically
        if present.
    top_k : int
        Number of nearest-neighbour matches to return (1–20).

    Returns
    -------
    dict
        Serialised ``FraudResult`` with keys ``fraud_score``, ``risk_level``,
        and ``top_matches``.

    Raises
    ------
    ValueError
        If ``image_b64`` is empty or cannot be decoded as valid image data.
    """
    if not image_b64:
        raise ValueError("image_b64 is empty")

    # Strip data-URI prefix if the client included it
    if "," in image_b64 and image_b64.startswith("data:"):
        image_b64 = image_b64.split(",", 1)[1]

    try:
        raw_bytes = base64.b64decode(image_b64)
    except Exception as exc:
        raise ValueError(f"Failed to base64-decode image data: {exc}") from exc

    from PIL import Image  # local import keeps startup fast when module is not used

    try:
        image = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
    except Exception as exc:
        raise ValueError(f"Cannot open image bytes as a valid image: {exc}") from exc

    top_k = max(1, min(top_k, 20))
    result: FraudResult = get_detector().score(image, top_k=top_k)
    return result.to_dict()
