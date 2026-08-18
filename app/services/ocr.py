from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)
MAX_OCR_CHARS = 20_000


@lru_cache(maxsize=1)
def _engine():
    try:
        from rapidocr_onnxruntime import RapidOCR
    except ImportError:
        return None
    return RapidOCR()


def extract_text_from_image(image_bytes: bytes, *, min_confidence: float = 0.35) -> str:
    """Extrae texto localmente; no guarda la imagen ni la envía a terceros."""

    engine = _engine()
    if engine is None:
        return ""
    try:
        result, _timings = engine(image_bytes)
    except Exception as exc:  # OCR es una ayuda; nunca debe tumbar el análisis
        logger.info("No se pudo extraer texto localmente: %s", type(exc).__name__)
        return ""
    if not result:
        return ""

    lines: list[tuple[float, float, str]] = []
    for item in result:
        if len(item) < 3:
            continue
        box, text, confidence = item[0], str(item[1]).strip(), float(item[2])
        if not text or confidence < min_confidence or not box:
            continue
        x = min(float(point[0]) for point in box)
        y = min(float(point[1]) for point in box)
        lines.append((y, x, text))
    lines.sort(key=lambda item: (round(item[0] / 12), item[1]))
    return "\n".join(text for _y, _x, text in lines)[:MAX_OCR_CHARS]
