from __future__ import annotations

import logging
from io import BytesIO

from app.schemas import MessageExtraction, RequestedAction
from app.services.redaction import URL_RE

logger = logging.getLogger(__name__)
MAX_QR_PAYLOADS = 8


def classify_qr_payload(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized.startswith(("http://", "https://")):
        return "url"
    if normalized.startswith(("bcd\n", "bitcoin:", "lightning:", "ethereum:", "upi:")):
        return "payment"
    if normalized.startswith("wifi:"):
        return "wifi"
    if normalized.startswith("tel:"):
        return "phone"
    return "text"


def decode_qr_payloads(image_bytes: bytes) -> list[str]:
    """Decodifica QR localmente. Nunca abre ni solicita el contenido obtenido."""
    try:
        import zxingcpp
        from PIL import Image

        Image.MAX_IMAGE_PIXELS = 25_000_000
        with Image.open(BytesIO(image_bytes)) as image:
            image.load()
            results = zxingcpp.read_barcodes(image)
        payloads = [result.text.strip() for result in results if result.text.strip()]
        return list(dict.fromkeys(payloads))[:MAX_QR_PAYLOADS]
    except Exception as exc:
        logger.info("No se pudo decodificar QR localmente: %s", type(exc).__name__)
        return []


def merge_qr_payloads(
    extraction: MessageExtraction,
    payloads: list[str],
) -> MessageExtraction:
    types = [classify_qr_payload(payload) for payload in payloads]
    urls = list(extraction.urls)
    for payload in payloads:
        urls.extend(match.group(0).rstrip(".,;:!?)\"]}'") for match in URL_RE.finditer(payload))

    requested_action = extraction.requested_action
    if requested_action == RequestedAction.NONE:
        if "payment" in types:
            requested_action = RequestedAction.TRANSFER
        elif "url" in types:
            requested_action = RequestedAction.CLICK_LINK

    return extraction.model_copy(
        update={
            "urls": list(dict.fromkeys(urls)),
            "requested_action": requested_action,
            "qr_payload_types": list(
                dict.fromkeys([*extraction.qr_payload_types, *types])
            ),
        }
    )
