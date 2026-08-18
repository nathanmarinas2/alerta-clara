from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas import MessageExtraction, MessageType, RequestedAction


@dataclass(frozen=True)
class MessageTypeAssessment:
    message_type: MessageType
    confidence: float
    reasons: list[str]


# Estas expresiones solo describen el tono/intención. Nunca elevan por sí solas el
# veredicto de riesgo a ESTafa.
COMMERCIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("promoción u oferta", re.compile(r"\b(?:oferta|promoci[oó]n|descuento|rebajas?)\b", re.I)),
    ("premio o sorteo", re.compile(r"\b(?:premio|sorteo|ganador(?:a)?|has ganado|regalo)\b", re.I)),
    (
        "llamada comercial",
        re.compile(r"\b(?:suscr[ií]bete|contrata|renueva|exclusiv[oa]|cup[oó]n)\b", re.I),
    ),
    ("baja publicitaria", re.compile(r"\b(?:baja|cancelar suscripci[oó]n|no recibir)\b", re.I)),
)

TRANSACTIONAL_PATTERN = re.compile(
    r"\b(?:cita|reserva|pedido|entrega|factura|recibo|turno|confirmad[oa]|recordatorio|"
    r"env[ií]o|paquete|mensajer[ií]a|recoger|recogida|reparto|punto de recogida|"
    r"disponible para recoger|seguimiento)\b",
    re.I,
)
PERSONAL_PATTERN = re.compile(
    r"\b(?:hola|buenas|familia|amigo|amiga|nos vemos|te echo de menos|qué tal)\b",
    re.I,
)


def classify_message_type(extraction: MessageExtraction) -> MessageTypeAssessment:
    """Clasifica la intención visible con reglas locales y abstención conservadora."""

    text = extraction.body_text or ""
    commercial_reasons = [label for label, pattern in COMMERCIAL_PATTERNS if pattern.search(text)]
    sensitive_action = extraction.requested_action in {
        RequestedAction.GIVE_CODE,
        RequestedAction.GIVE_CREDENTIALS,
        RequestedAction.TRANSFER,
        RequestedAction.INSTALL_APP,
    }
    suspicious_context = bool(
        sensitive_action
        or extraction.urgency_markers
        or (extraction.claimed_entity and extraction.urls)
    )

    # La urgencia comercial (por ejemplo, "solo hoy") no debe convertir una
    # promoción en phishing si no pide secretos, dinero ni acceso.
    if commercial_reasons and not sensitive_action and not (
        extraction.claimed_entity and extraction.urls
    ):
        return MessageTypeAssessment(
            MessageType.SPAM,
            min(0.94, 0.62 + (0.10 * len(commercial_reasons))),
            [f"tono comercial: {reason}" for reason in commercial_reasons[:3]],
        )

    # Un mensaje que intenta obtener secretos o dinero se describe como phishing,
    # aunque el motor de riesgo se mantenga separado y pueda abstenerse.
    if suspicious_context:
        reasons: list[str] = []
        if sensitive_action:
            reasons.append("incluye una petición de datos, dinero o acceso")
        if extraction.urls:
            reasons.append("contiene un enlace que debe verificarse")
        if extraction.urgency_markers:
            reasons.append("usa lenguaje de urgencia")
        return MessageTypeAssessment(
            MessageType.PHISHING,
            0.88 if sensitive_action else 0.72,
            reasons[:3],
        )

    if TRANSACTIONAL_PATTERN.search(text):
        transactional_reason = (
            "menciona un envío, paquete o punto de recogida"
            if re.search(
                r"\b(?:env[ií]o|paquete|mensajer[ií]a|recoger|recogida|reparto|"
                r"punto de recogida)\b",
                text,
                re.I,
            )
            else "menciona una cita, pedido o gestión esperable"
        )
        return MessageTypeAssessment(
            MessageType.TRANSACTIONAL,
            0.68,
            [transactional_reason],
        )

    if PERSONAL_PATTERN.search(text) and not extraction.urls:
        return MessageTypeAssessment(
            MessageType.PERSONAL,
            0.62,
            ["parece una conversación personal"],
        )

    return MessageTypeAssessment(
        MessageType.UNKNOWN,
        0.25,
        ["no hay suficientes rasgos lingüísticos para identificar el tipo de mensaje"],
    )
