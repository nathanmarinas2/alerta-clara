from __future__ import annotations

import re
from dataclasses import dataclass

from openai import AsyncOpenAI

from app.config import Settings
from app.entities import find_claimed_entity
from app.schemas import MessageExtraction, RequestedAction
from app.services.redaction import URL_RE, redact
from app.services.text_normalization import normalize_for_detection

ACTION_PATTERNS: tuple[tuple[RequestedAction, re.Pattern[str]], ...] = (
    (
        RequestedAction.INSTALL_APP,
        re.compile(
            r"\b(?:instal(?:a|e|ar)|descarg(?:a|ue|ar)).{0,35}"
            r"(?:anydesk|teamviewer|rustdesk|supremo|control remoto|aplicaci[oó]n|app)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        RequestedAction.GIVE_CODE,
        re.compile(
            r"\b(?:facilit(?:a|e|ar|es)|compart(?:a|e|ir|as)|"
            r"indic(?:a|e|ar|es)|env[ií](?:a|e|ar|es)|respond(?:a|e|er)\s+(?:a\s+este\s+mensaje\s+)?con|"
            r"dime|diga)\b.{0,35}(?:c[oó]digo|clave\s*(?:sms)?|otp|pin)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        RequestedAction.GIVE_CREDENTIALS,
        re.compile(
            r"\b(?:verifi(?:car?|que|caci[oó]n)|confirm(?:ar?|e|aci[oó]n)|actuali(?:zar?|ce|zaci[oó]n)|"
            r"introdu(?:cir?|zca|ce)|ingres(?:ar?|e)|valid(?:ar?|e|aci[oó]n)|complet(?:ar?|e)|"
            r"identifi(?:car?|que|caci[oó]n)|regulari(?:zar?|ce)|modifi(?:car?|que)|"
            r"aport(?:ar?|e)|adjunt(?:ar?|e)|acced(?:er?|a|e)).{0,55}"
            r"(?:datos|credenciales|contrase[ñn]a|clave|usuario|tarjeta|cuenta|dnis?|nifs?|ibans?|"
            r"c[oó]digo postal|domicilio|direcci[oó]n|identidad|palabras? clave|frase de recuperaci[oó]n|semilla)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        RequestedAction.TRANSFER,
        re.compile(
            r"\b(?:transferencia|transfiere|bizum|paga|pague|pagar|pago|abon(?:a|e|ar|o|en)|"
            r"liquid(?:a|e|ar)|satisfac(?:er|aga)|ingres(?:a|e|ar)|reembols(?:a|o|ar)|"
            r"arancel(?:es)?|tasas?\s+aduaneras?|env[ií]a dinero)\b",
            re.IGNORECASE,
        ),
    ),
    (
        RequestedAction.CALL,
        re.compile(
            r"\b(?:llam(?:a|e|ar)|contact(?:a|e|ar) por tel[eé]fono|tel[eé]fono)\b",
            re.IGNORECASE,
        ),
    ),
    (
        RequestedAction.CLICK_LINK,
        re.compile(
            r"\b(?:puls(?:a|e|ar)|pinch(?:a|e|ar)|ha(?:z|ga) clic|acced(?:e|a|er)|"
            r"entr(?:a|e|ar)|consult(?:a|e|ar)|visit(?:a|e|ar)|revis(?:a|e|ar)|"
            r"canje(?:a|e|ar)|descarg(?:a|ue|ar)|reclam(?:a|e|ar)|reprogram(?:a|e|ar)|"
            r"solicit(?:a|e|ar)|tramit(?:a|e|ar)|regulariz(?:a|e|ar)).{0,75}"
            r"(?:enlace|link|web|sede|portal|formulario|https?://|www\.)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)

URGENCY_TERMS = (
    "urgente",
    "inmediatamente",
    "último aviso",
    "24 horas",
    "hoy",
    "bloqueada",
    "bloqueado",
    "suspendida",
    "caduca",
    "evitar cargos",
)


@dataclass(frozen=True)
class ExtractionResult:
    data: MessageExtraction
    mode: str


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)\"]}'")


def local_extract(text: str, sender: str | None = None) -> MessageExtraction:
    detection_text = normalize_for_detection(text)
    entity = find_claimed_entity(detection_text)
    requested_action = RequestedAction.NONE
    for action, pattern in ACTION_PATTERNS:
        match = pattern.search(detection_text)
        if match:
            # Si parece GIVE_CODE pero está explícitamente negado ("no compartas"), es un aviso de seguridad
            if action == RequestedAction.GIVE_CODE:
                start_pos = max(0, match.start() - 15)
                preceding = detection_text[start_pos : match.start()].casefold()
                if any(neg in preceding for neg in ("no ", "nunca ", "jamas ", "jamás ")):
                    continue
            requested_action = action
            break

    urls = [_clean_url(match.group(0)) for match in URL_RE.finditer(text)]
    urgency = [term for term in URGENCY_TERMS if normalize_for_detection(term) in detection_text]
    sender_number = sender if sender and re.search(r"\d{6,}", sender.replace(" ", "")) else None
    sender_alias = sender if sender and not sender_number else None

    return MessageExtraction(
        sender_alias=sender_alias,
        sender_number=sender_number,
        body_text=text,
        urls=urls,
        claimed_entity=entity.name if entity else None,
        requested_action=requested_action,
        urgency_markers=urgency,
    )


class MessageExtractor:
    def __init__(self, settings: Settings):
        self.settings = settings
        api_key = settings.openai_api_key
        self.client = (
            AsyncOpenAI(api_key=api_key.get_secret_value(), timeout=20.0) if api_key else None
        )

    async def extract(
        self,
        text: str,
        sender: str | None = None,
        image_data_url: str | None = None,
    ) -> ExtractionResult:
        local = local_extract(text, sender)
        if not self.client:
            if image_data_url:
                raise ValueError("Configura OPENAI_API_KEY para analizar capturas")
            return ExtractionResult(local, "local")

        safe_text = redact(text)
        safe_sender = redact(sender or "") or "desconocido"
        message_for_model = safe_text or "[captura adjunta]"
        content: list[dict[str, str]] = [
            {
                "type": "input_text",
                "text": (
                    "Extrae hechos del mensaje en español. No valores si es una estafa. "
                    "No inventes datos ausentes. Remitente aportado: "
                    f"{safe_sender}. Mensaje: {message_for_model}"
                ),
            }
        ]
        if image_data_url:
            content.append({"type": "input_image", "image_url": image_data_url, "detail": "auto"})

        try:
            response = await self.client.responses.parse(
                model=self.settings.openai_model,
                input=[
                    {
                        "role": "system",
                        "content": (
                            "Eres una capa de extracción, no un clasificador. Devuelve solo hechos "
                            "visibles. requested_action debe usar el enum proporcionado."
                        ),
                    },
                    {"role": "user", "content": content},
                ],
                text_format=MessageExtraction,
            )
            parsed = response.output_parsed
            if not parsed:
                raise ValueError("El modelo no devolvió una extracción")
        except Exception:
            if image_data_url:
                raise
            return ExtractionResult(local, "local_fallback")

        merged = parsed.model_copy(
            update={
                "body_text": parsed.body_text or local.body_text,
                "urls": list(dict.fromkeys([*local.urls, *parsed.urls])),
                "sender_alias": parsed.sender_alias or local.sender_alias,
                "sender_number": parsed.sender_number or local.sender_number,
                "claimed_entity": parsed.claimed_entity or local.claimed_entity,
                "requested_action": (
                    parsed.requested_action
                    if parsed.requested_action != RequestedAction.NONE
                    else local.requested_action
                ),
                "urgency_markers": list(
                    dict.fromkeys([*local.urgency_markers, *parsed.urgency_markers])
                ),
            }
        )
        return ExtractionResult(merged, "openai_structured")
