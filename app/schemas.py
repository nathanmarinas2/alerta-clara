from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Channel(StrEnum):
    WEB = "web"
    API = "api"
    TELEGRAM = "telegram"
    WHATSAPP = "whatsapp"


class RequestedAction(StrEnum):
    CLICK_LINK = "pinchar_enlace"
    CALL = "llamar"
    TRANSFER = "transferir"
    INSTALL_APP = "instalar_app"
    GIVE_CODE = "dar_codigo"
    GIVE_CREDENTIALS = "introducir_credenciales"
    NONE = "ninguna"


class VerdictLevel(StrEnum):
    SCAM = "estafa"
    UNCERTAIN = "no_puedo_confirmarlo"


class MessageType(StrEnum):
    """Clasificación descriptiva, independiente del veredicto de riesgo."""

    PHISHING = "phishing"
    SPAM = "spam"
    TRANSACTIONAL = "transaccional"
    PERSONAL = "personal"
    UNKNOWN = "desconocido"


class SignalSeverity(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class SignalStatus(StrEnum):
    HIT = "hit"
    MISS = "miss"
    ERROR = "error"
    TIMEOUT = "timeout"
    NOT_APPLICABLE = "not_applicable"
    SUPPRESSED = "suppressed"


class RuleStatus(StrEnum):
    FIRED = "fired"
    NOT_FIRED = "not_fired"


class MessageExtraction(BaseModel):
    sender_alias: str | None = None
    sender_number: str | None = None
    body_text: str = ""
    urls: list[str] = Field(default_factory=list)
    claimed_entity: str | None = None
    requested_action: RequestedAction = RequestedAction.NONE
    urgency_markers: list[str] = Field(default_factory=list)
    qr_payload_types: list[str] = Field(default_factory=list)

    @field_validator("urls")
    @classmethod
    def deduplicate_urls(cls, urls: list[str]) -> list[str]:
        return list(dict.fromkeys(urls))


class EvidenceSignal(BaseModel):
    check_name: str
    value: Any
    weight: int = 0
    severity: SignalSeverity = SignalSeverity.INFO
    summary: str
    detail: str | None = None
    latency_ms: int = 0
    hard_rule: bool = False
    status: SignalStatus = SignalStatus.HIT
    source: str = "local"
    version: str = "1"


class RuleTrace(BaseModel):
    rule_id: str
    status: RuleStatus
    version: str
    summary: str
    observed: int | bool
    threshold: int | bool
    signal_names: list[str] = Field(default_factory=list)
    suppressed_signal_names: list[str] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    message: str = Field(min_length=1, max_length=20_000)
    sender: str | None = Field(default=None, max_length=120)
    channel: Channel = Channel.API
    user_reference: str | None = Field(default=None, max_length=200)


class AnalysisMeta(BaseModel):
    ruleset_version: str
    model_version: str
    extraction_mode: str
    duration_ms: int
    created_at: datetime


class OfficialPhoneNumber(BaseModel):
    number: str
    source: str
    verified_at: str
    purpose: str = ""


class OfficialVerification(BaseModel):
    entity_name: str
    official_numbers: list[OfficialPhoneNumber] = Field(default_factory=list)
    official_domains: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    id: str
    level: VerdictLevel
    message_type: MessageType = MessageType.UNKNOWN
    message_type_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    message_type_reasons: list[str] = Field(default_factory=list)
    headline: str
    summary: str
    action: str
    reasons: list[str]
    extraction: MessageExtraction
    signals: list[EvidenceSignal]
    rules: list[RuleTrace]
    incident_steps: list[str]
    official_verification: OfficialVerification | None = None
    meta: AnalysisMeta

    model_config = ConfigDict(from_attributes=True)


class FeedbackReason(StrEnum):
    OFFICIAL_ENTITY = "entidad_oficial"
    OFFICIAL_DOMAIN = "dominio_oficial"
    MISSED_ACTION = "accion_no_detectada"
    MISSED_IMPERSONATION = "suplantacion_no_detectada"
    SPAM_NOT_SCAM = "spam_no_estafa"
    NEEDS_REVIEW = "necesita_revision"


class FeedbackRequest(BaseModel):
    user_said: str = Field(pattern="^(correcto|incorrecto|no_se)$")
    reason_code: FeedbackReason | None = None


class ReviewResolution(StrEnum):
    CONFIRMED_SCAM = "confirmed_scam"
    DISMISSED = "dismissed"


class ReviewResolutionRequest(BaseModel):
    resolution: ReviewResolution
    notes: str | None = Field(default=None, max_length=1_000)
    confirm_campaign: bool = False


class ReviewQueueItem(BaseModel):
    id: str
    message_id: str
    reason: str
    payload: dict[str, Any]
    created_at: datetime
    body_redacted: str
    current_verdict: str


class FeedHealth(BaseModel):
    provider: str
    status: str
    entries: int
    last_success_at: datetime | None = None
    age_seconds: int | None = None


class HealthResponse(BaseModel):
    status: str
    database: str
    model_configured: bool
    threat_feeds: list[FeedHealth] = Field(default_factory=list)
    browser_scanner: str = "disabled"
    analyses_last_24h: int = 0
    pending_reviews: int = 0


class LivenessResponse(BaseModel):
    """Respuesta mínima pública: no expone métricas operativas ni estado de feeds."""

    status: str
    database: str
    model_configured: bool
