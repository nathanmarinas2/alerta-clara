from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.entities import registrable_domain
from app.models import Artifact, Campaign, Message
from app.schemas import EvidenceSignal, MessageExtraction, SignalSeverity
from app.services.fingerprint import simhash
from app.services.network import normalize_http_url
from app.services.redaction import PHONE_RE, extract_valid_ibans, redact

MAX_ARTIFACTS = 80
MATCHABLE_TYPES = {
    "domain",
    "redirect_domain",
    "url_path_template",
    "phone",
    "iban",
    "text_fingerprint",
}
TOKEN_SEGMENT_RE = re.compile(
    r"^(?:\d{4,}|[0-9a-f]{8,}|[A-Za-z0-9_-]{20,})$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ArtifactCandidate:
    artifact_type: str
    value_hash: str
    value_public: str | None
    source: str


@dataclass(frozen=True)
class CampaignArtifactMatch:
    campaign: Campaign
    match_count: int
    artifact_types: tuple[str, ...]


def _public_candidate(artifact_type: str, value: str, source: str) -> ArtifactCandidate:
    return ArtifactCandidate(
        artifact_type=artifact_type,
        value_hash=hashlib.sha256(value.encode()).hexdigest(),
        value_public=value,
        source=source,
    )


def _private_candidate(
    artifact_type: str,
    value: str,
    source: str,
    pepper: bytes,
) -> ArtifactCandidate:
    return ArtifactCandidate(
        artifact_type=artifact_type,
        value_hash=hmac.new(pepper, value.encode(), hashlib.sha256).hexdigest(),
        value_public=None,
        source=source,
    )


def _path_template(url: str) -> str | None:
    try:
        normalized = normalize_http_url(url)
        parsed = urlsplit(normalized)
    except (ValueError, UnicodeError):
        return None
    domain = registrable_domain(normalized)
    if not domain:
        return None
    path = "/".join(
        "{token}" if TOKEN_SEGMENT_RE.fullmatch(part) else part.casefold()
        for part in parsed.path.split("/")
    )
    query_keys = sorted({key.casefold() for key, _value in parse_qsl(parsed.query)})
    query_shape = "&".join(query_keys)
    return f"{domain}{path or '/'}?{query_shape}" if query_shape else f"{domain}{path or '/'}"


def build_artifacts(
    extraction: MessageExtraction,
    signals: list[EvidenceSignal],
    settings: Settings,
) -> list[ArtifactCandidate]:
    """Extrae pivotes de campaña; los identificadores personales solo salen como HMAC."""
    pepper = settings.server_pepper.get_secret_value().encode()
    candidates: list[ArtifactCandidate] = []
    for url in extraction.urls[:20]:
        domain = registrable_domain(url)
        if domain:
            candidates.append(_public_candidate("domain", domain, "extraction"))
        template = _path_template(url)
        if template:
            candidates.append(_public_candidate("url_path_template", template, "extraction"))

    for signal in signals:
        if signal.check_name != "redirect_chain" or not isinstance(signal.value, dict):
            continue
        final_domain = signal.value.get("final_domain")
        if isinstance(final_domain, str) and final_domain:
            candidates.append(
                _public_candidate("redirect_domain", final_domain.casefold(), "redirect")
            )

    phone_values = [match.group(0) for match in PHONE_RE.finditer(extraction.body_text)]
    if extraction.sender_number:
        phone_values.append(extraction.sender_number)
    for value in phone_values[:20]:
        normalized = "".join(character for character in value if character.isdigit())
        if normalized:
            candidates.append(_private_candidate("phone", normalized, "extraction", pepper))

    for value in extract_valid_ibans(extraction.body_text)[:10]:
        candidates.append(_private_candidate("iban", value, "extraction", pepper))

    fingerprint = simhash(redact(extraction.body_text))
    if fingerprint:
        candidates.append(
            _public_candidate("text_fingerprint", str(fingerprint), "local_fingerprint")
        )

    unique: dict[tuple[str, str], ArtifactCandidate] = {}
    for candidate in candidates:
        unique[(candidate.artifact_type, candidate.value_hash)] = candidate
    return list(unique.values())[:MAX_ARTIFACTS]


def find_campaign_by_artifacts(
    db: Session,
    candidates: list[ArtifactCandidate],
    settings: Settings,
) -> CampaignArtifactMatch | None:
    matchable = [item for item in candidates if item.artifact_type in MATCHABLE_TYPES]
    if not matchable:
        return None
    conditions = [
        and_(
            Artifact.artifact_type == item.artifact_type,
            Artifact.value_hash == item.value_hash,
        )
        for item in matchable
    ]
    cutoff = datetime.now(UTC) - timedelta(days=max(1, settings.campaign_window_days))
    stored = db.scalars(
        select(Artifact).where(
            Artifact.campaign_id.is_not(None),
            Artifact.created_at >= cutoff,
            or_(*conditions),
        )
    ).all()
    grouped: dict[str, set[str]] = {}
    for item in stored:
        if item.campaign_id:
            grouped.setdefault(item.campaign_id, set()).add(item.artifact_type)
    eligible = [
        (campaign_id, artifact_types)
        for campaign_id, artifact_types in grouped.items()
        if len(artifact_types) >= max(2, settings.campaign_min_artifact_matches)
    ]
    if not eligible:
        return None
    eligible.sort(key=lambda item: len(item[1]), reverse=True)
    campaign_id, artifact_types = eligible[0]
    campaign = db.get(Campaign, campaign_id)
    if not campaign or campaign.verdict != "estafa":
        return None
    return CampaignArtifactMatch(
        campaign=campaign,
        match_count=len(artifact_types),
        artifact_types=tuple(sorted(artifact_types)),
    )


def campaign_artifact_signal(
    match: CampaignArtifactMatch,
    settings: Settings,
) -> EvidenceSignal:
    hard = bool(match.campaign.confirmed)
    return EvidenceSignal(
        check_name="known_campaign_artifacts",
        value={
            "campaign_id": match.campaign.id,
            "match_count": match.match_count,
            "artifact_types": list(match.artifact_types),
            "confirmed": hard,
        },
        weight=100 if hard else 60,
        severity=SignalSeverity.CRITICAL if hard else SignalSeverity.WARNING,
        summary=(
            "Varios datos independientes coinciden con una campaña de estafa confirmada."
            if hard
            else "Varios datos coinciden con una campaña aún pendiente de revisión."
        ),
        detail="Se exigen al menos dos tipos de artefacto; una frase parecida no basta.",
        hard_rule=hard,
        source="artifact_correlation",
        version=settings.signalset_version,
    )


def attach_artifacts(
    message: Message,
    candidates: list[ArtifactCandidate],
    campaign: Campaign | None,
) -> None:
    message.artifacts = [
        Artifact(
            campaign_id=campaign.id if campaign else None,
            artifact_type=item.artifact_type,
            value_hash=item.value_hash,
            value_public=item.value_public,
            source=item.source,
        )
        for item in candidates
    ]
