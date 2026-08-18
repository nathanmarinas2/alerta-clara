from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from time import perf_counter

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.entities import get_entity
from app.models import Campaign, Extraction, Message, Signal, Verdict
from app.observability import observe_analysis
from app.schemas import (
    AnalysisMeta,
    AnalysisResponse,
    Channel,
    EvidenceSignal,
    MessageExtraction,
    OfficialPhoneNumber,
    OfficialVerification,
    SignalSeverity,
    SignalStatus,
    VerdictLevel,
)
from app.services.artifacts import (
    CampaignArtifactMatch,
    attach_artifacts,
    build_artifacts,
    campaign_artifact_signal,
    find_campaign_by_artifacts,
)
from app.services.browser import collect_browser_signals
from app.services.explanation import ExplanationWriter, allow_model_copy
from app.services.extraction import MessageExtractor
from app.services.fingerprint import simhash, simhash_bands, similarity
from app.services.google_safe_browsing import lookup_hashes
from app.services.message_type import classify_message_type
from app.services.redaction import redact, redact_value
from app.services.rules import decide, incident_steps
from app.services.signals import SignalCollector
from app.services.threat_intel import collect_reputation_signals


class AnalysisPipeline:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.extractor = MessageExtractor(settings)
        self.collector = SignalCollector(settings)
        self.writer = ExplanationWriter(settings)

    async def analyze(
        self,
        db: Session,
        text: str,
        *,
        sender: str | None = None,
        channel: Channel = Channel.API,
        user_reference: str | None = None,
        image_data_url: str | None = None,
        qr_payloads: list[str] | None = None,
    ) -> AnalysisResponse:
        started = perf_counter()
        extraction_result = await self.extractor.extract(text, sender, image_data_url)
        extraction = extraction_result.data
        if qr_payloads:
            from app.services.qr import merge_qr_payloads

            extraction = merge_qr_payloads(extraction, qr_payloads)
        message_type = classify_message_type(extraction)
        signals = await self.collector.collect(extraction)
        signals.append(
            EvidenceSignal(
                check_name="message_type_classifier",
                value={
                    "type": message_type.message_type.value,
                    "confidence": message_type.confidence,
                },
                weight=0,
                severity=SignalSeverity.INFO,
                summary=f"Tipo estimado: {message_type.message_type.value}.",
                detail="Es una descripción orientativa y no sustituye al veredicto de riesgo.",
                source="local_message_type",
                version="1",
            )
        )
        signals.extend(collect_reputation_signals(db, extraction, self.settings))
        for match in await lookup_hashes(set(extraction.urls), self.settings):
            signals.append(
                EvidenceSignal(
                    check_name="google_safe_browsing_hash_match",
                    value={"url_hash": match.url_hash, "threat_types": match.threat_types},
                    weight=60,
                    severity=SignalSeverity.WARNING,
                    summary="La URL coincide con una amenaza en Google Safe Browsing.",
                    detail=(
                        "La consulta se hizo con un prefijo hash; la URL completa no salió "
                        "del servidor."
                    ),
                    source="google_safe_browsing_v5",
                    version="v5",
                )
            )
        signals.extend(await collect_browser_signals(extraction, self.settings))
        artifact_candidates = build_artifacts(extraction, signals, self.settings)
        artifact_match = find_campaign_by_artifacts(db, artifact_candidates, self.settings)
        if artifact_match:
            signals.append(campaign_artifact_signal(artifact_match, self.settings))
        text_campaign_match = self._campaign_match(db, extraction.body_text)
        if text_campaign_match:
            signals.append(text_campaign_match[0])

        decision = decide(
            extraction,
            signals,
            ruleset_version=self.settings.ruleset_version,
            message_type=message_type.message_type,
        )
        model_copy = await self.writer.refine(decision, signals)
        if allow_model_copy(decision.level, model_copy):
            headline = model_copy.headline
            summary = model_copy.summary
            reasons = model_copy.reasons
        else:
            headline = decision.headline
            summary = decision.summary
            reasons = decision.reasons

        message = Message(
            channel=channel.value,
            user_hash=self._user_hash(user_reference),
            body_redacted=redact(extraction.body_text or text),
            lang="es",
        )
        message.extraction = Extraction(
            sender_alias=extraction.sender_alias,
            sender_number=redact(extraction.sender_number or "") or None,
            claimed_entity=extraction.claimed_entity,
            urls=[redact(url) for url in extraction.urls],
            requested_action=extraction.requested_action.value,
            urgency_markers=extraction.urgency_markers,
            qr_payload_types=extraction.qr_payload_types,
        )
        message.signals = [
            Signal(
                check_name=signal.check_name,
                value=redact_value(signal.value),
                weight=signal.weight,
                severity=signal.severity.value,
                summary=signal.summary,
                detail=signal.detail,
                latency_ms=signal.latency_ms,
                hard_rule=signal.hard_rule,
                status=signal.status.value,
                source=signal.source,
                version=signal.version,
            )
            for signal in signals
        ]
        message.verdict = Verdict(
            level=decision.level.value,
            message_type=message_type.message_type.value,
            message_type_confidence=message_type.confidence,
            message_type_reasons=message_type.reasons,
            confidence=decision.confidence,
            score=decision.score,
            explanation=summary,
            action=decision.action,
            model_version=(
                self.settings.openai_model if self.settings.openai_api_key else "local-extractor-v1"
            ),
            ruleset_version=self.settings.ruleset_version,
            rule_trace=[rule.model_dump(mode="json") for rule in decision.rules],
        )
        db.add(message)
        campaign_hint = (
            artifact_match.campaign
            if artifact_match
            else (text_campaign_match[1] if text_campaign_match else None)
        )
        campaign = self._record_campaign(
            db,
            extraction,
            decision.level,
            signals,
            campaign_hint=campaign_hint,
            artifact_match=artifact_match,
        )
        db.flush()
        attach_artifacts(message, artifact_candidates, campaign)
        db.commit()
        db.refresh(message)

        duration_ms = round((perf_counter() - started) * 1000)
        observe_analysis(decision.level.value, message_type.message_type.value, duration_ms)

        known_entity = get_entity(extraction.claimed_entity)
        official_verification = (
            OfficialVerification(
                entity_name=known_entity.name,
                official_numbers=[
                    OfficialPhoneNumber(
                        number=p.number,
                        source=p.source,
                        verified_at=p.verified_at,
                        purpose=p.purpose,
                    )
                    for p in known_entity.official_numbers
                ],
                official_domains=list(known_entity.official_domains),
            )
            if known_entity and (known_entity.official_numbers or known_entity.official_domains)
            else None
        )

        return AnalysisResponse(
            id=message.id,
            level=decision.level,
            message_type=message_type.message_type,
            message_type_confidence=message_type.confidence,
            message_type_reasons=message_type.reasons,
            headline=headline,
            summary=summary,
            action=decision.action,
            reasons=reasons,
            extraction=extraction,
            signals=signals,
            rules=decision.rules,
            incident_steps=incident_steps(extraction, message_type.message_type),
            official_verification=official_verification,
            meta=AnalysisMeta(
                ruleset_version=self.settings.ruleset_version,
                model_version=message.verdict.model_version,
                extraction_mode=extraction_result.mode,
                duration_ms=duration_ms,
                created_at=datetime.now(UTC),
            ),
        )

    def _user_hash(self, user_reference: str | None) -> str | None:
        if not user_reference:
            return None
        pepper = self.settings.server_pepper.get_secret_value().encode()
        return hmac.new(pepper, user_reference.encode(), hashlib.sha256).hexdigest()

    def _campaign_match(
        self, db: Session, text: str
    ) -> tuple[EvidenceSignal, Campaign] | None:
        fingerprint = simhash(redact(text))
        if not fingerprint:
            return None
        bands = simhash_bands(fingerprint)
        band_match = or_(
            Campaign.simhash_band_0.in_([bands[0]]),
            Campaign.simhash_band_1.in_([bands[1]]),
            Campaign.simhash_band_2.in_([bands[2]]),
            Campaign.simhash_band_3.in_([bands[3]]),
            Campaign.simhash_band_0.is_(None),
        )
        campaigns = db.scalars(
            select(Campaign)
            .where(
                Campaign.verdict == VerdictLevel.SCAM.value,
                band_match,
                Campaign.last_seen
                >= datetime.now(UTC)
                - timedelta(days=max(1, self.settings.campaign_window_days)),
            )
            .order_by(Campaign.last_seen.desc())
            .limit(150)
        ).all()
        best = max(
            ((similarity(fingerprint, int(item.simhash)), item) for item in campaigns),
            default=(0.0, None),
            key=lambda pair: pair[0],
        )
        if best[0] < 0.90 or best[1] is None:
            return None
        hard = bool(best[1].confirmed)
        return (
            EvidenceSignal(
                check_name="similar_campaign_text",
                value={
                    "campaign_id": best[1].id,
                    "similarity": round(best[0], 3),
                    "confirmed": hard,
                },
                weight=100 if hard else 55,
                severity=SignalSeverity.CRITICAL if hard else SignalSeverity.WARNING,
                summary=(
                    "El texto coincide con una campaña de estafa confirmada."
                    if hard
                    else "El texto se parece a una campaña pendiente de revisión."
                ),
                detail=(
                    "La similitud textual solo es concluyente después de confirmar la campaña."
                ),
                hard_rule=hard,
                source="campaign_store",
                version=self.settings.signalset_version,
            ),
            best[1],
        )

    def _record_campaign(
        self,
        db: Session,
        extraction: MessageExtraction,
        level: VerdictLevel,
        signals: list[EvidenceSignal],
        *,
        campaign_hint: Campaign | None,
        artifact_match: CampaignArtifactMatch | None,
    ) -> Campaign | None:
        if level != VerdictLevel.SCAM:
            return None
        fingerprint = simhash(redact(extraction.body_text))
        if not fingerprint:
            return None
        confirmed_seed = any(
            signal.status == SignalStatus.HIT
            and signal.hard_rule
            and signal.check_name
            not in {"known_campaign_artifacts", "similar_campaign_text"}
            for signal in signals
        )
        if campaign_hint:
            campaign_hint.hits += 1
            campaign_hint.last_seen = datetime.now(UTC)
            campaign_hint.confirmed = bool(campaign_hint.confirmed or confirmed_seed)
            if artifact_match:
                campaign_hint.cluster_method = "artifacts"
            return campaign_hint
        encoded = str(fingerprint)
        campaign = db.scalar(select(Campaign).where(Campaign.simhash == encoded))
        if campaign:
            campaign.hits += 1
            campaign.last_seen = datetime.now(UTC)
            campaign.confirmed = bool(campaign.confirmed or confirmed_seed)
            return campaign
        campaign = Campaign(
            simhash=encoded,
            simhash_band_0=simhash_bands(fingerprint)[0],
            simhash_band_1=simhash_bands(fingerprint)[1],
            simhash_band_2=simhash_bands(fingerprint)[2],
            simhash_band_3=simhash_bands(fingerprint)[3],
            entity=extraction.claimed_entity,
            verdict=level.value,
            confirmed=confirmed_seed,
            cluster_method="simhash",
        )
        db.add(campaign)
        return campaign
