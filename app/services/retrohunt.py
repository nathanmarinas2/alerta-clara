from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import Artifact, Campaign, FeedSnapshot, ReviewItem, ThreatIndicator, Verdict
from app.schemas import VerdictLevel


def _dedupe_key(message_id: str, reason: str, reference: str) -> str:
    return hashlib.sha256(f"{message_id}|{reason}|{reference}".encode()).hexdigest()


def _enqueue(
    db: Session,
    *,
    message_id: str,
    reason: str,
    reference: str,
    payload: dict,
) -> bool:
    key = _dedupe_key(message_id, reason, reference)
    if db.scalar(select(ReviewItem.id).where(ReviewItem.dedupe_key == key)):
        return False
    db.add(
        ReviewItem(
            message_id=message_id,
            dedupe_key=key,
            reason=reason,
            payload=payload,
        )
    )
    return True


def enqueue_feedback_review(
    db: Session,
    message_id: str,
    reason_code: str | None,
) -> bool:
    return _enqueue(
        db,
        message_id=message_id,
        reason="user_disagreed",
        reference=reason_code or "unspecified",
        payload={"reason_code": reason_code},
    )


def run_retro_hunt(db: Session) -> dict[str, int]:
    """Busca casos antiguos dudosos; nunca cambia un veredicto sin revisión humana."""
    queued_feed = 0
    queued_campaign = 0
    indicators = db.scalars(
        select(ThreatIndicator).where(
            ThreatIndicator.status == "active",
            ThreatIndicator.value_public.is_not(None),
        )
    ).all()
    from app.entities import registrable_domain
    from app.services.threat_intel import load_provider_config

    provider_ttls = {
        policy.name: policy.ttl_seconds for policy in load_provider_config().providers
    }
    snapshots: dict[str, FeedSnapshot | None] = {}
    providers_by_domain: dict[str, set[str]] = defaultdict(set)
    for indicator in indicators:
        if indicator.snapshot_id not in snapshots:
            snapshots[indicator.snapshot_id] = db.get(FeedSnapshot, indicator.snapshot_id)
        snapshot = snapshots[indicator.snapshot_id]
        if not snapshot:
            continue
        fetched_at = snapshot.fetched_at
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=UTC)
        age = max(0, int((datetime.now(UTC) - fetched_at).total_seconds()))
        fresh = age <= provider_ttls.get(indicator.provider, 0)
        if fresh and indicator.value_public:
            domain = indicator.value_public
            if indicator.indicator_type == "url":
                extracted = registrable_domain(indicator.value_public)
                if extracted:
                    domain = extracted
                else:
                    continue
            providers_by_domain[domain].add(indicator.provider)

    if providers_by_domain:
        suspicious_artifacts = db.scalars(
            select(Artifact)
            .join(Verdict, Verdict.message_id == Artifact.message_id)
            .where(
                Artifact.artifact_type.in_(["domain", "redirect_domain"]),
                Artifact.value_public.in_(list(providers_by_domain)),
                Verdict.level == VerdictLevel.UNCERTAIN.value,
            )
        ).all()
        for artifact in suspicious_artifacts:
            domain = artifact.value_public
            if not domain:
                continue
            queued_feed += _enqueue(
                db,
                message_id=artifact.message_id,
                reason="new_threat_indicator",
                reference=domain,
                payload={
                    "domain": domain,
                    "providers": sorted(providers_by_domain[domain]),
                    "previous_verdict": VerdictLevel.UNCERTAIN.value,
                },
            )

    confirmed_campaigns = db.scalars(
        select(Campaign).where(Campaign.confirmed.is_(True))
    ).all()
    campaign_ids = [campaign.id for campaign in confirmed_campaigns]
    if campaign_ids:
        campaign_artifacts = db.scalars(
            select(Artifact).where(Artifact.campaign_id.in_(campaign_ids))
        ).all()
        campaigns_by_signature: dict[tuple[str, str], set[str]] = defaultdict(set)
        for artifact in campaign_artifacts:
            if artifact.campaign_id:
                campaigns_by_signature[
                    (artifact.artifact_type, artifact.value_hash)
                ].add(artifact.campaign_id)

        signatures = list(campaigns_by_signature)
        conditions = [
            and_(
                Artifact.artifact_type == artifact_type,
                Artifact.value_hash == value_hash,
            )
            for artifact_type, value_hash in signatures[:2_000]
        ]
        if conditions:
            uncertain_artifacts = db.scalars(
                select(Artifact)
                .join(Verdict, Verdict.message_id == Artifact.message_id)
                .where(
                    Artifact.campaign_id.is_(None),
                    Verdict.level == VerdictLevel.UNCERTAIN.value,
                    or_(*conditions),
                )
            ).all()
            matches: dict[tuple[str, str], set[str]] = defaultdict(set)
            for artifact in uncertain_artifacts:
                signature = (artifact.artifact_type, artifact.value_hash)
                for campaign_id in campaigns_by_signature.get(signature, set()):
                    matches[(artifact.message_id, campaign_id)].add(artifact.artifact_type)
            for (message_id, campaign_id), artifact_types in matches.items():
                if len(artifact_types) < 2:
                    continue
                queued_campaign += _enqueue(
                    db,
                    message_id=message_id,
                    reason="confirmed_campaign_match",
                    reference=campaign_id,
                    payload={
                        "campaign_id": campaign_id,
                        "artifact_types": sorted(artifact_types),
                        "previous_verdict": VerdictLevel.UNCERTAIN.value,
                    },
                )

    db.commit()
    return {"feed_matches": queued_feed, "campaign_matches": queued_campaign}
