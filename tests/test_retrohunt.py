from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (
    Artifact,
    FeedSnapshot,
    Message,
    ReviewItem,
    ThreatIndicator,
    Verdict,
)
from app.services.retrohunt import run_retro_hunt
from app.services.threat_intel import indicator_hash, load_provider_config


def test_retrohunt_queues_but_does_not_rewrite_old_verdict() -> None:
    domain_provider = next(
        p.name for p in load_provider_config().providers if p.indicator_type == "domain"
    )
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        message = Message(channel="api", body_redacted="Visita malicious.example")
        message.verdict = Verdict(
            level="no_puedo_confirmarlo",
            confidence=0.4,
            score=20,
            explanation="No concluyente",
            action="Verifica por canal oficial",
            model_version="local",
            ruleset_version="test",
        )
        db.add(message)
        db.flush()
        db.add(
            Artifact(
                message_id=message.id,
                artifact_type="domain",
                value_hash=indicator_hash("malicious.example"),
                value_public="malicious.example",
            )
        )
        snapshot = FeedSnapshot(
            provider=domain_provider,
            version="v1",
            checksum="a" * 64,
            entry_count=1,
            fetched_at=datetime.now(UTC),
            succeeded=True,
        )
        db.add(snapshot)
        db.flush()
        db.add(
            ThreatIndicator(
                provider=domain_provider,
                snapshot_id=snapshot.id,
                indicator_type="domain",
                value_hash=indicator_hash("malicious.example"),
                value_public="malicious.example",
                status="active",
            )
        )
        db.commit()

        result = run_retro_hunt(db)

        assert result["feed_matches"] == 1
        review = db.scalar(select(ReviewItem).where(ReviewItem.message_id == message.id))
        assert review is not None and review.status == "pending"
        assert db.get(Verdict, message.id).level == "no_puedo_confirmarlo"
        assert run_retro_hunt(db)["feed_matches"] == 0


def test_retrohunt_matches_url_indicators_against_domain_artifacts() -> None:
    url_provider = next(
        p.name for p in load_provider_config().providers if p.indicator_type == "url"
    )
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        message = Message(channel="api", body_redacted="Accede a http://phishing-site.top/login")
        message.verdict = Verdict(
            level="no_puedo_confirmarlo",
            confidence=0.3,
            score=15,
            explanation="No concluyente",
            action="Verifica por canal oficial",
            model_version="local",
            ruleset_version="test",
        )
        db.add(message)
        db.flush()
        db.add(
            Artifact(
                message_id=message.id,
                artifact_type="domain",
                value_hash=indicator_hash("phishing-site.top"),
                value_public="phishing-site.top",
            )
        )
        snapshot = FeedSnapshot(
            provider=url_provider,
            version="v1",
            checksum="b" * 64,
            entry_count=1,
            fetched_at=datetime.now(UTC),
            succeeded=True,
        )
        db.add(snapshot)
        db.flush()
        db.add(
            ThreatIndicator(
                provider=url_provider,
                snapshot_id=snapshot.id,
                indicator_type="url",
                value_hash=indicator_hash("https://phishing-site.top/login/form"),
                value_public="https://phishing-site.top/login/form",
                status="active",
            )
        )
        db.commit()

        result = run_retro_hunt(db)

        assert result["feed_matches"] == 1
        review = db.scalar(select(ReviewItem).where(ReviewItem.message_id == message.id))
        assert review is not None
        assert review.payload["domain"] == "phishing-site.top"
        assert review.payload["providers"] == [url_provider]

