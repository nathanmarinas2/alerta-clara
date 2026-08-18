from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import Base
from app.models import FeedSnapshot, ThreatIndicator
from app.schemas import MessageExtraction
from app.services.threat_intel import collect_reputation_signals, indicator_hash, normalize_domain


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _indicator(db: Session, provider: str, domain: str, fetched_at: datetime) -> None:
    snapshot = FeedSnapshot(
        provider=provider,
        version="v-test",
        checksum="a" * 64,
        entry_count=1,
        fetched_at=fetched_at,
        succeeded=True,
    )
    db.add(snapshot)
    db.flush()
    db.add(
        ThreatIndicator(
            provider=provider,
            snapshot_id=snapshot.id,
            indicator_type="domain",
            value_hash=indicator_hash(domain),
            value_public=domain,
            status="active",
        )
    )


def test_consensus_is_auditable_and_stale_sources_do_not_score() -> None:
    settings = Settings(enable_network_checks=False, enable_threat_feeds=True)
    extraction = MessageExtraction(
        body_text="https://malicious.example/login",
        urls=["https://malicious.example/login"],
    )
    with _session() as db:
        _indicator(db, "phishing_database", "malicious.example", datetime.now(UTC))
        _indicator(db, "cert_pl", "malicious.example", datetime.now(UTC))
        db.commit()
        signals = collect_reputation_signals(db, extraction, settings)
        known = next(item for item in signals if item.check_name == "known_bad_indicator")
        assert known.hard_rule
        assert {item["provider"] for item in known.value["sources"]} == {
            "phishing_database",
            "cert_pl",
        }

    with _session() as db:
        _indicator(
            db,
            "phishing_database",
            "malicious.example",
            datetime.now(UTC) - timedelta(days=2),
        )
        db.commit()
        signals = collect_reputation_signals(db, extraction, settings)
        stale = next(item for item in signals if item.check_name == "stale_threat_indicator")
        assert stale.weight == 0
        assert not stale.hard_rule


def test_domain_normalizer_rejects_non_domains() -> None:
    assert normalize_domain("EXAMPLE.ORG") == "example.org"
    assert normalize_domain("2026.08.18") is None
    assert normalize_domain("bad_label.example") is None
