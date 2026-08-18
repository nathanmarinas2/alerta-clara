from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import Base
from app.models import Artifact, Campaign, Message
from app.schemas import MessageExtraction
from app.services.artifacts import (
    ArtifactCandidate,
    build_artifacts,
    campaign_artifact_signal,
    find_campaign_by_artifacts,
)


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_sensitive_artifacts_are_hmac_only() -> None:
    settings = Settings(server_pepper="test-pepper", enable_network_checks=False)
    extraction = MessageExtraction(
        body_text=(
            "Llama al 612 345 678 y paga en ES91 2100 0418 4502 0005 1332. "
            "Visita https://example.org/pago/12345678"
        ),
        sender_number="612345678",
        urls=["https://example.org/pago/12345678"],
    )

    artifacts = build_artifacts(extraction, [], settings)

    private = [item for item in artifacts if item.artifact_type in {"phone", "iban"}]
    assert {item.artifact_type for item in private} == {"phone", "iban"}
    assert all(item.value_public is None and len(item.value_hash) == 64 for item in private)
    assert all("612345678" not in item.value_hash for item in private)


def test_campaign_requires_two_artifact_types_and_confirmation_for_hard_rule() -> None:
    settings = Settings(enable_network_checks=False, campaign_min_artifact_matches=2)
    candidates = [
        ArtifactCandidate("domain", "domain-hash", "bad.example", "test"),
        ArtifactCandidate("url_path_template", "path-hash", "bad.example/login", "test"),
    ]
    with _session() as db:
        campaign = Campaign(simhash="123", verdict="estafa", confirmed=True)
        message = Message(channel="api", body_redacted="x")
        db.add_all([campaign, message])
        db.flush()
        db.add_all(
            [
                Artifact(
                    message_id=message.id,
                    campaign_id=campaign.id,
                    artifact_type="domain",
                    value_hash="domain-hash",
                    value_public="bad.example",
                ),
                Artifact(
                    message_id=message.id,
                    campaign_id=campaign.id,
                    artifact_type="url_path_template",
                    value_hash="path-hash",
                    value_public="bad.example/login",
                ),
            ]
        )
        db.commit()

        assert find_campaign_by_artifacts(db, candidates[:1], settings) is None
        match = find_campaign_by_artifacts(db, candidates, settings)
        assert match is not None
        signal = campaign_artifact_signal(match, settings)
        assert signal.hard_rule
        assert signal.value["match_count"] == 2
