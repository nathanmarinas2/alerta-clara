from datetime import UTC, datetime

from app.models import Extraction, Message, Verdict
from app.services.stix import build_stix_bundle


def test_stix_export_contains_only_redacted_observables() -> None:
    message = Message(
        id="message-test",
        channel="api",
        body_redacted="[TELÉFONO]",
        received_at=datetime.now(UTC),
    )
    message.extraction = Extraction(
        message_id=message.id,
        urls=["https://example.org/login"],
        requested_action="ninguna",
    )
    message.verdict = Verdict(
        message_id=message.id,
        level="no_puedo_confirmarlo",
        message_type="phishing",
        message_type_confidence=0.8,
        message_type_reasons=["enlace"],
        confidence=0.4,
        score=20,
        explanation="No hay prueba concluyente.",
        action="No pulses.",
        model_version="test",
        ruleset_version="test",
        created_at=datetime.now(UTC),
    )

    bundle = build_stix_bundle(message)

    indicators = [item for item in bundle["objects"] if item["type"] == "indicator"]
    assert bundle["type"] == "bundle"
    assert indicators[0]["pattern"] == "[url:value = 'https://example.org/login']"
    assert all("message-test" not in item.get("content", "") for item in bundle["objects"])
