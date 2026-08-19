from app.schemas import MessageExtraction, MessageType, RequestedAction
from app.services.message_type import classify_message_type


def test_promotional_message_is_spam_without_becoming_safe() -> None:
    result = classify_message_type(
        MessageExtraction(
            body_text="Oferta exclusiva: 70% de descuento. Suscríbete hoy y consigue tu cupón.",
        )
    )

    assert result.message_type == MessageType.SPAM
    assert result.confidence >= 0.7


def test_credential_request_is_phishing_type() -> None:
    result = classify_message_type(
        MessageExtraction(
            body_text="Verifica tus datos en el enlace para evitar el bloqueo",
            urls=["https://example.invalid/login"],
            requested_action=RequestedAction.GIVE_CREDENTIALS,
        )
    )

    assert result.message_type == MessageType.PHISHING


def test_neutral_message_abstains_on_type() -> None:
    result = classify_message_type(MessageExtraction(body_text="Nos vemos mañana a las seis"))

    assert result.message_type == MessageType.PERSONAL


def test_parcel_notification_is_transactional() -> None:
    result = classify_message_type(
        MessageExtraction(
            body_text=(
                "Celeritas: tu envío está disponible para recoger en un punto hasta el 24/08."
            ),
            claimed_entity="Celeritas",
        )
    )

    assert result.message_type == MessageType.TRANSACTIONAL


def test_100_spanish_sms_spam_dataset_detection() -> None:
    import json
    from pathlib import Path
    from app.services.extraction import local_extract

    dataset_path = Path(__file__).resolve().parents[1] / "data" / "sms_spam_100_es.jsonl"
    assert dataset_path.exists()

    lines = dataset_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 100

    detected_count = 0
    for line in lines:
        item = json.loads(line)
        extraction = local_extract(item["message"])
        assessment = classify_message_type(extraction)
        if assessment.message_type in {MessageType.SPAM, MessageType.PHISHING}:
            detected_count += 1

    # Tasa de detección de spam/phishing superior al 80%
    assert detected_count >= 80

