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
