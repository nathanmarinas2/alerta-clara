from app.services.redaction import redact


def test_redacts_personal_and_financial_data() -> None:
    text = (
        "DNI 12345678Z, IBAN ES91 2100 0418 4502 0005 1332, "
        "teléfono +34 612 345 678 y correo persona@example.com"
    )
    redacted = redact(text)

    assert "12345678Z" not in redacted
    assert "ES91" not in redacted
    assert "612" not in redacted
    assert "persona@example.com" not in redacted
    assert "[DNI]" in redacted
    assert "[IBAN]" in redacted


def test_redacts_sensitive_url_query_but_keeps_domain() -> None:
    result = redact("https://example.org/login?token=secret&lang=es#private")
    assert "example.org" in result
    assert "secret" not in result
    assert "private" not in result
    assert "lang=es" in result


def test_does_not_treat_urgency_phrase_as_iban() -> None:
    text = "Verifica tus datos en 24 horas en https://example.org/acceso"

    assert redact(text).startswith("Verifica tus datos en 24 horas")


def test_redacts_contextual_one_time_codes() -> None:
    result = redact("Tu código SMS es 123456")

    assert "123456" not in result
    assert "[CÓDIGO]" in result
