from __future__ import annotations

from app.services.text_normalization import adversarial_obfuscations, normalize_for_detection


def test_normalize_for_detection_handles_zero_width_spaces() -> None:
    raw = "c\u200bó\u200bdigo SMS"
    normalized = normalize_for_detection(raw)
    assert normalized == "codigo sms"


def test_normalize_for_detection_handles_spaced_letters() -> None:
    raw = "c o d i g o SMS de confirmacion"
    normalized = normalize_for_detection(raw)
    assert normalized == "codigo sms de confirmacion"


def test_normalize_for_detection_handles_leet_speak_and_leading_digits() -> None:
    assert normalize_for_detection("c0d1go") == "codigo"
    assert normalize_for_detection("4nyD3sk") == "anydesk"
    assert normalize_for_detection("1ogin") == "iogin"
    assert normalize_for_detection("s3guridad") == "seguridad"


def test_normalize_for_detection_handles_divided_app_names() -> None:
    assert normalize_for_detection("instala Any Desk ahora") == "instala anydesk ahora"
    assert normalize_for_detection("ejecuta Team Viewer") == "ejecuta teamviewer"
    assert normalize_for_detection("usa Rust Desk") == "usa rustdesk"


def test_normalize_for_detection_handles_cyrillic_confusables() -> None:
    # "а" en cirílico (\u0430) -> "a"
    raw = "s\u0430ntander login"
    assert normalize_for_detection(raw) == "santander login"


def test_adversarial_obfuscations_reports_correct_categories() -> None:
    assert "caracteres invisibles" in adversarial_obfuscations("c\u200bó\u200bdigo")
    assert "homoglifos o caracteres confusables" in adversarial_obfuscations("s\u0430ntander")
    assert "palabras separadas letra a letra" in adversarial_obfuscations("A n y D e s k")
    assert "nombre de aplicación dividido" in adversarial_obfuscations("Any Desk")
    assert "sustitución leet" in adversarial_obfuscations("4nyD3sk")
    assert "sustitución leet" in adversarial_obfuscations("c0d1go")
    assert adversarial_obfuscations("Texto normal sin trucos") == []
