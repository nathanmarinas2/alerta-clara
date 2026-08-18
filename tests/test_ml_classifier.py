from pathlib import Path

from app.config import Settings
from app.services.ml_classifier import predict_phishing
from app.services.redaction import model_text


def test_model_text_redacts_urls_and_sensitive_values() -> None:
    normalized = model_text(
        "Visita https://ejemplo.test/login?token=secreto y escribe el código SMS: 123456."
    )
    assert "https://" not in normalized
    assert "ejemplo.test" not in normalized
    assert "[CÓDIGO]" in normalized


def test_missing_model_is_an_explicit_noop(tmp_path: Path) -> None:
    settings = Settings(
        enable_ml_classifier=True,
        ml_classifier_path=str(tmp_path / "missing.joblib"),
    )
    assert predict_phishing("mensaje de prueba", settings) is None
