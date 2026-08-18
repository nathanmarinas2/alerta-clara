from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config import Settings
from app.services.redaction import model_text


@lru_cache(maxsize=4)
def _load_model(path: str) -> dict[str, Any] | None:
    """Carga solo artefactos locales generados por nuestro entrenamiento."""

    model_path = Path(path)
    if not model_path.is_file():
        return None
    try:
        import joblib

        artifact = joblib.load(model_path)
    except Exception:
        return None
    if not isinstance(artifact, dict) or "pipeline" not in artifact:
        return None
    return artifact


def predict_phishing(text: str, settings: Settings) -> tuple[float, dict[str, Any]] | None:
    """Devuelve una probabilidad auxiliar, nunca un veredicto independiente."""

    if not settings.enable_ml_classifier:
        return None
    artifact = _load_model(settings.ml_classifier_path)
    if not artifact:
        return None
    pipeline = artifact["pipeline"]
    try:
        probabilities = pipeline.predict_proba([model_text(text)])[0]
        classes = [str(name) for name in artifact.get("classes", [])]
        if "phishing" not in classes:
            return None
        probability = float(probabilities[classes.index("phishing")])
    except Exception:
        return None
    metadata = {
        "model_version": artifact.get("model_version", "unknown"),
        "dataset": artifact.get("dataset", "unknown"),
    }
    return probability, metadata
