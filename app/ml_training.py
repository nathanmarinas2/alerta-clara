from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from app.services.redaction import model_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "data" / "external" / "spaphish_v5.csv"
DEFAULT_SMS_INPUT = PROJECT_ROOT / "data" / "external" / "sms_mexico" / "dataset.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "models" / "phishing_tfidf.joblib"
DEFAULT_METRICS = PROJECT_ROOT / "models" / "phishing_tfidf.metrics.json"


def _read_rows(path: Path) -> tuple[list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"subject", "body", "Label"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Faltan columnas en el dataset: {', '.join(sorted(missing))}")
        for row in reader:
            label = str(row.get("Label", "")).strip()
            if label not in {"0", "1"}:
                continue
            raw = "\n".join(part.strip() for part in (row.get("subject"), row.get("body")) if part)
            text = model_text(raw).strip()
            if not text:
                continue
            digest = hashlib.sha256(text.casefold().encode("utf-8")).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            texts.append(text)
            labels.append("phishing" if label == "1" else "legitimate")
    if len(set(labels)) < 2:
        raise ValueError("El dataset debe contener al menos dos clases")
    return texts, labels


def _read_sms_rows(path: Path) -> tuple[list[str], list[str]]:
    """Lee el pequeño corpus de SMS en español como adaptación de dominio.

    El origen etiqueta `spam`; se conserva como clase separada para no confundir
    publicidad con phishing.
    """

    texts: list[str] = []
    labels: list[str] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"texto", "etiqueta"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Faltan columnas en el corpus SMS: {', '.join(sorted(missing))}")
        for row in reader:
            label = str(row.get("etiqueta", "")).strip().casefold()
            if label not in {"ham", "spam"}:
                continue
            text = model_text(str(row.get("texto", ""))).strip()
            if not text:
                continue
            digest = hashlib.sha256(text.casefold().encode("utf-8")).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            texts.append(text)
            labels.append("spam" if label == "spam" else "legitimate")
    return texts, labels


def _metric_report(y_true: Iterable[int], probabilities: Iterable[float]) -> dict[str, float]:
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    truth = list(y_true)
    scores = list(probabilities)
    predictions = [int(score >= 0.5) for score in scores]
    return {
        "accuracy": round(float(accuracy_score(truth, predictions)), 4),
        "precision": round(float(precision_score(truth, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(truth, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(truth, predictions, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(truth, scores)), 4),
        "average_precision": round(float(average_precision_score(truth, scores)), 4),
    }


def _threshold_report(
    y_true: Iterable[int], probabilities: Iterable[float]
) -> dict[str, dict[str, float]]:
    from sklearn.metrics import precision_score, recall_score

    truth = list(y_true)
    scores = list(probabilities)
    return {
        str(threshold): {
            "precision": round(
                float(
                    precision_score(
                        truth,
                        [int(score >= threshold) for score in scores],
                        zero_division=0,
                    )
                ),
                4,
            ),
            "recall": round(
                float(
                    recall_score(
                        truth,
                        [int(score >= threshold) for score in scores],
                        zero_division=0,
                    )
                ),
                4,
            ),
        }
        for threshold in (0.70, 0.80, 0.90)
    }


def train(
    input_path: Path,
    output_path: Path,
    metrics_path: Path,
    sms_input_path: Path | None = DEFAULT_SMS_INPUT,
) -> dict[str, object]:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import confusion_matrix
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    texts, labels = _read_rows(input_path)
    sms_count = 0
    if sms_input_path and sms_input_path.is_file():
        sms_texts, sms_labels = _read_sms_rows(sms_input_path)
        texts.extend(sms_texts)
        labels.extend(sms_labels)
        sms_count = len(sms_texts)
    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts,
        labels,
        test_size=0.20,
        random_state=20260818,
        stratify=labels,
    )
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=120_000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    C=2.0,
                    class_weight="balanced",
                    max_iter=2_000,
                    random_state=20260818,
                ),
            ),
        ]
    )
    pipeline.fit(train_texts, train_labels)
    class_names = [str(name) for name in pipeline.named_steps["classifier"].classes_]
    probabilities_by_class = pipeline.predict_proba(test_texts)
    phishing_index = class_names.index("phishing")
    phishing_probabilities = probabilities_by_class[:, phishing_index]
    phishing_truth = [int(label == "phishing") for label in test_labels]
    report = _metric_report(phishing_truth, phishing_probabilities)
    confusion = confusion_matrix(test_labels, pipeline.predict(test_texts), labels=class_names)

    digest = hashlib.sha256()
    digest.update(input_path.read_bytes())
    if sms_input_path and sms_input_path.is_file():
        digest.update(sms_input_path.read_bytes())
    dataset_hash = digest.hexdigest()
    artifact = {
        "pipeline": pipeline,
        "model_version": "spaphish-sms-char-tfidf-logreg-v3",
        "dataset": "SpaPhish v5 + SMS Spam Mexico (CC BY / CC BY-SA)",
        "dataset_sha256": dataset_hash,
        "trained_at": datetime.now(UTC).isoformat(),
        "text_normalization": "PII redacted; URLs replaced with [ENLACE]",
        "classes": class_names,
        "train_examples": len(train_texts),
        "test_examples": len(test_texts),
        "sms_examples": sms_count,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(artifact, output_path, compress=3)
    metrics = {
        **report,
        "thresholds": _threshold_report(phishing_truth, phishing_probabilities),
        "confusion_matrix": {
            "labels": class_names,
            "matrix": confusion.tolist(),
        },
        "examples": {"total": len(texts), "train": len(train_texts), "test": len(test_texts)},
        "dataset": artifact["dataset"],
        "dataset_sha256": dataset_hash,
        "model_version": artifact["model_version"],
        "trained_at": artifact["trained_at"],
        "warning": (
            "Evaluación aleatoria estratificada; no sustituye una prueba temporal "
            "y de SMS real."
        ),
    }
    metrics_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Entrena el clasificador auxiliar de phishing.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--sms-input", type=Path, default=DEFAULT_SMS_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--metrics", type=Path, default=DEFAULT_METRICS)
    args = parser.parse_args()
    metrics = train(args.input, args.output, args.metrics, args.sms_input)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
