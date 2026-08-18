from __future__ import annotations

import html
import uuid
from datetime import UTC, datetime

from app.models import Message

STIX_NAMESPACE = uuid.UUID("2fcb5d74-1e5a-46e6-86c8-0f5c5a0b5c4b")


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _object_id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, f'{kind}:{value}') }"


def _pattern(kind: str, value: str) -> str:
    safe = value.replace("\\", "\\\\").replace("'", "\\'")
    if kind == "url":
        return f"[url:value = '{safe}']"
    return f"[domain-name:value = '{safe}']"


def build_stix_bundle(message: Message) -> dict:
    """Exporta solo observables ya redactados; nunca el cuerpo original."""

    verdict = message.verdict
    created = _timestamp(verdict.created_at if verdict else message.received_at)
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": _object_id("identity", "alerta-clara"),
            "created": created,
            "modified": created,
            "name": "Alerta Clara",
            "identity_class": "system",
        }
    ]
    extraction = message.extraction
    values: list[tuple[str, str]] = []
    if extraction:
        values.extend(("url", value) for value in extraction.urls if value)
    for artifact in message.artifacts:
        if artifact.artifact_type in {"domain", "url"} and artifact.value_public:
            values.append((artifact.artifact_type, artifact.value_public))

    seen: set[tuple[str, str]] = set()
    for kind, value in values:
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _object_id("indicator", f"{kind}:{value}"),
                "created": created,
                "modified": created,
                "name": f"Observable {kind} de Alerta Clara",
                "pattern": _pattern(kind, value),
                "pattern_type": "stix",
                "valid_from": created,
                "confidence": round((verdict.confidence if verdict else 0.0) * 100),
                "labels": [
                    "alerta-clara",
                    verdict.level if verdict else "no_puedo_confirmarlo",
                    verdict.message_type if verdict else "desconocido",
                ],
            }
        )

    if verdict:
        description = html.escape(verdict.explanation or "")
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": _object_id("note", message.id),
                "created": created,
                "modified": created,
                "content": description,
                "object_refs": [item["id"] for item in objects if item["type"] == "indicator"],
                "labels": [verdict.level, verdict.message_type],
            }
        )
    return {
        "type": "bundle",
        "id": _object_id("bundle", message.id),
        "objects": objects,
    }
