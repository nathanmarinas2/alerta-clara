"""Contrato común para fuentes de inteligencia y analizadores externos.

Las implementaciones concretas pueden vivir fuera del pipeline. El contrato obliga a
conservar procedencia, frescura y política de reintento, inspirado en IntelOwl/OpenCTI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ConnectorObservation:
    provider: str
    indicator_type: str
    value: str
    status: str
    confidence: float | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    retrieved_at: datetime | None = None
    expires_at: datetime | None = None
    version: str = "1"
    provenance: dict[str, Any] = field(default_factory=dict)
    retryable: bool = False


@runtime_checkable
class Connector(Protocol):
    name: str
    version: str

    async def fetch(self) -> list[ConnectorObservation]: ...
