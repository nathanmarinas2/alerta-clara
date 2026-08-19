"""Servicio de verificación de remitentes alfanuméricos contra el Registro de Alias de la CNMC.

Basado en la Circular 1/2026 de la CNMC (BOE-A-2026-7043). Permite verificar si un alias
alfanumérico de SMS/MMS/RCS está debidamente registrado, identificar a su titular y
detectar suplantaciones de identidad de forma autoritativa.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.config import Settings
from app.entities import get_entity, normalize_token
from app.schemas import EvidenceSignal, SignalSeverity, SignalStatus

logger = logging.getLogger(__name__)
DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "cnmc_alias_registry.json"

PHONE_NUMBER_RE = re.compile(r"^\+?[0-9\s\-().]{6,20}$")


class AliasRecord(BaseModel):
    alias: str
    holder_name: str
    cif_nif: str
    category: str
    status: str
    activation_date: str
    authorized_entities: list[str]


class AliasRegistryData(BaseModel):
    source: str
    version: str
    enforcement_date: str
    ttl_seconds: int
    aliases: list[AliasRecord]


@lru_cache
def load_alias_registry() -> AliasRegistryData:
    return AliasRegistryData.model_validate_json(DATA_PATH.read_text(encoding="utf-8"))


def is_alphanumeric_sender(sender: str | None) -> bool:
    """Determina si un remitente es un alias alfanumérico sujeto a registro CNMC."""
    if not sender:
        return False
    clean = sender.strip()
    if not clean:
        return False
    # Si contiene letras o caracteres no puramente numéricos/telefónicos, es un alias
    digits_and_symbols = re.sub(r"[\d\s+\-().]", "", clean)
    if digits_and_symbols:
        return True
    return False


def find_alias_in_registry(
    sender_alias: str,
    registry: AliasRegistryData | None = None,
) -> AliasRecord | None:
    """Busca un alias en el registro de forma insensible a mayúsculas/minúsculas."""
    if not sender_alias:
        return None
    reg = registry or load_alias_registry()
    normalized_query = normalize_token(sender_alias)
    for record in reg.aliases:
        if normalize_token(record.alias) == normalized_query:
            return record
    return None


def verify_sender_alias(
    sender: str | None,
    claimed_entity_name: str | None,
    settings: Settings,
    reference_date: datetime | None = None,
) -> list[EvidenceSignal]:
    """Verifica el remitente alfanumérico contra el Registro de Alias de la CNMC."""
    if not settings.enable_cnmc_alias_registry or not is_alphanumeric_sender(sender):
        return []

    clean_sender = (sender or "").strip()
    registry = load_alias_registry()
    version = registry.version
    now = reference_date or datetime.now(UTC)

    # Fecha límite de entrada en vigor obligatoria (15 septiembre 2026)
    try:
        enforcement_dt = datetime.fromisoformat(
            settings.cnmc_registry_enforcement_date
        ).replace(tzinfo=UTC)
        is_enforced = now >= enforcement_dt
    except Exception:
        is_enforced = False

    record = find_alias_in_registry(clean_sender, registry)

    if record and record.status == "active":
        # Caso 1: Alias registrado. Comprobar si coincide con la entidad que dice ser el mensaje
        if claimed_entity_name:
            claimed_entity = get_entity(claimed_entity_name)
            claimed_norm = normalize_token(claimed_entity_name)
            entity_tokens = {claimed_norm}
            if claimed_entity:
                entity_tokens.add(normalize_token(claimed_entity.name))
                for a in claimed_entity.aliases:
                    entity_tokens.add(normalize_token(a))

            authorized_tokens = {
                normalize_token(auth) for auth in record.authorized_entities
            }
            holder_tokens = {normalize_token(record.holder_name)}

            # Coincide si algún token de la entidad está en los autorizados o en el titular
            is_authorized = bool(
                entity_tokens & authorized_tokens
                or any(t in normalize_token(record.holder_name) for t in entity_tokens if len(t) >= 4)
            )

            if not is_authorized:
                # Discrepancia dura: el alias es de otra entidad
                return [
                    EvidenceSignal(
                        check_name="cnmc_alias_mismatch",
                        value={
                            "sender_alias": clean_sender,
                            "registered_holder": record.holder_name,
                            "registered_cif": record.cif_nif,
                            "claimed_entity": claimed_entity_name,
                            "authorized_entities": record.authorized_entities,
                            "category": record.category,
                        },
                        weight=100,
                        severity=SignalSeverity.CRITICAL,
                        summary=(
                            f"Suplantación probada: el remitente '{clean_sender}' está registrado "
                            f"en la CNMC a nombre de {record.holder_name}, no de {claimed_entity_name}."
                        ),
                        detail=(
                            "Conforme a la Circular 1/2026 de la CNMC, el titular oficial de este "
                            "identificador no autoriza a la entidad reclamada en el texto."
                        ),
                        hard_rule=True,
                        status=SignalStatus.HIT,
                        source="cnmc_alias_registry",
                        version=version,
                    )
                ]

        # Alias verificado legítimo
        return [
            EvidenceSignal(
                check_name="cnmc_alias_verified",
                value={
                    "sender_alias": clean_sender,
                    "registered_holder": record.holder_name,
                    "registered_cif": record.cif_nif,
                    "category": record.category,
                    "activation_date": record.activation_date,
                },
                weight=0,
                severity=SignalSeverity.INFO,
                summary=(
                    f"El remitente '{clean_sender}' es un alias oficial registrado en la CNMC "
                    f"a nombre de {record.holder_name}."
                ),
                detail="Registro oficial conforme a la Circular 1/2026 de la CNMC.",
                status=SignalStatus.HIT,
                source="cnmc_alias_registry",
                version=version,
            )
        ]

    # Caso 2: Alias alfanumérico no presente en el catálogo local de referencia
    return [
        EvidenceSignal(
            check_name="cnmc_alias_unregistered",
            value={
                "sender_alias": clean_sender,
                "registry_catalog": "local_sample_subset",
            },
            weight=0,
            severity=SignalSeverity.INFO,
            summary=f"El remitente '{clean_sender}' no figura en el catálogo local de referencia.",
            detail="No influye en el veredicto para evitar falsos positivos ante catálogos no exhaustivos.",
            hard_rule=False,
            status=SignalStatus.NOT_APPLICABLE,
            source="cnmc_alias_registry",
            version=version,
        )
    ]
