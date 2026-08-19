"""Conector de Certificate Transparency (CT) vía crt.sh para detección temprana.

Implementa el protocolo Connector definido en app/connectors.py.
Vigila emisiones de certificados recientes que contengan tokens de entidades
conocidas, discriminando entre certificados corporativos legítimos (OV/EV) y
certificados de campaña fraudulentos (DV recientes en dominios no oficiales).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from app.connectors import ConnectorObservation
from app.entities import (
    KnownEntity,
    domain_similarity,
    get_entity,
    is_official_domain,
    normalize_token,
    registrable_domain,
)

logger = logging.getLogger(__name__)

# Emisores en campañas de phishing (validación DV gratuita/automatizada)
AUTOMATED_DV_ISSUERS = (
    "let's encrypt",
    "zerossl",
    "cpanel",
    "buypass",
    "ssl.com",
    "google trust services",
    "cloudflare",
)

RISKY_PHISHING_TLDS = (
    ".top",
    ".xyz",
    ".site",
    ".online",
    ".vip",
    ".icu",
    ".cc",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".work",
    ".click",
    ".rest",
    ".fit",
    ".sbs",
)


def is_valid_hostname(candidate: str) -> bool:
    """Valida si un string es un hostname FQDN y no una denominación social."""
    candidate = candidate.strip().lstrip("*.").casefold()
    if not candidate or " " in candidate or "," in candidate or "/" in candidate:
        return False
    return "." in candidate


def parse_ct_timestamp(timestamp_str: str | None) -> datetime | None:
    """Parsea timestamps en formato ISO de CT (ej: 2026-08-18T14:30:00)."""
    if not timestamp_str:
        return None
    try:
        clean_str = timestamp_str.replace("Z", "+00:00")
        if "+" not in clean_str and "-" in clean_str:
            clean_str = f"{clean_str}+00:00"
        return datetime.fromisoformat(clean_str)
    except Exception:
        return None


def calculate_ct_risk_score(
    domain: str,
    entity: KnownEntity,
    issuer_name: str,
    entry_timestamp: datetime | None,
) -> float:
    """Calcula la puntuación de riesgo (0.0 a 1.0) para un dominio observado en CT."""
    issuer_lower = issuer_name.casefold()
    is_dv = any(iss in issuer_lower for iss in AUTOMATED_DV_ISSUERS)

    tokens = {
        normalize_token(a)
        for a in (entity.name, *entity.aliases)
        if len(normalize_token(a)) >= 4
    }
    norm_dom = normalize_token(domain)
    has_brand_token = any(t in norm_dom for t in tokens)

    sim = max((domain_similarity(domain, o) for o in entity.official_domains), default=0.0)
    has_typo = sim >= 0.82

    is_risky_tld = any(domain.endswith(tld) for tld in RISKY_PHISHING_TLDS)

    is_recent = False
    if entry_timestamp:
        age_hours = (datetime.now(UTC) - entry_timestamp).total_seconds() / 3600
        if 0 <= age_hours <= 72:
            is_recent = True

    score = 0.20
    if is_dv:
        score += 0.30
    if has_brand_token or has_typo:
        score += 0.30
    if is_risky_tld:
        score += 0.15
    if is_recent:
        score += 0.05

    return min(1.0, round(score, 2))


def measure_early_warning_lead_time_seconds(
    message_received_at: datetime,
    indicator_first_seen: datetime,
) -> float:
    """Calcula el delta de alerta temprana en segundos entre CT y recepción del mensaje."""
    return (message_received_at - indicator_first_seen).total_seconds()


class CertificateTransparencyConnector:
    """Conector para recopilar y filtrar candidatos de suplantación en Certificate Transparency."""

    name: str = "crtsh_ct"
    version: str = "1.0.0"

    def __init__(
        self,
        target_entities: list[str] | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
    ) -> None:
        self.target_entities = target_entities or [
            "CaixaBank",
            "BBVA",
            "Banco Santander",
            "Banco Sabadell",
            "Bankinter",
            "ING",
            "Abanca",
            "Correos",
            "DGT",
            "Agencia Tributaria",
        ]
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    async def fetch_entity_certificates(
        self,
        entity_name: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Consulta crt.sh con política de reintentos y backoff ante 502/rate-limits."""
        entity = get_entity(entity_name)
        if not entity:
            return []

        search_token = normalize_token(entity.name)
        url = f"https://crt.sh/?q=%25{search_token}%25&output=json&exclude=expired"
        headers = {"User-Agent": "AlertaClara/1.0 (CT-Monitor; Security Research)"}

        for attempt in range(1, self.max_retries + 1):
            try:
                response = await client.get(url, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            return data
                    except json.JSONDecodeError:
                        logger.warning("crt.sh devolvió respuesta no-JSON para %s", entity_name)
                elif response.status_code in (429, 502, 503, 504):
                    logger.info(
                        "crt.sh respondió %d para %s (intento %d)",
                        response.status_code,
                        entity_name,
                        attempt,
                    )
            except (httpx.RequestError, TimeoutError) as exc:
                logger.warning(
                    "Error consultando crt.sh para %s (intento %d): %s",
                    entity_name,
                    attempt,
                    exc,
                )

            if attempt < self.max_retries:
                await asyncio.sleep(self.backoff_factor * attempt)

        return []

    async def fetch(self) -> list[ConnectorObservation]:
        """Obtiene observaciones de dominios sospechosos para las entidades objetivo."""
        observations: list[ConnectorObservation] = []
        seen_domains: set[str] = set()

        async with httpx.AsyncClient() as client:
            for entity_name in self.target_entities:
                entity = get_entity(entity_name)
                if not entity:
                    continue

                certs = await self.fetch_entity_certificates(entity_name, client)
                now = datetime.now(UTC)

                for cert in certs:
                    name_value = cert.get("name_value", "")
                    issuer_name = cert.get("issuer_name", "")
                    entry_ts = parse_ct_timestamp(cert.get("entry_timestamp"))

                    for raw_name in name_value.split("\n"):
                        raw_name = raw_name.strip()
                        if not is_valid_hostname(raw_name):
                            continue

                        dom = registrable_domain(raw_name)
                        if not dom or dom in seen_domains:
                            continue

                        # Descartar propiedades oficiales legítimas
                        if is_official_domain(dom, entity):
                            continue

                        seen_domains.add(dom)
                        confidence = calculate_ct_risk_score(dom, entity, issuer_name, entry_ts)

                        obs = ConnectorObservation(
                            provider=self.name,
                            indicator_type="domain",
                            value=dom,
                            status="active",
                            confidence=confidence,
                            first_seen=entry_ts,
                            last_seen=entry_ts,
                            retrieved_at=now,
                            version=self.version,
                            provenance={
                                "claimed_entity": entity.name,
                                "issuer_name": issuer_name,
                                "common_name": cert.get("common_name"),
                                "not_before": cert.get("not_before"),
                                "not_after": cert.get("not_after"),
                                "ct_id": cert.get("id"),
                            },
                            retryable=False,
                        )
                        observations.append(obs)

        return observations


def store_ct_observations(
    observations: list[ConnectorObservation],
    version: str = "1.0.0",
) -> int:
    """Persiste observaciones de CT en FeedSnapshot y ThreatIndicator."""
    if not observations:
        return 0

    from app.database import SessionLocal
    from app.models import FeedSnapshot, ThreatIndicator
    from app.services.threat_intel import indicator_hash

    with SessionLocal() as db:
        now = datetime.now(UTC)
        values = {obs.value for obs in observations}
        checksum = hashlib.sha256("".join(sorted(values)).encode()).hexdigest()
        snapshot = FeedSnapshot(
            provider="crtsh_ct",
            version=version,
            checksum=checksum,
            entry_count=len(observations),
            fetched_at=now,
            succeeded=True,
        )
        db.add(snapshot)
        db.flush()

        rows = [
            {
                "id": hashlib.sha256(
                    f"{obs.provider}|{obs.indicator_type}|{obs.value}".encode()
                ).hexdigest()[:36],
                "provider": obs.provider,
                "snapshot_id": snapshot.id,
                "indicator_type": obs.indicator_type,
                "value_hash": indicator_hash(obs.value),
                "value_public": obs.value,
                "status": obs.status,
                "first_seen": obs.first_seen or now,
                "last_seen": obs.last_seen or now,
            }
            for obs in observations
        ]

        dialect = db.bind.dialect.name if db.bind else ""
        for offset in range(0, len(rows), 5_000):
            chunk = rows[offset : offset + 5_000]
            if dialect == "sqlite":
                from sqlalchemy.dialects.sqlite import insert

                statement = insert(ThreatIndicator).values(chunk)
            elif dialect == "postgresql":
                from sqlalchemy.dialects.postgresql import insert

                statement = insert(ThreatIndicator).values(chunk)
            else:
                statement = None
            if statement is not None:
                statement = statement.on_conflict_do_update(
                    index_elements=["provider", "indicator_type", "value_hash"],
                    set_={
                        "snapshot_id": snapshot.id,
                        "value_public": statement.excluded.value_public,
                        "status": "active",
                        "last_seen": now,
                    },
                )
                db.execute(statement)
            else:
                from sqlalchemy import select

                for row in chunk:
                    existing = db.scalar(
                        select(ThreatIndicator).where(
                            ThreatIndicator.provider == row["provider"],
                            ThreatIndicator.indicator_type == row["indicator_type"],
                            ThreatIndicator.value_hash == row["value_hash"],
                        )
                    )
                    if existing:
                        existing.snapshot_id = snapshot.id
                        existing.status = "active"
                        existing.last_seen = now
                    else:
                        db.add(ThreatIndicator(**row))
        db.commit()
        return len(observations)


async def sync_ct_monitor(settings: Settings) -> int:
    """Ejecuta una ronda de recolección de CT y persiste los indicadores."""
    entities = None
    if settings.ct_monitor_target_entities:
        entities = [
            e.strip() for e in settings.ct_monitor_target_entities.split(",") if e.strip()
        ]
    connector = CertificateTransparencyConnector(target_entities=entities)
    observations = await connector.fetch()
    if not observations:
        return 0
    return await asyncio.to_thread(store_ct_observations, observations, connector.version)


async def ct_monitor_loop(settings: Settings) -> None:
    """Bucle periódico en segundo plano para monitorización de Certificate Transparency."""
    interval = max(600, settings.ct_monitor_interval_seconds)
    while True:
        try:
            count = await sync_ct_monitor(settings)
            logger.info("CT Monitor: sincronizados %d dominios sospechosos", count)
            if count > 0:
                from app.database import SessionLocal
                from app.services.retrohunt import run_retro_hunt

                def hunt() -> None:
                    with SessionLocal() as db:
                        run_retro_hunt(db)

                await asyncio.to_thread(hunt)
        except Exception as exc:
            logger.warning("Error en ciclo de CT Monitor: %s", exc)
        await asyncio.sleep(interval)

