from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import SessionLocal
from app.entities import registrable_domain
from app.models import FeedSnapshot, ThreatIndicator
from app.schemas import EvidenceSignal, FeedHealth, MessageExtraction, SignalSeverity

logger = logging.getLogger(__name__)
DATA_DIR = Path(__file__).resolve().parents[1] / "data"


class ProviderPolicy(BaseModel):
    name: str
    url: str
    format: str
    indicator_type: str
    trust_tier: int
    hard_rule_eligible: bool
    timeout_seconds: int
    ttl_seconds: int
    failure_policy: str
    level_mapping: dict[str, str]


class ProviderConfig(BaseModel):
    providers: list[ProviderPolicy]


@lru_cache
def load_provider_config() -> ProviderConfig:
    return ProviderConfig.model_validate_json(
        (DATA_DIR / "provider_policies.json").read_text(encoding="utf-8")
    )


@lru_cache
def load_reputation_contexts() -> dict:
    return json.loads((DATA_DIR / "reputation_contexts.json").read_text(encoding="utf-8"))


def indicator_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize_domain(value: str) -> str | None:
    candidate = value.strip().strip(".\"").casefold()
    if "://" in candidate:
        try:
            candidate = (urlsplit(candidate).hostname or "").casefold()
        except ValueError:
            return None
    if not candidate or " " in candidate or "." not in candidate:
        return None
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ) or labels[-1].isdigit():
        return None
    return normalized


def canonical_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = normalize_domain(parsed.hostname)
    if not host:
        return None
    try:
        port_number = parsed.port
    except ValueError:
        return None
    port = f":{port_number}" if port_number and port_number not in {80, 443} else ""
    return urlunsplit(
        (parsed.scheme.casefold(), f"{host}{port}", parsed.path or "/", parsed.query, "")
    )


def _feed_values(content: bytes, policy: ProviderPolicy) -> set[str]:
    text = content.decode("utf-8-sig", errors="replace")
    candidates: list[str] = []
    if policy.format == "csv":
        for row in csv.reader(io.StringIO(text)):
            candidates.extend(cell.strip() for cell in row)
    else:
        candidates.extend(line.strip() for line in text.splitlines())

    values: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate.startswith(("#", "//")):
            continue
        if policy.indicator_type == "domain":
            normalized = normalize_domain(candidate)
        else:
            normalized = canonical_url(candidate)
        if normalized:
            values.add(normalized)
    return values


def _upsert_indicators(
    db: Session,
    policy: ProviderPolicy,
    snapshot: FeedSnapshot,
    values: set[str],
) -> None:
    db.execute(
        update(ThreatIndicator)
        .where(ThreatIndicator.provider == policy.name)
        .values(status="inactive")
    )
    now = snapshot.fetched_at
    rows = [
        {
            "id": hashlib.sha256(
                f"{policy.name}|{policy.indicator_type}|{value}".encode()
            ).hexdigest()[:36],
            "provider": policy.name,
            "snapshot_id": snapshot.id,
            "indicator_type": policy.indicator_type,
            "value_hash": indicator_hash(value),
            # La URL se conserva sin fragmento y con las credenciales eliminadas;
            # los secretos de query ya se redaccionan antes de persistir señales.
            "value_public": value,
            "status": "active",
            "first_seen": now,
            "last_seen": now,
        }
        for value in values
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


def _store_success(
    policy: ProviderPolicy,
    checksum: str,
    version: str,
    values: set[str],
) -> None:
    with SessionLocal() as db:
        snapshot = FeedSnapshot(
            provider=policy.name,
            version=version,
            checksum=checksum,
            entry_count=len(values),
            fetched_at=datetime.now(UTC),
            succeeded=True,
        )
        db.add(snapshot)
        db.flush()
        _upsert_indicators(db, policy, snapshot, values)
        db.commit()


def _store_failure(policy: ProviderPolicy, error_type: str) -> None:
    with SessionLocal() as db:
        db.add(
            FeedSnapshot(
                provider=policy.name,
                version="error",
                checksum="",
                entry_count=0,
                succeeded=False,
                error_type=error_type,
            )
        )
        db.commit()


async def sync_provider(policy: ProviderPolicy, settings: Settings) -> int:
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(policy.timeout_seconds),
            follow_redirects=True,
            headers={"User-Agent": "AlertaClara/0.2 threat-feed-sync"},
        ) as client:
            chunks: list[bytes] = []
            downloaded = 0
            async with client.stream("GET", policy.url) as response:
                response.raise_for_status()
                declared_size = int(response.headers.get("content-length", "0") or 0)
                if declared_size > settings.threat_feed_max_bytes:
                    raise ValueError("feed_too_large")
                async for chunk in response.aiter_bytes():
                    downloaded += len(chunk)
                    if downloaded > settings.threat_feed_max_bytes:
                        raise ValueError("feed_too_large")
                    chunks.append(chunk)
                response_headers = dict(response.headers)
            content = b"".join(chunks)
        values = _feed_values(content, policy)
        if not values:
            raise ValueError("empty_feed")
        checksum = hashlib.sha256(content).hexdigest()
        version = response_headers.get("etag") or response_headers.get("last-modified")
        version = (version or checksum[:16]).strip('"')[:100]
        await asyncio.to_thread(_store_success, policy, checksum, version, values)
        return len(values)
    except Exception as exc:
        await asyncio.to_thread(_store_failure, policy, type(exc).__name__)
        logger.warning("No se pudo actualizar el feed %s: %s", policy.name, type(exc).__name__)
        return 0


async def sync_all_feeds(settings: Settings) -> dict[str, int]:
    policies = load_provider_config().providers
    results = await asyncio.gather(*(sync_provider(policy, settings) for policy in policies))
    return dict(zip((policy.name for policy in policies), results, strict=True))


async def threat_feed_loop(settings: Settings) -> None:
    interval = max(300, settings.threat_feed_refresh_seconds)
    while True:
        await sync_all_feeds(settings)
        from app.services.retrohunt import run_retro_hunt

        def hunt() -> None:
            with SessionLocal() as db:
                run_retro_hunt(db)

        await asyncio.to_thread(hunt)
        await asyncio.sleep(interval)


def _domain_candidates(domain: str) -> list[str]:
    labels = domain.split(".")
    return [".".join(labels[index:]) for index in range(max(1, len(labels) - 1))]


def collect_reputation_signals(
    db: Session,
    extraction: MessageExtraction,
    settings: Settings,
) -> list[EvidenceSignal]:
    policies = {policy.name: policy for policy in load_provider_config().providers}
    context_config = load_reputation_contexts()
    context_domains = tuple(context_config["shared_infrastructure"])
    domains = {
        domain for url in extraction.urls if (domain := registrable_domain(url))
    }
    urls = {normalized for raw_url in extraction.urls if (normalized := canonical_url(raw_url))}
    signals: list[EvidenceSignal] = []
    latest_snapshots: dict[str, FeedSnapshot] = {}
    if settings.enable_threat_feeds:
        for provider in policies:
            snapshot = db.scalar(
                select(FeedSnapshot)
                .where(FeedSnapshot.provider == provider, FeedSnapshot.succeeded.is_(True))
                .order_by(FeedSnapshot.fetched_at.desc())
                .limit(1)
            )
            if snapshot:
                latest_snapshots[provider] = snapshot

    def latest_snapshot(provider: str) -> FeedSnapshot | None:
        """Lee también snapshots legacy para no romper instalaciones ya migradas."""
        if provider not in latest_snapshots:
            latest_snapshots[provider] = db.scalar(
                select(FeedSnapshot)
                .where(FeedSnapshot.provider == provider, FeedSnapshot.succeeded.is_(True))
                .order_by(FeedSnapshot.fetched_at.desc())
                .limit(1)
            )
        return latest_snapshots[provider]

    for domain in sorted(domains):
        if any(domain == item or domain.endswith(f".{item}") for item in context_domains):
            signals.append(
                EvidenceSignal(
                    check_name="shared_infrastructure_context",
                    value={"domain": domain},
                    weight=0,
                    severity=SignalSeverity.INFO,
                    summary=(
                        "El dominio pertenece a una plataforma compartida: puede alojar contenido "
                        "legítimo o abusivo."
                    ),
                    detail="Este contexto nunca demuestra que el enlace sea seguro.",
                    source="local_warninglist",
                    version=context_config["version"],
                )
            )

        if not settings.enable_threat_feeds:
            continue
        matches = db.scalars(
            select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == "domain",
                ThreatIndicator.status == "active",
                ThreatIndicator.value_public.in_(_domain_candidates(domain)),
            )
        ).all()
        matching_providers = sorted({match.provider for match in matches})
        if not matching_providers:
            continue
        now = datetime.now(UTC)
        provider_evidence: list[dict[str, str | int | bool]] = []
        fresh_providers: list[str] = []
        for provider in matching_providers:
            snapshot = latest_snapshot(provider)
            if not snapshot:
                continue
            fetched_at = snapshot.fetched_at
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=UTC)
            age_seconds = max(0, int((now - fetched_at).total_seconds()))
            policy = policies.get(provider)
            ttl_seconds = policy.ttl_seconds if policy else settings.threat_feed_stale_hours * 3600
            fresh = age_seconds <= ttl_seconds
            if fresh:
                fresh_providers.append(provider)
            provider_evidence.append(
                {
                    "provider": provider,
                    "version": snapshot.version,
                    "age_seconds": age_seconds,
                    "fresh": fresh,
                }
            )
        if not fresh_providers:
            signals.append(
                EvidenceSignal(
                    check_name="stale_threat_indicator",
                    value={"domain": domain, "sources": provider_evidence},
                    weight=0,
                    severity=SignalSeverity.INFO,
                    summary="Hay una coincidencia antigua, pero la fuente ya no está vigente.",
                    detail="Una fuente caducada no interviene en el veredicto.",
                    source="threat_feeds",
                    version=settings.signalset_version,
                )
            )
            continue
        hard = len(fresh_providers) >= 2 or any(
            policies.get(provider) and policies[provider].hard_rule_eligible
            for provider in fresh_providers
        )
        signals.append(
            EvidenceSignal(
                check_name="known_bad_indicator",
                value={
                    "domain": domain,
                    "providers": fresh_providers,
                    "sources": provider_evidence,
                },
                weight=100 if hard else 60,
                severity=(SignalSeverity.CRITICAL if hard else SignalSeverity.WARNING),
                summary=(
                    "El dominio figura en fuentes actualizadas de phishing."
                    if hard
                    else "Una fuente de inteligencia ha marcado este dominio como malicioso."
                ),
                detail="La coincidencia conserva proveedor y versión para poder auditarla.",
                hard_rule=hard,
                source="threat_feeds",
                version=settings.signalset_version,
            )
        )

    # Las coincidencias exactas de URL se mantienen separadas de los dominios:
    # una URL concreta puede estar denunciada aunque su dominio raíz no lo esté.
    for url in sorted(urls):
        if not settings.enable_threat_feeds:
            continue
        matches = db.scalars(
            select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == "url",
                ThreatIndicator.status == "active",
                ThreatIndicator.value_public == url,
            )
        ).all()
        matching_providers = sorted({match.provider for match in matches})
        if not matching_providers:
            continue
        now = datetime.now(UTC)
        fresh_providers: list[str] = []
        provider_evidence: list[dict[str, str | int | bool]] = []
        for provider in matching_providers:
            snapshot = latest_snapshot(provider)
            policy = policies.get(provider)
            if not snapshot:
                continue
            fetched_at = snapshot.fetched_at
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=UTC)
            age_seconds = max(0, int((now - fetched_at).total_seconds()))
            ttl_seconds = policy.ttl_seconds if policy else settings.threat_feed_stale_hours * 3600
            fresh = age_seconds <= ttl_seconds
            if fresh:
                fresh_providers.append(provider)
            provider_evidence.append(
                {
                    "provider": provider,
                    "version": snapshot.version,
                    "age_seconds": age_seconds,
                    "fresh": fresh,
                }
            )
        if not fresh_providers:
            continue
        hard = len(fresh_providers) >= 2 or any(
            policies.get(provider) and policies[provider].hard_rule_eligible
            for provider in fresh_providers
        )
        signals.append(
            EvidenceSignal(
                check_name="known_bad_url",
                value={"url": url, "providers": fresh_providers, "sources": provider_evidence},
                weight=100 if hard else 60,
                severity=SignalSeverity.CRITICAL if hard else SignalSeverity.WARNING,
                summary=(
                    "La URL exacta figura en fuentes actualizadas de malware o phishing."
                    if hard
                    else "Una fuente de inteligencia ha marcado esta URL concreta."
                ),
                detail="La coincidencia conserva proveedor, versión y caducidad para auditarla.",
                hard_rule=hard,
                source="threat_feeds",
                version=settings.signalset_version,
            )
        )
    return signals


def feed_health(db: Session, settings: Settings) -> list[FeedHealth]:
    now = datetime.now(UTC)
    result: list[FeedHealth] = []
    for policy in load_provider_config().providers:
        if not settings.enable_threat_feeds:
            result.append(FeedHealth(provider=policy.name, status="disabled", entries=0))
            continue
        snapshot = db.scalar(
            select(FeedSnapshot)
            .where(FeedSnapshot.provider == policy.name, FeedSnapshot.succeeded.is_(True))
            .order_by(FeedSnapshot.fetched_at.desc())
            .limit(1)
        )
        entries = db.scalar(
            select(func.count(ThreatIndicator.id)).where(
                ThreatIndicator.provider == policy.name,
                ThreatIndicator.status == "active",
            )
        ) or 0
        if not snapshot:
            result.append(FeedHealth(provider=policy.name, status="not_synced", entries=entries))
            continue
        fetched_at = snapshot.fetched_at
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=UTC)
        age = max(0, int((now - fetched_at).total_seconds()))
        stale_after = min(policy.ttl_seconds, settings.threat_feed_stale_hours * 3600)
        stale = age > stale_after
        result.append(
            FeedHealth(
                provider=policy.name,
                status="stale" if stale else "ok",
                entries=entries,
                last_success_at=fetched_at,
                age_seconds=age,
            )
        )
    return result


def clear_feed_data(db: Session, provider: str) -> None:
    """Ayuda de desarrollo; no se invoca desde la API pública."""
    db.execute(delete(ThreatIndicator).where(ThreatIndicator.provider == provider))
    db.commit()
