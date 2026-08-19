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
from pathlib import Path
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:  # pragma: no cover - solo para anotaciones
    from app.config import Settings

logger = logging.getLogger(__name__)

AUDIT_LOG_DIR = Path(__file__).resolve().parents[2] / "data" / "ct_observations"

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
        timeout: float = 10.0,
        max_retries: int = 2,
        backoff_factor: float = 2.0,
        enable_postgres_fallback: bool = True,
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
        self.enable_postgres_fallback = enable_postgres_fallback
        # Registro de resultado por consulta: distingue "no habia nada" de "no pude mirar".
        self.run_records: list[dict[str, Any]] = []

    def _record_run(
        self,
        entity_name: str,
        *,
        source: str,
        ok: bool,
        certificates: int,
        attempts: int,
        last_status: int | None = None,
        error: str | None = None,
    ) -> None:
        """Deja constancia del resultado de la consulta, haya hallazgos o no.

        Sin esto, un día con crt.sh caído produce el mismo fichero vacío que un día
        sin dominios sospechosos, y la afirmación "monitorizamos N marcas el día D"
        deja de ser demostrable.
        """
        self.run_records.append(
            {
                "entity": entity_name,
                "source": source,
                "ok": ok,
                "certificates_seen": certificates,
                "attempts": attempts,
                "last_status": last_status,
                "error": error,
                "checked_at": datetime.now(UTC).isoformat(),
            }
        )

    async def _fetch_via_postgres(self, search_token: str) -> list[dict[str, Any]] | None:
        """Respaldo por la interfaz Postgres pública de crt.sh (certwatch).

        Suele responder cuando el frontend web devuelve 502. Devuelve None si no se
        pudo usar, para distinguirlo de "consultado y sin resultados".
        """
        if not self.enable_postgres_fallback:
            return None

        def _query() -> list[dict[str, Any]] | None:
            try:
                import psycopg
            except ImportError:
                return None
            sql = (
                "SELECT ci.NAME_VALUE AS name_value, c.ID AS id, ca.NAME AS issuer_name, "
                "x509_notBefore(c.CERTIFICATE) AS not_before, "
                "x509_notAfter(c.CERTIFICATE) AS not_after "
                "FROM certificate_identity ci "
                "JOIN certificate c ON c.ID = ci.CERTIFICATE_ID "
                "JOIN ca ON ca.ID = c.ISSUER_CA_ID "
                "WHERE ci.NAME_TYPE = 'dNSName' AND lower(ci.NAME_VALUE) LIKE %s "
                "AND x509_notBefore(c.CERTIFICATE) > now() - interval '30 days' "
                "LIMIT 2000"
            )
            try:
                with psycopg.connect(
                    "postgresql://guest@crt.sh:5432/certwatch",
                    connect_timeout=4,
                ) as conn, conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 4000")
                    cur.execute(sql, (f"%{search_token}%",))
                    columns = [d[0] for d in cur.description]
                    rows = [dict(zip(columns, r, strict=True)) for r in cur.fetchall()]
            except Exception:
                return None
            for row in rows:
                for key in ("not_before", "not_after"):
                    if row.get(key) is not None:
                        row[key] = str(row[key])
                row["entry_timestamp"] = row.get("not_before")
                row["common_name"] = None
            return rows

        return await asyncio.to_thread(_query)

    async def _fetch_via_certspotter(
        self,
        entity: KnownEntity,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]] | None:
        """Respaldo mediante la API pública de CertSpotter (SSLMate).

        Se consulta para los dominios oficiales de la entidad y subdominios asociados.
        Devuelve None si hubo error en todas las peticiones para distinguirlo de 0 hallazgos.
        """
        if not entity.official_domains:
            return None

        results: list[dict[str, Any]] = []
        any_success = False

        headers = {"User-Agent": "AlertaClara/1.0 (CT-Monitor; Security Research)"}
        for domain in entity.official_domains[:2]:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer"
            try:
                response = await client.get(url, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    any_success = True
                    data = response.json()
                    if isinstance(data, list):
                        for item in data:
                            dns_names = item.get("dns_names") or []
                            issuer = item.get("issuer") or {}
                            issuer_name = issuer.get("name") or issuer.get("friendly_name") or ""
                            results.append(
                                {
                                    "id": item.get("id"),
                                    "name_value": "\n".join(dns_names),
                                    "issuer_name": issuer_name,
                                    "entry_timestamp": item.get("not_before"),
                                    "not_before": item.get("not_before"),
                                    "not_after": item.get("not_after"),
                                    "common_name": dns_names[0] if dns_names else None,
                                }
                            )
            except Exception as exc:
                logger.debug("Error en CertSpotter para %s: %s", domain, exc)

        return results if any_success else None

    async def fetch_entity_certificates(
        self,
        entity_name: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Consulta crt.sh con reintentos, backoff y respaldos por Postgres y CertSpotter."""
        entity = get_entity(entity_name)
        if not entity:
            self._record_run(
                entity_name,
                source="none",
                ok=False,
                certificates=0,
                attempts=0,
                error="entidad_desconocida",
            )
            return []

        search_token = normalize_token(entity.name)
        url = f"https://crt.sh/?q=%25{search_token}%25&output=json&exclude=expired"
        headers = {"User-Agent": "AlertaClara/1.0 (CT-Monitor; Security Research)"}

        last_status: int | None = None
        last_error: str | None = None
        attempts = 0

        for attempt in range(1, self.max_retries + 1):
            attempts = attempt
            try:
                response = await client.get(url, headers=headers, timeout=self.timeout)
                last_status = response.status_code
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            self._record_run(
                                entity_name,
                                source="crtsh_http",
                                ok=True,
                                certificates=len(data),
                                attempts=attempt,
                                last_status=last_status,
                            )
                            return data
                    except json.JSONDecodeError:
                        last_error = "respuesta_no_json"
                        logger.warning("crt.sh devolvió respuesta no-JSON para %s", entity_name)
                elif response.status_code in (429, 502, 503, 504):
                    logger.info(
                        "crt.sh respondió %d para %s (intento %d)",
                        response.status_code,
                        entity_name,
                        attempt,
                    )
            except (httpx.RequestError, TimeoutError) as exc:
                last_error = type(exc).__name__
                logger.warning(
                    "Error consultando crt.sh para %s (intento %d): %s",
                    entity_name,
                    attempt,
                    exc,
                )

            if attempt < self.max_retries:
                await asyncio.sleep(self.backoff_factor * attempt)

        fallback_pg = await self._fetch_via_postgres(search_token)
        if fallback_pg is not None:
            self._record_run(
                entity_name,
                source="crtsh_postgres",
                ok=True,
                certificates=len(fallback_pg),
                attempts=attempts,
                last_status=last_status,
            )
            return fallback_pg

        fallback_spotter = await self._fetch_via_certspotter(entity, client)
        if fallback_spotter is not None:
            self._record_run(
                entity_name,
                source="certspotter",
                ok=True,
                certificates=len(fallback_spotter),
                attempts=attempts,
                last_status=last_status,
            )
            return fallback_spotter

        # Vías agotadas: se deja constancia explícita
        self._record_run(
            entity_name,
            source="crtsh_http+postgres+certspotter",
            ok=False,
            certificates=0,
            attempts=attempts,
            last_status=last_status,
            error=f"{last_error or 'sin_respuesta_utilizable'}/todos_los_respaldos_fallidos",
        )
        return []

    async def fetch(self) -> list[ConnectorObservation]:
        """Obtiene observaciones de dominios sospechosos para las entidades objetivo."""
        observations: list[ConnectorObservation] = []
        seen_domains: set[str] = set()
        self.run_records = []

        async with httpx.AsyncClient() as client:
            for entity_name in self.target_entities:
                entity = get_entity(entity_name)
                if not entity:
                    # Una errata en CT_MONITOR_TARGET_ENTITIES no puede desaparecer
                    # en silencio: el registro debe reflejar que esa marca no se miró.
                    self._record_run(
                        entity_name,
                        source="none",
                        ok=False,
                        certificates=0,
                        attempts=0,
                        error="entidad_desconocida",
                    )
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


def append_ct_run_log(
    run_records: list[dict[str, Any]],
    audit_dir: Path | None = None,
) -> Path:
    """Sella el resultado de cada consulta del día, con o sin hallazgos.

    Es lo que permite afirmar "el día D monitorizamos N marcas y M consultas
    tuvieron éxito". Sin este registro, un fichero de observaciones vacío es
    ambiguo entre "no había nada" y "no pude consultar".
    """
    target_dir = (audit_dir or AUDIT_LOG_DIR) / "runs"
    target_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(UTC)
    daily_file = target_dir / f"{now.strftime('%Y-%m-%d')}.jsonl"

    ok_count = sum(1 for r in run_records if r.get("ok"))
    entry = {
        "run_at": now.isoformat(),
        "entities_queried": len(run_records),
        "queries_ok": ok_count,
        "queries_failed": len(run_records) - ok_count,
        "sources_used": sorted({str(r.get("source")) for r in run_records}),
        "results": run_records,
    }
    with daily_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return daily_file


def append_ct_observations_to_audit_log(
    observations: list[ConnectorObservation],
    audit_dir: Path | None = None,
) -> Path:
    """Escribe observaciones al registro inmutable diario en data/ct_observations/YYYY-MM-DD.jsonl.

    Respeta el principio: 'Registra cuando observas, nunca reconstruyas hacia atrás'.
    Cada entrada contiene timestamp ISO de observación, entidad suplantada, emisor del cert y score.
    Actualiza además el manifest.json con el hash SHA-256 del fichero para notarización git.
    """
    target_dir = audit_dir or AUDIT_LOG_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(UTC)
    date_str = now.strftime("%Y-%m-%d")
    daily_file = target_dir / f"{date_str}.jsonl"

    existing_domains: set[str] = set()
    if daily_file.exists():
        for line in daily_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entry = json.loads(line)
                    existing_domains.add(entry.get("domain", ""))
                except json.JSONDecodeError:
                    logger.debug("Línea ilegible en el registro diario de CT; se ignora")

    new_lines: list[str] = []
    for obs in observations:
        dom = obs.value
        if dom in existing_domains:
            continue
        existing_domains.add(dom)
        entry = {
            "domain": dom,
            "observed_at": (obs.retrieved_at or now).isoformat(),
            "first_seen_cert": obs.first_seen.isoformat() if obs.first_seen else None,
            "claimed_entity": (
                obs.provenance.get("claimed_entity") if obs.provenance else None
            ),
            "issuer": obs.provenance.get("issuer_name") if obs.provenance else None,
            "ct_id": obs.provenance.get("ct_id") if obs.provenance else None,
            "risk_score": obs.confidence,
            "status": obs.status,
            "verification": {
                "source": None,
                "confirmed_at": None,
                "lead_time_days": None,
                "active_clone": False,
                "evidence_hash": None,
            },
        }
        new_lines.append(json.dumps(entry, ensure_ascii=False))

    if new_lines:
        with daily_file.open("a", encoding="utf-8") as f:
            for nl in new_lines:
                f.write(f"{nl}\n")

    manifest_file = target_dir / "manifest.json"
    manifest: dict[str, Any] = {"updated_at": now.isoformat(), "daily_files": {}}
    if manifest_file.exists():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest["updated_at"] = now.isoformat()
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Manifest de CT ilegible, se regenera: %s", exc)

    total_count = 0
    daily_files_meta: dict[str, Any] = {}
    for jsonl_path in sorted(target_dir.glob("**/*.jsonl")):
        content = jsonl_path.read_bytes()
        file_sha256 = hashlib.sha256(content).hexdigest()
        count = len(
            [
                line
                for line in content.decode("utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
        )
        total_count += count
        relative_name = jsonl_path.relative_to(target_dir).as_posix()
        daily_files_meta[relative_name] = {
            "sha256": file_sha256,
            "entry_count": count,
            "size_bytes": len(content),
        }

    manifest["total_observations"] = total_count
    manifest["daily_files"] = daily_files_meta
    manifest_file.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    return daily_file


def store_ct_observations(
    observations: list[ConnectorObservation],
    version: str = "1.0.0",
    audit_dir: Path | None = None,
) -> int:
    """Persiste observaciones de CT en FeedSnapshot, ThreatIndicator y registro git."""
    if not observations:
        return 0

    # 1. Escribir al registro inmutable diario git
    try:
        append_ct_observations_to_audit_log(observations, audit_dir=audit_dir)
    except Exception as exc:
        logger.warning("No se pudo escribir al registro de auditoría CT: %s", exc)

    # 2. Persistir en base de datos
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

    # El sellado de la ronda es independiente de que haya hallazgos: es la prueba
    # de que ese día se miró, y de si crt.sh respondió o no.
    if connector.run_records:
        try:
            await asyncio.to_thread(append_ct_run_log, connector.run_records)
        except Exception as exc:  # nunca debe tumbar la recolección
            logger.warning("No se pudo sellar el registro de ejecución CT: %s", exc)

    if not observations:
        try:
            await asyncio.to_thread(append_ct_observations_to_audit_log, [])
        except Exception as exc:
            logger.warning("No se pudo actualizar el manifest CT: %s", exc)
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

