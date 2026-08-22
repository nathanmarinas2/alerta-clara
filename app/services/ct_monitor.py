"""Conector de Certificate Transparency (CT) vía crt.sh para detección temprana.

Implementa el protocolo Connector definido en app/connectors.py.
Vigila emisiones de certificados recientes que contengan tokens de entidades
conocidas, discriminando entre certificados corporativos legítimos (OV/EV) y
certificados de campaña fraudulentos (DV recientes en dominios no oficiales).
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

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

PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv"

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


def is_campaign_plausible(domain: str, entity: KnownEntity, issuer_name: str) -> bool:
    """Reduce ruido exigiendo emisores DV automatizados para candidatos de campaña."""
    issuer_lower = issuer_name.casefold()
    return any(issuer in issuer_lower for issuer in AUTOMATED_DV_ISSUERS)


def references_entity(domain: str, entity: KnownEntity) -> bool:
    """Comprueba que el dominio menciona o se parece a la entidad consultada."""
    tokens = {
        normalize_token(alias)
        for alias in (entity.name, *entity.aliases)
        if len(normalize_token(alias)) >= 4
    }
    if any(token in normalize_token(domain) for token in tokens):
        return True
    similarity = max(
        (domain_similarity(domain, official) for official in entity.official_domains),
        default=0.0,
    )
    return similarity >= 0.82


class CertificateTransparencyConnector:
    """Conector para recopilar y filtrar candidatos de suplantación en Certificate Transparency."""

    name: str = "crtsh_ct"
    version: str = "1.0.0"

    def __init__(
        self,
        target_entities: list[str] | None = None,
        timeout: float = 12.0,
        max_retries: int = 2,
        backoff_factor: float = 2.0,
        enable_postgres_fallback: bool = True,
        max_concurrency: int = 4,
        min_confidence: float = 0.5,
        enable_phishing_feed: bool = True,
        phishing_feed_url: str = PHISHTANK_FEED_URL,
        phishing_feed_timeout: float = 20.0,
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
        self.max_concurrency = max(1, max_concurrency)
        self.min_confidence = min_confidence
        self.enable_phishing_feed = enable_phishing_feed
        self.phishing_feed_url = phishing_feed_url
        self.phishing_feed_timeout = max(5.0, phishing_feed_timeout)
        self._phishing_feed_rows: list[dict[str, str]] | None = None
        self._phishing_feed_loaded = False
        self._phishing_feed_error: str | None = None
        self._phishing_feed_lock: asyncio.Lock | None = None
        # Registro de resultado por consulta: distingue "no habia nada" de "no pude mirar".
        self.run_records: list[dict[str, Any]] = []
        self.last_run_duration_seconds = 0.0

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
                    connect_timeout=3,
                ) as conn, conn.cursor() as cur:
                    cur.execute("SET statement_timeout = 3000")
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

    async def _fetch_via_phishtank(
        self,
        entity: KnownEntity,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]] | None:
        """Obtiene dominios verificados de PhishTank como respaldo de disponibilidad.

        PhishTank no es un sustituto de CT: aporta URLs que ya han sido verificadas
        como phishing. Se usa únicamente cuando crt.sh/Postgres no responden (o
        devuelven un conjunto vacío), y se filtra por marca o por el campo ``target``
        del propio feed. El CSV se descarga una sola vez por ronda, aunque fallen las
        diez consultas de entidades.
        """
        if not self.enable_phishing_feed:
            return None

        if self._phishing_feed_lock is None:
            self._phishing_feed_lock = asyncio.Lock()
        async with self._phishing_feed_lock:
            if not self._phishing_feed_loaded:
                self._phishing_feed_loaded = True
                try:
                    response = await client.get(
                        self.phishing_feed_url,
                        headers={"User-Agent": "AlertaClara/1.0 (verified-phishing-feed)"},
                        timeout=self.phishing_feed_timeout,
                        follow_redirects=True,
                    )
                    response.raise_for_status()
                    if len(response.content) > 25 * 1024 * 1024:
                        raise ValueError("feed_demasiado_grande")

                    rows: list[dict[str, str]] = []
                    for row in csv.DictReader(response.text.splitlines()):
                        if (
                            str(row.get("verified", "")).casefold() != "yes"
                            or str(row.get("online", "")).casefold() != "yes"
                        ):
                            continue
                        raw_url = str(row.get("url", "")).strip()
                        host = (urlsplit(raw_url).hostname or "").rstrip(".").casefold()
                        if not host or "." not in host:
                            continue
                        rows.append(
                            {
                                "domain": host,
                                "url": raw_url,
                                "phish_id": str(row.get("phish_id", "")),
                                "target": str(row.get("target", "")),
                                "submission_time": str(row.get("submission_time", "")),
                                "detail_url": str(row.get("phish_detail_url", "")),
                            }
                        )
                    self._phishing_feed_rows = rows
                except (httpx.HTTPError, ValueError, csv.Error) as exc:
                    self._phishing_feed_error = type(exc).__name__
                    logger.warning("No se pudo descargar PhishTank: %s", exc)
                    self._phishing_feed_rows = None

        rows = self._phishing_feed_rows
        if rows is None:
            return None

        entity_tokens = {
            normalize_token(alias)
            for alias in (entity.name, *entity.aliases)
            if len(normalize_token(alias)) >= 3
        }
        matches: list[dict[str, Any]] = []
        for row in rows:
            host = row["domain"]
            host_token = normalize_token(host)
            target = normalize_token(row["target"])
            target_match = any(
                token == target or (len(token) >= 4 and token in target)
                for token in entity_tokens
                if token
            )
            domain_match = any(
                len(token) >= 4 and token in host_token for token in entity_tokens
            )
            if not domain_match and not target_match:
                continue
            domain = registrable_domain(host)
            if not domain:
                continue
            if is_official_domain(domain, entity):
                continue
            if not references_entity(domain, entity) and not target_match:
                continue
            matches.append(
                {
                    "id": f"phishtank:{row['phish_id']}:{domain}",
                    "name_value": domain,
                    "issuer_name": "PhishTank verified",
                    "entry_timestamp": row["submission_time"],
                    "not_before": row["submission_time"],
                    "common_name": row["url"],
                    "phish_id": row["phish_id"],
                    "detail_url": row["detail_url"],
                    "_target_match": target_match,
                    "_source": "phishtank",
                }
            )
        return matches

    async def fetch_entity_certificates(
        self,
        entity_name: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """Consulta crt.sh y usa Postgres/PhishTank cuando el proveedor falla."""
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
                            data = [item for item in data if isinstance(item, dict)]
                            if data:
                                self._record_run(
                                    entity_name,
                                    source="crtsh_http",
                                    ok=True,
                                    certificates=len(data),
                                    attempts=attempt,
                                    last_status=last_status,
                                )
                                return data
                            last_error = "crtsh_sin_certificados"
                    except (ValueError, TypeError):
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

        fallback = await self._fetch_via_postgres(search_token)
        if fallback:
            self._record_run(
                entity_name,
                source="crtsh_postgres",
                ok=True,
                certificates=len(fallback),
                attempts=attempts,
                last_status=last_status,
            )
            return fallback
        if fallback == []:
            last_error = "postgres_sin_certificados"

        # PhishTank no busca por marca en CT, pero sí aporta dominios ya verificados
        # como phishing. Es mejor evidencia accionable que devolver siempre cero cuando
        # crt.sh está caído; la procedencia queda explícita en cada observación.
        entity = get_entity(entity_name)
        phishing_matches = (
            await self._fetch_via_phishtank(entity, client) if entity is not None else None
        )
        if phishing_matches:
            self._record_run(
                entity_name,
                source="phishtank",
                ok=True,
                certificates=len(phishing_matches),
                attempts=attempts,
                last_status=last_status,
            )
            return phishing_matches

        # Ambas vías agotadas: se deja constancia explícita de que se intentaron las dos,
        # para que el registro diario distinga "no había nada" de "no se pudo consultar".
        fallback_note = (
            "respaldo_postgres_fallido"
            if self.enable_postgres_fallback
            else "respaldo_postgres_desactivado"
        )
        phishing_note = (
            "feed_phishtank_sin_coincidencias"
            if phishing_matches == []
            else f"feed_phishtank_fallido:{self._phishing_feed_error}"
            if self.enable_phishing_feed
            else "feed_phishtank_desactivado"
        )
        self._record_run(
            entity_name,
            source="crtsh_http+postgres+phishtank",
            ok=False,
            certificates=0,
            attempts=attempts,
            last_status=last_status,
            error=f"{last_error or 'sin_respuesta_utilizable'}/{fallback_note}/{phishing_note}",
        )
        return []

    async def fetch(self) -> list[ConnectorObservation]:
        """Obtiene observaciones de dominios sospechosos para las entidades objetivo."""
        started = perf_counter()
        observations: list[ConnectorObservation] = []
        seen_domains: set[str] = set()
        self.run_records = []

        async with httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=self.max_concurrency,
                max_keepalive_connections=self.max_concurrency,
            )
        ) as client:
            semaphore = asyncio.Semaphore(self.max_concurrency)

            async def fetch_one(entity_name: str) -> tuple[str, list[dict[str, Any]]]:
                async with semaphore:
                    try:
                        return entity_name, await self.fetch_entity_certificates(
                            entity_name, client
                        )
                    except Exception as exc:  # una entidad no debe tumbar la ronda
                        logger.exception("Error inesperado consultando %s", entity_name)
                        self._record_run(
                            entity_name,
                            source="internal",
                            ok=False,
                            certificates=0,
                            attempts=0,
                            error=f"{type(exc).__name__}: {exc}",
                        )
                        return entity_name, []

            results = await asyncio.gather(
                *(fetch_one(entity_name) for entity_name in self.target_entities)
            )
            certs_by_entity = dict(results)

            # PhishTank también se consulta cuando crt.sh respondió correctamente:
            # un 200 con certificados legítimos no debe ocultar dominios ya verificados
            # como phishing. El feed está cacheado, así que solo se descarga una vez.
            records_by_entity = {
                str(record.get("entity")): record for record in self.run_records
            }
            supplement_entities = [
                entity_name
                for entity_name in self.target_entities
                if get_entity(entity_name)
                and entity_name in records_by_entity
                and "phishtank" not in str(records_by_entity[entity_name].get("source"))
            ]
            if self.enable_phishing_feed and supplement_entities:
                supplements = await asyncio.gather(
                    *(
                        self._fetch_via_phishtank(get_entity(entity_name), client)
                        for entity_name in supplement_entities
                    )
                )
                for entity_name, feed_rows in zip(
                    supplement_entities, supplements, strict=True
                ):
                    record = records_by_entity[entity_name]
                    source = str(record.get("source"))
                    if "+phishtank" not in source:
                        record["source"] = f"{source}+phishtank"
                    if feed_rows:
                        certs_by_entity[entity_name] = [
                            *certs_by_entity.get(entity_name, []),
                            *feed_rows,
                        ]
                        record["certificates_seen"] = int(
                            record.get("certificates_seen") or 0
                        ) + len(feed_rows)
                    elif feed_rows is None and self._phishing_feed_error:
                        record["error"] = (
                            f"{record.get('error') or 'sin_error_ct'}/"
                            f"feed_phishtank_fallido:{self._phishing_feed_error}"
                        )

            # La concurrencia no debe cambiar el orden probatorio de las entidades.
            entity_order = {name: index for index, name in enumerate(self.target_entities)}
            self.run_records.sort(
                key=lambda record: entity_order.get(
                    str(record.get("entity")), len(entity_order)
                )
            )

            for entity_name in self.target_entities:
                entity = get_entity(entity_name)
                if not entity:
                    continue

                now = datetime.now(UTC)
                for cert in certs_by_entity.get(entity_name, []):
                    if not isinstance(cert, dict):
                        continue
                    name_value = cert.get("name_value") or ""
                    if not isinstance(name_value, str):
                        continue
                    issuer_name = str(cert.get("issuer_name") or "")
                    source = str(cert.get("_source") or "crtsh")
                    entry_ts = parse_ct_timestamp(cert.get("entry_timestamp"))

                    for raw_name in name_value.split("\n"):
                        raw_name = raw_name.strip()
                        if not is_valid_hostname(raw_name):
                            continue

                        dom = registrable_domain(raw_name)
                        if not dom or dom in seen_domains:
                            continue

                        # Descartar propiedades oficiales legítimas y ruido ajeno.
                        if is_official_domain(dom, entity):
                            continue
                        if not references_entity(dom, entity) and not (
                            source == "phishtank" and cert.get("_target_match")
                        ):
                            continue
                        if source != "phishtank" and not is_campaign_plausible(
                            dom, entity, issuer_name
                        ):
                            continue

                        confidence = calculate_ct_risk_score(dom, entity, issuer_name, entry_ts)
                        if source == "phishtank":
                            # El feed ya exige verificación y estado online; no depende
                            # de que el certificado exponga el emisor DV.
                            confidence = max(confidence, 0.80)
                        if confidence < self.min_confidence:
                            continue
                        seen_domains.add(dom)

                        observations.append(
                            ConnectorObservation(
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
                                    "source": source,
                                    "issuer_name": issuer_name,
                                    "common_name": cert.get("common_name"),
                                    "not_before": cert.get("not_before"),
                                    "not_after": cert.get("not_after"),
                                    "ct_id": cert.get("id"),
                                    "phish_id": cert.get("phish_id"),
                                    "feed_detail_url": cert.get("detail_url"),
                                },
                                retryable=False,
                            )
                        )

        self.last_run_duration_seconds = round(perf_counter() - started, 3)
        return observations


def append_ct_run_log(
    run_records: list[dict[str, Any]],
    audit_dir: Path | None = None,
    duration_seconds: float | None = None,
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
    if duration_seconds is not None:
        entry["duration_seconds"] = round(max(0.0, duration_seconds), 3)
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
    # Los resultados de consultas viven en runs/ y no son dominios observados.
    for jsonl_path in sorted(target_dir.glob("*.jsonl")):
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
    connector = CertificateTransparencyConnector(
        target_entities=entities,
        timeout=settings.ct_monitor_timeout_seconds,
        max_retries=settings.ct_monitor_max_retries,
        backoff_factor=settings.ct_monitor_backoff_seconds,
        max_concurrency=settings.ct_monitor_max_concurrency,
        min_confidence=getattr(settings, "ct_min_confidence", 0.5),
        enable_phishing_feed=settings.enable_phishing_feed,
        phishing_feed_url=settings.phishing_feed_url,
        phishing_feed_timeout=settings.phishing_feed_timeout_seconds,
    )
    observations = await connector.fetch()

    # El sellado de la ronda es independiente de que haya hallazgos: es la prueba
    # de que ese día se miró, y de si crt.sh respondió o no.
    if connector.run_records:
        try:
            await asyncio.to_thread(
                append_ct_run_log,
                connector.run_records,
                None,
                connector.last_run_duration_seconds,
            )
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

