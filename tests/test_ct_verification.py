import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.connectors import ConnectorObservation
from app.database import SessionLocal, create_tables
from app.models import FeedSnapshot, ThreatIndicator
from app.services.ct_monitor import append_ct_observations_to_audit_log, append_ct_run_log
from app.services.ct_verification import (
    calculate_lead_time_metrics,
    cross_reference_threat_feeds,
    verify_active_clone_playwright,
)
from app.services.threat_intel import indicator_hash


@pytest.fixture
def temp_audit_dir(tmp_path: Path) -> Path:
    audit_dir = tmp_path / "ct_observations"
    audit_dir.mkdir()
    return audit_dir


def test_append_ct_observations_writes_daily_file_and_manifest(temp_audit_dir: Path) -> None:
    now = datetime.now(UTC)
    obs1 = ConnectorObservation(
        provider="crtsh_ct",
        indicator_type="domain",
        value="bbva-seguridad-alerta.xyz",
        status="active",
        confidence=0.85,
        first_seen=now - timedelta(hours=2),
        last_seen=now,
        retrieved_at=now,
        version="1.0.0",
        provenance={
            "claimed_entity": "BBVA",
            "issuer_name": "Let's Encrypt",
            "ct_id": 99881122,
        },
    )
    obs2 = ConnectorObservation(
        provider="crtsh_ct",
        indicator_type="domain",
        value="caixabank-recibo-pago.top",
        status="active",
        confidence=0.90,
        first_seen=now - timedelta(hours=1),
        last_seen=now,
        retrieved_at=now,
        version="1.0.0",
        provenance={
            "claimed_entity": "CaixaBank",
            "issuer_name": "ZeroSSL",
            "ct_id": 99881123,
        },
    )

    daily_file = append_ct_observations_to_audit_log([obs1, obs2], audit_dir=temp_audit_dir)
    assert daily_file.exists()

    lines = [
        json.loads(line)
        for line in daily_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 2
    assert lines[0]["domain"] == "bbva-seguridad-alerta.xyz"
    assert lines[0]["claimed_entity"] == "BBVA"
    assert lines[0]["issuer"] == "Let's Encrypt"

    manifest_file = temp_audit_dir / "manifest.json"
    assert manifest_file.exists()
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest["total_observations"] == 2
    assert daily_file.name in manifest["daily_files"]
    assert manifest["daily_files"][daily_file.name]["entry_count"] == 2
    assert len(manifest["daily_files"][daily_file.name]["sha256"]) == 64


def test_manifest_does_not_count_query_runs_as_domain_observations(
    temp_audit_dir: Path,
) -> None:
    append_ct_run_log(
        [
            {
                "entity": "BBVA",
                "source": "crtsh_http",
                "ok": False,
                "certificates_seen": 0,
            }
        ],
        audit_dir=temp_audit_dir,
    )

    append_ct_observations_to_audit_log([], audit_dir=temp_audit_dir)
    manifest = json.loads((temp_audit_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["total_observations"] == 0
    assert manifest["daily_files"] == {}


@pytest.mark.asyncio
async def test_verify_active_clone_playwright_detects_credentials() -> None:
    mock_payload = {
        "password_fields": 1,
        "payment_fields": 0,
        "download_attempted": False,
        "final_url": "https://santander-acceso.xyz/login.php",
    }
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = lambda: mock_payload
        mock_post.return_value = mock_response

        result = await verify_active_clone_playwright(
            domain="santander-acceso.xyz",
            claimed_entity="Banco Santander",
        )
        assert result["is_active_clone"] is True
        assert result["password_fields"] == 1
        assert result["verification_source"] == "playwright_active_sandbox"
        assert result["confirmed_at"] is not None
        assert result["evidence_hash"] is not None


def test_cross_reference_threat_feeds_computes_delta_t(temp_audit_dir: Path) -> None:
    create_tables()
    now = datetime.now(UTC)
    obs_date = now - timedelta(days=5)  # CT vio el dominio hace 5 días

    obs = ConnectorObservation(
        provider="crtsh_ct",
        indicator_type="domain",
        value="correos-tasa-aduanas.site",
        status="active",
        confidence=0.85,
        first_seen=obs_date,
        last_seen=obs_date,
        retrieved_at=obs_date,
        version="1.0.0",
        provenance={"claimed_entity": "Correos", "issuer_name": "Let's Encrypt"},
    )
    append_ct_observations_to_audit_log([obs], audit_dir=temp_audit_dir)

    # Insertar indicador de URLhaus registrado hoy (5 días después de CT)
    with SessionLocal() as db:
        snap = FeedSnapshot(
            provider="urlhaus",
            version="1.0",
            checksum="testhash",
            entry_count=1,
            fetched_at=now,
            succeeded=True,
        )
        db.add(snap)
        db.flush()

        ind = ThreatIndicator(
            id="test-urlhaus-ind-1",
            provider="urlhaus",
            snapshot_id=snap.id,
            indicator_type="domain",
            value_hash=indicator_hash("correos-tasa-aduanas.site"),
            value_public="correos-tasa-aduanas.site",
            status="active",
            first_seen=now,  # Feed público lo publica hoy
            last_seen=now,
        )
        db.merge(ind)
        db.commit()

    matches = cross_reference_threat_feeds(audit_dir=temp_audit_dir)
    assert len(matches) == 1
    assert matches[0]["domain"] == "correos-tasa-aduanas.site"
    assert matches[0]["feed_provider"] == "urlhaus"
    # Delta-t debe ser aproximadamente 5 días
    assert 4.8 <= matches[0]["lead_time_days"] <= 5.2

    metrics = calculate_lead_time_metrics(audit_dir=temp_audit_dir)
    assert metrics["total_domains_monitored"] == 1
    assert metrics["corroborated_phishing_domains"] == 1
    assert 4.8 <= metrics["lead_time_summary"]["mean_days"] <= 5.2
    assert metrics["lead_time_summary"]["advance_detection_rate_pct"] == 100.0
