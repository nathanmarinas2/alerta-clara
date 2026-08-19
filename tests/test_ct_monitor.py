from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from app.connectors import Connector
from app.entities import get_entity
from app.services.ct_monitor import (
    CertificateTransparencyConnector,
    calculate_ct_risk_score,
    is_valid_hostname,
    measure_early_warning_lead_time_seconds,
    parse_ct_timestamp,
)


def test_is_valid_hostname_filters_corporate_names_and_invalid_strings() -> None:
    assert is_valid_hostname("caixabank-seguridad.top") is True
    assert is_valid_hostname("*.login-bbva.xyz") is True
    assert is_valid_hostname("sub.dominio.bancosantander.es") is True

    # Nombres corporativos que aparecen en campos CN de certificados OV/EV
    assert is_valid_hostname("CaixaBank SA") is False
    assert is_valid_hostname("caixabank asset management sgiic, s.a") is False
    assert is_valid_hostname("secb-fine sindicato de empleados de caixabank") is False
    assert is_valid_hostname("localhost") is False
    assert is_valid_hostname("") is False


def test_parse_ct_timestamp() -> None:
    ts = parse_ct_timestamp("2026-08-18T14:30:00")
    assert ts is not None
    assert ts.year == 2026
    assert ts.month == 8
    assert ts.day == 18

    assert parse_ct_timestamp(None) is None
    assert parse_ct_timestamp("invalido") is None


def test_calculate_ct_risk_score_discriminates_dv_and_corporate_issuers() -> None:
    entity = get_entity("CaixaBank")
    assert entity is not None

    now = datetime.now(UTC)

    # Caso 1: Certificado Let's Encrypt DV reciente en TLD riesgoso para phishing
    score_phish = calculate_ct_risk_score(
        domain="caixabank-alerta.top",
        entity=entity,
        issuer_name="C=US, O=Let's Encrypt, CN=R3",
        entry_timestamp=now - timedelta(hours=2),
    )
    assert score_phish >= 0.80

    # Caso 2: Certificado corporativo Sectigo OV para un subdominio/portal
    score_corp = calculate_ct_risk_score(
        domain="caixabank-evento.org",
        entity=entity,
        issuer_name="C=GB, O=Sectigo Limited, CN=Sectigo RSA Organization Validation",
        entry_timestamp=now - timedelta(days=30),
    )
    assert score_corp < score_phish


def test_measure_early_warning_lead_time_seconds() -> None:
    first_seen = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)
    received = datetime(2026, 8, 18, 12, 30, 0, tzinfo=UTC)
    delta = measure_early_warning_lead_time_seconds(received, first_seen)
    assert delta == 9000.0  # 2.5 horas = 9000 segundos


def test_ct_connector_implements_connector_protocol() -> None:
    connector = CertificateTransparencyConnector()
    assert isinstance(connector, Connector)
    assert connector.name == "crtsh_ct"
    assert connector.version == "1.0.0"


@pytest.mark.asyncio
async def test_ct_connector_fetch_filters_official_domains_and_emits_observations() -> None:
    mock_payload = [
        {
            "id": 123456,
            "entry_timestamp": "2026-08-18T10:00:00",
            "not_before": "2026-08-18T09:00:00",
            "not_after": "2026-11-18T09:00:00",
            "common_name": "caixabank-seguridad.top",
            "name_value": "caixabank-seguridad.top\n*.caixabank-seguridad.top\nCaixaBank SA",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        },
        {
            "id": 123457,
            "entry_timestamp": "2026-08-18T11:00:00",
            "not_before": "2026-08-18T10:00:00",
            "not_after": "2027-08-18T10:00:00",
            "common_name": "caixabank.com",
            "name_value": "caixabank.com\nwww.caixabank.com",
            "issuer_name": "C=GB, O=Sectigo Limited",
        },
    ]

    connector = CertificateTransparencyConnector(target_entities=["CaixaBank"])

    with patch.object(connector, "fetch_entity_certificates", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = mock_payload
        observations = await connector.fetch()

        # Descarta 'CaixaBank SA' (no FQDN) y 'caixabank.com' (dominio oficial)
        assert len(observations) == 1
        obs = observations[0]
        assert obs.provider == "crtsh_ct"
        assert obs.indicator_type == "domain"
        assert obs.value == "caixabank-seguridad.top"
        assert obs.confidence is not None and obs.confidence >= 0.70
        assert obs.provenance["claimed_entity"] == "CaixaBank"
        assert obs.provenance["ct_id"] == 123456


def test_store_ct_observations_writes_snapshot_and_indicators() -> None:
    from app.connectors import ConnectorObservation
    from app.database import SessionLocal, create_tables
    from app.models import FeedSnapshot, ThreatIndicator
    from app.services.ct_monitor import store_ct_observations

    create_tables()
    obs = ConnectorObservation(
        provider="crtsh_ct",
        indicator_type="domain",
        value="caixabank-alerta-sms.xyz",
        status="active",
        confidence=0.85,
        first_seen=datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC),
        last_seen=datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC),
        version="1.0.0",
        provenance={"claimed_entity": "CaixaBank"},
    )
    count = store_ct_observations([obs])
    assert count == 1

    with SessionLocal() as db:
        from sqlalchemy import select

        snapshot = db.scalar(
            select(FeedSnapshot)
            .where(FeedSnapshot.provider == "crtsh_ct")
            .order_by(FeedSnapshot.fetched_at.desc())
        )
        assert snapshot is not None
        assert snapshot.succeeded is True
        assert snapshot.entry_count == 1

        indicator = db.scalar(
            select(ThreatIndicator).where(
                ThreatIndicator.provider == "crtsh_ct",
                ThreatIndicator.value_public == "caixabank-alerta-sms.xyz",
            )
        )
        assert indicator is not None
        assert indicator.status == "active"


@pytest.mark.asyncio
async def test_sync_ct_monitor_integration() -> None:
    from app.config import Settings
    from app.database import create_tables
    from app.services.ct_monitor import sync_ct_monitor

    create_tables()
    settings = Settings(
        enable_ct_monitor=True,
        ct_monitor_target_entities="CaixaBank",
    )
    mock_payload = [
        {
            "id": 999999,
            "entry_timestamp": "2026-08-18T15:00:00",
            "not_before": "2026-08-18T14:00:00",
            "not_after": "2026-11-18T14:00:00",
            "common_name": "caixabank-portal-verificacion.top",
            "name_value": "caixabank-portal-verificacion.top",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        }
    ]
    with patch(
        "app.services.ct_monitor.CertificateTransparencyConnector.fetch_entity_certificates",
        new_callable=AsyncMock,
    ) as mock_fetch:
        mock_fetch.return_value = mock_payload
        count = await sync_ct_monitor(settings)
        assert count == 1

