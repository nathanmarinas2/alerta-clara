import pytest

from app.config import Settings
from app.schemas import (
    EvidenceSignal,
    MessageExtraction,
    RequestedAction,
    SignalSeverity,
    SignalStatus,
    VerdictLevel,
)
from app.services.rules import decide
from app.services.signals import SignalCollector


@pytest.mark.asyncio
async def test_remote_access_is_hard_scam_rule() -> None:
    extraction = MessageExtraction(
        body_text="Instala AnyDesk para que el técnico pueda ayudarte",
        requested_action=RequestedAction.INSTALL_APP,
    )
    signals = await SignalCollector(Settings(enable_network_checks=False)).collect(extraction)
    result = decide(extraction, signals)

    assert result.level == VerdictLevel.SCAM
    assert any(signal.hard_rule for signal in signals)


@pytest.mark.asyncio
async def test_risky_impersonation_accumulates_to_scam() -> None:
    extraction = MessageExtraction(
        body_text="CaixaBank: cuenta bloqueada. Verifica tus datos en 24 horas",
        urls=["https://caixabank-seguridad.top/acceso"],
        claimed_entity="CaixaBank",
        requested_action=RequestedAction.GIVE_CREDENTIALS,
        urgency_markers=["bloqueada", "24 horas"],
    )
    signals = await SignalCollector(Settings(enable_network_checks=False)).collect(extraction)
    result = decide(extraction, signals)

    assert result.level == VerdictLevel.SCAM
    assert result.score == 100


@pytest.mark.asyncio
async def test_neutral_message_never_returns_safe() -> None:
    extraction = MessageExtraction(body_text="Su cita está confirmada para el martes")
    signals = await SignalCollector(Settings(enable_network_checks=False)).collect(extraction)
    result = decide(extraction, signals)

    assert result.level == VerdictLevel.UNCERTAIN
    assert "seguro" in result.summary.casefold()


@pytest.mark.asyncio
async def test_cyrillic_homograph_is_detected_as_hard_rule() -> None:
    extraction = MessageExtraction(
        body_text="Santander: acceda para confirmar sus datos",
        urls=["https://sаntander.com/login"],  # La segunda letra es una a cirílica.
        claimed_entity="Banco Santander",
        requested_action=RequestedAction.GIVE_CREDENTIALS,
    )
    signals = await SignalCollector(Settings(enable_network_checks=False)).collect(extraction)

    assert any(
        signal.check_name == "claimed_entity_domain_mismatch" and signal.hard_rule
        for signal in signals
    )


@pytest.mark.asyncio
async def test_local_url_checks_detect_ip_and_suspicious_path() -> None:
    extraction = MessageExtraction(
        body_text="Accede para actualizar tu cuenta en http://198.51.100.42/login/cuenta",
        urls=["http://198.51.100.42/login/cuenta"],
        requested_action=RequestedAction.GIVE_CREDENTIALS,
    )
    signals = await SignalCollector(Settings(enable_network_checks=False)).collect(extraction)
    active = {
        signal.check_name for signal in signals if signal.status == SignalStatus.HIT
    }

    assert {"raw_ip_hostname", "phishing_url_keywords"} <= active
    assert any(signal.status == SignalStatus.NOT_APPLICABLE for signal in signals)


def test_failed_signal_can_never_fire_a_rule() -> None:
    extraction = MessageExtraction(body_text="Mensaje sin hechos verificables")
    failed = EvidenceSignal(
        check_name="provider_failure",
        value=None,
        weight=100,
        severity=SignalSeverity.CRITICAL,
        summary="Proveedor no disponible",
        hard_rule=True,
        status=SignalStatus.TIMEOUT,
    )

    decision = decide(extraction, [failed], ruleset_version="test")

    assert decision.level == VerdictLevel.UNCERTAIN
    assert decision.score == 0
    assert all(rule.status == "not_fired" for rule in decision.rules)


def test_repeated_check_is_scored_only_once() -> None:
    extraction = MessageExtraction(body_text="Dos enlaces con el mismo tipo de indicio")
    signals = [
        EvidenceSignal(
            check_name="risky_tld",
            value=domain,
            weight=35,
            severity=SignalSeverity.WARNING,
            summary="Dominio de riesgo",
        )
        for domain in ("one.top", "two.top", "three.top")
    ]

    decision = decide(extraction, signals)

    assert decision.score == 35
    assert decision.level == VerdictLevel.UNCERTAIN


def test_shared_infrastructure_suppresses_only_noisy_technical_signal() -> None:
    extraction = MessageExtraction(body_text="Formulario", urls=["https://forms.gle/example"])
    context = EvidenceSignal(
        check_name="shared_infrastructure_context",
        value={"domain": "forms.gle"},
        summary="Infraestructura compartida",
    )
    noisy = EvidenceSignal(
        check_name="high_domain_entropy",
        value={"domain": "forms.gle", "entropy": 4.1},
        weight=20,
        severity=SignalSeverity.WARNING,
        summary="Dominio poco natural",
    )
    content = EvidenceSignal(
        check_name="requested_action",
        value="introducir_credenciales",
        weight=55,
        severity=SignalSeverity.WARNING,
        summary="Solicita credenciales",
    )

    decision = decide(extraction, [context, noisy, content])

    assert noisy.status == SignalStatus.SUPPRESSED
    assert content.status == SignalStatus.HIT
    assert decision.score == 55
    suppression = next(
        rule for rule in decision.rules if rule.rule_id == "shared_infrastructure_suppression"
    )
    assert suppression.suppressed_signal_names == ["high_domain_entropy"]
