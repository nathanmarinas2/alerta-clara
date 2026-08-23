from app.config import Settings
from app.schemas import SignalSeverity, SignalStatus
from app.services.alias_registry import (
    find_alias_in_registry,
    is_alphanumeric_sender,
    verify_sender_alias,
)


def test_is_alphanumeric_sender_classification() -> None:
    # Remitentes alfanuméricos (sujetos a registro CNMC)
    assert is_alphanumeric_sender("CaixaBank") is True
    assert is_alphanumeric_sender("BBVA") is True
    assert is_alphanumeric_sender("CORREOS") is True
    assert is_alphanumeric_sender("DGT") is True
    assert is_alphanumeric_sender("SMS-INFO") is True

    # Remitentes numéricos estándar (no son alias alfanuméricos)
    assert is_alphanumeric_sender("+34612345678") is False
    assert is_alphanumeric_sender("612345678") is False
    assert is_alphanumeric_sender("900102801") is False
    assert is_alphanumeric_sender("+34 600 000 000") is False
    assert is_alphanumeric_sender(None) is False
    assert is_alphanumeric_sender("") is False


def test_find_alias_in_registry() -> None:
    record = find_alias_in_registry("CaixaBank")
    assert record is not None
    assert record.holder_name == "CaixaBank, S.A."
    assert record.cif_nif == "A08663619"
    assert "CaixaBank" in record.authorized_entities

    # Case insensitivity
    record_lower = find_alias_in_registry("caixabank")
    assert record_lower is not None
    assert record_lower.holder_name == "CaixaBank, S.A."

    # Alias inexistente
    assert find_alias_in_registry("BancoFalso123") is None


def test_verify_sender_alias_verified_match() -> None:
    settings = Settings(enable_cnmc_alias_registry=True)
    signals = verify_sender_alias(
        sender="CaixaBank",
        claimed_entity_name="CaixaBank",
        settings=settings,
    )
    assert len(signals) == 1
    sig = signals[0]
    assert sig.check_name == "cnmc_alias_verified"
    assert sig.severity == SignalSeverity.INFO
    assert sig.weight == 0
    assert sig.status == SignalStatus.HIT
    assert "CaixaBank, S.A." in sig.summary


def test_verify_sender_alias_mismatch_hard_rule() -> None:
    settings = Settings(enable_cnmc_alias_registry=True)
    # Remitente CORREOS pero el mensaje dice ser CaixaBank
    signals = verify_sender_alias(
        sender="CORREOS",
        claimed_entity_name="CaixaBank",
        settings=settings,
    )
    assert len(signals) == 1
    sig = signals[0]
    assert sig.check_name == "cnmc_alias_mismatch"
    assert sig.hard_rule is True
    assert sig.weight == 100
    assert sig.severity == SignalSeverity.CRITICAL
    assert "Suplantación probada" in sig.summary


def test_verify_sender_alias_unregistered_is_non_destructive() -> None:
    settings = Settings(enable_cnmc_alias_registry=True)
    signals = verify_sender_alias(
        sender="EmpresaDesconocida123",
        claimed_entity_name=None,
        settings=settings,
    )
    assert len(signals) == 1
    assert signals[0].check_name == "cnmc_alias_unregistered"
    assert signals[0].weight == 0
    assert signals[0].hard_rule is False
    assert signals[0].severity == SignalSeverity.INFO
    assert signals[0].status == SignalStatus.NOT_APPLICABLE

