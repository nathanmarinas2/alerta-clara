from app.schemas import RequestedAction
from app.services.extraction import local_extract


def test_extracts_entity_url_urgency_and_credentials() -> None:
    result = local_extract(
        "CaixaBank: cuenta bloqueada. Verifica tus datos en 24 horas en "
        "https://caixabank-seguridad.top/acceso"
    )

    assert result.claimed_entity == "CaixaBank"
    assert result.urls == ["https://caixabank-seguridad.top/acceso"]
    assert result.requested_action == RequestedAction.GIVE_CREDENTIALS
    assert {"bloqueada", "24 horas"}.issubset(result.urgency_markers)


def test_remote_app_has_priority_over_click() -> None:
    result = local_extract("Instala AnyDesk desde este enlace para que podamos ayudarte")
    assert result.requested_action == RequestedAction.INSTALL_APP


def test_extracts_spanish_mobile_sender() -> None:
    result = local_extract("BBVA: llame para verificar su cuenta", "+34 612 345 678")
    assert result.sender_number == "+34 612 345 678"
    assert result.sender_alias is None


def test_understands_formal_spanish_instruction() -> None:
    result = local_extract("Verifique sus datos para evitar el bloqueo de la cuenta")
    assert result.requested_action == RequestedAction.GIVE_CREDENTIALS
