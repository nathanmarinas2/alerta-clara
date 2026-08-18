import re
from datetime import UTC, datetime, timedelta

from app.entities import load_entities, registrable_domain


def test_registrable_domain_uses_public_suffix_boundaries() -> None:
    assert registrable_domain("https://login.example.co.uk/access") == "example.co.uk"
    assert registrable_domain("https://sub.example.com/path") == "example.com"
    assert registrable_domain("https://192.0.2.10/path") == "192.0.2.10"


def test_official_numbers_require_provenance_and_recent_verification() -> None:
    entities = load_entities()
    now = datetime.now(UTC).date()
    max_age = timedelta(days=180)

    total_phones = 0
    for entity in entities:
        for phone in entity.official_numbers:
            total_phones += 1
            assert re.fullmatch(r"[0-9]{3,9}", phone.number), (
                f"Número inválido '{phone.number}' en {entity.name}"
            )
            assert phone.source.startswith("https://"), (
                f"Fuente no oficial/segura '{phone.source}' en {entity.name}"
            )
            assert len(phone.purpose.strip()) > 3, (
                f"Propósito no especificado para {phone.number} en {entity.name}"
            )
            phone_date = datetime.strptime(phone.verified_at, "%Y-%m-%d").date()
            assert phone_date <= now, f"Fecha futura '{phone.verified_at}' en {entity.name}"
            assert (now - phone_date) <= max_age, (
                f"Verificación caducada (>6 meses) '{phone.verified_at}' en {entity.name}"
            )

    assert total_phones >= 15, "Deben existir al menos 15 teléfonos oficiales auditados"


def test_non_phone_channels_do_not_publish_unverified_numbers() -> None:
    entities = {e.name: e for e in load_entities()}
    unsupported = ["Netflix", "Vinted", "Wallapop", "AliExpress", "Celeritas", "SEUR", "MRW"]
    for name in unsupported:
        assert len(entities[name].official_numbers) == 0, (
            f"{name} no debe tener números publicados sin verificación de fuente primaria directa"
        )
