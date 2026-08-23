"""Garantiza que una ronda de CT deja constancia aunque no encuentre nada.

Un fichero de observaciones vacío es ambiguo: puede significar "no había dominios
sospechosos" o "crt.sh estaba caído". La afirmación pública "el día D monitorizamos
N marcas" solo es defendible si el resultado de cada consulta queda sellado.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.services.ct_monitor import (
    CertificateTransparencyConnector,
    append_ct_run_log,
)


def test_run_log_registra_consultas_fallidas(tmp_path: Path) -> None:
    registros = [
        {
            "entity": "CaixaBank",
            "source": "crtsh_http+postgres",
            "ok": False,
            "certificates_seen": 0,
            "attempts": 3,
            "last_status": 502,
            "error": "sin_respuesta_utilizable/respaldo_postgres_fallido",
            "checked_at": "2026-08-19T18:00:00+00:00",
        },
        {
            "entity": "Correos",
            "source": "crtsh_http",
            "ok": True,
            "certificates_seen": 120,
            "attempts": 1,
            "last_status": 200,
            "error": None,
            "checked_at": "2026-08-19T18:00:05+00:00",
        },
    ]

    ruta = append_ct_run_log(registros, audit_dir=tmp_path)

    assert ruta.exists()
    entradas = [
        json.loads(linea)
        for linea in ruta.read_text(encoding="utf-8").splitlines()
        if linea.strip()
    ]
    assert len(entradas) == 1
    entrada = entradas[0]
    assert entrada["entities_queried"] == 2
    assert entrada["queries_ok"] == 1
    assert entrada["queries_failed"] == 1
    assert entrada["results"][0]["last_status"] == 502


def test_run_log_es_de_solo_anadir(tmp_path: Path) -> None:
    """Nunca se reescribe hacia atrás: cada ronda añade una línea."""
    append_ct_run_log([{"entity": "BBVA", "ok": True, "source": "crtsh_http"}], audit_dir=tmp_path)
    ruta = append_ct_run_log(
        [{"entity": "BBVA", "ok": False, "source": "crtsh_http"}], audit_dir=tmp_path
    )
    lineas = [x for x in ruta.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(lineas) == 2


@pytest.mark.asyncio
async def test_fetch_fallido_deja_registro_no_vacio() -> None:
    """Aunque crt.sh falle para todas las entidades, la ronda queda documentada."""
    # Esta prueba verifica únicamente que una consulta fallida deja registro;
    # el feed verificado se prueba por separado y aquí debe permanecer aislado.
    conector = CertificateTransparencyConnector(
        target_entities=["CaixaBank"], enable_phishing_feed=False
    )

    with patch.object(
        conector, "fetch_entity_certificates", new_callable=AsyncMock
    ) as mock_fetch:
        # Simula el comportamiento real: sin certificados y sin registro propio,
        # porque el mock sustituye al método que normalmente lo escribe.
        mock_fetch.return_value = []
        observaciones = await conector.fetch()

    assert observaciones == []

    # Sin mock, el propio método debe registrar el fallo.
    conector_real = CertificateTransparencyConnector(
        target_entities=["EntidadQueNoExiste"], max_retries=1
    )
    await conector_real.fetch()
    assert conector_real.run_records, "una ronda sin hallazgos debe dejar registro"
    assert conector_real.run_records[0]["ok"] is False
