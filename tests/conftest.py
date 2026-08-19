from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

TEST_DB = Path(tempfile.gettempdir()) / "alerta_clara_pytest.db"
if TEST_DB.exists():
    TEST_DB.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["ENABLE_NETWORK_CHECKS"] = "false"
os.environ.pop("OPENAI_API_KEY", None)


@pytest.fixture(autouse=True)
def _aislar_registro_ct(tmp_path, monkeypatch):
    """Impide que cualquier test escriba en el registro real de Certificate Transparency.

    `data/ct_observations/` es material probatorio: sostiene la afirmación de haber
    observado un dominio en una fecha concreta. Un fixture de test escrito ahí destruye
    su valor, y el fallo es silencioso. Este aislamiento es automático para toda la
    suite, de modo que también cubra los tests que se escriban en el futuro.
    """
    from app.services import ct_monitor

    monkeypatch.setattr(ct_monitor, "AUDIT_LOG_DIR", tmp_path / "ct_observations")
    yield
