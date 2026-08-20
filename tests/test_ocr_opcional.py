"""El OCR es un extra opcional: la API debe funcionar sin él y decirlo con claridad.

La cadena `rapidocr -> opencv -> ffmpeg` no viaja en la imagen de la API. Estos tests
fijan las dos garantías de esa decisión: que nada se rompe cuando falta, y que el
mensaje al usuario no le manda a mejorar una foto que aquí nadie va a leer.
"""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import app
from app.services.ocr import extract_text_from_image


def test_extraccion_devuelve_vacio_si_no_hay_motor() -> None:
    with patch("app.services.ocr._engine", return_value=None):
        assert extract_text_from_image(b"cualquier-cosa") == ""


def test_captura_sin_motor_de_ocr_da_un_mensaje_util() -> None:
    """Sin OCR instalado, 'prueba con una imagen más nítida' es un consejo inútil."""
    app.dependency_overrides[get_settings] = lambda: Settings(
        enable_network_checks=False,
        enable_qr_decode=False,
    )
    try:
        with (
            patch("app.main.is_ocr_available", return_value=False),
            TestClient(app) as client,
        ):
            respuesta = client.post(
                "/api/v1/analyze",
                data={"message": ""},
                files={"image": ("captura.png", b"\x89PNG\r\n\x1a\ncontenido", "image/png")},
            )
        assert respuesta.status_code == 422
        detalle = respuesta.json()["detail"]
        assert "no puede leer el texto de las capturas" in detalle.casefold()
        assert "nítida" not in detalle.casefold()
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_el_analisis_de_texto_no_depende_del_ocr() -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(enable_network_checks=False)
    try:
        with (
            patch("app.main.is_ocr_available", return_value=False),
            TestClient(app) as client,
        ):
            respuesta = client.post(
                "/api/v1/analyze/json",
                json={
                    "message": (
                        "CaixaBank: cuenta bloqueada. Verifica tus datos en "
                        "https://caixabank-seguridad.top/acceso"
                    )
                },
            )
        assert respuesta.status_code == 200
        assert respuesta.json()["level"] == "estafa"
    finally:
        app.dependency_overrides.pop(get_settings, None)
