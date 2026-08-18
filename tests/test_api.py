from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import app


def test_health_and_analysis_round_trip() -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        response = client.post(
            "/api/v1/analyze/json",
            json={
                "message": (
                    "CaixaBank: cuenta bloqueada. Verifica tus datos en 24 horas en "
                    "https://caixabank-seguridad.top/acceso"
                )
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["level"] == "estafa"
    assert payload["meta"]["ruleset_version"] == "2026.08.3"
    assert payload["meta"]["model_version"] == "local-extractor-v1"
    assert len(payload["id"]) == 36
    assert {rule["rule_id"] for rule in payload["rules"]} == {
        "hard_evidence",
        "weighted_score",
        "shared_infrastructure_suppression",
    }
    assert payload["incident_steps"]
    assert all({"status", "source", "version"} <= signal.keys() for signal in payload["signals"])


def test_form_requires_text_or_image() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/analyze", data={"message": ""})
    assert response.status_code == 422


def test_browser_style_form_with_empty_file_field_accepts_text() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            data={"message": "Instala AnyDesk para que el técnico pueda ayudarte"},
            files={"image": ("", b"", "application/octet-stream")},
        )
    assert response.status_code == 200
    assert response.json()["level"] == "estafa"


def test_image_only_qr_is_decoded_locally_without_model() -> None:
    from io import BytesIO

    import zxingcpp
    from PIL import Image

    bitmap = zxingcpp.write_barcode(
        zxingcpp.BarcodeFormat.QRCode,
        "https://example.org/verify",
        300,
        300,
    )
    buffer = BytesIO()
    Image.fromarray(bitmap).save(buffer, format="PNG")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            data={"message": ""},
            files={"image": ("qr.png", buffer.getvalue(), "image/png")},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["extraction"]["qr_payload_types"] == ["url"]
    assert payload["extraction"]["urls"] == ["https://example.org/verify"]
    assert any(signal["check_name"] == "qr_payload_detected" for signal in payload["signals"])


def test_incorrect_feedback_enters_protected_human_review_queue() -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(
        enable_network_checks=False,
        review_api_key="review-secret",
    )
    try:
        with TestClient(app) as client:
            analysis = client.post(
                "/api/v1/analyze/json",
                json={"message": "Mensaje difícil de verificar"},
            ).json()
            feedback = client.post(
                f"/api/v1/analyses/{analysis['id']}/feedback",
                json={"user_said": "incorrecto", "reason_code": "necesita_revision"},
            )
            forbidden = client.get("/api/v1/reviews")
            queue = client.get(
                "/api/v1/reviews",
                headers={"X-Review-Key": "review-secret"},
            )

        assert feedback.status_code == 204
        assert forbidden.status_code == 403
        item = next(row for row in queue.json() if row["message_id"] == analysis["id"])
        assert item["reason"] == "user_disagreed"

        with TestClient(app) as client:
            resolved = client.post(
                f"/api/v1/reviews/{item['id']}/resolve",
                headers={"X-Review-Key": "review-secret"},
                json={"resolution": "dismissed", "notes": "Revisado en prueba"},
            )
        assert resolved.status_code == 204
    finally:
        app.dependency_overrides.pop(get_settings, None)
