from __future__ import annotations

import pytest

from app.config import Settings
from app.schemas import MessageExtraction, SignalStatus
from app.services import browser as browser_service


class _Response:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {
            "final_url": "https://other.example/login",
            "password_fields": 1,
            "payment_fields": 0,
            "download_attempted": False,
        }


class _Client:
    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, _url: str, *, json: dict) -> _Response:
        assert json["url"] == "https://example.org/login"
        return _Response()


@pytest.mark.asyncio
async def test_browser_sidecar_response_is_normalized_to_signals(monkeypatch) -> None:
    async def public_host(_host: str) -> None:
        return None

    monkeypatch.setattr(browser_service, "assert_public_host", public_host)
    monkeypatch.setattr(browser_service.httpx, "AsyncClient", _Client)
    settings = Settings(
        enable_network_checks=False,
        enable_browser_checks=True,
        browser_scanner_url="http://scanner:8090",
    )

    signals = await browser_service.collect_browser_signals(
        MessageExtraction(
            body_text="Enlace",
            urls=["https://example.org/login"],
        ),
        settings,
    )

    credential = next(item for item in signals if item.check_name == "browser_credential_form")
    redirect = next(
        item for item in signals if item.check_name == "browser_cross_domain_navigation"
    )
    assert credential.status == SignalStatus.HIT and credential.weight == 50
    assert redirect.status == SignalStatus.HIT
    assert all(not item.hard_rule for item in signals)


@pytest.mark.asyncio
async def test_browser_sidecar_visual_brand_clone(monkeypatch) -> None:
    class _VisualCloneResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "final_url": "https://caixabank-portal-falso.top/login",
                "password_fields": 1,
                "payment_fields": 0,
                "download_attempted": False,
                "visual_clone_entity": "CaixaBank",
                "visual_similarity": 0.94,
                "phash": "a8f0c3d2e1b40987",
            }

    class _VisualCloneClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, _url: str, *, json: dict) -> _VisualCloneResponse:
            return _VisualCloneResponse()

    async def public_host(_host: str) -> None:
        return None

    monkeypatch.setattr(browser_service, "assert_public_host", public_host)
    monkeypatch.setattr(browser_service.httpx, "AsyncClient", _VisualCloneClient)
    settings = Settings(
        enable_network_checks=False,
        enable_browser_checks=True,
        browser_scanner_url="http://scanner:8090",
    )

    signals = await browser_service.collect_browser_signals(
        MessageExtraction(
            body_text="Acceso",
            urls=["https://caixabank-portal-falso.top/login"],
        ),
        settings,
    )

    clone_signal = next(item for item in signals if item.check_name == "visual_brand_clone")
    assert clone_signal.status == SignalStatus.HIT
    assert clone_signal.weight == 100
    assert clone_signal.hard_rule is True
    assert "CaixaBank" in clone_signal.summary
    assert "94%" in clone_signal.summary

