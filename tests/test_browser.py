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
