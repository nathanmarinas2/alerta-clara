from __future__ import annotations

import base64
import hashlib
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pydantic import SecretStr

from app.config import Settings
from app.services.google_safe_browsing import lookup_hashes


@pytest.mark.asyncio
async def test_google_safe_browsing_disabled_returns_empty() -> None:
    settings = Settings(enable_google_safe_browsing=False)
    matches = await lookup_hashes({"https://malicious.example/path"}, settings)
    assert matches == []


@pytest.mark.asyncio
async def test_google_safe_browsing_matching_hash_returns_threats() -> None:
    url = "https://malicious.example/phishing"
    full_digest = hashlib.sha256(url.encode("utf-8")).digest()
    full_hash_b64 = base64.b64encode(full_digest).decode("ascii")

    settings = Settings(
        enable_google_safe_browsing=True,
        google_safe_browsing_api_key=SecretStr("test-api-key"),
    )

    mock_response = httpx.Response(
        200,
        json={
            "fullHashes": [
                {
                    "fullHash": full_hash_b64,
                    "fullHashDetails": [
                        {"threatType": "SOCIAL_ENGINEERING"},
                        {"threatType": "MALWARE"},
                    ],
                }
            ]
        },
        request=httpx.Request("POST", "https://safebrowsing.googleapis.com/v5/hashes:search"),
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_response
        matches = await lookup_hashes({url}, settings)

        assert len(matches) == 1
        assert matches[0].url_hash == full_digest.hex()
        assert matches[0].threat_types == ("SOCIAL_ENGINEERING", "MALWARE")
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args.kwargs
        assert "hashPrefixes" in call_kwargs["json"]
        assert call_kwargs["params"] == {"key": "test-api-key"}


@pytest.mark.asyncio
async def test_google_safe_browsing_handles_http_error_gracefully() -> None:
    settings = Settings(
        enable_google_safe_browsing=True,
        google_safe_browsing_api_key=SecretStr("test-api-key"),
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection refused")
        matches = await lookup_hashes({"https://malicious.example/phishing"}, settings)
        assert matches == []
