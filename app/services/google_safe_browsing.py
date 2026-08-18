"""Comprobación opcional de URLs mediante Google Safe Browsing v5.

Solo se envían prefijos de hashes SHA-256 de URLs canónicas; el proveedor no recibe
el texto del mensaje ni la URL completa. La integración está desactivada por defecto.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

import httpx

from app.config import Settings
from app.services.threat_intel import canonical_url

ENDPOINT = "https://safebrowsing.googleapis.com/v5/hashes:search"


@dataclass(frozen=True)
class HashMatch:
    url_hash: str
    threat_types: tuple[str, ...]


def _url_hash(url: str) -> bytes:
    return hashlib.sha256(url.encode("utf-8")).digest()


async def lookup_hashes(urls: set[str], settings: Settings) -> list[HashMatch]:
    if not settings.enable_google_safe_browsing or not settings.google_safe_browsing_api_key:
        return []
    canonical = {item for raw in urls if (item := canonical_url(raw))}
    if not canonical:
        return []
    digests = {_url_hash(url): url for url in canonical}
    prefixes = [base64.b64encode(digest[:4]).decode("ascii") for digest in digests]
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                ENDPOINT,
                params={"key": settings.google_safe_browsing_api_key.get_secret_value()},
                json={"hashPrefixes": prefixes},
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return []

    matches: list[HashMatch] = []
    for item in payload.get("fullHashes", []):
        encoded = item.get("fullHash") if isinstance(item, dict) else None
        if not isinstance(encoded, str):
            continue
        try:
            digest = base64.b64decode(encoded, validate=True)
        except ValueError:
            continue
        if digest not in digests:
            continue
        details = item.get("fullHashDetails", [])
        threat_types = tuple(
            str(detail.get("threatType"))
            for detail in details
            if isinstance(detail, dict) and detail.get("threatType")
        )
        matches.append(HashMatch(url_hash=digest.hex(), threat_types=threat_types))
    return matches
