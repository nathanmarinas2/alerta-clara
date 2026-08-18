from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote, urljoin, urlsplit

import httpx

USER_AGENT = "AlertaClara/0.2 (+security-check; no-content-indexing)"


class UnsafeTargetError(ValueError):
    pass


@dataclass(frozen=True)
class RdapResult:
    domain: str
    created_at: datetime | None


@dataclass(frozen=True)
class RedirectResult:
    original_url: str
    final_url: str
    hops: int


@dataclass(frozen=True)
class TlsResult:
    domain: str
    issued_at: datetime | None


def _is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


async def assert_public_host(host: str) -> None:
    try:
        if not _is_public_ip(host):
            raise UnsafeTargetError("El destino no es una IP pública")
        return
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        addresses = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError("No se pudo resolver el dominio") from exc
    resolved = {item[4][0] for item in addresses}
    if not resolved or any(not _is_public_ip(address) for address in resolved):
        raise UnsafeTargetError("El dominio resuelve a una red no pública")


def normalize_http_url(url: str) -> str:
    candidate = url if "://" in url else f"https://{url}"
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTargetError("Solo se permiten URLs HTTP(S)")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("No se permiten credenciales en la URL")
    if parsed.port not in {None, 80, 443}:
        raise UnsafeTargetError("Puerto no permitido")
    return candidate


async def rdap_lookup(domain: str) -> RdapResult:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(3.0), headers={"User-Agent": USER_AGENT}
    ) as client:
        response = await client.get(f"https://rdap.org/domain/{quote(domain, safe='.-')}")
        response.raise_for_status()
        payload = response.json()
    created_at: datetime | None = None
    for event in payload.get("events", []):
        if event.get("eventAction") in {"registration", "registered"}:
            raw_date = event.get("eventDate")
            if raw_date:
                created_at = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                break
    return RdapResult(domain=domain, created_at=created_at)


async def follow_redirects(url: str, max_hops: int = 6) -> RedirectResult:
    current = normalize_http_url(url)
    original = current
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(3.0),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
    ) as client:
        for hop in range(max_hops + 1):
            parsed = urlsplit(current)
            await assert_public_host(parsed.hostname or "")
            response = await client.request("HEAD", current)
            if response.status_code in {405, 501}:
                response = await client.get(current, headers={"Range": "bytes=0-0"})
            if not response.is_redirect:
                return RedirectResult(original_url=original, final_url=str(response.url), hops=hop)
            location = response.headers.get("location")
            if not location:
                return RedirectResult(original_url=original, final_url=current, hops=hop)
            current = normalize_http_url(urljoin(current, location))
    return RedirectResult(original_url=original, final_url=current, hops=max_hops)


async def tls_certificate(domain: str) -> TlsResult:
    await assert_public_host(domain)
    context = ssl.create_default_context()
    _reader, writer = await asyncio.open_connection(
        domain, 443, ssl=context, server_hostname=domain
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert() if ssl_object else {}
        raw_not_before = certificate.get("notBefore")
        issued_at = (
            datetime.fromtimestamp(ssl.cert_time_to_seconds(raw_not_before), tz=UTC)
            if raw_not_before
            else None
        )
        return TlsResult(domain=domain, issued_at=issued_at)
    finally:
        writer.close()
        await writer.wait_closed()
