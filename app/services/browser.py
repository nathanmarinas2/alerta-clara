from __future__ import annotations

from time import perf_counter

import httpx

from app.config import Settings
from app.entities import registrable_domain
from app.schemas import (
    EvidenceSignal,
    MessageExtraction,
    SignalSeverity,
    SignalStatus,
)
from app.services.network import assert_public_host, normalize_http_url


async def browser_health(settings: Settings) -> str:
    if not settings.enable_browser_checks:
        return "disabled"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(1.5)) as client:
            response = await client.get(f"{settings.browser_scanner_url.rstrip('/')}/health")
            response.raise_for_status()
        return "ok"
    except Exception:
        return "unavailable"


def _result_signal(
    check_name: str,
    value: dict,
    weight: int,
    severity: SignalSeverity,
    summary: str,
    *,
    hit: bool,
    latency_ms: int,
    version: str,
) -> EvidenceSignal:
    return EvidenceSignal(
        check_name=check_name,
        value=value,
        weight=weight,
        severity=severity,
        summary=summary,
        detail="La página se abrió sin enviar datos, en un navegador desechable y aislado.",
        latency_ms=latency_ms,
        status=SignalStatus.HIT if hit else SignalStatus.MISS,
        source="browser_sidecar",
        version=version,
    )


async def collect_browser_signals(
    extraction: MessageExtraction,
    settings: Settings,
) -> list[EvidenceSignal]:
    if not settings.enable_browser_checks or not extraction.urls:
        return []
    started = perf_counter()
    try:
        target = normalize_http_url(extraction.urls[0])
        parsed = httpx.URL(target)
        await assert_public_host(parsed.host)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.browser_scan_timeout_seconds)
        ) as client:
            request_kwargs: dict[str, object] = {}
            if settings.browser_scanner_token:
                request_kwargs["headers"] = {
                    "X-Scanner-Token": settings.browser_scanner_token.get_secret_value()
                }
            response = await client.post(
                f"{settings.browser_scanner_url.rstrip('/')}/scan",
                json={"url": target},
                **request_kwargs,
            )
            response.raise_for_status()
            payload = response.json()
        latency_ms = round((perf_counter() - started) * 1000)
        password_fields = int(payload.get("password_fields", 0))
        payment_fields = int(payload.get("payment_fields", 0))
        download_attempted = bool(payload.get("download_attempted", False))
        final_url = str(payload.get("final_url", target))
        original_domain = registrable_domain(target)
        final_domain = registrable_domain(final_url)
        cross_domain = bool(final_domain and final_domain != original_domain)
        return [
            _result_signal(
                "browser_credential_form",
                {
                    "password_fields": password_fields,
                    "payment_fields": payment_fields,
                    "final_domain": final_domain,
                },
                50,
                SignalSeverity.WARNING,
                (
                    "La página intenta recoger contraseñas o datos de pago."
                    if password_fields or payment_fields
                    else "La página no mostró campos de contraseña o pago."
                ),
                hit=bool(password_fields or payment_fields),
                latency_ms=latency_ms,
                version=settings.signalset_version,
            ),
            _result_signal(
                "browser_download_attempt",
                {"attempted": download_attempted},
                60,
                SignalSeverity.WARNING,
                (
                    "La página intentó iniciar una descarga."
                    if download_attempted
                    else "La página no intentó iniciar una descarga."
                ),
                hit=download_attempted,
                latency_ms=latency_ms,
                version=settings.signalset_version,
            ),
            _result_signal(
                "browser_cross_domain_navigation",
                {"original_domain": original_domain, "final_domain": final_domain},
                20,
                SignalSeverity.WARNING,
                (
                    "El navegador terminó en un dominio diferente."
                    if cross_domain
                    else "El navegador terminó en el mismo dominio."
                ),
                hit=cross_domain,
                latency_ms=latency_ms,
                version=settings.signalset_version,
            ),
        ]
    except httpx.TimeoutException:
        return [
            EvidenceSignal(
                check_name="browser_isolated_scan",
                value=None,
                summary="El navegador aislado agotó su tiempo máximo.",
                latency_ms=round((perf_counter() - started) * 1000),
                status=SignalStatus.TIMEOUT,
                source="browser_sidecar",
                version=settings.signalset_version,
            )
        ]
    except Exception as exc:
        return [
            EvidenceSignal(
                check_name="browser_isolated_scan",
                value={"error_type": type(exc).__name__},
                summary="El navegador aislado no pudo completar la comprobación.",
                latency_ms=round((perf_counter() - started) * 1000),
                status=SignalStatus.ERROR,
                source="browser_sidecar",
                version=settings.signalset_version,
            )
        ]
