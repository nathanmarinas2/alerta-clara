from __future__ import annotations

import threading
import time
from collections import deque

from fastapi import HTTPException, Request, status

try:
    from redis import Redis
except ImportError:  # pragma: no cover - the in-memory path remains valid in tests
    Redis = None


class SlidingWindowLimiter:
    """Limitador pequeño y sin dependencias para una instancia de desarrollo.

    En despliegues con varias réplicas se puede sustituir por el mismo contrato
    respaldado por Redis; nunca se usa el contenido del mensaje como clave.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str, *, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            events = self._events.setdefault(key, deque())
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(events[0] + window_seconds - now) + 1)
                return False, retry_after
            events.append(now)
            if len(self._events) > 10_000:
                self._events = {
                    candidate: values
                    for candidate, values in self._events.items()
                    if values and values[-1] > cutoff
                }
            return True, 0


limiter = SlidingWindowLimiter()
_redis_clients: dict[str, object] = {}
_redis_lock = threading.Lock()


def _client_key(request: Request, scope: str) -> str:
    # El proxy debe sobrescribir client.host de forma fiable; no confiamos en
    # X-Forwarded-For enviado directamente por el usuario.
    host = request.client.host if request.client else "unknown"
    return f"{scope}:{host}"


def _redis_allow(key: str, limit: int, redis_url: str) -> tuple[bool, int] | None:
    if Redis is None:
        return None
    try:
        with _redis_lock:
            client = _redis_clients.get(redis_url)
            if client is None:
                client = Redis.from_url(redis_url, decode_responses=True, socket_timeout=0.15)
                _redis_clients[redis_url] = client
        bucket = f"alerta-clara:ratelimit:{key}:{int(time.time() // 60)}"
        count = int(client.incr(bucket))
        if count == 1:
            client.expire(bucket, 65)
        return (count <= limit, 60 - (int(time.time()) % 60))
    except Exception:
        return None


def enforce_rate_limit(
    request: Request,
    *,
    scope: str,
    limit: int,
    redis_url: str | None = None,
    use_redis: bool = False,
) -> None:
    key = _client_key(request, scope)
    result = _redis_allow(key, limit, redis_url) if use_redis and redis_url else None
    allowed, retry_after = result if result is not None else limiter.allow(key, limit=limit)
    if allowed:
        return
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Demasiadas solicitudes. Espera un momento y vuelve a intentarlo.",
        headers={"Retry-After": str(retry_after)},
    )
