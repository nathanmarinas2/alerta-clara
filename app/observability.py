from __future__ import annotations

import json
import logging
from collections import Counter
from threading import Lock

try:
    from opentelemetry import trace
except ImportError:  # pragma: no cover - optional until an exporter is configured
    trace = None


class SafeMetrics:
    """Métricas agregadas sin cuerpo, URL, remitente ni identificador de análisis."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: Counter[str] = Counter()

    def increment(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def prometheus(self) -> str:
        lines = [
            "# HELP alerta_clara_total_count Aggregated application counters.",
            "# TYPE alerta_clara_total_count counter",
        ]
        for name, value in sorted(self.snapshot().items()):
            safe_name = "alerta_clara_" + name.replace(".", "_").replace("-", "_")
            lines.append(f"{safe_name}_total {value}")
        return "\n".join(lines) + "\n"


metrics = SafeMetrics()
tracer = trace.get_tracer("alerta-clara") if trace else None
logger = logging.getLogger("alerta_clara.http")


def observe_analysis(level: str, message_type: str, duration_ms: int) -> None:
    metrics.increment("analysis_total")
    metrics.increment(f"analysis_verdict_{level}")
    metrics.increment(f"analysis_type_{message_type}")
    metrics.increment("analysis_duration_ms_sum", duration_ms)
    if tracer:
        with tracer.start_as_current_span("alerta_clara.analysis") as span:
            span.set_attribute("analysis.verdict", level)
            span.set_attribute("analysis.message_type", message_type)
            span.set_attribute("analysis.duration_ms", duration_ms)


def observe_request(
    path: str,
    status_code: int,
    *,
    request_id: str | None = None,
    duration_ms: int | None = None,
) -> None:
    metrics.increment("http_requests_total")
    metrics.increment(f"http_status_{status_code}")
    if path.startswith("/api/v1/analyze"):
        metrics.increment("analysis_http_requests_total")
    logger.info(
        json.dumps(
            {
                "event": "http_request",
                "path": path,
                "status_code": status_code,
                "request_id": request_id,
                "duration_ms": duration_ms,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
