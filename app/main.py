from __future__ import annotations

import asyncio
import base64
import hmac
import time
import uuid
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import SessionLocal, create_tables, get_db
from app.models import AuditEvent, Campaign, Feedback, Message, ReviewItem
from app.observability import metrics, observe_request
from app.schemas import (
    AnalysisRequest,
    AnalysisResponse,
    Channel,
    FeedbackRequest,
    HealthResponse,
    LivenessResponse,
    ReviewQueueItem,
    ReviewResolution,
    ReviewResolutionRequest,
)
from app.services.browser import browser_health
from app.services.ct_monitor import ct_monitor_loop
from app.services.ocr import extract_text_from_image
from app.services.pipeline import AnalysisPipeline
from app.services.qr import decode_qr_payloads
from app.services.ratelimit import enforce_rate_limit
from app.services.retention import retention_loop
from app.services.retrohunt import enqueue_feedback_review
from app.services.stix import build_stix_bundle
from app.services.threat_intel import feed_health, threat_feed_loop

BASE_DIR = Path(__file__).parent
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}


def _run_analysis_sync(
    settings: Settings,
    text: str,
    *,
    sender: str | None,
    channel: Channel,
    user_reference: str | None = None,
    image_data_url: str | None = None,
    qr_payloads: list[str] | None = None,
) -> AnalysisResponse:
    """Ejecuta SQLAlchemy y el pipeline en un hilo con su propia sesión/event loop."""
    with SessionLocal() as db:
        return asyncio.run(
            AnalysisPipeline(settings).analyze(
                db,
                text,
                sender=sender,
                channel=channel,
                user_reference=user_reference,
                image_data_url=image_data_url,
                qr_payloads=qr_payloads,
            )
        )


async def _run_analysis(
    settings: Settings,
    text: str,
    *,
    sender: str | None,
    channel: Channel,
    user_reference: str | None = None,
    image_data_url: str | None = None,
    qr_payloads: list[str] | None = None,
) -> AnalysisResponse:
    return await asyncio.to_thread(
        _run_analysis_sync,
        settings,
        text,
        sender=sender,
        channel=channel,
        user_reference=user_reference,
        image_data_url=image_data_url,
        qr_payloads=qr_payloads,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    create_tables()
    settings = get_settings()
    background_tasks = [asyncio.create_task(retention_loop(settings))]
    if settings.enable_threat_feeds:
        background_tasks.append(asyncio.create_task(threat_feed_loop(settings)))
    if settings.enable_ct_monitor:
        background_tasks.append(asyncio.create_task(ct_monitor_loop(settings)))
    try:
        yield
    finally:
        for task in background_tasks:
            task.cancel()
        for task in background_tasks:
            with suppress(asyncio.CancelledError):
                await task


app = FastAPI(
    title="Alerta Clara API",
    version="0.2.0",
    description=(
        "Analiza mensajes sospechosos con extracción estructurada, señales verificables "
        "y una decisión conservadora basada en reglas."
    ),
    lifespan=lifespan,
    docs_url=None if get_settings().app_env.lower() == "production" else "/docs",
    redoc_url=None if get_settings().app_env.lower() == "production" else "/redoc",
    openapi_url=None if get_settings().app_env.lower() == "production" else "/openapi.json",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    started = time.perf_counter()
    request_id = request.headers.get("X-Request-ID")
    if not request_id or len(request_id) > 80 or not all(
        char.isalnum() or char in "-_." for char in request_id
    ):
        request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    observe_request(
        request.url.path,
        response.status_code,
        request_id=request_id,
        duration_ms=round((time.perf_counter() - started) * 1000),
    )
    response.headers.setdefault("X-Request-ID", request_id)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'",
        )
    return response


def _require_ops_key(settings: Settings, supplied: str | None) -> None:
    if settings.app_env.lower() != "production":
        return
    configured = settings.health_api_key.get_secret_value() if settings.health_api_key else ""
    if not supplied or not configured or not hmac.compare_digest(configured, supplied):
        raise HTTPException(status_code=404, detail="No encontrado")


@app.get("/metrics", include_in_schema=False, response_class=PlainTextResponse)
def metrics_endpoint(
    settings: Annotated[Settings, Depends(get_settings)],
    health_key: Annotated[str | None, Header(alias="X-Health-Key")] = None,
) -> PlainTextResponse:
    _require_ops_key(settings, health_key)
    return PlainTextResponse(metrics.prometheus(), media_type="text/plain; version=0.0.4")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home() -> HTMLResponse:
    return HTMLResponse((BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8"))


@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
def privacy() -> HTMLResponse:
    content = (BASE_DIR / "templates" / "privacy.html").read_text(encoding="utf-8")
    return HTMLResponse(
        content,
        headers={
            "Content-Security-Policy": (
                "default-src 'self'; style-src 'unsafe-inline' 'self'; frame-ancestors 'none'"
            )
        },
    )


@app.get("/health", response_model=LivenessResponse, tags=["operación"])
async def health(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LivenessResponse:
    db.execute(text("SELECT 1"))
    return LivenessResponse(
        status="ok",
        database="ok",
        model_configured=bool(settings.openai_api_key),
    )


@app.get("/ready", response_model=HealthResponse, include_in_schema=False)
async def ready(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    health_key: Annotated[str | None, Header(alias="X-Health-Key")] = None,
) -> HealthResponse:
    _require_ops_key(settings, health_key)
    db.execute(text("SELECT 1"))
    return HealthResponse(
        status="ok",
        database="ok",
        model_configured=bool(settings.openai_api_key),
        threat_feeds=feed_health(db, settings),
        browser_scanner=await browser_health(settings),
        analyses_last_24h=(
            db.scalar(
                select(func.count(Message.id)).where(
                    Message.received_at >= datetime.now(UTC) - timedelta(hours=24)
                )
            )
            or 0
        ),
        pending_reviews=(
            db.scalar(select(func.count(ReviewItem.id)).where(ReviewItem.status == "pending")) or 0
        ),
    )


@app.post("/api/v1/analyze/json", response_model=AnalysisResponse, tags=["análisis"])
async def analyze_json(
    request: Request,
    payload: AnalysisRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AnalysisResponse:
    enforce_rate_limit(
        request,
        scope="analysis",
        limit=settings.rate_limit_analyses_per_minute,
        redis_url=settings.redis_url,
        use_redis=settings.rate_limit_use_redis,
    )
    return await _run_analysis(
        settings,
        payload.message,
        sender=payload.sender,
        channel=payload.channel,
        user_reference=payload.user_reference,
    )


@app.post("/api/v1/analyze", response_model=AnalysisResponse, tags=["análisis"])
async def analyze_form(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    message: Annotated[str, Form(max_length=20_000)] = "",
    sender: Annotated[str | None, Form(max_length=120)] = None,
    image: Annotated[UploadFile | None, File()] = None,
) -> AnalysisResponse:
    enforce_rate_limit(
        request,
        scope="analysis",
        limit=settings.rate_limit_analyses_per_minute,
        redis_url=settings.redis_url,
        use_redis=settings.rate_limit_use_redis,
    )
    image_data_url: str | None = None
    qr_payloads: list[str] = []
    ocr_text = ""
    if image and image.filename:
        if image.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Usa una captura JPG, PNG, WEBP o GIF.",
            )
        content = await image.read(settings.max_upload_bytes + 1)
        if len(content) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="La captura supera el límite de 5 MB.",
            )
        encoded = base64.b64encode(content).decode("ascii")
        image_data_url = f"data:{image.content_type};base64,{encoded}"
        if settings.enable_qr_decode:
            qr_payloads = await asyncio.to_thread(decode_qr_payloads, content)
        if settings.enable_local_ocr:
            ocr_text = await asyncio.to_thread(
                extract_text_from_image,
                content,
                min_confidence=settings.ocr_min_confidence,
            )

    combined_message = "\n".join(
        part for part in (message.strip(), ocr_text.strip()) if part
    )

    if not combined_message and not image_data_url:
        raise HTTPException(status_code=422, detail="Pega un mensaje o añade una captura.")
    if (
        not combined_message
        and image_data_url
        and not (settings.openai_api_key and settings.allow_external_image_analysis)
        and not qr_payloads
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "No pude extraer texto legible de la captura. Prueba con una imagen más nítida, "
                "activa ALLOW_EXTERNAL_IMAGE_ANALYSIS con consentimiento o pega el mensaje."
            ),
        )

    try:
        return await _run_analysis(
            settings,
            combined_message,
            sender=sender,
            channel=Channel.WEB,
            image_data_url=(
                image_data_url
                if settings.openai_api_key and settings.allow_external_image_analysis
                else None
            ),
            qr_payloads=qr_payloads,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        if image_data_url:
            raise HTTPException(
                status_code=502,
                detail="No se pudo leer la captura. Prueba de nuevo o pega el texto del mensaje.",
            ) from exc
        raise


@app.post("/api/v1/analyses/{message_id}/feedback", status_code=204, tags=["feedback"])
def save_feedback(
    message_id: str,
    payload: FeedbackRequest,
    db: Annotated[Session, Depends(get_db)],
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    enforce_rate_limit(
        request,
        scope="feedback",
        limit=settings.rate_limit_feedback_per_minute,
        redis_url=settings.redis_url,
        use_redis=settings.rate_limit_use_redis,
    )
    if not db.scalar(select(Message.id).where(Message.id == message_id)):
        raise HTTPException(status_code=404, detail="Análisis no encontrado")
    feedback = db.get(Feedback, message_id)
    if feedback:
        feedback.user_said = payload.user_said
        feedback.reason_code = payload.reason_code.value if payload.reason_code else None
    else:
        db.add(
            Feedback(
                message_id=message_id,
                user_said=payload.user_said,
                reason_code=payload.reason_code.value if payload.reason_code else None,
            )
        )
    if payload.user_said == "incorrecto":
        enqueue_feedback_review(
            db,
            message_id,
            payload.reason_code.value if payload.reason_code else None,
        )
    db.commit()


@app.get("/api/v1/analyses/{message_id}/stix", tags=["análisis"])
def export_stix(
    message_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> JSONResponse:
    message = db.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Análisis no encontrado")
    return JSONResponse(
        content=build_stix_bundle(message),
        media_type="application/stix+json;version=2.1",
        headers={"Content-Disposition": f'attachment; filename="alerta-{message_id}.json"'},
    )


def _review_tokens(settings: Settings) -> dict[str, str]:
    tokens: dict[str, str] = {}
    if settings.review_tokens:
        for item in settings.review_tokens.split(","):
            actor, separator, token = item.partition("=")
            if separator and actor.strip() and token.strip():
                tokens[actor.strip()] = token.strip()
    if settings.review_api_key:
        tokens.setdefault("legacy-reviewer", settings.review_api_key.get_secret_value())
    return tokens


def _require_review_key(
    settings: Settings,
    supplied: str | None,
    authorization: str | None = None,
    *,
    required_role: str = "reviewer",
) -> str:
    configured = _review_tokens(settings)
    if not configured:
        raise HTTPException(status_code=503, detail="La cola de revisión no está habilitada")
    candidate = supplied
    if not candidate and authorization and authorization.casefold().startswith("bearer "):
        candidate = authorization[7:].strip()
    actor = next(
        (
            name
            for name, token in configured.items()
            if candidate and hmac.compare_digest(token, candidate)
        ),
        None,
    )
    if not actor:
        raise HTTPException(status_code=403, detail="Clave de revisión no válida")
    if required_role == "admin" and actor != "admin":
        raise HTTPException(status_code=403, detail="Se necesita un revisor administrador")
    return actor


@app.get("/api/v1/reviews", response_model=list[ReviewQueueItem], tags=["revisión"])
def list_reviews(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    review_key: Annotated[str | None, Header(alias="X-Review-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[ReviewQueueItem]:
    actor = _require_review_key(settings, review_key, authorization)
    items = db.scalars(
        select(ReviewItem)
        .where(ReviewItem.status == "pending")
        .order_by(ReviewItem.created_at)
        .limit(limit)
    ).all()
    result: list[ReviewQueueItem] = []
    for item in items:
        message = db.get(Message, item.message_id)
        if not message:
            continue
        result.append(
            ReviewQueueItem(
                id=item.id,
                message_id=item.message_id,
                reason=item.reason,
                payload=item.payload,
                created_at=item.created_at,
                body_redacted=message.body_redacted,
                current_verdict=(message.verdict.level if message.verdict else "unknown"),
            )
        )
    db.add(AuditEvent(actor=actor, action="review.list", metadata_json={"limit": limit}))
    db.commit()
    return result


@app.post("/api/v1/reviews/{review_id}/resolve", status_code=204, tags=["revisión"])
def resolve_review(
    review_id: str,
    payload: ReviewResolutionRequest,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    review_key: Annotated[str | None, Header(alias="X-Review-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    actor = _require_review_key(
        settings,
        review_key,
        authorization,
        required_role="admin" if payload.confirm_campaign else "reviewer",
    )
    item = db.get(ReviewItem, review_id)
    if not item:
        raise HTTPException(status_code=404, detail="Revisión no encontrada")
    if item.status != "pending":
        raise HTTPException(status_code=409, detail="La revisión ya estaba resuelta")
    item.status = payload.resolution.value
    item.resolved_at = datetime.now(UTC)
    item.payload = {**item.payload, "review_notes": payload.notes}
    if payload.confirm_campaign and payload.resolution == ReviewResolution.CONFIRMED_SCAM:
        campaign_id = item.payload.get("campaign_id")
        campaign = db.get(Campaign, campaign_id) if isinstance(campaign_id, str) else None
        if campaign:
            campaign.confirmed = True
    db.add(
        AuditEvent(
            actor=actor,
            action="review.resolve",
            target_id=review_id,
            metadata_json={
                "resolution": payload.resolution.value,
                "confirm_campaign": payload.confirm_campaign,
            },
        )
    )
    db.commit()
