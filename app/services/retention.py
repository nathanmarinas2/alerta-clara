from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.config import Settings
from app.database import SessionLocal
from app.models import Message

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PurgeResult:
    messages_purged: int
    cutoff: datetime


def purge_expired_message_data(
    db: Session,
    retention_hours: int,
    *,
    now: datetime | None = None,
) -> PurgeResult:
    """Elimina contenido y seudónimos expirados, conservando señales y veredictos."""
    current_time = now or datetime.now(UTC)
    cutoff = current_time - timedelta(hours=max(0, retention_hours))
    messages = db.scalars(
        select(Message)
        .options(selectinload(Message.extraction))
        .where(Message.received_at < cutoff, Message.purged_at.is_(None))
    ).all()

    for message in messages:
        message.body_redacted = ""
        message.user_hash = None
        message.purged_at = current_time
        if message.extraction:
            message.extraction.sender_alias = None
            message.extraction.sender_number = None
            message.extraction.urls = []
            message.extraction.urgency_markers = []

    db.commit()
    return PurgeResult(messages_purged=len(messages), cutoff=cutoff)


def run_retention_once(settings: Settings) -> PurgeResult:
    with SessionLocal() as db:
        return purge_expired_message_data(db, settings.body_retention_hours)


async def retention_loop(settings: Settings) -> None:
    interval = max(60, settings.retention_purge_interval_seconds)
    while True:
        try:
            await asyncio.to_thread(run_retention_once, settings)
        except Exception:
            logger.exception("La purga periódica de retención ha fallado")
        await asyncio.sleep(interval)
