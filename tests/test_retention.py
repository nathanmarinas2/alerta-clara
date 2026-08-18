from datetime import UTC, datetime, timedelta

from app.database import SessionLocal, create_tables
from app.models import Extraction, Message
from app.services.retention import purge_expired_message_data


def test_purge_removes_expired_personal_content_but_keeps_record() -> None:
    create_tables()
    now = datetime.now(UTC)
    with SessionLocal() as db:
        message = Message(
            channel="api",
            user_hash="hashed-user",
            received_at=now - timedelta(hours=48),
            body_redacted="Texto ya redactado",
        )
        message.extraction = Extraction(
            sender_alias="Remitente",
            sender_number="[TELÉFONO]",
            claimed_entity="CaixaBank",
            urls=["https://example.org/?token=[DATO]"],
            requested_action="pinchar_enlace",
            urgency_markers=["urgente"],
        )
        db.add(message)
        db.commit()
        message_id = message.id

        result = purge_expired_message_data(db, 24, now=now)

        db.expire_all()
        purged = db.get(Message, message_id)
        assert result.messages_purged >= 1
        assert purged is not None
        assert purged.body_redacted == ""
        assert purged.user_hash is None
        stored_purge_time = purged.purged_at
        assert stored_purge_time is not None
        if stored_purge_time.tzinfo is None:
            stored_purge_time = stored_purge_time.replace(tzinfo=UTC)
        assert stored_purge_time == now
        assert purged.extraction is not None
        assert purged.extraction.sender_alias is None
        assert purged.extraction.sender_number is None
        assert purged.extraction.urls == []
        assert purged.extraction.claimed_entity == "CaixaBank"
