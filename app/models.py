from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    channel: Mapped[str] = mapped_column(String(24), nullable=False)
    user_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    body_redacted: Mapped[str] = mapped_column(Text, default="")
    lang: Mapped[str] = mapped_column(String(10), default="es")
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    extraction: Mapped[Extraction | None] = relationship(
        back_populates="message", cascade="all, delete-orphan", uselist=False
    )
    signals: Mapped[list[Signal]] = relationship(
        back_populates="message", cascade="all, delete-orphan"
    )
    verdict: Mapped[Verdict | None] = relationship(
        back_populates="message", cascade="all, delete-orphan", uselist=False
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="message", cascade="all, delete-orphan"
    )


class Extraction(Base):
    __tablename__ = "extractions"

    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), primary_key=True)
    sender_alias: Mapped[str | None] = mapped_column(String(120))
    sender_number: Mapped[str | None] = mapped_column(String(40))
    claimed_entity: Mapped[str | None] = mapped_column(String(120))
    urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    requested_action: Mapped[str] = mapped_column(String(40), nullable=False)
    urgency_markers: Mapped[list[str]] = mapped_column(JSON, default=list)
    qr_payload_types: Mapped[list[str] | None] = mapped_column(JSON, default=list)

    message: Mapped[Message] = relationship(back_populates="extraction")


class Signal(Base):
    __tablename__ = "signals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), index=True)
    check_name: Mapped[str] = mapped_column(String(80), nullable=False)
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON)
    weight: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    hard_rule: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str | None] = mapped_column(String(24), default="hit")
    source: Mapped[str | None] = mapped_column(String(40), default="local")
    version: Mapped[str | None] = mapped_column(String(40), default="1")

    message: Mapped[Message] = relationship(back_populates="signals")


class Verdict(Base):
    __tablename__ = "verdicts"

    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), primary_key=True)
    level: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    message_type: Mapped[str] = mapped_column(String(32), nullable=False, default="desconocido")
    message_type_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    message_type_reasons: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    score: Mapped[int | None] = mapped_column(Integer, default=0)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    model_version: Mapped[str] = mapped_column(String(100), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(50), nullable=False)
    rule_trace: Mapped[list[dict] | None] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    message: Mapped[Message] = relationship(back_populates="verdict")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    simhash: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    simhash_band_0: Mapped[int | None] = mapped_column(Integer, index=True)
    simhash_band_1: Mapped[int | None] = mapped_column(Integer, index=True)
    simhash_band_2: Mapped[int | None] = mapped_column(Integer, index=True)
    simhash_band_3: Mapped[int | None] = mapped_column(Integer, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    hits: Mapped[int] = mapped_column(Integer, default=1)
    entity: Mapped[str | None] = mapped_column(String(120))
    verdict: Mapped[str] = mapped_column(String(40), nullable=False)
    confirmed: Mapped[bool | None] = mapped_column(Boolean, default=False)
    cluster_method: Mapped[str | None] = mapped_column(String(40), default="simhash")


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("message_id", "artifact_type", "value_hash", name="uq_message_artifact"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), index=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), index=True)
    artifact_type: Mapped[str] = mapped_column(String(40), index=True)
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    value_public: Mapped[str | None] = mapped_column(String(500), index=True)
    source: Mapped[str] = mapped_column(String(40), default="extraction")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    message: Mapped[Message] = relationship(back_populates="artifacts")


class FeedSnapshot(Base):
    __tablename__ = "feed_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(80), index=True)
    version: Mapped[str] = mapped_column(String(100))
    checksum: Mapped[str] = mapped_column(String(64))
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=True)
    error_type: Mapped[str | None] = mapped_column(String(100))


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint(
            "provider", "indicator_type", "value_hash", name="uq_provider_indicator"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(80), index=True)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("feed_snapshots.id"), index=True)
    indicator_type: Mapped[str] = mapped_column(String(20), index=True)
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    value_public: Mapped[str | None] = mapped_column(String(500), index=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ReviewItem(Base):
    __tablename__ = "review_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), unique=True)
    reason: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Feedback(Base):
    __tablename__ = "feedback"

    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id"), primary_key=True)
    user_said: Mapped[str] = mapped_column(String(20), nullable=False)
    human_reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    was_correct: Mapped[bool | None] = mapped_column(Boolean)
    reason_code: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_id: Mapped[str | None] = mapped_column(String(80), index=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    official_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    official_numbers: Mapped[list[str]] = mapped_column(JSON, default=list)
