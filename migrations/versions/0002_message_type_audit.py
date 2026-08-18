"""Persist the independent message type and review audit events."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0002_message_type_audit"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("verdicts")}
    additions = (
        ("message_type", sa.String(length=32), "desconocido"),
        ("message_type_confidence", sa.Float(), "0"),
        ("message_type_reasons", sa.JSON(), None),
    )
    for name, column_type, default in additions:
        if name not in columns:
            server_default = sa.text(f"'{default}'") if default is not None else None
            op.add_column(
                "verdicts",
                sa.Column(name, column_type, server_default=server_default),
            )
    if not inspector.has_table("audit_events"):
        op.create_table(
            "audit_events",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("actor", sa.String(length=80), nullable=False),
            sa.Column("action", sa.String(length=80), nullable=False),
            sa.Column("target_id", sa.String(length=80)),
            sa.Column("metadata_json", sa.JSON()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_audit_events_actor", "audit_events", ["actor"])
        op.create_index("ix_audit_events_action", "audit_events", ["action"])
        op.create_index("ix_audit_events_target_id", "audit_events", ["target_id"])


def downgrade() -> None:
    inspector = inspect(op.get_bind())
    if inspector.has_table("audit_events"):
        op.drop_index("ix_audit_events_target_id", table_name="audit_events")
        op.drop_index("ix_audit_events_action", table_name="audit_events")
        op.drop_index("ix_audit_events_actor", table_name="audit_events")
        op.drop_table("audit_events")
    columns = {column["name"] for column in inspector.get_columns("verdicts")}
    for name in ("message_type_reasons", "message_type_confidence", "message_type"):
        if name in columns:
            op.drop_column("verdicts", name)
