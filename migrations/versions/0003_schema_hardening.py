"""Añade columnas introducidas después del esquema inicial.

Revision ID: 0003_schema_hardening
Revises: 0002_message_type_audit
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_schema_hardening"
down_revision = "0002_message_type_audit"
branch_labels = None
depends_on = None


def _add_if_missing(table: str, column: str, definition: sa.Column) -> None:
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table(table) and column not in {
        item["name"] for item in inspector.get_columns(table)
    }:
        op.add_column(table, definition)


def upgrade() -> None:
    additions = {
        "messages": [("purged_at", sa.Column("purged_at", sa.DateTime(timezone=True)))],
        "signals": [
            ("detail", sa.Column("detail", sa.Text())),
            ("status", sa.Column("status", sa.String(24), server_default="hit")),
            ("source", sa.Column("source", sa.String(40), server_default="legacy")),
            ("version", sa.Column("version", sa.String(40), server_default="legacy")),
        ],
        "verdicts": [
            ("score", sa.Column("score", sa.Integer(), server_default="0")),
            ("rule_trace", sa.Column("rule_trace", sa.JSON())),
            (
                "message_type",
                sa.Column("message_type", sa.String(32), server_default="desconocido"),
            ),
            (
                "message_type_confidence",
                sa.Column("message_type_confidence", sa.Float(), server_default="0"),
            ),
            ("message_type_reasons", sa.Column("message_type_reasons", sa.JSON())),
        ],
        "extractions": [("qr_payload_types", sa.Column("qr_payload_types", sa.JSON()))],
        "campaigns": [
            ("confirmed", sa.Column("confirmed", sa.Boolean(), server_default=sa.false())),
            (
                "cluster_method",
                sa.Column("cluster_method", sa.String(40), server_default="simhash"),
            ),
            ("simhash_band_0", sa.Column("simhash_band_0", sa.Integer())),
            ("simhash_band_1", sa.Column("simhash_band_1", sa.Integer())),
            ("simhash_band_2", sa.Column("simhash_band_2", sa.Integer())),
            ("simhash_band_3", sa.Column("simhash_band_3", sa.Integer())),
        ],
        "feedback": [("reason_code", sa.Column("reason_code", sa.String(40)))],
    }
    for table, columns in additions.items():
        for name, definition in columns:
            _add_if_missing(table, name, definition)
    inspector = sa.inspect(op.get_bind())
    existing_indexes = {item["name"] for item in inspector.get_indexes("campaigns")}
    for band in range(4):
        index_name = f"ix_campaigns_simhash_band_{band}"
        if index_name not in existing_indexes:
            op.create_index(index_name, "campaigns", [f"simhash_band_{band}"])


def downgrade() -> None:
    # Las columnas son compatibles hacia atrás; Alembic puede revertirlas en orden.
    for table, columns in {
        "feedback": ["reason_code"],
        "campaigns": [
            "simhash_band_3",
            "simhash_band_2",
            "simhash_band_1",
            "simhash_band_0",
            "cluster_method",
            "confirmed",
        ],
        "extractions": ["qr_payload_types"],
        "verdicts": [
            "message_type_reasons",
            "message_type_confidence",
            "message_type",
            "rule_trace",
            "score",
        ],
        "signals": ["version", "source", "status", "detail"],
        "messages": ["purged_at"],
    }.items():
        inspector = sa.inspect(op.get_bind())
        if not inspector.has_table(table):
            continue
        existing = {item["name"] for item in inspector.get_columns(table)}
        for column in columns:
            if column in existing:
                op.drop_column(table, column)
    for band in range(4):
        index_name = f"ix_campaigns_simhash_band_{band}"
        if index_name in {
            item["name"] for item in sa.inspect(op.get_bind()).get_indexes("campaigns")
        }:
            op.drop_index(index_name, table_name="campaigns")
