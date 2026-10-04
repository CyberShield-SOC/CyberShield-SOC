"""Sprint 6 correlation groups and exact source evidence."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = "s601_correlation"
down_revision = "f2a9c7e410b3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "correlation_groups",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("group_type", sa.String(100), nullable=False),
        sa.Column("entity_type", sa.String(20), nullable=False),
        sa.Column("entity_value", sa.String(255), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Integer()),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("rule_key", sa.String(100), nullable=False),
        sa.Column("rule_context", pg.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("entity_type IN ('source_ip','account','host','upload_batch')", name="ck_correlation_entity_type"),
        sa.CheckConstraint("last_seen >= first_seen", name="ck_correlation_observation_order"),
        sa.CheckConstraint("window_seconds > 0", name="ck_correlation_window"),
        sa.CheckConstraint("confidence IS NULL OR confidence BETWEEN 0 AND 100", name="ck_correlation_confidence"),
        sa.CheckConstraint("severity IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_correlation_severity"),
    )
    op.create_index("ix_correlation_entity", "correlation_groups", ["entity_type", "entity_value"])
    op.create_index("ix_correlation_first_seen", "correlation_groups", ["first_seen", "id"])
    op.create_index("ix_correlation_rule_key", "correlation_groups", ["rule_key"])
    for table, target, column, index in (
        ("correlation_group_events", "logs.id", "log_id", "ix_correlation_events_log"),
        ("correlation_group_alerts", "alerts.id", "alert_id", "ix_correlation_alerts_alert"),
        ("correlation_group_uploads", "upload_batches.upload_id", "upload_id", "ix_correlation_uploads_upload"),
    ):
        op.create_table(
            table,
            sa.Column("group_id", sa.BigInteger(), sa.ForeignKey("correlation_groups.id", ondelete="CASCADE"), primary_key=True),
            sa.Column(column, pg.UUID(as_uuid=True) if column == "upload_id" else sa.BigInteger(), sa.ForeignKey(target, ondelete="RESTRICT"), primary_key=True),
        )
        op.create_index(index, table, [column])
    op.create_table(
        "alert_event_links",
        sa.Column("alert_id", sa.BigInteger(), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("log_id", sa.BigInteger(), sa.ForeignKey("logs.id", ondelete="RESTRICT"), primary_key=True),
    )
    op.create_index("ix_alert_event_links_log", "alert_event_links", ["log_id"])
    # Missing legacy events remain missing. Never join a line from another upload.
    op.execute("""
        INSERT INTO alert_event_links (alert_id, log_id)
        SELECT DISTINCT a.id, l.id FROM alerts a JOIN logs l
          ON l.upload_id = a.upload_id AND l.line_number = ANY(a.matched_line_numbers)
        ON CONFLICT DO NOTHING
    """)


def downgrade():
    for table in ("alert_event_links", "correlation_group_uploads", "correlation_group_alerts", "correlation_group_events", "correlation_groups"):
        op.drop_table(table)
