"""Canonical investigation states and immutable history."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "s602_investigation"
down_revision = "s601_correlation"
branch_labels = depends_on = None


def upgrade():
    op.add_column("alerts", sa.Column("investigation_state", sa.String(30), nullable=False, server_default="NEW"))
    op.add_column("alerts", sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
    op.execute("UPDATE alerts SET investigation_state = CASE status WHEN 'REVIEWING' THEN 'INVESTIGATING' WHEN 'CLOSED' THEN 'LEGACY_CLOSED' ELSE status END")
    op.create_check_constraint("ck_alerts_investigation_state", "alerts", "investigation_state IN ('NEW', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE', 'LEGACY_CLOSED')")
    op.create_check_constraint("ck_alerts_version", "alerts", "version > 0")
    op.create_table("workflow_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("alert_id", sa.BigInteger(), sa.ForeignKey("alerts.id", ondelete="RESTRICT")),
        sa.Column("incident_id", sa.BigInteger(), sa.ForeignKey("incidents.id", ondelete="RESTRICT")),
        sa.Column("actor_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("actor_name", sa.String(100), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("before", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("after", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("reason", sa.Text()), sa.Column("note", sa.Text()),
        sa.CheckConstraint("(alert_id IS NOT NULL)::integer + (incident_id IS NOT NULL)::integer = 1", name="ck_workflow_events_parent"),
    )
    op.create_index("ix_workflow_events_alert_id_id", "workflow_events", ["alert_id", "id"])
    op.create_index("ix_workflow_events_incident_id_id", "workflow_events", ["incident_id", "id"])
    op.create_table("investigation_notes",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("alert_id", sa.BigInteger(), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("author_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_investigation_notes_alert_id_id", "investigation_notes", ["alert_id", "id"])
    op.execute("""INSERT INTO workflow_events(alert_id, actor_name, event_type, after, reason)
        SELECT id, 'Unknown (legacy import)', 'LEGACY_IMPORTED', jsonb_build_object('state', investigation_state, 'status', status),
        'Imported current state; earlier transitions and their actors were not recorded.' FROM alerts""")
    op.execute("""CREATE FUNCTION reject_workflow_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'Workflow history is append-only'; END; $$""")
    op.execute("CREATE TRIGGER workflow_events_append_only BEFORE UPDATE OR DELETE ON workflow_events FOR EACH ROW EXECUTE FUNCTION reject_workflow_event_mutation()")


def downgrade():
    op.execute("DROP TRIGGER workflow_events_append_only ON workflow_events")
    op.execute("DROP FUNCTION reject_workflow_event_mutation()")
    op.drop_table("investigation_notes")
    op.drop_table("workflow_events")
    op.drop_constraint("ck_alerts_version", "alerts", type_="check")
    op.drop_constraint("ck_alerts_investigation_state", "alerts", type_="check")
    op.drop_column("alerts", "version")
    op.drop_column("alerts", "investigation_state")
