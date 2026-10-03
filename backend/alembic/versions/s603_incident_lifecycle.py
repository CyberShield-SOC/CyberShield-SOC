"""Incident resolution snapshots, reopening, and multiple linked alerts."""
from alembic import op
import sqlalchemy as sa

revision = "s603_incidents"
down_revision = "s602_investigation"
branch_labels = depends_on = None


def upgrade():
    op.add_column("incidents", sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("incidents", sa.Column("resolution_reason", sa.Text()))
    op.add_column("incidents", sa.Column("resolution_note", sa.Text()))
    op.add_column("incidents", sa.Column("resolved_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL")))
    op.add_column("incidents", sa.Column("resolved_by_name", sa.String(100)))
    op.create_check_constraint("ck_incidents_version", "incidents", "version > 0")
    op.create_table("incident_alert_links",
        sa.Column("incident_id", sa.BigInteger(), sa.ForeignKey("incidents.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("alert_id", sa.BigInteger(), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), primary_key=True, unique=True),
    )
    op.create_index("ix_incident_alert_links_incident_id", "incident_alert_links", ["incident_id"])
    op.execute("INSERT INTO incident_alert_links(incident_id, alert_id) SELECT id, source_alert_id FROM incidents")
    op.execute("UPDATE incidents SET resolution_reason = 'LEGACY_UNKNOWN' WHERE status IN ('RESOLVED', 'FALSE_POSITIVE')")
    op.execute("""INSERT INTO workflow_events(incident_id, actor_name, event_type, after, reason)
        SELECT id, 'Unknown (legacy import)', 'LEGACY_IMPORTED',
        jsonb_build_object('status', status, 'assigned_user_id', assigned_user_id, 'source_alert_id', source_alert_id,
        'created_at', created_at, 'resolved_at', resolved_at, 'closed_at', closed_at),
        'Imported existing facts; resolution notes, previous transitions, and responsible actors are unknown.' FROM incidents""")


def downgrade():
    # Workflow history remains in s602; this downgrade removes derived links
    # and current completion fields without rewriting historical events.
    op.drop_table("incident_alert_links")
    op.drop_constraint("ck_incidents_version", "incidents", type_="check")
    for column in ("resolved_by_name", "resolved_by_user_id", "resolution_note", "resolution_reason", "version"):
        op.drop_column("incidents", column)
