"""add authenticator-app (TOTP) MFA"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e5f9c2b7d4a1"
down_revision: Union[str, Sequence[str], None] = "d4e8b1a6c3f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("totp_last_counter", sa.BigInteger(), nullable=True))

    op.add_column(
        "otp_verifications",
        sa.Column("method", sa.String(length=10), server_default="email", nullable=False),
    )
    op.create_check_constraint(
        "ck_otp_verifications_method", "otp_verifications", "method IN ('email', 'totp')"
    )
    # An authenticator challenge has no emailed code to hash.
    op.alter_column("otp_verifications", "otp_hash", existing_type=sa.String(length=64), nullable=True)

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_codes_user_code"),
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_mfa_recovery_codes_user_id", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")

    # Pending authenticator challenges cannot exist without the column.
    op.execute("DELETE FROM otp_verifications WHERE otp_hash IS NULL")
    op.alter_column("otp_verifications", "otp_hash", existing_type=sa.String(length=64), nullable=False)
    op.drop_constraint("ck_otp_verifications_method", "otp_verifications", type_="check")
    op.drop_column("otp_verifications", "method")

    op.drop_column("users", "totp_last_counter")
    op.drop_column("users", "totp_enabled_at")
    op.drop_column("users", "totp_secret")
