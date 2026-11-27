from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("mfa_recovery_codes",
        sa.Column("account_id", sa.Uuid(), sa.ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("code_hash", sa.String(64), primary_key=True))
    op.execute("GRANT SELECT, INSERT, DELETE ON mfa_recovery_codes TO rights360_runtime")

def downgrade():
    op.drop_table("mfa_recovery_codes")
