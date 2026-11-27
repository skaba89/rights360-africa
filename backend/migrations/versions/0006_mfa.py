from alembic import op
import sqlalchemy as sa
revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("account_mfa",
        sa.Column("account_id",sa.Uuid(),sa.ForeignKey("accounts.id",ondelete="CASCADE"),primary_key=True),
        sa.Column("secret_ciphertext",sa.Text(),nullable=False),
        sa.Column("last_step",sa.BigInteger(),nullable=False),
        sa.Column("enabled",sa.Boolean(),nullable=False,server_default=sa.false()))
    op.execute("GRANT SELECT, INSERT, UPDATE ON account_mfa TO rights360_runtime")

def downgrade():
    op.drop_table("account_mfa")
