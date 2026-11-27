from alembic import op
import sqlalchemy as sa
revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("platform_admins",
        sa.Column("account_id",sa.Uuid(),sa.ForeignKey("accounts.id",ondelete="CASCADE"),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("active",sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.ForeignKeyConstraint(["account_id","organization_id"],["memberships.account_id","memberships.organization_id"],ondelete="CASCADE"))
    op.execute("GRANT SELECT ON platform_admins TO rights360_runtime")

def downgrade():
    op.drop_table("platform_admins")
