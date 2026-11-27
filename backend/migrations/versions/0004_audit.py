from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("audit_events",
        sa.Column("id",sa.BigInteger(),sa.Identity(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("actor_id",sa.Uuid(),nullable=False),
        sa.Column("action",sa.String(100),nullable=False),
        sa.Column("resource_key",sa.String(100),nullable=False),
        sa.Column("details",JSONB(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    op.execute("ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_events FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY audit_insert ON audit_events FOR INSERT TO rights360_runtime
        WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute("GRANT INSERT ON audit_events TO rights360_runtime")
    op.execute("GRANT USAGE ON SEQUENCE audit_events_id_seq TO rights360_runtime")

def downgrade():
    op.drop_table("audit_events")
