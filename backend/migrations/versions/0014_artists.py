from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("artists",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("member_number",sa.String(50),nullable=False),
        sa.Column("legal_name",sa.String(200),nullable=False),
        sa.Column("stage_name",sa.String(200)),
        sa.Column("email",sa.String(254)),
        sa.Column("phone",sa.String(40)),
        sa.Column("status",sa.String(20),nullable=False,server_default="pending"),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id","member_number",name="artist_member_number_unique"),
        sa.CheckConstraint("status IN ('pending','active','suspended','archived')",name="artist_status_valid"))
    op.create_index("ix_artists_org_name","artists",["organization_id","legal_name","id"])
    op.execute("ALTER TABLE artists ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE artists FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY artist_scope ON artists FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute("GRANT SELECT,INSERT,UPDATE ON artists TO rights360_runtime")

def downgrade():
    op.drop_table("artists")
