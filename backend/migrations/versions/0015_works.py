from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

def upgrade():
    op.create_unique_constraint("artist_org_id_unique","artists",["organization_id","id"])
    op.create_table("works",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("reference",sa.String(50),nullable=False),
        sa.Column("title",sa.String(250),nullable=False),
        sa.Column("category",sa.String(30),nullable=False),
        sa.Column("primary_artist_id",sa.Uuid(),nullable=False),
        sa.Column("iswc",sa.String(11)),
        sa.Column("status",sa.String(20),nullable=False,server_default="draft"),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","primary_artist_id"],["artists.organization_id","artists.id"],name="work_artist_same_org"),
        sa.UniqueConstraint("organization_id","reference",name="work_reference_unique"),
        sa.UniqueConstraint("organization_id","iswc",name="work_iswc_unique"),
        sa.CheckConstraint("category IN ('music','literary','audiovisual','visual','other')",name="work_category_valid"),
        sa.CheckConstraint("status IN ('draft','registered','archived')",name="work_status_valid"),
        sa.CheckConstraint("iswc IS NULL OR (category='music' AND iswc ~ '^T[0-9]{10}$')",name="work_iswc_format"))
    op.create_index("ix_works_org_title","works",["organization_id","title","id"])
    op.execute("ALTER TABLE works ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE works FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY work_scope ON works FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute("GRANT SELECT,INSERT,UPDATE ON works TO rights360_runtime")

def downgrade():
    op.drop_table("works")
    op.drop_constraint("artist_org_id_unique","artists",type_="unique")
