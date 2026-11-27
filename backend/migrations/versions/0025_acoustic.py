from alembic import op
import sqlalchemy as sa
revision="0025"
down_revision="0024"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("acoustic_references",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("work_id",sa.Uuid(),nullable=False),
        sa.Column("audio_sha256",sa.String(64),nullable=False),
        sa.Column("signature",sa.JSON(),nullable=False),
        sa.Column("created_by",sa.Uuid(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
        sa.ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),
        sa.UniqueConstraint("organization_id","audio_sha256",name="acoustic_digest_unique"))
    op.execute("ALTER TABLE acoustic_references ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE acoustic_references FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_scope ON acoustic_references FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute("GRANT SELECT,INSERT ON acoustic_references TO rights360_runtime")

def downgrade():
    op.drop_table("acoustic_references")
