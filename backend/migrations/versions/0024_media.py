from alembic import op
import sqlalchemy as sa
revision="0024"
down_revision="0023"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("media_observations",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("operator_id",sa.Uuid(),nullable=False),
        sa.Column("external_reference",sa.String(100),nullable=False),
        sa.Column("aired_at",sa.DateTime(timezone=True),nullable=False),
        sa.Column("duration_seconds",sa.Integer(),nullable=False),
        sa.Column("reported_title",sa.String(250),nullable=False),
        sa.Column("reported_artist",sa.String(200),nullable=False),
        sa.Column("fingerprint_sha256",sa.String(64)),
        sa.Column("created_by",sa.Uuid(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","operator_id"],["operators.organization_id","operators.id"]),
        sa.UniqueConstraint("organization_id","id",name="media_org_id_unique"),
        sa.UniqueConstraint("organization_id","operator_id","external_reference",name="media_reference_unique"),
        sa.CheckConstraint("duration_seconds BETWEEN 1 AND 86400",name="media_duration_valid"))
    op.create_table("media_reviews",
        sa.Column("organization_id",sa.Uuid(),primary_key=True),
        sa.Column("observation_id",sa.Uuid(),primary_key=True),
        sa.Column("work_id",sa.Uuid()),
        sa.Column("decision",sa.String(20),nullable=False),
        sa.Column("reviewed_by",sa.Uuid(),nullable=False),
        sa.Column("reviewed_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","observation_id"],["media_observations.organization_id","media_observations.id"]),
        sa.ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),
        sa.CheckConstraint("(decision='matched' AND work_id IS NOT NULL) OR (decision='unmatched' AND work_id IS NULL)",name="media_review_valid"))
    for table in ("media_observations","media_reviews"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
        op.execute(f"GRANT SELECT,INSERT ON {table} TO rights360_runtime")
    op.create_index("ix_media_org_aired","media_observations",["organization_id","aired_at"])

def downgrade():
    op.drop_table("media_reviews")
    op.drop_table("media_observations")
