from alembic import op
import sqlalchemy as sa
revision="0026"
down_revision="0025"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("documents",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("title",sa.String(200),nullable=False),
        sa.Column("category",sa.String(30),nullable=False),
        sa.Column("artist_id",sa.Uuid()),
        sa.Column("work_id",sa.Uuid()),
        sa.Column("operator_id",sa.Uuid()),
        sa.Column("license_id",sa.Uuid()),
        sa.Column("created_by",sa.Uuid(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),
        sa.ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),
        sa.ForeignKeyConstraint(["organization_id","operator_id"],["operators.organization_id","operators.id"]),
        sa.ForeignKeyConstraint(["organization_id","license_id"],["exploitation_licenses.organization_id","exploitation_licenses.id"]),
        sa.CheckConstraint("num_nonnulls(artist_id,work_id,operator_id,license_id)<=1",name="document_one_subject"),
        sa.CheckConstraint("category IN ('contract','license','supporting','administrative','other')",name="document_category_valid"),
        sa.UniqueConstraint("organization_id","id",name="documents_org_id_unique"))
    op.create_table("document_versions",
        sa.Column("organization_id",sa.Uuid(),primary_key=True),
        sa.Column("document_id",sa.Uuid(),primary_key=True),
        sa.Column("version",sa.Integer(),primary_key=True),
        sa.Column("sha256",sa.String(64),nullable=False),
        sa.Column("size_bytes",sa.Integer(),nullable=False),
        sa.Column("content",sa.LargeBinary(),nullable=False),
        sa.Column("created_by",sa.Uuid(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","document_id"],["documents.organization_id","documents.id"]),
        sa.CheckConstraint("version>0 AND size_bytes BETWEEN 1 AND 2097152 AND octet_length(content)=size_bytes",name="document_version_valid"),
        sa.UniqueConstraint("organization_id","document_id","sha256",name="document_content_unique"))
    op.create_table("document_archives",
        sa.Column("organization_id",sa.Uuid(),primary_key=True),
        sa.Column("document_id",sa.Uuid(),primary_key=True),
        sa.Column("archived_by",sa.Uuid(),nullable=False),
        sa.Column("archived_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","document_id"],["documents.organization_id","documents.id"]))
    for table in ("documents","document_versions","document_archives"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
        op.execute(f"GRANT SELECT,INSERT ON {table} TO rights360_runtime")

def downgrade():
    op.drop_table("document_archives")
    op.drop_table("document_versions")
    op.drop_table("documents")
