from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("tariffs",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("reference",sa.String(50),nullable=False),
        sa.Column("version",sa.Integer(),nullable=False),
        sa.Column("category",sa.String(30),nullable=False),
        sa.Column("usage_type",sa.String(100),nullable=False),
        sa.Column("method",sa.String(20),nullable=False),
        sa.Column("currency",sa.String(3),nullable=False),
        sa.Column("rate",sa.BigInteger(),nullable=False),
        sa.Column("starts_on",sa.Date(),nullable=False),
        sa.Column("ends_on",sa.Date(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id","reference","version",name="tariff_version_unique"),
        sa.CheckConstraint("version>0 AND starts_on<=ends_on AND rate>0 AND rate<=1000000000000",name="tariff_values_valid"),
        sa.CheckConstraint("category IN ('radio','television','hotel','restaurant','event','digital','other')",name="tariff_category_valid"),
        sa.CheckConstraint("method IN ('flat','revenue','capacity','frequency') AND (method<>'revenue' OR rate<=10000)",name="tariff_method_valid"),
        sa.CheckConstraint("currency IN ('GNF','XOF','EUR','USD')",name="tariff_currency_valid"))
    op.execute("ALTER TABLE tariffs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tariffs FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tariff_scope ON tariffs FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute("GRANT SELECT,INSERT ON tariffs TO rights360_runtime")

def downgrade():
    op.drop_table("tariffs")
