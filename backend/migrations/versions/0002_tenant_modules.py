from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("tenant_modules",
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), primary_key=True),
        sa.Column("module_key", sa.String(80), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    for table, column in (("organizations", "id"), ("tenant_modules", "organization_id")):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
          USING ({column} = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
          WITH CHECK ({column} = NULLIF(current_setting('app.tenant_id', true), '')::uuid)""")
    op.execute("GRANT SELECT ON organizations TO rights360_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_modules TO rights360_runtime")

def downgrade():
    op.execute("REVOKE SELECT ON organizations FROM rights360_runtime")
    op.execute("DROP POLICY tenant_scope ON organizations")
    op.execute("ALTER TABLE organizations NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE organizations DISABLE ROW LEVEL SECURITY")
    op.drop_table("tenant_modules")
