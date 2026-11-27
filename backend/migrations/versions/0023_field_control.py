from alembic import op
import sqlalchemy as sa
revision="0023"
down_revision="0022"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("field_visits",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("operator_id",sa.Uuid(),nullable=False),
        sa.Column("agent_id",sa.Uuid(),nullable=False),
        sa.Column("visited_at",sa.DateTime(timezone=True),nullable=False),
        sa.Column("latitude_e6",sa.Integer()),
        sa.Column("longitude_e6",sa.Integer()),
        sa.Column("finding",sa.String(30),nullable=False),
        sa.Column("notes",sa.String(2000),nullable=False),
        sa.Column("payload_hash",sa.String(64),nullable=False),
        sa.Column("license_snapshot",sa.JSON(),nullable=False),
        sa.Column("received_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","operator_id"],["operators.organization_id","operators.id"]),
        sa.CheckConstraint("finding IN ('observed','suspected_noncompliance','followup')",name="visit_finding_valid"),
        sa.CheckConstraint("(latitude_e6 IS NULL AND longitude_e6 IS NULL) OR (latitude_e6 IS NOT NULL AND longitude_e6 IS NOT NULL AND latitude_e6 BETWEEN -90000000 AND 90000000 AND longitude_e6 BETWEEN -180000000 AND 180000000)",name="visit_coordinates_valid"))
    op.create_index("ix_field_visits_org_date","field_visits",["organization_id","visited_at"])
    op.execute("ALTER TABLE field_visits ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE field_visits FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_scope ON field_visits FOR ALL TO rights360_runtime
      USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
      WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute("GRANT SELECT,INSERT ON field_visits TO rights360_runtime")

def downgrade():
    op.drop_table("field_visits")
