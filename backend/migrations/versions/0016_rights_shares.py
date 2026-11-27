from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

def upgrade():
    op.create_unique_constraint("work_org_id_unique","works",["organization_id","id"])
    op.create_table("work_rights_declarations",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("work_id",sa.Uuid(),nullable=False),
        sa.Column("version",sa.Integer(),nullable=False),
        sa.Column("status",sa.String(20),nullable=False),
        sa.Column("created_by",sa.Uuid(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),
        sa.UniqueConstraint("organization_id","id",name="rights_declaration_org_id_unique"),
        sa.UniqueConstraint("organization_id","work_id","version",name="rights_declaration_version_unique"),
        sa.CheckConstraint("version>0 AND status IN ('draft','complete')",name="rights_declaration_valid"))
    op.create_table("work_rights_shares",
        sa.Column("organization_id",sa.Uuid(),primary_key=True),
        sa.Column("declaration_id",sa.Uuid(),primary_key=True),
        sa.Column("artist_id",sa.Uuid(),primary_key=True),
        sa.Column("role",sa.String(30),primary_key=True),
        sa.Column("basis_points",sa.Integer(),nullable=False),
        sa.ForeignKeyConstraint(["organization_id","declaration_id"],["work_rights_declarations.organization_id","work_rights_declarations.id"]),
        sa.ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),
        sa.CheckConstraint("basis_points BETWEEN 1 AND 10000",name="rights_share_range"),
        sa.CheckConstraint("role IN ('author','composer','publisher','beneficiary','other')",name="rights_share_role_valid"))
    for table in ("work_rights_declarations","work_rights_shares"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
            USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
            WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
        op.execute(f"GRANT SELECT,INSERT ON {table} TO rights360_runtime")
    # Enforce aggregate limits even when an insert bypasses the application.
    op.execute("""
    CREATE FUNCTION public.check_rights_declaration_total() RETURNS trigger
    LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    DECLARE org uuid; declaration uuid; expected text; total bigint;
    BEGIN
      org:=NEW.organization_id;
      IF TG_TABLE_NAME='work_rights_declarations' THEN declaration:=NEW.id;
      ELSE declaration:=NEW.declaration_id; END IF;
      SELECT status INTO expected FROM public.work_rights_declarations WHERE organization_id=org AND id=declaration;
      SELECT COALESCE(sum(basis_points),0) INTO total FROM public.work_rights_shares WHERE organization_id=org AND declaration_id=declaration;
      IF total>10000 OR (expected='complete' AND total<>10000) THEN
        RAISE check_violation USING MESSAGE='Invalid rights share total';
      END IF;
      RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER rights_declaration_total AFTER INSERT ON work_rights_declarations
      DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.check_rights_declaration_total();
    CREATE CONSTRAINT TRIGGER rights_share_total AFTER INSERT ON work_rights_shares
      DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.check_rights_declaration_total();
    """)

def downgrade():
    op.drop_table("work_rights_shares")
    op.drop_table("work_rights_declarations")
    op.execute("DROP FUNCTION public.check_rights_declaration_total()")
    op.drop_constraint("work_org_id_unique","works",type_="unique")
