from alembic import op
import sqlalchemy as sa
revision="0020"
down_revision="0019"
branch_labels=None
depends_on=None

def upgrade():
    op.create_unique_constraint("receipt_org_id_unique","royalty_receipts",["organization_id","id"])
    op.create_table("royalty_distributions",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("receipt_id",sa.Uuid(),nullable=False),
        sa.Column("declaration_id",sa.Uuid(),nullable=False),
        sa.Column("currency",sa.String(3),nullable=False),
        sa.Column("gross_minor",sa.BigInteger(),nullable=False),
        sa.Column("commission_bps",sa.Integer(),nullable=False),
        sa.Column("commission_minor",sa.BigInteger(),nullable=False),
        sa.Column("net_minor",sa.BigInteger(),nullable=False),
        sa.Column("created_by",sa.Uuid(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","receipt_id"],["royalty_receipts.organization_id","royalty_receipts.id"]),
        sa.ForeignKeyConstraint(["organization_id","declaration_id"],["work_rights_declarations.organization_id","work_rights_declarations.id"]),
        sa.UniqueConstraint("organization_id","id",name="distribution_org_id_unique"),
        sa.UniqueConstraint("organization_id","receipt_id",name="distribution_receipt_unique"),
        sa.CheckConstraint("gross_minor>0 AND commission_bps BETWEEN 0 AND 10000 AND commission_minor>=0 AND net_minor>=0 AND gross_minor=commission_minor+net_minor",name="distribution_amounts_valid"))
    op.create_table("royalty_distribution_lines",
        sa.Column("organization_id",sa.Uuid(),primary_key=True),
        sa.Column("distribution_id",sa.Uuid(),primary_key=True),
        sa.Column("artist_id",sa.Uuid(),primary_key=True),
        sa.Column("role",sa.String(30),primary_key=True),
        sa.Column("basis_points",sa.Integer(),nullable=False),
        sa.Column("amount_minor",sa.BigInteger(),nullable=False),
        sa.ForeignKeyConstraint(["organization_id","distribution_id"],["royalty_distributions.organization_id","royalty_distributions.id"]),
        sa.ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),
        sa.CheckConstraint("amount_minor>=0 AND basis_points BETWEEN 1 AND 10000",name="distribution_line_valid"))
    for table in ("royalty_distributions","royalty_distribution_lines"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
        op.execute(f"GRANT SELECT,INSERT ON {table} TO rights360_runtime")
    op.execute("""
    CREATE FUNCTION public.check_distribution_total() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    DECLARE distribution uuid; org uuid; net bigint; total numeric; bps bigint;
    BEGIN
      org:=NEW.organization_id;
      IF TG_TABLE_NAME='royalty_distributions' THEN distribution:=NEW.id; ELSE distribution:=NEW.distribution_id; END IF;
      SELECT net_minor INTO net FROM public.royalty_distributions WHERE organization_id=org AND id=distribution;
      SELECT COALESCE(sum(amount_minor),0),COALESCE(sum(basis_points),0) INTO total,bps FROM public.royalty_distribution_lines WHERE organization_id=org AND distribution_id=distribution;
      IF net IS NULL OR total<>net OR bps<>10000 THEN RAISE check_violation USING MESSAGE='Distribution not balanced'; END IF;
      RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER distribution_total AFTER INSERT ON royalty_distributions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.check_distribution_total();
    CREATE CONSTRAINT TRIGGER distribution_line_total AFTER INSERT ON royalty_distribution_lines DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.check_distribution_total();
    """)

def downgrade():
    op.drop_table("royalty_distribution_lines")
    op.drop_table("royalty_distributions")
    op.execute("DROP FUNCTION public.check_distribution_total()")
    op.drop_constraint("receipt_org_id_unique","royalty_receipts",type_="unique")
