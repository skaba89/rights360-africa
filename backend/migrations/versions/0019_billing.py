from alembic import op
import sqlalchemy as sa
revision="0019"
down_revision="0018"
branch_labels=None
depends_on=None

def upgrade():
    op.create_unique_constraint("tariff_org_id_unique","tariffs",["organization_id","id"])
    op.create_unique_constraint("license_org_id_unique","exploitation_licenses",["organization_id","id"])
    op.create_table("royalty_invoices",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("reference",sa.String(50),nullable=False),
        sa.Column("license_id",sa.Uuid(),nullable=False),
        sa.Column("tariff_id",sa.Uuid(),nullable=False),
        sa.Column("usage_date",sa.Date(),nullable=False),
        sa.Column("due_on",sa.Date(),nullable=False),
        sa.Column("quantity",sa.BigInteger()),
        sa.Column("revenue_minor",sa.BigInteger()),
        sa.Column("amount_minor",sa.BigInteger(),nullable=False),
        sa.Column("currency",sa.String(3),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
        sa.ForeignKeyConstraint(["organization_id","license_id"],["exploitation_licenses.organization_id","exploitation_licenses.id"]),
        sa.ForeignKeyConstraint(["organization_id","tariff_id"],["tariffs.organization_id","tariffs.id"]),
        sa.UniqueConstraint("organization_id","id",name="invoice_org_id_unique"),
        sa.UniqueConstraint("organization_id","reference",name="invoice_reference_unique"),
        sa.UniqueConstraint("organization_id","license_id","usage_date",name="invoice_usage_unique"),
        sa.CheckConstraint("amount_minor>0 AND due_on>=usage_date",name="invoice_values_valid"))
    op.create_table("royalty_receipts",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("invoice_id",sa.Uuid(),nullable=False),
        sa.Column("reference",sa.String(50),nullable=False),
        sa.Column("amount_minor",sa.BigInteger(),nullable=False),
        sa.Column("received_on",sa.Date(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
        sa.ForeignKeyConstraint(["organization_id","invoice_id"],["royalty_invoices.organization_id","royalty_invoices.id"]),
        sa.UniqueConstraint("organization_id","reference",name="receipt_reference_unique"),
        sa.CheckConstraint("amount_minor>0",name="receipt_amount_valid"))
    for table in ("royalty_invoices","royalty_receipts"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
        op.execute(f"GRANT SELECT,INSERT ON {table} TO rights360_runtime")
    op.execute("""
    CREATE FUNCTION public.check_receipt_total() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE billed bigint; paid numeric;
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtextextended(NEW.invoice_id::text,362));
      SELECT amount_minor INTO billed FROM public.royalty_invoices WHERE organization_id=NEW.organization_id AND id=NEW.invoice_id;
      SELECT COALESCE(sum(amount_minor),0) INTO paid FROM public.royalty_receipts WHERE organization_id=NEW.organization_id AND invoice_id=NEW.invoice_id;
      IF billed IS NULL OR paid+NEW.amount_minor>billed THEN RAISE check_violation USING MESSAGE='Receipt exceeds balance'; END IF;
      RETURN NEW;
    END $$;
    REVOKE ALL ON FUNCTION public.check_receipt_total() FROM PUBLIC;
    CREATE TRIGGER receipt_total BEFORE INSERT ON royalty_receipts FOR EACH ROW EXECUTE FUNCTION public.check_receipt_total();
    """)

def downgrade():
    op.drop_table("royalty_receipts")
    op.execute("DROP FUNCTION public.check_receipt_total()")
    op.drop_table("royalty_invoices")
    op.drop_constraint("license_org_id_unique","exploitation_licenses",type_="unique")
    op.drop_constraint("tariff_org_id_unique","tariffs",type_="unique")
