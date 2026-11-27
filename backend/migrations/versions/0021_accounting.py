from alembic import op
import sqlalchemy as sa
revision="0021"
down_revision="0020"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("accounting_entries",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("source_type",sa.String(20),nullable=False),
        sa.Column("source_id",sa.Uuid(),nullable=False),
        sa.Column("currency",sa.String(3),nullable=False),
        sa.Column("posted_by",sa.Uuid(),nullable=False),
        sa.Column("posted_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id","id",name="entry_org_id_unique"),
        sa.UniqueConstraint("organization_id","source_type","source_id",name="entry_source_unique"),
        sa.CheckConstraint("source_type IN ('invoice','receipt','distribution')",name="entry_source_valid"))
    op.create_table("accounting_lines",
        sa.Column("organization_id",sa.Uuid(),primary_key=True),
        sa.Column("entry_id",sa.Uuid(),primary_key=True),
        sa.Column("line_no",sa.Integer(),primary_key=True),
        sa.Column("account_key",sa.String(40),nullable=False),
        sa.Column("artist_id",sa.Uuid()),
        sa.Column("debit_minor",sa.BigInteger(),nullable=False),
        sa.Column("credit_minor",sa.BigInteger(),nullable=False),
        sa.ForeignKeyConstraint(["organization_id","entry_id"],["accounting_entries.organization_id","accounting_entries.id"]),
        sa.ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),
        sa.CheckConstraint("(debit_minor>0 AND credit_minor=0) OR (credit_minor>0 AND debit_minor=0)",name="accounting_side_valid"))
    for table in ("accounting_entries","accounting_lines"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
        op.execute(f"GRANT SELECT,INSERT ON {table} TO rights360_runtime")
    op.execute("""
    CREATE FUNCTION public.check_accounting_balance() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    DECLARE entry uuid; org uuid; deb numeric; cred numeric;
    BEGIN
      org:=NEW.organization_id;
      IF TG_TABLE_NAME='accounting_entries' THEN entry:=NEW.id; ELSE entry:=NEW.entry_id; END IF;
      SELECT COALESCE(sum(debit_minor),0),COALESCE(sum(credit_minor),0) INTO deb,cred FROM public.accounting_lines WHERE organization_id=org AND entry_id=entry;
      IF deb=0 OR deb<>cred THEN RAISE check_violation USING MESSAGE='Unbalanced entry'; END IF;
      RETURN NULL;
    END $$;
    CREATE CONSTRAINT TRIGGER entry_balance AFTER INSERT ON accounting_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.check_accounting_balance();
    CREATE CONSTRAINT TRIGGER line_balance AFTER INSERT ON accounting_lines DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.check_accounting_balance();
    """)

def downgrade():
    op.drop_table("accounting_lines")
    op.drop_table("accounting_entries")
    op.execute("DROP FUNCTION public.check_accounting_balance()")
