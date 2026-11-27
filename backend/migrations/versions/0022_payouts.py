from alembic import op
import sqlalchemy as sa
revision="0022"
down_revision="0021"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("payout_orders",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("distribution_id",sa.Uuid(),nullable=False),
        sa.Column("artist_id",sa.Uuid(),nullable=False),
        sa.Column("channel",sa.String(30),nullable=False),
        sa.Column("amount_minor",sa.BigInteger(),nullable=False),
        sa.Column("currency",sa.String(3),nullable=False),
        sa.Column("created_by",sa.Uuid(),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","distribution_id"],["royalty_distributions.organization_id","royalty_distributions.id"]),
        sa.ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),
        sa.UniqueConstraint("organization_id","id",name="payout_org_id_unique"),
        sa.UniqueConstraint("organization_id","distribution_id","artist_id",name="payout_once"),
        sa.CheckConstraint("amount_minor>0 AND channel IN ('bank','orange_money','mtn_momo','other')",name="payout_values_valid"))
    op.create_table("payout_reviews",
        sa.Column("organization_id",sa.Uuid(),primary_key=True),
        sa.Column("order_id",sa.Uuid(),primary_key=True),
        sa.Column("reviewer_id",sa.Uuid(),primary_key=True),
        sa.Column("decision",sa.String(20),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id","order_id"],["payout_orders.organization_id","payout_orders.id"]),
        sa.CheckConstraint("decision IN ('approve','reject')",name="payout_decision_valid"))
    for table in ("payout_orders","payout_reviews"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
        WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
        op.execute(f"GRANT SELECT,INSERT ON {table} TO rights360_runtime")
    op.execute("""
    CREATE FUNCTION public.check_payout_review() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    DECLARE creator uuid; approvals integer; rejected boolean;
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtextextended(NEW.order_id::text,363));
      SELECT created_by INTO creator FROM public.payout_orders WHERE organization_id=NEW.organization_id AND id=NEW.order_id;
      SELECT count(*) FILTER (WHERE decision='approve'),COALESCE(bool_or(decision='reject'),false)
      INTO approvals,rejected FROM public.payout_reviews WHERE organization_id=NEW.organization_id AND order_id=NEW.order_id;
      IF creator IS NULL OR creator=NEW.reviewer_id OR rejected OR approvals>=2 THEN
        RAISE check_violation USING MESSAGE='Invalid payout review';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER payout_review_guard BEFORE INSERT ON payout_reviews FOR EACH ROW EXECUTE FUNCTION public.check_payout_review();
    """)

def downgrade():
    op.drop_table("payout_reviews")
    op.execute("DROP FUNCTION public.check_payout_review()")
    op.drop_table("payout_orders")
