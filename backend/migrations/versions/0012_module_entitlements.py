from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("module_entitlements",
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),primary_key=True),
        sa.Column("module_key",sa.String(80),primary_key=True),
        sa.Column("granted",sa.Boolean(),nullable=False,server_default=sa.false()),
        sa.Column("expires_at",sa.DateTime(timezone=True),nullable=True),
        sa.CheckConstraint("module_key IN ('artists','works','licenses','royalties','finance','field_control','media','analytics','legal','documents')",name="entitlement_module_valid"))
    op.execute("ALTER TABLE module_entitlements ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE module_entitlements FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY entitlement_read ON module_entitlements FOR SELECT TO rights360_runtime
        USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute("GRANT SELECT ON module_entitlements TO rights360_runtime")
    op.execute("ALTER TABLE platform_audit_events ADD COLUMN details jsonb NOT NULL DEFAULT '{}'::jsonb")
    op.execute("""
    CREATE FUNCTION public.platform_set_entitlement(p_session text,p_org uuid,p_key text,p_granted boolean,p_expiry timestamptz)
    RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
      IF NOT public.platform_authorized(p_session) THEN RAISE insufficient_privilege; END IF;
      PERFORM 1 FROM public.organizations WHERE id=p_org AND active FOR UPDATE;
      IF NOT FOUND THEN RETURN false; END IF;
      IF p_granted IS NULL OR (p_granted AND p_expiry IS NOT NULL AND p_expiry<=now()) THEN RAISE check_violation; END IF;
      INSERT INTO public.module_entitlements(organization_id,module_key,granted,expires_at)
      VALUES(p_org,p_key,p_granted,p_expiry)
      ON CONFLICT(organization_id,module_key) DO UPDATE SET granted=EXCLUDED.granted,expires_at=EXCLUDED.expires_at;
      INSERT INTO public.platform_audit_events(actor_id,organization_id,action,details)
      SELECT account_id,p_org,'entitlement.updated',jsonb_build_object('module',p_key,'granted',p_granted,'expires_at',p_expiry)
      FROM public.auth_sessions WHERE token_hash=p_session;
      RETURN true;
    END $$;
    REVOKE ALL ON FUNCTION public.platform_set_entitlement(text,uuid,text,boolean,timestamptz) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_set_entitlement(text,uuid,text,boolean,timestamptz) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.platform_list_entitlements(p_session text,p_org uuid)
    RETURNS TABLE(module_key varchar,granted boolean,expires_at timestamptz)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
      IF NOT public.platform_authorized(p_session) THEN RAISE insufficient_privilege; END IF;
      RETURN QUERY SELECT e.module_key,e.granted,e.expires_at FROM public.module_entitlements e
      WHERE e.organization_id=p_org ORDER BY e.module_key;
    END $$;
    REVOKE ALL ON FUNCTION public.platform_list_entitlements(text,uuid) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_list_entitlements(text,uuid) TO rights360_runtime;
    """)

def downgrade():
    op.execute("DROP FUNCTION public.platform_list_entitlements(text,uuid)")
    op.execute("DROP FUNCTION public.platform_set_entitlement(text,uuid,text,boolean,timestamptz)")
    op.execute("ALTER TABLE platform_audit_events DROP COLUMN details")
    op.drop_table("module_entitlements")
