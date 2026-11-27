from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

def upgrade():
    op.execute("""
    CREATE FUNCTION public.tenant_admin_org(p_session text) RETURNS uuid
    LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
      SELECT s.organization_id FROM public.auth_sessions s
      JOIN public.accounts a ON a.id=s.account_id
      JOIN public.memberships m ON m.account_id=s.account_id AND m.organization_id=s.organization_id
      JOIN public.account_mfa f ON f.account_id=s.account_id
      JOIN public.organizations o ON o.id=s.organization_id
      WHERE s.token_hash=p_session AND s.expires_at>now() AND a.active AND m.active
        AND m.role='admin' AND f.enabled AND o.active
    $$;
    REVOKE ALL ON FUNCTION public.tenant_admin_org(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.tenant_admin_org(text) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.tenant_list_members(p_session text,p_limit integer,p_offset integer)
    RETURNS TABLE(account_id uuid,email varchar,role varchar,active boolean,mfa_enabled boolean)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE org uuid;
    BEGIN
      org := public.tenant_admin_org(p_session);
      IF org IS NULL THEN RAISE insufficient_privilege; END IF;
      RETURN QUERY SELECT m.account_id,a.email,m.role,(m.active AND a.active),COALESCE(f.enabled,false)
      FROM public.memberships m JOIN public.accounts a ON a.id=m.account_id
      LEFT JOIN public.account_mfa f ON f.account_id=m.account_id
      WHERE m.organization_id=org ORDER BY a.email,m.account_id
      LIMIT LEAST(GREATEST(p_limit,1),100) OFFSET GREATEST(p_offset,0);
    END $$;
    REVOKE ALL ON FUNCTION public.tenant_list_members(text,integer,integer) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.tenant_list_members(text,integer,integer) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.tenant_update_member(p_session text,p_target uuid,p_role text,p_active boolean)
    RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE org uuid; actor uuid; old_role text;
    BEGIN
      org := public.tenant_admin_org(p_session);
      IF org IS NULL THEN RAISE insufficient_privilege; END IF;
      PERFORM 1 FROM public.organizations WHERE id=org AND active FOR UPDATE;
      IF NOT FOUND OR public.tenant_admin_org(p_session) IS DISTINCT FROM org THEN
        RAISE insufficient_privilege;
      END IF;
      SELECT account_id INTO actor FROM public.auth_sessions WHERE token_hash=p_session;
      IF actor=p_target OR p_role IS NULL OR p_active IS NULL
        OR p_role NOT IN ('manager','auditor','artist') THEN
        RAISE insufficient_privilege;
      END IF;
      SELECT role INTO old_role FROM public.memberships WHERE organization_id=org AND account_id=p_target FOR UPDATE;
      IF NOT FOUND THEN RETURN false; END IF;
      IF old_role='admin' OR EXISTS (SELECT 1 FROM public.platform_admins WHERE account_id=p_target) THEN
        RAISE insufficient_privilege;
      END IF;
      UPDATE public.memberships SET role=p_role,active=p_active WHERE organization_id=org AND account_id=p_target;
      DELETE FROM public.auth_sessions WHERE organization_id=org AND account_id=p_target;
      INSERT INTO public.audit_events(organization_id,actor_id,action,resource_key,details)
      VALUES(org,actor,'member.updated',p_target::text,jsonb_build_object('role',p_role,'active',p_active));
      RETURN true;
    END $$;
    REVOKE ALL ON FUNCTION public.tenant_update_member(text,uuid,text,boolean) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.tenant_update_member(text,uuid,text,boolean) TO rights360_runtime;
    """)

def downgrade():
    op.execute("DROP FUNCTION public.tenant_update_member(text,uuid,text,boolean)")
    op.execute("DROP FUNCTION public.tenant_list_members(text,integer,integer)")
    op.execute("DROP FUNCTION public.tenant_admin_org(text)")
