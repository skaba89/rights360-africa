from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("organizations", sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_table("platform_audit_events",
        sa.Column("id",sa.BigInteger(),sa.Identity(),primary_key=True),
        sa.Column("actor_id",sa.Uuid(),nullable=False),
        sa.Column("organization_id",sa.Uuid(),nullable=False),
        sa.Column("action",sa.String(80),nullable=False),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    # Narrow SECURITY DEFINER functions; no cross-tenant table grants.
    op.execute("""
    CREATE FUNCTION public.platform_authorized(p_token text) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
      SELECT EXISTS (
        SELECT 1 FROM public.auth_sessions s
        JOIN public.accounts a ON a.id=s.account_id
        JOIN public.memberships m ON m.account_id=s.account_id AND m.organization_id=s.organization_id
        JOIN public.platform_admins p ON p.account_id=s.account_id AND p.organization_id=s.organization_id
        JOIN public.account_mfa f ON f.account_id=s.account_id
        JOIN public.organizations o ON o.id=s.organization_id
        WHERE s.token_hash=p_token AND s.expires_at>now() AND a.active AND m.active
          AND m.role='admin' AND p.active AND f.enabled AND o.active)
    $$;
    REVOKE ALL ON FUNCTION public.platform_authorized(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_authorized(text) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.organization_active(p_id uuid) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
      SELECT EXISTS (SELECT 1 FROM public.organizations WHERE id=p_id AND active)
    $$;
    REVOKE ALL ON FUNCTION public.organization_active(uuid) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.organization_active(uuid) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.platform_list_organizations(p_token text,p_limit integer,p_offset integer)
    RETURNS TABLE(id uuid,slug varchar,name varchar,active boolean)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
      IF NOT public.platform_authorized(p_token) THEN RAISE insufficient_privilege; END IF;
      RETURN QUERY SELECT o.id,o.slug,o.name,o.active FROM public.organizations o
      ORDER BY o.slug LIMIT LEAST(GREATEST(p_limit,1),100) OFFSET GREATEST(p_offset,0);
    END $$;
    REVOKE ALL ON FUNCTION public.platform_list_organizations(text,integer,integer) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_list_organizations(text,integer,integer) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.platform_create_organization(p_token text,p_id uuid,p_slug text,p_name text)
    RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
      IF NOT public.platform_authorized(p_token) THEN RAISE insufficient_privilege; END IF;
      INSERT INTO public.organizations(id,slug,name,active) VALUES(p_id,p_slug,p_name,true);
      INSERT INTO public.platform_audit_events(actor_id,organization_id,action)
      SELECT account_id,p_id,'organization.created' FROM public.auth_sessions WHERE token_hash=p_token;
      RETURN p_id;
    END $$;
    REVOKE ALL ON FUNCTION public.platform_create_organization(text,uuid,text,text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_create_organization(text,uuid,text,text) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.platform_set_organization_active(p_token text,p_id uuid,p_active boolean)
    RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
      IF NOT public.platform_authorized(p_token) THEN RAISE insufficient_privilege; END IF;
      IF EXISTS (SELECT 1 FROM public.platform_admins WHERE organization_id=p_id AND active) THEN
        RAISE check_violation USING MESSAGE='Protected platform organization';
      END IF;
      UPDATE public.organizations SET active=p_active WHERE id=p_id;
      IF NOT FOUND THEN RETURN false; END IF;
      INSERT INTO public.platform_audit_events(actor_id,organization_id,action)
      SELECT account_id,p_id,CASE WHEN p_active THEN 'organization.activated' ELSE 'organization.suspended' END
      FROM public.auth_sessions WHERE token_hash=p_token;
      IF NOT p_active THEN DELETE FROM public.auth_sessions WHERE organization_id=p_id; END IF;
      RETURN true;
    END $$;
    REVOKE ALL ON FUNCTION public.platform_set_organization_active(text,uuid,boolean) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_set_organization_active(text,uuid,boolean) TO rights360_runtime;
    """)

def downgrade():
    for signature in ("platform_set_organization_active(text,uuid,boolean)","platform_create_organization(text,uuid,text,text)","platform_list_organizations(text,integer,integer)","organization_active(uuid)","platform_authorized(text)"):
        op.execute(f"DROP FUNCTION public.{signature}")
    op.drop_table("platform_audit_events")
    op.drop_column("organizations","active")
