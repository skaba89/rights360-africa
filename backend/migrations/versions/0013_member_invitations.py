from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("member_invitations",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("email",sa.String(254),nullable=False),
        sa.Column("role",sa.String(40),nullable=False),
        sa.Column("token_hash",sa.String(64),unique=True,nullable=False),
        sa.Column("expires_at",sa.DateTime(timezone=True),nullable=False),
        sa.Column("consumed_at",sa.DateTime(timezone=True)),
        sa.Column("revoked_at",sa.DateTime(timezone=True)),
        sa.CheckConstraint("role IN ('manager','auditor','artist')",name="member_invitation_role_valid"))
    op.create_index("ix_member_invitation_org_email","member_invitations",["organization_id","email"])
    op.execute("""
    CREATE FUNCTION public.tenant_invite_member(p_session text,p_id uuid,p_email text,p_role text,p_hash text)
    RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE org uuid; actor uuid;
    BEGIN
      org:=public.tenant_admin_org(p_session);
      IF org IS NULL OR p_role IS NULL OR p_role NOT IN ('manager','auditor','artist') THEN RAISE insufficient_privilege; END IF;
      PERFORM 1 FROM public.organizations WHERE id=org AND active FOR UPDATE;
      IF NOT FOUND OR public.tenant_admin_org(p_session) IS DISTINCT FROM org THEN RAISE insufficient_privilege; END IF;
      IF EXISTS(SELECT 1 FROM public.accounts WHERE email=p_email) THEN RAISE unique_violation; END IF;
      SELECT account_id INTO actor FROM public.auth_sessions WHERE token_hash=p_session;
      UPDATE public.member_invitations SET revoked_at=now()
      WHERE organization_id=org AND email=p_email AND consumed_at IS NULL AND revoked_at IS NULL;
      INSERT INTO public.member_invitations(id,organization_id,email,role,token_hash,expires_at)
      VALUES(p_id,org,p_email,p_role,p_hash,now()+interval '24 hours');
      INSERT INTO public.audit_events(organization_id,actor_id,action,resource_key,details)
      VALUES(org,actor,'member.invited',p_id::text,jsonb_build_object('role',p_role));
      RETURN p_id;
    END $$;
    REVOKE ALL ON FUNCTION public.tenant_invite_member(text,uuid,text,text,text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.tenant_invite_member(text,uuid,text,text,text) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.tenant_revoke_invitation(p_session text,p_id uuid)
    RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE org uuid; actor uuid;
    BEGIN
      org:=public.tenant_admin_org(p_session);
      IF org IS NULL THEN RAISE insufficient_privilege; END IF;
      PERFORM 1 FROM public.organizations WHERE id=org AND active FOR UPDATE;
      IF NOT FOUND OR public.tenant_admin_org(p_session) IS DISTINCT FROM org THEN RAISE insufficient_privilege; END IF;
      SELECT account_id INTO actor FROM public.auth_sessions WHERE token_hash=p_session;
      UPDATE public.member_invitations SET revoked_at=now()
      WHERE id=p_id AND organization_id=org AND consumed_at IS NULL AND revoked_at IS NULL;
      IF NOT FOUND THEN RETURN false; END IF;
      INSERT INTO public.audit_events(organization_id,actor_id,action,resource_key,details)
      VALUES(org,actor,'member.invitation_revoked',p_id::text,'{}'::jsonb);
      RETURN true;
    END $$;
    REVOKE ALL ON FUNCTION public.tenant_revoke_invitation(text,uuid) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.tenant_revoke_invitation(text,uuid) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.accept_member_invitation(p_hash text,p_account uuid,p_password_hash text)
    RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE invitation public.member_invitations%ROWTYPE; org uuid;
    BEGIN
      SELECT organization_id INTO org FROM public.member_invitations WHERE token_hash=p_hash;
      IF NOT FOUND THEN RETURN NULL; END IF;
      PERFORM 1 FROM public.organizations WHERE id=org AND active FOR UPDATE;
      IF NOT FOUND THEN RETURN NULL; END IF;
      SELECT * INTO invitation FROM public.member_invitations
      WHERE token_hash=p_hash AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE;
      IF NOT FOUND THEN RETURN NULL; END IF;
      IF EXISTS(SELECT 1 FROM public.accounts WHERE email=invitation.email) THEN RETURN NULL; END IF;
      INSERT INTO public.accounts(id,email,password_hash) VALUES(p_account,invitation.email,p_password_hash);
      INSERT INTO public.memberships(account_id,organization_id,role) VALUES(p_account,org,invitation.role);
      UPDATE public.member_invitations SET consumed_at=now() WHERE id=invitation.id;
      INSERT INTO public.audit_events(organization_id,actor_id,action,resource_key,details)
      VALUES(org,p_account,'member.invitation_accepted',invitation.id::text,jsonb_build_object('role',invitation.role));
      RETURN org;
    END $$;
    REVOKE ALL ON FUNCTION public.accept_member_invitation(text,uuid,text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.accept_member_invitation(text,uuid,text) TO rights360_runtime;
    """)

def downgrade():
    op.execute("DROP FUNCTION public.accept_member_invitation(text,uuid,text)")
    op.execute("DROP FUNCTION public.tenant_revoke_invitation(text,uuid)")
    op.execute("DROP FUNCTION public.tenant_invite_member(text,uuid,text,text,text)")
    op.drop_table("member_invitations")
