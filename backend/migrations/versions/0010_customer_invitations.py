from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("customer_invitations",
        sa.Column("id",sa.Uuid(),primary_key=True),
        sa.Column("organization_id",sa.Uuid(),sa.ForeignKey("organizations.id"),nullable=False),
        sa.Column("email",sa.String(254),nullable=False),
        sa.Column("token_hash",sa.String(64),unique=True,nullable=False),
        sa.Column("expires_at",sa.DateTime(timezone=True),nullable=False),
        sa.Column("consumed_at",sa.DateTime(timezone=True)),
        sa.Column("revoked_at",sa.DateTime(timezone=True)))
    op.execute("""
    CREATE FUNCTION public.platform_invite_admin(p_session text,p_id uuid,p_org uuid,p_email text,p_hash text)
    RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    BEGIN
      IF NOT public.platform_authorized(p_session) THEN RAISE insufficient_privilege; END IF;
      PERFORM 1 FROM public.organizations WHERE id=p_org AND active FOR UPDATE;
      IF NOT FOUND THEN RETURN NULL; END IF;
      IF EXISTS (SELECT 1 FROM public.platform_admins WHERE organization_id=p_org)
        OR EXISTS (SELECT 1 FROM public.memberships WHERE organization_id=p_org AND role='admin')
        OR EXISTS (SELECT 1 FROM public.accounts WHERE email=p_email) THEN
        RAISE unique_violation USING MESSAGE='Invitation conflicts with existing account or administrator';
      END IF;
      UPDATE public.customer_invitations SET revoked_at=now()
      WHERE organization_id=p_org AND consumed_at IS NULL AND revoked_at IS NULL;
      INSERT INTO public.customer_invitations(id,organization_id,email,token_hash,expires_at)
      VALUES(p_id,p_org,p_email,p_hash,now()+interval '24 hours');
      INSERT INTO public.platform_audit_events(actor_id,organization_id,action)
      SELECT account_id,p_org,'administrator.invited' FROM public.auth_sessions WHERE token_hash=p_session;
      RETURN p_id;
    END $$;
    REVOKE ALL ON FUNCTION public.platform_invite_admin(text,uuid,uuid,text,text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_invite_admin(text,uuid,uuid,text,text) TO rights360_runtime;
    """)
    op.execute("""
    CREATE FUNCTION public.accept_customer_invitation(p_hash text,p_account uuid,p_password_hash text)
    RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE invitation public.customer_invitations%ROWTYPE; target_org uuid;
    BEGIN
      SELECT organization_id INTO target_org FROM public.customer_invitations WHERE token_hash=p_hash;
      IF NOT FOUND THEN RETURN NULL; END IF;
      PERFORM 1 FROM public.organizations WHERE id=target_org AND active FOR UPDATE;
      IF NOT FOUND THEN RETURN NULL; END IF;
      SELECT * INTO invitation FROM public.customer_invitations
      WHERE token_hash=p_hash AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE;
      IF NOT FOUND THEN RETURN NULL; END IF;
      IF EXISTS (SELECT 1 FROM public.memberships WHERE organization_id=target_org AND role='admin')
        OR EXISTS (SELECT 1 FROM public.accounts WHERE email=invitation.email) THEN RETURN NULL; END IF;
      INSERT INTO public.accounts(id,email,password_hash) VALUES(p_account,invitation.email,p_password_hash);
      INSERT INTO public.memberships(account_id,organization_id,role) VALUES(p_account,target_org,'admin');
      UPDATE public.customer_invitations SET consumed_at=now() WHERE id=invitation.id;
      INSERT INTO public.platform_audit_events(actor_id,organization_id,action)
      VALUES(p_account,target_org,'administrator.accepted');
      RETURN target_org;
    END $$;
    REVOKE ALL ON FUNCTION public.accept_customer_invitation(text,uuid,text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.accept_customer_invitation(text,uuid,text) TO rights360_runtime;
    """)

def downgrade():
    op.execute("DROP FUNCTION public.accept_customer_invitation(text,uuid,text)")
    op.execute("DROP FUNCTION public.platform_invite_admin(text,uuid,uuid,text,text)")
    op.drop_table("customer_invitations")
