import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import BigInteger, Integer, Identity, func, Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, String, Text, Uuid, UniqueConstraint, Index, false, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())

class TenantModule(Base):
    __tablename__ = "tenant_modules"
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), primary_key=True)
    module_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())

class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())

class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (CheckConstraint("role IN ('admin','manager','auditor','artist')", name="membership_role_valid"),)
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("accounts.id"), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())

class AuthSession(Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (ForeignKeyConstraint(["account_id", "organization_id"], ["memberships.account_id", "memberships.organization_id"], ondelete="CASCADE"),)
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_key: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LoginBucket(Base):
    __tablename__ = "login_buckets"
    bucket: Mapped[str] = mapped_column(String(80), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)

class AccountMFA(Base):
    __tablename__ = "account_mfa"
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True)
    secret_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    last_step: Mapped[int] = mapped_column(BigInteger, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())

class MFARecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)

class PlatformAdmin(Base):
    __tablename__ = "platform_admins"
    __table_args__ = (ForeignKeyConstraint(["account_id","organization_id"], ["memberships.account_id","memberships.organization_id"], ondelete="CASCADE"),)
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())

class PlatformAuditEvent(Base):
    __tablename__ = "platform_audit_events"
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    actor_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class CustomerInvitation(Base):
    __tablename__ = "customer_invitations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class ModuleEntitlement(Base):
    __tablename__ = "module_entitlements"
    __table_args__ = (CheckConstraint("module_key IN ('artists','works','licenses','royalties','finance','field_control','media','analytics','legal','documents')",name="entitlement_module_valid"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"),primary_key=True)
    module_key: Mapped[str] = mapped_column(String(80),primary_key=True)
    granted: Mapped[bool] = mapped_column(Boolean,nullable=False,server_default=false())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class MemberInvitation(Base):
    __tablename__ = "member_invitations"
    __table_args__ = (CheckConstraint("role IN ('manager','auditor','artist')",name="member_invitation_role_valid"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,ForeignKey("organizations.id"),nullable=False)
    email: Mapped[str] = mapped_column(String(254),nullable=False)
    role: Mapped[str] = mapped_column(String(40),nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64),unique=True,nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class Artist(Base):
    __tablename__ = "artists"
    __table_args__ = (UniqueConstraint("organization_id","member_number",name="artist_member_number_unique"),UniqueConstraint("organization_id","id",name="artist_org_id_unique"),CheckConstraint("status IN ('pending','active','suspended','archived')",name="artist_status_valid"),Index("ix_artists_org_name","organization_id","legal_name","id"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,ForeignKey("organizations.id"),nullable=False)
    member_number: Mapped[str] = mapped_column(String(50),nullable=False)
    legal_name: Mapped[str] = mapped_column(String(200),nullable=False)
    stage_name: Mapped[str | None] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(254))
    phone: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20),nullable=False,server_default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class Work(Base):
    __tablename__ = "works"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id","primary_artist_id"],["artists.organization_id","artists.id"],name="work_artist_same_org"),
        UniqueConstraint("organization_id","reference",name="work_reference_unique"),
        UniqueConstraint("organization_id","id",name="work_org_id_unique"),
        UniqueConstraint("organization_id","iswc",name="work_iswc_unique"),
        CheckConstraint("category IN ('music','literary','audiovisual','visual','other')",name="work_category_valid"),
        CheckConstraint("status IN ('draft','registered','archived')",name="work_status_valid"),
        CheckConstraint("iswc IS NULL OR (category='music' AND iswc ~ '^T[0-9]{10}$')",name="work_iswc_format"),
        Index("ix_works_org_title","organization_id","title","id"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,ForeignKey("organizations.id"),nullable=False)
    reference: Mapped[str] = mapped_column(String(50),nullable=False)
    title: Mapped[str] = mapped_column(String(250),nullable=False)
    category: Mapped[str] = mapped_column(String(30),nullable=False)
    primary_artist_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    iswc: Mapped[str | None] = mapped_column(String(11))
    status: Mapped[str] = mapped_column(String(20),nullable=False,server_default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class WorkRightsDeclaration(Base):
    __tablename__ = "work_rights_declarations"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),
        UniqueConstraint("organization_id","id",name="rights_declaration_org_id_unique"),
        UniqueConstraint("organization_id","work_id","version",name="rights_declaration_version_unique"),
        CheckConstraint("version>0 AND status IN ('draft','complete')",name="rights_declaration_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    work_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    version: Mapped[int] = mapped_column(Integer,nullable=False)
    status: Mapped[str] = mapped_column(String(20),nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class WorkRightsShare(Base):
    __tablename__ = "work_rights_shares"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id","declaration_id"],["work_rights_declarations.organization_id","work_rights_declarations.id"]),
        ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),
        CheckConstraint("basis_points BETWEEN 1 AND 10000",name="rights_share_range"),
        CheckConstraint("role IN ('author','composer','publisher','beneficiary','other')",name="rights_share_role_valid"))
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    declaration_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    artist_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    role: Mapped[str] = mapped_column(String(30),primary_key=True)
    basis_points: Mapped[int] = mapped_column(Integer,nullable=False)
