import uuid
from datetime import datetime, date
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import JSON, BigInteger, Integer, Identity, func, Boolean, CheckConstraint, Date, DateTime, ForeignKey, ForeignKeyConstraint, String, Text, Uuid, UniqueConstraint, Index, false, true
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
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    peer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)

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

class Operator(Base):
    __tablename__ = "operators"
    __table_args__ = (UniqueConstraint("organization_id","id",name="operator_org_id_unique"),UniqueConstraint("organization_id","reference",name="operator_reference_unique"),CheckConstraint("category IN ('radio','television','hotel','restaurant','event','digital','other')",name="operator_category_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,ForeignKey("organizations.id"),nullable=False)
    reference: Mapped[str] = mapped_column(String(50),nullable=False)
    name: Mapped[str] = mapped_column(String(200),nullable=False)
    category: Mapped[str] = mapped_column(String(30),nullable=False)
    email: Mapped[str | None] = mapped_column(String(254))
    phone: Mapped[str | None] = mapped_column(String(40))

class ExploitationLicense(Base):
    __tablename__ = "exploitation_licenses"
    __table_args__ = (ForeignKeyConstraint(["organization_id","operator_id"],["operators.organization_id","operators.id"]),ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),UniqueConstraint("organization_id","reference",name="exploitation_reference_unique"),UniqueConstraint("organization_id","id",name="license_org_id_unique"),CheckConstraint("ends_on>=starts_on",name="exploitation_dates_valid"),CheckConstraint("status IN ('draft','active','revoked')",name="exploitation_status_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    operator_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    work_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    reference: Mapped[str] = mapped_column(String(50),nullable=False)
    territory: Mapped[str] = mapped_column(String(100),nullable=False)
    usage_type: Mapped[str] = mapped_column(String(100),nullable=False)
    starts_on: Mapped[date] = mapped_column(Date,nullable=False)
    ends_on: Mapped[date] = mapped_column(Date,nullable=False)
    status: Mapped[str] = mapped_column(String(20),nullable=False,server_default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class Tariff(Base):
    __tablename__ = "tariffs"
    __table_args__ = (
        UniqueConstraint("organization_id","reference","version",name="tariff_version_unique"),
        UniqueConstraint("organization_id","id",name="tariff_org_id_unique"),
        CheckConstraint("version>0 AND starts_on<=ends_on AND rate>0 AND rate<=1000000000000",name="tariff_values_valid"),
        CheckConstraint("category IN ('radio','television','hotel','restaurant','event','digital','other')",name="tariff_category_valid"),
        CheckConstraint("method IN ('flat','revenue','capacity','frequency') AND (method<>'revenue' OR rate<=10000)",name="tariff_method_valid"),
        CheckConstraint("currency IN ('GNF','XOF','EUR','USD')",name="tariff_currency_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,ForeignKey("organizations.id"),nullable=False)
    reference: Mapped[str] = mapped_column(String(50),nullable=False)
    version: Mapped[int] = mapped_column(Integer,nullable=False)
    category: Mapped[str] = mapped_column(String(30),nullable=False)
    usage_type: Mapped[str] = mapped_column(String(100),nullable=False)
    method: Mapped[str] = mapped_column(String(20),nullable=False)
    currency: Mapped[str] = mapped_column(String(3),nullable=False)
    rate: Mapped[int] = mapped_column(BigInteger,nullable=False)
    starts_on: Mapped[date] = mapped_column(Date,nullable=False)
    ends_on: Mapped[date] = mapped_column(Date,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class RoyaltyInvoice(Base):
    __tablename__ = "royalty_invoices"
    __table_args__ = (ForeignKeyConstraint(["organization_id","license_id"],["exploitation_licenses.organization_id","exploitation_licenses.id"]),ForeignKeyConstraint(["organization_id","tariff_id"],["tariffs.organization_id","tariffs.id"]),UniqueConstraint("organization_id","id",name="invoice_org_id_unique"),UniqueConstraint("organization_id","reference",name="invoice_reference_unique"),UniqueConstraint("organization_id","license_id","usage_date",name="invoice_usage_unique"),CheckConstraint("amount_minor>0 AND due_on>=usage_date",name="invoice_values_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    reference: Mapped[str] = mapped_column(String(50),nullable=False)
    license_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    tariff_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    usage_date: Mapped[date] = mapped_column(Date,nullable=False)
    due_on: Mapped[date] = mapped_column(Date,nullable=False)
    quantity: Mapped[int | None] = mapped_column(BigInteger)
    revenue_minor: Mapped[int | None] = mapped_column(BigInteger)
    amount_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)
    currency: Mapped[str] = mapped_column(String(3),nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class RoyaltyReceipt(Base):
    __tablename__ = "royalty_receipts"
    __table_args__ = (ForeignKeyConstraint(["organization_id","invoice_id"],["royalty_invoices.organization_id","royalty_invoices.id"]),UniqueConstraint("organization_id","reference",name="receipt_reference_unique"),UniqueConstraint("organization_id","id",name="receipt_org_id_unique"),CheckConstraint("amount_minor>0",name="receipt_amount_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    invoice_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    reference: Mapped[str] = mapped_column(String(50),nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)
    received_on: Mapped[date] = mapped_column(Date,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class RoyaltyDistribution(Base):
    __tablename__ = "royalty_distributions"
    __table_args__ = (ForeignKeyConstraint(["organization_id","receipt_id"],["royalty_receipts.organization_id","royalty_receipts.id"]),ForeignKeyConstraint(["organization_id","declaration_id"],["work_rights_declarations.organization_id","work_rights_declarations.id"]),UniqueConstraint("organization_id","id",name="distribution_org_id_unique"),UniqueConstraint("organization_id","receipt_id",name="distribution_receipt_unique"),CheckConstraint("gross_minor>0 AND commission_bps BETWEEN 0 AND 10000 AND commission_minor>=0 AND net_minor>=0 AND gross_minor=commission_minor+net_minor",name="distribution_amounts_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    receipt_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    declaration_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    currency: Mapped[str] = mapped_column(String(3),nullable=False)
    gross_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)
    commission_bps: Mapped[int] = mapped_column(Integer,nullable=False)
    commission_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)
    net_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class RoyaltyDistributionLine(Base):
    __tablename__ = "royalty_distribution_lines"
    __table_args__ = (ForeignKeyConstraint(["organization_id","distribution_id"],["royalty_distributions.organization_id","royalty_distributions.id"]),ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),CheckConstraint("amount_minor>=0 AND basis_points BETWEEN 1 AND 10000",name="distribution_line_valid"))
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    distribution_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    artist_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    role: Mapped[str] = mapped_column(String(30),primary_key=True)
    basis_points: Mapped[int] = mapped_column(Integer,nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)

class AccountingEntry(Base):
    __tablename__ = "accounting_entries"
    __table_args__ = (UniqueConstraint("organization_id","id",name="entry_org_id_unique"),UniqueConstraint("organization_id","source_type","source_id",name="entry_source_unique"),CheckConstraint("source_type IN ('invoice','receipt','distribution')",name="entry_source_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,ForeignKey("organizations.id"),nullable=False)
    source_type: Mapped[str] = mapped_column(String(20),nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    currency: Mapped[str] = mapped_column(String(3),nullable=False)
    posted_by: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    posted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class AccountingLine(Base):
    __tablename__ = "accounting_lines"
    __table_args__ = (ForeignKeyConstraint(["organization_id","entry_id"],["accounting_entries.organization_id","accounting_entries.id"]),ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),CheckConstraint("(debit_minor>0 AND credit_minor=0) OR (credit_minor>0 AND debit_minor=0)",name="accounting_side_valid"))
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    entry_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    line_no: Mapped[int] = mapped_column(Integer,primary_key=True)
    account_key: Mapped[str] = mapped_column(String(40),nullable=False)
    artist_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    debit_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)
    credit_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)

class PayoutOrder(Base):
    __tablename__ = "payout_orders"
    __table_args__ = (ForeignKeyConstraint(["organization_id","distribution_id"],["royalty_distributions.organization_id","royalty_distributions.id"]),ForeignKeyConstraint(["organization_id","artist_id"],["artists.organization_id","artists.id"]),UniqueConstraint("organization_id","id",name="payout_org_id_unique"),UniqueConstraint("organization_id","distribution_id","artist_id",name="payout_once"),CheckConstraint("amount_minor>0 AND channel IN ('bank','orange_money','mtn_momo','other')",name="payout_values_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    distribution_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    artist_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    channel: Mapped[str] = mapped_column(String(30),nullable=False)
    amount_minor: Mapped[int] = mapped_column(BigInteger,nullable=False)
    currency: Mapped[str] = mapped_column(String(3),nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class PayoutReview(Base):
    __tablename__ = "payout_reviews"
    __table_args__ = (ForeignKeyConstraint(["organization_id","order_id"],["payout_orders.organization_id","payout_orders.id"]),CheckConstraint("decision IN ('approve','reject')",name="payout_decision_valid"))
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    order_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    reviewer_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    decision: Mapped[str] = mapped_column(String(20),nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class FieldVisit(Base):
    __tablename__ = "field_visits"
    __table_args__ = (ForeignKeyConstraint(["organization_id","operator_id"],["operators.organization_id","operators.id"]),CheckConstraint("finding IN ('observed','suspected_noncompliance','followup')",name="visit_finding_valid"),CheckConstraint("(latitude_e6 IS NULL AND longitude_e6 IS NULL) OR (latitude_e6 IS NOT NULL AND longitude_e6 IS NOT NULL AND latitude_e6 BETWEEN -90000000 AND 90000000 AND longitude_e6 BETWEEN -180000000 AND 180000000)",name="visit_coordinates_valid"),Index("ix_field_visits_org_date","organization_id","visited_at"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    operator_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    visited_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False)
    latitude_e6: Mapped[int | None] = mapped_column(Integer)
    longitude_e6: Mapped[int | None] = mapped_column(Integer)
    finding: Mapped[str] = mapped_column(String(30),nullable=False)
    notes: Mapped[str] = mapped_column(String(2000),nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64),nullable=False)
    license_snapshot: Mapped[dict] = mapped_column(JSON,nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class MediaObservation(Base):
    __tablename__ = "media_observations"
    __table_args__ = (ForeignKeyConstraint(["organization_id","operator_id"],["operators.organization_id","operators.id"]),UniqueConstraint("organization_id","id",name="media_org_id_unique"),UniqueConstraint("organization_id","operator_id","external_reference",name="media_reference_unique"),CheckConstraint("duration_seconds BETWEEN 1 AND 86400",name="media_duration_valid"),Index("ix_media_org_aired","organization_id","aired_at"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    operator_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    external_reference: Mapped[str] = mapped_column(String(100),nullable=False)
    aired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer,nullable=False)
    reported_title: Mapped[str] = mapped_column(String(250),nullable=False)
    reported_artist: Mapped[str] = mapped_column(String(200),nullable=False)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class MediaReview(Base):
    __tablename__ = "media_reviews"
    __table_args__ = (ForeignKeyConstraint(["organization_id","observation_id"],["media_observations.organization_id","media_observations.id"]),ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),CheckConstraint("(decision='matched' AND work_id IS NOT NULL) OR (decision='unmatched' AND work_id IS NULL)",name="media_review_valid"))
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    observation_id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    work_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    decision: Mapped[str] = mapped_column(String(20),nullable=False)
    reviewed_by: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())

class AcousticReference(Base):
    __tablename__ = "acoustic_references"
    __table_args__ = (ForeignKeyConstraint(["organization_id","work_id"],["works.organization_id","works.id"]),UniqueConstraint("organization_id","audio_sha256",name="acoustic_digest_unique"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid,primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    work_id: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    audio_sha256: Mapped[str] = mapped_column(String(64),nullable=False)
    signature: Mapped[list] = mapped_column(JSON,nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid,nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),nullable=False,server_default=func.now())
