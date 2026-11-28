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


# ── PHASE 2: legal and litigation module (migration 0028) ────────────────────
class LegalCase(Base):
    __tablename__ = "legal_cases"
    __table_args__ = (
        CheckConstraint("category IN ('rights_dispute','operator_dispute','claim','share_challenge','succession','contract','other')", name="legal_case_category_valid"),
        CheckConstraint("status IN ('open','in_review','amicable','judicial','resolved','closed','withdrawn')", name="legal_case_status_valid"),
        CheckConstraint("priority IN ('low','normal','high','urgent')", name="legal_case_priority_valid"),
        CheckConstraint("counterpart_type IN ('artist','operator','member','external')", name="legal_case_counterpart_valid"),
        CheckConstraint("closed_on IS NULL OR closed_on >= opened_on", name="legal_case_dates_valid"),
        UniqueConstraint("organization_id", "case_number", name="legal_case_number_unique"),
        UniqueConstraint("organization_id", "id", name="legal_case_org_id_unique"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    case_number: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, server_default="open")
    priority: Mapped[str] = mapped_column(String(20), nullable=False, server_default="normal")
    counterpart_type: Mapped[str] = mapped_column(String(20), nullable=False)
    counterpart_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    opened_on: Mapped[date] = mapped_column(Date, nullable=False)
    closed_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LegalCaseParty(Base):
    __tablename__ = "legal_case_parties"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
        CheckConstraint("role IN ('claimant','respondent','heir','representative','witness','other')", name="legal_party_role_valid"),
        CheckConstraint("account_id IS NOT NULL OR external_name IS NOT NULL", name="legal_party_identity_required"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    account_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    external_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    external_contact: Mapped[str | None] = mapped_column(String(200), nullable=True)
    added_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LegalCaseEvent(Base):
    __tablename__ = "legal_case_events"
    __table_args__ = (ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
                      CheckConstraint("kind IN ('claim','notice','amicable','judicial','decision','hearing','correspondence','other')", name="legal_event_kind_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_on: Mapped[date] = mapped_column(Date, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LegalDecision(Base):
    __tablename__ = "legal_decisions"
    __table_args__ = (ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
                      CheckConstraint("status IN ('pending','approved','rejected')", name="legal_decision_status_valid"),
                      CheckConstraint("proposed_action IN ('transition','mandate_revoke','succession_approve')", name="legal_decision_action_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    proposed_action: Mapped[str] = mapped_column(String(40), nullable=False)
    proposed_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    proposed_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class LegalDeadline(Base):
    __tablename__ = "legal_deadlines"
    __table_args__ = (ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
                      CheckConstraint("kind IN ('hearing','filing','response','notice','other')", name="legal_deadline_kind_valid"),
                      CheckConstraint("status IN ('pending','met','missed')", name="legal_deadline_status_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    notified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LegalMandate(Base):
    __tablename__ = "legal_mandates"
    __table_args__ = (ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="SET NULL"),
                      CheckConstraint("mandatee_account_id IS NOT NULL OR mandatee_external IS NOT NULL", name="legal_mandatee_required"),
                      CheckConstraint("valid_until IS NULL OR valid_until >= valid_from", name="legal_mandate_dates_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    mandatee_account_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    mandatee_external: Mapped[str | None] = mapped_column(String(200), nullable=True)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    territory: Mapped[str] = mapped_column(String(100), nullable=False)
    valid_from: Mapped[date] = mapped_column(Date, nullable=False)
    valid_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LegalSuccession(Base):
    __tablename__ = "legal_successions"
    __table_args__ = (CheckConstraint("share_basis_points BETWEEN 1 AND 10000", name="legal_succession_share_valid"),
                      CheckConstraint("status IN ('pending','approved','rejected','revoked')", name="legal_succession_status_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    deceased_account_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    heir_account_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    share_basis_points: Mapped[int] = mapped_column(Integer, nullable=False)
    declared_on: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LegalContract(Base):
    __tablename__ = "legal_contracts"
    __table_args__ = (CheckConstraint("kind IN ('reciprocity','representation','settlement','other')", name="legal_contract_kind_valid"),
                      CheckConstraint("status IN ('draft','active','terminated')", name="legal_contract_status_valid"),
                      CheckConstraint("valid_until IS NULL OR valid_until >= valid_from", name="legal_contract_dates_valid"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    counterpart: Mapped[str] = mapped_column(String(200), nullable=False)
    territory: Mapped[str] = mapped_column(String(100), nullable=False)
    valid_from: Mapped[date] = mapped_column(Date, nullable=False)
    valid_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LegalCaseDocument(Base):
    __tablename__ = "legal_case_documents"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["organization_id", "document_id"], ["documents.organization_id", "documents.id"], ondelete="CASCADE"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    document_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    linked_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

# ── PHASE 3: advanced copyright and related rights (migration 0029) ─────────
class Recording(Base):
    __tablename__ = "recordings"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "work_id"], ["works.organization_id", "works.id"], ondelete="CASCADE"),
        CheckConstraint("isrc ~ '^[A-Z]{2}[0-9A-Z]{3}[0-9]{2}[0-9]{5}$'", name="recording_isrc_format"),
        UniqueConstraint("organization_id", "isrc", name="recording_isrc_unique"),
        Index("ix_recordings_work", "organization_id", "work_id"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    work_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    isrc: Mapped[str] = mapped_column(String(12), nullable=False)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class RightsGrant(Base):
    __tablename__ = "rights_grants"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "work_id"], ["works.organization_id", "works.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["organization_id", "artist_id"], ["artists.organization_id", "artists.id"], ondelete="CASCADE"),
        CheckConstraint("role IN ('author','composer','publisher','producer_phonographic','producer_audiovisual','performer','heir','mandatary','other')", name="rights_grant_role_valid"),
        CheckConstraint("scope IN ('collective','direct')", name="rights_grant_scope_valid"),
        CheckConstraint("basis_points BETWEEN 1 AND 10000", name="rights_grant_basis_valid"),
        CheckConstraint("status IN ('active','terminated','disputed')", name="rights_grant_status_valid"),
        CheckConstraint("valid_until IS NULL OR valid_until >= valid_from", name="rights_grant_dates_valid"),
        Index("ix_rights_grants_work", "organization_id", "work_id"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    work_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    artist_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    territory: Mapped[str] = mapped_column(String(100), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False)
    basis_points: Mapped[int] = mapped_column(Integer, nullable=False)
    valid_from: Mapped[date] = mapped_column(Date, nullable=False)
    valid_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="active")
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class DistributionRule(Base):
    __tablename__ = "distribution_rules"
    __table_args__ = (
        CheckConstraint("version > 0", name="distribution_rule_version_positive"),
        CheckConstraint("rule_category IN ('mechanical','performance','broadcast','synchronization','digital','public_lending','other')", name="distribution_rule_category_valid"),
        CheckConstraint("status IN ('draft','active','superseded')", name="distribution_rule_status_valid"),
        UniqueConstraint("organization_id", "rule_category", "version", name="distribution_rule_version_unique"),
        Index("ix_distribution_rules_category", "organization_id", "rule_category", "version"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    rule_category: Mapped[str] = mapped_column(String(40), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    allocation: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="draft")
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class RightsUnidentified(Base):
    __tablename__ = "rights_unidentified"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "distribution_id"], ["royalty_distributions.organization_id", "royalty_distributions.id"], ondelete="SET NULL"),
        CheckConstraint("amount_minor > 0", name="rights_unidentified_amount_positive"),
        CheckConstraint("status IN ('pending','identified','claimed','expired')", name="rights_unidentified_status_valid"),
        UniqueConstraint("organization_id", "id", name="rights_unidentified_org_id_unique"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    distribution_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    reason: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class RightsClaim(Base):
    __tablename__ = "rights_claims"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "claimant_artist_id"], ["artists.organization_id", "artists.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["organization_id", "work_id"], ["works.organization_id", "works.id"], ondelete="SET NULL"),
        ForeignKeyConstraint(["organization_id", "unidentified_id"], ["rights_unidentified.organization_id", "rights_unidentified.id"], ondelete="SET NULL"),
        CheckConstraint("amount_minor > 0", name="rights_claim_amount_positive"),
        CheckConstraint("status IN ('pending','approved','rejected','paid')", name="rights_claim_status_valid"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    claimant_artist_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    work_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    unidentified_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    amount_minor: Mapped[int] = mapped_column(BigInteger, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    proposed_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

# ── PHASE 4: Finance et comptabilité SYSCOHADA (migration 0030) ──────────────
# Configurable plan comptable + generic->SYSCOHADA mapping + journaux +
# fiscal periods with multi-level close + contrepassations + withholding tax.
# Existing accounting_entries/lines (0021) keep their generic account_key; the
# chart_of_accounts + account_mappings layer lets the trial balance be produced
# in SYSCOHADA account_code order without rewriting the double-entry engine.


class ChartOfAccount(Base):
    __tablename__ = "chart_of_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "account_code", name="chart_account_code_unique"),
        UniqueConstraint("organization_id", "id", name="chart_account_org_id_unique"),
        CheckConstraint("syscohada_class IN ('1','2','3','4','5','6','7','8')", name="chart_class_valid"),
        CheckConstraint("account_type IN ('asset','liability','equity','revenue','expense')", name="chart_type_valid"),
        CheckConstraint("account_code ~ '^[0-9]{1,8}$'", name="chart_code_format"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    account_code: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    syscohada_class: Mapped[str] = mapped_column(String(1), nullable=False)
    account_type: Mapped[str] = mapped_column(String(20), nullable=False)
    parent_account_code: Mapped[str | None] = mapped_column(String(20), nullable=True)
    is_postable: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AccountMapping(Base):
    __tablename__ = "account_mappings"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "account_code"],
                             ["chart_of_accounts.organization_id", "chart_of_accounts.account_code"]),
        UniqueConstraint("organization_id", "generic_key", name="account_mapping_key_unique"),
        UniqueConstraint("organization_id", "id", name="account_mapping_org_id_unique"),
        CheckConstraint("generic_key IN ('receivable','royalties_unallocated','cash_unverified','management_commission','beneficiary_payable')",
                        name="account_mapping_key_valid"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    generic_key: Mapped[str] = mapped_column(String(40), nullable=False)
    account_code: Mapped[str] = mapped_column(String(20), nullable=False)


class Journal(Base):
    __tablename__ = "journals"
    __table_args__ = (
        UniqueConstraint("organization_id", "code", name="journal_code_unique"),
        UniqueConstraint("organization_id", "id", name="journal_org_id_unique"),
        CheckConstraint("kind IN ('sales','receipts','general','payouts')", name="journal_kind_valid"),
        CheckConstraint("code ~ '^[A-Z0-9]{1,10}$'", name="journal_code_format"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    code: Mapped[str] = mapped_column(String(10), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class FiscalPeriod(Base):
    __tablename__ = "fiscal_periods"
    __table_args__ = (
        UniqueConstraint("organization_id", "fiscal_year", "period_index", name="fiscal_period_unique"),
        UniqueConstraint("organization_id", "id", name="fiscal_period_org_id_unique"),
        CheckConstraint("status IN ('open','closed','locked')", name="fiscal_period_status_valid"),
        CheckConstraint("period_index BETWEEN 0 AND 12", name="fiscal_period_index_valid"),
        CheckConstraint("ends_on >= starts_on", name="fiscal_period_dates_valid"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    fiscal_year: Mapped[int] = mapped_column(Integer, nullable=False)
    period_index: Mapped[int] = mapped_column(Integer, nullable=False)
    starts_on: Mapped[date] = mapped_column(Date, nullable=False)
    ends_on: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="open")
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class FiscalPeriodReview(Base):
    __tablename__ = "fiscal_period_reviews"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "period_id"],
                             ["fiscal_periods.organization_id", "fiscal_periods.id"], ondelete="CASCADE"),
        UniqueConstraint("organization_id", "id", name="fiscal_review_org_id_unique"),
        UniqueConstraint("organization_id", "period_id", "reviewer_id", name="fiscal_review_no_duplicate"),
        CheckConstraint("decision IN ('approve','reject')", name="fiscal_review_decision_valid"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    period_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    reviewer_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("accounts.id"), nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    rationale: Mapped[str | None] = mapped_column(String(500), nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AccountingReversal(Base):
    __tablename__ = "accounting_reversals"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "original_entry_id"],
                             ["accounting_entries.organization_id", "accounting_entries.id"]),
        ForeignKeyConstraint(["organization_id", "reversal_entry_id"],
                             ["accounting_entries.organization_id", "accounting_entries.id"]),
        UniqueConstraint("organization_id", "id", name="reversal_org_id_unique"),
        UniqueConstraint("organization_id", "original_entry_id", name="reversal_entry_unique"),
        CheckConstraint("original_entry_id <> reversal_entry_id", name="reversal_not_self_valid"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    original_entry_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    reversal_entry_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    reversed_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("accounts.id"), nullable=False)
    reversed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class TaxRule(Base):
    __tablename__ = "tax_rules"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "account_code"],
                             ["chart_of_accounts.organization_id", "chart_of_accounts.account_code"]),
        UniqueConstraint("organization_id", "category", "country", name="tax_rule_unique"),
        UniqueConstraint("organization_id", "id", name="tax_rule_org_id_unique"),
        CheckConstraint("rate_bps BETWEEN 0 AND 10000", name="tax_rate_valid"),
        CheckConstraint("country ~ '^[A-Z]{2}$'", name="tax_country_format"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    country: Mapped[str] = mapped_column(String(2), nullable=False)
    rate_bps: Mapped[int] = mapped_column(Integer, nullable=False)
    account_code: Mapped[str | None] = mapped_column(String(20), nullable=True)

# ── PHASE 5: Banques et Mobile Money (migration 0031) ────────────────────────
# Provider-independent payment execution layer: connector config, beneficiary
# details, idempotent attempts, authenticated webhooks, reconciliation, and the
# DSIG-gated platform settings table. Existing payout_orders (0022) keeps its
# double-approval flow; new columns (provider/beneficiary_id/external_ref/
# executed_at) are nullable so existing rows are unaffected.


class PaymentProvider(Base):
    __tablename__ = "payment_providers"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", name="provider_kind_unique"),
        UniqueConstraint("organization_id", "id", name="provider_org_id_unique"),
        CheckConstraint("provider IN ('orange_money','mtn_momo','bank_transfer')", name="provider_kind_valid"),
        CheckConstraint("mode IN ('sandbox','live')", name="provider_mode_valid"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    mode: Mapped[str] = mapped_column(String(10), nullable=False, server_default="sandbox")
    api_base: Mapped[str | None] = mapped_column(String(200), nullable=True)
    credentials_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    webhook_secret: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PaymentBeneficiary(Base):
    __tablename__ = "payment_beneficiaries"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "artist_id"], ["artists.organization_id", "artists.id"]),
        UniqueConstraint("organization_id", "artist_id", "channel", name="beneficiary_artist_channel_unique"),
        UniqueConstraint("organization_id", "id", name="beneficiary_org_id_unique"),
        CheckConstraint("channel IN ('bank','orange_money','mtn_momo')", name="beneficiary_channel_valid"),
        CheckConstraint("msisdn IS NOT NULL OR iban IS NOT NULL OR account_number IS NOT NULL", name="beneficiary_details_present"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    artist_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    channel: Mapped[str] = mapped_column(String(30), nullable=False)
    msisdn: Mapped[str | None] = mapped_column(String(20), nullable=True)
    iban: Mapped[str | None] = mapped_column(String(34), nullable=True)
    account_number: Mapped[str | None] = mapped_column(String(40), nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
    verified_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PaymentAttempt(Base):
    __tablename__ = "payment_attempts"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "payout_id"], ["payout_orders.organization_id", "payout_orders.id"]),
        UniqueConstraint("organization_id", "idempotency_key", name="attempt_idempotency_unique"),
        UniqueConstraint("organization_id", "payout_id", name="attempt_payout_unique"),
        UniqueConstraint("organization_id", "id", name="attempt_org_id_unique"),
        CheckConstraint("status IN ('pending','succeeded','failed','refunded')", name="attempt_status_valid"),
        CheckConstraint("idempotency_key ~ '^[A-Za-z0-9_-]{8,64}$'", name="attempt_idempotency_format"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    payout_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    external_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    attempted_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PaymentWebhook(Base):
    __tablename__ = "payment_webhooks"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "event_ref", name="webhook_event_unique"),
        UniqueConstraint("organization_id", "id", name="webhook_org_id_unique"),
        CheckConstraint("provider IN ('orange_money','mtn_momo','bank_transfer')", name="webhook_provider_valid"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    event_ref: Mapped[str] = mapped_column(String(100), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    matched_attempt_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PaymentReconciliation(Base):
    __tablename__ = "payment_reconciliations"
    __table_args__ = (
        ForeignKeyConstraint(["organization_id", "attempt_id"], ["payment_attempts.organization_id", "payment_attempts.id"]),
        ForeignKeyConstraint(["organization_id", "webhook_id"], ["payment_webhooks.organization_id", "payment_webhooks.id"]),
        UniqueConstraint("organization_id", "attempt_id", name="reconciliation_attempt_unique"),
        UniqueConstraint("organization_id", "id", name="reconciliation_org_id_unique"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("organizations.id"), nullable=False)
    attempt_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    webhook_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    reconciled_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    reconciled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PlatformSetting(Base):
    __tablename__ = "platform_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
