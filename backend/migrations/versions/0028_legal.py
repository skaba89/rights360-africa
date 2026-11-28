"""PHASE 2 — Legal and litigation module.

Activable per institution (require_enabled_module(conn, 'legal')). Provides
dossiers, parties, immutable event history, sensitive-decision double review,
deadline calendar, representation mandates, successions/heirs, reciprocity
contracts, and linkage to the existing GED (documents) without altering it.

RLS: every table is tenant-scoped via app.tenant_id (same pattern as 0026).
Grants: SELECT,INSERT,UPDATE,DELETE on legal tables to rights360_runtime
(legal lifecycle needs edits and removals; RLS scopes them to the tenant).

Compliance note: this module is an operational record-keeping tool. It MUST NOT
be presented as officially conformant to any jurisdiction without validation by
a locally qualified legal professional. No automated legal decision is taken.
"""
import sqlalchemy as sa
from alembic import op

revision = "0028"
down_revision = "0027"  # PHASE 2 chains after the PHASE 1 session diagnostics migration
branch_labels = None
depends_on = None

LEGAL_TABLES = [
    "legal_cases", "legal_case_parties", "legal_case_events", "legal_decisions",
    "legal_deadlines", "legal_mandates", "legal_successions", "legal_contracts",
    "legal_case_documents",
]


def _rls(table):
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
    USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute(f"GRANT SELECT,INSERT,UPDATE,DELETE ON {table} TO rights360_runtime")


def upgrade():
    # 1. Dossiers juridiques
    op.create_table("legal_cases",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("case_number", sa.String(40), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("status", sa.String(40), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(20), nullable=False, server_default="normal"),
        sa.Column("counterpart_type", sa.String(20), nullable=False),
        sa.Column("counterpart_ref", sa.String(200), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("opened_on", sa.Date(), nullable=False),
        sa.Column("closed_on", sa.Date(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("category IN ('rights_dispute','operator_dispute','claim','share_challenge','succession','contract','other')", name="legal_case_category_valid"),
        sa.CheckConstraint("status IN ('open','in_review','amicable','judicial','resolved','closed','withdrawn')", name="legal_case_status_valid"),
        sa.CheckConstraint("priority IN ('low','normal','high','urgent')", name="legal_case_priority_valid"),
        sa.CheckConstraint("counterpart_type IN ('artist','operator','member','external')", name="legal_case_counterpart_valid"),
        sa.CheckConstraint("closed_on IS NULL OR closed_on >= opened_on", name="legal_case_dates_valid"),
        sa.UniqueConstraint("organization_id", "case_number", name="legal_case_number_unique"),
        sa.UniqueConstraint("organization_id", "id", name="legal_case_org_id_unique"))
    op.create_index("ix_legal_cases_status", "legal_cases", ["organization_id", "status"])

    # 2. Parties au dossier (ayants droit, exploitants, héritiers, mandataires, externes)
    op.create_table("legal_case_parties",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=True),
        sa.Column("external_name", sa.String(200), nullable=True),
        sa.Column("external_contact", sa.String(200), nullable=True),
        sa.Column("added_by", sa.Uuid(), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
        sa.CheckConstraint("role IN ('claimant','respondent','heir','representative','witness','other')", name="legal_party_role_valid"),
        sa.CheckConstraint("account_id IS NOT NULL OR external_name IS NOT NULL", name="legal_party_identity_required"))

    # 3. Historique immuable des décisions / procédures (amiables, judiciaires, mises en demeure, réclamations)
    op.create_table("legal_case_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("occurred_on", sa.Date(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
        sa.CheckConstraint("kind IN ('claim','notice','amicable','judicial','decision','hearing','correspondence','other')", name="legal_event_kind_valid"))

    # 4. Décisions sensibles (transitions de statut) — validation humaine par double revue
    op.create_table("legal_decisions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("proposed_action", sa.String(40), nullable=False),
        sa.Column("proposed_status", sa.String(40), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("proposed_by", sa.Uuid(), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("reviewed_by", sa.Uuid(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
        sa.CheckConstraint("status IN ('pending','approved','rejected')", name="legal_decision_status_valid"),
        sa.CheckConstraint("proposed_action IN ('transition','mandate_revoke','succession_approve')", name="legal_decision_action_valid"))

    # 5. Calendrier des échéances + notifications
    op.create_table("legal_deadlines",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("notified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
        sa.CheckConstraint("kind IN ('hearing','filing','response','notice','other')", name="legal_deadline_kind_valid"),
        sa.CheckConstraint("status IN ('pending','met','missed')", name="legal_deadline_status_valid"))
    op.create_index("ix_legal_deadlines_due", "legal_deadlines", ["organization_id", "due_at"])

    # 6. Mandats de représentation
    op.create_table("legal_mandates",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column("mandatee_account_id", sa.Uuid(), nullable=True),
        sa.Column("mandatee_external", sa.String(200), nullable=True),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("territory", sa.String(100), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=False),
        sa.Column("valid_until", sa.Date(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="SET NULL"),
        sa.CheckConstraint("mandatee_account_id IS NOT NULL OR mandatee_external IS NOT NULL", name="legal_mandatee_required"),
        sa.CheckConstraint("valid_until IS NULL OR valid_until >= valid_from", name="legal_mandate_dates_valid"))

    # 7. Successions et héritiers
    op.create_table("legal_successions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("deceased_account_id", sa.Uuid(), nullable=False),
        sa.Column("heir_account_id", sa.Uuid(), nullable=False),
        sa.Column("share_basis_points", sa.Integer(), nullable=False),
        sa.Column("declared_on", sa.Date(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("share_basis_points BETWEEN 1 AND 10000", name="legal_succession_share_valid"),
        sa.CheckConstraint("status IN ('pending','approved','rejected','revoked')", name="legal_succession_status_valid"))

    # 8. Contrats et accords de réciprocité
    op.create_table("legal_contracts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("counterpart", sa.String(200), nullable=False),
        sa.Column("territory", sa.String(100), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=False),
        sa.Column("valid_until", sa.Date(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("kind IN ('reciprocity','representation','settlement','other')", name="legal_contract_kind_valid"),
        sa.CheckConstraint("status IN ('draft','active','terminated')", name="legal_contract_status_valid"),
        sa.CheckConstraint("valid_until IS NULL OR valid_until >= valid_from", name="legal_contract_dates_valid"))

    # 9. Lien dossiers <-> GED existante (documents) — non invasif
    op.create_table("legal_case_documents",
        sa.Column("organization_id", sa.Uuid(), primary_key=True),
        sa.Column("case_id", sa.Uuid(), primary_key=True),
        sa.Column("document_id", sa.Uuid(), primary_key=True),
        sa.Column("linked_by", sa.Uuid(), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "case_id"], ["legal_cases.organization_id", "legal_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id", "document_id"], ["documents.organization_id", "documents.id"], ondelete="CASCADE"))

    for t in LEGAL_TABLES:
        _rls(t)


def downgrade():
    for t in reversed(LEGAL_TABLES):
        op.drop_table(t)
