"""PHASE 4 — Finance et comptabilité SYSCOHADA.

Adds the configurable SYSCOHADA layer the existing accounting engine lacks
(today ``accounting_lines.account_key`` is a free-form string and
``accounting.py`` hardcodes five generic keys: receivable, royalties_unallocated,
cash_unverified, management_commission, beneficiary_payable).

NON-destructive schema additions:
  * chart_of_accounts       — configurable plan comptable (SYSCOHADA classes 1-8)
  * account_mappings        — generic_key -> SYSCOHADA account_code bridge
  * journals                — journaux (sales / receipts / general / payouts)
  * fiscal_periods          — exercices + périodes, status open/closed/locked
  * fiscal_period_reviews   — multi-level approval before closing a period
  * accounting_reversals    — contrepassations (reversal of a posted entry)
  * tax_rules               — retenues à la source (withholding), configurable
  * accounting_entries      — ALTERed: +journal_id, +fiscal_period_id (nullable)

Existing accounting_entries/lines rows are unaffected (new columns nullable,
new tables independent). RLS reuses the app.tenant_id tenant_scope policy on
every new table; ALTERed accounting_entries keeps its existing RLS policies
(RLS is row-level, not column-level, so new columns are covered automatically).

NOTE — SYSCOHADA compliance: the default OHADA chart seeded by the router
(POST /api/v1/finance/chart-of-accounts/seed) is a sensible default for an
IP-rights collective-management organisation. Per ROADMAP_99.md, the SYSCOHADA
rules, account mapping and tax rates MUST be qualified by a professional
(commissaire aux comptes) before production use.
"""
import sqlalchemy as sa
from alembic import op

revision = "0030"
down_revision = "0029"  # PHASE 4 chains after the PHASE 3 rights module
branch_labels = None
depends_on = None

NEW_TABLES = ["chart_of_accounts", "account_mappings", "journals",
              "fiscal_periods", "fiscal_period_reviews", "accounting_reversals",
              "tax_rules"]


def _rls(table):
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
    USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute(f"GRANT SELECT,INSERT,UPDATE,DELETE ON {table} TO rights360_runtime")


def upgrade():
    # ── 1. Plan comptable configurable (SYSCOHADA classes 1-8) ───────────────
    op.create_table("chart_of_accounts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("account_code", sa.String(20), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("syscohada_class", sa.String(1), nullable=False),
        sa.Column("account_type", sa.String(20), nullable=False),
        sa.Column("parent_account_code", sa.String(20), nullable=True),
        sa.Column("is_postable", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("syscohada_class IN ('1','2','3','4','5','6','7','8')", name="chart_class_valid"),
        sa.CheckConstraint("account_type IN ('asset','liability','equity','revenue','expense')", name="chart_type_valid"),
        sa.CheckConstraint("account_code ~ '^[0-9]{1,8}$'", name="chart_code_format"),
        sa.UniqueConstraint("organization_id", "account_code", name="chart_account_code_unique"),
        sa.UniqueConstraint("organization_id", "id", name="chart_account_org_id_unique"))

    # ── 2. generic_key -> SYSCOHADA account_code bridge ──────────────────────
    # Maps the five hardcoded accounting.py keys to configurable SYSCOHADA
    # accounts, so the existing double-entry engine can produce a SYSCOHADA
    # trial balance without rewriting accounting_lines.
    op.create_table("account_mappings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("generic_key", sa.String(40), nullable=False),
        sa.Column("account_code", sa.String(20), nullable=False),
        sa.ForeignKeyConstraint(["organization_id", "account_code"],
                                ["chart_of_accounts.organization_id", "chart_of_accounts.account_code"]),
        sa.CheckConstraint("generic_key IN ('receivable','royalties_unallocated','cash_unverified','management_commission','beneficiary_payable')",
                           name="account_mapping_key_valid"),
        sa.UniqueConstraint("organization_id", "generic_key", name="account_mapping_key_unique"),
        sa.UniqueConstraint("organization_id", "id", name="account_mapping_org_id_unique"))

    # ── 3. Journaux ─────────────────────────────────────────────────────────
    op.create_table("journals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("code", sa.String(10), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("kind IN ('sales','receipts','general','payouts')", name="journal_kind_valid"),
        sa.CheckConstraint("code ~ '^[A-Z0-9]{1,10}$'", name="journal_code_format"),
        sa.UniqueConstraint("organization_id", "code", name="journal_code_unique"),
        sa.UniqueConstraint("organization_id", "id", name="journal_org_id_unique"))

    # ── 4. Exercices / périodes comptables ───────────────────────────────────
    op.create_table("fiscal_periods",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("fiscal_year", sa.Integer(), nullable=False),
        sa.Column("period_index", sa.Integer(), nullable=False),
        sa.Column("starts_on", sa.Date(), nullable=False),
        sa.Column("ends_on", sa.Date(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="open"),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('open','closed','locked')", name="fiscal_period_status_valid"),
        sa.CheckConstraint("period_index BETWEEN 0 AND 12", name="fiscal_period_index_valid"),
        sa.CheckConstraint("ends_on >= starts_on", name="fiscal_period_dates_valid"),
        sa.UniqueConstraint("organization_id", "fiscal_year", "period_index", name="fiscal_period_unique"),
        sa.UniqueConstraint("organization_id", "id", name="fiscal_period_org_id_unique"))

    # ── 5. Multi-level approval before closing a period ─────────────────────
    op.create_table("fiscal_period_reviews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("period_id", sa.Uuid(), nullable=False),
        sa.Column("reviewer_id", sa.Uuid(), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("rationale", sa.String(500), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "period_id"],
                                ["fiscal_periods.organization_id", "fiscal_periods.id"], ondelete="CASCADE"),
        sa.CheckConstraint("decision IN ('approve','reject')", name="fiscal_review_decision_valid"),
        sa.UniqueConstraint("organization_id", "id", name="fiscal_review_org_id_unique"),
        sa.UniqueConstraint("organization_id", "period_id", "reviewer_id", name="fiscal_review_no_duplicate"))

    # ── 6. Contrepassations (reversal of a posted entry) ─────────────────────
    op.create_table("accounting_reversals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("original_entry_id", sa.Uuid(), nullable=False),
        sa.Column("reversal_entry_id", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("reversed_by", sa.Uuid(), nullable=False),
        sa.Column("reversed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "original_entry_id"],
                                ["accounting_entries.organization_id", "accounting_entries.id"]),
        sa.ForeignKeyConstraint(["organization_id", "reversal_entry_id"],
                                ["accounting_entries.organization_id", "accounting_entries.id"]),
        sa.CheckConstraint("original_entry_id <> reversal_entry_id", name="reversal_not_self_valid"),
        sa.UniqueConstraint("organization_id", "id", name="reversal_org_id_unique"),
        sa.UniqueConstraint("organization_id", "original_entry_id", name="reversal_entry_unique"))

    # ── 7. Retenues à la source (withholding tax rules) ──────────────────────
    op.create_table("tax_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("country", sa.String(2), nullable=False),
        sa.Column("rate_bps", sa.Integer(), nullable=False),
        sa.Column("account_code", sa.String(20), nullable=True),
        sa.ForeignKeyConstraint(["organization_id", "account_code"],
                                ["chart_of_accounts.organization_id", "chart_of_accounts.account_code"]),
        sa.CheckConstraint("rate_bps BETWEEN 0 AND 10000", name="tax_rate_valid"),
        sa.CheckConstraint("country ~ '^[A-Z]{2}$'", name="tax_country_format"),
        sa.UniqueConstraint("organization_id", "category", "country", name="tax_rule_unique"),
        sa.UniqueConstraint("organization_id", "id", name="tax_rule_org_id_unique"))

    # ── 8. Extend accounting_entries: journal + fiscal period (nullable) ─────
    op.add_column("accounting_entries", sa.Column("journal_id", sa.Uuid(), nullable=True))
    op.add_column("accounting_entries", sa.Column("fiscal_period_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("entry_journal_fk", "accounting_entries", "journals",
                          ["organization_id", "journal_id"], ["organization_id", "id"])
    op.create_foreign_key("entry_period_fk", "accounting_entries", "fiscal_periods",
                          ["organization_id", "fiscal_period_id"], ["organization_id", "id"])
    # Allow 'reversal' as a source_type so contrepassations can be posted as real
    # (balanced) entries that net out the original in the trial balance. The
    # reversal entry's source_id is the original entry's id, and the existing
    # entry_source_unique(org, source_type, source_id) then enforces one
    # reversal per original entry.
    op.execute("ALTER TABLE accounting_entries DROP CONSTRAINT IF EXISTS entry_source_valid")
    op.create_check_constraint("entry_source_valid", "accounting_entries",
        "source_type IN ('invoice','receipt','distribution','reversal')")

    # ── RLS on every new table ───────────────────────────────────────────────
    for t in NEW_TABLES:
        _rls(t)

    # ── Integrity triggers ───────────────────────────────────────────────────
    # Multi-level approval: a period cannot be closed unless it has >= 2
    # distinct approvals and no rejects. These are regular BEFORE ROW triggers
    # (immediate, not deferred): they RAISE check_violation to abort the
    # offending UPDATE/INSERT. (PostgreSQL CONSTRAINT triggers must be AFTER,
    # so BEFORE guards use plain CREATE TRIGGER.)
    op.execute("""
    CREATE FUNCTION public.check_fiscal_period_close() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    DECLARE approves int; rejects int;
    BEGIN
      IF NEW.status='closed' AND (OLD.status IS DISTINCT FROM 'closed') THEN
        SELECT COUNT(*), COUNT(*) FILTER (WHERE decision='reject')
          INTO approves, rejects
          FROM public.fiscal_period_reviews
         WHERE organization_id=NEW.organization_id AND period_id=NEW.id;
        IF rejects > 0 THEN RAISE check_violation USING MESSAGE='Period has a rejection and cannot be closed'; END IF;
        IF approves < 2 THEN RAISE check_violation USING MESSAGE='Period requires at least 2 independent approvals before closing'; END IF;
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER fiscal_period_close_guard
      BEFORE UPDATE OF status ON fiscal_periods
      FOR EACH ROW EXECUTE FUNCTION public.check_fiscal_period_close();

    CREATE FUNCTION public.check_fiscal_period_review() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
    DECLARE pstatus text; approves int;
    BEGIN
      SELECT status INTO pstatus FROM public.fiscal_periods
       WHERE organization_id=NEW.organization_id AND id=NEW.period_id;
      IF pstatus IS NULL THEN RAISE check_violation USING MESSAGE='Fiscal period not found'; END IF;
      IF pstatus='closed' OR pstatus='locked' THEN RAISE check_violation USING MESSAGE='Period already closed'; END IF;
      SELECT COUNT(*) INTO approves FROM public.fiscal_period_reviews
       WHERE organization_id=NEW.organization_id AND period_id=NEW.period_id AND decision='approve';
      IF NEW.decision='approve' AND approves >= 2 THEN RAISE check_violation USING MESSAGE='Period already has 2 approvals'; END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER fiscal_period_review_guard
      BEFORE INSERT ON fiscal_period_reviews
      FOR EACH ROW EXECUTE FUNCTION public.check_fiscal_period_review();
    """)


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS public.check_fiscal_period_review() CASCADE")
    op.execute("DROP FUNCTION IF EXISTS public.check_fiscal_period_close() CASCADE")
    # Restore the original accounting_entries.source_type CHECK (no 'reversal').
    op.execute("ALTER TABLE accounting_entries DROP CONSTRAINT IF EXISTS entry_source_valid")
    op.create_check_constraint("entry_source_valid", "accounting_entries",
        "source_type IN ('invoice','receipt','distribution')")
    op.drop_constraint("entry_period_fk", "accounting_entries", type_="foreignkey")
    op.drop_constraint("entry_journal_fk", "accounting_entries", type_="foreignkey")
    op.drop_column("accounting_entries", "fiscal_period_id")
    op.drop_column("accounting_entries", "journal_id")
    for t in reversed(NEW_TABLES):
        op.drop_table(t)
