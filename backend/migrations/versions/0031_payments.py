"""PHASE 5 — Banques et Mobile Money (connecteurs de paiement sandbox).

Adds the provider-independent payment-execution layer the existing payout
flow lacked. Today ``payouts.py`` only *approves* payouts (double review ->
``approved_for_review_only``) and hardcodes ``execution_enabled=False`` on
every response; no money ever moves. This phase adds:

  * payment_providers      — per-org connector config (Orange/MTN/bank, sandbox/live)
  * payment_beneficiaries  — per-artist payment details (msisdn/iban/account), verified
  * payment_attempts       — idempotent execution attempts (one per payout, idempotency key)
  * payment_webhooks       — authenticated (HMAC) provider callback ingestion, deduped
  * payment_reconciliations — match a webhook to an attempt (rapprochement)
  * platform_settings      — DSIG-gated global flags (payments_execution_enabled)
  * payout_orders          — ALTERed: +provider, +beneficiary_id, +external_ref, +executed_at

NON-destructive: existing payout_orders/payout_reviews (0022) keep their
schema + double-approval trigger; new columns are nullable. RLS reuses the
app.tenant_id tenant_scope policy on every new org-scoped table.

DSIG GATE (ROADMAP_99.md line 119): payments execution has an EXTERNAL
authorization lock that can only be lifted by the DSIG. The
``payments_execution_enabled`` platform setting defaults to FALSE; while it
is false the execute endpoint runs in SANDBOX (records a succeeded attempt
with an ``external_ref=sandbox-...``, no real money movement). Lifting the
gate to 'live' is a DSIG human process, not a code change.
"""
import sqlalchemy as sa
from alembic import op

revision = "0031"
down_revision = "0030"  # PHASE 5 chains after the PHASE 4 finance module
branch_labels = None
depends_on = None

NEW_TABLES = ["payment_providers", "payment_beneficiaries", "payment_attempts",
              "payment_webhooks", "payment_reconciliations"]


def _rls(table):
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
    USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute(f"GRANT SELECT,INSERT,UPDATE,DELETE ON {table} TO rights360_runtime")


def upgrade():
    # ── 1. Connecteur config (per org + provider) ───────────────────────────
    op.create_table("payment_providers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("mode", sa.String(10), nullable=False, server_default="sandbox"),
        sa.Column("api_base", sa.String(200), nullable=True),
        sa.Column("credentials_ref", sa.String(200), nullable=True),
        sa.Column("webhook_secret", sa.String(128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("provider IN ('orange_money','mtn_momo','bank_transfer')", name="provider_kind_valid"),
        sa.CheckConstraint("mode IN ('sandbox','live')", name="provider_mode_valid"),
        sa.UniqueConstraint("organization_id", "provider", name="provider_kind_unique"),
        sa.UniqueConstraint("organization_id", "id", name="provider_org_id_unique"))

    # ── 2. Bénéficiaires (artist payment details per channel) ────────────────
    op.create_table("payment_beneficiaries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("artist_id", sa.Uuid(), nullable=False),
        sa.Column("channel", sa.String(30), nullable=False),
        sa.Column("msisdn", sa.String(20), nullable=True),
        sa.Column("iban", sa.String(34), nullable=True),
        sa.Column("account_number", sa.String(40), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("verified_by", sa.Uuid(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "artist_id"], ["artists.organization_id", "artists.id"]),
        sa.CheckConstraint("channel IN ('bank','orange_money','mtn_momo')", name="beneficiary_channel_valid"),
        sa.CheckConstraint("msisdn IS NOT NULL OR iban IS NOT NULL OR account_number IS NOT NULL", name="beneficiary_details_present"),
        sa.UniqueConstraint("organization_id", "artist_id", "channel", name="beneficiary_artist_channel_unique"),
        sa.UniqueConstraint("organization_id", "id", name="beneficiary_org_id_unique"))

    # ── 3. Tentatives d'exécution (idempotentes) ─────────────────────────────
    op.create_table("payment_attempts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("payout_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("external_ref", sa.String(100), nullable=True),
        sa.Column("error_message", sa.String(500), nullable=True),
        sa.Column("attempted_by", sa.Uuid(), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id", "payout_id"], ["payout_orders.organization_id", "payout_orders.id"]),
        sa.CheckConstraint("status IN ('pending','succeeded','failed','refunded')", name="attempt_status_valid"),
        sa.CheckConstraint("idempotency_key ~ '^[A-Za-z0-9_-]{8,64}$'", name="attempt_idempotency_format"),
        sa.UniqueConstraint("organization_id", "idempotency_key", name="attempt_idempotency_unique"),
        sa.UniqueConstraint("organization_id", "payout_id", name="attempt_payout_unique"),
        sa.UniqueConstraint("organization_id", "id", name="attempt_org_id_unique"))

    # ── 4. Webhooks entrants (HMAC-authentifiés, dédupliqués) ────────────────
    op.create_table("payment_webhooks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider", sa.String(30), nullable=False),
        sa.Column("event_ref", sa.String(100), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("raw_payload", sa.JSON(), nullable=False),
        sa.Column("matched_attempt_id", sa.Uuid(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("provider IN ('orange_money','mtn_momo','bank_transfer')", name="webhook_provider_valid"),
        sa.UniqueConstraint("organization_id", "provider", "event_ref", name="webhook_event_unique"),
        sa.UniqueConstraint("organization_id", "id", name="webhook_org_id_unique"))

    # ── 5. Rapprochements (match webhook <-> attempt) ────────────────────────
    op.create_table("payment_reconciliations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("attempt_id", sa.Uuid(), nullable=False),
        sa.Column("webhook_id", sa.Uuid(), nullable=False),
        sa.Column("note", sa.String(500), nullable=True),
        sa.Column("reconciled_by", sa.Uuid(), nullable=False),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "attempt_id"], ["payment_attempts.organization_id", "payment_attempts.id"]),
        sa.ForeignKeyConstraint(["organization_id", "webhook_id"], ["payment_webhooks.organization_id", "payment_webhooks.id"]),
        sa.UniqueConstraint("organization_id", "attempt_id", name="reconciliation_attempt_unique"),
        sa.UniqueConstraint("organization_id", "id", name="reconciliation_org_id_unique"))

    # ── 6. Extend payout_orders: provider, beneficiary, external ref ────────
    op.add_column("payout_orders", sa.Column("provider", sa.String(30), nullable=True))
    op.add_column("payout_orders", sa.Column("beneficiary_id", sa.Uuid(), nullable=True))
    op.add_column("payout_orders", sa.Column("external_ref", sa.String(100), nullable=True))
    op.add_column("payout_orders", sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key("payout_beneficiary_fk", "payout_orders", "payment_beneficiaries",
                          ["organization_id", "beneficiary_id"], ["organization_id", "id"])
    # The execute endpoint stamps provider/beneficiary_id/external_ref/executed_at
    # on payout_orders; 0022 only granted SELECT,INSERT -> add UPDATE.
    op.execute("GRANT UPDATE ON payout_orders TO rights360_runtime")

    # ── 7. DSIG-gated platform settings (global, NOT org-scoped) ─────────────
    op.create_table("platform_settings",
        sa.Column("key", sa.String(80), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.execute("GRANT SELECT ON platform_settings TO rights360_runtime")
    # Seed the DSIG gate: payments execution is DISABLED by default. Lifting it
    # to 'true' is a DSIG human authorization process, not a code change.
    op.execute("INSERT INTO platform_settings(key,value,updated_by) VALUES ('payments_execution_enabled','false','00000000-0000-0000-0000-000000000000')")

    # ── 8. RLS on the 5 new org-scoped tables ────────────────────────────────
    for t in NEW_TABLES:
        _rls(t)

    # ── 9. payments_execution_enabled() — DSIG gate read (SECURITY DEFINER) ─
    op.execute("""
    CREATE FUNCTION public.payments_execution_enabled() RETURNS boolean
    LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
      SELECT COALESCE((SELECT value='true' FROM public.platform_settings WHERE key='payments_execution_enabled'), false)
    $$;
    REVOKE ALL ON FUNCTION public.payments_execution_enabled() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.payments_execution_enabled() TO rights360_runtime;
    """)


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS public.payments_execution_enabled() CASCADE")
    for t in reversed(NEW_TABLES):
        op.drop_table(t)
    op.drop_constraint("payout_beneficiary_fk", "payout_orders", type_="foreignkey")
    op.drop_column("payout_orders", "executed_at")
    op.drop_column("payout_orders", "external_ref")
    op.drop_column("payout_orders", "beneficiary_id")
    op.drop_column("payout_orders", "provider")
    op.drop_table("platform_settings")
