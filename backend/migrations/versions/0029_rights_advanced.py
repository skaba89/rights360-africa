"""PHASE 3 — Advanced copyright and related rights.

Extends the existing works/artists/rights schema NON-destructively:
  * artists: holder category + IPI + ISNI identifiers (nullable)
  * works: genre, language, derivation (original/derived/...), visibility
    (public/private), parent_work_id (org-scoped self-reference for derivatives)
  * recordings: ISRC sound recordings linked to a work
  * rights_grants: territorial, time-bound rights with collective/direct scope
  * distribution_rules: per-category, versioned, reproducible allocation rules
  * rights_unidentified: amounts held pending identification
  * rights_claims: holder claims/adjustments with an approval workflow

ISWC already exists on works (migration 0015). New columns are nullable so
existing rows are unaffected. RLS reuses the app.tenant_id tenant_scope policy
on every new table; ALTERed works/artists keep their existing RLS policies
(RLS is row-level, not column-level, so new columns are covered automatically).
"""
import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"  # PHASE 3 chains after the PHASE 2 legal module
branch_labels = None
depends_on = None

NEW_TABLES = ["recordings", "rights_grants", "distribution_rules",
              "rights_unidentified", "rights_claims"]


def _rls(table):
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
    USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute(f"GRANT SELECT,INSERT,UPDATE,DELETE ON {table} TO rights360_runtime")


def upgrade():
    # ── Extend artists: holder category + IPI + ISNI ────────────────────────
    op.add_column("artists", sa.Column("category", sa.String(40), nullable=True))
    op.add_column("artists", sa.Column("ipi", sa.String(20), nullable=True))
    op.add_column("artists", sa.Column("isni", sa.String(16), nullable=True))
    op.create_check_constraint("artist_category_valid", "artists",
        "category IS NULL OR category IN ('author','composer','publisher',"
        "'producer_phonographic','producer_audiovisual','performer','heir','mandatary','other')")
    op.create_check_constraint("artist_ipi_format", "artists",
        "ipi IS NULL OR ipi ~ '^[0-9]{9,11}$'")
    op.create_check_constraint("artist_isni_format", "artists",
        "isni IS NULL OR isni ~ '^[0-9]{15}[0-9X]$'")
    op.create_unique_constraint("artist_ipi_unique", "artists", ["organization_id", "ipi"])
    op.create_unique_constraint("artist_isni_unique", "artists", ["organization_id", "isni"])

    # ── Extend works: genre, language, derivation, visibility, parent work ──
    op.add_column("works", sa.Column("genre", sa.String(60), nullable=True))
    op.add_column("works", sa.Column("language", sa.String(10), nullable=True))
    op.add_column("works", sa.Column("derivation", sa.String(20), nullable=True, server_default="original"))
    op.add_column("works", sa.Column("visibility", sa.String(20), nullable=True, server_default="private"))
    op.add_column("works", sa.Column("parent_work_id", sa.Uuid(), nullable=True))
    op.create_check_constraint("work_derivation_valid", "works",
        "derivation IS NULL OR derivation IN ('original','derived','adaptation','arrangement')")
    op.create_check_constraint("work_visibility_valid", "works",
        "visibility IS NULL OR visibility IN ('public','private')")
    op.create_foreign_key("work_parent_same_org", "works", "works",
                          ["organization_id", "parent_work_id"], ["organization_id", "id"])

    # ── Recordings (ISRC) ──────────────────────────────────────────────────
    op.create_table("recordings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("work_id", sa.Uuid(), nullable=False),
        sa.Column("isrc", sa.String(12), nullable=False),
        sa.Column("title", sa.String(250), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "work_id"], ["works.organization_id", "works.id"], ondelete="CASCADE"),
        sa.CheckConstraint("isrc ~ '^[A-Z]{2}[0-9A-Z]{3}[0-9]{2}[0-9]{5}$'", name="recording_isrc_format"),
        sa.UniqueConstraint("organization_id", "isrc", name="recording_isrc_unique"))
    op.create_index("ix_recordings_work", "recordings", ["organization_id", "work_id"])

    # ── Territorial rights grants (collective vs direct) ───────────────────
    op.create_table("rights_grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("work_id", sa.Uuid(), nullable=False),
        sa.Column("artist_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(40), nullable=False),
        sa.Column("territory", sa.String(100), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("basis_points", sa.Integer(), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=False),
        sa.Column("valid_until", sa.Date(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "work_id"], ["works.organization_id", "works.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id", "artist_id"], ["artists.organization_id", "artists.id"], ondelete="CASCADE"),
        sa.CheckConstraint("role IN ('author','composer','publisher','producer_phonographic','producer_audiovisual','performer','heir','mandatary','other')", name="rights_grant_role_valid"),
        sa.CheckConstraint("scope IN ('collective','direct')", name="rights_grant_scope_valid"),
        sa.CheckConstraint("basis_points BETWEEN 1 AND 10000", name="rights_grant_basis_valid"),
        sa.CheckConstraint("status IN ('active','terminated','disputed')", name="rights_grant_status_valid"),
        sa.CheckConstraint("valid_until IS NULL OR valid_until >= valid_from", name="rights_grant_dates_valid"))
    op.create_index("ix_rights_grants_work", "rights_grants", ["organization_id", "work_id"])

    # ── Distribution rules, versioned per category (reproducible) ───────────
    op.create_table("distribution_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("rule_category", sa.String(40), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("allocation", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("version > 0", name="distribution_rule_version_positive"),
        sa.CheckConstraint("rule_category IN ('mechanical','performance','broadcast','synchronization','digital','public_lending','other')", name="distribution_rule_category_valid"),
        sa.CheckConstraint("status IN ('draft','active','superseded')", name="distribution_rule_status_valid"),
        sa.UniqueConstraint("organization_id", "rule_category", "version", name="distribution_rule_version_unique"))
    op.create_index("ix_distribution_rules_category", "distribution_rules", ["organization_id", "rule_category", "version"])

    # ── Unidentified / pending rights (amounts awaiting identification) ────
    op.create_table("rights_unidentified",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("distribution_id", sa.Uuid(), nullable=True),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("reason", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "distribution_id"], ["royalty_distributions.organization_id", "royalty_distributions.id"], ondelete="SET NULL"),
        sa.CheckConstraint("amount_minor > 0", name="rights_unidentified_amount_positive"),
        sa.CheckConstraint("status IN ('pending','identified','claimed','expired')", name="rights_unidentified_status_valid"),
        sa.UniqueConstraint("organization_id", "id", name="rights_unidentified_org_id_unique"))

    # ── Claims / adjustments (holder claims, approval workflow) ─────────────
    op.create_table("rights_claims",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("claimant_artist_id", sa.Uuid(), nullable=False),
        sa.Column("work_id", sa.Uuid(), nullable=True),
        sa.Column("unidentified_id", sa.Uuid(), nullable=True),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("proposed_by", sa.Uuid(), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("reviewed_by", sa.Uuid(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id", "claimant_artist_id"], ["artists.organization_id", "artists.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id", "work_id"], ["works.organization_id", "works.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id", "unidentified_id"], ["rights_unidentified.organization_id", "rights_unidentified.id"], ondelete="SET NULL"),
        sa.CheckConstraint("amount_minor > 0", name="rights_claim_amount_positive"),
        sa.CheckConstraint("status IN ('pending','approved','rejected','paid')", name="rights_claim_status_valid"))

    for t in NEW_TABLES:
        _rls(t)


def downgrade():
    for t in reversed(NEW_TABLES):
        op.drop_table(t)
    op.drop_constraint("work_parent_same_org", "works", type_="foreignkey")
    for col in ("parent_work_id", "visibility", "derivation", "language", "genre"):
        op.drop_column("works", col)
    op.drop_constraint("artist_isni_unique", "artists", type_="unique")
    op.drop_constraint("artist_ipi_unique", "artists", type_="unique")
    op.drop_constraint("artist_isni_format", "artists", type_="check")
    op.drop_constraint("artist_ipi_format", "artists", type_="check")
    op.drop_constraint("artist_category_valid", "artists", type_="check")
    for col in ("isni", "ipi", "category"):
        op.drop_column("artists", col)
