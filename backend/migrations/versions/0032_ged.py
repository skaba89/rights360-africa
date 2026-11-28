"""PHASE 6 — GED entreprise (Gestion Électronique de Documents).

Extends the existing documents flow (0026: documents + document_versions with
bytea content + SHA-256 + versioning + archive lock) with the enterprise
capabilities the roadmap requires (GED 45 -> 82): quarantine + antivirus,
quotas, retention + litigation hold, access journal, presigned URLs,
metadata + search, object-storage abstraction + encryption. **"Jamais de
téléchargement en quarantaine."**

Non-destructive: the existing document_versions content column + its integrity
CC stay intact (dual-write when object storage is enabled). New columns are
nullable/defaulted so legacy rows keep working. The three behavioral flags
(quarantine / object storage / encryption) are platform settings seeded to
FALSE -> the existing upload/download flow is unchanged until a flag is lifted;
the features are exercised by tests that flip the flags.

Tables (all org-scoped, RLS tenant_scope):
  document_storage           per-org backend config (local/s3/b2)
  document_quotas            per-org byte + document limits
  document_retention_policies  category -> retain_days
  document_litigation_holds   freeze deletion (released_at nullable)
  document_access_log         journal of every view/download/presign/scan
  document_metadata           key-value metadata per document

ALTER document_versions: +object_key, +encryption_iv, +ocr_text,
                          +quarantine_status (default 'clean')
ALTER documents:         +retention_until, +litigation_hold (default false)

platform_settings seeds: documents_quarantine_enabled / object_storage_enabled /
encryption_enabled = 'false'. Generic platform_setting_bool(key) function.
"""
import sqlalchemy as sa
from alembic import op

revision = "0032"
down_revision = "0031"  # PHASE 6 chains after PHASE 5 payments
branch_labels = None
depends_on = None

NEW_TABLES = ["document_storage", "document_quotas", "document_retention_policies",
              "document_litigation_holds", "document_access_log", "document_metadata"]


def _rls(table):
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_scope ON {table} FOR ALL TO rights360_runtime
    USING (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (organization_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid)""")
    op.execute(f"GRANT SELECT,INSERT,UPDATE,DELETE ON {table} TO rights360_runtime")


def upgrade():
    # ── 1. Storage backend config (per org) ─────────────────────────────────
    op.create_table("document_storage",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("backend", sa.String(10), nullable=False, server_default="local"),
        sa.Column("bucket", sa.String(120), nullable=True),
        sa.Column("endpoint", sa.String(200), nullable=True),
        sa.Column("region", sa.String(40), nullable=True),
        sa.Column("credentials_ref", sa.String(200), nullable=True),
        sa.Column("encryption_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("backend IN ('local','s3','b2')", name="storage_backend_valid"),
        sa.UniqueConstraint("organization_id", name="storage_org_unique"))

    # ── 2. Quotas (per org) ─────────────────────────────────────────────────
    op.create_table("document_quotas",
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("max_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_documents", sa.Integer(), nullable=False),
        sa.Column("enforced", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("max_bytes>0 AND max_documents>0", name="quota_values_valid"))

    # ── 3. Retention policies (category -> retain_days); composite PK ───────
    op.create_table("document_retention_policies",
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True, nullable=False),
        sa.Column("category", sa.String(30), primary_key=True, nullable=False),
        sa.Column("retain_days", sa.Integer(), nullable=False),
        sa.Column("legal_hold_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("retain_days>=0", name="retention_days_valid"))

    # ── 4. Litigation holds (freeze deletion; released_at nullable) ─────────
    op.create_table("document_litigation_holds",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("held_by", sa.Uuid(), nullable=False),
        sa.Column("held_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id", "document_id"], ["documents.organization_id", "documents.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "id", name="litigation_org_id_unique"))
    op.create_index("litigation_active_unique", "document_litigation_holds",
                    ["organization_id", "document_id"], unique=True,
                    postgresql_where=sa.text("released_at IS NULL"))

    # ── 5. Access journal (every view/download/presign/scan) ────────────────
    op.create_table("document_access_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=True),  # nullable: presigned (anonymous) downloads have no account
        sa.Column("ip_hash", sa.String(64), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("action IN ('view','download','presign','scan','archive','hold','release')", name="access_action_valid"),
        sa.UniqueConstraint("organization_id", "id", name="access_log_org_id_unique"))

    # ── 6. Metadata (key-value per document) ────────────────────────────────
    op.create_table("document_metadata",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(80), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id", "document_id"], ["documents.organization_id", "documents.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "document_id", "key", name="metadata_doc_key_unique"),
        sa.UniqueConstraint("organization_id", "id", name="metadata_org_id_unique"))

    # ── 7. Extend document_versions + documents (nullable, non-destructive) ─
    op.add_column("document_versions", sa.Column("object_key", sa.String(256), nullable=True))
    op.add_column("document_versions", sa.Column("encryption_iv", sa.String(64), nullable=True))
    op.add_column("document_versions", sa.Column("ocr_text", sa.Text(), nullable=True))
    op.add_column("document_versions", sa.Column("quarantine_status", sa.String(20), nullable=False, server_default="clean"))
    op.execute("ALTER TABLE document_versions DROP CONSTRAINT IF EXISTS document_version_valid")
    op.execute("""ALTER TABLE document_versions ADD CONSTRAINT document_version_valid
        CHECK (version>0 AND size_bytes BETWEEN 1 AND 2097152 AND octet_length(content)=size_bytes
               AND quarantine_status IN ('clean','quarantine','infected'))""")
    op.add_column("documents", sa.Column("retention_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("documents", sa.Column("litigation_hold", sa.Boolean(), nullable=False, server_default=sa.false()))

    # ── 8. Platform flags (default FALSE -> existing flow unchanged) ────────
    op.execute("GRANT UPDATE ON documents TO rights360_runtime")  # patch retention_until/litigation_hold
    op.execute("GRANT UPDATE ON document_versions TO rights360_runtime")  # ged scan endpoint stamps quarantine_status
    for key in ("documents_quarantine_enabled", "documents_object_storage_enabled", "documents_encryption_enabled"):
        op.execute(f"INSERT INTO platform_settings(key,value,updated_by) VALUES ('{key}','false','00000000-0000-0000-0000-000000000000') ON CONFLICT (key) DO NOTHING")

    # ── 9. Generic platform_setting_bool(key) — reusable DSIG-gated flag read ─
    op.execute("""
    CREATE FUNCTION public.platform_setting_bool(k text) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
      SELECT COALESCE((SELECT value='true' FROM public.platform_settings WHERE key=k), false)
    $$;
    REVOKE ALL ON FUNCTION public.platform_setting_bool(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.platform_setting_bool(text) TO rights360_runtime;
    """)

    # ── 10. RLS on the 6 new org-scoped tables ──────────────────────────────
    for t in NEW_TABLES:
        _rls(t)


def downgrade():
    op.execute("DROP FUNCTION IF EXISTS public.platform_setting_bool(text) CASCADE")
    for t in reversed(NEW_TABLES):
        op.drop_table(t)
    op.drop_column("documents", "litigation_hold")
    op.drop_column("documents", "retention_until")
    op.execute("ALTER TABLE document_versions DROP CONSTRAINT IF EXISTS document_version_valid")
    op.execute("""ALTER TABLE document_versions ADD CONSTRAINT document_version_valid
        CHECK (version>0 AND size_bytes BETWEEN 1 AND 2097152 AND octet_length(content)=size_bytes)""")
    op.drop_column("document_versions", "quarantine_status")
    op.drop_column("document_versions", "ocr_text")
    op.drop_column("document_versions", "encryption_iv")
    op.drop_column("document_versions", "object_key")
