"""Session diagnostics: issued_at, peer, user_agent.

Adds audit columns to ``auth_sessions`` so administrators can diagnose active
sessions without exposing secrets, and supports the concurrent-session cap
introduced in PHASE 1. Non-destructive: nullable columns with a server default
for ``issued_at`` so existing rows backfill cleanly.

RLS/grants: ``auth_sessions`` already grants SELECT, INSERT, DELETE to
``rights360_runtime`` (migration 0003). New columns inherit table privileges;
no additional GRANT needed. The login path only INSERTs and DELETEs sessions
(never UPDATEs), so the cap is implemented as a counted DELETE.
"""
import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "auth_sessions",
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.add_column("auth_sessions", sa.Column("peer", sa.String(64), nullable=True))
    op.add_column("auth_sessions", sa.Column("user_agent", sa.String(256), nullable=True))
    op.create_index("ix_auth_sessions_account_issued", "auth_sessions", ["account_id", "issued_at"])


def downgrade():
    op.drop_index("ix_auth_sessions_account_issued", table_name="auth_sessions")
    op.drop_column("auth_sessions", "user_agent")
    op.drop_column("auth_sessions", "peer")
    op.drop_column("auth_sessions", "issued_at")
