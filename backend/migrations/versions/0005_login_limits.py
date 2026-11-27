from alembic import op
import sqlalchemy as sa
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("login_buckets",
        sa.Column("bucket",sa.String(80),primary_key=True),
        sa.Column("window_start",sa.DateTime(timezone=True),nullable=False),
        sa.Column("attempts",sa.Integer(),nullable=False))
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON login_buckets TO rights360_runtime")

def downgrade():
    op.drop_table("login_buckets")
