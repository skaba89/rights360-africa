from contextlib import contextmanager
from uuid import UUID
from sqlalchemy import text
from app.db import get_engine

@contextmanager
def tenant_transaction(organization_id: UUID):
    """Internal only: callers must authenticate and authorize membership first."""
    tenant_id = str(UUID(str(organization_id)))
    with get_engine().begin() as conn:
        conn.execute(text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": tenant_id})
        yield conn
