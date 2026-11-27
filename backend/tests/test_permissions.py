import pytest
from fastapi import HTTPException
from app.permissions import require_permission

@pytest.mark.parametrize("role", ["manager","auditor","artist","unknown"])
def test_non_admin_cannot_write_modules(role):
    with pytest.raises(HTTPException) as exc:
        require_permission("modules:write")({"role":role})
    assert exc.value.status_code == 403

def test_admin_can_write():
    assert require_permission("modules:write")({"role":"admin"}) == {"role":"admin"}

def test_unknown_permission_denied():
    with pytest.raises(HTTPException):
        require_permission("unknown")({"role":"admin"})
