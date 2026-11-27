import pytest
from fastapi import HTTPException
from app.platform_admin import require_platform_admin

@pytest.mark.parametrize("identity", [{"role":"admin","mfa_enabled":False},{"role":"artist","mfa_enabled":True}])
def test_platform_denies_ineligible_roles(identity):
    with pytest.raises(HTTPException) as exc:
        require_platform_admin(identity)
    assert exc.value.status_code == 403
