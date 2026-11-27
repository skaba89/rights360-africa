import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import APIRouter, Depends, HTTPException, Response, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import text
from app.db import get_engine
from app.login_limits import reserve_login

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
hasher = PasswordHasher()
dummy_hash = hasher.hash(secrets.token_hex(32))
bearer = HTTPBearer(auto_error=False)

class Login(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)
    organization_id: UUID

def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def invalid():
    return HTTPException(status_code=401, detail="Invalid credentials or session", headers={"WWW-Authenticate": "Bearer"})

def verify_password(encoded: str, password: str) -> bool:
    try:
        return hasher.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False

def current_identity(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if credentials is None or len(credentials.credentials) > 128:
        raise invalid()
    with get_engine().connect() as conn:
        row = conn.execute(text("""
          SELECT a.id AS account_id, a.email, m.organization_id, m.role
          FROM auth_sessions s JOIN accounts a ON a.id=s.account_id
          JOIN memberships m ON m.account_id=s.account_id AND m.organization_id=s.organization_id
          WHERE s.token_hash=:token AND s.expires_at>now() AND a.active AND m.active
        """), {"token": digest(credentials.credentials)}).mappings().first()
    if row is None:
        raise invalid()
    return dict(row)

@router.post("/login")
def login(payload: Login, response: Response, request: Request):
    reserve_login(payload.email, payload.organization_id, request.client.host if request.client else 'unknown')
    with get_engine().begin() as conn:
        account = conn.execute(text("""
          SELECT a.id, a.password_hash FROM accounts a JOIN memberships m ON m.account_id=a.id
          WHERE a.email=:email AND m.organization_id=:org AND a.active AND m.active
        """), {"email":payload.email.strip().lower(),"org":payload.organization_id}).mappings().first()
        valid = verify_password(account["password_hash"] if account else dummy_hash, payload.password)
        if not account or not valid:
            raise invalid()
        token = secrets.token_urlsafe(48)
        conn.execute(text("DELETE FROM auth_sessions WHERE account_id=:account AND expires_at<=now()"), {"account":account["id"]})
        conn.execute(text("INSERT INTO auth_sessions(token_hash,account_id,organization_id,expires_at) VALUES (:token,:account,:org,:expiry)"),
          {"token":digest(token),"account":account["id"],"org":payload.organization_id,"expiry":datetime.now(timezone.utc)+timedelta(minutes=30)})
    response.headers["Cache-Control"] = "no-store"
    return {"access_token":token,"token_type":"bearer","expires_in":1800}

@router.get("/me")
def me(response: Response, identity=Depends(current_identity)):
    response.headers["Cache-Control"] = "no-store"
    return identity

@router.post("/logout", status_code=204)
def logout(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if credentials is not None and len(credentials.credentials)<=128:
        with get_engine().begin() as conn:
            conn.execute(text("DELETE FROM auth_sessions WHERE token_hash=:token"), {"token":digest(credentials.credentials)})
    return Response(status_code=204, headers={"Cache-Control":"no-store"})
