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
from app.mfa import consume_code, cipher, new_secret
from app.recovery import generate_codes, consume_recovery

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
hasher = PasswordHasher()
dummy_hash = hasher.hash(secrets.token_hex(32))
bearer = HTTPBearer(auto_error=False)
# Maximum concurrent active sessions per (account, organization). Excess oldest
# sessions are revoked at login time so a compromised account cannot accumulate
# an unbounded number of live tokens.
MAX_SESSIONS = 5

class Login(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)
    organization_id: UUID
    otp: str | None = Field(default=None, max_length=6)
    recovery_code: str | None = Field(default=None, max_length=35)

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
          SELECT a.id AS account_id, a.email, m.organization_id, m.role, COALESCE(f.enabled,false) AS mfa_enabled
          FROM auth_sessions s JOIN accounts a ON a.id=s.account_id
          JOIN memberships m ON m.account_id=s.account_id AND m.organization_id=s.organization_id
          LEFT JOIN account_mfa f ON f.account_id=a.id
          WHERE s.token_hash=:token AND s.expires_at>now() AND a.active AND m.active AND public.organization_active(m.organization_id)
        """), {"token": digest(credentials.credentials)}).mappings().first()
    if row is None:
        raise invalid()
    identity = dict(row)
    identity['mfa_required'] = identity['role'] == 'admin' and not identity['mfa_enabled']
    return identity

def require_admin_mfa(identity):
    if identity["role"] != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")
    if not identity.get("mfa_enabled", False):
        raise HTTPException(status_code=403, detail="MFA enrollment required")
    return identity

@router.post("/login")
def login(payload: Login, response: Response, request: Request):
    peer = request.client.host if request.client else 'unknown'
    user_agent = (request.headers.get('user-agent') or '')[:256] or None
    reserve_login(payload.email, payload.organization_id, peer)
    with get_engine().begin() as conn:
        account = conn.execute(text("""
          SELECT a.id, a.password_hash, m.role FROM accounts a JOIN memberships m ON m.account_id=a.id
          WHERE a.email=:email AND m.organization_id=:org AND a.active AND m.active AND public.organization_active(m.organization_id)
        """), {"email":payload.email.strip().lower(),"org":payload.organization_id}).mappings().first()
        valid = verify_password(account["password_hash"] if account else dummy_hash, payload.password)
        if not account or not valid:
            raise invalid()
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text), 360))"), {"id":account["id"]})
        enabled = conn.execute(text("SELECT enabled FROM account_mfa WHERE account_id=:id"), {"id":account["id"]}).scalar_one_or_none()
        if enabled:
            if payload.otp and payload.recovery_code:
                raise invalid()
            if not (consume_recovery(conn, account["id"], payload.recovery_code) if payload.recovery_code else consume_code(conn, account["id"], payload.otp)):
                raise invalid()
        token = secrets.token_urlsafe(48)
        conn.execute(text("DELETE FROM auth_sessions WHERE account_id=:account AND expires_at<=now()"), {"account":account["id"]})
        # Concurrent-session cap: keep at most MAX_SESSIONS-1 active sessions
        # before issuing a new one, revoking the oldest first.
        active = conn.execute(text("""
            SELECT count(*) FROM auth_sessions
            WHERE account_id=:account AND organization_id=:org AND expires_at>now()
        """), {"account":account["id"],"org":payload.organization_id}).scalar_one()
        surplus = active - (MAX_SESSIONS - 1)
        if surplus > 0:
            conn.execute(text("""
                DELETE FROM auth_sessions WHERE token_hash IN (
                    SELECT token_hash FROM auth_sessions
                    WHERE account_id=:account AND organization_id=:org AND expires_at>now()
                    ORDER BY issued_at ASC LIMIT :n
                )
            """), {"account":account["id"],"org":payload.organization_id,"n":surplus})
        conn.execute(text("INSERT INTO auth_sessions(token_hash,account_id,organization_id,expires_at,peer,user_agent) VALUES (:token,:account,:org,:expiry,:peer,:ua)"),
          {"token":digest(token),"account":account["id"],"org":payload.organization_id,"expiry":datetime.now(timezone.utc)+timedelta(minutes=30),"peer":peer,"ua":user_agent})
    response.headers["Cache-Control"] = "no-store"
    return {"access_token":token,"token_type":"bearer","expires_in":1800,"mfa_required":account["role"] == "admin" and not enabled}

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

@router.get("/sessions")
def list_sessions(response: Response, identity=Depends(current_identity)):
    # Diagnostic tool for administrators: lists active sessions for the current
    # account without exposing secrets (token_hash truncated to its suffix).
    require_admin_mfa(identity)
    response.headers["Cache-Control"] = "no-store"
    with get_engine().connect() as conn:
        rows = conn.execute(text("""
            SELECT token_hash, organization_id, issued_at, expires_at, peer, user_agent
            FROM auth_sessions WHERE account_id=:account AND expires_at>now()
            ORDER BY issued_at DESC
        """), {"account": identity["account_id"]}).mappings().all()
    return [{"token_suffix": str(r["token_hash"])[-8:],
             "organization_id": str(r["organization_id"]),
             "issued_at": str(r["issued_at"]),
             "expires_at": str(r["expires_at"]),
             "peer": r["peer"],
             "user_agent": r["user_agent"]} for r in rows]

@router.post("/sessions/revoke-others", status_code=204)
def revoke_other_sessions(credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                          identity=Depends(current_identity)):
    require_admin_mfa(identity)
    with get_engine().begin() as conn:
        conn.execute(text("""
            DELETE FROM auth_sessions
            WHERE account_id=:account AND token_hash<>:current AND expires_at>now()
        """), {"account": identity["account_id"], "current": digest(credentials.credentials)})
    return Response(status_code=204, headers={"Cache-Control": "no-store"})

class MFASetup(BaseModel):
    password: str = Field(min_length=1,max_length=256)

class MFAConfirm(MFASetup):
    otp: str = Field(min_length=6,max_length=6)

def lock_and_verify(conn, identity, password):
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text), 360))"), {"id":identity["account_id"]})
    row = conn.execute(text("SELECT password_hash FROM accounts WHERE id=:id AND active"), {"id":identity["account_id"]}).scalar_one_or_none()
    if not row or not verify_password(row,password):
        raise invalid()

@router.post("/mfa/setup")
def setup_mfa(payload: MFASetup, request: Request, response: Response, identity=Depends(current_identity)):
    reserve_login(identity["email"],identity["organization_id"],request.client.host if request.client else "unknown")
    with get_engine().begin() as conn:
        lock_and_verify(conn,identity,payload.password)
        enabled = conn.execute(text("SELECT enabled FROM account_mfa WHERE account_id=:id"), {"id":identity["account_id"]}).scalar_one_or_none()
        if enabled:
            raise HTTPException(status_code=409,detail="MFA already enabled")
        secret = new_secret()
        conn.execute(text("""INSERT INTO account_mfa(account_id,secret_ciphertext,last_step,enabled)
            VALUES (:id,:secret,-1,false) ON CONFLICT(account_id) DO UPDATE SET secret_ciphertext=EXCLUDED.secret_ciphertext,last_step=-1"""),
            {"id":identity["account_id"],"secret":cipher().encrypt(secret.encode()).decode()})
    response.headers["Cache-Control"]="no-store"
    return {"secret":secret}

@router.post("/mfa/confirm")
def confirm_mfa(payload: MFAConfirm, request: Request, response: Response, identity=Depends(current_identity)):
    reserve_login(identity["email"],identity["organization_id"],request.client.host if request.client else "unknown")
    with get_engine().begin() as conn:
        lock_and_verify(conn,identity,payload.password)
        if not consume_code(conn,identity["account_id"],payload.otp,require_enabled=False):
            raise invalid()
        conn.execute(text("UPDATE account_mfa SET enabled=true WHERE account_id=:id"),{"id":identity["account_id"]})
        codes = generate_codes(conn, identity["account_id"])
        conn.execute(text("DELETE FROM auth_sessions WHERE account_id=:id"),{"id":identity["account_id"]})
    response.headers["Cache-Control"]="no-store"
    return {"enabled":True,"reauthenticate":True,"recovery_codes":codes}

@router.post("/mfa/recovery/regenerate")
def regenerate_recovery(payload: MFAConfirm, request: Request, response: Response, identity=Depends(current_identity)):
    reserve_login(identity["email"],identity["organization_id"],request.client.host if request.client else "unknown")
    with get_engine().begin() as conn:
        lock_and_verify(conn,identity,payload.password)
        if not consume_code(conn,identity["account_id"],payload.otp):
            raise invalid()
        codes = generate_codes(conn, identity["account_id"])
    response.headers["Cache-Control"]="no-store"
    return {"recovery_codes":codes}
