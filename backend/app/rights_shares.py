from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator
from sqlalchemy import text
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/works",tags=["rights declarations"])
Role=Literal["author","composer","publisher","beneficiary","other"]

class Share(BaseModel):
    model_config=ConfigDict(extra="forbid")
    artist_id: UUID
    role: Role
    basis_points: StrictInt=Field(ge=1,le=10000)

class Declaration(BaseModel):
    model_config=ConfigDict(extra="forbid")
    expected_version: StrictInt=Field(ge=0)
    status: Literal["draft","complete"]="draft"
    shares: list[Share]=Field(min_length=1,max_length=100)

    @model_validator(mode="after")
    def validate_total(self):
        keys={(s.artist_id,s.role) for s in self.shares}
        total=sum(s.basis_points for s in self.shares)
        if len(keys)!=len(self.shares):
            raise ValueError("Duplicate artist and role")
        if total>10000 or (self.status=="complete" and total!=10000):
            raise ValueError("Invalid share total")
        return self

def check_work(conn,work_id,lock=False):
    sql="SELECT id FROM works WHERE id=:id"+(" FOR UPDATE" if lock else "")
    if conn.execute(text(sql),{"id":work_id}).scalar_one_or_none() is None:
        raise HTTPException(404,"Work not found")

def read_declarations(conn,work_id):
    declarations=conn.execute(text("""SELECT id,version,status,created_at,created_by
        FROM work_rights_declarations WHERE work_id=:id ORDER BY version DESC LIMIT 100"""),{"id":work_id}).mappings().all()
    results=[]
    for declaration in declarations:
        row=dict(declaration)
        shares=conn.execute(text("""SELECT artist_id,role,basis_points FROM work_rights_shares
            WHERE declaration_id=:id ORDER BY artist_id,role"""),{"id":row["id"]}).mappings().all()
        row["shares"]=[dict(s) for s in shares]
        row["total_basis_points"]=sum(s["basis_points"] for s in shares)
        results.append(row)
    return results

@router.get("/{work_id}/rights")
def history(work_id: UUID,response: Response,identity=Depends(require_permission("works:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"works")
        check_work(conn,work_id)
        rows=read_declarations(conn,work_id)
    response.headers["Cache-Control"]="no-store"
    return rows

@router.post("/{work_id}/rights",status_code=201)
def declare(work_id: UUID,payload: Declaration,response: Response,identity=Depends(require_permission("works:write"))):
    org=identity["organization_id"]
    with tenant_transaction(org) as conn:
        require_enabled_module(conn,"works")
        check_work(conn,work_id,lock=True)
        current=conn.execute(text("SELECT COALESCE(max(version),0) FROM work_rights_declarations WHERE work_id=:id"),{"id":work_id}).scalar_one()
        if current!=payload.expected_version:
            raise HTTPException(409,"Declaration version changed")
        for share in payload.shares:
            if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM artists WHERE id=:id)"),{"id":share.artist_id}).scalar_one():
                raise HTTPException(404,"Rights holder not found")
        declaration_id=uuid4()
        conn.execute(text("""INSERT INTO work_rights_declarations(id,organization_id,work_id,version,status,created_by)
            VALUES(:id,:org,:work,:version,:status,:actor)"""),
            {"id":declaration_id,"org":org,"work":work_id,"version":current+1,"status":payload.status,"actor":identity["account_id"]})
        conn.execute(text("""INSERT INTO work_rights_shares(organization_id,declaration_id,artist_id,role,basis_points)
            VALUES(:org,:declaration,:artist_id,:role,:basis_points)"""),
            [{"org":org,"declaration":declaration_id,**s.model_dump()} for s in payload.shares])
        conn.execute(text("""INSERT INTO audit_events(organization_id,actor_id,action,resource_key,details)
            VALUES(:org,:actor,'rights.declared',:resource,jsonb_build_object('version',CAST(:version AS integer),'status',CAST(:status AS text)))"""),
            {"org":org,"actor":identity["account_id"],"resource":str(work_id),"version":current+1,"status":payload.status})
        result=read_declarations(conn,work_id)[0]
    response.headers["Cache-Control"]="no-store"
    return result
