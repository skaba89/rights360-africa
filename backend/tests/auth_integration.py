import os
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.auth import hasher
from app.db import get_engine
from app.main import app

def main():
    admin = get_engine(migration=True)
    org_a, org_b, account = uuid4(), uuid4(), uuid4()
    email = f"{account}@example.invalid"
    password = "integration-test-password"
    with admin.begin() as conn:
        for org in (org_a, org_b):
            conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Integration test')"), {"id":org,"slug":str(org)})
        conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"), {"id":account,"email":email,"hash":hasher.hash(password)})
        conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"), {"id":account,"org":org_a})
    try:
        with TestClient(app) as client:
            payload = {"email":email,"password":password,"organization_id":str(org_a)}
            assert client.post("/api/v1/auth/login",json={**payload,"password":"wrong"}).status_code == 401
            assert client.post("/api/v1/auth/login",json={**payload,"organization_id":str(org_b)}).status_code == 401
            response = client.post("/api/v1/auth/login",json=payload)
            assert response.status_code == 200, response.text
            headers = {"Authorization":"Bearer "+response.json()["access_token"]}
            identity = client.get("/api/v1/auth/me",headers=headers)
            assert identity.status_code == 200
            assert identity.json()["organization_id"] == str(org_a)
            assert response.json()["mfa_required"] is True
            assert identity.json()["mfa_required"] is True
            assert client.get("/api/v1/organization",headers=headers).status_code == 403
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 403
            # Enroll this administrator before exercising privileged operations.
            import pyotp
            import time
            setup_admin = client.post("/api/v1/auth/mfa/setup",headers=headers,json={"password":password})
            assert setup_admin.status_code == 200
            admin_totp = pyotp.TOTP(setup_admin.json()["secret"])
            admin_step = int(time.time() // 30)
            confirmed_admin = client.post("/api/v1/auth/mfa/confirm",headers=headers,json={"password":password,"otp":admin_totp.at((admin_step-1)*30)})
            assert confirmed_admin.status_code == 200
            admin_codes = confirmed_admin.json()["recovery_codes"]
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
            response = client.post("/api/v1/auth/login",json={**payload,"otp":admin_totp.at(admin_step*30)})
            assert response.status_code == 200
            assert response.json()["mfa_required"] is False
            headers = {"Authorization":"Bearer "+response.json()["access_token"]}
            assert client.get("/api/v1/organization",headers=headers).json()["id"] == str(org_a)
            assert client.get("/api/v1/platform/me",headers=headers).status_code == 403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO platform_admins(account_id,organization_id) VALUES (:id,:org)"), {"id":account,"org":org_a})
            platform = client.get("/api/v1/platform/me",headers=headers)
            assert platform.status_code == 200
            assert platform.json()["platform_role"] == "super_admin"
            entitlement_url=f"/api/v1/platform/organizations/{org_a}/entitlements"
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 403
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True,"expires_at":"2000-01-01T00:00:00Z"}).status_code == 422
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True}).status_code == 200
            assert client.get(entitlement_url,headers=headers).json()[0]["granted"] is True
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":False}).status_code == 200
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 403
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True}).status_code == 200
            slug = "test-" + str(uuid4())
            created = client.post("/api/v1/platform/organizations",headers=headers,json={"slug":slug,"name":"Test client"})
            assert created.status_code == 201, created.text
            created_id = created.json()["id"]
            invited_email = f"{uuid4()}@example.invalid"
            try:
                assert client.post("/api/v1/platform/organizations",headers=headers,json={"slug":slug,"name":"Duplicate"}).status_code == 409
                listing = client.get("/api/v1/platform/organizations",headers=headers)
                assert listing.status_code == 200
                assert any(item["id"] == created_id for item in listing.json())
                assert client.patch(f"/api/v1/platform/organizations/{org_a}/status",headers=headers,json={"active":False}).status_code == 409
                assert client.patch(f"/api/v1/platform/organizations/{created_id}/status",headers=headers,json={"active":False}).status_code == 200
                assert client.patch(f"/api/v1/platform/organizations/{created_id}/status",headers=headers,json={"active":True}).status_code == 200
                with admin.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM platform_audit_events WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id}).scalar_one() == 3
                with get_engine().connect() as conn:
                    assert conn.execute(text("SELECT count(*) FROM organizations WHERE id=CAST(:id AS uuid)"), {"id":created_id}).scalar_one() == 0
                url = f"/api/v1/platform/organizations/{created_id}/invitations"
                first = client.post(url,headers=headers,json={"email":invited_email})
                assert first.status_code == 201, first.text
                second = client.post(url,headers=headers,json={"email":invited_email})
                assert second.status_code == 201, second.text
                accept_url = "/api/v1/auth/invitations/accept"
                assert client.post(accept_url,json={"token":first.json()["token"],"password":password}).status_code == 400
                invited = client.post(accept_url,json={"token":second.json()["token"],"password":password})
                assert invited.status_code == 201, invited.text
                assert invited.json()["organization_id"] == created_id
                assert client.post(accept_url,json={"token":second.json()["token"],"password":password}).status_code == 400
                login_new = client.post("/api/v1/auth/login",json={"email":invited_email,"password":password,"organization_id":created_id})
                assert login_new.status_code == 200
                assert login_new.json()["mfa_required"] is True
                new_headers = {"Authorization":"Bearer "+login_new.json()["access_token"]}
                assert client.get("/api/v1/platform/me",headers=new_headers).status_code == 403
                assert client.get("/api/v1/organization",headers=new_headers).status_code == 403
                assert client.patch(f"/api/v1/platform/organizations/{created_id}/status",headers=headers,json={"active":False}).status_code == 200
                assert client.get("/api/v1/auth/me",headers=new_headers).status_code == 401
            finally:
                with admin.begin() as conn:
                    conn.execute(text("DELETE FROM customer_invitations WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id})
                    conn.execute(text("DELETE FROM memberships WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id})
                    conn.execute(text("DELETE FROM accounts WHERE email=:email"), {"email":invited_email})
                    conn.execute(text("DELETE FROM platform_audit_events WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id})
                    conn.execute(text("DELETE FROM organizations WHERE id=CAST(:id AS uuid)"), {"id":created_id})
            with admin.begin() as conn:
                conn.execute(text("UPDATE platform_admins SET active=false WHERE account_id=:id"), {"id":account})
            assert client.get("/api/v1/platform/me",headers=headers).status_code == 403
            assert client.get("/api/v1/platform/organizations",headers=headers).status_code == 403
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True}).status_code == 403
            invite_email = f"{uuid4()}@example.invalid"
            invite_url = "/api/v1/organization/invitations"
            accept_url = "/api/v1/auth/member-invitations/accept"
            try:
                assert client.post(invite_url,headers=headers,json={"email":invite_email,"role":"admin"}).status_code == 422
                first = client.post(invite_url,headers=headers,json={"email":invite_email,"role":"artist"})
                assert first.status_code == 201, first.text
                assert client.delete(invite_url+"/"+first.json()["id"],headers=headers).status_code == 204
                assert client.post(accept_url,json={"token":first.json()["token"],"password":password}).status_code == 400
                second = client.post(invite_url,headers=headers,json={"email":invite_email,"role":"manager"})
                assert second.status_code == 201, second.text
                third = client.post(invite_url,headers=headers,json={"email":invite_email,"role":"auditor"})
                assert third.status_code == 201, third.text
                assert client.post(accept_url,json={"token":second.json()["token"],"password":password}).status_code == 400
                accepted = client.post(accept_url,json={"token":third.json()["token"],"password":password})
                assert accepted.status_code == 201, accepted.text
                assert accepted.json()["organization_id"] == str(org_a)
                assert client.post(accept_url,json={"token":third.json()["token"],"password":password}).status_code == 400
                logged = client.post("/api/v1/auth/login",json={"email":invite_email,"password":password,"organization_id":str(org_a)})
                assert logged.status_code == 200
                invited_headers = {"Authorization":"Bearer "+logged.json()["access_token"]}
                assert client.get("/api/v1/auth/me",headers=invited_headers).json()["role"] == "auditor"
                assert client.post(invite_url,headers=invited_headers,json={"email":f"{uuid4()}@example.invalid","role":"artist"}).status_code == 403
                assert client.post(invite_url,headers=headers,json={"email":invite_email,"role":"artist"}).status_code == 409
            finally:
                with admin.begin() as conn:
                    conn.execute(text("DELETE FROM member_invitations WHERE organization_id=:org"),{"org":org_a})
                    conn.execute(text("DELETE FROM memberships WHERE account_id IN (SELECT id FROM accounts WHERE email=:email)"),{"email":invite_email})
                    conn.execute(text("DELETE FROM accounts WHERE email=:email"),{"email":invite_email})
            collaborator, outside = uuid4(), uuid4()
            with admin.begin() as conn:
                for member_id, org in ((collaborator,org_a),(outside,org_b)):
                    conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"), {"id":member_id,"email":f"{member_id}@example.invalid","hash":hasher.hash(password)})
                    conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'artist')"), {"id":member_id,"org":org})
            try:
                members_url = "/api/v1/organization/members"
                members = client.get(members_url,headers=headers)
                assert members.status_code == 200, members.text
                assert str(collaborator) in [row["account_id"] for row in members.json()]
                assert str(outside) not in [row["account_id"] for row in members.json()]
                change = {"role":"manager","active":False}
                assert client.patch(f"{members_url}/{outside}",headers=headers,json=change).status_code == 404
                assert client.patch(f"{members_url}/{account}",headers=headers,json=change).status_code == 403
                assert client.patch(f"{members_url}/{collaborator}",headers=headers,json={"role":"admin","active":True}).status_code == 422
                member_login = {"email":f"{collaborator}@example.invalid","password":password,"organization_id":str(org_a)}
                logged_member = client.post("/api/v1/auth/login",json=member_login)
                assert logged_member.status_code == 200
                member_headers = {"Authorization":"Bearer "+logged_member.json()["access_token"]}
                assert client.get(members_url,headers=member_headers).status_code == 403
                assert client.patch(f"{members_url}/{collaborator}",headers=headers,json=change).status_code == 200
                assert client.get("/api/v1/auth/me",headers=member_headers).status_code == 401
                assert client.post("/api/v1/auth/login",json=member_login).status_code == 401
                assert client.patch(f"{members_url}/{collaborator}",headers=headers,json={"role":"auditor","active":True}).status_code == 200
                assert client.get("/api/v1/auth/me",headers=member_headers).status_code == 401
                logged_member = client.post("/api/v1/auth/login",json=member_login)
                assert logged_member.status_code == 200
                member_headers = {"Authorization":"Bearer "+logged_member.json()["access_token"]}
                assert client.get("/api/v1/auth/me",headers=member_headers).json()["role"] == "auditor"
                with admin.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM audit_events WHERE organization_id=:org AND action='member.updated'"),{"org":org_a}).scalar_one() == 2
            finally:
                with admin.begin() as conn:
                    for member_id in (collaborator,outside):
                        conn.execute(text("DELETE FROM memberships WHERE account_id=:id"),{"id":member_id})
                        conn.execute(text("DELETE FROM accounts WHERE id=:id"),{"id":member_id})
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 200
            assert client.put("/api/v1/organization/modules/unknown",headers=headers,json={"enabled":True}).status_code == 404
            assert next(m for m in client.get("/api/v1/organization/modules",headers=headers).json() if m["module_key"]=="artists")["enabled"] is True
            artist_url="/api/v1/artists"
            artist_data={"member_number":"test-001","legal_name":"Integration Artist","status":"active"}
            created_artist=client.post(artist_url,headers=headers,json=artist_data)
            assert created_artist.status_code == 201, created_artist.text
            artist_id=created_artist.json()["id"]
            assert created_artist.json()["member_number"] == "TEST-001"
            assert client.post(artist_url,headers=headers,json=artist_data).status_code == 409
            assert client.get(artist_url,headers=headers,params={"q":"Integration","status":"active"}).json()[0]["id"] == artist_id
            assert client.get(artist_url+"/"+artist_id,headers=headers).status_code == 200
            assert client.put(artist_url+"/"+artist_id,headers=headers,json={**artist_data,"status":"archived"}).status_code == 200
            foreign_id=uuid4()
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO artists(id,organization_id,member_number,legal_name) VALUES (:id,:org,'TEST-001','Outside')"),{"id":foreign_id,"org":org_b})
            assert client.get(artist_url+"/"+str(foreign_id),headers=headers).status_code == 404
            assert client.put(artist_url+"/"+str(foreign_id),headers=headers,json=artist_data).status_code == 404
            assert client.get(artist_url,headers=headers).json()[0]["id"] == artist_id
            work_url="/api/v1/works"
            work_data={"reference":"work-001","title":"Integration Work","category":"music","primary_artist_id":artist_id}
            assert client.get(work_url,headers=headers).status_code == 403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'works',true)"),{"org":org_a})
            assert client.put("/api/v1/organization/modules/works",headers=headers,json={"enabled":True}).status_code == 200
            work=client.post(work_url,headers=headers,json=work_data)
            assert work.status_code == 201, work.text
            work_id=work.json()["id"]
            assert work.json()["reference"]=="WORK-001"
            assert client.post(work_url,headers=headers,json=work_data).status_code == 409
            assert client.post(work_url,headers=headers,json={**work_data,"reference":"outside","primary_artist_id":str(foreign_id)}).status_code == 404
            assert client.get(work_url,headers=headers,params={"q":"Integration","category":"music"}).json()[0]["id"] == work_id
            assert client.put(work_url+"/"+work_id,headers=headers,json={**work_data,"status":"registered"}).status_code == 200
            assert client.get(work_url+"/"+work_id,headers=headers).json()["status"] == "registered"
            rights_url=work_url+"/"+work_id+"/rights"
            share={"artist_id":artist_id,"role":"author","basis_points":6000}
            other={"artist_id":artist_id,"role":"composer","basis_points":4000}
            assert client.post(rights_url,headers=headers,json={"expected_version":0,"status":"complete","shares":[share]}).status_code == 422
            assert client.post(rights_url,headers=headers,json={"expected_version":0,"shares":[{**share,"artist_id":str(foreign_id)}]}).status_code == 404
            declaration=client.post(rights_url,headers=headers,json={"expected_version":0,"status":"complete","shares":[share,other]})
            assert declaration.status_code == 201, declaration.text
            assert declaration.json()["total_basis_points"] == 10000
            assert client.post(rights_url,headers=headers,json={"expected_version":0,"shares":[share]}).status_code == 409
            assert client.post(rights_url,headers=headers,json={"expected_version":1,"shares":[share]}).status_code == 201
            history=client.get(rights_url,headers=headers).json()
            assert [row["version"] for row in history] == [2,1]
            assert history[1]["total_basis_points"] == 10000
            assert client.get("/api/v1/operators",headers=headers).status_code == 403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'licenses',true)"),{"org":org_a})
            assert client.put("/api/v1/organization/modules/licenses",headers=headers,json={"enabled":True}).status_code == 200
            operator=client.post("/api/v1/operators",headers=headers,json={"reference":"radio-1","name":"Test radio","category":"radio"})
            assert operator.status_code == 201, operator.text
            operator_id=operator.json()["id"]
            assert client.post("/api/v1/operators",headers=headers,json={"reference":"radio-1","name":"Duplicate","category":"radio"}).status_code == 409
            foreign_operator=uuid4()
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO operators(id,organization_id,reference,name,category) VALUES (:id,:org,'RADIO-1','Outside','radio')"),{"id":foreign_operator,"org":org_b})
            license_data={"reference":"lic-1","operator_id":operator_id,"work_id":work_id,"territory":"Guinee","usage_type":"broadcast","starts_on":"2020-01-01","ends_on":"2099-12-31"}
            lic_url="/api/v1/exploitation-licenses"
            assert client.post(lic_url,headers=headers,json={**license_data,"operator_id":str(foreign_operator)}).status_code == 404
            assert client.post(lic_url,headers=headers,json={**license_data,"ends_on":"2019-01-01"}).status_code == 422
            lic=client.post(lic_url,headers=headers,json=license_data)
            assert lic.status_code == 201, lic.text
            assert lic.json()["status"]=="draft"
            status_url=lic_url+"/"+lic.json()["id"]+"/status"
            assert client.patch(status_url,headers=headers,json={"status":"active"}).status_code == 200
            assert client.get(lic_url,headers=headers).json()[0]["effective"] is True
            tariff_data={"reference":"radio-rate","expected_version":0,"category":"radio","usage_type":"broadcast","method":"revenue","currency":"GNF","rate":500,"starts_on":"2020-01-01","ends_on":"2099-12-31"}
            tariff=client.post("/api/v1/tariffs",headers=headers,json=tariff_data)
            assert tariff.status_code == 201, tariff.text
            tariff_id=tariff.json()["id"]
            assert client.post("/api/v1/tariffs",headers=headers,json=tariff_data).status_code == 409
            quote_url="/api/v1/tariffs/"+tariff_id+"/quote"
            quote_data={"license_id":lic.json()["id"],"usage_date":"2026-01-01","revenue_minor":1000000}
            estimate=client.post(quote_url,headers=headers,json=quote_data)
            assert estimate.status_code == 200, estimate.text
            assert estimate.json()["amount_minor"]=="50000"
            assert client.post(quote_url,headers=headers,json={**quote_data,"usage_date":"2100-01-01"}).status_code == 409
            assert client.post("/api/v1/tariffs",headers=headers,json={**tariff_data,"expected_version":1,"rate":600}).status_code == 201
            assert client.post(quote_url,headers=headers,json=quote_data).json()["amount_minor"]=="50000"
            invoice_url="/api/v1/invoices"
            assert client.get(invoice_url,headers=headers).status_code == 403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'finance',true)"),{"org":org_a})
            assert client.put("/api/v1/organization/modules/finance",headers=headers,json={"enabled":True}).status_code == 200
            invoice_data={**quote_data,"tariff_id":tariff_id,"reference":"inv-1","due_on":"2099-12-31"}
            invoice=client.post(invoice_url,headers=headers,json=invoice_data)
            assert invoice.status_code == 201, invoice.text
            assert invoice.json()["amount_minor"]=="50000"
            assert client.post(invoice_url,headers=headers,json={**invoice_data,"reference":"inv-2"}).status_code == 409
            receipts_url=invoice_url+"/"+invoice.json()["id"]+"/receipts"
            receipt={"reference":"pay-1","amount_minor":20000,"received_on":"2026-01-01"}
            assert client.post(receipts_url,headers=headers,json=receipt).status_code == 201
            assert client.post(receipts_url,headers=headers,json=receipt).status_code == 409
            assert client.get(invoice_url,headers=headers).json()[0]["status"]=="partial"
            assert client.post(receipts_url,headers=headers,json={**receipt,"reference":"pay-2","amount_minor":30001}).status_code == 409
            assert client.post(receipts_url,headers=headers,json={**receipt,"reference":"pay-2","amount_minor":30000}).status_code == 201
            assert client.get(invoice_url,headers=headers).json()[0]["status"]=="paid"
            assert len(client.get(receipts_url,headers=headers).json())==2
            dist_url="/api/v1/distributions"
            assert client.get(dist_url,headers=headers).status_code == 403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'royalties',true)"),{"org":org_a})
            assert client.put("/api/v1/organization/modules/royalties",headers=headers,json={"enabled":True}).status_code == 200
            receipt_id=client.get(receipts_url,headers=headers).json()[0]["id"]
            dist_data={"receipt_id":receipt_id,"declaration_id":history[1]["id"],"commission_bps":1000}
            assert client.post(dist_url,headers=headers,json={**dist_data,"declaration_id":history[0]["id"]}).status_code == 409
            dist=client.post(dist_url,headers=headers,json=dist_data)
            assert dist.status_code == 201, dist.text
            assert int(dist.json()["gross_minor"])==int(dist.json()["commission_minor"])+int(dist.json()["net_minor"])
            assert sum(int(line["amount_minor"]) for line in dist.json()["lines"])==int(dist.json()["net_minor"])
            assert client.post(dist_url,headers=headers,json=dist_data).status_code == 409
            assert len(client.get(dist_url+"/"+dist.json()["id"]+"/lines",headers=headers).json())==2
            accounting_url="/api/v1/accounting/entries"
            posting={"source_type":"distribution","source_id":dist.json()["id"]}
            assert client.post(accounting_url,headers=headers,json=posting).status_code==409
            for kind,source in (("invoice",invoice.json()["id"]),("receipt",receipt_id),("distribution",dist.json()["id"])):
                entry=client.post(accounting_url,headers=headers,json={"source_type":kind,"source_id":source})
                assert entry.status_code==201,entry.text
                lines=entry.json()["lines"]
                assert sum(int(x["debit_minor"]) for x in lines)==sum(int(x["credit_minor"]) for x in lines)
                assert client.post(accounting_url,headers=headers,json={"source_type":kind,"source_id":source}).status_code==409
            assert len(client.get(accounting_url,headers=headers).json())==3
            balances=client.get("/api/v1/accounting/balances",headers=headers).json()
            assert sum(int(x["balance_minor"]) for x in balances)==0
            payout_url="/api/v1/payouts"
            payout_artist=dist.json()["lines"][0]["artist_id"]
            with admin.begin() as conn:
                conn.execute(text("UPDATE artists SET status='active' WHERE id=:id"),{"id":payout_artist})
            payout_data={"distribution_id":dist.json()["id"],"artist_id":payout_artist,"channel":"orange_money"}
            payout=client.post(payout_url,headers=headers,json=payout_data)
            assert payout.status_code==201,payout.text
            assert payout.json()["execution_enabled"] is False
            assert client.post(payout_url,headers=headers,json=payout_data).status_code==409
            review_url=payout_url+"/"+payout.json()["id"]+"/reviews"
            assert client.post(review_url,headers=headers,json={"decision":"approve"}).status_code==409
            assert client.get(payout_url,headers=headers).json()[0]["status"]=="pending"
            field_url="/api/v1/field-visits"
            assert client.get(field_url,headers=headers).status_code==403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'field_control',true)"),{"org":org_a})
            assert client.put("/api/v1/organization/modules/field_control",headers=headers,json={"enabled":True}).status_code==200
            visit_data={"id":str(uuid4()),"operator_id":operator_id,"visited_at":"2026-01-01T10:00:00Z","latitude_e6":9500000,"longitude_e6":-13700000,"finding":"observed","notes":"Test visit"}
            assert client.post(field_url,headers=headers,json={**visit_data,"operator_id":str(foreign_operator)}).status_code==404
            visit=client.post(field_url,headers=headers,json=visit_data)
            assert visit.status_code==201,visit.text
            assert visit.json()["license_snapshot"]["historical_status_verified"] is False
            assert client.post(field_url,headers=headers,json=visit_data).status_code==200
            assert client.post(field_url,headers=headers,json={**visit_data,"notes":"Changed"}).status_code==409
            assert len(client.get(field_url,headers=headers).json())==1
            assert client.get(field_url+"/operators",headers=headers).json()[0]["id"]==operator_id
            media_url="/api/v1/media-observations"
            assert client.get(media_url,headers=headers).status_code==403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'media',true)"),{"org":org_a})
            assert client.put("/api/v1/organization/modules/media",headers=headers,json={"enabled":True}).status_code==200
            media_data={"operator_id":operator_id,"external_reference":"broadcast-001","aired_at":"2026-01-01T10:00:00Z","duration_seconds":180,"reported_title":work.json()["title"],"reported_artist":"Test artist"}
            assert client.post(media_url,headers=headers,json={**media_data,"operator_id":str(foreign_operator)}).status_code==404
            observed=client.post(media_url,headers=headers,json=media_data)
            assert observed.status_code==201,observed.text
            assert client.post(media_url,headers=headers,json=media_data).status_code==409
            observation_url=media_url+"/"+observed.json()["id"]
            candidates=client.get(observation_url+"/candidates",headers=headers).json()
            assert candidates["verified_audio"] is False
            assert work_id in [row["id"] for row in candidates["candidates"]]
            assert client.post(observation_url+"/review",headers=headers,json={"decision":"matched","work_id":work_id}).status_code==201
            assert client.post(observation_url+"/review",headers=headers,json={"decision":"unmatched"}).status_code==409
            assert client.get(media_url,headers=headers).json()[0]["status"]=="matched"
            analytics_url="/api/v1/analytics/summary"
            assert client.get(analytics_url,headers=headers).status_code==403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'analytics',true)"),{"org":org_a})
            assert client.put("/api/v1/organization/modules/analytics",headers=headers,json={"enabled":True}).status_code==200
            summary=client.get(analytics_url,headers=headers)
            assert summary.status_code==200,summary.text
            sections=summary.json()["sections"]
            assert sections["artists"]["total"]==1
            assert sections["works"]["registered"]==1
            assert sections["licenses"]["operators"]==1
            assert sections["finance"]["currencies"][0]["billed_minor"]=="50000"
            assert sections["finance"]["currencies"][0]["received_minor"]=="50000"
            assert sections["finance"]["currencies"][0]["outstanding_minor"]=="0"
            assert sections["media"]["matched"]==1
            assert sections["field_control"]["visits"]==1
            assert client.put("/api/v1/organization/modules/media",headers=headers,json={"enabled":False}).status_code==200
            assert "media" not in client.get(analytics_url,headers=headers).json()["sections"]








            assert client.patch(status_url,headers=headers,json={"status":"revoked"}).status_code == 200
            assert client.post(quote_url,headers=headers,json=quote_data).status_code == 409
            assert client.patch(status_url,headers=headers,json={"status":"active"}).status_code == 409


            with admin.begin() as conn:
                conn.execute(text("UPDATE module_entitlements SET granted=false WHERE organization_id=:org AND module_key='works'"),{"org":org_a})
            assert client.get(work_url,headers=headers).status_code == 403


            with admin.begin() as conn:
                conn.execute(text("UPDATE module_entitlements SET expires_at=now()-interval '1 second' WHERE organization_id=:org"),{"org":org_a})
            assert next(m for m in client.get("/api/v1/organization/modules",headers=headers).json() if m["module_key"]=="artists")["enabled"] is False
            assert client.get("/api/v1/artists",headers=headers).status_code == 403
            with admin.begin() as conn:
                assert conn.execute(text("SELECT count(*) FROM audit_events WHERE organization_id=:org AND action='module.updated' AND resource_key='artists'"), {"org":org_a}).scalar_one() == 1
                conn.execute(text("UPDATE memberships SET role='auditor' WHERE account_id=:id"), {"id":account})
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":False}).status_code == 403
            assert client.post("/api/v1/auth/logout",headers=headers).status_code == 204
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
            response = client.post("/api/v1/auth/login",json={**payload,"recovery_code":admin_codes[0]})
            assert response.status_code == 200
            headers = {"Authorization":"Bearer "+response.json()["access_token"]}
            with admin.begin() as conn:
                conn.execute(text("UPDATE memberships SET active=false WHERE account_id=:id"), {"id":account})
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
            # Exercise MFA with a separate account to isolate rate limits.
            mfa_account = uuid4()
            mfa_email = f"{mfa_account}@example.invalid"
            import pyotp
            import time
            from app.mfa import cipher
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"), {"id":mfa_account,"email":mfa_email,"hash":hasher.hash(password)})
                conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"), {"id":mfa_account,"org":org_a})
            try:
                mfa_payload = {"email":mfa_email,"password":password,"organization_id":str(org_a)}
                logged = client.post("/api/v1/auth/login",json=mfa_payload)
                assert logged.status_code == 200
                mfa_headers = {"Authorization":"Bearer "+logged.json()["access_token"]}
                setup = client.post("/api/v1/auth/mfa/setup",headers=mfa_headers,json={"password":password})
                assert setup.status_code == 200
                secret = setup.json()["secret"]
                with admin.begin() as conn:
                    encrypted = conn.execute(text("SELECT secret_ciphertext FROM account_mfa WHERE account_id=:id"), {"id":mfa_account}).scalar_one()
                    assert encrypted != secret
                    assert cipher().decrypt(encrypted.encode()).decode() == secret
                totp = pyotp.TOTP(secret)
                step = int(time.time() // 30)
                confirmed = client.post("/api/v1/auth/mfa/confirm",headers=mfa_headers,json={"password":password,"otp":totp.at((step-1)*30)})
                assert confirmed.status_code == 200, confirmed.text
                codes = confirmed.json()["recovery_codes"]
                assert len(set(codes)) == 10
                assert client.get("/api/v1/auth/me",headers=mfa_headers).status_code == 401
                assert client.post("/api/v1/auth/login",json=mfa_payload).status_code == 401
                code = totp.at(step*30)
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"otp":code}).status_code == 200
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"otp":code}).status_code == 401
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"recovery_code":codes[0]}).status_code == 200
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"recovery_code":codes[0]}).status_code == 401
            finally:
                with admin.begin() as conn:
                    conn.execute(text("DELETE FROM memberships WHERE account_id=:id"), {"id":mfa_account})
                    conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id":mfa_account})
                    from app.login_limits import bucket_key
                    conn.execute(text("DELETE FROM login_buckets WHERE bucket=:key"), {"key":bucket_key("account",mfa_email)})
            # Seed the current window at its threshold to avoid clock-boundary flakiness.
            from app.login_limits import bucket_key
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO login_buckets VALUES (:key,date_trunc('minute',now()),10) ON CONFLICT (bucket) DO UPDATE SET attempts=10,window_start=EXCLUDED.window_start"), {"key":bucket_key("account",email)})
            blocked = client.post("/api/v1/auth/login",json=payload)
            assert blocked.status_code == 429
            assert blocked.headers["Retry-After"] == "60"
    finally:
        with admin.begin() as conn:
            from app.login_limits import bucket_key
            conn.execute(text("DELETE FROM login_buckets WHERE bucket IN (:account,:peer)"), {"account":bucket_key("account",email),"peer":bucket_key("peer","testclient")})
            conn.execute(text("DELETE FROM audit_events WHERE organization_id=:org"), {"org":org_a})
            conn.execute(text("DELETE FROM payout_reviews WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM payout_orders WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM accounting_lines WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM accounting_entries WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM royalty_distribution_lines WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM royalty_distributions WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM royalty_receipts WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM royalty_invoices WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM tariffs WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM exploitation_licenses WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM media_reviews WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM media_observations WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM field_visits WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM operators WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM work_rights_shares WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM work_rights_declarations WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM works WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM artists WHERE organization_id IN (:a,:b)"),{"a":org_a,"b":org_b})
            conn.execute(text("DELETE FROM module_entitlements WHERE organization_id=:org"),{"org":org_a})
            conn.execute(text("DELETE FROM platform_audit_events WHERE organization_id=:org"),{"org":org_a})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org"), {"org":org_a})
            conn.execute(text("DELETE FROM memberships WHERE account_id=:id"), {"id":account})
            conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id":account})
            conn.execute(text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a":org_a,"b":org_b})

if __name__ == "__main__":
    main()
