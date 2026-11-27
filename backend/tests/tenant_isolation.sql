BEGIN;
INSERT INTO organizations(id,slug,name) VALUES
('11111111-1111-4111-8111-111111111111','rls-test-a','Test A'),
('22222222-2222-4222-8222-222222222222','rls-test-b','Test B');
INSERT INTO tenant_modules(organization_id,module_key,enabled) VALUES
('11111111-1111-4111-8111-111111111111','artists',true),
('22222222-2222-4222-8222-222222222222','artists',false);
SET LOCAL ROLE rights360_runtime;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM organizations) OR EXISTS(SELECT 1 FROM tenant_modules) THEN
  RAISE EXCEPTION 'Missing context leaked data';
 END IF;
END $$;
SELECT set_config('app.tenant_id','11111111-1111-4111-8111-111111111111',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM organizations) <> 1 OR (SELECT count(*) FROM tenant_modules) <> 1 THEN
  RAISE EXCEPTION 'Incorrect tenant visibility';
 END IF;
 IF EXISTS(SELECT 1 FROM organizations WHERE slug='rls-test-b') THEN
  RAISE EXCEPTION 'Cross tenant read';
 END IF;
 UPDATE tenant_modules SET enabled=true WHERE organization_id='22222222-2222-4222-8222-222222222222';
 IF FOUND THEN RAISE EXCEPTION 'Cross tenant update'; END IF;
 BEGIN
  INSERT INTO tenant_modules VALUES ('22222222-2222-4222-8222-222222222222','finance',true);
  RAISE EXCEPTION 'Cross tenant insert';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
SELECT set_config('app.tenant_id','22222222-2222-4222-8222-222222222222',true);
DO $$ BEGIN
 IF (SELECT count(*) FROM organizations WHERE slug='rls-test-b') <> 1 OR EXISTS(SELECT 1 FROM organizations WHERE slug='rls-test-a') THEN
  RAISE EXCEPTION 'Tenant switching failed';
 END IF;
END $$;
ROLLBACK;
