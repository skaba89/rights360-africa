const assert=require("node:assert/strict");
const {chromium}=require("playwright");
(async()=>{
 const browser=await chromium.launch({headless:true});
 try{
  const context=await browser.newContext({serviceWorkers:"allow"});
  const page=await context.newPage();
  await page.goto("http://127.0.0.1:8500/portal");
  await page.evaluate(()=>navigator.serviceWorker.ready);
  await page.reload();
  await page.waitForFunction(()=>!!navigator.serviceWorker.controller);
  const result=await page.evaluate(async()=>{
   const scope="test-org:test-account",pass="test phrase only 2026";
   const first=await RightsOffline.unlock(scope,pass);
   const stale=await RightsOffline.unlock(scope,pass);
   await RightsOffline.save(first,[{id:"test-1",notes:"private synthetic draft"}]);
   let conflict=false,wrong=false;
   try{await RightsOffline.save(stale,[]);}catch(e){conflict=true;}
   try{await RightsOffline.unlock(scope,"wrong passphrase 2026");}catch(e){wrong=true;}
   const restored=await RightsOffline.unlock(scope,pass);
   const other=await RightsOffline.unlock("other-org:test-account",pass);
   const record=await new Promise((resolve,reject)=>{
    const req=indexedDB.open("rights360-field-v1",1);
    req.onerror=()=>reject(req.error);
    req.onsuccess=()=>{const db=req.result;const tx=db.transaction("vault","readonly");const get=tx.objectStore("vault").get(scope);get.onsuccess=()=>resolve(get.result);tx.oncomplete=()=>db.close();};
   });
   return {conflict,wrong,count:restored.queue.length,other:other.queue.length,encrypted:record.cipher instanceof ArrayBuffer&&!JSON.stringify(record).includes("private synthetic draft")};
  });
  assert.deepEqual(result,{conflict:true,wrong:true,count:1,other:0,encrypted:true});
  await context.setOffline(true);
  await page.reload();
  assert.equal(await page.locator("title").textContent(),"Connexion | Rights360 Africa");
  const offline=await page.evaluate(async()=>{
   let apiAvailable=false;
   try{await fetch("/api/v1/field-visits");apiAvailable=true;}catch(e){}
   const recovered=await RightsOffline.unlock("test-org:test-account","test phrase only 2026");
   return {apiAvailable,count:recovered.queue.length};
  });
  assert.deepEqual(offline,{apiAvailable:false,count:1});
  await context.setOffline(false);
  await context.close();
  console.log("Offline browser checks PASS");
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
