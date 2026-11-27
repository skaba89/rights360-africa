"use strict";
(() => {
  const el = id => document.getElementById(id);
  const views = ["login","invite","mfa","recovery","session","platform"];
  let token = null, timer = null, busy = false, selected = null, offset = 0, organizations = [];
  function notice(message="",error=false){el("notice").textContent=message;el("notice").classList.toggle("error",error);}
  function show(view){views.forEach(v=>{el(v+"-view").hidden=v!==view;});notice();}
  function clearSession(){resetPlatform();token=null;clearTimeout(timer);timer=null;el("secret").textContent="";el("recovery").textContent="";el("saved").checked=false;el("finish").disabled=true;el("confirm-form").hidden=true;el("setup-form").hidden=false;document.querySelectorAll("form").forEach(f=>f.reset());}
  async function api(path,method="GET",data,authorized=false){
    const headers={Accept:"application/json"};
    if(data!==undefined)headers["Content-Type"]="application/json";
    if(authorized&&token)headers.Authorization="Bearer "+token;
    const response=await fetch(path,{method,headers,body:data===undefined?undefined:JSON.stringify(data),cache:"no-store",credentials:"omit",redirect:"error"});
    if(!response.ok){const messages={400:"Invitation invalide ou expirée.",401:"Identifiants, code de sécurité ou session invalides.",403:"Accès refusé.",409:"Cette opération est déjà effectuée ou incompatible.",422:"Vérifiez les informations saisies.",429:"Trop de tentatives. Réessayez dans une minute."};const error=new Error(messages[response.status]||"Service indisponible. Réessayez ultérieurement.");error.status=response.status;throw error;}
    return response.status===204?null:response.json();
  }
  function action(form,handler){el(form).addEventListener("submit",async e=>{e.preventDefault();if(busy)return;busy=true;const button=e.currentTarget.querySelector("button[type=submit]");button.disabled=true;notice();try{await handler();}catch(err){notice(err.message||"Erreur de connexion.",true);}finally{busy=false;button.disabled=false;e.target.querySelectorAll('input[type="password"],input[autocomplete="one-time-code"]').forEach(i=>i.value="");}});}
  action("login-form",async()=>{
    const data={organization_id:el("org").value.trim(),email:el("email").value.trim(),password:el("password").value};
    if(el("code").value.trim())data[el("factor").value]=el("code").value.trim();
    const result=await api("/api/v1/auth/login","POST",data);token=result.access_token;
    clearTimeout(timer);timer=setTimeout(()=>{clearSession();show("login");notice("Session expirée. Reconnectez-vous.",true);},result.expires_in*1000);
    try{const me=await api("/api/v1/auth/me","GET",undefined,true);
      if(me.mfa_required){show("mfa");return;}
      el("session-email").textContent=me.email;el("session-org").textContent=me.organization_id;el("session-role").textContent=({admin:"Administrateur",manager:"Gestionnaire",auditor:"Auditeur",artist:"Artiste"})[me.role]||me.role;el("session-mfa").textContent=me.mfa_enabled?"Activé":"Non activé";el("enable-mfa").hidden=me.mfa_enabled;el("open-platform").hidden=true;show("session");if(me.role==="admin"&&me.mfa_enabled){try{await api("/api/v1/platform/me","GET",undefined,true);if(token)el("open-platform").hidden=false;}catch(err){if(err.status!==403)notice("Vérification de l’accès DSIG indisponible.",true);}}
    }catch(err){clearSession();show("login");throw err;}
  });
  action("invite-form",async()=>{const result=await api("/api/v1/auth/"+el("invite-kind").value+"/accept","POST",{token:el("invite-token").value,password:el("invite-password").value});show("login");el("org").value=result.organization_id;notice("Compte activé. Connectez-vous avec votre email et votre nouveau mot de passe.");});
  action("setup-form",async()=>{const result=await api("/api/v1/auth/mfa/setup","POST",{password:el("setup-password").value},true);el("secret").textContent=result.secret;el("setup-form").hidden=true;el("confirm-form").hidden=false;});
  action("confirm-form",async()=>{const result=await api("/api/v1/auth/mfa/confirm","POST",{password:el("confirm-password").value,otp:el("otp").value},true);token=null;clearTimeout(timer);el("secret").textContent="";el("recovery").textContent=result.recovery_codes.join("\n");show("recovery");});

  const modules={artists:"Artistes",works:"Œuvres",licenses:"Licences",royalties:"Répartition",finance:"Finance",field_control:"Contrôle terrain",media:"Média",analytics:"Analyse",legal:"Juridique",documents:"Documents"};
  const base="/api/v1/platform/organizations";
  for(const [key,label] of Object.entries(modules)){const option=document.createElement("option");option.value=key;option.textContent=label;el("module-key").append(option);}
  function hideInvitation(){el("invitation-token").textContent="";el("invitation-result").hidden=true;}
  function resetPlatform(){selected=null;offset=0;organizations=[];el("org-list").replaceChildren();el("entitlement-list").replaceChildren();el("org-detail").hidden=true;el("open-platform").hidden=true;hideInvitation();}
  function renderOrganizations(){
    const list=el("org-list");list.replaceChildren();
    if(!organizations.length){const p=document.createElement("p");p.textContent="Aucune organisation sur cette page.";list.append(p);}
    for(const org of organizations){const button=document.createElement("button");button.type="button";button.className="org-row";button.textContent=org.name+" · "+org.slug+" · "+(org.active?"Active":"Suspendue");button.addEventListener("click",()=>run(()=>selectOrganization(org)));list.append(button);}
    el("prev-orgs").disabled=offset===0;el("next-orgs").disabled=organizations.length<20;el("org-page").textContent="Page "+(offset/20+1);
  }
  async function loadOrganizations(nextOffset=offset){
    const rows=await api(base+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    organizations=rows;offset=nextOffset;renderOrganizations();
  }
  async function loadEntitlements(){
    const org=selected;if(!org)return;
    const rows=await api(base+"/"+org.id+"/entitlements","GET",undefined,true);
    if(!token||selected!==org)return;
    const byKey=new Map(rows.map(row=>[row.module_key,row]));
    el("entitlement-list").replaceChildren();
    for(const [key,label] of Object.entries(modules)){
      const row=byKey.get(key);const item=document.createElement("p");const expired=row?.expires_at&&Date.parse(row.expires_at)<=Date.now();
      item.textContent=label+" — "+(row?.granted?(expired?"Expirée":"Autorisée"):"Non autorisée")+(row?.expires_at?" · "+new Date(row.expires_at).toLocaleString("fr-FR"):"");el("entitlement-list").append(item);
    }
  }
  async function selectOrganization(org){selected=org;hideInvitation();el("grant-form").reset();el("platform-invite").reset();el("detail-name").textContent=org.name;el("detail-id").textContent=org.id;el("change-status").textContent=org.active?"Suspendre l’organisation":"Réactiver l’organisation";el("org-detail").hidden=false;el("entitlement-list").replaceChildren();await loadEntitlements();}
  async function run(handler){if(busy||!token)return;busy=true;notice();try{await handler();}catch(err){if(err.status===401){clearSession();show("login");}notice(err.message,true);}finally{busy=false;}}
  el("open-platform").addEventListener("click",()=>run(async()=>{await api("/api/v1/platform/me","GET",undefined,true);if(!token)return;show("platform");await loadOrganizations(0);}));
  el("back-profile").addEventListener("click",()=>{if(!busy){hideInvitation();show("session");}});
  el("refresh-orgs").addEventListener("click",()=>run(()=>loadOrganizations()));
  el("prev-orgs").addEventListener("click",()=>run(()=>loadOrganizations(Math.max(0,offset-20))));
  el("next-orgs").addEventListener("click",()=>run(()=>loadOrganizations(offset+20)));
  el("hide-invitation").addEventListener("click",hideInvitation);
  action("create-org",async()=>{const org=await api(base,"POST",{slug:el("new-slug").value.trim(),name:el("new-name").value.trim()},true);if(!token)return;el("create-org").reset();await loadOrganizations(0);await selectOrganization(org);notice("Organisation créée.");});
  el("change-status").addEventListener("click",()=>run(async()=>{if(!selected)return;const org=selected;if(!window.confirm((org.active?"Suspendre ":"Réactiver ")+org.name+" ?"))return;const result=await api(base+"/"+org.id+"/status","PATCH",{active:!org.active},true);if(!token)return;await loadOrganizations();await selectOrganization({...org,active:result.active});notice("Statut mis à jour.");}));
  action("grant-form",async()=>{if(!selected)return;const expiry=el("grant-expiry").value;const granted=el("grant-status").value==="true";await api(base+"/"+selected.id+"/entitlements/"+el("module-key").value,"PUT",{granted,expires_at:expiry?new Date(expiry).toISOString():null},true);if(!token)return;await loadEntitlements();notice("Autorisation enregistrée.");});
  action("platform-invite",async()=>{if(!selected)return;hideInvitation();const result=await api(base+"/"+selected.id+"/invitations","POST",{email:el("admin-email").value.trim()},true);if(!token)return;el("invitation-token").textContent=result.token;el("invitation-result").hidden=false;el("platform-invite").reset();notice("Invitation créée. Aucun email n’a été envoyé automatiquement.");});
  el("saved").addEventListener("change",()=>el("finish").disabled=!el("saved").checked);
  el("finish").addEventListener("click",()=>{clearSession();show("login");notice("MFA activé. Reconnectez-vous avec un nouveau code TOTP.");});
  el("open-invite").addEventListener("click",()=>{if(!busy)show("invite");});
  el("enable-mfa").addEventListener("click",()=>show("mfa"));
  document.querySelectorAll("[data-back]").forEach(b=>b.addEventListener("click",()=>{if(!busy){el("invite-form").reset();show("login");}}));
  document.querySelectorAll("[data-logout]").forEach(b=>b.addEventListener("click",async()=>{if(busy)return;busy=true;let failed=false;try{await api("/api/v1/auth/logout","POST",undefined,true);}catch{failed=true;}finally{clearSession();show("login");busy=false;notice(failed?"Session locale fermée. La révocation serveur n’a pas pu être confirmée.":"Vous êtes déconnecté.",failed);}}));
})();
