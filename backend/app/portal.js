"use strict";
(() => {
  const el = id => document.getElementById(id);
  const views = ["login","invite","mfa","recovery","session","platform","institution"];
  let token = null, timer = null, busy = false, selected = null, offset = 0, organizations = [], memberOffset = 0, identity = null, artistOffset = 0, editingArtist = null;
  function notice(message="",error=false){el("notice").textContent=message;el("notice").classList.toggle("error",error);}
  function show(view){views.forEach(v=>{el(v+"-view").hidden=v!==view;});notice();}
  function clearSession(){resetInstitution();resetPlatform();token=null;clearTimeout(timer);timer=null;el("secret").textContent="";el("recovery").textContent="";el("saved").checked=false;el("finish").disabled=true;el("confirm-form").hidden=true;el("setup-form").hidden=false;document.querySelectorAll("form").forEach(f=>f.reset());}
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
      identity=me;
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

  const tenantBase="/api/v1/organization";
  const roles={admin:"Administrateur",manager:"Gestionnaire",auditor:"Auditeur",artist:"Artiste"};
  function hideMemberInvitation(){el("member-invite-token").textContent="";el("member-invite-id").textContent="";el("member-invite-result").hidden=true;}
  function resetInstitution(){resetArtists();identity=null;memberOffset=0;hideMemberInvitation();for(const id of ["institution-name","institution-role","institution-module-list","member-list","member-page"])el(id).replaceChildren();el("institution-modules").hidden=true;el("institution-members").hidden=true;}
  async function loadInstitution(){
    const me=await api("/api/v1/auth/me","GET",undefined,true);if(!token)return;
    if(me.mfa_required){identity=null;show("mfa");return;}
    identity=me;
    const org=await api(tenantBase,"GET",undefined,true);if(!token)return;
    el("institution-name").textContent=org.name;el("institution-role").textContent=roles[me.role]||me.role;
    const admin=me.role==="admin"&&me.mfa_enabled;
    el("institution-modules").hidden=!["admin","manager","auditor"].includes(me.role);
    el("institution-members").hidden=!admin;
    el("institution-module-list").replaceChildren();el("member-list").replaceChildren();
    show("institution");
    if(!el("institution-modules").hidden)await loadTenantModules(admin);
    if(admin&&token)await loadMembers(0);
  }
  async function loadTenantModules(admin){
    const rows=await api(tenantBase+"/modules","GET",undefined,true);if(!token)return;
    const list=el("institution-module-list");list.replaceChildren();
    const artistEnabled=rows.some(row=>row.module_key==="artists"&&row.enabled);
    if(!artistEnabled)resetArtists();
    for(const row of rows){
      const item=document.createElement("article");item.className="tenant-card";
      const title=document.createElement("strong");title.textContent=modules[row.module_key]||row.module_key;item.append(title);
      const status=document.createElement("p");status.textContent=row.enabled?(row.module_key==="artists"?"Activé — registre disponible":"Activé — métier à développer"):row.entitled?"Autorisé, désactivé":"Licence non attribuée ou expirée";item.append(status);
      if(admin&&(row.entitled||row.enabled)){const button=document.createElement("button");button.type="button";button.textContent=row.enabled?"Désactiver":"Activer";button.addEventListener("click",()=>run(async()=>{await api(tenantBase+"/modules/"+encodeURIComponent(row.module_key),"PUT",{enabled:!row.enabled},true);if(!token)return;await loadTenantModules(true);notice("Configuration enregistrée.");}));item.append(button);}
      if(row.module_key==="artists"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir le registre";open.addEventListener("click",()=>run(async()=>{resetArtists();el("artist-workspace").hidden=false;el("artist-form").hidden=!["admin","manager"].includes(identity?.role);await loadArtists(0);}));item.append(open);}
      list.append(item);
    }
  }
  async function loadMembers(nextOffset=memberOffset){
    const rows=await api(tenantBase+"/members?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    memberOffset=nextOffset;const list=el("member-list");list.replaceChildren();
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucun collaborateur sur cette page.";list.append(p);}
    for(const row of rows){
      const item=document.createElement("article");item.className="tenant-card";
      const title=document.createElement("strong");title.textContent=row.email;item.append(title);
      const info=document.createElement("p");info.textContent=(roles[row.role]||row.role)+" · "+(row.active?"Actif":"Suspendu")+" · MFA "+(row.mfa_enabled?"activé":"non activé");item.append(info);
      if(row.role!=="admin"&&row.account_id!==identity?.account_id){
        const select=document.createElement("select");select.setAttribute("aria-label","Rôle de "+row.email);
        for(const key of ["manager","auditor","artist"]){const option=document.createElement("option");option.value=key;option.textContent=roles[key];select.append(option);}select.value=row.role;
        const save=document.createElement("button");save.type="button";save.textContent="Enregistrer le rôle";
        const status=document.createElement("button");status.type="button";status.textContent=row.active?"Suspendre":"Réactiver";
        const update=active=>run(async()=>{if(!window.confirm("Modifier les accès de "+row.email+" ? Les sessions seront révoquées."))return;await api(tenantBase+"/members/"+encodeURIComponent(row.account_id),"PATCH",{role:select.value,active},true);if(!token)return;await loadMembers();notice("Collaborateur mis à jour.");});
        save.addEventListener("click",()=>update(row.active));status.addEventListener("click",()=>update(!row.active));item.append(select,save,status);
      }list.append(item);
    }
    el("prev-members").disabled=memberOffset===0;el("next-members").disabled=rows.length<20;el("member-page").textContent="Page "+(memberOffset/20+1);
  }
  el("open-institution").addEventListener("click",()=>run(loadInstitution));
  el("institution-refresh").addEventListener("click",()=>run(loadInstitution));
  el("institution-back").addEventListener("click",()=>{if(!busy){hideMemberInvitation();show("session");}});
  el("prev-members").addEventListener("click",()=>run(()=>loadMembers(Math.max(0,memberOffset-20))));
  el("next-members").addEventListener("click",()=>run(()=>loadMembers(memberOffset+20)));
  el("member-hide-invite").addEventListener("click",hideMemberInvitation);
  action("member-invite-form",async()=>{hideMemberInvitation();const result=await api(tenantBase+"/invitations","POST",{email:el("member-email").value.trim(),role:el("member-role").value},true);if(!token)return;el("member-invite-token").textContent=result.token;el("member-invite-id").textContent="UUID : "+result.id;el("member-revoke-id").value=result.id;el("member-invite-result").hidden=false;el("member-invite-form").reset();notice("Invitation créée. Aucun email automatique envoyé.");});
  action("member-revoke-form",async()=>{if(!window.confirm("Révoquer cette invitation ?"))return;await api(tenantBase+"/invitations/"+encodeURIComponent(el("member-revoke-id").value.trim()),"DELETE",undefined,true);if(!token)return;hideMemberInvitation();el("member-revoke-form").reset();notice("Invitation révoquée.");});

  const artistBase="/api/v1/artists";
  const artistStatuses={pending:"En attente",active:"Actif",suspended:"Suspendu",archived:"Archivé"};
  function resetArtists(){editingArtist=null;artistOffset=0;el("artist-workspace").hidden=true;el("artist-list").replaceChildren();el("artist-form").reset();el("artist-search").reset();el("artist-form-title").textContent="Nouvel adhérent";}
  function editArtist(row){editingArtist=row?.id||null;el("artist-form").reset();el("artist-form-title").textContent=row?"Modifier le dossier":"Nouvel adhérent";if(row){for(const [field,key] of Object.entries({number:"member_number",name:"legal_name",stage:"stage_name",email:"email",phone:"phone",status:"status"}))el("artist-"+field).value=row[key]||"";}}
  async function loadArtists(nextOffset=artistOffset){
    const query=new URLSearchParams({q:el("artist-query").value,limit:"20",offset:String(nextOffset)});
    if(el("artist-filter").value)query.set("status",el("artist-filter").value);
    const rows=await api(artistBase+"?"+query,"GET",undefined,true);if(!token)return;
    artistOffset=nextOffset;const list=el("artist-list");list.replaceChildren();
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucun dossier sur cette page.";list.append(p);}
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";
      const title=document.createElement("strong");title.textContent=row.legal_name;item.append(title);
      for(const value of [row.member_number+" · "+artistStatuses[row.status],row.stage_name,row.email,row.phone])if(value){const p=document.createElement("p");p.textContent=value;item.append(p);}
      if(["admin","manager"].includes(identity?.role)){const button=document.createElement("button");button.type="button";button.textContent="Modifier";button.addEventListener("click",()=>{if(!busy)editArtist(row);});item.append(button);}list.append(item);}
    el("artist-prev").disabled=artistOffset===0;el("artist-next").disabled=rows.length<20;el("artist-page").textContent="Page "+(artistOffset/20+1);
  }
  action("artist-search",()=>loadArtists(0));
  el("artist-prev").addEventListener("click",()=>run(()=>loadArtists(Math.max(0,artistOffset-20))));
  el("artist-next").addEventListener("click",()=>run(()=>loadArtists(artistOffset+20)));
  el("artist-new").addEventListener("click",()=>{if(!busy)editArtist(null);});
  action("artist-form",async()=>{const data={member_number:el("artist-number").value,legal_name:el("artist-name").value,stage_name:el("artist-stage").value||null,email:el("artist-email").value||null,phone:el("artist-phone").value||null,status:el("artist-status").value};await api(artistBase+(editingArtist?"/"+encodeURIComponent(editingArtist):""),editingArtist?"PUT":"POST",data,true);if(!token)return;editArtist(null);await loadArtists(0);notice("Dossier enregistré.");});
  el("saved").addEventListener("change",()=>el("finish").disabled=!el("saved").checked);
  el("finish").addEventListener("click",()=>{clearSession();show("login");notice("MFA activé. Reconnectez-vous avec un nouveau code TOTP.");});
  el("open-invite").addEventListener("click",()=>{if(!busy)show("invite");});
  el("enable-mfa").addEventListener("click",()=>show("mfa"));
  document.querySelectorAll("[data-back]").forEach(b=>b.addEventListener("click",()=>{if(!busy){el("invite-form").reset();show("login");}}));
  document.querySelectorAll("[data-logout]").forEach(b=>b.addEventListener("click",async()=>{if(busy)return;busy=true;let failed=false;try{await api("/api/v1/auth/logout","POST",undefined,true);}catch{failed=true;}finally{clearSession();show("login");busy=false;notice(failed?"Session locale fermée. La révocation serveur n’a pas pu être confirmée.":"Vous êtes déconnecté.",failed);}}));
})();
