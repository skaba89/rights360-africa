"use strict";
(() => {
  const el = id => document.getElementById(id);
  const views = ["login","invite","mfa","recovery","session","platform","institution"];
  let token = null, timer = null, busy = false, selected = null, offset = 0, organizations = [], memberOffset = 0, identity = null, artistOffset = 0, editingArtist = null, workOffset = 0, editingWork = null;
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
  function resetInstitution(){resetExchange();resetAnalytics();resetMedia();resetField();resetPayouts();resetAccounting();resetDistribution();resetBilling();resetTariffs();resetLicenses();resetWorks();resetArtists();identity=null;memberOffset=0;hideMemberInvitation();for(const id of ["institution-name","institution-role","institution-module-list","member-list","member-page"])el(id).replaceChildren();el("institution-modules").hidden=true;el("institution-members").hidden=true;}
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
    if(!artistEnabled||!rows.some(row=>row.module_key==="works"&&row.enabled))resetExchange();
    if(!rows.some(row=>row.module_key==="analytics"&&row.enabled))resetAnalytics();
    if(!rows.some(row=>row.module_key==="media"&&row.enabled))resetMedia();
    if(!rows.some(row=>row.module_key==="field_control"&&row.enabled))resetField();
    if(!rows.some(row=>row.module_key==="finance"&&row.enabled)){resetPayouts();resetAccounting();resetBilling();}
    if(!rows.some(row=>row.module_key==="royalties"&&row.enabled))resetDistribution();
    if(!rows.some(row=>row.module_key==="licenses"&&row.enabled)){resetTariffs();resetLicenses();}
    if(!rows.some(row=>row.module_key==="works"&&row.enabled))resetWorks();
    for(const row of rows){
      const item=document.createElement("article");item.className="tenant-card";
      const title=document.createElement("strong");title.textContent=modules[row.module_key]||row.module_key;item.append(title);
      const status=document.createElement("p");status.textContent=row.enabled?(["artists","works","licenses","finance","royalties","field_control","media","analytics"].includes(row.module_key)?"Activé — registre disponible":"Activé — métier à développer"):row.entitled?"Autorisé, désactivé":"Licence non attribuée ou expirée";item.append(status);
      if(admin&&(row.entitled||row.enabled)){const button=document.createElement("button");button.type="button";button.textContent=row.enabled?"Désactiver":"Activer";button.addEventListener("click",()=>run(async()=>{await api(tenantBase+"/modules/"+encodeURIComponent(row.module_key),"PUT",{enabled:!row.enabled},true);if(!token)return;await loadTenantModules(true);notice("Configuration enregistrée.");}));item.append(button);}
      if(row.module_key==="artists"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir le registre";open.addEventListener("click",()=>run(async()=>{resetArtists();el("artist-workspace").hidden=false;el("artist-form").hidden=!["admin","manager"].includes(identity?.role);await loadArtists(0);}));item.append(open);}
      if(row.module_key==="works"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir les œuvres";open.addEventListener("click",()=>run(async()=>{resetWorks();el("work-workspace").hidden=false;el("work-form").hidden=!["admin","manager"].includes(identity?.role);await loadWorks(0);}));item.append(open);}
      if(row.module_key==="licenses"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir les licences";open.addEventListener("click",()=>run(openLicenses));item.append(open);}
      if(row.module_key==="licenses"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir les barèmes";open.addEventListener("click",()=>run(openTariffs));item.append(open);}
      if(row.module_key==="finance"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir la facturation";open.addEventListener("click",()=>run(openBilling));item.append(open);}
      if(row.module_key==="royalties"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir les répartitions";open.addEventListener("click",()=>run(openDistribution));item.append(open);}
      if(row.module_key==="finance"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ouvrir le journal comptable";open.addEventListener("click",()=>run(openAccounting));item.append(open);}
      if(row.module_key==="finance"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Ordres de reversement";open.addEventListener("click",()=>run(openPayouts));item.append(open);}
      if(row.module_key==="field_control"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Contrôle terrain";open.addEventListener("click",()=>run(openField));item.append(open);}
      if(row.module_key==="media"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Media Intelligence";open.addEventListener("click",()=>run(openMedia));item.append(open);}
      if(row.module_key==="analytics"&&row.enabled){const open=document.createElement("button");open.type="button";open.textContent="Tableau de bord décisionnel";open.addEventListener("click",()=>run(openAnalytics));item.append(open);}
      if(row.module_key==="works"&&row.enabled&&artistEnabled){const open=document.createElement("button");open.type="button";open.textContent="Échanges de répertoires";open.addEventListener("click",()=>run(openExchange));item.append(open);}
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
      for(const value of [row.member_number+" · "+artistStatuses[row.status],row.stage_name,row.email,row.phone,"UUID : "+row.id])if(value){const p=document.createElement("p");p.textContent=value;item.append(p);}
      if(["admin","manager"].includes(identity?.role)){const button=document.createElement("button");button.type="button";button.textContent="Modifier";button.addEventListener("click",()=>{if(!busy)editArtist(row);});item.append(button);}list.append(item);}
    el("artist-prev").disabled=artistOffset===0;el("artist-next").disabled=rows.length<20;el("artist-page").textContent="Page "+(artistOffset/20+1);
  }
  action("artist-search",()=>loadArtists(0));
  el("artist-prev").addEventListener("click",()=>run(()=>loadArtists(Math.max(0,artistOffset-20))));
  el("artist-next").addEventListener("click",()=>run(()=>loadArtists(artistOffset+20)));
  el("artist-new").addEventListener("click",()=>{if(!busy)editArtist(null);});
  action("artist-form",async()=>{const data={member_number:el("artist-number").value,legal_name:el("artist-name").value,stage_name:el("artist-stage").value||null,email:el("artist-email").value||null,phone:el("artist-phone").value||null,status:el("artist-status").value};await api(artistBase+(editingArtist?"/"+encodeURIComponent(editingArtist):""),editingArtist?"PUT":"POST",data,true);if(!token)return;editArtist(null);await loadArtists(0);notice("Dossier enregistré.");});

  const workBase="/api/v1/works";
  const workCategories={music:"Musique",literary:"Littéraire",audiovisual:"Audiovisuel",visual:"Arts visuels",other:"Autre"};
  const workStatuses={draft:"Brouillon",registered:"Enregistrée",archived:"Archivée"};
  function resetWorks(){resetRights();editingWork=null;workOffset=0;el("work-workspace").hidden=true;el("work-list").replaceChildren();el("work-form").reset();el("work-search").reset();el("work-form-title").textContent="Nouvelle œuvre";}
  function editWork(row){editingWork=row?.id||null;el("work-form").reset();el("work-form-title").textContent=row?"Modifier l’œuvre":"Nouvelle œuvre";if(row){for(const [field,key] of Object.entries({reference:"reference",title:"title",category:"category",artist:"primary_artist_id",iswc:"iswc",status:"status"}))el("work-"+field).value=row[key]||"";}}
  async function loadWorks(nextOffset=workOffset){
    const query=new URLSearchParams({q:el("work-query").value,limit:"20",offset:String(nextOffset)});
    if(el("work-filter").value)query.set("category",el("work-filter").value);
    const rows=await api(workBase+"?"+query,"GET",undefined,true);if(!token)return;
    workOffset=nextOffset;const list=el("work-list");list.replaceChildren();
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucune œuvre sur cette page.";list.append(p);}
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";
      const title=document.createElement("strong");title.textContent=row.title;item.append(title);
      for(const value of [row.reference+" · "+workCategories[row.category]+" · "+workStatuses[row.status],row.iswc,"Artiste : "+row.primary_artist_id])if(value){const p=document.createElement("p");p.textContent=value;item.append(p);}
      if(["admin","manager"].includes(identity?.role)){const button=document.createElement("button");button.type="button";button.textContent="Modifier";button.addEventListener("click",()=>{if(!busy)editWork(row);});item.append(button);}
      const rights=document.createElement("button");rights.type="button";rights.textContent="Ayants droit";rights.addEventListener("click",()=>run(()=>openRights(row)));item.append(rights);list.append(item);}
    el("work-prev").disabled=workOffset===0;el("work-next").disabled=rows.length<20;el("work-page").textContent="Page "+(workOffset/20+1);
  }
  action("work-search",()=>loadWorks(0));
  el("work-prev").addEventListener("click",()=>run(()=>loadWorks(Math.max(0,workOffset-20))));
  el("work-next").addEventListener("click",()=>run(()=>loadWorks(workOffset+20)));
  el("work-new").addEventListener("click",()=>{if(!busy)editWork(null);});
  action("work-form",async()=>{const data={reference:el("work-reference").value,title:el("work-title").value,category:el("work-category").value,primary_artist_id:el("work-artist").value.trim(),iswc:el("work-iswc").value.trim()||null,status:el("work-status").value};await api(workBase+(editingWork?"/"+encodeURIComponent(editingWork):""),editingWork?"PUT":"POST",data,true);if(!token)return;editWork(null);await loadWorks(0);notice("Œuvre enregistrée.");});

  let rightsWork=null, rightsVersion=0;
  const rightsRoles={author:"Auteur",composer:"Compositeur",publisher:"Éditeur",beneficiary:"Bénéficiaire",other:"Autre"};
  function resetRights(){rightsWork=null;rightsVersion=0;el("rights-workspace").hidden=true;el("rights-form").hidden=true;el("rights-history").replaceChildren();el("rights-rows").replaceChildren();el("rights-work-name").textContent="";el("rights-total").textContent="";el("rights-form").reset();}
  function rightsTotal(){const total=Array.from(el("rights-rows").querySelectorAll("input[data-share]")).reduce((sum,input)=>sum+Number(input.value||0),0);el("rights-total").textContent="Total : "+(total/100).toFixed(2)+" %";}
  function addRightsRow(share={}){
    if(el("rights-rows").children.length>=100)return;
    const row=document.createElement("div");row.className="tenant-card";
    const artist=document.createElement("input");artist.required=true;artist.maxLength=36;artist.placeholder="UUID de l’artiste";artist.setAttribute("aria-label","UUID de l’ayant droit");artist.value=share.artist_id||"";
    const role=document.createElement("select");role.setAttribute("aria-label","Qualité de l’ayant droit");
    for(const [key,label] of Object.entries(rightsRoles)){const option=document.createElement("option");option.value=key;option.textContent=label;role.append(option);}role.value=share.role||"author";
    const amount=document.createElement("input");amount.type="number";amount.required=true;amount.min="1";amount.max="10000";amount.step="1";amount.dataset.share="true";amount.placeholder="Points de base (100 = 1 %)";amount.setAttribute("aria-label","Quote-part en points de base");amount.value=share.basis_points||"";amount.addEventListener("input",rightsTotal);
    const remove=document.createElement("button");remove.type="button";remove.textContent="Retirer";remove.addEventListener("click",()=>{if(!busy){row.remove();rightsTotal();}});row.append(artist,role,amount,remove);el("rights-rows").append(row);rightsTotal();
  }
  async function openRights(work){
    resetRights();rightsWork=work;
    const history=await api(workBase+"/"+encodeURIComponent(work.id)+"/rights","GET",undefined,true);
    if(!token||rightsWork!==work)return;
    el("rights-work-name").textContent=work.title;el("rights-workspace").hidden=false;
    const latest=history[0];rightsVersion=latest?.version||0;
    for(const declaration of history){
      const item=document.createElement("article");item.className="tenant-card";const heading=document.createElement("strong");heading.textContent="Version "+declaration.version+" · "+(declaration.status==="complete"?"Complète":"Brouillon")+" · "+(declaration.total_basis_points/100).toFixed(2)+" %";item.append(heading);const id=document.createElement("p");id.textContent="UUID : "+declaration.id;item.append(id);
      for(const share of declaration.shares){const p=document.createElement("p");p.textContent=share.artist_id+" · "+rightsRoles[share.role]+" · "+(share.basis_points/100).toFixed(2)+" %";item.append(p);}el("rights-history").append(item);
    }
    if(["admin","manager"].includes(identity?.role)){el("rights-form").hidden=false;el("rights-status").value=latest?.status||"draft";for(const share of latest?.shares||[{artist_id:work.primary_artist_id,role:"author"}])addRightsRow(share);}
  }
  el("rights-close").addEventListener("click",()=>{if(!busy)resetRights();});
  el("rights-add").addEventListener("click",()=>{if(!busy)addRightsRow();});
  action("rights-form",async()=>{if(!rightsWork)return;const work=rightsWork;
    const shares=Array.from(el("rights-rows").children).map(row=>({artist_id:row.children[0].value.trim(),role:row.children[1].value,basis_points:Number(row.children[2].value)}));
    await api(workBase+"/"+encodeURIComponent(work.id)+"/rights","POST",{expected_version:rightsVersion,status:el("rights-status").value,shares},true);
    if(!token)return;await openRights(work);notice("Nouvelle version enregistrée.");
  });

  let licenseOffset=0;
  const operatorBase="/api/v1/operators",licenseBase="/api/v1/exploitation-licenses";
  function resetLicenses(){licenseOffset=0;el("license-workspace").hidden=true;el("operator-list").replaceChildren();el("license-list").replaceChildren();el("operator-form").reset();el("license-form").reset();}
  async function openLicenses(){resetLicenses();el("license-workspace").hidden=false;const write=["admin","manager"].includes(identity?.role);el("operator-form").hidden=!write;el("license-form").hidden=!write;await loadOperators();if(token)await loadLicenses(0);}
  async function loadOperators(){
    const rows=await api(operatorBase+"?limit=100","GET",undefined,true);if(!token)return;
    const list=el("operator-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=row.name+" · "+row.reference;item.append(title);const p=document.createElement("p");p.textContent=row.category+" · UUID : "+row.id;item.append(p);list.append(item);}
    if(!rows.length||rows.length===100){const p=document.createElement("p");p.textContent=rows.length?"100 premiers exploitants affichés. Recherche complète disponible via API.":"Aucun exploitant.";list.append(p);}
  }
  async function loadLicenses(nextOffset=licenseOffset){
    const rows=await api(licenseBase+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    licenseOffset=nextOffset;const list=el("license-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=row.reference+" · "+({draft:"Brouillon",active:"Active",revoked:"Révoquée"})[row.status];item.append(title);
      for(const value of [row.territory+" · "+row.usage_type,row.starts_on+" — "+row.ends_on,row.effective?"En vigueur":"Hors vigueur","Exploitant : "+row.operator_id,row.work_id?"Œuvre : "+row.work_id:"Périmètre non documenté"]){const p=document.createElement("p");p.textContent=value;item.append(p);}
      if(identity?.role==="admin"&&row.status!=="revoked"){for(const state of (row.status==="draft"?["active","revoked"]:["revoked"])){const button=document.createElement("button");button.type="button";button.textContent=state==="active"?"Activer":"Révoquer";button.addEventListener("click",()=>run(async()=>{if(!window.confirm("Confirmer cette modification de licence ?"))return;await api(licenseBase+"/"+encodeURIComponent(row.id)+"/status","PATCH",{status:state},true);if(!token)return;await loadLicenses();notice("Statut enregistré.");}));item.append(button);}}list.append(item);}
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucune licence sur cette page.";list.append(p);}
    el("license-prev").disabled=licenseOffset===0;el("license-next").disabled=rows.length<20;el("license-page").textContent="Page "+(licenseOffset/20+1);
  }
  el("license-refresh").addEventListener("click",()=>run(async()=>{await loadOperators();if(token)await loadLicenses();}));
  el("license-prev").addEventListener("click",()=>run(()=>loadLicenses(Math.max(0,licenseOffset-20))));
  el("license-next").addEventListener("click",()=>run(()=>loadLicenses(licenseOffset+20)));
  action("operator-form",async()=>{const data={reference:el("operator-reference").value,name:el("operator-name").value,category:el("operator-category").value,email:el("operator-email").value||null,phone:el("operator-phone").value||null};const result=await api(operatorBase,"POST",data,true);if(!token)return;el("operator-form").reset();el("license-operator").value=result.id;await loadOperators();notice("Exploitant créé.");});
  action("license-form",async()=>{const data={reference:el("license-reference").value,operator_id:el("license-operator").value.trim(),work_id:el("license-work").value.trim()||null,territory:el("license-territory").value,usage_type:el("license-usage").value,starts_on:el("license-start").value,ends_on:el("license-end").value};await api(licenseBase,"POST",data,true);if(!token)return;el("license-form").reset();await loadLicenses(0);notice("Brouillon créé.");});

  let tariffOffset=0, selectedTariff=null;
  const tariffBase="/api/v1/tariffs";
  const tariffMethods={flat:"Forfait",revenue:"Pourcentage du chiffre d’affaires",capacity:"Capacité",frequency:"Fréquence"};
  function resetTariffs(){tariffOffset=0;selectedTariff=null;el("tariff-workspace").hidden=true;el("tariff-list").replaceChildren();el("tariff-form").reset();el("quote-form").reset();el("quote-form").hidden=true;el("quote-result").textContent="";el("quote-tariff").textContent="";}
  async function openTariffs(){resetTariffs();el("tariff-workspace").hidden=false;el("tariff-form").hidden=identity?.role!=="admin";await loadTariffs(0);}
  function selectTariff(row){selectedTariff=row;el("quote-form").reset();el("quote-form").hidden=false;el("quote-tariff").textContent=row.reference+" · V"+row.version+" · "+tariffMethods[row.method];el("quote-result").textContent="";el("quote-quantity-group").hidden=!["capacity","frequency"].includes(row.method);el("quote-revenue-group").hidden=row.method!=="revenue";el("quote-quantity").required=!el("quote-quantity-group").hidden;el("quote-revenue").required=!el("quote-revenue-group").hidden;}
  async function loadTariffs(nextOffset=tariffOffset){
    const rows=await api(tariffBase+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    tariffOffset=nextOffset;const list=el("tariff-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=row.reference+" · V"+row.version;item.append(title);
      for(const value of [row.category+" · "+row.usage_type,tariffMethods[row.method],row.method==="revenue"?(row.rate/100)+" %":row.rate+" unités minimales "+row.currency,row.starts_on+" — "+row.ends_on]){const p=document.createElement("p");p.textContent=value;item.append(p);}
      const quote=document.createElement("button");quote.type="button";quote.textContent="Estimer";quote.addEventListener("click",()=>{if(!busy)selectTariff(row);});item.append(quote);
      if(identity?.role==="admin"){const copy=document.createElement("button");copy.type="button";copy.textContent="Préparer une nouvelle version";copy.addEventListener("click",()=>{if(busy)return;for(const [field,key] of Object.entries({reference:"reference",version:"version",category:"category",usage:"usage_type",method:"method",currency:"currency",rate:"rate",start:"starts_on",end:"ends_on"}))el("tariff-"+field).value=row[key];});item.append(copy);}list.append(item);}
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucun barème sur cette page.";list.append(p);}
    el("tariff-prev").disabled=tariffOffset===0;el("tariff-next").disabled=rows.length<20;el("tariff-page").textContent="Page "+(tariffOffset/20+1);
  }
  el("tariff-refresh").addEventListener("click",()=>run(()=>loadTariffs()));
  el("tariff-prev").addEventListener("click",()=>run(()=>loadTariffs(Math.max(0,tariffOffset-20))));
  el("tariff-next").addEventListener("click",()=>run(()=>loadTariffs(tariffOffset+20)));
  action("tariff-form",async()=>{const data={reference:el("tariff-reference").value,expected_version:Number(el("tariff-version").value),category:el("tariff-category").value,usage_type:el("tariff-usage").value,method:el("tariff-method").value,currency:el("tariff-currency").value,rate:Number(el("tariff-rate").value),starts_on:el("tariff-start").value,ends_on:el("tariff-end").value};await api(tariffBase,"POST",data,true);if(!token)return;el("tariff-form").reset();await loadTariffs(0);notice("Version de barème créée.");});
  action("quote-form",async()=>{if(!selectedTariff)return;el("quote-result").textContent="";const data={license_id:el("quote-license").value.trim(),usage_date:el("quote-date").value};if(selectedTariff.method==="revenue")data.revenue_minor=Number(el("quote-revenue").value);if(["capacity","frequency"].includes(selectedTariff.method))data.quantity=Number(el("quote-quantity").value);const result=await api(tariffBase+"/"+encodeURIComponent(selectedTariff.id)+"/quote","POST",data,true);if(!token)return;el("quote-result").textContent="Estimation : "+result.amount_minor+" unités minimales "+result.currency+" (version "+result.tariff_version+").";});

  let billingOffset=0,selectedInvoice=null;
  const billingBase="/api/v1/invoices";
  const billingStates={paid:"Payée",partial:"Partielle",overdue:"En retard",unpaid:"Impayée"};
  function resetBilling(){billingOffset=0;selectedInvoice=null;el("billing-workspace").hidden=true;el("receipt-workspace").hidden=true;el("billing-list").replaceChildren();el("receipt-list").replaceChildren();el("billing-form").reset();el("receipt-form").reset();}
  async function openBilling(){resetBilling();el("billing-workspace").hidden=false;el("billing-form").hidden=identity?.role!=="admin";await loadBilling(0);}
  async function loadBilling(nextOffset=billingOffset){
    const rows=await api(billingBase+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    billingOffset=nextOffset;const list=el("billing-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=row.reference+" · "+billingStates[row.status];item.append(title);
      for(const value of ["Montant : "+row.amount_minor+" "+row.currency+" (unités minimales)","Encaissé : "+row.paid_minor,"Solde : "+row.balance_minor,"Échéance : "+row.due_on,"UUID : "+row.id]){const p=document.createElement("p");p.textContent=value;item.append(p);}
      const button=document.createElement("button");button.type="button";button.textContent="Encaissements";button.addEventListener("click",()=>run(()=>openReceipts(row)));item.append(button);list.append(item);}
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucune facture sur cette page.";list.append(p);}
    el("billing-prev").disabled=billingOffset===0;el("billing-next").disabled=rows.length<20;el("billing-page").textContent="Page "+(billingOffset/20+1);
  }
  async function openReceipts(row){selectedInvoice=row;el("receipt-title").textContent="Encaissements · "+row.reference;el("receipt-workspace").hidden=false;el("receipt-form").hidden=identity?.role!=="admin";el("receipt-form").reset();
    const rows=await api(billingBase+"/"+encodeURIComponent(row.id)+"/receipts","GET",undefined,true);if(!token)return;
    const list=el("receipt-list");list.replaceChildren();
    for(const receipt of rows){const p=document.createElement("p");p.textContent=receipt.reference+" · "+receipt.amount_minor+" "+row.currency+" · "+receipt.received_on+" · UUID : "+receipt.id;list.append(p);}
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucun encaissement.";list.append(p);}
  }
  el("billing-refresh").addEventListener("click",()=>run(()=>loadBilling()));
  el("billing-prev").addEventListener("click",()=>run(()=>loadBilling(Math.max(0,billingOffset-20))));
  el("billing-next").addEventListener("click",()=>run(()=>loadBilling(billingOffset+20)));
  action("billing-form",async()=>{const data={reference:el("billing-ref").value,license_id:el("billing-license").value.trim(),tariff_id:el("billing-tariff").value.trim(),usage_date:el("billing-usage").value,due_on:el("billing-due").value};if(el("billing-quantity").value)data.quantity=Number(el("billing-quantity").value);if(el("billing-revenue").value)data.revenue_minor=Number(el("billing-revenue").value);if(!window.confirm("Émettre cette créance interne ?"))return;await api(billingBase,"POST",data,true);if(!token)return;el("billing-form").reset();await loadBilling(0);notice("Créance enregistrée.");});
  action("receipt-form",async()=>{if(!selectedInvoice)return;const row=selectedInvoice;const amount=Number(el("receipt-amount").value);if(!Number.isSafeInteger(amount)||amount<=0)throw new Error("Montant invalide.");if(!window.confirm("Confirmer un encaissement réellement reçu ?"))return;await api(billingBase+"/"+encodeURIComponent(row.id)+"/receipts","POST",{reference:el("receipt-ref").value,amount_minor:amount,received_on:el("receipt-date").value},true);if(!token)return;await openReceipts(row);await loadBilling();notice("Encaissement enregistré.");});

  let distributionOffset=0;
  const distributionBase="/api/v1/distributions";
  function resetDistribution(){distributionOffset=0;el("distribution-workspace").hidden=true;el("distribution-list").replaceChildren();el("distribution-lines").replaceChildren();el("distribution-detail-title").textContent="";el("distribution-form").reset();}
  async function openDistribution(){resetDistribution();el("distribution-workspace").hidden=false;el("distribution-form").hidden=identity?.role!=="admin";await loadDistributions(0);}
  async function loadDistributions(nextOffset=distributionOffset){
    const rows=await api(distributionBase+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    distributionOffset=nextOffset;const list=el("distribution-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent="Répartition "+row.id;item.append(title);
      for(const value of ["Brut : "+row.gross_minor+" "+row.currency,"Commission : "+row.commission_minor+" ("+row.commission_bps/100+" %)","Net : "+row.net_minor,"Encaissement : "+row.receipt_id]){const p=document.createElement("p");p.textContent=value;item.append(p);}
      const button=document.createElement("button");button.type="button";button.textContent="Détail des ayants droit";button.addEventListener("click",()=>run(()=>loadDistributionLines(row)));item.append(button);list.append(item);}
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucune répartition sur cette page.";list.append(p);}
    el("distribution-prev").disabled=distributionOffset===0;el("distribution-next").disabled=rows.length<20;el("distribution-page").textContent="Page "+(distributionOffset/20+1);
  }
  async function loadDistributionLines(row){const rows=await api(distributionBase+"/"+encodeURIComponent(row.id)+"/lines","GET",undefined,true);if(!token)return;
    el("distribution-detail-title").textContent="Détail · "+row.id;const list=el("distribution-lines");list.replaceChildren();
    for(const line of rows){const p=document.createElement("p");p.textContent=line.artist_id+" · "+line.role+" · "+line.basis_points/100+" % · "+line.amount_minor+" "+row.currency;list.append(p);}
  }
  el("distribution-refresh").addEventListener("click",()=>run(()=>loadDistributions()));
  el("distribution-prev").addEventListener("click",()=>run(()=>loadDistributions(Math.max(0,distributionOffset-20))));
  el("distribution-next").addEventListener("click",()=>run(()=>loadDistributions(distributionOffset+20)));
  action("distribution-form",async()=>{const data={receipt_id:el("distribution-receipt").value.trim(),declaration_id:el("distribution-declaration").value.trim(),commission_bps:Number(el("distribution-commission").value)};if(!window.confirm("Enregistrer ce calcul interne ? Aucun paiement ne sera effectué."))return;const result=await api(distributionBase,"POST",data,true);if(!token)return;el("distribution-form").reset();await loadDistributions(0);await loadDistributionLines(result);notice("Calcul enregistré.");});

  let accountingOffset=0;
  const accountingBase="/api/v1/accounting";
  const accountNames={receivable:"Créances",royalties_unallocated:"Droits non répartis",cash_unverified:"Encaissements non rapprochés",management_commission:"Commissions",beneficiary_payable:"Dettes envers les ayants droit"};
  function resetAccounting(){accountingOffset=0;el("accounting-workspace").hidden=true;for(const id of ["accounting-list","accounting-balances","accounting-lines","accounting-detail-title","accounting-page"])el(id).replaceChildren();el("accounting-form").reset();}
  async function openAccounting(){resetAccounting();el("accounting-workspace").hidden=false;el("accounting-form").hidden=identity?.role!=="admin";await loadAccounting(0);}
  function accountingText(parent,value){const p=document.createElement("p");p.textContent=value;parent.append(p);}
  async function loadAccounting(nextOffset=accountingOffset){
    const balances=await api(accountingBase+"/balances","GET",undefined,true);if(!token)return;
    const balanceList=el("accounting-balances");balanceList.replaceChildren();
    for(const row of balances)accountingText(balanceList,row.currency+" · "+(accountNames[row.account_key]||row.account_key)+" · Débit "+row.debit_minor+" · Crédit "+row.credit_minor+" · Solde "+row.balance_minor);
    if(!balances.length)accountingText(balanceList,"Aucun solde comptabilisé.");
    const rows=await api(accountingBase+"/entries?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    accountingOffset=nextOffset;const list=el("accounting-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=row.source_type+" · "+row.currency;item.append(title);accountingText(item,"Source : "+row.source_id);accountingText(item,row.posted_at);const button=document.createElement("button");button.type="button";button.textContent="Détail débit / crédit";button.addEventListener("click",()=>run(()=>loadAccountingLines(row)));item.append(button);list.append(item);}
    if(!rows.length)accountingText(list,"Aucune écriture sur cette page.");
    el("accounting-prev").disabled=accountingOffset===0;el("accounting-next").disabled=rows.length<20;el("accounting-page").textContent="Page "+(accountingOffset/20+1);
  }
  async function loadAccountingLines(row){const rows=await api(accountingBase+"/entries/"+encodeURIComponent(row.id)+"/lines","GET",undefined,true);if(!token)return;el("accounting-detail-title").textContent="Écriture "+row.id;const list=el("accounting-lines");list.replaceChildren();for(const line of rows)accountingText(list,(accountNames[line.account_key]||line.account_key)+" · Débit "+line.debit_minor+" · Crédit "+line.credit_minor+" "+row.currency+(line.artist_id?" · Ayant droit "+line.artist_id:""));}
  el("accounting-refresh").addEventListener("click",()=>run(()=>loadAccounting()));
  el("accounting-prev").addEventListener("click",()=>run(()=>loadAccounting(Math.max(0,accountingOffset-20))));
  el("accounting-next").addEventListener("click",()=>run(()=>loadAccounting(accountingOffset+20)));
  action("accounting-form",async()=>{if(!window.confirm("Comptabiliser cette source dans le journal auxiliaire ?"))return;const row=await api(accountingBase+"/entries","POST",{source_type:el("accounting-source-type").value,source_id:el("accounting-source-id").value.trim()},true);if(!token)return;el("accounting-form").reset();await loadAccounting(0);await loadAccountingLines(row);notice("Écriture enregistrée.");});

  let payoutOffset=0;
  const payoutBase="/api/v1/payouts";
  const payoutStates={pending:"En attente de revue",rejected:"Rejeté",approved_for_review_only:"Double revue terminée — exécution désactivée"};
  function resetPayouts(){payoutOffset=0;el("payout-workspace").hidden=true;el("payout-list").replaceChildren();el("payout-form").reset();el("payout-page").textContent="";}
  async function openPayouts(){resetPayouts();el("payout-workspace").hidden=false;el("payout-form").hidden=!["admin","manager"].includes(identity?.role);await loadPayouts(0);}
  async function loadPayouts(nextOffset=payoutOffset){
    const rows=await api(payoutBase+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;
    payoutOffset=nextOffset;const list=el("payout-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=payoutStates[row.status];item.append(title);
      for(const value of ["Ordre : "+row.id,"Ayant droit : "+row.artist_id,row.amount_minor+" "+row.currency+" (unités minimales)",row.channel,"Revues : "+row.reviews.filter(r=>r.decision==="approve").length+"/2"]) {const p=document.createElement("p");p.textContent=value;item.append(p);}
      if(["admin","auditor"].includes(identity?.role)&&row.status==="pending"&&row.created_by!==identity.account_id&&!row.reviews.some(r=>r.reviewer_id===identity.account_id)){for(const decision of ["approve","reject"]){const button=document.createElement("button");button.type="button";button.textContent=decision==="approve"?"Approuver la revue":"Rejeter";button.addEventListener("click",()=>run(async()=>{if(!window.confirm("Confirmer cette décision interne ? Aucun paiement ne sera exécuté."))return;await api(payoutBase+"/"+encodeURIComponent(row.id)+"/reviews","POST",{decision},true);if(!token)return;await loadPayouts();notice("Décision enregistrée.");}));item.append(button);}}list.append(item);}
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucun ordre sur cette page.";list.append(p);}
    el("payout-prev").disabled=payoutOffset===0;el("payout-next").disabled=rows.length<20;el("payout-page").textContent="Page "+(payoutOffset/20+1);
  }
  el("payout-refresh").addEventListener("click",()=>run(()=>loadPayouts()));
  el("payout-prev").addEventListener("click",()=>run(()=>loadPayouts(Math.max(0,payoutOffset-20))));
  el("payout-next").addEventListener("click",()=>run(()=>loadPayouts(payoutOffset+20)));
  action("payout-form",async()=>{await api(payoutBase,"POST",{distribution_id:el("payout-distribution").value.trim(),artist_id:el("payout-artist").value.trim(),channel:el("payout-channel").value},true);if(!token)return;el("payout-form").reset();await loadPayouts(0);notice("Ordre préparé, aucun transfert effectué.");});

  let fieldOffset=0,fieldQueue=[],fieldGeneration=0;
  const fieldBase="/api/v1/field-visits";
  function fieldQueueStatus(){el("field-queue-status").textContent=fieldQueue.length+" constat(s) en mémoire. Non conservés après fermeture, expiration ou déconnexion.";el("field-sync").hidden=!fieldQueue.length;el("field-discard").hidden=!fieldQueue.length;}
  function resetField(){fieldGeneration++;fieldOffset=0;fieldQueue=[];el("field-workspace").hidden=true;el("field-list").replaceChildren();el("field-operators").replaceChildren();el("field-form").reset();el("field-search").reset();fieldQueueStatus();}
  async function openField(){el("field-workspace").hidden=false;el("field-form").hidden=!["admin","manager"].includes(identity?.role);fieldQueueStatus();await loadFieldOperators();if(token)await loadField(0);}
  async function loadFieldOperators(){const rows=await api(fieldBase+"/operators?limit=50&q="+encodeURIComponent(el("field-query").value),"GET",undefined,true);if(!token)return;const list=el("field-operators");list.replaceChildren();for(const row of rows){const button=document.createElement("button");button.type="button";button.textContent=row.name+" · "+row.reference;button.addEventListener("click",()=>{if(!busy)el("field-operator").value=row.id;});list.append(button);}}
  async function loadField(nextOffset=fieldOffset){const rows=await api(fieldBase+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;fieldOffset=nextOffset;const list=el("field-list");list.replaceChildren();for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=row.finding+" · "+row.visited_at;item.append(title);for(const value of ["Exploitant : "+row.operator_id,row.notes,"Licences à la réception : "+row.license_snapshot.records.length+(row.license_snapshot.truncated?" (liste tronquée)":""),row.latitude_e6===null?"Position non fournie":"Position : "+row.latitude_e6/1000000+", "+row.longitude_e6/1000000]){const p=document.createElement("p");p.textContent=value;item.append(p);}for(const lic of row.license_snapshot.records){const p=document.createElement("p");p.textContent=lic.reference+" · "+lic.status+" · "+lic.starts_on+" — "+lic.ends_on;item.append(p);}list.append(item);}el("field-prev").disabled=fieldOffset===0;el("field-next").disabled=rows.length<20;el("field-page").textContent="Page "+(fieldOffset/20+1);}
  async function syncField(){const generation=fieldGeneration;while(token&&fieldQueue.length&&generation===fieldGeneration){const pending=fieldQueue[0];await api(fieldBase,"POST",pending,true);if(!token||generation!==fieldGeneration)return;fieldQueue.shift();fieldQueueStatus();}if(token&&generation===fieldGeneration)await loadField(0);}
  el("field-location").addEventListener("click",()=>{if(!navigator.geolocation){notice("Géolocalisation indisponible.",true);return;}const generation=fieldGeneration;navigator.geolocation.getCurrentPosition(position=>{if(!token||generation!==fieldGeneration)return;el("field-lat").value=position.coords.latitude.toFixed(6);el("field-lon").value=position.coords.longitude.toFixed(6);},()=>{if(token&&generation===fieldGeneration)notice("Position non obtenue.",true);},{enableHighAccuracy:true,timeout:10000,maximumAge:0});});
  el("field-refresh").addEventListener("click",()=>run(()=>loadField()));
  el("field-prev").addEventListener("click",()=>run(()=>loadField(Math.max(0,fieldOffset-20))));
  el("field-next").addEventListener("click",()=>run(()=>loadField(fieldOffset+20)));
  el("field-sync").addEventListener("click",()=>run(syncField));
  el("field-discard").addEventListener("click",()=>{if(!busy&&window.confirm("Effacer les constats non synchronisés ?")){fieldQueue=[];fieldQueueStatus();}});
  action("field-search",loadFieldOperators);
  action("field-form",async()=>{if(fieldQueue.length>=50)throw new Error("File pleine : synchroniser avant de poursuivre.");const lat=el("field-lat").value,lon=el("field-lon").value;if(Boolean(lat)!==Boolean(lon))throw new Error("Renseigner les deux coordonnées ou aucune.");const data={id:crypto.randomUUID(),operator_id:el("field-operator").value.trim(),visited_at:new Date(el("field-date").value).toISOString(),latitude_e6:lat?Math.round(Number(lat)*1000000):null,longitude_e6:lon?Math.round(Number(lon)*1000000):null,finding:el("field-finding").value,notes:el("field-notes").value};fieldQueue.push(data);el("field-form").reset();fieldQueueStatus();if(navigator.onLine)await syncField();else notice("Constat en mémoire uniquement. Synchroniser avant de fermer la page.");});

  let mediaOffset=0,mediaSelected=null;
  const mediaBase="/api/v1/media-observations";
  function resetMedia(){el("acoustic-file").value="";el("acoustic-work").value="";el("acoustic-result").textContent="";mediaOffset=0;mediaSelected=null;el("media-workspace").hidden=true;el("media-list").replaceChildren();el("media-candidates").replaceChildren();el("media-review").hidden=true;el("media-form").reset();el("media-review").reset();}
  async function openMedia(){resetMedia();el("media-workspace").hidden=false;el("acoustic-workspace").hidden=!["admin","manager"].includes(identity?.role);el("acoustic-enroll").hidden=identity?.role!=="admin";el("media-form").hidden=!["admin","manager"].includes(identity?.role);await loadMedia(0);}
  async function loadMedia(nextOffset=mediaOffset){const rows=await api(mediaBase+"?limit=20&offset="+nextOffset,"GET",undefined,true);if(!token)return;mediaOffset=nextOffset;const list=el("media-list");list.replaceChildren();
    for(const row of rows){const item=document.createElement("article");item.className="tenant-card";const title=document.createElement("strong");title.textContent=row.reported_title+" — "+row.reported_artist;item.append(title);for(const value of [row.external_reference,row.aired_at+" · "+row.duration_seconds+" s",({pending:"À vérifier",matched:"Correspondance retenue",unmatched:"Non identifié"})[row.status],row.work_id?"Œuvre : "+row.work_id:""]){if(!value)continue;const p=document.createElement("p");p.textContent=value;item.append(p);}
    if(row.status==="pending"){const button=document.createElement("button");button.type="button";button.textContent="Rechercher dans le catalogue";button.addEventListener("click",()=>run(()=>loadMediaCandidates(row)));item.append(button);}list.append(item);}
    if(!rows.length){const p=document.createElement("p");p.textContent="Aucun relevé sur cette page.";list.append(p);}el("media-prev").disabled=mediaOffset===0;el("media-next").disabled=rows.length<20;el("media-page").textContent="Page "+(mediaOffset/20+1);
  }
  async function loadMediaCandidates(row){mediaSelected=null;el("media-review").hidden=true;el("media-candidates").replaceChildren();const result=await api(mediaBase+"/"+encodeURIComponent(row.id)+"/candidates","GET",undefined,true);if(!token)return;mediaSelected=row;const list=el("media-candidates");const heading=document.createElement("p");heading.textContent="Suggestions par titre exact : "+row.reported_title+" (audio non vérifié)";list.append(heading);for(const candidate of result.candidates){const button=document.createElement("button");button.type="button";button.textContent=candidate.title+" · "+candidate.id;button.addEventListener("click",()=>{if(!busy){el("media-work").value=candidate.id;el("media-decision").value="matched";}});list.append(button);}el("media-review").reset();el("media-review").hidden=identity?.role!=="admin";}
  el("media-refresh").addEventListener("click",()=>run(()=>loadMedia()));
  el("media-prev").addEventListener("click",()=>run(()=>loadMedia(Math.max(0,mediaOffset-20))));
  el("media-next").addEventListener("click",()=>run(()=>loadMedia(mediaOffset+20)));
  action("media-form",async()=>{await api(mediaBase,"POST",{operator_id:el("media-operator").value.trim(),external_reference:el("media-ref").value,aired_at:new Date(el("media-date").value).toISOString(),duration_seconds:Number(el("media-duration").value),reported_title:el("media-title").value,reported_artist:el("media-artist").value},true);if(!token)return;el("media-form").reset();await loadMedia(0);notice("Relevé enregistré.");});
  action("media-review",async()=>{if(!mediaSelected)return;const decision=el("media-decision").value;await api(mediaBase+"/"+encodeURIComponent(mediaSelected.id)+"/review","POST",{decision,work_id:decision==="matched"?el("media-work").value.trim():null},true);if(!token)return;mediaSelected=null;el("media-review").hidden=true;el("media-candidates").replaceChildren();await loadMedia();notice("Décision enregistrée.");});

  const analyticsNames={artists:"Artistes",works:"Œuvres",licenses:"Exploitants et licences",field_control:"Contrôle terrain",media:"Diffusions",finance:"Recouvrement",royalties:"Répartitions"};
  const metricNames={total:"Total",active:"Actifs",registered:"Enregistrées",operators:"Exploitants",licenses:"Licences",effective:"En vigueur",visits:"Visites",suspected:"Non-conformités présumées",observations:"Diffusions",matched:"Rapprochées",unmatched:"Non identifiées",pending:"En attente",invoices:"Créances",billed_minor:"Facturé",received_minor:"Encaissé déclaré",outstanding_minor:"Solde",overdue_minor:"En retard",distributions:"Répartitions",gross_minor:"Brut",commission_minor:"Commissions",net_minor:"Net"};
  function resetAnalytics(){el("analytics-workspace").hidden=true;el("analytics-sections").replaceChildren();el("analytics-asof").textContent="";}
  async function openAnalytics(){resetAnalytics();el("analytics-workspace").hidden=false;await loadAnalytics();}
  function addMetric(parent,key,value){const p=document.createElement("p");p.textContent=(metricNames[key]||key)+" : "+String(value);parent.append(p);}
  async function loadAnalytics(){const result=await api("/api/v1/analytics/summary","GET",undefined,true);if(!token)return;el("analytics-asof").textContent="Actualisation : "+result.as_of+" — lectures successives";const list=el("analytics-sections");list.replaceChildren();for(const [key,data] of Object.entries(result.sections)){const item=document.createElement("article");item.className="tenant-card";const heading=document.createElement("h4");heading.textContent=analyticsNames[key]||key;item.append(heading);if(data.currencies){for(const currency of data.currencies){const title=document.createElement("strong");title.textContent=currency.currency+" — montants en unités minimales";item.append(title);for(const [k,v] of Object.entries(currency))if(k!=="currency")addMetric(item,k,v);}if(!data.currencies.length){const p=document.createElement("p");p.textContent="Aucune opération.";item.append(p);}}else for(const [k,v] of Object.entries(data))addMetric(item,k,v);list.append(item);}if(!Object.keys(result.sections).length){const p=document.createElement("p");p.textContent="Aucun module métier actif.";list.append(p);}}
  el("analytics-refresh").addEventListener("click",()=>run(loadAnalytics));

  const exchangeBase="/api/v1/exchange";
  let exchangeValidated=null;
  function resetExchange(){exchangeValidated=null;el("exchange-workspace").hidden=true;el("exchange-output").value="";el("exchange-input").value="";el("exchange-report").textContent="";el("exchange-commit").disabled=true;}
  function openExchange(){resetExchange();el("exchange-workspace").hidden=false;el("exchange-form").hidden=identity?.role!=="admin";}
  async function exportExchange(dataset){const offset=Number(el("exchange-offset").value);if(!Number.isInteger(offset)||offset<0||offset>1000000)throw new Error("Décalage invalide.");const result=await api(exchangeBase+"/"+dataset+"?limit=100&offset="+offset,"GET",undefined,true);if(token)el("exchange-output").value=JSON.stringify(result,null,2);}
  el("exchange-artists").addEventListener("click",()=>run(()=>exportExchange("artists")));
  el("exchange-works").addEventListener("click",()=>run(()=>exportExchange("works")));
  el("exchange-input").addEventListener("input",()=>{exchangeValidated=null;el("exchange-commit").disabled=true;el("exchange-report").textContent="";});
  action("exchange-form",async()=>{exchangeValidated=null;el("exchange-commit").disabled=true;const raw=el("exchange-input").value;const catalog=JSON.parse(raw);const report=await api(exchangeBase+"/import","POST",{catalog,dry_run:true},true);if(!token)return;el("exchange-report").textContent=JSON.stringify(report,null,2);if(report.valid&&raw===el("exchange-input").value){exchangeValidated=raw;el("exchange-commit").disabled=false;}});
  el("exchange-commit").addEventListener("click",()=>run(async()=>{if(!exchangeValidated||exchangeValidated!==el("exchange-input").value)return;if(!window.confirm("Importer les nouveaux éléments sans écraser les fiches existantes ?"))return;const catalog=JSON.parse(exchangeValidated);exchangeValidated=null;el("exchange-commit").disabled=true;const report=await api(exchangeBase+"/import","POST",{catalog,dry_run:false},true);if(token)el("exchange-report").textContent=JSON.stringify(report,null,2);}));
  async function acousticRequest(enroll){
    const file=el("acoustic-file").files[0];if(!file||file.size>480044)throw new Error("Sélectionner un WAV de taille autorisée.");
    const path=enroll?"/api/v1/acoustic/references/"+encodeURIComponent(el("acoustic-work").value.trim()):"/api/v1/acoustic/match";
    if(enroll&&!window.confirm("Confirmer que cet extrait peut être utilisé comme référence ?"))return;
    const session=token;
    const response=await fetch(path,{method:"POST",headers:{Authorization:"Bearer "+session,"Content-Type":"audio/wav",Accept:"application/json"},body:file,cache:"no-store",credentials:"omit",redirect:"error"});
    if(!token||token!==session)return;
    if(!response.ok){const err=new Error("Échec de comparaison ou enregistrement (HTTP "+response.status+").");err.status=response.status;throw err;}
    const result=await response.json();if(token===session)el("acoustic-result").textContent=JSON.stringify(result,null,2);
  }
  el("acoustic-enroll").addEventListener("click",()=>run(()=>acousticRequest(true)));
  el("acoustic-match").addEventListener("click",()=>run(()=>acousticRequest(false)));
  el("saved").addEventListener("change",()=>el("finish").disabled=!el("saved").checked);
  el("finish").addEventListener("click",()=>{clearSession();show("login");notice("MFA activé. Reconnectez-vous avec un nouveau code TOTP.");});
  el("open-invite").addEventListener("click",()=>{if(!busy)show("invite");});
  el("enable-mfa").addEventListener("click",()=>show("mfa"));
  document.querySelectorAll("[data-back]").forEach(b=>b.addEventListener("click",()=>{if(!busy){el("invite-form").reset();show("login");}}));
  document.querySelectorAll("[data-logout]").forEach(b=>b.addEventListener("click",async()=>{if(busy)return;busy=true;let failed=false;try{await api("/api/v1/auth/logout","POST",undefined,true);}catch{failed=true;}finally{clearSession();show("login");busy=false;notice(failed?"Session locale fermée. La révocation serveur n’a pas pu être confirmée.":"Vous êtes déconnecté.",failed);}}));
})();
