"use strict";
(() => {
  const el = id => document.getElementById(id);
  const views = ["login","invite","mfa","recovery","session"];
  let token = null, timer = null, busy = false;
  function notice(message="",error=false){el("notice").textContent=message;el("notice").classList.toggle("error",error);}
  function show(view){views.forEach(v=>{el(v+"-view").hidden=v!==view;});notice();}
  function clearSession(){token=null;clearTimeout(timer);timer=null;el("secret").textContent="";el("recovery").textContent="";el("saved").checked=false;el("finish").disabled=true;el("confirm-form").hidden=true;el("setup-form").hidden=false;document.querySelectorAll("form").forEach(f=>f.reset());}
  async function api(path,method="GET",data,authorized=false){
    const headers={Accept:"application/json"};
    if(data!==undefined)headers["Content-Type"]="application/json";
    if(authorized&&token)headers.Authorization="Bearer "+token;
    const response=await fetch(path,{method,headers,body:data===undefined?undefined:JSON.stringify(data),cache:"no-store",credentials:"omit",redirect:"error"});
    if(!response.ok){const messages={400:"Invitation invalide ou expirée.",401:"Identifiants, code de sécurité ou session invalides.",403:"Accès refusé.",409:"Cette opération est déjà effectuée ou incompatible.",422:"Vérifiez les informations saisies.",429:"Trop de tentatives. Réessayez dans une minute."};throw new Error(messages[response.status]||"Service indisponible. Réessayez ultérieurement.");}
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
      el("session-email").textContent=me.email;el("session-org").textContent=me.organization_id;el("session-role").textContent=({admin:"Administrateur",manager:"Gestionnaire",auditor:"Auditeur",artist:"Artiste"})[me.role]||me.role;el("session-mfa").textContent=me.mfa_enabled?"Activé":"Non activé";el("enable-mfa").hidden=me.mfa_enabled;show("session");
    }catch(err){clearSession();show("login");throw err;}
  });
  action("invite-form",async()=>{const result=await api("/api/v1/auth/"+el("invite-kind").value+"/accept","POST",{token:el("invite-token").value,password:el("invite-password").value});show("login");el("org").value=result.organization_id;notice("Compte activé. Connectez-vous avec votre email et votre nouveau mot de passe.");});
  action("setup-form",async()=>{const result=await api("/api/v1/auth/mfa/setup","POST",{password:el("setup-password").value},true);el("secret").textContent=result.secret;el("setup-form").hidden=true;el("confirm-form").hidden=false;});
  action("confirm-form",async()=>{const result=await api("/api/v1/auth/mfa/confirm","POST",{password:el("confirm-password").value,otp:el("otp").value},true);token=null;clearTimeout(timer);el("secret").textContent="";el("recovery").textContent=result.recovery_codes.join("\n");show("recovery");});
  el("saved").addEventListener("change",()=>el("finish").disabled=!el("saved").checked);
  el("finish").addEventListener("click",()=>{clearSession();show("login");notice("MFA activé. Reconnectez-vous avec un nouveau code TOTP.");});
  el("open-invite").addEventListener("click",()=>{if(!busy)show("invite");});
  el("enable-mfa").addEventListener("click",()=>show("mfa"));
  document.querySelectorAll("[data-back]").forEach(b=>b.addEventListener("click",()=>{if(!busy){el("invite-form").reset();show("login");}}));
  document.querySelectorAll("[data-logout]").forEach(b=>b.addEventListener("click",async()=>{if(busy)return;busy=true;let failed=false;try{await api("/api/v1/auth/logout","POST",undefined,true);}catch{failed=true;}finally{clearSession();show("login");busy=false;notice(failed?"Session locale fermée. La révocation serveur n’a pas pu être confirmée.":"Vous êtes déconnecté.",failed);}}));
})();
