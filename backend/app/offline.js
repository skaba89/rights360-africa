/* Encrypted, account-scoped visit drafts. No bearer tokens persisted. */
"use strict";
window.RightsOffline=(()=>{
  const enc=new TextEncoder(),dec=new TextDecoder();
  const open=()=>new Promise((resolve,reject)=>{const req=indexedDB.open("rights360-field-v1",1);req.onupgradeneeded=()=>req.result.createObjectStore("vault");req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);});
  async function access(mode,fn){const db=await open();try{return await new Promise((resolve,reject)=>{const tx=db.transaction("vault",mode),req=fn(tx.objectStore("vault"));tx.oncomplete=()=>resolve(req.result);tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error);});}finally{db.close();}}
  async function key(pass,salt){const material=await crypto.subtle.importKey("raw",enc.encode(pass),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:600000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);}
  async function unlock(scope,pass){if(pass.length<12)throw Error("Phrase secrète : 12 caractères minimum.");const record=await access("readonly",s=>s.get(scope));const salt=record?record.salt:crypto.getRandomValues(new Uint8Array(16));const secret=await key(pass,salt);let queue=[];if(record){const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:record.iv,additionalData:enc.encode(scope)},secret,record.cipher);queue=JSON.parse(dec.decode(plain));if(!Array.isArray(queue)||queue.length>50)throw Error("Coffre invalide.");}return {scope,salt,secret,queue};}
  async function save(vault,queue){const iv=crypto.getRandomValues(new Uint8Array(12));const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:enc.encode(vault.scope)},vault.secret,enc.encode(JSON.stringify(queue)));await access("readwrite",s=>s.put({salt:vault.salt,iv,cipher},vault.scope));}
  return {unlock,save};
})();
