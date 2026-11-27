"use strict";
const CACHE="rights360-field-shell-v2";
const SHELL=["/portal","/portal.css","/portal.js","/offline.js","/field-manifest.json","/field-icon.svg"];
self.addEventListener("install",event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(SHELL))));
self.addEventListener("activate",event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith("rights360-field-shell-")&&k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener("fetch",event=>{const req=event.request,url=new URL(req.url);if(req.method!=="GET"||url.origin!==self.location.origin||url.search||!SHELL.includes(url.pathname)||req.headers.has("Authorization"))return;event.respondWith(fetch(req).catch(()=>caches.match(url.pathname).then(result=>result||Response.error())));});
