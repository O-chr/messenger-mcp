import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {GoogleGatedProvider} from './auth.js';
import {createHTTPApp} from './http.js';
import type {Config} from './policy.js';

test('web confirmation hides body before Google owner login; cookie, CSRF, origin, revocation and single-use POST enforced',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'messenger-web-'));chmodSync(dir,0o700);
 const cfg:Config={version:1,permissions:['read','write'],confirm_send:true,chats:{'100':{name:'Friend',kind:'dm',jid:'999@msgr',read:true,write:true}}};
 const originalFetch=globalThis.fetch;let claims:Record<string,unknown>={},sends=0,restores=0;
 globalThis.fetch=(async(input:Parameters<typeof fetch>[0],init?:RequestInit)=>String(input)==='https://oauth2.googleapis.com/token'?new Response(JSON.stringify({id_token:'id-token'}),{headers:{'content-type':'application/json'}}):originalFetch(input,init)) as typeof fetch;
 const provider=new GoogleGatedProvider({publicUrl:'https://messenger.example.test',clientId:'google-client',clientSecret:'google-secret',allowedEmail:'owner@example.test',store:join(dir,'oauth.json'),verifyGoogleToken:async()=>claims});
 const {app,close,confirmations}=createHTTPApp(provider,'https://messenger.example.test',{request:async(op,args)=>{if(op==='status')return {connected:true,history_ready:false};if(op==='restore_history'){restores++;assert.equal(args?.pin,'123456');return {history_ready:true};}sends++;return {status:'server_acknowledged'};},close(){}},()=>cfg);
 const listener=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>listener.once('listening',resolve));const base=`http://127.0.0.1:${(listener.address() as {port:number}).port}`;
 const request=(path:string,init?:RequestInit)=>fetch(base+path,{redirect:'manual',...init});
 async function login(id:string,email='owner@example.test'){
   const r=await request('/confirm/'+id);assert.equal(r.status,302);const google=new URL(r.headers.get('location')!);assert.equal(google.origin,'https://accounts.google.com');
   claims={aud:'google-client',nonce:google.searchParams.get('nonce'),email,email_verified:true};
   return request('/oauth/google/callback?code=google-code&state='+google.searchParams.get('state'));
 }
 async function ready(id:string){const r=await login(id);assert.equal(r.status,302);const set=r.headers.get('set-cookie')!;assert.match(set,/HttpOnly/);assert.match(set,/Secure/);const cookie=set.split(';')[0];
  const page=await request('/confirm/'+id,{headers:{cookie}});assert.equal(page.status,200);assert.equal(page.headers.get('referrer-policy'),'same-origin');const html=await page.text();assert.match(html,/PRIVATE TEXT/);return {cookie,csrf:/name="csrf" value="([^"]+)"/.exec(html)![1]};}
 const post=(id:string,cookie:string,csrf:string,origin='https://messenger.example.test',decision='approve')=>request('/confirm/'+id,{method:'POST',headers:{cookie,origin,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,decision})});
 try{
  const setup=await request('/history/setup');assert.equal(setup.status,302);const su=new URL(setup.headers.get('location')!);
  claims={aud:'google-client',nonce:su.searchParams.get('nonce'),email:'owner@example.test',email_verified:true};
  const callback=await request('/oauth/google/callback?code=google-code&state='+su.searchParams.get('state'));assert.equal(callback.status,302);assert.equal(callback.headers.get('location'),'/history/setup');
  const hc=callback.headers.get('set-cookie')!.split(';')[0];assert.match(callback.headers.get('set-cookie')!,/Path=\/history/);
  const setupPage=await request('/history/setup',{headers:{cookie:hc}}),sh=await setupPage.text();assert.equal(setupPage.headers.get('referrer-policy'),'same-origin');assert.match(sh,/type="password"/);const sc=/name="csrf" value="([^"]+)"/.exec(sh)![1];
  const hp=(cookie:string,csrf:string,pin:string)=>request('/history/setup',{method:'POST',headers:{cookie,origin:'https://messenger.example.test','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,pin})});
  assert.equal((await hp('',sc,'123456')).status,403);assert.equal((await hp(hc,'bad','123456')).status,403);assert.equal((await hp(hc,sc,'not-pin')).status,400);assert.equal(restores,0);
  const restored=await hp(hc,sc,'123456');assert.equal(restored.status,200);assert.doesNotMatch(await restored.text(),/123456/);assert.equal(restores,1);assert.equal(sends,0);
  const p=confirmations!.create('client','100','PRIVATE TEXT <script>alert(1)</script>');
  const anonymous=await request('/confirm/'+p.confirmation_id);assert.equal(anonymous.status,302);assert.doesNotMatch(await anonymous.text(),/PRIVATE TEXT/);assert.equal(sends,0);
  assert.equal((await login(p.confirmation_id,'other@example.test')).status,403);
  const {cookie,csrf}=await ready(p.confirmation_id);
  assert.equal((await post(p.confirmation_id,'',csrf)).status,403);assert.equal((await post(p.confirmation_id,cookie,'bad')).status,403);
  assert.equal((await post(p.confirmation_id,cookie,'あ'.repeat(csrf.length))).status,403);
  assert.equal((await post(p.confirmation_id,cookie,csrf,'https://chatgpt.com')).status,403);assert.equal(sends,0);
  assert.equal((await post(p.confirmation_id,cookie,csrf,'null')).status,403);assert.equal(sends,0);
  const approved=await post(p.confirmation_id,cookie,csrf);assert.equal(approved.status,200);assert.doesNotMatch(await approved.text(),/<script>/);assert.equal(sends,1);
  await post(p.confirmation_id,cookie,csrf);assert.equal(sends,1);
  const revoked=confirmations!.create('client','100','PRIVATE TEXT revoked'),auth=await ready(revoked.confirmation_id);cfg.chats['100'].write=false;
  assert.equal((await post(revoked.confirmation_id,auth.cookie,auth.csrf)).status,403);assert.equal(sends,1);
 }finally{globalThis.fetch=originalFetch;await close();listener.closeAllConnections();await new Promise<void>(resolve=>listener.close(()=>resolve()));rmSync(dir,{recursive:true,force:true});}
});
