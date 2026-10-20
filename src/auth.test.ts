import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,chmodSync,rmSync,readFileSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import type {Response} from 'express';
import {GoogleGatedProvider} from './auth.js';
import {createHTTPApp} from './http.js';
import type {OAuthClientInformationFull} from '@modelcontextprotocol/sdk/shared/auth.js';

test('owner OAuth, PKCE, resource binding, rotation and authenticated session isolation',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'messenger-auth-'));chmodSync(dir,0o700);const store=join(dir,'oauth.json');
 let claims:Record<string,unknown>={},email='owner@example.test';const originalFetch=globalThis.fetch;
 globalThis.fetch=(async(input:Parameters<typeof fetch>[0],init?:RequestInit)=>{
   if(String(input)==='https://oauth2.googleapis.com/token')return new Response(JSON.stringify({id_token:'test-id-token'}),{status:200,headers:{'content-type':'application/json'}});
   return originalFetch(input,init);
 }) as typeof fetch;
 const p=new GoogleGatedProvider({publicUrl:'https://messenger.example.test',allowedEmail:'owner@example.test',clientId:'google-client',clientSecret:'google-secret',store,verifyGoogleToken:async()=>claims});
 const backend={request:async()=>({ok:true}),close(){}};const {app,close}=createHTTPApp(p,'https://messenger.example.test',backend);
 const listener=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>listener.once('listening',resolve));const port=(listener.address() as {port:number}).port;const base=`http://127.0.0.1:${port}`;
 const verifier='abcdefghijklmnopqrstuvwxyz0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ';const challenge=createHash('sha256').update(verifier).digest('base64url');
 const register=()=>p.clientsStore.registerClient({redirect_uris:['https://client.example.test/callback'],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']});
 async function code(client:OAuthClientInformationFull){let google='';await p.authorize(client,{redirectUri:client.redirect_uris[0],codeChallenge:challenge,state:'client-state',scopes:['messenger:tools'],resource:p.resource},{redirect:(s:string)=>{google=s;}} as Response);
   const u=new URL(google);claims={aud:'google-client',nonce:u.searchParams.get('nonce'),email,email_verified:true};return new URL(await p.handleGoogleCallback('google-code',u.searchParams.get('state')!)).searchParams.get('code')!;
 }
 const tokenRequest=(c:OAuthClientInformationFull,value:string,v=verifier)=>fetch(`${base}/token`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:c.client_id,code:value,code_verifier:v,redirect_uri:c.redirect_uris[0],resource:p.resource.href})});
 try{
   assert.equal((await fetch(`${base}/mcp`)).status,401);
   assert.equal((await fetch(`${base}/mcp`,{headers:{authorization:'Bearer invalid'}})).status,401);
   assert.equal((await fetch(`${base}/health`,{headers:{origin:'https://evil.example.test'}})).status,403);
   assert.throws(()=>p.clientsStore.registerClient({redirect_uris:['http://evil.example.test/cb']}));
   const c=register();email='wrong@example.test';await assert.rejects(()=>code(c));email='owner@example.test';
   const value=await code(c);assert.equal((await tokenRequest(c,value,'wrong-verifier')).status,400);
   const response=await tokenRequest(c,value);assert.equal(response.status,200);const tokens=await response.json() as {access_token:string;refresh_token:string};
   assert.equal((await p.verifyAccessToken(tokens.access_token)).clientId,c.client_id);await assert.rejects(()=>p.verifyAccessToken(tokens.refresh_token));
   await assert.rejects(()=>p.exchangeRefreshToken(c,tokens.refresh_token,undefined,new URL('https://other.example.test/mcp')));
   const next=await p.exchangeRefreshToken(c,tokens.refresh_token,undefined,p.resource);await assert.rejects(()=>p.exchangeRefreshToken(c,tokens.refresh_token));
   const stored=readFileSync(store,'utf8');assert.ok(!stored.includes(tokens.access_token)&&!stored.includes(next.refresh_token!));assert.equal(statSync(store).mode&0o777,0o600);
   const c2=register(),v2=await code(c2),t2=await p.exchangeAuthorizationCode(c2,v2,undefined,c2.redirect_uris[0],p.resource);
   const initialize=await fetch(`${base}/mcp`,{method:'POST',headers:{authorization:`Bearer ${next.access_token}`,'content-type':'application/json',accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'test',version:'1'}}})});
   assert.equal(initialize.status,200);const sid=initialize.headers.get('mcp-session-id');assert.ok(sid);await initialize.text();
   const foreign=await fetch(`${base}/mcp`,{method:'POST',headers:{authorization:`Bearer ${t2.access_token}`,'mcp-session-id':sid!,'content-type':'application/json',accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/list',params:{}})});assert.equal(foreign.status,404);
   await p.revokeToken(c,{token:next.access_token});await assert.rejects(()=>p.verifyAccessToken(next.access_token));
 }finally{globalThis.fetch=originalFetch;await close();listener.closeAllConnections();await new Promise<void>(resolve=>listener.close(()=>resolve()));rmSync(dir,{recursive:true,force:true});}
});
