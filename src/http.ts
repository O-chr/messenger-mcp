#!/usr/bin/env node
import express from "express";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { buildServer } from "./server.js";
import { CliBackend, type Backend } from "./backend.js";
import { toolPerms, loadConfig, type Config } from "./policy.js";
import { GoogleGatedProvider } from "./auth.js";
import { Confirmations, confirmationHTML } from "./confirmations.js";
import { historyPage } from "./history-page.js";

export function createHTTPApp(provider:OAuthServerProvider,publicUrl:string,backend:Backend,load:()=>Config=loadConfig){
  const origin=new URL(publicUrl).origin;
  const confirmations=provider instanceof GoogleGatedProvider?new Confirmations(publicUrl,backend,load):undefined;
  const app=createMcpExpressApp({host:"127.0.0.1",allowedHosts:[new URL(publicUrl).hostname,"127.0.0.1","localhost"]});
  app.disable("x-powered-by");
  // Only the local cloudflared hop is trusted; do not trust arbitrary proxies.
  app.set("trust proxy","loopback");
  app.use((req,res,next)=>{
    if(req.headers.origin && ![origin,"https://chatgpt.com","https://chat.openai.com"].includes(req.headers.origin)){res.status(403).json({error:"Origin denied"});return;}
    res.setHeader("Cache-Control","no-store");next();
  });
  app.get("/health",(_req,res)=>res.json({ok:true}));
  app.get("/.well-known/oauth-protected-resource",(_req,res)=>res.json({resource:`${publicUrl}/mcp`,authorization_servers:[`${publicUrl}/`],bearer_methods_supported:["header"],scopes_supported:["messenger:tools"]}));
  app.use(mcpAuthRouter({provider,issuerUrl:new URL(publicUrl),resourceServerUrl:new URL(`${publicUrl}/mcp`),scopesSupported:["messenger:tools"]}));
  app.get("/oauth/google/callback",async(req,res)=>{
    try{
      if(!(provider instanceof GoogleGatedProvider)){res.sendStatus(404);return;}
      const state=String(req.query.state??""),code=String(req.query.code??"");
      if(provider.isOwnerConfirmationCallback(state)){
        const s=await provider.finishOwnerConfirmation(code,state);
        const history=s.approvalId==="history-setup";
        res.cookie("__Secure-messenger-confirm",s.cookie,{httpOnly:true,secure:true,sameSite:"lax",path:history?"/history":"/confirm",maxAge:600_000});
        res.redirect(history?"/history/setup":`/confirm/${s.approvalId}`);return;
      }
      const back=await provider.handleGoogleCallback(code,state);res.redirect(back);
    }catch{res.status(403).type("text").send("Google login was not accepted. Use the configured owner's account or restart the login flow.");}
  });
  const webSession=(cookie:string|undefined,id:string)=>{
    if(!(provider instanceof GoogleGatedProvider))return undefined;
    const value=cookie?.split(";").map(v=>v.trim()).find(v=>v.startsWith("__Secure-messenger-confirm="))?.slice("__Secure-messenger-confirm=".length);
    return value?provider.ownerConfirmationSession(value,id):undefined;
  };
  const protectPage=(res:express.Response)=>{
    res.setHeader("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    // no-referrer makes Chrome navigation POSTs send Origin:null. same-origin
    // keeps strict POST origin checks while suppressing cross-site referrers.
    res.setHeader("Referrer-Policy","same-origin");res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("X-Frame-Options","DENY");
  };
  app.get("/confirm/:id",(req,res)=>{
    protectPage(res);const id=String(req.params.id);
    if(!confirmations?.has(id)||!(provider instanceof GoogleGatedProvider)){res.status(404).send("Confirmation expired or unavailable.");return;}
    const owner=webSession(req.headers.cookie,id);
    if(!owner){try{res.redirect(provider.beginOwnerConfirmation(id));}catch{res.status(429).send("Restart confirmation later.");}return;}
    try{res.type("html").send(confirmationHTML(confirmations.describe(id),owner.csrf));}catch{res.status(403).send("Permission revoked or confirmation expired. Not sent.");}
  });
  let restoringHistory=false;
  app.get("/history/setup",async(req,res)=>{
    protectPage(res);if(!(provider instanceof GoogleGatedProvider)){res.sendStatus(404);return;}
    const owner=webSession(req.headers.cookie,"history-setup");
    if(!owner){try{res.redirect(provider.beginOwnerConfirmation("history-setup"));}catch{res.sendStatus(429);}return;}
    try{const status=await backend.request("status") as {history_ready?:boolean};res.type("html").send(historyPage(owner.csrf,status.history_ready===true));}catch{res.status(503).send("Messenger connection unavailable. No PIN was requested.");}
  });
  app.post("/history/setup",express.urlencoded({extended:false,limit:"2kb"}),async(req,res)=>{
    protectPage(res);const owner=webSession(req.headers.cookie,"history-setup");const csrf=Buffer.from(typeof req.body?.csrf==="string"?req.body.csrf:"");
    const expected=Buffer.from(owner?.csrf??"");
    if(!owner||req.headers.origin!==origin||csrf.length!==expected.length||!timingSafeEqual(csrf,expected)){res.status(403).send("Owner login required.");return;}
    const pin=typeof req.body?.pin==="string"?req.body.pin:"";if(req.body)req.body.pin="";
    if(!/^[0-9]{6}$/.test(pin)){res.status(400).type("html").send(historyPage(owner.csrf,false,"6桁のPINを入力してください。"));return;}
    if(restoringHistory){res.status(409).send("History setup is already in progress. Do not retry.");return;}
    restoringHistory=true;
    try{
      // The backend connects on demand after checking permissions. Idle status
      // is normally disconnected and must not block the owner's first setup.
      const result=await backend.request("restore_history",{pin}) as {history_ready?:boolean};
      res.type("html").send(historyPage(owner.csrf,result.history_ready===true));
    }catch(e){const message=e instanceof Error?e.message.replaceAll(pin,"[redacted]"):"History setup failed. No automatic retry.";res.status(400).type("html").send(historyPage(owner.csrf,false,message));}
    finally{restoringHistory=false;}
  });
  app.post("/confirm/:id",express.urlencoded({extended:false,limit:"2kb"}),async(req,res)=>{
    protectPage(res);const id=String(req.params.id),owner=webSession(req.headers.cookie,id);
    const csrf=typeof req.body?.csrf==="string"?req.body.csrf:"";
    const actual=Buffer.from(csrf),expected=Buffer.from(owner?.csrf??"");
    if(!confirmations||!owner||req.headers.origin!==origin||actual.length!==expected.length||!timingSafeEqual(actual,expected)){res.status(403).send("Owner confirmation required. Not sent.");return;}
    try{
      if(req.body.decision==="approve")await confirmations.approve(id);
      else if(req.body.decision==="decline")confirmations.decline(id);
      else{res.status(400).send("Invalid decision. Not sent.");return;}
      res.type("html").send(confirmationHTML(confirmations.describe(id),owner.csrf));
    }catch{res.status(403).send("Permission revoked or confirmation expired. Not sent.");}
  });
  type Session={transport:StreamableHTTPServerTransport;server:ReturnType<typeof buildServer>["server"];clientId:string;lastUsed:number};
  const sessions=new Map<string,Session>();
  const auth=requireBearerAuth({verifier:provider,requiredScopes:["messenger:tools"],resourceMetadataUrl:`${publicUrl}/.well-known/oauth-protected-resource/mcp`});
  app.all("/mcp",auth,async(req,res)=>{
    const id=req.headers["mcp-session-id"];
    if(typeof id==="string"){
      const session=sessions.get(id);
      if(!session||session.clientId!==req.auth!.clientId){res.status(404).json({error:"Unknown MCP session"});return;}
      session.lastUsed=Date.now();
      try{await session.transport.handleRequest(req,res,req.body);}catch{if(!res.headersSent)res.status(500).json({error:"MCP request failed"});}
      return;
    }
    if(req.method!=="POST"||req.body?.method!=="initialize"){res.status(400).json({error:"Initialize an authenticated MCP session first"});return;}
    if(sessions.size>=30){res.status(429).json({error:"Too many MCP sessions"});return;}
    const {server}=buildServer({backend,load,confirmations,clientId:req.auth!.clientId});
    let record:Session;
    const transport=new StreamableHTTPServerTransport({sessionIdGenerator:randomUUID,onsessioninitialized:sid=>{sessions.set(sid,record);}});
    record={transport,server,clientId:req.auth!.clientId,lastUsed:Date.now()};
    transport.onclose=()=>{if(transport.sessionId)sessions.delete(transport.sessionId);};
    try{await server.connect(transport);await transport.handleRequest(req,res,req.body);}catch{await server.close();if(!res.headersSent)res.status(500).json({error:"MCP initialization failed"});}
  });
  const cleanup=setInterval(()=>{confirmations?.prune();for(const [id,s]of sessions)if(Date.now()-s.lastUsed>30*60_000){sessions.delete(id);void s.server.close();}},60_000);cleanup.unref();
  return {app,confirmations,close:async()=>{clearInterval(cleanup);for(const s of sessions.values())await s.server.close();sessions.clear();backend.close();}};
}

if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1]){
  const need=(key:string)=>{const value=process.env[key];if(!value)throw new Error(`Missing ${key}`);return value;};
  const publicUrl=need("MESSENGER_MCP_PUBLIC_URL").replace(/\/$/,"");if(new URL(publicUrl).protocol!=="https:")throw new Error("Public URL must use HTTPS.");
  const path=need("GOOGLE_OAUTH_JSON"),st=lstatSync(path);if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077))throw new Error("Google OAuth file must be private.");
  const google=JSON.parse(readFileSync(path,"utf8")).web;
  const provider=new GoogleGatedProvider({clientId:google.client_id,clientSecret:google.client_secret,publicUrl,allowedEmail:need("MESSENGER_MCP_ALLOWED_EMAIL")});
  const backend=new CliBackend([...toolPerms()].join(","));
  void backend.request("status").catch(()=>console.error("Messenger receiver could not connect. Check the local profile before use."));
  const {app,close}=createHTTPApp(provider,publicUrl,backend);
  const port=Number(process.env.PORT??8791);if(!Number.isInteger(port)||port<1024||port>65535)throw new Error("Invalid port.");
  const listener=app.listen(port,"127.0.0.1",()=>console.error(`Messenger MCP listening on 127.0.0.1:${port}`));
  const stop=()=>{listener.close();void close().finally(()=>process.exit(0));};process.once("SIGTERM",stop);process.once("SIGINT",stop);
}
