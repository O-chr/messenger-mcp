#!/usr/bin/env node
import express from "express";
import { randomUUID } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { buildServer } from "./server.js";
import { CliBackend, type Backend } from "./backend.js";
import { toolPerms } from "./policy.js";
import { GoogleGatedProvider } from "./auth.js";

export function createHTTPApp(provider:OAuthServerProvider,publicUrl:string,backend:Backend){
  const origin=new URL(publicUrl).origin;
  const app=createMcpExpressApp({host:"127.0.0.1",allowedHosts:[new URL(publicUrl).hostname,"127.0.0.1","localhost"]});
  app.disable("x-powered-by");
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
      const back=await provider.handleGoogleCallback(String(req.query.code??""),String(req.query.state??""));res.redirect(back);
    }catch{res.status(403).type("text").send("Google login was not accepted. Use the configured owner's account or restart the login flow.");}
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
    const {server}=buildServer({backend});
    let record:Session;
    const transport=new StreamableHTTPServerTransport({sessionIdGenerator:randomUUID,onsessioninitialized:sid=>{sessions.set(sid,record);}});
    record={transport,server,clientId:req.auth!.clientId,lastUsed:Date.now()};
    transport.onclose=()=>{if(transport.sessionId)sessions.delete(transport.sessionId);};
    try{await server.connect(transport);await transport.handleRequest(req,res,req.body);}catch{await server.close();if(!res.headersSent)res.status(500).json({error:"MCP initialization failed"});}
  });
  const cleanup=setInterval(()=>{for(const [id,s]of sessions)if(Date.now()-s.lastUsed>30*60_000){sessions.delete(id);void s.server.close();}},60_000);cleanup.unref();
  return {app,close:async()=>{clearInterval(cleanup);for(const s of sessions.values())await s.server.close();sessions.clear();backend.close();}};
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
