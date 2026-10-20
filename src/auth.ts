import { createHash, randomBytes } from "node:crypto";
import { lstatSync, readFileSync, mkdirSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type { Response } from "express";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { InvalidTokenError, InvalidGrantError, InvalidTargetError, InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export interface GoogleCfg {clientId:string;clientSecret:string;publicUrl:string;allowedEmail:string;store?:string;verifyGoogleToken?:(idToken:string)=>Promise<JWTPayload>}
type Pending={client:OAuthClientInformationFull;params:AuthorizationParams;nonce:string;verifier:string;expires:number};
type Code={clientId:string;challenge:string;redirect:string;expires:number};
type Token={clientId:string;expires:number;refresh:boolean;resource:string};
type Data={version:1;clients:Record<string,OAuthClientInformationFull>;tokens:Record<string,Token>};
const hash=(s:string)=>createHash("sha256").update(s).digest("hex");
const rand=()=>randomBytes(32).toString("base64url");
const now=()=>Math.floor(Date.now()/1000);
export class GoogleGatedProvider implements OAuthServerProvider {
  readonly resource:URL;
  private data:Data={version:1,clients:{},tokens:{}};
  private pending=new Map<string,Pending>();
  private codes=new Map<string,Code>();
  private webPending=new Map<string,{approvalId:string;nonce:string;verifier:string;expires:number}>();
  private webSessions=new Map<string,{approvalId:string;csrf:string;expires:number}>();
  private store:string;
  private jwks=createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));
  constructor(private cfg:GoogleCfg){
    this.resource=new URL(`${cfg.publicUrl}/mcp`);
    this.store=cfg.store??join(homedir(),".config","messenger-personal-mcp","oauth.json");
    try{
      const st=lstatSync(this.store);if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)||st.size>2*1024*1024)throw new Error("private store required");
      const d=JSON.parse(readFileSync(this.store,"utf8"));if(d.version!==1||!d.clients||!d.tokens)throw new Error("invalid store");this.data=d;
    }catch(e){if((e as NodeJS.ErrnoException).code!=="ENOENT")throw new Error("OAuth store is invalid or not private.");}
  }
  private save(){
    const dir=dirname(this.store);mkdirSync(dir,{recursive:true,mode:0o700});
    const st=lstatSync(dir);if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077))throw new Error("OAuth directory must be private.");
    const temp=join(dir,`.oauth-${rand()}`);
    try{writeFileSync(temp,JSON.stringify(this.data),{mode:0o600,flag:"wx"});renameSync(temp,this.store);}finally{try{unlinkSync(temp);}catch{}}
  }
  private validateResource(resource?:URL){if(resource&&resource.href!==this.resource.href)throw new InvalidTargetError("Unexpected MCP resource.");}
  get clientsStore(){return {
    getClient:(id:string)=>Object.hasOwn(this.data.clients,id)?this.data.clients[id]:undefined,
    registerClient:(c:Omit<OAuthClientInformationFull,"client_id"|"client_id_issued_at">)=>{
      if(Object.keys(this.data.clients).length>=500)throw new InvalidClientMetadataError("Client registration limit reached.");
      for(const redirect of c.redirect_uris){const u=new URL(redirect);if(u.username||u.password||u.hash||!(u.protocol==="https:"||(u.protocol==="http:"&&["localhost","127.0.0.1","[::1]"].includes(u.hostname))))throw new InvalidClientMetadataError("HTTPS or loopback redirect required.");}
      const auth=c.token_endpoint_auth_method??"none";
      const full={...c,client_id:rand(),client_id_issued_at:now(),token_endpoint_auth_method:auth,...(auth!=="none"?{client_secret:rand()}:{} )} as OAuthClientInformationFull;
      this.data.clients[full.client_id]=full;this.save();return full;
    },
  };}
  async authorize(client:OAuthClientInformationFull,params:AuthorizationParams,res:Response){
    this.validateResource(params.resource);
    for(const [k,p]of this.pending)if(p.expires<now())this.pending.delete(k);
    for(const [k,p]of this.codes)if(p.expires<now())this.codes.delete(k);
    if(this.pending.size>=100)throw new InvalidGrantError("Too many pending logins.");
    const state=rand(),nonce=rand(),verifier=rand();
    this.pending.set(state,{client,params,nonce,verifier,expires:now()+600});
    res.redirect(this.googleURL(state,nonce,verifier));
  }
  private googleURL(state:string,nonce:string,verifier:string){
    const u=new URL("https://accounts.google.com/o/oauth2/v2/auth");
    u.search=new URLSearchParams({client_id:this.cfg.clientId,redirect_uri:`${this.cfg.publicUrl}/oauth/google/callback`,response_type:"code",scope:"openid email",state,nonce,code_challenge:createHash("sha256").update(verifier).digest("base64url"),code_challenge_method:"S256",prompt:"select_account"}).toString();
    return u.href;
  }
  async handleGoogleCallback(code:string,state:string){
    const p=this.pending.get(state);this.pending.delete(state);
    if(!p||p.expires<now()||!code)throw new InvalidGrantError("Login expired.");
    await this.verifyOwner(code,p.nonce,p.verifier);
    const value=rand();this.codes.set(value,{clientId:p.client.client_id,challenge:p.params.codeChallenge,redirect:p.params.redirectUri,expires:now()+300});
    const back=new URL(p.params.redirectUri);back.searchParams.set("code",value);if(p.params.state)back.searchParams.set("state",p.params.state);return back.href;
  }
  private async verifyOwner(code:string,nonce:string,verifier:string){
    const r=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({code,client_id:this.cfg.clientId,client_secret:this.cfg.clientSecret,redirect_uri:`${this.cfg.publicUrl}/oauth/google/callback`,grant_type:"authorization_code",code_verifier:verifier}),signal:AbortSignal.timeout(20000)});
    if(!r.ok)throw new InvalidGrantError("Google login failed.");
    const token=(await r.json() as {id_token?:string}).id_token;if(!token)throw new InvalidGrantError("Google login failed.");
    const claims=this.cfg.verifyGoogleToken?await this.cfg.verifyGoogleToken(token):(await jwtVerify(token,this.jwks,{audience:this.cfg.clientId,issuer:["https://accounts.google.com","accounts.google.com"]})).payload;
    if(claims.aud!==this.cfg.clientId||claims.nonce!==nonce||claims.email_verified!==true||typeof claims.email!=="string"||claims.email.toLowerCase()!==this.cfg.allowedEmail.toLowerCase())throw new InvalidGrantError("This Google account is not allowed.");
  }
  beginOwnerConfirmation(approvalId:string){
    for(const [k,p]of this.webPending)if(p.expires<now())this.webPending.delete(k);
    for(const [k,p]of this.webSessions)if(p.expires<now())this.webSessions.delete(k);
    if(this.webPending.size>=100)throw new InvalidGrantError("Too many pending confirmations.");
    const state=rand(),nonce=rand(),verifier=rand();this.webPending.set(state,{approvalId,nonce,verifier,expires:now()+600});
    return this.googleURL(state,nonce,verifier);
  }
  isOwnerConfirmationCallback(state:string){return this.webPending.has(state);}
  async finishOwnerConfirmation(code:string,state:string){
    const p=this.webPending.get(state);this.webPending.delete(state);
    if(!p||p.expires<now()||!code)throw new InvalidGrantError("Confirmation login expired.");
    await this.verifyOwner(code,p.nonce,p.verifier);
    const cookie=rand();this.webSessions.set(hash(cookie),{approvalId:p.approvalId,csrf:rand(),expires:now()+600});
    return {approvalId:p.approvalId,cookie};
  }
  ownerConfirmationSession(cookie:string,approvalId:string){
    const s=this.webSessions.get(hash(cookie));return s&&s.expires>=now()&&s.approvalId===approvalId?{csrf:s.csrf}:undefined;
  }
  async challengeForAuthorizationCode(client:OAuthClientInformationFull,code:string){
    const c=this.codes.get(code);if(!c||c.expires<now()||c.clientId!==client.client_id)throw new InvalidGrantError("Invalid code.");return c.challenge;
  }
  private issue(clientId:string):OAuthTokens{
    const access=rand(),refresh=rand();
    this.data.tokens[hash(access)]={clientId,expires:now()+3600,refresh:false,resource:this.resource.href};
    this.data.tokens[hash(refresh)]={clientId,expires:now()+30*86400,refresh:true,resource:this.resource.href};
    for(const [k,t]of Object.entries(this.data.tokens))if(t.expires<now())delete this.data.tokens[k];this.save();
    return {access_token:access,token_type:"Bearer",expires_in:3600,refresh_token:refresh,scope:"messenger:tools"};
  }
  async exchangeAuthorizationCode(client:OAuthClientInformationFull,code:string,_verifier?:string,redirect?:string,resource?:URL){
    this.validateResource(resource);const c=this.codes.get(code);this.codes.delete(code);
    // The SDK token handler validates PKCE via challengeForAuthorizationCode first.
    if(!c||c.expires<now()||c.clientId!==client.client_id||redirect!==c.redirect)throw new InvalidGrantError("Invalid code.");return this.issue(client.client_id);
  }
  async exchangeRefreshToken(client:OAuthClientInformationFull,value:string,scopes?:string[],resource?:URL){
    this.validateResource(resource);if(scopes?.some(s=>s!=="messenger:tools"))throw new InvalidGrantError("Invalid scope.");
    const t=this.data.tokens[hash(value)];if(!t?.refresh||t.expires<now()||t.clientId!==client.client_id||t.resource!==this.resource.href)throw new InvalidGrantError("Invalid refresh token.");
    delete this.data.tokens[hash(value)];return this.issue(client.client_id);
  }
  async verifyAccessToken(value:string):Promise<AuthInfo>{
    const t=this.data.tokens[hash(value)];if(!t||t.refresh||t.expires<now()||t.resource!==this.resource.href)throw new InvalidTokenError("Invalid token.");
    return {token:value,clientId:t.clientId,scopes:["messenger:tools"],expiresAt:t.expires,resource:this.resource};
  }
  async revokeToken(client:OAuthClientInformationFull,req:{token:string}){const key=hash(req.token);if(this.data.tokens[key]?.clientId===client.client_id){delete this.data.tokens[key];this.save();}}
}
