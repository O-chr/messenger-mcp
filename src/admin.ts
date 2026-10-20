#!/usr/bin/env node
// Owner-only permission editor. This executable is never exposed as an MCP tool.
import { lstatSync,readFileSync } from "node:fs";
import { join } from "node:path";
import { CONFIG_PATH, STATE_DIR, loadConfig, saveConfig, idSchema, type Config, type ChatRule, type Perm } from "./policy.js";

type Chat={id:string;name:string;type:number;jid?:string};
function catalog():Chat[]{
  const path=join(STATE_DIR,"account.json"),st=lstatSync(path);
  if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)||st.size>10*1024*1024)throw new Error("CLI profile is not private.");
  const raw=JSON.parse(readFileSync(path,"utf8"));
  // Do not print or copy the cookie fields in this file.
  return Object.values(raw.chats??{}) as Chat[];
}
function permissions(s:string):Perm[]{const ps=s.split(",").filter(Boolean);if(ps.some(p=>p!=="read"&&p!=="write"))throw new Error("permissions must be read, write, read,write, or an empty string");return [...new Set(ps)] as Perm[];}
function rule(chat:Chat,ps:Perm[],group:boolean):ChatRule{
  const dm=[1,7,10,13,15].includes(chat.type);
  if(!dm&&!group)throw new Error("Group chats require --group (or --groups for allow-all).");
  return {name:chat.name||chat.id,kind:dm?"dm":"group",jid:chat.jid??"",read:ps.includes("read"),write:ps.includes("write"),...(!dm?{group:true}:{})};
}
try{
  const args=process.argv.slice(2),cmd=args[0],cfg=loadConfig();
  if(cmd==="chats"){
    for(const c of catalog())console.log(`${c.id}\t${c.type===15||c.type===16?"E2EE":"unsupported-send"}\t${c.name}`);
  }else if(cmd==="show")console.log(JSON.stringify(cfg,null,2));
  else if(cmd==="permissions"){
    cfg.permissions=permissions(args[1]??"");saveConfig(cfg);console.log("Global permission ceiling saved; reconnect clients to refresh tool discovery.");
  }else if(cmd==="allow"||cmd==="deny"){
    const id=idSchema.parse(args[1]);
    if(cmd==="deny")delete cfg.chats[id];
    else {const chat=catalog().find(c=>c.id===id);if(!chat)throw new Error("Unknown chat ID; refresh CLI chats as the owner first.");cfg.chats[id]=rule(chat,permissions(args[2]??"read"),args.includes("--group"));}
    saveConfig(cfg);console.log("Saved",CONFIG_PATH);
  }else if(cmd==="allow-all"){
    const ps=permissions(args[1]??"read"),chats=catalog();
    for(const c of chats){if(!idSchema.safeParse(c.id).success)continue;if(![1,2,7,8,10,13,15,16].includes(c.type))continue;cfg.chats[c.id]=rule(c,ps,args.includes("--groups"));}
    saveConfig(cfg);console.log("Saved explicit rules for",Object.keys(cfg.chats).length,"currently known chats. Future chats remain denied.");
  }else console.log("admin chats | show | permissions read,write | allow ID [read,write] [--group] | deny ID | allow-all [read,write] [--groups]");
}catch{console.error("Permission update failed. Check the command, chat ID and private file permissions. No secrets were printed.");process.exitCode=1;}
