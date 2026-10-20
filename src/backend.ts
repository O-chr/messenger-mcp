import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { CONFIG_PATH, STATE_DIR } from "./policy.js";

export interface Backend { request(op: string, args?: Record<string, unknown>): Promise<unknown>; close(): void }
export const CLI_BIN = process.env.MESSENGER_BIN ?? "/Users/chr/code/mautrix-meta/bin/messenger";
export class CliBackend implements Backend {
  private child?: ChildProcessWithoutNullStreams;
  private sequence=0;
  private pending=new Map<number,{ resolve:(v:unknown)=>void; reject:(e:Error)=>void; timer:NodeJS.Timeout }>();
  constructor(private ceiling="read,write") {}
  private start() {
    if (this.child) return;
    const child=spawn(CLI_BIN,["--state-dir",STATE_DIR,"bridge","--policy",CONFIG_PATH,"--permissions",this.ceiling],{stdio:["pipe","pipe","pipe"],shell:false});
    this.child=child;
    // Never relay arbitrary stderr or protocol payloads to a client or access log.
    child.stderr.resume();
    child.stdin.on("error",()=>this.fail(child,"Messenger backend input closed."));
    const lines=createInterface({input:child.stdout});
    lines.on("line",line=>{
      if (line.length>2*1024*1024) { this.fail(child,"Messenger backend response exceeded limits."); return; }
      try {
        const r=JSON.parse(line) as {id:number; result?:unknown; error?:string};
        const p=this.pending.get(r.id); if (!p) return;
        clearTimeout(p.timer); this.pending.delete(r.id);
        if (r.error) p.reject(new Error(r.error.slice(0,500))); else p.resolve(r.result);
      } catch { this.fail(child,"Invalid Messenger backend response."); }
    });
    child.on("error",()=>this.fail(child,"Messenger backend could not start. Check the local CLI path."));
    child.on("close",()=>{lines.close(); this.fail(child,"Messenger backend stopped. No send was retried; verify Messenger before retrying a send.");});
  }
  private fail(child:ChildProcessWithoutNullStreams,message:string) {
    if (this.child!==child) return;
    this.child=undefined;
    child.stdin.end();
    child.kill("SIGTERM");
    const killTimer=setTimeout(()=>child.kill("SIGKILL"),3000);killTimer.unref();child.once("close",()=>clearTimeout(killTimer));
    for(const p of this.pending.values()){ clearTimeout(p.timer); p.reject(new Error(message)); }
    this.pending.clear();
  }
  request(op:string,args:Record<string,unknown>={}):Promise<unknown> {
    this.start(); const child=this.child!; const id=++this.sequence;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>this.fail(child,"Messenger request timed out. Send outcome may be unknown; no automatic retry."),95_000);
      this.pending.set(id,{resolve,reject,timer});
      child.stdin.write(JSON.stringify({id,op,...args})+"\n",e=>{if(e)this.fail(child,"Messenger backend input closed.");});
    });
  }
  close(){ if(this.child)this.fail(this.child,"Messenger MCP closed."); }
}
