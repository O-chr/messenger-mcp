import {randomBytes} from 'node:crypto';
import type {Backend} from './backend.js';
import {allowed,loadConfig,ruleFingerprint,toolPerms,type Config,type Perm} from './policy.js';

type Proposal={id:string;clientId:string;chatId:string;jid:string;name:string;text:string;binding:string;expires:number;state:'pending'|'sending'|'sent'|'unknown'|'declined';result?:unknown};
export class Confirmations {
  private items=new Map<string,Proposal>();
  constructor(readonly publicUrl:string,private backend:Backend,private load:()=>Config=loadConfig,private ceiling:Set<Perm>=toolPerms(),private now:()=>number=Date.now){}
  prune(){for(const [id,p]of this.items){let valid=true;try{this.permitted(p);}catch{valid=false;}if(p.state!=='sending'&&(p.expires<this.now()||!valid))this.items.delete(id);}}
  has(id:string){this.prune();return this.items.has(id);}
  private permitted(p:Proposal){const cfg=this.load();if(!allowed('write',p.chatId,cfg,this.ceiling)||ruleFingerprint(cfg.chats[p.chatId])!==p.binding)throw new Error('Permission revoked or chat target changed; not sent.');}
  private get(id:string){this.prune();const p=this.items.get(id);if(!p)throw new Error('Confirmation expired or unavailable.');return p;}
  private summary(p:Proposal){return {confirmation_id:p.id,status:p.state,expires_at:new Date(p.expires).toISOString(),...(p.state==='pending'?{confirmation_url:`${this.publicUrl}/confirm/${p.id}`,instruction:'Not sent. Ask the owner to open this link, sign in with Google, review the exact recipient and text, then approve. Opening the link does not send. Do not open or approve on the owner’s behalf.'}:{result:p.result})};}
  create(clientId:string,chatId:string,text:string){
    this.prune();const cfg=this.load();if(!allowed('write',chatId,cfg,this.ceiling))throw new Error('Chat write permission denied.');
    const binding=ruleFingerprint(cfg.chats[chatId]);
    for(const p of this.items.values())if(p.clientId===clientId&&p.chatId===chatId&&p.text===text&&p.binding===binding)return this.summary(p);
    if(this.items.size>=100)throw new Error('Too many pending confirmations.');
    const p:Proposal={id:randomBytes(32).toString('base64url'),clientId,chatId,jid:cfg.chats[chatId].jid,name:cfg.chats[chatId].name,text,binding,expires:this.now()+600_000,state:'pending'};
    this.items.set(p.id,p);return this.summary(p);
  }
  status(clientId:string,id:string){const p=this.get(id);if(p.clientId!==clientId)throw new Error('Confirmation unavailable.');this.permitted(p);return this.summary(p);}
  describe(id:string){const p=this.get(id);this.permitted(p);return {name:p.name,chatId:p.chatId,text:p.text,state:p.state,result:p.result};}
  decline(id:string){const p=this.get(id);if(p.state==='pending')p.state='declined';return this.summary(p);}
  async approve(id:string){
    const p=this.get(id);this.permitted(p);if(p.state!=='pending')return this.summary(p);
    // Synchronous state change before awaiting prevents duplicate POSTs/retries.
    p.state='sending';p.expires=this.now()+600_000;
    try{p.result=await this.backend.request('send',{chat_id:p.chatId,expected_jid:p.jid,text:p.text});p.state='sent';}
    catch{p.state='unknown';p.result={instruction:'Send outcome may be unknown. Check Messenger before retrying. No automatic resend.'};}
    return this.summary(p);
  }
}
export function confirmationHTML(p:ReturnType<Confirmations['describe']>,csrf:string){
  const e=(s:string)=>s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
  const states={pending:'未送信：内容を確認してください',sending:'送信処理中です。この画面から再送しないでください。',sent:'送信先サーバーが受け付けました。',unknown:'結果が不明です。Messengerで確認してください。自動再送はしません。',declined:'送信をキャンセルしました。'};
  return `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Messenger 送信確認</title><style>body{font:17px system-ui;max-width:700px;margin:48px auto;padding:0 24px;color:#172335;background:#f7f9fc}article{background:white;padding:24px;border:1px solid #ccd5e0;border-radius:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;background:#f1f4f8;padding:20px;border-radius:8px}button{font:inherit;padding:12px 20px;margin:8px 12px 0 0;border-radius:7px;border:1px solid #8695a7}button[value=approve]{background:#125bdf;color:white;border-color:#125bdf}small{color:#536174}</style><h1>Messenger 送信確認</h1><article><p><strong>${e(states[p.state])}</strong></p><h2>宛先</h2><p>${e(p.name)}<br><small>チャットID: ${e(p.chatId)}</small></p><h2>本文</h2><pre>${e(p.text)}</pre>${p.state==='pending'?`<form method="post"><input type="hidden" name="csrf" value="${e(csrf)}"><button name="decision" value="approve">この1通を送信する</button><button name="decision" value="decline">送信しない</button></form><p><small>上の送信ボタンを押すまで送信しません。承認の有効期限は10分です。</small></p>`:''}</article></html>`;
}
