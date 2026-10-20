import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {ElicitRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {buildServer} from './server.js';
import {defaultConfig,type Config} from './policy.js';

const config=():Config=>({version:1,permissions:['read','write'],confirm_send:true,chats:{'100':{name:'Friend',kind:'dm',jid:'999@msgr',read:true,write:true},'200':{name:'Secret',kind:'dm',jid:'200@msgr',read:false,write:false}}});
async function harness(cfg:Config,form=false,onRequest?:(op:string)=>void){
  const calls:{op:string;args:unknown}[]=[];
  const backend={request:async(op:string,args?:Record<string,unknown>)=>{calls.push({op,args});onRequest?.(op);return {ok:true};},close(){}};
  const {server}=buildServer({backend,load:()=>structuredClone(cfg),permissions:'read,write'});
  const client=new Client({name:'test',version:'1'},{capabilities:form?{elicitation:{form:{}}}:{}});
  const [a,b]=InMemoryTransport.createLinkedPair();await server.connect(a);await client.connect(b);
  return {client,calls,close:async()=>{await client.close();await server.close();}};
}
test('default deny and global read ceiling hide send tool',async()=>{
  const cfg=defaultConfig(),h=await harness(cfg);try{
    assert.deepEqual((await h.client.listTools()).tools.map(t=>t.name).sort(),['messenger_list_chats','messenger_read_messages','messenger_status']);
    const r=await h.client.callTool({name:'messenger_read_messages',arguments:{chat_id:'100',limit:5}});assert.equal(r.isError,true);assert.equal(h.calls.length,0);
  }finally{await h.close();}
});
test('unallowed chat metadata and invalid targets never reach backend',async()=>{
  const h=await harness(config());try{
    const r=await h.client.callTool({name:'messenger_list_chats'});const text=JSON.stringify(r);assert.match(text,/Friend/);assert.doesNotMatch(text,/Secret/);
    const invalid=await h.client.callTool({name:'messenger_send_message',arguments:{chat_id:'100@msgr',text:'hello'}});assert.equal(invalid.isError,true);
    const denied=await h.client.callTool({name:'messenger_send_message',arguments:{chat_id:'200',text:'hello'}});assert.equal(denied.isError,true);assert.equal(h.calls.length,0);
  }finally{await h.close();}
});
test('unsupported, declined and cancelled confirmations never send',async()=>{
  const no=await harness(config());try{assert.equal((await no.client.callTool({name:'messenger_send_message',arguments:{chat_id:'100',text:'hello'}})).isError,true);assert.equal(no.calls.length,0);}finally{await no.close();}
  for(const action of ['decline','cancel','accept'] as const){const h=await harness(config(),true);try{
    h.client.setRequestHandler(ElicitRequestSchema,async()=>({action,...(action==='accept'?{content:{approve:false}}:{})}));
    assert.equal((await h.client.callTool({name:'messenger_send_message',arguments:{chat_id:'100',text:'hello'}})).isError,true);assert.equal(h.calls.length,0);
  }finally{await h.close();}}
});
test('approval binds exact body and target, permission revocation or target change stops send',async()=>{
  for(const mode of ['approve','revoke','swap']){const cfg=config(),h=await harness(cfg,true);try{
    h.client.setRequestHandler(ElicitRequestSchema,async req=>{assert.match(req.params.message,/Friend \(100\)/);assert.match(req.params.message,/exact body/);if(mode==='revoke')cfg.chats['100'].write=false;if(mode==='swap')cfg.chats['100'].jid='666@msgr';return {action:'accept',content:{approve:true}};});
    const r=await h.client.callTool({name:'messenger_send_message',arguments:{chat_id:'100',text:'exact body'}});
    assert.equal(Boolean(r.isError),mode!=='approve');assert.equal(h.calls.length,mode==='approve'?1:0);
    if(mode==='approve')assert.deepEqual(h.calls[0],{op:'send',args:{chat_id:'100',expected_jid:'999@msgr',text:'exact body'}});
  }finally{await h.close();}}
});
test('revocation while reading drops fetched data',async()=>{
  const cfg=config(),h=await harness(cfg,false,op=>{if(op==='read')cfg.chats['100'].read=false;});try{
    const r=await h.client.callTool({name:'messenger_read_messages',arguments:{chat_id:'100'}});assert.equal(r.isError,true);assert.doesNotMatch(JSON.stringify(r),/"ok"/);
  }finally{await h.close();}
});
test('status reports whether this client supports the required send confirmation',async()=>{
  for(const form of [false,true]){const h=await harness(config(),form);try{
    const r=await h.client.callTool({name:'messenger_status'});const c=r.content as {type:string;text:string}[];
    assert.equal(JSON.parse(c[0].text).confirmation_supported,form);
  }finally{await h.close();}}
});
