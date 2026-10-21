import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {ElicitRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {buildServer} from './server.js';
import {defaultConfig,type Config} from './policy.js';
import {Confirmations} from './confirmations.js';

const config=():Config=>({version:1,permissions:['read','write'],confirm_send:true,chats:{'100':{name:'Friend',kind:'dm',jid:'999@msgr',read:true,write:true},'200':{name:'Secret',kind:'dm',jid:'200@msgr',read:false,write:false}}});
async function harness(cfg:Config,form=false,onRequest?:(op:string)=>void,fallback=false){
  const calls:{op:string;args:unknown}[]=[];
  const backend={request:async(op:string,args?:Record<string,unknown>)=>{calls.push({op,args});onRequest?.(op);return {ok:true};},close(){}};
  const confirmations=fallback?new Confirmations('https://example.test',backend,()=>cfg):undefined;
  const {server}=buildServer({backend,load:()=>structuredClone(cfg),permissions:'read,write',confirmations,clientId:fallback?'client':undefined});
  const client=new Client({name:'test',version:'1'},{capabilities:form?{elicitation:{form:{}}}:{}});
  const [a,b]=InMemoryTransport.createLinkedPair();await server.connect(a);await client.connect(b);
  return {client,calls,close:async()=>{await client.close();await server.close();}};
}
test('default deny and global read ceiling hide send tool',async()=>{
  const cfg=defaultConfig(),h=await harness(cfg);try{
    assert.deepEqual((await h.client.listTools()).tools.map(t=>t.name).sort(),['messenger_list_chats','messenger_read_history','messenger_status']);
    const r=await h.client.callTool({name:'messenger_read_history',arguments:{chat_id:'100',limit:5}});assert.equal(r.isError,true);assert.equal(h.calls.length,0);
  }finally{await h.close();}
});
test('history reads enforce permission, cursor bounds and revocation without accepting a PIN',async()=>{
  const cfg=config(),h=await harness(cfg,false,op=>{if(op==='history')cfg.chats['100'].read=false;});try{
    const schema=(await h.client.listTools()).tools.find(t=>t.name==='messenger_read_history')!.inputSchema;
    assert.ok(!Object.hasOwn(schema.properties??{},'pin'));
    for(const args of [{chat_id:'200',limit:5},{chat_id:'100',limit:51},{chat_id:'100',before_ms:-1}]){
      const r=await h.client.callTool({name:'messenger_read_history',arguments:args});assert.equal(r.isError,true);
    }
    assert.equal(h.calls.length,0);
    const r=await h.client.callTool({name:'messenger_read_history',arguments:{chat_id:'100',limit:5,before_ms:1700000000000}});assert.equal(r.isError,true);
    assert.deepEqual(h.calls[0],{op:'history',args:{chat_id:'100',expected_jid:'999@msgr',limit:5,before_ms:1700000000000}});
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
  const cfg=config(),h=await harness(cfg,false,op=>{if(op==='history')cfg.chats['100'].read=false;});try{
    const r=await h.client.callTool({name:'messenger_read_history',arguments:{chat_id:'100'}});assert.equal(r.isError,true);assert.doesNotMatch(JSON.stringify(r),/"ok"/);
  }finally{await h.close();}
});
test('status reports whether this client supports the required send confirmation',async()=>{
  for(const form of [false,true]){const h=await harness(config(),form);try{
    const r=await h.client.callTool({name:'messenger_status'});const c=r.content as {type:string;text:string}[];
    assert.equal(JSON.parse(c[0].text).confirmation_supported,form);
  }finally{await h.close();}}
});
test('clients without forms receive an owner-only link and a read-only status tool; nothing is sent',async()=>{
  const h=await harness(config(),false,undefined,true);try{
    const r=await h.client.callTool({name:'messenger_send_message',arguments:{chat_id:'100',text:'exact body'}});
    const p=JSON.parse((r.content as {text:string}[])[0].text);assert.equal(p.status,'pending');assert.match(p.confirmation_url,/^https:\/\/example.test\/confirm\//);assert.equal(h.calls.length,0);
    const s=await h.client.callTool({name:'messenger_send_status',arguments:{confirmation_id:p.confirmation_id}});assert.equal(s.isError,false);assert.equal(h.calls.length,0);
  }finally{await h.close();}
});
