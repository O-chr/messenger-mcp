import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Confirmations,confirmationHTML} from './confirmations.js';
import type {Config} from './policy.js';
const cfg=():Config=>({version:1,permissions:['read','write'],confirm_send:true,chats:{'100':{name:'<script>name</script>',kind:'dm',jid:'999@msgr',read:true,write:true}}});

test('web proposals require approval, bind client/body/target, deduplicate and send at most once',async()=>{
 const c=cfg(),calls:unknown[]=[],q=new Confirmations('https://example.test',{request:async(op,args)=>{calls.push({op,args});await new Promise(r=>setTimeout(r,5));return {status:'server_acknowledged'};},close(){}},()=>c);
 const p=q.create('client-a','100','exact <script>body</script>');assert.equal(p.status,'pending');assert.equal(calls.length,0);
 assert.equal(q.create('client-a','100','exact <script>body</script>').confirmation_id,p.confirmation_id);
 assert.throws(()=>q.status('client-b',p.confirmation_id));
 const html=confirmationHTML(q.describe(p.confirmation_id),'csrf');assert.doesNotMatch(html,/<script>/);assert.match(html,/&lt;script&gt;body/);
 await Promise.all([q.approve(p.confirmation_id),q.approve(p.confirmation_id)]);assert.equal(calls.length,1);assert.equal(q.status('client-a',p.confirmation_id).status,'sent');
 assert.equal(q.create('client-a','100','exact <script>body</script>').status,'sent');
});
test('revocation, target change, expiry and decline prevent sends; unknown outcomes are not retried',async()=>{
 for(const mode of ['revoke','swap','expire','decline','unknown']){
  const c=cfg();let clock=Date.now(),calls=0;const q=new Confirmations('https://example.test',{request:async()=>{calls++;throw new Error('private backend error');},close(){}},()=>c,new Set(['read','write']),()=>clock);
  const p=q.create('client','100','hello');
  if(mode==='revoke')c.chats['100'].write=false;if(mode==='swap')c.chats['100'].jid='666@msgr';if(mode==='expire')clock+=600_001;
  if(mode==='decline')q.decline(p.confirmation_id);
  if(mode==='unknown'){await q.approve(p.confirmation_id);await q.approve(p.confirmation_id);assert.equal(calls,1);assert.equal(q.status('client',p.confirmation_id).status,'unknown');assert.doesNotMatch(JSON.stringify(q.status('client',p.confirmation_id)),/private backend error/);}
  else{try{await q.approve(p.confirmation_id);}catch{}assert.equal(calls,0);}
 }
});
