import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,chmodSync,writeFileSync,rmSync,symlinkSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {defaultConfig,saveConfig,loadConfig,allowed,toolPerms} from './policy.js';
test('strict private configuration, default deny, group opt-in and global ceilings',()=>{
  const dir=mkdtempSync(join(tmpdir(),'messenger-policy-'));chmodSync(dir,0o700);const path=join(dir,'config.json');
  try{
    assert.deepEqual(loadConfig(path),defaultConfig());const cfg=defaultConfig();cfg.chats['100']={name:'Friend',jid:'999@msgr',kind:'dm',read:true,write:true};
    saveConfig(cfg,path);assert.equal(statSync(path).mode&0o777,0o600);assert.equal(allowed('write','100',loadConfig(path),toolPerms('read,write')),false);
    cfg.permissions=['read','write'];assert.equal(allowed('write','100',cfg,toolPerms('read')),false);assert.equal(allowed('read','200',cfg,toolPerms()),false);
    assert.throws(()=>saveConfig({...cfg,confirm_send:false} as never,path));
    assert.throws(()=>saveConfig({...cfg,chats:{'200':{name:'Group',jid:'200@g.us',kind:'group',read:true,write:true}}},path));
    chmodSync(path,0o644);assert.throws(()=>loadConfig(path));rmSync(path);symlinkSync(join(dir,'target'),path);assert.throws(()=>saveConfig({...cfg,permissions:['bad']} as never,path));
    writeFileSync(join(dir,'target'),'{}',{mode:0o600});assert.throws(()=>loadConfig(path));assert.throws(()=>toolPerms('admin'));
  }finally{rmSync(dir,{recursive:true,force:true});}
});
