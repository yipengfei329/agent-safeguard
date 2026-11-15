import test from 'node:test';
import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
import {boundaryClean,boundarySensitive} from '../fixtures/credential-boundaries.mjs';
import {credentialReason} from '../src/credentials.js';
import {secretValue} from '../src/credential-values.js';
const engine=compile(),secret='vD8!qZ3_nB7#sJ5-pR2@wK9';
const wrappers=[x=>x,x=>({stdout:x,stderr:''}),x=>JSON.stringify(x),x=>({content:[{type:'text',text:typeof x==='string'?x:JSON.stringify(x)}]})];
for(const [id,value] of boundaryClean)for(const [i,wrap] of wrappers.entries())test(`boundary clean ${id} wrapper ${i}`,()=>{
 for(const source of ['tool.input','tool.result','user.prompt','prompt.context']){
  assert.equal(engine.scan(wrap(value),source,'Edit').blocked,false,id);
  assert.equal(engine.scan({result:wrap(value),stderr:`DB_PASSWORD=${secret}`},source,'Edit').rule,'security.credentials');
 }
});
for(const [id,value] of boundarySensitive)for(const [i,wrap] of wrappers.entries())test(`boundary sensitive ${id} wrapper ${i}`,()=>{
 for(const source of ['tool.input','tool.result','user.prompt','prompt.context'])assert.equal(engine.scan(wrap(value),source,'Edit').rule,'security.credentials',id);
});
test('field and template exceptions retain explicit formats and exact rules',()=>{
 const cfg=structuredClone(defaults);cfg.rules.push({id:'custom.boundary',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['${PASSWORD}'],caseSensitive:true}});
 assert.equal(compile(cfg).scan('DB_PASSWORD="${PASSWORD}"').rule,'custom.boundary');
 assert.equal(engine.scan('interface Settings { DB_PASSWORD: "ghp_'+'Z'.repeat(36)+'"; }').rule,'security.credentials');
});
test('shared identity extraction still checks the next assignment',()=>{
 assert.equal(engine.scan('hostname= BUILD_LABEL=demo-service').blocked,false);
 assert.equal(engine.scan('hostname= hostname=SyntheticMac').rule,'identity.environment');
 assert.equal(engine.scan('device_id= device_id=SYNTHETIC12345').rule,'identity.device');
});
test('template scanning participates in the budget without exposing content',()=>{
 let checkpoints=0;
 assert.throws(()=>secretValue('${call('+'a'.repeat(10000)+')}','password',()=>{if(++checkpoints===3)throw Error('BUDGET');}),/BUDGET/);
 assert.equal(credentialReason(`DB_PASSWORD="${secret}\${SUFFIX}"`),'literal-value');
 assert.equal(engine.scan({password:'${'.repeat(70)+'x'+'}'.repeat(70)}).rule,'inspection.failed');
});
