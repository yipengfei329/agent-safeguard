import test from 'node:test';
import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
import {atomicEvidence} from '../src/credential-shape.js';
import {shapeClean,shapeSensitive,shapeSecret} from '../fixtures/credential-shapes.mjs';
const engine=compile();
for(const [i,value] of shapeClean.entries())test(`syntax is not credential material ${i}`,()=>{
 for(const field of ['Authorization','api_key','password'])for(const input of [
  {[field]:value},JSON.stringify({[field]:value}),`["${field}": "${value}"]`,
  {stdout:`const ${field} = "${value}";`,stderr:''},
 ])for(const source of ['tool.input','tool.result','user.prompt','prompt.context']){
  assert.equal(engine.scan(input,source,'Bash').blocked,false,`${i} ${field}`);
  assert.equal(engine.scan({result:input,stderr:'DB_PASSWORD='+shapeSecret},source,'Bash').rule,'security.credentials');
 }
});
for(const [i,value] of shapeSensitive.entries())test(`actual material survives syntax boundaries ${i}`,()=>{
 for(const field of ['Authorization','api_key','password'])for(const input of [{[field]:value},`["${field}": "${value}"]`])assert.equal(engine.scan(input).rule,'security.credentials');
});
test('positive evidence rejects delimiter complexity independently of reference names',()=>{
 for(const v of ['<binding:credential>','[source:session]','<mT8rV3:zQ7bK5>'])assert.equal(atomicEvidence(v),null);
 assert.equal(atomicEvidence(shapeSecret),'mixed-secret');
 assert.equal(atomicEvidence('a19c7e2d03f8b6a4a19c7e2d03f8b6a4'),'opaque-token');
 assert.equal(engine.scan({password:'Copper meadow 7! violet lantern'}).rule,'security.credentials');
});
test('explicit formats and user exact rules remain stronger than syntax filtering',()=>{
 const cfg=structuredClone(defaults);cfg.rules.push({id:'custom.shape',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['<binding:credential>'],caseSensitive:true}});
 assert.equal(compile(cfg).scan('Authorization: "<binding:credential>"').rule,'custom.shape');
 assert.equal(engine.scan('Authorization: "<binding:ghp_'+'Z'.repeat(36)+'>"').rule,'security.credentials');
});
