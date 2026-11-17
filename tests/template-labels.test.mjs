import test from 'node:test';import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
const engine=compile(),secret='qR7_mN2-zP8_vL4-tX9';
const prefixes=['access-token-','sample-bearer-','local-session-','service_access_'];
for(const prefix of prefixes)for(const marker of ['${state.sequence}','{{ sequence }}'])for(const form of [v=>'state.token = `'+v+'`;',v=>'token = "'+v+'"',v=>({token:v}),v=>'src/synthetic.js:17: token: "'+v+'"'])test('template label '+prefix+marker+String(form),()=>{
 const value=form(prefix+marker);assert.equal(engine.scan(value).blocked,false);
 for(const adjacent of ['password="'+secret+'"','serialNumber: SYNTHETIC123456','hostname: SyntheticHost'])assert.equal(engine.scan({value,adjacent}).blocked,true);
});
for(const value of [secret+'-${state.sequence}','access-token-${state.sequence}-'+secret,'${state.sequence}-'+secret,secret+'_${state.sequence}_access-token-'])test('opaque fixed template material remains blocked '+value,()=>assert.equal(engine.scan('state.token = `'+value+'`;').rule,'security.credentials'));
for(const text of ['password=`sample-bearer-${state.sequence}`','token="access-token-"','token="ghp_'+'A'.repeat(36)+'-${state.sequence}"','url="https://fixture:short@service.example.invalid"'])test('unchanged non-label evidence '+text,()=>assert.equal(engine.scan(text).rule,'security.credentials'));
test('custom exact rules still protect label-shaped template material',()=>{const c=structuredClone(defaults);c.rules.unshift({id:'custom.synthetic',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['access-token-'],caseSensitive:true}});assert.equal(compile(c).scan('token=`access-token-${state.sequence}`').rule,'custom.synthetic');});

test('opt-in location identifies the field without returning a value or private key name',()=>{
 const e=compile(defaults,{diagnostics:true});
 const text='// synthetic heading\nconst safe = 1;\nstate.privateAccessToken = "'+secret+'";';
 const result=e.scan(text);assert.deepEqual(result.location,{textIndex:1,line:3,field:'token'});
 assert(!JSON.stringify(result).includes(secret));assert(!JSON.stringify(result).includes('privateAccessToken'));
 assert.equal(engine.scan(text).location,undefined);
 for(const [value,field] of [[{password:secret},'password'],[{deviceId:'SYNTHETIC123456'},'device'],[{hostname:'SyntheticHost'},'hostname']]){
  const hit=e.scan(value);assert.equal(hit.location.line,1);assert.equal(hit.location.field,field);
 }
});
test('observed field matches cannot become the position of a different blocking rule',()=>{
 const c=structuredClone(defaults);c.rules.find(r=>r.id==='security.credentials').action='observe';c.rules.push({id:'custom.fixture',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['SYNTHETIC_MARKER'],caseSensitive:true}});
 const hit=compile(c,{diagnostics:true}).scan('token="'+secret+'"\nSYNTHETIC_MARKER');assert.equal(hit.rule,'custom.fixture');assert.equal(hit.location,undefined);
});
