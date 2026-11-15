import test from 'node:test';import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
import {atomicEvidence} from '../src/credential-shape.js';
import {numberedLabels,extraLabels,protectedValues} from '../fixtures/numbered-labels.mjs';
const engine=compile(),sources=['tool.input','tool.result','user.prompt','prompt.context'];
for(const field of ['token','api_key','serviceAccessToken','client_secret','Authorization'])test('numbered label family '+field,()=>{
 for(const value of [...numberedLabels,...extraLabels])for(const input of [
  {[field]:value},JSON.stringify({[field]:value}),`const ${field}: &str = "${value}";`,
  `${field}=${value}`,`const ${field} = "${value}";`,`["${field}": .string("${value}")]`,
 ])for(const source of sources)assert.equal(engine.scan(input,source,'Bash').blocked,false);
});
test('labels cannot exempt adjacent or wrapped actual material',()=>{
 for(const source of sources)for(const secret of protectedValues){
  for(const value of [secret,`<binding:${secret}>`,`Bearer ${secret}`])assert.equal(engine.scan({token:value},source,'Bash').rule,'security.credentials');
  assert.equal(engine.scan({stdout:'const TOKEN: &str = "lanterns-24680";',stderr:`API_KEY="${secret}"`},source,'Bash').rule,'security.credentials');
 }
});
test('password and identity policies retain word-number values',()=>{
 for(const field of ['password','DB_PASSWORD','passwd'])for(const value of ['lanterns-24680','Lanterns24680','LANTERNS_24680'])assert.equal(engine.scan({[field]:value}).rule,'security.credentials');
 assert.equal(engine.scan({device_id:'lanterns-24680'}).rule,'identity.device');
 assert.equal(engine.scan({hostname:'lanterns-24680'}).rule,'identity.environment');
});
test('shape boundaries preserve stronger evidence and explicit overrides',()=>{
 for(const value of ['pM8sQ3vL7rD5tN2xK9','a19c7e2d03f8b6a4','lanterns-1234567890','Lanterns-24680!'])assert.ok(atomicEvidence(value));
 for(const value of ['<binding:lanterns-24680>','Bearer lanterns-24680','lanterns-24680${SUFFIX}'])assert.equal(engine.scan({token:value}).blocked,false);
 const cfg=structuredClone(defaults);cfg.rules.push({id:'custom.numbered',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['lanterns-24680'],caseSensitive:true}});
 assert.equal(compile(cfg).scan({token:'lanterns-24680'}).rule,'custom.numbered');
 assert.equal(engine.scan('redis://:lanterns-24680@cache.example.invalid').rule,'security.credentials');
 assert.equal(engine.scan('const token="lanterns-24680";\n-----BEGIN PRIVATE KEY-----').rule,'security.credentials');
});
test('value decisions are local to roles and cannot skip multiline suffixes',()=>{
 const secret=protectedValues[0];
 for(const text of [
  'token="lanterns-24680";\npassword="lanterns-24680";',
  'token="lanterns-24680";\ntoken="lanterns-24680" + "'+secret+'";',
  'token="<binding:" + """\nslot>""";\ntoken="<binding:" + """\n'+secret+'>""";',
  'token="""slot\nvalue""";\ntoken="""slot\n'+secret+'""";',
 ])assert.equal(engine.scan(text).rule,'security.credentials');
 assert.equal(engine.scan({token:secret}).rule,'security.credentials');
});
