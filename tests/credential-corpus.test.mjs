import test from 'node:test';
import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
import {credentialReason} from '../src/credentials.js';
import {readQuoted} from '../src/credential-values.js';
import {clean,sensitive,secret,formatProbes} from '../fixtures/credential-corpus.mjs';
const engine=compile(),sources=['tool.input','tool.result','user.prompt','prompt.context'];
const wrappers=[x=>x,x=>({stdout:x,stderr:''}),x=>JSON.stringify({content:[{type:'text',text:x}]}),x=>({originalFile:x,structuredPatch:[{lines:x.split('\n')}]} )];
for(const [id,,value] of clean)for(const [index,wrap] of wrappers.entries())test(`credential precision ${id} wrapper ${index}`,()=>{
  for(const source of sources){
    assert.equal(engine.scan(wrap(value),source,'Edit').blocked,false,id);
    assert.equal(engine.scan({result:wrap(value),stderr:`api_key=${secret}`},source,'Edit').rule,'security.credentials');
    assert.equal(engine.scan(wrap(value+`\napi_key=${secret}`),source,'Edit').rule,'security.credentials');
  }
});
for(const [id,,value] of sensitive)for(const [index,wrap] of wrappers.entries())test(`credential retention ${id} wrapper ${index}`,()=>{
  for(const source of sources)assert.equal(engine.scan(wrap(value),source,'Edit').rule,'security.credentials',id);
});
test('type syntax is field-local and cannot exempt a literal, comment, initializer or neighbor',()=>{
  for(const text of [
    `let token: &'static str = "${secret}";`,
    `let token: "custom-token-one" | "custom-token-two" = "${secret}";`,
    `interface Options { /* password=${secret} */ field: string; }`,
    `interface Options {\n * password=${secret}\n field: string; }`,
    `type Options = { value: { kind: string } }; const value = { token: "${secret}" };`,
    `const type = { token: "${secret}" };`,
    `const interfaceName = { token: "${secret}" };`,
    `type Options = { token: "${secret}"`, // incomplete: no type exemption
    `const x = "type Options = {"; password="${secret}"`,
    `/* type Options = { */ password="${secret}"`,
    `function render() { const pattern = /interface Options {/; const x = { token: "${secret}" }; }`,
    `function render() { const pattern = /type Options = {/; const x = { token: "${secret}" }; }`,
  ])assert.equal(engine.scan(text).rule,'security.credentials',text);
});
test('shared identity extraction distinguishes complete type declarations from runtime data',()=>{
  const source='interface Options { hostname: "custom-host-label"; device_id: "custom-device-label"; }';
  assert.equal(engine.scan(source).blocked,false);
  assert.equal(engine.scan(source+'\nhostname: SyntheticMac').rule,'identity.environment');
  assert.equal(engine.scan(source+'\ndevice_id: SYNTHETIC123456').rule,'identity.device');
  assert.equal(engine.scan({hostname:'custom-host-label'}).rule,'identity.environment');
  assert.equal(engine.scan({device_id:'custom-device-label'}).rule,'identity.device');
});
test('value exclusions do not disable explicit formats, custom exact rules or high-entropy neighbors',()=>{
  const cfg=structuredClone(defaults);cfg.rules.push({id:'custom.literal',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['access_token'],caseSensitive:true}});
  assert.equal(compile(cfg).scan('token="access_token"').rule,'custom.literal');
  for(const value of [
    'ghp_'+'A'.repeat(36)+' access_token',
    secret+'_access_token',
    `Please enter password ${secret}`,
    `https://user:${secret}@service.example.invalid`,
    `https://service.example.invalid/?password=${secret}`,
  ])assert.equal(engine.scan({password:value}).rule,'security.credentials');
  // No blanket exclusion of a testing path, a UUID, or a multiword passphrase.
  for(const value of ['Synthetic-example-'+secret,'a19c7e2d-03f8-46a4-b5c6-7e8f901234ab','Copper meadow 7! violet lantern'])assert.equal(engine.scan({password:value}).rule,'security.credentials');
  assert.equal(engine.scan('token="correct-horse-battery-staple"; password="correct-horse-battery-staple"').blocked,false);
});
test('source string decoding keeps offsets and does not treat escaping as entropy',()=>{
  const quoted=readQuoted(String.raw`"a\"b\\c\x21" + "tail"`);
  assert.equal(quoted.value,'a"b\\c!');
  assert.equal(String.raw`"a\"b\\c\x21" + "tail"`.slice(quoted.length),' + "tail"');
  assert.equal(engine.scan(String.raw`password="aaaaaaaa\"aaaaaa"`).blocked,false);
  assert.equal(engine.scan(String.raw`token="rQ7\x21mL2_" + "zA9#vC4-pF8@tN6"`).rule,'security.credentials');
});
test('new lexical paths cooperate with failure budgets and expose no secret in reasons',()=>{
  assert.throws(()=>credentialReason('interface Options { token: "kind"; }','',()=>{throw Error('BUDGET');}));
  assert.equal(engine.scan('type X = {'+'{'.repeat(65)+'token: "kind"'+'}'.repeat(66)).rule,'inspection.failed');
  assert.equal(credentialReason(`token="${secret}"`),'literal-value');
});
for(const [id,,value] of formatProbes)test(id,()=>assert.equal(engine.scan(value).rule,'security.credentials'));
