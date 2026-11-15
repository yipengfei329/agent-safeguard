import test from 'node:test';import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
import {assignmentFields,assignmentExpressions,expressionForms} from '../fixtures/assignment-corpus.mjs';
const sources=['tool.input','tool.result','user.prompt','prompt.context'];
const config=structuredClone(defaults);
// Test detector semantics at all supported sources, without changing the
// installed profile (identity rules do not inspect tool input by default).
for(const rule of config.rules)if(rule.detector.kind==='builtin')rule.sources=sources;
const engine=compile(config);
for(const [field,literal,rule] of assignmentFields)for(const [id,rhs] of assignmentExpressions)test(`shared extraction ${field} ${id}`,()=>{
 for(const source of sources)for(const text of expressionForms(field,rhs)){
  assert.equal(engine.scan(text,source,'Bash').blocked,false,`${field} ${id}`);
  assert.equal(engine.scan({stdout:text,stderr:JSON.stringify({[field]:literal})},source,'Bash').rule,rule);
 }
});
for(const [field,literal,rule] of assignmentFields)test(`literal retention ${field}`,()=>{
 for(const value of [
  {[field]:literal},{[field]:[literal]},JSON.stringify({[field]:literal}),
  `${field} = "${literal}"`,`    ${field} = "${literal}"`,`${field} := "${literal}"`,
  `const ${field}: string = "${literal}";`,`["${field}": .string("${literal}")]`,
  `${field}: |\n  ${literal}`,`${field}="${literal.slice(0,4)}" + "${literal.slice(4)}"`,
  `${field} = r"${literal}"`,`${field} = """${literal}"""`,`${field} = r#"${literal}"#`,
 ])for(const source of sources)assert.equal(engine.scan(value,source,'Bash').rule,rule,field);
});
test('references use code context; structured strings remain actual data',()=>{
 for(const [field] of assignmentFields){
  for(const text of [`${field} = settings.identity`,`    ${field} = identity_reference`,`const ${field} = identity_reference;`,`{${field}: settings.identity}`])assert.equal(engine.scan(text).blocked,false);
 }
 // DNS-like data is not globally exempted because it could also be a member path.
 for(const text of ['hostname=host.example.invalid','hostname: host.example.invalid',{hostname:'settings.identity'},'hostname="settings.identity"'])assert.equal(engine.scan(text).rule,'identity.environment');
 assert.equal(engine.scan({device_id:'settings.identity'}).rule,'identity.device');
});
test('identity templates are expressions; static values and literal concatenation still block',()=>{
 for(const field of ['device_id','hostname'])for(const rhs of ['`prefix-${identity_reference}`','"\\(identity_reference)"','"prefix-" + identity_reference'])assert.equal(engine.scan(`const ${field} = ${rhs};`).blocked,false);
 assert.equal(engine.scan('const device_id = "SYNTHETIC456789";').rule,'identity.device');
});
test('identity policies reject UI prose and syntax, not real identifiers',()=>{
 for(const value of [{device_id:'Enter the device identifier'},{device_id:'<binding:identity>'},{hostname:'Please enter the host name'},{hostname:'<binding:host>'}])assert.equal(engine.scan(value).blocked,false);
 for(const value of [{device_id:'SYNTHETIC456789'},{device_id:1234567},{device_id:'c3ludGhldGljLWlk=='},{hostname:'SyntheticHost'},{computername:'Synthetic Computer'},{computername:'Synthetic Computer (2) 🚀'}])assert.equal(engine.scan(value).blocked,true);
});
test('local expression decisions cannot skip explicit signatures or custom rules',()=>{
 const cfg=structuredClone(defaults);cfg.rules.push({id:'custom.expression',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['resolve_identity('],caseSensitive:true}});
 assert.equal(compile(cfg).scan('device_id = resolve_identity(').rule,'custom.expression');
 assert.equal(engine.scan('device_id = resolve_identity(\n token="ghp_'+'Z'.repeat(36)+'")').rule,'security.credentials');
 assert.equal(engine.scan('device_id = resolve_identity(\n mac="aa:bb:cc:dd:ee:ff")').rule,'identity.device');
});
