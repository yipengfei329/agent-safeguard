import test from 'node:test';import assert from 'node:assert/strict';
import {compile} from '../dist/core.js';
const e=compile(),secret='rQ7!mL2_zA9#vC4-pF8@tN6';
const expressions=[
 '.string(key)', '.string(credential.value)', '.some(.string(key))',
 '.init(rawValue: value)', '.custom<Payload>(value)',
 'Swift.JSONValue.string(key)', 'new UnknownSecretType(reference)',
 'await resolveCredential(provider)', 'try await resolveCredential(provider)',
 '&credential_reference', '*credential_reference',
 'config?.credential ?? defaultCredential', 'credentials[provider]',
 '(credential_reference)', '[credential_reference]', '{ getCredential() }',
 'credential_reference |> transform', 'credential_reference + suffix',
 'credential_reference as String', 'std::move(reference)',
 'Unknown<Generic<Payload>>::construct(reference)',
 '...credential_reference', '\\Environment.credential',
 '$config["credential"]', '->credential_reference',
 // High-entropy expression punctuation must never be used as value evidence.
 '.unknown_Ab7_Kd3_Xp9[factory](reference)!',
];
for(const [i,rhs] of expressions.entries())for(const field of ['api_key','password','token'])test(`unknown expression ${i} ${field}`,()=>{
 const forms=[`${field}: ${rhs}`,`["${field}": ${rhs}])`,`let ${field} = ${rhs};`,`src/example.swift:17: ["${field}": ${rhs}])`];
 for(const source of ['tool.input','tool.result','user.prompt','prompt.context'])for(const text of forms){
  assert.equal(e.scan(text,source).blocked,false,text);
  assert.equal(e.scan(JSON.stringify({stdout:text}),source).blocked,false,text);
  assert.equal(e.scan(text+'\napi_key="'+secret+'"',source).rule,'security.credentials');
 }
});
for(const expression of [`.string("${secret}")`,`.some(.string("${secret}"))`,`JSONValue.string("${secret}")`,`Some("${secret}")`,`"${secret}"`])test('concrete value '+expression.slice(0,15),()=>{
 for(const source of ['tool.input','tool.result','user.prompt','prompt.context'])assert.equal(e.scan(`["api_key": ${expression}]`,source).rule,'security.credentials');
});
test('structured values, environment atoms and provider formats retain evidence paths',()=>{
 for(const input of [{api_key:secret},'API_KEY='+secret,'password='+secret,'Authorization: Bearer '+secret,'ghp_'+'A'.repeat(36),'-----BEGIN PRIVATE KEY-----'])assert.equal(e.scan(input).rule,'security.credentials');
 assert.equal(e.scan('["api_key": .string(key)], "password": "'+secret+'"').rule,'security.credentials');
});
