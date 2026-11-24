import test from 'node:test';import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
const engine=compile(defaults,{diagnostics:true});
const label='account-password-required',secret='qR7_mN2-zP8_vL4-tX9';
const names=['errMissingPassword','ErrMissingPassword','errorRequiredPassword','ERR_REQUIRED_PASSWORD','error_missing_passwd','state.errMissingPassword'];
const object=(name,value)=>name.split('.').reverse().reduce((v,key)=>({[key]:v}),value);
const forms={
 go:(n,v)=>`const (\n  ${n} = "${v}"\n)`,
 javascript:(n,v)=>`const ${n} = "${v}";`,
 typescript:(n,v)=>`const ${n}: string = "${v}";`,
 swift:(n,v)=>`let ${n}: String = "${v}"`,
 rust:(n,v)=>`const ${n}: &str = "${v}";`,
 python:(n,v)=>`${n} = "${v}"`,
 kotlin:(n,v)=>`val ${n}: String = "${v}"`,
 java:(n,v)=>`static final String ${n} = "${v}";`,
 cpp:(n,v)=>`const char* ${n} = "${v}";`,
 grep:(n,v)=>`src/synthetic.go:53: ${n} = "${v}"`,
 structured:object,
 json:(n,v)=>JSON.stringify(object(n,v)),
};
for(const name of names)for(const [syntax,form] of Object.entries(forms))test(`diagnostic label ${name} ${syntax}`,()=>{
 for(const source of ['tool.input','tool.result','user.prompt']){
  assert.equal(engine.scan(form(name,label),source,'Write').blocked,false);
  assert.equal(engine.scan(form(name,secret),source,'Write').rule,'security.credentials');
 }
});
test('clean hyphenated diagnostic labels pass across all field names while strong passwords and passphrases remain blocked',()=>{
 for(const name of ['password','adminPassword','noterrorPassword','myErrorPassword'])for(const form of Object.values(forms)){
  assert.equal(engine.scan(form(name,label)).blocked,false);
 }
 for(const value of ['Lanterns24680','password-required-82!','four secret words 42!','account-password-required-'+secret]){
  assert.equal(engine.scan(`errMissingPassword="${value}"`).rule,'security.credentials',value);
 }
});
test('role-separated cache cannot suppress a mixed-case-digit password after a token field',()=>{
 const roleValue='Lanterns24680';
 for(const text of [
  `token="${roleValue}"; password="${roleValue}"`,
  `api_key="${roleValue}"; adminPassword="${roleValue}"`,
  `password="${roleValue}"; token="${roleValue}"`,
  JSON.stringify({token:roleValue,password:roleValue}),
  {token:roleValue,password:roleValue},
 ])assert.equal(engine.scan(text).rule,'security.credentials');
 const hit=engine.scan(`token="${roleValue}"\npassword="${roleValue}"`);
 assert.deepEqual(hit.location,{textIndex:1,line:2,field:'password'});
});
test('diagnostic labels never exempt adjacent credential, device or hostname fields',()=>{
 for(const [field,value,rule] of [['password',secret,'security.credentials'],['deviceId','SYNTHETIC123456','identity.device'],['hostname','SyntheticHost','identity.environment']]){
  for(const form of Object.values(forms))assert.equal(engine.scan({code:form('errMissingPassword',label),adjacent:form(field,value)}).rule,rule);
  assert.equal(engine.scan(`errMissingPassword="${label}"; ${field}="${value}"`).rule,rule);
 }
});
test('literal concatenation with secrets and independent formats remain protected',()=>{
 assert.equal(engine.scan('errMissingPassword="account-password-" + "required"').blocked,false);
 for(const text of [
  `errMissingPassword="${label}" + "${secret}"`,
  `errMissingPassword="${label}"; value="ghp_${'Z'.repeat(36)}"`,
  `errMissingPassword="${label}"; value="https://fixture:short@service.example.invalid"`,
  `errMissingPassword="${label}"; value="-----BEGIN PRIVATE KEY-----"`,
 ])assert.equal(engine.scan(text).rule,'security.credentials');
 const cfg=structuredClone(defaults);cfg.rules.unshift({id:'custom.synthetic',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:[label],caseSensitive:true}});
 assert.equal(compile(cfg).scan(`errMissingPassword="${label}"`).rule,'custom.synthetic');
});
