import test from 'node:test';import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
import {symbolName,symbolReference} from '../src/symbol-values.js';
import {symbolNames,symbolSecrets,namingPrefixes} from '../fixtures/symbolic-values.mjs';
const engine=compile();const sources=['tool.input','tool.result','user.prompt','prompt.context'];
for(const field of ['secret','api_key','token','password'])test('explicit symbolic name slots '+field,()=>{
 for(const name of symbolNames)for(const prefix of namingPrefixes)for(const rhs of [name,`"${name}"`,`'${name}'`,`\`${name}\``]){
  const text=`${prefix}${field}: ${rhs} (configured by operator)`;
  assert.equal(engine.scan(text).blocked,false,text);
 }
});
test('reference expressions are complete and contain only symbolic indexes',()=>{
 for(const name of symbolNames)for(const value of [
  `secrets.${name}`,`secrets['${name}']`,`env["${name}"]`,`process.env.${name}`,`settings[${name}]`,`settings['auth'].${name}`,
  '${'+name+'}','${{ secrets.'+name+' }}',
 ])for(const input of [{secret:value},JSON.stringify({token:value}),`# token: ${value}`])assert.equal(engine.scan(input).blocked,false);
 assert.equal(symbolName('UNSEGMENTEDRANDOMMATERIAL'),false);assert.equal(symbolName('A'.repeat(129)+'_TOKEN'),false);
 assert.equal(symbolReference('secrets["pM8!sQ3_vL7#rD5-tN2@xK9"]'),false);
 for(const value of symbolSecrets.slice(0,4))assert.equal(engine.scan({secret:`secrets['${value}']`}).rule,'security.credentials');
});
test('ordinary comment values and structured data retain credential detection',()=>{
 for(const source of sources)for(const value of symbolSecrets)for(const input of [
  `# token=${value}`,`// secret: ${value}`,`/* api_key="${value}" */`,`# password: '${value}'`,
  {token:value},JSON.stringify({password:value}),`token="${value}"`,
 ])assert.equal(engine.scan(input,source,'Bash').rule,'security.credentials');
 // Even the exact same uppercase name remains a value outside a name slot.
 for(const name of symbolNames)for(const input of [{secret:name},`# secret: ${name}`,`token=${name}`,`# Repository secret="${name}"`])assert.equal(engine.scan(input).rule,'security.credentials');
});
test('name declarations cannot swallow literal concatenation or adjacent values',()=>{
 for(const secret of symbolSecrets.slice(0,4))for(const prefix of namingPrefixes){
  for(const text of [
   `${prefix}secret: ${secret}`,`${prefix}secret: "${secret}"`,
   `${prefix}secret: "ORCHARD_BUILD_TOKEN" + "${secret}"`,
   `${prefix}secret: ORCHARD_BUILD_TOKEN; password="${secret}"`,
   `${prefix}secret: ORCHARD_BUILD_TOKEN\n# secret: ${secret}`,
  ])assert.equal(engine.scan(text).rule,'security.credentials');
 }
 for(const text of [
  '# Repository secret: ORCHARD_BUILD_TOKEN\n# secret: ORCHARD_BUILD_TOKEN',
  '# Repository secret: "ORCHARD_BUILD_TOKEN"\nsecret="ORCHARD_BUILD_TOKEN"',
 ])assert.equal(engine.scan(text).rule,'security.credentials');
});
test('names do not bypass explicit formats, exact rules or other field policies',()=>{
 const cfg=structuredClone(defaults);cfg.rules.push({id:'custom.symbol',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['ORCHARD_BUILD_TOKEN'],caseSensitive:true}});
 assert.equal(compile(cfg).scan('# Repository secret: ORCHARD_BUILD_TOKEN').rule,'custom.symbol');
 for(const text of ['# Repository secret: ghp_'+'Z'.repeat(36),'# Repository secret: -----BEGIN PRIVATE KEY-----','# Repository secret: redis://:ORCHARD_BUILD_TOKEN@cache.example.invalid'])assert.equal(engine.scan(text).rule,'security.credentials');
 for(const [field,rule] of [['device_id','identity.device'],['hostname','identity.environment']])assert.equal(engine.scan(`# Repository ${field}: ORCHARD_BUILD_TOKEN`).rule,rule);
});
test('shared extractor still handles cross-language uppercase variable references',()=>{
 const cfg=structuredClone(defaults);for(const r of cfg.rules)if(r.detector.kind==='builtin')r.sources=sources;const e=compile(cfg);
 for(const field of ['token','password','device_id','hostname'])for(const text of [
  `const ${field} = ORCHARD_BUILD_VALUE;`,`let ${field}: String = ORCHARD_BUILD_VALUE;`,
  `${field} := ORCHARD_BUILD_VALUE`,`    ${field} = ORCHARD_BUILD_VALUE`,
  `${field} = settings.ORCHARD_BUILD_VALUE`,`const options = {${field}: ORCHARD_BUILD_VALUE};`,
 ])for(const source of sources)assert.equal(e.scan(text,source,'Bash').blocked,false,text);
});

test('hash comments cannot turn actual values into source-code references',()=>{
 for(const secret of symbolSecrets)for(const prefix of ['# const ','// const ','/* const ','echo example # const ']){
  assert.equal(engine.scan(`${prefix}token = ${secret};`).rule,'security.credentials');
 }
});
