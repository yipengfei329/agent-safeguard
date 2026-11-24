import test from 'node:test';
import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
const engine=compile();
const sources=['tool.input','tool.result','user.prompt','prompt.context'];
const opaque='rQ7!mL2_zA9#vC4-pF8@tN6';
const clean=[
 'pub api_key: String,','token: AuthenticationChallengeConfiguration,','token: customTokenReference','pub(crate) token: Option<String>,',
 "pub(super) access_token: Option<std::borrow::Cow<'a, str>>,",
 "fn connect(api_key: &'static str, password: Option<String>) {}",
 'let api_key: Option<String> = config.api_key.clone();',
 'struct Credentials { pub token: std::sync::Arc<SecretString>, pub password: String }',
 'pub token: [u8; 32],', 'pub token: (String, Option<Vec<u8>>),',
 'pub token: Result<Vec<String>, AuthError>,',
 'async fn connect<T>(token: &T) -> Result<(), Error> {}',
 'fn connect(\n token: Option<String>,\n password: &str,\n) {}',
 'interface Options { token?: Readonly<Array<string>>; password: string | null }',
 'function connect(token: Record<string, string> = options.token) {}',
 'class Options { public token: Promise<string>; }',
 'def connect(token: Optional[str], password: str = None): pass',
 'let token = Some(config.token.clone());',
 'const token = getSecret("TOKEN_ENV_VARIABLE");',
 'const token = {description: "An authentication token is optional"};',
 'var token: String { get }',
 'App/Push.swift:23: if token == nil, arguments.contains("-SyntheticTestApprove") { token = "simulator" }',
 'if testMode { token = "localstub" }; password = config.password',
 {token:'Authentication',secret:'Authenticator'},
 {token:'String',password:'getSecret()',secret:'Bool'},
 {token:'config.token',api_key:'your_api_key_here',password:'changeme'},
 {token:['false','simulator','${TOKEN}']},
 {password:123456},'password=true','secret: Bool','password=String',
 'token="a short description"','token=INSERT_API_KEY_HERE',
 'secret: [REDACTED]','pub token: Option<String>, // no value',
 '// arbitrary opaque text outside a credential field: '+opaque,
];
const wrappers=[x=>x,x=>({stdout:x,stderr:''}),x=>({content:[{type:'text',text:typeof x==='string'?x:JSON.stringify(x)}]}),x=>JSON.stringify({payload:x})];
for(const [i,value] of clean.entries())for(const [w,wrap] of wrappers.entries())test(`low-confidence content ${i} wrapper ${w}`,()=>{
 for(const source of sources)assert.equal(engine.scan(wrap(value),source,'Edit').blocked,false,JSON.stringify(value));
 // An allowed declaration/placeholder never exempts adjacent actual material.
 for(const source of sources)assert.equal(engine.scan({result:wrap(value),stderr:'api_key='+opaque},source,'Edit').rule,'security.credentials');
});
const secrets=[
 `pub const TOKEN: &str = "${opaque}";`,
 `let api_key: Option<String> = Some("${opaque}".into());`,
 `let token: std::sync::Arc<SecretString> = SecretString::new("${opaque}");`,
 `let token = Some(String::from("${opaque}"));`,
 `Options { token: Some('${opaque}') }`,
 `const token = "Bearer " + "${opaque}";`,
 `token = "${opaque.slice(0,10)}" + "${opaque.slice(10)}"`,
 `password=${opaque}`,`export API_KEY=${opaque}`,`Authorization: Bearer ${opaque}`,
 {token:opaque},{password:opaque},{token:[opaque]},
 `token: |\n  ${opaque}`,
 'token='+('a19c7e2d03f8b6a4'.repeat(2)),
 'token=qweryuplkjhgfdsmnbvcxzetaop',
 'token=ghp_'+'A'.repeat(36),
 '// -----BEGIN PRIVATE KEY-----',
 'https://user:short@service.example.invalid',
 // A schema declaration followed by another actual value on the same line.
 `pub api_key: String, // password=${opaque}`,
];
for(const [i,value] of secrets.entries())for(const [w,wrap] of wrappers.entries())test(`concrete secret ${i} wrapper ${w}`,()=>{
 for(const source of sources)assert.equal(engine.scan(wrap(value),source,'Edit').rule,'security.credentials',JSON.stringify(value));
});
test('Edit return with full source and patch metadata passes without excluding those fields',()=>{
 const source=clean.filter(x=>typeof x==='string').join('\n');
 const result={filePath:'/synthetic/api.rs',originalFile:source,newString:'pub token: Option<String>,',structuredPatch:[{lines:['+pub api_key: String,']}]};
 assert.equal(engine.scan(result).blocked,false);
 result.structuredPatch[0].lines.push('+api_key='+opaque);assert.equal(engine.scan(result).rule,'security.credentials');
});
test('JSON semantic credential scan preserves raw exact matching and key inheritance',()=>{
 const cfg=structuredClone(defaults);
 cfg.rules=[{id:'custom.raw',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:['{"marker":"literal"}'],caseSensitive:true}}];
 assert.equal(compile(cfg).scan('{"marker":"literal"}').rule,'custom.raw');
 assert.equal(engine.scan({token:JSON.stringify([opaque])}).rule,'security.credentials');
 assert.equal(engine.scan(JSON.stringify(JSON.stringify({token:opaque}))).rule,'security.credentials');
});
test('generic ambiguity exceptions do not weaken explicit authentication or identity rules',()=>{
 assert.equal(engine.scan('https://user:changeme@service.example.invalid').rule,'security.credentials');
 assert.equal(engine.scan({hostname:'placeholder'}).blocked,false);
 assert.equal(engine.scan({device_id:'placeholder'}).blocked,false);
 assert.equal(engine.scan({hostname:'SyntheticHost'}).rule,'identity.environment');
 assert.equal(engine.scan({device_id:'SYNTHETIC12345'}).rule,'identity.device');
});
