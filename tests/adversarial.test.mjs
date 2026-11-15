import test from 'node:test';
import assert from 'node:assert/strict';
import {compile,defaults} from './strict-engine.mjs';
const sources=['tool.input','tool.result','user.prompt','prompt.context'];
const clean=[
 'interface Config { hostname: string; device_id: string; }',
 'const hostname = os.hostname();', 'const serialNumber = device.serialNumber;',
 'func load(hostname: String, udid: String) {}',
 'public var device_id: String? = nil',
 'src/device.ts:28: const hostname = config.hostname;',
 'hostname == expectedHost', 'serialNumber == expectedSerial',
 '9::root{color:#abcdef} 33:.map::before{stroke-dasharray:2 4}',
 'const token = "Bearer " + sessionToken;', 'Authorization: Bearer ${SESSION_TOKEN}',
 'Authorization: Basic {{config.authorization}}',
 'const token = `Bearer ${session.token}`;',
 'device_id=\nnext/file.ts:40: value',
 'hostname:\nnext/file.ts:40: value',
 'password: # comment', 'password=${PASSWORD}',
 'Version v1.2.3.4; sha abcdef123; 999.888.777.666',
 'Author: Example <person@example.invalid> /Users/example/src',
 'http://127.0.0.1:8080 10.2.3.4 [fd00::3] fe80::1%en0',
 'notprivate.example.invalid private.example.invalid.evil.invalid',
];
const specs=[
 ['network.address','203.0.113.27', ['203.0.113.27.','peer [2001:db8::7]:443','peer 2001:db8::7.','::ffff:203.0.113.27']],
 ['identity.device','serialNumber: SYNTHETIC12345', ['hardware UUID: SYNTHETIC-12345','UDID="SYNTHETIC-12345"','ether aa:bb:cc:dd:ee:ff','MAC AA-BB-CC-DD-EE-FF','hardware  UUID: SYNTHETIC-12345',{device_id:'SYNTHETIC_DEVICE_123'}]],
 ['identity.environment','hostname: ExampleMac', ['computername=ExampleMac','localHostName: ExampleMac',{hostname:'ExampleMac'},{hostname:'x'}]],
 ['security.credentials','password=SYNTHETIC_PASSWORD', ['Authorization: Bearer SYNTHETIC_TOKEN','const token = "Bearer " + "SYNTHETIC_TOKEN"',{token:'SYNTHETIC_TOKEN'},'-----BEGIN PRIVATE KEY-----']],
 ['personal.synthetic-value','SYNTHETIC_DEVICE_ID_0001',['prefix SYNTHETIC_DEVICE_ID_0001 suffix']],
 ['personal.synthetic-domain','private.example.invalid',['PRIVATE.EXAMPLE.INVALID.','https://sub.private.example.invalid/a','private.example.invalid:443']],
 ['personal.synthetic-subnet','203.0.113.27',['203.0.113.255','2001:db8::7']],
];
const wrappers=[x=>x,x=>({stdout:x,stderr:''}),x=>({content:[{type:'text',text:x}]}),x=>({result:{deep:{value:x}}}),x=>JSON.stringify({payload:x}),x=>({content:[{type:'image',source:{type:'base64',media_type:'image/png',data:'AAAA'}},{type:'text',text:x}]}),x=>({isError:true,stderr:x}),x=>typeof x==='string'?'\x1b[31m'+x+'\x1b[0m':x];
for(const [id,base,values] of specs){
 const c=structuredClone(defaults);c.rules=c.rules.filter(r=>r.id===id);c.rules[0].enabled=true;c.rules[0].sources=sources;
 const engine=compile(c);
 for(const [i,value] of [base,...values].entries())for(const [w,wrap] of wrappers.entries())for(const source of sources)test(`${id} sensitive ${i} wrapper ${w} ${source}`,()=>assert.equal(engine.scan(wrap(value),source,'Bash').rule,id));
 for(const [i,value] of clean.entries())test(`${id} clean and mixed ${i}`,()=>{
  assert.equal(engine.scan(value).blocked,false,value);
  assert.equal(engine.scan(value+'\n'+base).rule,id);
  assert.equal(engine.scan({stdout:value,stderr:base}).rule,id);
 });
 for(const mode of ['disabled','observe','source','tool'])test(`${id} scope ${mode}`,()=>{
  const cfg=structuredClone(c),r=cfg.rules[0];
  if(mode==='disabled')r.enabled=false;
  if(mode==='observe')r.action='observe';
  if(mode==='source')r.sources=['user.prompt'];
  if(mode==='tool'){r.sources=['tool.result'];r.tools=['Read'];}
  const result=compile(cfg).scan(base,'tool.result','Bash');assert.equal(result.blocked,false);
  if(mode==='observe')assert.deepEqual(result.observed,[id]);
 });
}
test('deterministic address boundary corpus: 512 public/private pairs',()=>{
 const e=compile();
 for(let i=1;i<=128;i++)for(const [local,publicIP] of [[`10.23.4.${i}`,`203.0.113.${i}`],[`192.168.5.${i}`,`198.51.100.${i}`],[`fd00::${i.toString(16)}`,`2001:db8::${i.toString(16)}`],[`::ffff:192.168.5.${i}`,`::ffff:203.0.113.${i}`]]){
  assert.equal(e.scan(local).blocked,false);assert.equal(e.scan(publicIP).rule,'network.address');
  assert.equal(e.scan(local+' '+publicIP).rule,'network.address');
 }
});
test('exact matching case sensitivity and escaped nested JSON',()=>{
 const c=structuredClone(defaults);c.rules=[c.rules[4]];c.rules[0].detector.caseSensitive=false;
 assert.equal(compile(c).scan('synthetic_device_id_0001').blocked,true);
 assert.equal(compile().scan({content:[{type:'text',text:'{"address":"203.0.\\u0031\\u00313.7"}'}]}).blocked,true);
});

test('structured sensitive fields retain their meaning through arrays and numeric values',()=>{
 const e=compile();
 for(const value of [{token:['SYNTHETIC_TOKEN']},{hostname:['ExampleMac']},{device_id:[['SYNTHETIC12345']]}])assert.equal(e.scan(value).blocked,true);
 for(const value of [{password:123456},{password:null},{secret:false},{token:[]},{token:[null,false]},{token:{description:'documentation'}}])assert.equal(e.scan(value).blocked,false);
});

test('limits and malformed configurations remain fail closed',()=>{
 for(const change of [c=>c.policy.onUnsupportedContent='ignore',c=>c.limits.maxDepth=65,c=>c.rules[0].sources=['unknown'],c=>c.rules[0].tools=['Bash'],c=>c.rules[4].detector.values=[],c=>c.rules.push(c.rules[0])]){const c=structuredClone(defaults);change(c);assert.throws(()=>compile(c));}
 const c=structuredClone(defaults);c.limits.maxNodes=8;assert.equal(compile(c).scan(Array(20).fill('safe')).rule,'inspection.failed');
 const e=compile(),shared={text:'clean'};assert.equal(e.scan([shared,shared]).blocked,false);
 const cycle={type:'image'};cycle.caption=cycle;assert.equal(e.scan(cycle).rule,'inspection.failed');
});
