import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {compile,defaults} from './strict-engine.mjs';
const cases=JSON.parse(readFileSync(new URL('../fixtures/replays.json',import.meta.url)));
for(const c of cases)test(c.name,()=>assert.equal(compile().scan(c.value).blocked,c.block));
test('尾部命中1MiB',()=>assert.equal(compile().scan('x'.repeat(1000000)+' 203.0.113.7').blocked,true));
test('超限与深度不能放行',()=>{const e=compile();assert(e.scan('x'.repeat(4194305)).blocked);let v={};for(let i=0;i<66;i++)v={v};assert(e.scan(v).blocked);});
test('循环对象不能放行',()=>{const v={};v.self=v;assert(compile().scan(v).blocked);});
test('配置错误拒绝加载',()=>{for(const change of [c=>c.rules.push(c.rules[0]),c=>c.rules[0].detector={kind:'remote-ai'},c=>c.policy.onInspectionFailure='allow',c=>c.rules[4].detector.values=['']]){let c=structuredClone(defaults);change(c);assert.throws(()=>compile(c));}});
test('版本迭代新增特征',()=>{let c=structuredClone(defaults);const old=compile(c);c.ruleSetVersion='0.2';c.rules[4].detector.values=['NEW_SYNTHETIC_VALUE'];const next=compile(c);assert(!old.scan('NEW_SYNTHETIC_VALUE').blocked);assert(next.scan('NEW_SYNTHETIC_VALUE').blocked);});
test('CIDR范围和IPv6',()=>{let c=structuredClone(defaults);c.rules=[{...c.rules[0],detector:{kind:'ip',mode:'cidr',cidrs:['203.0.113.0/24','2001:db8::/32']}}];const e=compile(c);assert(e.scan('203.0.113.9').blocked);assert(e.scan('2001:db8::9').blocked);assert(!e.scan('192.168.10.1').blocked);});
test('JSON包裹ANSI文本仍阻断',()=>assert(compile().scan(JSON.stringify('203.0.\x1b[31m113.7')).blocked));
test('长无分隔符文本不误报',()=>assert(!compile().scan('x'.repeat(1048576)).blocked));
test('observe只记录规则编号而不阻断',()=>{let c=structuredClone(defaults);c.rules=[{...c.rules[0],action:'observe'}];const r=compile(c).scan('203.0.113.7');assert.equal(r.blocked,false);assert.deepEqual(r.observed,['network.address']);});
test('编译快照不受原配置后续修改影响',()=>{const c=structuredClone(defaults),e=compile(c);c.rules[4].detector.values[0]='DIFFERENT_VALUE';assert(e.scan('SYNTHETIC_DEVICE_ID_0001').blocked);});

test('用户路径各入口放行，混合敏感值继续命中',()=>{const e=compile();for(const source of ['user.prompt','tool.result','prompt.context']){assert.equal(e.scan('/Users/example/Code/project',source).blocked,false);assert.equal(e.scan('/home/example/src/project',source).blocked,false);for(const suffix of ['203.0.113.7','password=SYNTHETIC_SECRET','serialNumber: SYNTHETIC12345','hostname: ExampleMac'])assert.equal(e.scan('/Users/example/Code/project '+suffix,source).blocked,true,suffix);}});

test('邮箱在各入口放行，同一内容中的其他风险仍被检测',()=>{const e=compile();for(const source of ['user.prompt','tool.result','prompt.context']){for(const value of ['Author: Example <person@example.invalid>','Co-authored-by: Example Bot <bot@example.invalid>',{email:'person@example.invalid'}])assert.equal(e.scan(value,source).blocked,false);for(const suffix of ['203.0.113.7','password=SYNTHETIC_SECRET','serialNumber: SYNTHETIC12345','hostname: ExampleMac'])assert.equal(e.scan('person@example.invalid '+suffix,source).blocked,true,suffix);}});

test('本机、内网、共享和Fake IP各入口放行，覆盖边界及IPv4映射',()=>{
 const e=compile();const allowed=['0.0.0.0','10.0.0.0','10.255.255.255','100.64.0.0','100.127.255.255','127.0.0.1','127.255.255.255','169.254.0.0','169.254.255.255','172.16.0.0','172.31.255.255','192.168.0.0','192.168.255.255','198.18.0.0','198.19.255.255','255.255.255.255','::','::1','fc00::1','fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff','fe80::1%en0','febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff','::ffff:127.0.0.1','::ffff:192.168.50.1','::ffff:c0a8:3201','fd00:aa:bb:cc:dd:ee:ff:1'];
 for(const source of ['user.prompt','tool.result','prompt.context'])for(const ip of allowed)assert.equal(e.scan('address ['+ip+']',source).blocked,false,ip);
 assert.equal(e.scan({content:[{type:'text',text:JSON.stringify({address:'[fe80::1%en0]:8080',url:'http://127.0.0.1:8080'})}]}).blocked,false);
});
test('内网边界外的地址不被扩大放行',()=>{
 const e=compile();for(const ip of ['9.255.255.255','11.0.0.0','100.63.255.255','100.128.0.0','126.255.255.255','128.0.0.0','169.253.255.255','169.255.0.0','172.15.255.255','172.32.0.0','192.167.255.255','192.169.0.0','198.17.255.255','198.20.0.0','fbff::1','fe00::1','fe7f::1','fec0::1','2001:db8::7','::ffff:203.0.113.7','::ffff:cb00:7107'])assert.equal(e.scan(ip).rule,'network.address',ip);
});
test('本地地址不豁免其他地址或凭据设备规则',()=>{
 const e=compile();for(const sensitive of ['203.0.113.7','2001:db8::7','::ffff:203.0.113.7','password=SYNTHETIC_SECRET','serialNumber: SYNTHETIC12345','ether aa:bb:cc:dd:ee:ff','hostname: ExampleMac']){
  for(const text of ['127.0.0.1 192.168.50.1 '+sensitive,sensitive+' fd00::1'])assert(e.scan(text).blocked,sensitive);
 }
});
test('网段豁免配置可撤回，且不影响其他精确规则',()=>{
 const c=structuredClone(defaults);delete c.rules[0].detector.excludeCidrs;
 assert(compile(c).scan('127.0.0.1').blocked);
 c.rules[0].detector.excludeCidrs=['127.0.0.0/8'];assert(!compile(c).scan('127.0.0.1').blocked);assert(compile(c).scan('192.168.50.1').blocked);
 c.rules[4].detector.values=['127.0.0.1'];assert.equal(compile(c).scan('127.0.0.1').rule,'personal.synthetic-value');
 c.rules[0].detector.excludeCidrs=['not-a-cidr'];assert.throws(()=>compile(c));
 c.rules[0].detector.excludeCidrs=['127.0.0.0/99'];assert.throws(()=>compile(c));
 c.rules[0].detector.excludeCidrs=['127.0.0.0/8'];c.limits.maxMatchValues=1;assert.throws(()=>compile(c));
});

test('显式类型声明不当作凭据，真实初始化值仍阻断',()=>{
 const e=compile();const clean=['public var secret: Bool = false','public var secret: Bool = true','let password: String','private let apiKey: String? = nil','const token: string;','let authorization: string | null = null','public var secret: Foundation.Data = Data()'];
 for(const source of ['user.prompt','tool.input','tool.result','prompt.context'])for(const s of clean)assert.equal(e.scan(s,source).blocked,false,s);
 for(const s of ['let password: String = "SYNTHETIC_PASSWORD"','const token: string = "SYNTHETIC_TOKEN"','public var secret: Bool = false; password=SYNTHETIC_PASSWORD','public var secret: Bool = false\nAuthorization: Bearer SYNTHETIC_TOKEN',JSON.stringify({token:'SYNTHETIC_TOKEN'})])assert.equal(e.scan(s).rule,'security.credentials',JSON.stringify(s));
});

test('类型声明只豁免自身且保留其他字段和其他规则',()=>{
 const e=compile();for(const text of ['const access_token: string = "SYNTHETIC_TOKEN"','const refreshToken: string = "SYNTHETIC_TOKEN"','let secret: Data = Data(base64Encoded: "SYNTHETIC_SECRET")','public var secret: Bool = false // api_key=SYNTHETIC_KEY','public var secret: Bool = false\n{"token":"SYNTHETIC_TOKEN"}','public var secret: Bool = false\n-----BEGIN PRIVATE KEY-----','public var secret: Bool = false\nsocks5://example:SYNTHETIC_SECRET@proxy.example.invalid'])assert.equal(e.scan(text).rule,'security.credentials',text);
 for(const value of [{token:'Bool'},{secret:'String'},{secret:'Foundation.Data'},JSON.stringify({secret:'Bool'})])assert.equal(e.scan(value).blocked,false);
 assert.equal(e.scan('public var secret: Bool = false\n203.0.113.7').rule,'network.address');
});

// grep's line delimiter plus a CSS pseudo selector must not form a partial IPv6.
test('CSS grep line prefixes are not truncated IPv6 addresses',()=>{
 const e=compile();
 for(const selector of [':root','::before','::after','::first-letter','::placeholder',':hover']) {
  const output='9:'+selector+'{--live:#5f6b85;color:red}';
  assert.equal(e.scan(output).blocked,false,selector);
  assert.equal(e.scan(output+'\n2001:db8::7').rule,'network.address');
  assert.equal(e.scan(output+'\npassword=SYNTHETIC_PASSWORD').rule,'security.credentials');
 }
 for(const address of ['2001:db8::7','[2001:db8::7]:443','9::','[9::]','::ffff:203.0.113.7','2001:db8::7%en0'])assert.equal(e.scan(address).rule,'network.address',address);
});
