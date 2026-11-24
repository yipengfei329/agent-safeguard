import test from 'node:test';
import assert from 'node:assert/strict';
import ipaddr from 'ipaddr.js';
import {compile,defaults} from '../dist/core.js';
import {createGeoIP,bundledGeoIP} from '../src/geoip.js';
import snapshot from '../data/geoip-country.js';
function envelope(v4,v6){
 const words=[...v4.flat(),...v6.flat()],buffer=Buffer.alloc(words.length*4);
 words.forEach((n,i)=>buffer.writeUInt32LE(n,i*4));let checksum=2166136261;
 for(const b of buffer)checksum=Math.imul(checksum^b,16777619)>>>0;
 return {schema:1,format:'cn-other-unknown-u32le-v1',month:'2026-11',sourceSha256:'a'.repeat(64),counts:[v4.length,v6.length],checksum,payload:buffer.toString('base64')};
}
// Entirely synthetic country assignments within documentation ranges.
const sample=envelope([[0xcb00710a,0xcb007114,1],[0xcb00711e,0xcb007128,2]],[[0x20010db8,0,0,10,0x20010db8,0,0,20,1],[0x20010db8,0,0,30,0x20010db8,0,0,40,2]]);
const geo=createGeoIP(sample),e=compile(defaults,{geoip:geo});
for(const [ip,state] of [['203.0.113.9',0],['203.0.113.10',1],['203.0.113.20',1],['203.0.113.21',0],['203.0.113.30',2],['203.0.113.40',2],['203.0.113.41',0],['2001:db8::9',0],['2001:db8::a',1],['2001:db8::14',1],['2001:db8::15',0],['2001:db8::1e',2],['2001:db8::28',2],['2001:db8::29',0],['::ffff:203.0.113.10',1],['::ffff:cb00:710a',1]]){
 test(`synthetic country boundary ${ip}`,()=>{
  assert.equal(geo.lookup(ipaddr.parse(ip)),state);
  for(const source of ['user.prompt','tool.result','prompt.context'])assert.equal(e.scan(ip,source).blocked,state===1);
 });
}
test('other and unknown never exempt adjacent secrets, hostnames or later CN addresses',()=>{
 for(const allowed of ['203.0.113.9','203.0.113.30']){
  assert.equal(e.scan(allowed).blocked,false);
  for(const sensitive of ['203.0.113.10','password=sY9!nT4_hE7#tI2-cK8','hostname: ExampleMac','serialNumber: SYNTHETIC12345'])assert.equal(e.scan(allowed+' '+sensitive).blocked,true);
 }
 assert.equal(e.scan({content:[{type:'text',text:JSON.stringify({peer:'203.0.113.10'})}]}).rule,'network.address');
 assert.equal(e.scan('203.0.\x1b[31m113.10.').rule,'network.address');
});
test('private exclusions precede GeoIP and custom strict modes remain available',()=>{
 const throwing=compile(defaults,{geoip:{lookup(){throw Error('DO_NOT_CALL');}}});
 for(const ip of ['127.0.0.1','192.168.1.1','10.0.0.1','fd00::1','::ffff:192.168.1.1'])assert.equal(throwing.scan(ip).blocked,false);
 assert.equal(throwing.scan('203.0.113.10').rule,'inspection.failed');
 const cfg=structuredClone(defaults);cfg.rules[0].detector={kind:'ip',mode:'cidr',cidrs:['203.0.113.0/24']};assert(compile(cfg).scan('203.0.113.9').blocked);
 cfg.rules[0].enabled=false;assert(!compile(cfg).scan('203.0.113.9').blocked);
});
test('country schema rejects policy changes and observe stays non-blocking',()=>{
 for(const change of [{country:'US'},{onUnknown:'block'},{mode:'remote'},{extra:true}]){
  const c=structuredClone(defaults);Object.assign(c.rules[0].detector,change);assert.throws(()=>compile(c));
 }
 const c=structuredClone(defaults);c.rules[0].action='observe';assert.deepEqual(compile(c,{geoip:geo}).scan('203.0.113.10'),{blocked:false,observed:['network.address']});
});
test('missing, corrupted, truncated and malformed databases are errors, not unknown',()=>{
 for(const bad of [null,{}, {...sample,schema:2},{...sample,counts:[0,2]},{...sample,counts:[1.5,2]},{...sample,checksum:0},{...sample,payload:sample.payload.slice(4)},{...sample,payload:'!'+sample.payload.slice(1)},{...sample,sourceSha256:'wrong'},envelope([[20,10,1]],[[1,0,0,0,1,0,0,1,1]]),envelope([[10,20,1],[20,30,2]],[[1,0,0,0,1,0,0,1,1]]),envelope([[10,20,3]],[[1,0,0,0,1,0,0,1,1]])])assert.throws(()=>createGeoIP(bad),/INVALID_GEOIP_DATABASE/);
});
test('bundled snapshot is reused, metadata is immutable and document IPs pass',()=>{
 assert.equal(bundledGeoIP(),bundledGeoIP());assert(Object.isFrozen(bundledGeoIP().metadata));
 const d=compile();assert.equal(d.geoip.month,snapshot.month);
 for(const ip of ['203.0.113.17','198.51.100.17','192.0.2.17','2001:db8::7'])assert.equal(d.scan(ip).blocked,false);
});
test('all bundled interval endpoints agree with encoded states',()=>{
 const bytes=Buffer.from(snapshot.payload,'base64');let offset=0;
 for(const [i,n] of [1,4].entries())for(let row=0;row<snapshot.counts[i];row++){
  const a=[],b=[];for(let j=0;j<n;j++,offset+=4)a.push(bytes.readUInt32LE(offset));for(let j=0;j<n;j++,offset+=4)b.push(bytes.readUInt32LE(offset));const state=bytes.readUInt32LE(offset);offset+=4;
  for(const words of [a,b]){
   const octets=words.flatMap(x=>[x>>>24,(x>>>16)&255,(x>>>8)&255,x&255]);const ip=ipaddr.fromByteArray(octets);
   // Mapped IPv6 deliberately uses IPv4 classification instead.
   if(ip.kind()==='ipv6'&&ip.isIPv4MappedAddress())continue;
   assert.equal(bundledGeoIP().lookup(ip),state);
  }
 }
});
