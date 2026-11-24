import test from 'node:test';
import assert from 'node:assert/strict';
import {compile,defaults} from '../dist/core.js';
const uuid='11111111-2222-4333-8444-555555555555';
const record={architecture:'arm64',deviceId:uuid,deviceName:'Synthetic E2E',modelName:'Synthetic Phone',platform:'iOS Simulator'};
const profile=structuredClone(defaults);profile.rules.find(r=>r.id==='identity.device').sources.push('tool.input');
const e=compile(profile);
const grep=text=>text.split('\n').map((s,i)=>`${i+1}${i===0?':':'-'}${s}`).join('\n');
const wrappers=[v=>v,v=>({stdout:v,stderr:''}),v=>({content:[{type:'text',text:typeof v==='string'?v:JSON.stringify(v)}]}),v=>JSON.stringify({result:v})];
const allowed=[record,{devices:[record]},JSON.stringify(record),JSON.stringify({devices:[record]},null,2),
 'UI tests failed:\n'+JSON.stringify({devices:[record]},null,2)+'\nlast output: compile failed',
 grep(JSON.stringify({devices:[record]},null,2)),
 JSON.stringify([record,{...record,platform:'tvOS Simulator'}]),
 ...['deviceId','device_id','device-id','udid'].map(key=>({[key]:uuid,platform:'iOS Simulator'})),
 ...['watchOS Simulator','visionOS Simulator'].map(platform=>({...record,platform})),
];
for(const [i,value] of allowed.entries())for(const [j,wrap] of wrappers.entries())test(`simulator record ${i} wrapper ${j}`,()=>{
 for(const source of ['user.prompt','tool.input','tool.result','prompt.context'])assert.equal(e.scan(wrap(value),source,'Bash').blocked,false);
 // Never allow a whole result because it contains a simulator.
 assert.equal(e.scan({result:wrap(value),other:{deviceId:uuid}}).rule,'identity.device');
 assert.equal(e.scan({result:wrap(value),other:'password=sY9!nT4_hE7#tI2-cK8'}).rule,'security.credentials');
});
const rejected=[
 {deviceId:uuid}, {...record,platform:'iOS'}, {...record,platform:'macOS'},
 {...record,platform:'iOS Simulator connected to real device'},
 {deviceId:uuid,description:'iOS Simulator'},
 {platform:'iOS Simulator',child:{deviceId:uuid}},
 {platform:'iOS Simulator',deviceId:[uuid]},
 {platform:'iOS Simulator',deviceId:'SYNTHETIC_REAL_DEVICE_ID'},
 {platform:'iOS Simulator',serialNumber:'SYNTHETIC12345'},
 {platform:'iOS Simulator',hardwareUUID:uuid},
 {platform:'iOS Simulator',mac:'aa:bb:cc:dd:ee:ff'},
 {devices:[record,{deviceId:uuid,platform:'iOS'}]},
 {devices:[{deviceId:uuid},record]},
 'iOS Simulator\ndeviceId: '+uuid,
 JSON.stringify(record).slice(0,-1),
 'deviceId='+uuid+'\n'+JSON.stringify(record),
 // Same value in a nested or adjacent real device must still be detected.
 JSON.stringify({...record,child:{deviceId:uuid}}),
 grep(JSON.stringify({devices:[record,{deviceId:uuid,platform:'iOS'}]},null,2)),
 grep(JSON.stringify({...record,child:{deviceId:uuid}},null,2)),
];
for(const [i,value] of rejected.entries())for(const [j,wrap] of wrappers.entries())test(`real or ambiguous identity ${i} wrapper ${j}`,()=>{
 for(const source of ['user.prompt','tool.input','tool.result','prompt.context'])assert.equal(e.scan(wrap(value),source,'Bash').rule,'identity.device');
});
test('same-record exception does not bypass custom exact rules or IP and environment checks',()=>{
 const cfg=structuredClone(defaults);cfg.rules.push({id:'custom.uuid',enabled:true,sources:['tool.result'],action:'block',detector:{kind:'exact',values:[uuid],caseSensitive:true}});
 for(const value of [record,JSON.stringify(record),grep(JSON.stringify(record,null,2))])assert.equal(compile(cfg).scan(value).rule,'custom.uuid');
 assert.equal(e.scan({...record,address:'1.0.1.7'}).rule,'network.address');
 assert.equal(e.scan({...record,hostname:'SyntheticHost'}).rule,'identity.environment');
 assert.equal(e.scan({...record,api_key:'rQ7!mL2_zA9#vC4-pF8@tN6'}).rule,'security.credentials');
});
test('simulator scan stays within traversal limits and does not mutate input',()=>{
 const original=structuredClone(record);assert(!e.scan(record).blocked);assert.deepEqual(record,original);
 assert.equal(e.scan({platform:'iOS Simulator',data:'x'.repeat(4194305)}).rule,'inspection.failed');
 const cfg=structuredClone(defaults);cfg.rules.find(r=>r.id==='identity.device').enabled=false;
 assert(!compile(cfg).scan({deviceId:uuid}).blocked);
});

test('head truncation removes simulator evidence; summary projection excludes identifiers',()=>{
 const report={devices:[record],testNodes:[{name:'Synthetic test',result:'Passed'}]};
 const raw=JSON.stringify(report,null,2),head=raw.split('\n').slice(0,5).join('\n');
 assert.equal(e.scan(head).rule,'identity.device');
 assert.equal(e.scan(raw).blocked,false);
 const summary=JSON.stringify({testNodes:report.testNodes});
 assert.equal(e.scan(summary).blocked,false);assert(!summary.includes(uuid));
 // A neighboring physical record is not covered by the simulator exception.
 assert.equal(e.scan({devices:[record,{deviceId:uuid,platform:'iOS'}]}).rule,'identity.device');
});
