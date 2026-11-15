import {test,expect} from 'claude-code/testing';
import {defaults} from '../dist/core.js';
const samples=[['network.address','2001:db8::7.'],['identity.device','serialNumber: SYNTHETIC12345'],['identity.environment','hostname: ExampleMac'],['security.credentials','password=SYNTHETIC_PASSWORD'],['personal.synthetic-value','SYNTHETIC_DEVICE_ID_0001'],['personal.synthetic-domain','PRIVATE.EXAMPLE.INVALID.'],['personal.synthetic-subnet','203.0.113.27']];
for(const [id,value] of samples)test(id+' blocks a mixed result and prevents later dispatch',async($,on)=>{
 const c=JSON.parse(JSON.stringify(defaults));c.rules=c.rules.filter(r=>r.id===id);c.rules[0].enabled=true;if(id==='network.address'){c.rules[0].detector.mode='any';delete c.rules[0].detector.country;delete c.rules[0].detector.onUnknown;}c.rules[0].sources=['tool.result'];
 on('fs.exists',($,e)=>({value:!e.path.endsWith('desktop.json')}));on('fs.read',()=>({value:JSON.stringify(c)}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/work'}));on('turn.start',($,e)=>({turnId:e.turnId}));on('turn.abort',()=>({value:undefined}));
 on('tool.call',()=>({result:{content:[{type:'image',source:{type:'base64',media_type:'image/png',data:'AAAA'}},{type:'text',text:'interface Config { hostname: string; device_id: string; }'},{type:'text',text:value}]}}));
 let calls=0;on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});await $.turn.start({turnId:'t',text:'fixture'});
 expect((await $.tool.call({tool:'Read',file_path:'/work/fixture'})).deny).toBe('SAFEGUARD_BLOCKED');
 const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});let r=await it.next();while(!r.done)r=await it.next();expect(calls).toBe(0);
 expect(JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text).lastRule).toBe(id);
});
