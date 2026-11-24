import {test,expect} from 'claude-code/testing';
// Public database-derived probes, never contacted. No user IPs or transcripts.
const cn='1.0.1.7',cn6='2400:3200::7';
function setup(on){on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));}
for(const [name,value,blocked] of [['cn',cn,true],['cn6',cn6,true],['mapped','::ffff:'+cn,true],['other','8.8.8.8',false],['unknown','203.0.113.7 2001:db8::7',false],['mixed','8.8.8.8 '+cn,true],['other-secret','8.8.8.8 password=sY9!nT4_hE7#tI2-cK8',true]])test(`country hook ${name}`,async($,on)=>{
 setup(on);on('tool.call',()=>({result:{stdout:value,stderr:''}}));let calls=0;
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});const r=await $.tool.call({tool:'Bash',command:'fixture'});
 if(blocked)expect(r.deny).toBe('SAFEGUARD_BLOCKED');else expect(r.result.stdout).toBe(value);
 const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});let step=await it.next();while(!step.done)step=await it.next();expect(calls).toBe(blocked?0:1);
 const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);expect(status.geoip.country).toBe('CN');expect(status.geoip.onUnknown).toBe('allow');
});
for(const [value,blocked] of [[cn,true],['8.8.8.8 203.0.113.7',false]])test(`country prompt ${blocked}`,async($,on)=>{
 setup(on);on('prompt.submit',($,e)=>({text:e.text}));const r=await $.prompt.submit({text:String(value)});if(blocked)expect(r.drop).toContain('SAFEGUARD_BLOCKED');else expect(r.text).toBe(value);
});
test('country native full-path latency', {timeoutMs:30000},async($,on)=>{
 setup(on);let output='';on('tool.call',()=>({result:output}));let t=Date.now();await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});console.log(JSON.stringify({scope:'country-native-init',ms:Date.now()-t}));
 for(const count of [1,100,1000])for(const concurrency of [1,4]){
  output=Array.from({length:count},(_,i)=>`peer${i}=203.0.113.${i%254+1}`).join('\n');const samples=[];
  for(let i=0;i<35;i++)await Promise.all(Array.from({length:concurrency},async()=>{const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'fixture'});expect(r.result).toBe(output);if(i>=5)samples.push(Date.now()-start);}));
  samples.sort((a,b)=>a-b);const q=p=>samples[Math.ceil(p*samples.length)-1];console.log(JSON.stringify({scope:'country-native-full-scan',addresses:count,bytes:output.length,activeRules:6,concurrency,p50:q(.5),p95:q(.95),p99:q(.99)}));
 }
});
