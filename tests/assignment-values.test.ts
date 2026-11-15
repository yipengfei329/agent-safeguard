import {test,expect} from 'claude-code/testing';
function setup(on){on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));on('turn.start',($,e)=>({turnId:e.turnId}));on('turn.abort',()=>({value:undefined}));}
const source='    device_id = identity_service.resolve_identity(\n        payload.device_id,\n    )\n    hostname = names.resolve_host(request)\n    api_key = credentials.resolve_key(request)\n';
for(const [name,output,rule,error] of [
 ['python-calls',source,null,false],
 ['error-calls',source,null,true],
 ['member-reference','device_id = payload.device_id\nhostname = names.current_host',null,false],
 ['identity-prose','{"device_id":"Enter the device identifier","hostname":"<binding:host>"}',null,false],
 ['device-literal',source+'\ndevice_id="SYNTHETIC456789"','identity.device',false],
 ['host-literal',source+'\nhostname="SyntheticHost"','identity.environment',false],
 ['error-literal',source+'\nserialNumber="SYNTHETIC456789"','identity.device',true],
 ['credential-literal',source+'\npassword="pM8!sQ3_vL7#rD5-tN2@xK9"','security.credentials',false],
])test('shared value result '+name,async($,on)=>{
 setup(on);let calls=0;on('tool.call',()=>({isError:error,result:{stdout:output}}));
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});await $.turn.start({turnId:'t',text:'probe'});
 const r=await $.tool.call({tool:'Bash',command:'read synthetic source'});
 if(rule){expect(r.deny).toBe('SAFEGUARD_BLOCKED');const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);expect(status.lastRule).toBe(rule);expect(status.lastReason).toBe('literal-value');}else expect(r.result.stdout).toBe(output);
 const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});while(!(await it.next()).done){}
 expect(calls).toBe(rule?0:1);
});
test('shared extractor mixed-field latency',{timeoutMs:30000},async($,on)=>{
 setup(on);let output='';on('tool.call',()=>({result:{stdout:output}}));await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 for(const bytes of [10240,102400,1048576])for(const concurrency of [1,4]){
  output=source.repeat(Math.floor(bytes/source.length)).padEnd(bytes,' ');const samples=[];
  for(let i=0;i<25;i++)await Promise.all(Array.from({length:concurrency},async()=>{
   const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'read synthetic source'});expect(r.result.stdout.length).toBe(bytes);if(i>=5)samples.push(Date.now()-start);
  }));
  samples.sort((a,b)=>a-b);const q=p=>samples[Math.min(samples.length-1,Math.ceil(samples.length*p)-1)];
  console.log(JSON.stringify({scope:'native-shared-values',bytes,concurrency,rules:6,samples:samples.length,p50:q(.5),p95:q(.95),p99:q(.99)}));
 }
});
