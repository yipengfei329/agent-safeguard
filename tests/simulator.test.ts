import {test,expect} from 'claude-code/testing';
const uuid='11111111-2222-4333-8444-555555555555';
const record={deviceId:uuid,platform:'iOS Simulator',deviceName:'Synthetic E2E'};
const grep=JSON.stringify({devices:[record]},null,2).split('\n').map((v,i)=>`${i+1}-${v}`).join('\n');
const cases=[['structured',record,false],['grep',grep,false],['real',{...record,platform:'iOS'},true],['mixed',{devices:[record,{deviceId:uuid}]},true],['serial',{...record,serialNumber:'SYNTHETIC12345'},true],['credential',{...record,token:'sY9!nT4_hE7#tI2-cK8'},true]];
for(const [name,value,blocked] of cases)test(`simulator adapter ${name}`,async($,on)=>{
 on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));
 on('tool.call',()=>({result:{output:value}}));let calls=0;
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});const result=await $.tool.call({tool:'Bash',command:'read test log'});
 if(blocked)expect(result.deny).toBe('SAFEGUARD_BLOCKED');else expect(JSON.stringify(result.result.output)).toBe(JSON.stringify(value));
 const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});let next=await it.next();while(!next.done)next=await it.next();expect(calls).toBe(blocked?0:1);
});
test('native simulator log latency and concurrent clean results', {timeoutMs:30000},async($,on)=>{
 on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));
 let output='';on('tool.call',()=>({result:{stdout:output,stderr:''}}));await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 for(const bytes of [10240,102400])for(const concurrency of [1,4]){
  output=(grep+'\n').repeat(Math.floor(bytes/(grep.length+1))).padEnd(bytes,' ');const samples=[];
  for(let i=0;i<25;i++)await Promise.all(Array.from({length:concurrency},async()=>{const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'read test log'});expect(r.result.stdout.length).toBe(bytes);if(i>=5)samples.push(Date.now()-start);}));
  samples.sort((a,b)=>a-b);const q=p=>samples[Math.ceil(p*samples.length)-1];console.log(JSON.stringify({scope:'native-simulator-log',bytes,rules:6,concurrency,p50:q(.5),p95:q(.95),p99:q(.99)}));
 }
});
