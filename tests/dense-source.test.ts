import {test,expect} from 'claude-code/testing';
import {denseSource} from '../fixtures/dense-source.mjs';
function setup(on){on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));on('turn.start',($,e)=>({turnId:e.turnId}));on('turn.abort',()=>({value:undefined}));}
for(const unique of [false,true])test('dense full-path unique='+unique,{timeoutMs:60000},async($,on)=>{
 setup(on);let output='';on('tool.call',()=>({result:{stdout:output}}));await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 for(const bytes of [10240,102400,1048576])for(const concurrency of [1,4]){
  output=denseSource(bytes,unique);const samples=[];
  for(let i=0;i<25;i++)await Promise.all(Array.from({length:concurrency},async()=>{const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'read fixture'});expect(r.deny).toBeUndefined();expect(r.result.stdout.length).toBe(bytes);if(i>=5)samples.push(Date.now()-start);}));
  samples.sort((a,b)=>a-b);const q=p=>samples[Math.min(samples.length-1,Math.ceil(p*samples.length)-1)];console.log(JSON.stringify({scope:'native-dense-source',unique,bytes,rules:6,concurrency,samples:samples.length,p50:q(.5),p95:q(.95),p99:q(.99)}));
 }
});
for(const error of [false,true])test('dense tail secret stops subsequent dispatch error='+error,async($,on)=>{
 setup(on);let calls=0;const output=denseSource(1048576,true)+'\nAPI_KEY="pM8!sQ3_vL7#rD5-tN2@xK9";';
 on('tool.call',()=>({isError:error,result:error?{stderr:output}:{stdout:output}}));
 on('turn.step',async function*(){calls++;return {turnId:'t',index:1,answer:'sent',toolUses:[],stopReason:'end_turn',usage:null};});
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});await $.turn.start({turnId:'t',text:'probe'});
 expect((await $.tool.call({tool:'Bash',command:'read fixture'})).deny).toBe('SAFEGUARD_BLOCKED');
 const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);expect(status.lastRule).toBe('security.credentials');
 const it=$.turn.step({turnId:'t',index:1,model:'test',messageCount:2});while(!(await it.next()).done){}expect(calls).toBe(0);
});
