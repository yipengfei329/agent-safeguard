import {test} from 'claude-code/testing';
import {denseSource} from '../fixtures/dense-source.mjs';
const precision='interface Options { token: "custom-type-discriminant"; }\nconst password = "Please enter your password";\nconst secret = "AWS_SECRET_ACCESS_KEY";\nconst token = "application/json";\nconst Authorization = "<binding:credential>";\n';
for(const workload of ['precision','repeated-fields','unique-fields'])for(const bytes of [10240,102400,1048576])for(const concurrency of [1,4])test(`native dense comparison ${workload} ${bytes} ${concurrency}`,{timeoutMs:60000},async($,on)=>{
 on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));
 const output=workload==='precision'?precision.repeat(Math.floor(bytes/precision.length)).padEnd(bytes,' '):denseSource(bytes,workload==='unique-fields');
 let executions=0;on('tool.call',()=>{executions++;return {result:{stdout:output}};});await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 const samples=[];let blocked=0,warmupBlocked=0;
 for(let round=0;round<25;round++){
  await Promise.all(Array.from({length:concurrency},async()=>{
   const start=Date.now();const result=await $.tool.call({tool:'Bash',command:'read synthetic fixture'});
   if(round<5){if(result.deny)warmupBlocked++;}else{samples.push(Date.now()-start);if(result.deny)blocked++;}
  }));
  // A denial latches the session. Never count subsequent cheap refusals as
  // successful scans or let a failed workload contaminate another scenario.
  if(blocked||warmupBlocked)break;
 }
 const complete=!blocked&&!warmupBlocked;
 samples.sort((a,b)=>a-b);const q=p=>complete?samples[Math.min(samples.length-1,Math.ceil(p*samples.length)-1)]:null;
 const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);
 console.log(JSON.stringify({scope:'native-dense-comparison',workload,bytes,rules:6,concurrency,samples:samples.length,executions,complete,blocked,warmupBlocked,lastRule:status.lastRule,p50:q(.5),p95:q(.95),p99:q(.99)}));
});
