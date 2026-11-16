import {test} from 'claude-code/testing';
import {defaults,migrateRules} from '../dist/core.js';
for(const workload of ['clean','redacted'])for(const bytes of [10240,102400,1048576,4193280])for(const rules of [8,100,1000])for(const concurrency of [1,4])test(`recovery path ${workload} ${bytes} ${rules} ${concurrency}`,{timeoutMs:60000},async($,on)=>{
 const config=migrateRules(defaults,{redactIds:['network.address']});
 for(const r of config.rules){r.sources=r.sources.filter(s=>s!=='prompt.context');if(r.detector.kind==='ip'){r.detector={kind:'ip',mode:'any'};}}
 while(config.rules.length<rules)config.rules.push({id:'bench.'+config.rules.length,enabled:true,sources:['tool.result'],action:'observe',detector:{kind:'exact',values:['NON_MATCHING_SYNTHETIC_MARKER'],caseSensitive:true}});
 config.limits.maxRules=1000;
 on('fs.exists',($,e)=>({value:!e.path.endsWith('desktop.json')}));on('fs.read',()=>({value:JSON.stringify(config)}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));
 const tail=workload==='redacted'?'peer=203.0.113.17':'status=ok',line='network check ok\n';const output=line.repeat(Math.floor((bytes-tail.length)/line.length)).padEnd(bytes-tail.length,' ')+tail;
 let executions=0;on('tool.call',()=>{executions++;return {result:{stdout:output,stderr:'',interrupted:false}};});await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});
 const samples=[];let blocked=0,warmupBlocked=0;
 for(let round=0;round<25;round++){
  await Promise.all(Array.from({length:concurrency},async()=>{const start=Date.now(),r=await $.tool.call({tool:'Bash',command:'read synthetic fixture'});if(round<5){if(r.deny)warmupBlocked++;}else{samples.push(Date.now()-start);if(r.deny)blocked++;}}));
  if(blocked||warmupBlocked)break;
 }
 samples.sort((a,b)=>a-b);const complete=!blocked&&!warmupBlocked;const q=p=>complete?samples[Math.min(samples.length-1,Math.ceil(p*samples.length)-1)]:null;
 const status=JSON.parse((await $.command.run({command:'agent-safeguard-status',args:''})).text);
 console.log(JSON.stringify({scope:'native-recovery',workload,bytes,rules:config.rules.length,concurrency,samples:samples.length,executions,complete,blocked,warmupBlocked,lastRule:status.lastRule,lastReason:status.lastReason,p50:q(.5),p95:q(.95),p99:q(.99)}));
});
