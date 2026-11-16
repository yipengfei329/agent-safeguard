import {test} from 'claude-code/testing';
// This probe is loaded with an EMPTY registration module (the harness requires a module). It measures dispatch and
// result transfer only, on the same host and with the same result shape.
for(const bytes of [10240,102400,1048576,4193280])for(const concurrency of [1,4])test(`baseline ${bytes} ${concurrency}`,async($,on)=>{
 const line='network check ok\n',output=line.repeat(Math.floor(bytes/line.length)).padEnd(bytes,' ');
 on('tool.call',()=>({result:{stdout:output,stderr:'',interrupted:false}}));const samples=[];
 for(let round=0;round<25;round++)await Promise.all(Array.from({length:concurrency},async()=>{const start=Date.now();await $.tool.call({tool:'Bash',command:'read synthetic fixture'});if(round>=5)samples.push(Date.now()-start);}));
 samples.sort((a,b)=>a-b);const q=p=>samples[Math.min(samples.length-1,Math.ceil(p*samples.length)-1)];
 console.log(JSON.stringify({scope:'native-recovery-baseline',bytes,rules:0,concurrency,samples:samples.length,p50:q(.5),p95:q(.95),p99:q(.99)}));
});
