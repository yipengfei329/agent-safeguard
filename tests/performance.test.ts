import {test,expect} from 'claude-code/testing';
test('native dispatch latency with clean outputs',async($,on)=>{
 on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/work'}));
 let output='';on('tool.call',()=>({result:{stdout:output,stderr:''}}));
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});
 for(const size of [102400,1048576])for(const dense of [false,true]){const line=dense?'const token = config.token; opts := Options{Secret: cmd == \"ask-secret\"};\n':'build complete\n';output=line.repeat(Math.floor(size/line.length)).padEnd(size,' ');const samples=[];for(let i=0;i<25;i++){const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'fixture'});expect(r.result.stdout.length).toBe(size);if(i>=5)samples.push(Date.now()-start);}samples.sort((a,b)=>a-b);console.log(JSON.stringify({bytes:size,dense,rules:6,concurrency:1,scope:'native-test-dispatch',p50:samples[9],p95:samples[18],p99:samples[19]}));}
});
// Matched workload with and without the desktop observer. The host fs boundary
// is stubbed here; real installed-plugin delivery is checked by flow.py.
import {mock} from 'claude-code/testing';
import {defaults} from '../dist/core.js';
for(const bridgeEnabled of [false,true])test(`observer overhead bridge=${bridgeEnabled}`,{timeoutMs:30000},async($,on)=>{
 const clock=mock.clock(on);const config=JSON.parse(JSON.stringify(defaults));
 let writtenBytes=0;
 on('fs.exists',($,e)=>({value:e.path.endsWith('desktop.json')?bridgeEnabled:true}));
 on('fs.read',($,e)=>({value:JSON.stringify(e.path.endsWith('desktop.json')?{schema:1,rulesPath:'/synthetic/rules.json',statusDir:'/synthetic/sessions'}:config)}));
 on('fs.write',($,e)=>{writtenBytes+=e.text.length;return {value:undefined};});
 on('session.id',()=>({value:'00000000-0000-4000-8000-000000000111'}));on('session.root',()=>({value:'/synthetic'}));on('session.model',()=>({value:'synthetic-model'}));
 on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/synthetic'}));
 let output='';on('tool.call',()=>({result:output}));
 await $.session.start({cwd:'/synthetic',surface:null,isInteractive:false});await clock.advance(1100);
 for(const bytes of [102400,1048576])for(const concurrency of [1,4]){
  output='build complete\n'.repeat(Math.ceil(bytes/15)).slice(0,bytes);const samples=[];
  for(let i=0;i<25;i++)await Promise.all(Array.from({length:concurrency},async()=>{const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'fixture'});expect(r.result.length).toBe(bytes);if(i>=5)samples.push(Date.now()-start);}));
  samples.sort((a,b)=>a-b);const q=p=>samples[Math.min(samples.length-1,Math.ceil(p*samples.length)-1)];
  console.log(JSON.stringify({scope:'native-test-dispatch-observer',bridgeEnabled,bytes,rules:config.rules.length,concurrency,samples:samples.length,p50:q(.5),p95:q(.95),p99:q(.99),reportBytes:writtenBytes}));
 }
});
