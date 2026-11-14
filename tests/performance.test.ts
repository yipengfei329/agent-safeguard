import {test,expect} from 'claude-code/testing';
test('native dispatch latency with clean outputs',async($,on)=>{
 on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/work'}));
 let output='';on('tool.call',()=>({result:{stdout:output,stderr:''}}));
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});
 for(const size of [102400,1048576])for(const dense of [false,true]){const line=dense?'const token = config.token; opts := Options{Secret: cmd == \"ask-secret\"};\n':'build complete\n';output=line.repeat(Math.floor(size/line.length)).padEnd(size,' ');const samples=[];for(let i=0;i<25;i++){const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'fixture'});expect(r.result.stdout.length).toBe(size);if(i>=5)samples.push(Date.now()-start);}samples.sort((a,b)=>a-b);console.log(JSON.stringify({bytes:size,dense,rules:6,concurrency:1,scope:'native-test-dispatch',p50:samples[9],p95:samples[18],p99:samples[19]}));}
});
