import {test,expect} from 'claude-code/testing';
test('native dispatch latency with clean outputs',async($,on)=>{
 on('fs.exists',()=>({value:false}));on('command.register',()=>({value:undefined}));on('session.start',()=>({cwd:'/work'}));
 let output='';on('tool.call',()=>({result:{stdout:output,stderr:''}}));
 await $.session.start({cwd:'/work',surface:null,isInteractive:false});
 for(const size of [102400,1048576]){output='build complete\n'.repeat(Math.ceil(size/15)).slice(0,size);const samples=[];for(let i=0;i<50;i++){const start=Date.now();const r=await $.tool.call({tool:'Bash',command:'fixture'});expect(r.result.stdout.length).toBe(size);if(i>=10)samples.push(Date.now()-start);}samples.sort((a,b)=>a-b);console.log(JSON.stringify({bytes:size,scope:'native-test-dispatch',p50:samples[19],p95:samples[37],p99:samples[39]}));}
});
